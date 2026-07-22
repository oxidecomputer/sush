//! Manage authentication, job signature verification, and the session
//! state machine. Does not manage jobs directly.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use http_range_header::SyntacticallyCorrectRange as Range;
use lru::LruCache;
use rumors::Rumors;
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, info, o, warn};
use tokio::sync::{Mutex, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::der::{DecodePem as _, Encode as _};

use sush_api::{JobStartParams, JobStopParams, JobWait};
use sush_common::authn::{Credentials, Identity, Nonce};
use sush_common::jobs::JobOutputStream::{self};
use sush_common::jobs::{JobId, JobStatusMap, Session, SessionId, SignedJob};
use sush_common::keys::{KeyError, KeyId, Signature, SshPublicKey};

use crate::error::JobError;
use crate::interactive::SocketSender;
use crate::messages::{JobRequest, Message, Request, SessionRequest};
use crate::output::JobOutputDir;
use crate::state::{State, StateManager};

/// Self-signed (root) X.509 certificates. Self-signed certificates may
/// not be imported (except in test code), and so must be included here.
pub const ROOT_CERTS: &[&[u8]] = &[
    // export PERMSLIP_URL="https://permslip.inickles.0xeng.dev"
    // export SUSH_PERMSLIP_KEY="UNTRUSTED Support Shell Prototype"
    include_bytes!("../certs/sandbox.pem"),
];

/// Maximum certificate chain length.
const MAX_CERT_CHAIN_LEN: usize = 10;

/// Maximum number of job signing certificates.
/// The ideal number of certs is 1, so this need not be large.
const MAX_CERTS: NonZeroUsize = NonZeroUsize::new(100).unwrap();

/// Maximum number of cached identities.
const MAX_CACHED_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// Maximum number of outstanding authentication nonces.
/// We do not really expect more than one simultaneous user,
/// nor do we expect hostile (DoS) requests, so a small value
/// here is adequate.
const MAX_OUTSTANDING_NONCES: NonZeroUsize = NonZeroUsize::new(100).unwrap();

/// NB: All tables must have a fixed maximum size!
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct JobManager {
    log: Logger,
    nonces: Arc<Mutex<LruCache<Nonce, DateTime<Utc>>>>,
    identities: Arc<Mutex<LruCache<(KeyId, Nonce), (Identity, Credentials)>>>,
    certs: Arc<Mutex<LruCache<KeyId, Certificate>>>,
    output_dir: JobOutputDir,
    own_baseboard: BaseboardId,
    state: watch::Receiver<State>, // from the state manager
    tx_req: mpsc::Sender<Request>, // to the state manager
}

impl JobManager {
    pub async fn new(
        log: Logger,
        output_dir: PathBuf,
        own_baseboard: BaseboardId,
        rumors: Rumors<Message>,
        shutdown: CancellationToken,
    ) -> Result<Self, JobError> {
        // Make the new manager instance.
        let output_dir = JobOutputDir::new(output_dir);
        let (tx_req, rx_req) = mpsc::channel(16);
        let requests = ReceiverStream::new(rx_req);
        let new = Self {
            log: log.new(o!("component" => "job manager")),
            nonces: Arc::new(Mutex::new(LruCache::new(MAX_OUTSTANDING_NONCES))),
            identities: Arc::new(Mutex::new(LruCache::new(MAX_CACHED_IDENTITIES))),
            certs: Arc::new(Mutex::new(LruCache::new(MAX_CERTS))),
            own_baseboard: own_baseboard.clone(),
            output_dir: output_dir.clone(),
            state: StateManager::run(
                log.new(o!("component" => "state manager")),
                output_dir,
                own_baseboard,
                requests,
                rumors,
                shutdown,
            ),
            tx_req,
        };

        // Import the root certificates.
        for root in ROOT_CERTS {
            new.import_cert_inner(Certificate::from_pem(root)?, true)
                .await?;
        }

        Ok(new)
    }

    pub fn own_baseboard(&self) -> &BaseboardId {
        &self.own_baseboard
    }

    async fn session_request(&self, request: SessionRequest) -> Result<(), JobError> {
        self.tx_req
            .send(Request::session(request))
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    async fn job_request(&self, _authn: &Identity, request: JobRequest) -> Result<(), JobError> {
        self.tx_req
            .send(Request::job(request))
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    // Certificate management.

    /// Tests must import a root to use ephemeral signers,
    /// but this is not allowed in production.
    #[cfg(feature = "import_root_for_test_only")] // disabled by default
    pub async fn import_root(&self, root: Certificate) -> Result<KeyId, JobError> {
        self.import_cert_inner(root, true).await
    }

    pub async fn import_cert(
        &self,
        _authn: &Identity,
        cert: Certificate,
    ) -> Result<KeyId, JobError> {
        self.import_cert_inner(cert, false).await
    }

    async fn import_cert_inner(
        &self,
        cert: Certificate,
        root_allowed: bool,
    ) -> Result<KeyId, JobError> {
        // Verify the certificate signature.
        let signature = Signature::try_from(&cert)?;
        let tbs = cert.tbs_certificate.to_der()?;
        let subject = &cert.tbs_certificate.subject;
        let issuer = &cert.tbs_certificate.issuer;
        let root = subject == issuer;
        if root {
            if root_allowed {
                signature.verify_with_spki(&tbs, &cert.tbs_certificate.subject_public_key_info)?;
            } else {
                return Err(KeyError::SelfSigned.into());
            }
        } else {
            let issuer_key_id = KeyId::try_from(issuer)?;
            if let Some(issuer) = self.certs.lock().await.get(&issuer_key_id) {
                signature
                    .verify_with_spki(&tbs, &issuer.tbs_certificate.subject_public_key_info)?;
            } else {
                return Err(JobError::MissingCert(issuer_key_id));
            }
        }

        // Try to make room for the new cert, but do not evict roots.
        let key_id = KeyId::try_from(subject)?;
        let mut certs = self.certs.lock().await;
        if certs.len() >= MAX_CERTS.get() && !certs.contains(&key_id) {
            let mut i = 0;
            while let Some((lru_key_id, lru_cert)) =
                certs.peek_lru().map(|(k, v)| (k.to_owned(), v.to_owned()))
            {
                if lru_cert.tbs_certificate.subject == lru_cert.tbs_certificate.issuer {
                    certs.promote(&lru_key_id);
                    i += 1;
                } else {
                    certs.pop_lru();
                    break;
                }
                if i == MAX_CERTS.get() {
                    return Err(JobError::TooManyCerts(MAX_CERTS.get()));
                }
            }
        }

        // Import the certificate.
        certs.put(key_id.clone(), cert);
        info!(self.log, "imported certificate"; "key_id" => %key_id, "root" => root);
        Ok(key_id)
    }

    /// Return the cert chain for the given key in root-to-leaf order.
    pub async fn cert_chain(
        &self,
        _authn: &Identity,
        key_id: &KeyId,
    ) -> Result<Vec<Certificate>, JobError> {
        let mut certs = self.certs.lock().await;
        let mut chain = Vec::new();
        let mut key_id = key_id.to_owned();
        loop {
            if chain.len() >= MAX_CERT_CHAIN_LEN {
                return Err(JobError::CertChainTooLong);
            }
            let Some(cert) = certs.get(&key_id) else {
                return Err(JobError::MissingCert(key_id));
            };
            chain.push(cert.to_owned());
            if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
                break;
            }
            key_id = KeyId::try_from(&cert.tbs_certificate.issuer)?;
        }
        chain.reverse();
        Ok(chain)
    }

    // Identity management.

    /// Authenticate and cache authorization credentials.
    pub async fn iam(
        &self,
        authorization: Option<String>,
        public_key: Option<SshPublicKey>,
    ) -> Result<Identity, JobError> {
        // NB: Do not use the `?` operator in this function! We must ensure
        // that all authentication failures are logged and receive a proper
        // 401 Unauthorized response with a fresh nonce.
        macro_rules! unauthorized {
            ($error:expr) => {{
                warn!(self.log, "authentication failed"; "error" => %$error);
                let nonce = Nonce::generate();
                self.nonces.lock().await.put(nonce.clone(), Utc::now());
                return Err(JobError::unauthorized(nonce));
            }};
        }

        macro_rules! try_authn {
            // $expr -> Result
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => unauthorized!(error),
                }
            };
            // $expr -> bool
            ($expr:expr, $error:expr) => {
                $expr || unauthorized!($error)
            };
        }

        // Parse the supplied credentials.
        let Some(authorization) = authorization else {
            unauthorized!("missing authorization")
        };
        let credentials: Credentials = try_authn!(authorization.parse());
        let Credentials {
            key_id,
            nonce,
            cnonce,
            signature,
        } = credentials.clone();

        // Check the identity cache.
        let now = Utc::now();
        {
            let mut identities = self.identities.lock().await;
            let cache_key = (key_id.clone(), nonce.clone());
            if let Some((identity, cached_credentials)) = identities.get(&cache_key).cloned() {
                if !identity.is_still_valid(&now) {
                    assert!(identities.pop(&cache_key).is_some());
                } else if cached_credentials.cnonce == cnonce
                    && cached_credentials.signature == signature
                {
                    assert_eq!(cached_credentials.nonce, nonce);
                    debug!(self.log, "credentials cache hit"; "key_id" => %key_id);
                    return Ok(identity);
                } else {
                    unauthorized!("invalid credentials for cached identity");
                }
            }
        }

        // Claim the nonce.
        let Some(generated) = self.nonces.lock().await.pop(&nonce) else {
            unauthorized!("nonce not found");
        };
        if !Nonce::is_still_valid(&generated, &now) {
            unauthorized!("nonce expired");
        };

        // Verify the supplied credentials.
        let Some(public_key) = public_key else {
            unauthorized!("missing public key");
        };
        if public_key.key_id().ok() != Some(key_id.clone()) {
            unauthorized!("invalid key ID");
        }
        let response = credentials.clone().into_challenge_response();
        let verified = try_authn!(response.verify_with_ssh_public_key(&public_key));
        let identity = try_authn!(Identity::new(public_key.to_owned(), verified, now));

        // Authenticated! Cache the identity & credentials.
        debug!(self.log, "authenticated credentials for identity"; "key_id" => %key_id);
        self.identities
            .lock()
            .await
            .put((key_id.to_owned(), nonce), (identity.clone(), credentials));
        Ok(identity)
    }

    pub async fn identities(&self, _authn: &Identity) -> Result<Vec<Identity>, JobError> {
        let now = Utc::now();
        Ok(self
            .identities
            .lock()
            .await
            .iter()
            .filter(|(_, (identity, _credentials))| identity.is_still_valid(&now))
            .map(|(_, (identity, _credentials))| identity.to_owned())
            .collect())
    }

    // Session management.

    pub async fn session(&self, _authn: &Identity) -> Option<Session> {
        self.state.borrow().session()
    }

    pub async fn session_id(&self, authn: &Identity) -> Result<SessionId, JobError> {
        let Some(session) = self.session(authn).await else {
            return Err(JobError::NoSession);
        };
        Ok(session.into_session_id())
    }

    pub async fn session_start(
        &self,
        _authn: &Identity,
        session_id: SessionId,
    ) -> Result<(), JobError> {
        self.session_request(SessionRequest::Start(session_id))
            .await
    }

    pub async fn session_stop(
        &self,
        _authn: &Identity,
        session_id: SessionId,
    ) -> Result<(), JobError> {
        self.session_request(SessionRequest::Stop(session_id)).await
    }

    // Job management.

    fn wait_for(&self, job_id: &JobId, wait: JobWait) -> impl FnMut(&State) -> bool {
        move |state| {
            state
                .get_job_status(job_id)
                .and_then(|map| map.get(self.own_baseboard()))
                .map(|status| wait.matches_status(status))
                .unwrap_or(false)
        }
    }

    async fn maybe_wait(&self, job_id: &JobId, wait: JobWait) -> Result<(), JobError> {
        if wait.is_some() {
            self.state
                .clone()
                .wait_for(self.wait_for(job_id, wait))
                .await
                .map_err(|_| JobError::ChannelClosed)?;
        }
        Ok(())
    }

    pub async fn job_start(
        &self,
        authn: &Identity,
        job: SignedJob,
        params: JobStartParams,
    ) -> Result<(), JobError> {
        // Validate the job request.
        if job.command.starts_with('-') {
            return Err(JobError::InvalidCommand(job.into_payload().command));
        }
        let cert_key_id = job.key_id().to_owned();
        let chain = self.cert_chain(authn, &cert_key_id).await?;
        let job = if let Some(leaf) = chain.last() {
            job.verify_with_cert(leaf)?
        } else {
            return Err(JobError::MissingCert(cert_key_id));
        };
        let job_id = job.job_id().to_owned();
        let wait = params.wait.to_owned();

        // Submit the job for execution.
        self.job_request(authn, JobRequest::Start(job.into_signed(), params))
            .await?;

        self.maybe_wait(&job_id, wait).await
    }

    pub async fn job_stop(
        &self,
        authn: &Identity,
        job_id: &JobId,
        JobStopParams { wait }: JobStopParams,
    ) -> Result<(), JobError> {
        self.job_request(authn, JobRequest::Stop(job_id.to_owned()))
            .await?;
        self.maybe_wait(job_id, wait).await
    }

    pub async fn job_status(
        &self,
        _authn: &Identity,
        job_id: &JobId,
    ) -> Result<JobStatusMap, JobError> {
        if let Some(status) = self.state.borrow().get_job_status(job_id) {
            Ok(status.to_owned())
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn job_output(
        &self,
        _authn: &Identity,
        job_id: &JobId,
        target: &BaseboardId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        if self.own_baseboard() == target && self.state.borrow().get_job_status(job_id).is_some() {
            self.output_dir.job_output(job_id, stream, range).await
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn job_attachment(
        &self,
        _authn: &Identity,
        job_id: &JobId,
        target: &BaseboardId,
    ) -> Result<SocketSender, JobError> {
        if self.own_baseboard() == target
            && let Some(attachment) = self.state.borrow().get_attachment(job_id)
        {
            Ok(attachment.to_owned())
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn job_history(
        &self,
        _authn: &Identity,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<JobStatusMap>, JobError> {
        todo!("get job history from state")
    }
}

// See tests in `tests/src/manager_tests.rs`
