//! Manage authentication, job signature verification, and the session
//! state machine. Does not manage jobs directly.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use http_range_header::SyntacticallyCorrectRange as Range;
use lru::LruCache;
use rumors::Rumors;
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, info, o, warn};
use tokio::sync::{Mutex, MutexGuard, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::der::{DecodePem as _, Encode as _};

use sush_api::JobStartParams;
use sush_common::authn::{Credentials, Identity, Nonce};
use sush_common::jobs::JobOutputStream::{self};
use sush_common::jobs::{JobId, JobStatus, Session, SessionId, SignedJob};
use sush_common::keys::{KeyError, KeyId, Signature, SshPublicKey};

use crate::error::JobError;
use crate::interactive::SocketSender;
use crate::messages::{JobRequest, Message, Request, SessionRequest};
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

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = ByteSize::mb(128).as_u64();

type SessionGuard<'a> = MutexGuard<'a, Option<Session>>;

/// NB: All tables must have a fixed maximum size!
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct JobManager {
    log: Logger,
    nonces: Arc<Mutex<LruCache<Nonce, DateTime<Utc>>>>,
    identities: Arc<Mutex<LruCache<(KeyId, Nonce), (Identity, Credentials)>>>,
    certs: Arc<Mutex<LruCache<KeyId, Certificate>>>,
    output_dir: PathBuf,
    state: watch::Receiver<State>,
    tx_req: mpsc::Sender<Request>,
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
        let (tx_req, rx_req) = mpsc::channel(16);
        let requests = ReceiverStream::new(rx_req);
        let new = Self {
            log: log.new(o!("component" => "manager")),
            nonces: Arc::new(Mutex::new(LruCache::new(MAX_OUTSTANDING_NONCES))),
            identities: Arc::new(Mutex::new(LruCache::new(MAX_CACHED_IDENTITIES))),
            certs: Arc::new(Mutex::new(LruCache::new(MAX_CERTS))),
            output_dir: output_dir.clone(),
            state: StateManager::run(output_dir, own_baseboard, requests, rumors, shutdown),
            tx_req,
        };

        // Import the root certificates.
        for root in ROOT_CERTS {
            new.import_cert_inner(Certificate::from_pem(root)?, true)
                .await?;
        }

        Ok(new)
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

    pub fn session(&self, _authn: &Identity) -> Option<Session> {
        self.state.borrow().session()
    }

    pub fn session_id(&self, authn: &Identity) -> Result<SessionId, JobError> {
        let Some(session) = self.session(authn) else {
            return Err(JobError::NoSession);
        };
        Ok(session.into_session_id())
    }

    pub async fn session_start(
        &self,
        _authn: &Identity,
        session_id: SessionId,
    ) -> Result<(), JobError> {
        self.tx_req
            .send(Request::Session(SessionRequest::Start(session_id)))
            .await
            .map_err(|_| JobError::ChannelClosed)?;
        Ok(())
    }

    pub async fn session_stop(
        &self,
        _authn: &Identity,
        session_id: SessionId,
    ) -> Result<(), JobError> {
        self.tx_req
            .send(Request::Session(SessionRequest::Stop(session_id)))
            .await
            .map_err(|_| JobError::ChannelClosed)?;
        Ok(())
    }

    // Job management.

    pub async fn job_start(
        &self,
        authn: &Identity,
        job: SignedJob,
        params: JobStartParams,
    ) -> Result<(), JobError> {
        // Verify the job request.
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

        // Submit the job for execution.
        self.tx_req
            .send(Request::Job(
                self.session_id(authn)?,
                JobRequest::Start(job, params),
            ))
            .await
            .map_err(|_| JobError::ChannelClosed)?;

        Ok(())
    }

    pub async fn job_stop(&self, authn: &Identity, job_id: &JobId) -> Result<(), JobError> {
        self.tx_req
            .send(Request::Job(
                self.session_id(authn)?,
                JobRequest::Stop(job_id.to_owned()),
            ))
            .await
            .map_err(|_| JobError::ChannelClosed)?;
        Ok(())
    }

    pub async fn job_status(
        &self,
        _authn: &Identity,
        job_id: &JobId,
    ) -> Result<JobStatus, JobError> {
        todo!("get job status for {job_id}")
    }

    pub async fn job_output(
        &self,
        _authn: &Identity,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        todo!("get job {stream} for {job_id}: {range:?}")
    }

    pub async fn job_start_interactive_session(
        &self,
        authn: &Identity,
        job_id: &JobId,
    ) -> Result<SocketSender, JobError> {
        self.tx_req
            .send(Request::Job(
                self.session_id(authn)?,
                JobRequest::Attach(job_id.to_owned()),
            ))
            .await
            .map_err(|_| JobError::ChannelClosed)?;
        todo!("get interactive session socket sender somehow")
    }

    pub async fn job_history(
        &self,
        _authn: &Identity,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<JobStatus>, JobError> {
        todo!("get job history from state")
    }
}

// See tests in `tests/src/manager_tests.rs`
