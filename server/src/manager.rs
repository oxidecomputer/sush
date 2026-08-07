//! Manage authentication, job signature verification, and the session
//! state machine. Does not manage jobs directly.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use http_range_header::SyntacticallyCorrectRange as Range;
use lru::LruCache;
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, o, warn};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;

use sush_api::{JobStartParams, JobStopParams, JobWait};
use sush_common::authn::{Credentials, Identity, Nonce};
use sush_common::jobs::JobOutputStream;
use sush_common::jobs::{JobId, JobStatusMap, Session, SessionId, SignedJob};
use sush_common::keys::{KeyError, KeyId, SshPublicKey};

use crate::error::JobError;
use crate::executor::PathIsolation;
use crate::job::SocketSender;
use crate::messages::v0::{CertRequest, JobRequest, Request, SessionRequest};
use crate::output::{JobOutputDir, JobOutputFileStream};
use crate::state::{GossipNetwork, MAX_CERTS, State, StateManager};

/// Maximum number of cached identities.
const MAX_CACHED_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// Maximum number of outstanding authentication nonces.
/// We do not really expect more than one simultaneous user,
/// nor do we expect hostile (DoS) requests, so a small value
/// here is adequate.
const MAX_OUTSTANDING_NONCES: NonZeroUsize = NonZeroUsize::new(100).unwrap();

/// Maximum amount of time we're willing to wait for job start or stop.
const WAIT_TIMEOUT: Duration = Duration::from_secs(600);

/// NB: All tables must have a fixed maximum size!
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct JobManager {
    log: Logger,
    nonces: Arc<Mutex<LruCache<Nonce, DateTime<Utc>>>>,
    identities: Arc<Mutex<LruCache<(KeyId, Nonce), (Identity, Credentials)>>>,
    output_dir: JobOutputDir,
    own_baseboard: BaseboardId,
    state: watch::Receiver<State>, // from the state manager
    tx_req: mpsc::Sender<Request>, // to the state manager
    join_state: Option<JoinHandle<()>>,
}

impl JobManager {
    pub async fn new(
        log: Logger,
        path_isolation: PathIsolation,
        output_dir: PathBuf,
        own_baseboard: BaseboardId,
        rumors: GossipNetwork,
        roots: &[Certificate],
        shutdown: CancellationToken,
    ) -> Result<Self, JobError> {
        let output_dir = JobOutputDir::new(output_dir);
        let (tx_req, rx_req) = mpsc::channel(16);
        let requests = ReceiverStream::new(rx_req);
        let (rx_state, join_state) = StateManager::run(
            log.new(o!("component" => "state manager")),
            path_isolation,
            output_dir.clone(),
            own_baseboard.clone(),
            requests,
            rumors,
            roots,
            shutdown,
        );
        Ok(Self {
            log: log.new(o!("component" => "job manager")),
            nonces: Arc::new(Mutex::new(LruCache::new(MAX_OUTSTANDING_NONCES))),
            identities: Arc::new(Mutex::new(LruCache::new(MAX_CACHED_IDENTITIES))),
            own_baseboard,
            output_dir,
            state: rx_state,
            tx_req,
            join_state: Some(join_state),
        })
    }

    pub fn own_baseboard(&self) -> &BaseboardId {
        &self.own_baseboard
    }

    async fn cert_request(&self, request: CertRequest) -> Result<(), JobError> {
        self.tx_req
            .send(Request::cert(request))
            .await
            .map_err(|_| JobError::ChannelClosed)
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

    pub async fn import_cert(
        &self,
        _authn: &Identity,
        cert: Certificate,
        wait: bool,
    ) -> Result<(), JobError> {
        if self.state.borrow().num_certs() >= MAX_CERTS {
            return Err(KeyError::TooManyCerts(MAX_CERTS).into());
        }
        if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
            return Err(KeyError::SelfSigned.into());
        }
        let key_id = KeyId::try_from(&cert)?;
        self.cert_request(CertRequest::Import(cert)).await?;
        if wait {
            self.wait_for(self.wait_for_cert(key_id)).await?;
        }
        Ok(())
    }

    pub fn cert_chain(
        &self,
        _authn: &Identity,
        key_id: &KeyId,
    ) -> Result<Vec<Certificate>, JobError> {
        Ok(self.state.borrow().cert_chain(key_id)?)
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

    // Waiting.

    pub fn take_join_handle(&mut self) -> Option<JoinHandle<()>> {
        self.join_state.take()
    }

    fn wait_for_cert(&self, key_id: KeyId) -> impl FnMut(&State) -> bool {
        move |state| state.cert_chain(&key_id).is_ok()
    }

    fn wait_for_session(&self, session_id: SessionId) -> impl FnMut(&State) -> bool {
        move |state| {
            state
                .session()
                .is_some_and(|s| *s.session_id() == session_id)
        }
    }

    fn wait_for_job(&self, job_id: &JobId, wait: JobWait) -> impl FnMut(&State) -> bool {
        move |state| {
            if wait.is_some() {
                state
                    .get_job_status(job_id)
                    .and_then(|map| map.get(self.own_baseboard()))
                    .map(|status| wait.matches_status(status))
                    .unwrap_or(false)
            } else {
                true
            }
        }
    }

    async fn wait_for(&self, predicate: impl FnMut(&State) -> bool) -> Result<(), JobError> {
        timeout(WAIT_TIMEOUT, self.state.clone().wait_for(predicate))
            .await
            .map_err(|_| JobError::Timeout)?
            .map_err(|_| JobError::ChannelClosed)?;
        Ok(())
    }

    /// Wait until the local state manager has recorded *any* status for
    /// this job on this baseboard, including `Queued`. Used only to make
    /// the `Queued` state observable in tests.
    #[cfg(feature = "test-support")]
    pub async fn wait_for_job_status(&self, job_id: &JobId) -> Result<(), JobError> {
        let job_id = job_id.to_owned();
        let baseboard = self.own_baseboard().to_owned();
        self.wait_for(move |state: &State| {
            state
                .get_job_status(&job_id)
                .and_then(|map| map.get(&baseboard))
                .is_some()
        })
        .await
    }

    // Session management.

    pub fn session(&self, _authn: &Identity) -> Option<Session> {
        self.state.borrow().session().cloned()
    }

    pub async fn session_id(&self, authn: &Identity) -> Result<SessionId, JobError> {
        let Some(session) = self.session(authn) else {
            return Err(JobError::NoSession);
        };
        Ok(session.into_session_id())
    }

    pub async fn session_start(
        &self,
        _authn: &Identity,
        session_id: SessionId,
        wait: bool,
    ) -> Result<(), JobError> {
        self.session_request(SessionRequest::Start(session_id.clone()))
            .await?;
        if wait {
            self.wait_for(self.wait_for_session(session_id.clone()))
                .await?;
        }
        Ok(())
    }

    pub async fn session_stop(
        &self,
        _authn: &Identity,
        session_id: SessionId,
    ) -> Result<(), JobError> {
        self.session_request(SessionRequest::Stop(session_id)).await
    }

    pub async fn session_skip_job(
        &self,
        _authn: &Identity,
        session_id: SessionId,
        job_id: JobId,
    ) -> Result<(), JobError> {
        self.session_request(SessionRequest::Skip(session_id, job_id))
            .await
    }

    // Job management.

    pub async fn job_start(
        &self,
        authn: &Identity,
        job: SignedJob,
        params: JobStartParams,
    ) -> Result<(), JobError> {
        let job_id = job.job_id().to_owned();
        let wait = params.wait.to_owned();

        // A job can only ever run within an active session; fail fast
        // rather than silently queuing (or discarding) a job that can
        // never execute.
        if self.session(authn).is_none() {
            return Err(JobError::NoSession);
        }

        // Reject job IDs we already know about, rather than silently
        // queuing a resubmission that can never advance the session's
        // job chain. Without this, a caller that resubmits an
        // already-completed job ID and waits would see the *original*
        // job's status returned as if it belonged to this submission.
        if self.state.borrow().get_job_status(&job_id).is_some() {
            return Err(JobError::DuplicateJobId(job_id));
        }

        // Submit the job for execution.
        self.job_request(authn, JobRequest::Start(job, params))
            .await?;
        self.wait_for(self.wait_for_job(&job_id, wait)).await
    }

    pub async fn job_stop(
        &self,
        authn: &Identity,
        job_id: &JobId,
        JobStopParams { wait }: JobStopParams,
    ) -> Result<(), JobError> {
        self.job_request(authn, JobRequest::Stop(job_id.to_owned()))
            .await?;
        self.wait_for(self.wait_for_job(job_id, wait)).await
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
    ) -> Result<JobOutputFileStream, JobError> {
        if self.own_baseboard() == target
            && self
                .state
                .borrow()
                .get_job_status(job_id)
                .map(|m| m.contains_key(target))
                .unwrap_or(false)
        {
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
        limit: u32,
        offset: u32,
    ) -> Result<Vec<JobStatusMap>, JobError> {
        Ok(self
            .state
            .borrow()
            .history()
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }
}

// See tests in `tests/src/manager_tests.rs`
