// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Manage authentication, job signature verification, and the session
//! state machine. Does not manage jobs directly.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use http_range_header::SyntacticallyCorrectRange as Range;
use lru::LruCache;
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, info, o, warn};
use tokio::fs::read;
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::der::DecodePem as _;

use sush_api::{JobStartParams, JobStopParams, JobWait};
use sush_common::authn::{
    Authn, BoundRequest, Credentials, IDENTITY_IDLE_TTL, IDENTITY_MAX_TTL, Identity, NONCE_TTL,
    Nonce, RequestVerifier, SeqWindow,
};
use sush_common::jobs::{
    Access, JobId, JobStatusMap, Session, SessionId, SessionSignerNonce, SignedJob,
};
use sush_common::jobs::{JobOutputStream, SessionSushNonce};
use sush_common::keys::{KeyError, KeyId, SshPublicKey};
use sush_common::targets::{Cubbies, SledVersion};
use sush_common::version::LONG_VERSION;

use crate::error::JobError;
use crate::executor::PathIsolation;
use crate::job::SocketSender;
use crate::messages::v0::{CertRequest, IdentityRequest, JobRequest, Request, SessionRequest};
use crate::output::{JobOutputDir, JobOutputFileStream};
use crate::state::{GossipNetwork, MAX_CERTS, State, StateManager};

/// Maximum number of cached identities.
const MAX_CACHED_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// Maximum number of outstanding authentication nonces. Every failed
/// request mints one, so garbage traffic evicts real challenges. This
/// is sized so a flood must sustain hundreds of requests per second
/// for the whole nonce TTL to lock a user out.
const MAX_OUTSTANDING_NONCES: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// Maximum amount of time we're willing to wait for job start or stop.
const WAIT_TIMEOUT: Duration = Duration::from_secs(600);

/// An authenticated identity and the state that authorizes its
/// requests: the ephemeral verifier, the spent sequence numbers, and
/// its lifetime, kept on the monotonic clock because the wall clock
/// may step by decades when NTP first syncs.
#[derive(Debug)]
struct CachedIdentity {
    identity: Identity,
    verifier: RequestVerifier,
    window: SeqWindow,
    authenticated: Instant,
    last_used: Instant,
}

impl CachedIdentity {
    fn is_still_valid(&self) -> bool {
        self.identity.time_revoked.is_none()
            && self.authenticated.elapsed() < IDENTITY_MAX_TTL
            && self.last_used.elapsed() < IDENTITY_IDLE_TTL
    }
}

/// NB: All tables must have a fixed maximum size!
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct JobManager {
    log: Logger,
    nonces: Arc<Mutex<LruCache<Nonce, Instant>>>,
    identities: Arc<Mutex<LruCache<(KeyId, Nonce), CachedIdentity>>>,
    session_sush_nonce: Arc<SyncMutex<SessionSushNonce>>,
    output_dir: JobOutputDir,
    own_baseboard: BaseboardId,
    state: watch::Receiver<State>, // from the state manager
    tx_req: mpsc::Sender<Request>, // to the state manager
    join_state: Option<JoinHandle<()>>,
}

impl JobManager {
    /// Trust the root certificates in `roots`, one PEM-encoded certificate
    /// per file.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        log: Logger,
        path_isolation: PathIsolation,
        output_dir: JobOutputDir,
        own_baseboard: BaseboardId,
        cubbies: watch::Receiver<Cubbies>,
        universe: watch::Receiver<GossipNetwork>,
        roots: &[impl AsRef<Path>],
        shutdown: CancellationToken,
    ) -> Result<Self, JobError> {
        let roots = read_root_certs(roots).await?;
        Self::with_root_certs(
            log,
            path_isolation,
            output_dir,
            own_baseboard,
            cubbies,
            universe,
            &roots,
            shutdown,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn with_root_certs(
        log: Logger,
        path_isolation: PathIsolation,
        output_dir: JobOutputDir,
        own_baseboard: BaseboardId,
        cubbies: watch::Receiver<Cubbies>,
        universe: watch::Receiver<GossipNetwork>,
        roots: &[Certificate],
        shutdown: CancellationToken,
    ) -> Result<Self, JobError> {
        info!(log, "starting sush"; "version" => LONG_VERSION);
        let (tx_req, rx_req) = mpsc::channel(16);
        let requests = ReceiverStream::new(rx_req);
        let session_sush_nonce = Arc::new(SyncMutex::new(SessionSushNonce::random()));
        let (rx_state, join_state) = StateManager::run(
            log.new(o!("component" => "state manager")),
            path_isolation,
            output_dir.clone(),
            own_baseboard.clone(),
            requests,
            cubbies,
            universe,
            roots,
            session_sush_nonce.clone(),
            shutdown,
        )?;
        Ok(Self {
            log: log.new(o!("component" => "job manager")),
            nonces: Arc::new(Mutex::new(LruCache::new(MAX_OUTSTANDING_NONCES))),
            identities: Arc::new(Mutex::new(LruCache::new(MAX_CACHED_IDENTITIES))),
            session_sush_nonce,
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

    /// Every sled known by cubby or by build, sorted by cubby first.
    pub fn versions(&self) -> Vec<SledVersion> {
        let state = self.state.borrow();
        let mut sleds: BTreeSet<&BaseboardId> = state.versions().keys().collect();
        sleds.extend(state.cubbies().values());
        let mut rows: Vec<SledVersion> = sleds
            .into_iter()
            .map(|baseboard| SledVersion {
                cubby: state
                    .cubbies()
                    .iter()
                    .find_map(|(cubby, b)| (b == baseboard).then_some(*cubby)),
                baseboard: baseboard.clone(),
                version: state.versions().get(baseboard).cloned(),
            })
            .collect();
        rows.sort_by_key(|row| (row.cubby.is_none(), row.cubby));
        rows
    }

    async fn cert_request(&self, authn: &Identity, request: CertRequest) -> Result<(), JobError> {
        self.tx_req
            .send(Request::cert(authn.key_id.clone(), request))
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    async fn session_request(
        &self,
        authn: &Identity,
        request: SessionRequest,
    ) -> Result<(), JobError> {
        self.tx_req
            .send(Request::session(authn.key_id.clone(), request))
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    async fn job_request(&self, authn: &Identity, request: JobRequest) -> Result<(), JobError> {
        self.tx_req
            .send(Request::job(authn.key_id.clone(), request))
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    async fn identity_request(
        &self,
        actor: KeyId,
        request: IdentityRequest,
    ) -> Result<(), JobError> {
        self.tx_req
            .send(Request::identity(actor, request))
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    // Certificate management.

    pub async fn cert_import(
        &self,
        authn: &Identity,
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
        self.cert_request(authn, CertRequest::Import(cert)).await?;
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

    pub async fn cert_revoke(
        &self,
        authn: &Identity,
        key_id: KeyId,
        wait: bool,
    ) -> Result<(), JobError> {
        if self.state.borrow().is_root(&key_id) {
            return Err(JobError::RootRevocation(key_id));
        }
        self.cert_request(authn, CertRequest::Revoke(key_id.clone(), Utc::now()))
            .await?;
        if wait {
            self.wait_for(self.wait_for_revocation(key_id)).await?;
        }
        Ok(())
    }

    // Identity management.

    /// Authenticate initial credentials at `iam`, or authorize a bound
    /// request against a cached identity. `request` is the request
    /// line: the method and the target exactly as received.
    pub async fn iam(
        &self,
        authorization: Option<String>,
        public_key: Option<SshPublicKey>,
        request: (&str, &str),
    ) -> Result<Identity, JobError> {
        // NB: Do not use the `?` operator in this function! We must ensure
        // that all authentication failures are logged and receive a proper
        // 401 Unauthorized response with a fresh nonce.
        macro_rules! unauthorized {
            ($error:expr) => {{
                warn!(self.log, "authentication failed"; "error" => %$error);
                let nonce = Nonce::random();
                self.nonces.lock().await.put(nonce.clone(), Instant::now());
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
        let now = Utc::now();
        let credentials = match try_authn!(authorization.parse::<Authn>()) {
            // A bound request authorizes against a cached identity.
            Authn::Bound(bound) => {
                let mut identities = self.identities.lock().await;
                let cache_key = (bound.key_id.clone(), bound.nonce.clone());
                // A login elsewhere on the rack reaches us as a
                // registered identity. Adopt it on first use.
                if !identities.contains(&cache_key) {
                    let Some(registered) =
                        self.state.borrow().registered_identity(&cache_key).cloned()
                    else {
                        unauthorized!("unknown identity");
                    };
                    debug!(self.log, "adopting registered identity"; "key_id" => %bound.key_id);
                    identities.put(
                        cache_key.clone(),
                        CachedIdentity {
                            identity: registered.identity,
                            verifier: registered.verifier,
                            window: SeqWindow::default(),
                            authenticated: Instant::now(),
                            last_used: Instant::now(),
                        },
                    );
                }
                let Some(cached) = identities.get_mut(&cache_key) else {
                    unauthorized!("unknown identity");
                };
                if !cached.is_still_valid() {
                    identities.pop(&cache_key);
                    unauthorized!("identity expired");
                }
                let (method, target) = request;
                let received = BoundRequest::new(method, target, bound.seq);
                try_authn!(cached.verifier.verify(&received, &bound));
                if !cached.window.spend(bound.seq) {
                    unauthorized!("sequence number already spent");
                }
                cached.last_used = Instant::now();
                debug!(self.log, "bound request authorized"; "key_id" => %bound.key_id);
                return Ok(cached.identity.clone());
            }
            Authn::Initial(credentials) => *credentials,
        };
        let Credentials { key_id, nonce, .. } = credentials.clone();

        // Initial credentials authenticate only at `iam` itself.
        let (method, target) = request;
        if method != "POST" || target.split('?').next() != Some("/iam") {
            unauthorized!("initial credentials presented outside iam");
        }

        // Refuse revoked keys.
        if self.state.borrow().is_key_revoked(&key_id) {
            unauthorized!("key is revoked");
        }

        // Claim the nonce.
        let Some(minted) = self.nonces.lock().await.pop(&nonce) else {
            unauthorized!("nonce not found");
        };
        if minted.elapsed() >= NONCE_TTL {
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
        let verified = try_authn!(response.clone().verify_with_ssh_public_key(&public_key));
        let identity = try_authn!(Identity::new(public_key.clone(), verified, now));

        // Authenticated! Cache the identity and its request verifier,
        // and gossip the evidence.
        debug!(self.log, "authenticated credentials for identity"; "key_id" => %key_id);
        self.identities.lock().await.put(
            (key_id.clone(), nonce),
            CachedIdentity {
                identity: identity.clone(),
                verifier: credentials.epk,
                window: SeqWindow::default(),
                authenticated: Instant::now(),
                last_used: Instant::now(),
            },
        );
        let login = IdentityRequest::Login(public_key, response);
        self.identity_request(key_id, login)
            .await
            .map(|()| identity)
    }

    pub async fn identities(&self, _authn: &Identity) -> Result<Vec<Identity>, JobError> {
        Ok(self
            .identities
            .lock()
            .await
            .iter()
            .filter(|(_, cached)| cached.is_still_valid())
            .map(|(_, cached)| cached.identity.to_owned())
            .collect())
    }

    pub async fn iam_revoke(
        &self,
        authn: &Identity,
        key_id: KeyId,
        wait: bool,
    ) -> Result<(), JobError> {
        let now = Utc::now();
        let mut identities = self.identities.lock().await;
        for (_, cached) in identities.iter_mut().filter(|((id, _), _)| *id == key_id) {
            cached.identity.time_revoked = Some(now);
        }
        drop(identities);
        info!(self.log, "revoking identity"; "key_id" => %key_id, "actor" => %authn.key_id);
        self.identity_request(
            authn.key_id.clone(),
            IdentityRequest::Revoke(key_id.clone(), now),
        )
        .await?;
        if wait {
            self.wait_for(self.wait_for_key_revocation(key_id)).await?;
        }
        Ok(())
    }

    // Waiting.

    pub fn take_join_handle(&mut self) -> Option<JoinHandle<()>> {
        self.join_state.take()
    }

    fn wait_for_cert(&self, key_id: KeyId) -> impl FnMut(&State) -> bool {
        move |state| state.cert_chain(&key_id).is_ok()
    }

    fn wait_for_revocation(&self, key_id: KeyId) -> impl FnMut(&State) -> bool {
        move |state| state.is_cert_revoked(&key_id)
    }

    fn wait_for_key_revocation(&self, key_id: KeyId) -> impl FnMut(&State) -> bool {
        move |state| state.is_key_revoked(&key_id)
    }

    fn wait_for_session(&self, session_id: SessionId) -> impl FnMut(&State) -> bool {
        move |state| {
            state
                .session()
                .is_some_and(|s| s.session_id() == session_id)
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
    /// this job on this baseboard, including `Queued`. This is what makes the
    /// `Queued` state observable.
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

    pub fn session_sush_nonce(&self) -> SessionSushNonce {
        *self.session_sush_nonce.lock().unwrap()
    }

    pub async fn session_start(
        &self,
        authn: &Identity,
        session_id: SessionId,
        signer_nonce: SessionSignerNonce,
        wait: bool,
    ) -> Result<(), JobError> {
        // Verify that the session ID provided by the client is meant for
        // this instance of Sush, by checking that the signer nonce was
        // hashed with our baseboard and nonce. The state machine rotates
        // the nonce when a session activates.
        let sush_nonce = *self.session_sush_nonce.lock().unwrap();
        let computed = SessionId::compute(self.own_baseboard(), sush_nonce, signer_nonce);
        if computed != session_id {
            return Err(JobError::InvalidSessionId);
        }

        self.session_request(authn, SessionRequest::Start(session_id))
            .await?;
        if wait {
            self.wait_for(self.wait_for_session(session_id)).await?;
        }
        Ok(())
    }

    pub async fn session_stop(
        &self,
        authn: &Identity,
        session_id: SessionId,
    ) -> Result<(), JobError> {
        self.starter_check(authn)?;
        self.currency_check(session_id)?;
        self.session_request(authn, SessionRequest::Stop(session_id))
            .await
    }

    /// The authoritative skip is in the state machine, which ignores
    /// requests that lost a race. This check fails fast and loudly.
    pub async fn session_skip_job(
        &self,
        authn: &Identity,
        session_id: SessionId,
        job_id: JobId,
    ) -> Result<(), JobError> {
        self.starter_check(authn)?;
        self.currency_check(session_id)?;
        if let Some(session) = self.session(authn)
            && session.next_job_id() != job_id
        {
            return Err(JobError::NotNextJob(job_id));
        }
        self.session_request(authn, SessionRequest::Skip(session_id, job_id))
            .await
    }

    /// A request naming a session other than the current one would be
    /// silently ignored by the state machine. This check fails fast.
    fn currency_check(&self, session_id: SessionId) -> Result<(), JobError> {
        match self.state.borrow().session() {
            None => Err(JobError::NoSession),
            Some(session) if session.session_id() != session_id => {
                Err(JobError::SessionNotCurrent(session_id))
            }
            Some(_) => Ok(()),
        }
    }

    /// Only the session starter may stop the session, skip its jobs,
    /// or grant and deny attach access. The authoritative check is in
    /// the state machine. This one fails fast.
    fn starter_check(&self, authn: &Identity) -> Result<(), JobError> {
        match self.state.borrow().session() {
            None => Err(JobError::NoSession),
            Some(session) if session.started_by() == Some(&authn.key_id) => Ok(()),
            Some(_) => Err(JobError::NotSessionStarter),
        }
    }

    pub async fn session_allow_attach(
        &self,
        authn: &Identity,
        session_id: SessionId,
        key_id: KeyId,
        access: Access,
    ) -> Result<(), JobError> {
        self.starter_check(authn)?;
        self.currency_check(session_id)?;
        self.session_request(
            authn,
            SessionRequest::AllowAttach(session_id, key_id, access),
        )
        .await
    }

    pub async fn session_deny_attach(
        &self,
        authn: &Identity,
        session_id: SessionId,
        key_id: KeyId,
    ) -> Result<(), JobError> {
        self.starter_check(authn)?;
        self.currency_check(session_id)?;
        self.session_request(authn, SessionRequest::DenyAttach(session_id, key_id))
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

        // A job can only run in the session it was signed for.
        let payload = job.payload();
        match self.session(authn) {
            None => return Err(JobError::NoSession),
            Some(session) if session.session_id() != payload.session_id() => {
                return Err(JobError::SessionNotCurrent(payload.session_id()));
            }
            Some(_) => (),
        }

        // A broader target would orphan jobs on unattached sleds.
        if payload.is_interactive() && payload.target().single_baseboard().is_none() {
            return Err(JobError::InteractiveTarget);
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
        JobStopParams { wait, .. }: JobStopParams,
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
        authn: &Identity,
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
            info!(
                self.log, "job output read";
                "job_id" => %job_id, "stream" => %stream, "actor" => %authn.key_id,
            );
            self.output_dir.job_output(job_id, stream, range).await
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn job_attachment(
        &self,
        authn: &Identity,
        job_id: &JobId,
        target: &BaseboardId,
    ) -> Result<(SocketSender, Access), JobError> {
        let Some(access) = self.state.borrow().attach_access(&authn.key_id) else {
            return Err(JobError::AttachDenied);
        };
        if self.own_baseboard() == target
            && let Some(attachment) = self.state.borrow().get_attachment(job_id)
        {
            info!(
                self.log, "job attach";
                "job_id" => %job_id, "access" => ?access, "actor" => %authn.key_id,
            );
            Ok((attachment.to_owned(), access))
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

/// Read one PEM-encoded certificate from each of `paths`.
pub async fn read_root_certs(paths: &[impl AsRef<Path>]) -> Result<Vec<Certificate>, JobError> {
    let mut roots = Vec::with_capacity(paths.len());
    for path in paths {
        let path = path.as_ref();
        let pem = read(path).await.map_err(JobError::file_io_for(path))?;
        roots.push(Certificate::from_pem(&pem)?);
    }
    Ok(roots)
}

// See tests in `tests/src/manager_tests.rs`
