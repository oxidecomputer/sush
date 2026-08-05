//! Session state manager.
//!
//! Manage sessions and their associated jobs by sending and receiving
//! messages via the gossip protocol.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use rumors::{Key, Rumors, Version};
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, error, info, o, warn};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_api::JobStartParams;
use sush_common::jobs::{JobId, JobStatus, JobStatusMap, Session, SessionId, SignedJob};
use sush_common::keys::{KeyError, KeyId, Signature};

use crate::executor::Executor;
use crate::history::JobHistory;
use crate::job::SocketSender;
use crate::messages::{
    CertRequest, Error, Event, JobEvent, JobRequest, Message, Request, SessionRequest,
};
use crate::output::JobOutputDir;

pub type AttachmentPoints = BTreeMap<JobId, watch::Receiver<Option<SocketSender>>>;
pub type Certificates = BTreeMap<KeyId, CertState>;
pub type QueuedJobs = BTreeMap<JobId, (SignedJob, JobStartParams)>;
pub type RunningJobs = BTreeMap<(JobId, BaseboardId), DateTime<Utc>>;

/// Maximum certificate chain length.
pub const MAX_CERT_CHAIN_LEN: usize = 10;

/// Maximum number of job request signing certificates.
/// The ideal number of certs is 1, so this need not be large.
pub const MAX_CERTS: usize = 100;

/// Maximum number of jobs a session may have queued (submitted, but not
/// yet next in the causal chain to run). Bounds memory in the presence
/// of out-of-order, duplicate, or malformed submissions.
pub const MAX_QUEUED_JOBS: usize = 1_000;

#[derive(Clone, Debug)]
pub enum SessionState {
    Inactive {
        /// Last observed session request.
        frontier: Version,
    },
    Active {
        /// Last observed session request.
        frontier: Version,
        /// Start of this session; identity anchor.
        started: Version,
        /// The active session.
        session: Box<Session>,
        /// Jobs waiting to run in this session.
        queued_jobs: QueuedJobs,
    },
}

impl SessionState {
    fn frontier(&self) -> Version {
        use SessionState::*;
        match self {
            Inactive { frontier } => frontier.clone(),
            Active { frontier, .. } => frontier.clone(),
        }
    }

    fn active_session(&mut self) -> Option<SessionGuard<'_>> {
        use SessionState::*;
        match self {
            Inactive { .. } => None,
            Active {
                session,
                queued_jobs,
                ..
            } => Some(SessionGuard {
                inner: session,
                queued_jobs,
            }),
        }
    }

    pub fn session(&self) -> Option<&Session> {
        use SessionState::*;
        match self {
            Inactive { .. } => None,
            Active { session, .. } => Some(session),
        }
    }

    fn queued_jobs(&self) -> Option<&QueuedJobs> {
        use SessionState::*;
        match self {
            Inactive { .. } => None,
            Active { queued_jobs, .. } => Some(queued_jobs),
        }
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::Inactive {
            frontier: Version::new(),
        }
    }
}

/// A dynamic guard around an active session and its job queue.
struct SessionGuard<'a> {
    inner: &'a mut Session,
    queued_jobs: &'a mut QueuedJobs,
}

impl<'a> SessionGuard<'a> {
    pub fn session_id(&self) -> &SessionId {
        self.inner.session_id()
    }

    pub fn job_started(&mut self, job: SignedJob) {
        self.inner.job_started(job)
    }

    pub fn skip_job(&mut self, job_id: &JobId) {
        self.inner.skip_job(job_id.clone())
    }

    pub fn next_queued_job(&mut self) -> Option<(SignedJob, JobStartParams)> {
        self.queued_jobs.remove(&self.inner.next_job_id())
    }

    pub fn enqueue_job(
        &mut self,
        log: &Logger,
        history: &mut JobHistory,
        running: &RunningJobs,
        own_baseboard: &BaseboardId,
        job: SignedJob,
        params: JobStartParams,
    ) {
        let job_id = job.job_id().clone();
        if history.contains(&job_id) {
            // Note but otherwise ignore the duplicate job.
            info!(log, "already started job"; "job_id" => %job_id);
        } else if self.queued_jobs.len() >= MAX_QUEUED_JOBS
            && !self.queued_jobs.contains_key(&job_id)
        {
            // We have no choice; drop the job on the floor.
            warn!(log, "too many jobs queued"; "job_id" => %job_id, "max" => MAX_QUEUED_JOBS);
        } else {
            // Insert the job into our queue and record its new status.
            self.queued_jobs.insert(job_id.clone(), (job, params));
            history.set_job_status(
                &job_id,
                own_baseboard,
                JobStatus::Queued {
                    job_id: job_id.clone(),
                    time_queued: Utc::now(),
                },
                None,
                Some(self.queued_jobs),
                running,
            );
        }
    }

    pub fn cancel_job(
        &mut self,
        job_id: &JobId,
        own_baseboard: &BaseboardId,
        history: &mut JobHistory,
        running: &RunningJobs,
    ) {
        self.queued_jobs.remove(job_id);
        history.transition_job_status(
            job_id,
            own_baseboard,
            None,
            |old_status| match old_status {
                None | Some(JobStatus::Queued { .. }) => Some(JobStatus::Cancelled {
                    job_id: job_id.clone(),
                    time_cancelled: Utc::now(),
                }),
                _ => None,
            },
            Some(self.queued_jobs),
            running,
        );
    }

    /// Pull out the next job to execute (if any), repeatedly.
    /// We loop because adding or skipping a job may have "filled a hole"
    /// in the hash chain, and there may be an unbounded number of
    /// newly-ready-to-run jobs after it in the queue. Once we reach
    /// a fixed point, we have nothing further to do.
    pub fn execute_ready_jobs(
        &mut self,
        own_baseboard: &BaseboardId,
        certs: &mut Certificates,
        history: &mut JobHistory,
        executor: &mut Executor,
        attachments: &mut AttachmentPoints,
    ) {
        while let Some((request, params)) = self.next_queued_job() {
            let (tx_attachment, rx_attachment) = watch::channel(None);
            let job_id = request.payload().job_id().to_owned();
            if history
                .get_job_status(&job_id)
                .map(|status| matches!(status.get(own_baseboard), Some(JobStatus::Queued { .. })))
                .unwrap_or(true)
            {
                executor.job_start(certs, request.clone(), params, tx_attachment);
                attachments.insert(job_id.clone(), rx_attachment);
            }
            self.job_started(request);
        }
    }
}

#[derive(Debug)]
pub struct State {
    /// The ID of the baseboard (sled) the server is running on.
    own_baseboard: BaseboardId,
    /// Status of all jobs everywhere (lossy).
    history: JobHistory,
    /// The set of running jobs everywhere, tagged by start wall-clock time.
    running: RunningJobs,
    /// The current state of the active session, if any.
    session: SessionState,
    /// Attachment points (socket senders) for interactive jobs.
    attachments: AttachmentPoints,
    /// Job request signing certificates.
    certs: Certificates,
    /// Hard-coded root certificate key IDs. Self-signed certificates
    /// not in this set will be revoked with prejudice.
    roots: Box<[KeyId]>,
}

impl State {
    pub fn new(own_baseboard: BaseboardId, root_certs: &[Certificate]) -> Self {
        let certs = root_certs
            .iter()
            .map(|cert| {
                (
                    KeyId::try_from(cert).expect("root certificate must be well-formed"),
                    CertState::Unknown(Box::new(cert.clone())),
                )
            })
            .collect::<BTreeMap<KeyId, CertState>>();
        let roots: Box<[KeyId]> = certs.keys().cloned().collect();
        let mut new = Self {
            own_baseboard,
            running: Default::default(),
            history: Default::default(),
            session: Default::default(),
            attachments: Default::default(),
            certs,
            roots: roots.clone(),
        };
        new.validate_certs(&roots);
        for root in &roots {
            assert!(new.certs[root].is_valid());
        }
        new
    }

    pub fn get_attachment(&self, job_id: &JobId) -> Option<SocketSender> {
        self.attachments.get(job_id)?.borrow().to_owned()
    }

    pub fn session(&self) -> Option<&Session> {
        self.session.session()
    }

    pub fn history(&self) -> &JobHistory {
        &self.history
    }

    pub fn get_job_status(&self, job_id: &JobId) -> Option<&JobStatusMap> {
        self.history.get_job_status(job_id)
    }

    fn import_cert(&mut self, cert: &Certificate) -> Result<KeyId, KeyError> {
        if self.certs.len() >= MAX_CERTS {
            return Err(KeyError::TooManyCerts(MAX_CERTS));
        }

        let key_id = KeyId::try_from(cert)?;
        if let Some(CertState::Revoked(_, when)) = self.certs.get(&key_id) {
            return Err(KeyError::Revoked(key_id, *when));
        }

        self.certs
            .insert(key_id.clone(), CertState::Unknown(Box::new(cert.clone())));
        Ok(key_id)
    }

    pub fn cert_chain(&self, key_id: &KeyId) -> Result<Vec<Certificate>, KeyError> {
        cert_chain(&self.certs, key_id)
    }

    pub fn num_certs(&self) -> usize {
        self.certs.len()
    }

    fn update(
        &mut self,
        log: &Logger,
        executor: &mut Executor,
        // We don't use the `key` here because we only redact messages once
        // they're committed to persistent storage:
        _key: Key,
        incoming_version: &Version,
        message: &Arc<Message>,
    ) -> Result<(), Error> {
        use SessionState::*;
        match message.as_ref() {
            Message::Request(request) => match request {
                Request::Cert(cert_request) => match cert_request.as_ref() {
                    CertRequest::Import(cert) => match self.import_cert(cert) {
                        Ok(key_id) => {
                            info!(log, "imported certificate"; "key_id" => %key_id);
                            self.validate_certs(&self.roots.clone());
                        }
                        Err(error) => {
                            error!(log, "ignoring invalid certificate"; "cert" => ?cert, "error" => %error);
                        }
                    },
                    CertRequest::Revoke(key_id, when) => {
                        if self.roots.contains(key_id) {
                            error!(log, "refusing to revoke root certificate"; "key_id" => %key_id);
                        } else if let Some(cert) = self.certs.get_mut(key_id) {
                            *cert = CertState::Revoked(key_id.clone(), *when);
                            info!(log, "revoked known certificate"; "key_id" => %key_id);
                        } else {
                            self.certs
                                .insert(key_id.clone(), CertState::Revoked(key_id.clone(), *when));
                            info!(log, "revoked unknown certificate"; "key_id" => %key_id);
                        }
                    }
                },
                Request::Session(session_request) => match session_request.as_ref() {
                    SessionRequest::Start(session_id) => match &mut self.session {
                        // Re-announcement of active session; absorb and ignore.
                        Active {
                            frontier, session, ..
                        } if session.session_id() == session_id => {
                            *frontier |= incoming_version.clone();
                            info!(log, "duplicate session start"; "session_id" => %session_id);
                        }

                        // If the incoming new session is in the *strict
                        // causal future* of everything we have observed,
                        // adopt it regardless of our current state. Every
                        // other peer will make the same decision, so it
                        // will come to dominate the network entirely.
                        Inactive { frontier } | Active { frontier, .. }
                            if *incoming_version > *frontier =>
                        {
                            self.session = Active {
                                frontier: self.session.frontier() | incoming_version.clone(),
                                started: incoming_version.clone(),
                                session: Box::new(Session::new(session_id.clone())),
                                queued_jobs: QueuedJobs::new(),
                            }
                        }

                        // When the incoming session is concurrent, we can't
                        // establish which is older, so we have to kill both
                        // sessions. Every peer will make this same decision,
                        // so as a partition resolves, both sessions will be
                        // killed everywhere.
                        Active {
                            frontier,
                            started,
                            session,
                            ..
                        } if incoming_version.partial_cmp(frontier).is_none() => {
                            let error = Error::ConcurrentSessions {
                                own_session: session.session_id().clone(),
                                own_version: started.clone(),
                                incoming_session: session_id.clone(),
                                incoming_version: incoming_version.clone(),
                            };
                            self.session = Inactive {
                                frontier: &*frontier | incoming_version.clone(),
                            };
                            return Err(error);
                        }

                        // Stale (≤ frontier) or concurrent while inactive; OBE.
                        // Absorb and ignore.
                        Inactive { frontier, .. } | Active { frontier, .. } => {
                            info!(
                                log,
                                "stale session start";
                                "session_id" => %session_id,
                                "frontier" => %frontier,
                                "incoming_version" => %incoming_version,
                            );
                            *frontier |= incoming_version.clone();
                        }
                    },
                    SessionRequest::Stop(session_id) => {
                        // Any session stop request for a session that isn't
                        // ours is silently ignored. Even in the case of
                        // arbitrary causal reordering (which we must handle),
                        // this is safe, because we're guaranteed (1) that a
                        // stop must come *after* its corresponding start, and
                        // (2) that all sessions are locally causally ordered
                        // relative to one another, because we create this
                        // ordering above when handling session-start. Together,
                        // this means that we can't fail to react to a stop for
                        // the active session.
                        if let Active {
                            frontier, session, ..
                        } = &self.session
                            && session.session_id() == session_id
                        {
                            self.session = Inactive {
                                frontier: frontier.clone(),
                            }
                        }
                    }
                    SessionRequest::Skip(session_id, job_id) => {
                        if let Some(mut session) = self.session.active_session()
                            && session.session_id() == session_id
                        {
                            session.skip_job(job_id);
                            session.cancel_job(
                                job_id,
                                &self.own_baseboard,
                                &mut self.history,
                                &self.running,
                            );
                            session.execute_ready_jobs(
                                &self.own_baseboard,
                                &mut self.certs,
                                &mut self.history,
                                executor,
                                &mut self.attachments,
                            );
                        } else {
                            info!(
                                log,
                                "skipping job in inactive or invalid session";
                                "session_id" => %session_id
                            );
                        }
                    }
                },
                Request::Job(job_request) => match job_request.as_ref() {
                    JobRequest::Start(signed, params) => {
                        // TODO: When we implement
                        // https://github.com/oxidecomputer/sush/issues/23, we
                        // should check for revocation here before executing the
                        // job. This enforces revocation globally, instead of
                        // just when the job is injected first into the system.

                        // The session must be active and must match the
                        // submitted job.
                        //
                        // It is safe to discard all other jobs. By cases:
                        //
                        // - If the job came from a session in the causal
                        // past of our own, the session has been superseded,
                        // so we should not run it.
                        // - If the job came from a session concurrent to
                        // our own, both sessions should be annihilated, so
                        // we should not run it.
                        // - If the job came from a session in the causal
                        // future of our own, contradiction: we consume
                        // messages in causal order, so it's not possible to
                        // receive a job from a session before that
                        // session's own start (since each session is
                        // linearized by its accepting server).
                        if let Some(mut session) = self.session.active_session() {
                            session.enqueue_job(
                                log,
                                &mut self.history,
                                &self.running,
                                &self.own_baseboard,
                                signed.clone(),
                                params.clone(),
                            );
                            session.execute_ready_jobs(
                                &self.own_baseboard,
                                &mut self.certs,
                                &mut self.history,
                                executor,
                                &mut self.attachments,
                            );
                        }
                    }
                    JobRequest::Stop(job_id) => {
                        executor.job_stop(job_id);
                        if let Some(mut session) = self.session.active_session() {
                            session.cancel_job(
                                job_id,
                                &self.own_baseboard,
                                &mut self.history,
                                &self.running,
                            );
                        }
                    }
                },
            },
            Message::Event(baseboard_id, event) => match event {
                // Track the active set of known-running jobs anywhere in the rack.
                Event::Job(job_event) => match job_event {
                    JobEvent::Start(job_id, when) => {
                        info!(log, "job started"; "job_id" => %job_id, "when" => %when);
                        self.running
                            .insert((job_id.clone(), baseboard_id.clone()), *when);
                        self.history.set_job_status(
                            job_id,
                            baseboard_id,
                            JobStatus::Started {
                                job_id: job_id.clone(),
                                time_started: *when,
                            },
                            Some(incoming_version.rank()),
                            self.session.queued_jobs(),
                            &self.running,
                        );
                    }
                    JobEvent::Stop(job_id, when, result, output) => {
                        info!(log, "job stopped"; "job_id" => %job_id, "when" => %when, "result" => ?result);
                        if baseboard_id == &self.own_baseboard {
                            self.attachments.remove(job_id);
                        }
                        self.running.remove(&(job_id.clone(), baseboard_id.clone()));
                        self.history.transition_job_status(
                            job_id,
                            baseboard_id,
                            Some(incoming_version.rank()),
                            |old_status| match old_status {
                                Some(JobStatus::Started { time_started, .. }) => {
                                    Some(JobStatus::Stopped {
                                        job_id: job_id.clone(),
                                        time_started: *time_started,
                                        time_stopped: *when,
                                        result: result.clone(),
                                        output: output.clone(),
                                    })
                                }
                                _ => None,
                            },
                            self.session.queued_jobs(),
                            &self.running,
                        );
                        if *baseboard_id == self.own_baseboard {
                            executor.job_stopped(job_id);
                        }
                    }
                    JobEvent::Error(job_id, when, error) => {
                        error!(log, "job error"; "job_id" => %job_id, "when" => %when, "error" => %error);
                        if baseboard_id == &self.own_baseboard {
                            self.attachments.remove(job_id);
                        }
                        self.running.remove(&(job_id.clone(), baseboard_id.clone()));
                        self.history.set_job_status(
                            job_id,
                            baseboard_id,
                            JobStatus::Error {
                                job_id: job_id.clone(),
                                time_error: *when,
                                error: error.clone(),
                            },
                            Some(incoming_version.rank()),
                            self.session.queued_jobs(),
                            &self.running,
                        );
                        if *baseboard_id == self.own_baseboard {
                            executor.job_stopped(job_id);
                        }
                    }
                },
                Event::Error(error) => {
                    error!(log, "session error"; "error" => %error);
                }
            },
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct StateManager {}

impl StateManager {
    /// Run the state machine over all locally-injected `messages` and
    /// remote-received gossip messages, terminating when no further
    /// requests, events, or messages can be received. Returns a shared
    /// `State` that will be asynchronously updated in response to
    /// messages and events.
    pub fn run<R>(
        log: Logger,
        output_dir: JobOutputDir,
        own_baseboard: BaseboardId,
        mut requests: R,
        rumors: Rumors<Message>,
        roots: &[Certificate],
        shutdown: CancellationToken,
    ) -> (watch::Receiver<State>, JoinHandle<()>)
    where
        R: Stream<Item = Request> + Send + Unpin + 'static,
    {
        // We report our current state through a watch channel.
        let (tx_state, rx_state) = watch::channel(State::new(own_baseboard.clone(), roots));

        // We process messages in causal order, so that we can rely on
        // things like "the session stop happens after its corresponding
        // session start". This costs a little extra in-memory bookkeeping
        // and computation, but makes it much easier to ensure that our
        // state machine is correct, because it now only has to be correct
        // in the face of arbitrary *causal* reorderings.
        let mut causal_messages = rumors.causal_messages();

        // The executor needs to have access to send messages back.
        let (mut executor, mut events) = Executor::new(
            log.new(o!("component" => "executor")),
            output_dir,
            shutdown.child_token(),
        );

        // We will drop this once we want to drain the remaining messages.
        let mut rumors = Some(rumors);

        (
            rx_state,
            spawn(async move {
                info!(log, "managing state");

                // These flip both to `true` once our two input streams (local
                // requests and local events from the executor) terminate or
                // we're shutting down. At this point, we must drop `rumors`
                // and thereby permit its own `unordered_messages` stream to
                // eventually be drained; we do this so that we fully update
                // the local state until nothing more is left to do.
                let mut requests_empty = false;
                let mut events_empty = false;

                loop {
                    let message = causal_messages.borrow_next();

                    // Once we drain the requests and events, we drop `rumors` so
                    // that if there are no outstanding copies elsewhere, we will
                    // drain it and then break.
                    //
                    // If there are still gossip sessions happening, those will
                    // complete and we will process their messages into the state.
                    if requests_empty && events_empty {
                        rumors = None;
                    }

                    select! {
                        // Forward local requests into the rumors state,
                        // so they are processed by the state machine.
                        next = requests.next(), if !requests_empty => match next {
                            // When our incoming stream of locally injected messages
                            // ends, we have no more local messages to process, but
                            // we need to let all spawned tasks by the executor
                            // quiesce, updating the state all the way.
                            None => requests_empty = true,
                            Some(request) => if let Some(rumors) = &rumors {
                                debug!(log, "forwarding request to gossip network"; "request" => ?request);
                                rumors.send(Message::Request(request));
                            },
                        },

                        // Handle events produced by the executor.
                        next = events.next(), if !events_empty => match next {
                            None => events_empty = true,
                            Some(event) => if let Some(rumors) = &rumors {
                                debug!(log, "forwarding event to gossip network"; "event" => ?event);
                                rumors.send(Message::Event(own_baseboard.clone(), event));
                            },
                        },

                        // Handle messages from the gossip network.
                        next = message => match next {
                            None => {
                                // There are no more events, requests, or messages from
                                // the gossip network. We're done.
                                info!(log, "gossip network quiescent");
                                break;
                            }
                            Some((key, version, message)) => {
                                // We unconditionally mark the watch sender as modified
                                // even though it might not be, because *most* of the
                                // messages cause *some* modification of the state, and we
                                // would rather be safe against future code changes than
                                // manually tracking precisely which messages *don't* modify
                                // state. The cost is a few spurious wakeups.
                                tx_state.send_modify(|state| {
                                    if let Err(error) = state.update(&log, &mut executor, key, version, message) {
                                        error!(log, "state update failed"; "error" => ?error);
                                        if let Some(rumors) = &rumors {
                                            debug!(log, "sending error to gossip network"; "error" => ?error);
                                            rumors.send(Message::Event(own_baseboard.clone(), Event::Error(error)));
                                        }
                                    }
                                });
                            },
                        },

                        // Stop processing requests on shutdown.
                        _ = shutdown.cancelled(), if !requests_empty => {
                            requests_empty = true;
                        }
                    }
                }
            }),
        )
    }
}

/// Certificate validation state.
///
/// Transitions are monotone: state only moves upward in this
/// lattice, so the resulting map is a function of the set of
/// messages received, independent of their delivery order.
///
/// ```text
///              Revoked
///             ▲   ▲   ▲
///            /    |    \
///        Valid    |    Invalid
///            ▲    |    ▲
///             \   |   /
///              Unknown ──┐
///                  ▲     │ (issuer not yet seen)
///                  └─────┘
/// ```
///
/// Allowed transitions are `Unknown → Valid` on successful chain validation;
/// `Unknown → Unknown` when an unknown issuer is encountered during validation;
/// `Unknown → Invalid` on a permanent failure (bad signature or encoding);
/// and any state `→ Revoked`, from which no state ever returns.
#[derive(Debug)]
pub enum CertState {
    Unknown(Box<Certificate>),
    Valid(Box<Certificate>),
    Invalid(KeyError),
    Revoked(KeyId, DateTime<Utc>),
}

impl CertState {
    fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    fn map_valid<R>(&self, f: impl FnOnce(&Certificate) -> &R) -> Option<&R> {
        if let Self::Valid(cert) = self {
            Some(f(cert))
        } else {
            None
        }
    }

    fn validate(self, certs: &Certificates, roots: &[KeyId]) -> Self {
        if let Self::Unknown(cert) = self {
            macro_rules! with_err {
                ($expr:expr) => {
                    match $expr {
                        Ok(res) => res,
                        Err(err) => return Self::Invalid(err.into()),
                    }
                };
            }

            // Verify the certificate signature.
            // TODO: Mythos report #82-86: check expiry, basicConstraints, keyUsage
            let signature = with_err!(Signature::try_from(cert.as_ref()));
            let tbs = with_err!(cert.tbs_certificate.to_der());
            let subject = &cert.tbs_certificate.subject;
            let issuer = &cert.tbs_certificate.issuer;
            let root = subject == issuer;
            if root {
                let key_id = with_err!(KeyId::try_from(issuer));
                if !roots.contains(&key_id) {
                    return Self::Invalid(KeyError::SelfSigned);
                }
                with_err!(
                    signature.verify_with_spki(&tbs, &cert.tbs_certificate.subject_public_key_info)
                );
            } else {
                let issuer_key_id = with_err!(KeyId::try_from(issuer));
                if let Some(issuer) = certs.get(&issuer_key_id)
                    && let Some(spki) =
                        issuer.map_valid(|cert| &cert.tbs_certificate.subject_public_key_info)
                {
                    with_err!(signature.verify_with_spki(&tbs, spki));
                } else {
                    // Don't complain about the missing cert, because certs could
                    // arrive out of order.
                    return Self::Unknown(cert);
                }
            }
            Self::Valid(cert)
        } else {
            self
        }
    }
}

impl State {
    /// Move as many certificates as possible from `Unknown → `Valid`.
    /// This allows us to eventually validate chains whose elements
    /// may arrive out of order.
    fn validate_certs(&mut self, roots: &[KeyId]) {
        loop {
            let pending = self
                .certs
                .iter()
                .filter(|(_, c)| c.is_unknown())
                .map(|(k, _)| k.clone())
                .collect::<Vec<KeyId>>();
            let mut progressed = false;
            for key_id in pending {
                let state = self.certs.remove(&key_id).unwrap();
                let validated = state.validate(&self.certs, roots);
                progressed |= !validated.is_unknown();
                self.certs.insert(key_id, validated);
            }
            if !progressed {
                break;
            }
        }
    }
}

/// Return the cert chain for the given key in root-to-leaf order.
/// Will never return an empty chain.
pub fn cert_chain(certs: &Certificates, key_id: &KeyId) -> Result<Vec<Certificate>, KeyError> {
    let mut chain = Vec::new();
    let mut key_id = key_id.to_owned();
    loop {
        if chain.len() >= MAX_CERT_CHAIN_LEN {
            return Err(KeyError::CertChainTooLong);
        }
        let cert = match certs.get(&key_id) {
            None | Some(CertState::Unknown(_)) => return Err(KeyError::MissingCert(key_id)),
            Some(CertState::Valid(cert)) => *cert.clone(),
            Some(CertState::Invalid(error)) => {
                return Err(KeyError::InvalidCert(error.to_string()));
            }
            Some(CertState::Revoked(key_id, when)) => {
                return Err(KeyError::Revoked(key_id.clone(), *when));
            }
        };
        chain.push(cert.clone());
        if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
            break;
        }
        key_id = KeyId::try_from(&cert.tbs_certificate.issuer)?;
    }
    assert!(!chain.is_empty());
    chain.reverse();
    Ok(chain)
}
