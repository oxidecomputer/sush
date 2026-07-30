//! Session state manager.
//!
//! Manage sessions and their associated jobs by sending and receiving
//! messages via the gossip protocol.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use rumors::{Key, Rumors, Version};
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, error, info, o, warn};
use tokio::sync::watch;
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

use sush_api::JobStartParams;
use sush_common::jobs::{JobId, JobStatus, JobStatusMap, Session, SessionId, SignedJob};

use crate::executor::Executor;
use crate::history::JobHistory;
use crate::interactive::SocketSender;
use crate::messages::{Error, Event, JobEvent, JobRequest, Message, Request, SessionRequest};
use crate::output::JobOutputDir;

pub type QueuedJobs = BTreeMap<JobId, (SignedJob, JobStartParams)>;
pub type RunningJobs = BTreeMap<(JobId, BaseboardId), DateTime<Utc>>;
pub type AttachmentPoints = BTreeMap<JobId, watch::Receiver<Option<SocketSender>>>;

/// Maximum number of jobs a session may have queued (submitted, but not
/// yet next in the causal chain to run). Bounds memory in the presence
/// of out-of-order, duplicate, or malformed submissions.
const MAX_QUEUED_JOBS: usize = 1_000;

#[derive(Clone, Debug, Default)]
pub enum SessionState {
    #[default]
    Inactive,
    Active {
        session: Box<Session>,
        session_start: Version,
        queued_jobs: QueuedJobs,
    },
}

impl SessionState {
    fn active_session(&mut self) -> Option<SessionGuard<'_>> {
        use SessionState::*;
        match self {
            Inactive => None,
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
            Inactive => None,
            Active { session, .. } => Some(session),
        }
    }

    fn queued_jobs(&self) -> Option<&QueuedJobs> {
        use SessionState::*;
        match self {
            Inactive => None,
            Active { queued_jobs, .. } => Some(queued_jobs),
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
            warn!(log, "already started job"; "job_id" => %job_id);
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
        history: &mut JobHistory,
        executor: &mut Executor,
        attachments: &mut AttachmentPoints,
    ) {
        while let Some((request, params)) = self.next_queued_job() {
            let (tx_attachment, rx_attachment) = watch::channel(None);
            let payload = request.payload();
            let job_id = payload.job_id();
            if history
                .get_job_status(job_id)
                .map(|status| matches!(status.get(own_baseboard), Some(JobStatus::Queued { .. })))
                .unwrap_or(true)
            {
                executor.job_start(payload.clone(), params, tx_attachment);
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
}

impl State {
    pub fn new(own_baseboard: BaseboardId) -> Self {
        Self {
            own_baseboard,
            running: Default::default(),
            history: Default::default(),
            session: Default::default(),
            attachments: Default::default(),
        }
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
                Request::Session(session_request) => match session_request.as_ref() {
                    SessionRequest::Start(session_id) => match &mut self.session {
                        Inactive => {
                            self.session = Active {
                                session: Box::new(Session::new(session_id.clone())),
                                session_start: incoming_version.clone(),
                                queued_jobs: QueuedJobs::new(),
                            }
                        }
                        Active {
                            session,
                            session_start: created,
                            ..
                        } if session.session_id() == session_id => {
                            // Duplicate session starts; join with the incoming
                            // version and ignore.
                            *created |= incoming_version.clone();
                            info!(log, "duplicate session start"; "session_id" => %session_id);
                        }
                        Active {
                            session,
                            session_start: created,
                            ..
                        } => match (*created).partial_cmp(incoming_version) {
                            // If the incoming new session is in the *strict
                            // causal future* of our current session, then we
                            // adopt that session; every other peer will make
                            // the same decision, so it will come to dominate
                            // the network entirely.
                            Some(Ordering::Less) => {
                                self.session = Active {
                                    session: Box::new(Session::new(session_id.clone())),
                                    session_start: incoming_version.clone(),
                                    queued_jobs: QueuedJobs::new(),
                                }
                            }
                            // If we already have the newest session, then we
                            // just drop the other one on the floor.
                            Some(Ordering::Greater) => {}
                            // When the incoming session is concurrent, we can't
                            // establish which is older, so we have to kill both
                            // sessions. Every peer will make this same
                            // decision, so as a partition resolves, both
                            // sessions will be killed everywhere.
                            None => {
                                let error = Error::ConcurrentSessions {
                                    own_session: session.session_id().clone(),
                                    own_version: created.clone(),
                                    incoming_session: session_id.clone(),
                                    incoming_version: incoming_version.clone(),
                                };
                                self.session = Inactive;
                                return Err(error);
                            }
                            // No sessions can have equal creation times,
                            // because rumors guarantees that no messages have
                            // equal versions. However, we can't panic here, so
                            // invalidate both sessions.
                            Some(Ordering::Equal) => {
                                error!(
                                    log,
                                    "causality violation: distinct sessions with equal versions";
                                    "session_id" => %session.session_id(),
                                    "version" => %created,
                                );
                                self.session = Inactive;
                            }
                        },
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
                        if let Active { session, .. } = &self.session
                            && session.session_id() == session_id
                        {
                            self.session = Inactive
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
                                &mut self.history,
                                executor,
                                &mut self.attachments,
                            );
                        } else {
                            warn!(
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
                        self.attachments.remove(job_id);
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
                        self.attachments.remove(job_id);
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
        shutdown: CancellationToken,
    ) -> watch::Receiver<State>
    where
        R: Stream<Item = Request> + Send + Unpin + 'static,
    {
        // We report our current state through a watch channel.
        let (tx_state, rx_state) = watch::channel(State::new(own_baseboard.clone()));

        // We process messages in causal order, so that we can rely on
        // things like "the session stop happens after its corresponding
        // session start". This costs a little extra in-memory bookkeeping
        // and computation, but makes it much easier to ensure that our
        // state machine is correct, because it now only has to be correct
        // in the face of arbitrary *causal* reorderings.
        let mut causal_messages = rumors.causal_messages();

        // The executor needs to have access to send messages back.
        let (mut executor, mut events) =
            Executor::new(log.new(o!("component" => "executor")), output_dir, shutdown);

        // We will drop this once we want to drain the remaining messages.
        let mut rumors = Some(rumors);

        spawn({
            async move {
                info!(log, "managing state");

                // These flip both to `true` once our two input streams (local
                // requests and local events from the executor) terminate. At
                // this point, we must drop `rumors` and thereby permit its own
                // `unordered_messages` stream to eventually be drained; we do
                // this so that we fully update the local state until nothing
                // more is left to do.
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
                    }
                }
            }
        });

        rx_state
    }
}
