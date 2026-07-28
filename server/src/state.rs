//! Session state manager.
//!
//! Manage sessions and their associated jobs by sending and receiving
//! messages via the gossip protocol.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use rumors::before::Rank;
use rumors::{Key, Rumors, Version};
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, error, info, o, warn};
use sush_api::JobStartParams;
use sush_common::jobs::{JobId, JobStatus, JobStatusMap, Session, SignedJob};
use tokio::sync::watch;
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

use crate::executor::Executor;
use crate::interactive::SocketSender;
use crate::messages::{Error, Event, JobEvent, JobRequest, Message, Request, SessionRequest};
use crate::output::JobOutputDir;

#[derive(Clone, Debug)]
pub struct State {
    /// The ID of the baseboard (sled) the server is running on.
    own_baseboard: BaseboardId,
    /// The set of running jobs *everywhere*, tagged by start wall-clock time.
    running: BTreeMap<(JobId, BaseboardId), DateTime<Utc>>,
    /// The set of *all* jobs (running or stopped) *everywhere*, causally
    /// ordered; we use causal ordering to garbage-collect jobs which are the
    /// causally oldest, once the memory representation of our state gets big.
    causal_jobs: BTreeSet<(Rank, JobId, BaseboardId)>,
    /// Lookup table for job status of *all* jobs *everywhere*, pruned by the
    /// causal ordering in `causal_jobs`, and indexed first by job ID so that
    /// it's possible to ask "what's the status of this job across the rack?"
    job_status: BTreeMap<JobId, JobStatusMap>,
    /// The current state of the active session, if any.
    session: SessionState,
    /// Attachment points (socket senders) for interactive jobs.
    attachments: BTreeMap<JobId, watch::Receiver<Option<SocketSender>>>,
}

impl State {
    pub fn new(own_baseboard: BaseboardId) -> Self {
        Self {
            own_baseboard,
            running: Default::default(),
            causal_jobs: Default::default(),
            job_status: Default::default(),
            session: Default::default(),
            attachments: Default::default(),
        }
    }

    pub fn get_job_status(&self, job_id: &JobId) -> Option<&JobStatusMap> {
        self.job_status.get(job_id)
    }

    pub fn set_job_status(
        &mut self,
        job_id: &JobId,
        baseboard_id: &BaseboardId,
        status: JobStatus,
    ) {
        self.job_status
            .entry(job_id.to_owned())
            .or_default()
            .insert(baseboard_id.clone(), status);
        self.evict_old_history();
    }

    /// Evict causally-oldest job status entries once we exceed
    /// `MAX_HISTORY`. A job may appear more than once in `causal_jobs`
    /// (once per causal event: start, and stop or error), so the
    /// causally-oldest entry isn't automatically safe to evict;
    /// it may be the *start* event of a job that's still running,
    /// whose terminal event (and thus later `causal_jobs` entry)
    /// hasn't happened yet. We only ever evict full job entries,
    /// and only for jobs that aren't currently running anywhere.
    fn evict_old_history(&mut self) {
        while self.job_status.len() > MAX_HISTORY {
            let evictable = self
                .causal_jobs
                .iter()
                .map(|(_, job_id, _)| job_id)
                .find(|job_id| self.running.keys().all(|(id, _)| id != *job_id))
                .cloned();
            let Some(job_id) = evictable else {
                // Everything we know about is still running somewhere;
                // there's nothing safe to evict yet.
                break;
            };
            self.job_status.remove(&job_id);
            self.causal_jobs.retain(|(_, id, _)| id != &job_id);
        }
    }

    pub fn get_attachment(&self, job_id: &JobId) -> Option<SocketSender> {
        self.attachments.get(job_id)?.borrow().to_owned()
    }
}

/// Maximum number of historical job statuses to retain before evicting them.
/// This is specified as 32 (maximum sleds per rack) times 2,048 (maximum
/// "scrollback" per sled).
const MAX_HISTORY: usize = 32 * 2048;

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
        queued_jobs: BTreeMap<JobId, (SignedJob, JobStartParams)>,
    },
}

impl SessionState {
    pub fn session(&self) -> Option<Session> {
        use SessionState::*;
        match self {
            Inactive => None,
            Active { session, .. } => Some(*session.clone()),
        }
    }
}

impl State {
    pub fn session(&self) -> Option<Session> {
        self.session.session()
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
                                queued_jobs: BTreeMap::new(),
                            }
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
                                    queued_jobs: BTreeMap::new(),
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
                            Some(Ordering::Equal) => self.session = Inactive,
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
                        if let Self {
                            session:
                                Active {
                                    session,
                                    queued_jobs,
                                    ..
                                },
                            ..
                        } = self
                        {
                            let payload = signed.payload().clone();
                            let job_id = payload.job_id.clone();

                            // A job ID that has a status has already run,
                            // here or elsewhere; resubmitting it can never
                            // advance the chain (it will never again match
                            // `next_job_id`), so there's no point queuing it.
                            // And if we're at capacity with a new ID, drop it
                            // rather than grow without bound; a well-behaved
                            // client can resubmit once earlier jobs are done.
                            if self.job_status.contains_key(&job_id) {
                                warn!(
                                    log,
                                    "ignoring resubmission of already started job";
                                    "job_id" => %job_id
                                );
                            } else if queued_jobs.len() >= MAX_QUEUED_JOBS
                                && !queued_jobs.contains_key(&job_id)
                            {
                                warn!(
                                    log,
                                    "dropping job request, too many jobs queued";
                                    "job_id" => %job_id,
                                    "limit" => MAX_QUEUED_JOBS
                                );
                            } else {
                                queued_jobs.insert(job_id, (signed.clone(), params.clone()));
                            }

                            // Then, pull out the next job to execute (if any),
                            // repeatedly. We loop because adding this new job
                            // may have "filled a hole" in the hash chain, and
                            // there may be an unbounded number of
                            // newly-ready-to-run jobs after it in the queue.
                            // Once we reach a fixed point, we have nothing
                            // further to do.
                            while let Some((request, params)) =
                                queued_jobs.remove(&session.next_job_id())
                            {
                                let (tx_attachment, rx_attachment) = watch::channel(None);
                                let payload = request.payload();
                                let job_id = payload.job_id();
                                if self
                                    .job_status
                                    .get(job_id)
                                    .map(|status| status.get(&self.own_baseboard).is_none())
                                    .unwrap_or(true)
                                {
                                    executor.job_start(payload.clone(), params, tx_attachment);
                                    self.attachments.insert(job_id.clone(), rx_attachment);
                                }
                                session.job_started(request);
                            }
                        }
                    }
                    JobRequest::Stop(job_id) => {
                        // If we can't remove the job from the queued jobs,
                        // then it's possible it has been already executed
                        // (or is starting to be). We cannot rely on it
                        // already being present in the started jobs state,
                        // because this is updated asynchronously, so we
                        // unconditionally tell the executor to stop the
                        // job, even if it may not have ever existed. If we
                        // don't have a session, we still want to stop the
                        // job, because it could be from another session.
                        if let Active { queued_jobs, .. } = &mut self.session {
                            queued_jobs.remove(job_id);
                        }
                        executor.job_stop(job_id);
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
                        self.causal_jobs.insert((
                            incoming_version.rank(),
                            job_id.clone(),
                            baseboard_id.clone(),
                        ));
                        self.set_job_status(
                            job_id,
                            baseboard_id,
                            JobStatus::Started {
                                job_id: job_id.clone(),
                                time_started: *when,
                            },
                        );
                    }
                    JobEvent::Stop(job_id, when, result, output) => {
                        info!(log, "job stopped"; "job_id" => %job_id, "when" => %when, "result" => ?result);
                        self.attachments.remove(job_id);
                        self.running.remove(&(job_id.clone(), baseboard_id.clone()));
                        self.causal_jobs.insert((
                            incoming_version.rank(),
                            job_id.clone(),
                            baseboard_id.clone(),
                        ));
                        if let Some(JobStatus::Started {
                            job_id: jid,
                            time_started,
                        }) = self
                            .get_job_status(job_id)
                            .and_then(|m| m.get(baseboard_id))
                            .cloned()
                            && jid == *job_id
                        {
                            self.set_job_status(
                                job_id,
                                baseboard_id,
                                JobStatus::Stopped {
                                    job_id: job_id.clone(),
                                    time_started,
                                    time_stopped: *when,
                                    result: result.clone(),
                                    output: output.clone(),
                                },
                            );
                        }
                        if *baseboard_id == self.own_baseboard {
                            executor.job_stopped(job_id);
                        }
                    }
                    JobEvent::Error(job_id, when, error) => {
                        error!(log, "job error"; "job_id" => %job_id, "when" => %when, "error" => %error);
                        self.attachments.remove(job_id);
                        self.running.remove(&(job_id.clone(), baseboard_id.clone()));
                        self.causal_jobs.insert((
                            incoming_version.rank(),
                            job_id.clone(),
                            baseboard_id.clone(),
                        ));
                        self.set_job_status(
                            job_id,
                            baseboard_id,
                            JobStatus::Error {
                                job_id: job_id.clone(),
                                time_error: *when,
                                error: error.clone(),
                            },
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
