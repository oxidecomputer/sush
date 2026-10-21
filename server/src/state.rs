// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Session state manager.
//!
//! Manage sessions and their associated jobs by sending and receiving
//! messages via the gossip protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::{FutureExt as _, Stream, StreamExt};
use lru::LruCache;
use rumors::{CausalMessages, Network, Rumors, Version};
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, error, info, o, warn};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;

use sush_api::JobStartParams;
use sush_common::jobs::{
    Access, JobId, JobStatus, JobStatusMap, LastJob, ProcessError, Session, SessionId,
    SessionPreimage, SessionSeq, SkipReason, VerifiedJob,
};
use sush_common::keys::{KeyError, KeyId};
use sush_common::targets::Cubbies;
use sush_common::version::VersionInfo;

use crate::certs::Certificates;
use crate::executor::{Executor, PathIsolation};
use crate::gossip::{Seed, Universe};
use crate::history::JobHistory;
use crate::identities::Identities;
use crate::job::SocketSender;
use crate::locker::Locker;
use crate::locker::bookmark::SushBookmark;
use crate::locker::boundary::{Boundary, BoundaryStore};
use crate::messages::v0::{Event, JobEvent, JobRequest, Message, Request, SessionRequest};
use crate::messages::{VersionedMessage, VersionedMessage::*};
use crate::output::JobOutputDir;
use crate::rack::Rack;

pub type AttachmentPoints = BTreeMap<JobId, watch::Receiver<Option<SocketSender>>>;
pub type GossipNetwork = Rumors<VersionedMessage, SushBookmark>;
pub type GossipSeed = Seed<VersionedMessage>;
pub type GossipUniverse = Universe<VersionedMessage>;
pub type QueuedJobs = BTreeMap<JobId, QueuedJob>;

/// Maximum number of jobs a session may have queued (submitted, but not
/// yet next in the causal chain to run). Bounds memory in the presence
/// of out-of-order, duplicate, or malformed submissions.
pub const MAX_QUEUED_JOBS: usize = 1_000;

/// A job waiting in the session queue for its turn in the causal chain.
/// Jobs replayed from history that predates our join keep the chain intact
/// but never execute here.
#[derive(Clone, Debug)]
pub struct QueuedJob {
    pub job: VerifiedJob,
    pub params: JobStartParams,
    pub replayed: bool,
}

/// Maximum number of session starts pending on a sled. Each one
/// comes from a session start ceremony, so this need not be large.
const MAX_PENDING_STARTS: NonZeroUsize = NonZeroUsize::new(10).unwrap();

/// A session start that no verified job has confirmed yet.
#[derive(Debug)]
struct PendingStart {
    preimage: SessionPreimage,
    actor: KeyId,
    live: bool,
}

#[derive(Clone, Debug, Default)]
pub enum SessionState {
    #[default]
    Inactive,
    Active {
        /// Where the active session falls in the signer-assigned
        /// order. A start wins the slot only by exceeding this
        /// sequence number, with ties broken by session id.
        seq: SessionSeq,

        /// Whether this session's start arrived as live traffic
        /// rather than replayed history. A session replayed onto a
        /// sled with no boundary record may include jobs a previous
        /// life ran, so [`Past::screen`] refuses to run its jobs.
        live: bool,

        /// The active session.
        session: Box<Session>,

        /// Jobs waiting to run in this session.
        queued_jobs: QueuedJobs,

        /// Keys the starter has granted attach access, and how much.
        attach_grants: BTreeMap<KeyId, Access>,
    },
}

impl SessionState {
    pub fn session(&self) -> Option<&Session> {
        use SessionState::*;
        match self {
            Inactive => None,
            Active { session, .. } => Some(session),
        }
    }

    /// The attach access `key_id` has to this session's interactive
    /// jobs, if any.
    pub fn attach_access(&self, key_id: &KeyId) -> Option<Access> {
        use SessionState::*;
        let Active {
            session,
            attach_grants,
            ..
        } = self
        else {
            return None;
        };
        if session.started_by() == Some(key_id) {
            return Some(Access::ReadWrite);
        }
        attach_grants.get(key_id).copied()
    }

    /// Where an active session stands in the total order of sessions
    /// by signer-assigned sequence number, then ID.
    pub fn rank(&self) -> Option<(SessionSeq, SessionId)> {
        use SessionState::*;
        match self {
            Inactive => None,
            Active { seq, session, .. } => Some((*seq, session.session_id())),
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

/// What [`Past::screen`] decides about a job of the active session.
enum Admission {
    /// Execute normally.
    Admit,

    /// Refuse to execute the job because the session has been superseded.
    Refuse,
}

/// This incarnation's relationship to its own past: where it entered
/// the universe, what a previous life committed to, and what it left
/// running.
#[derive(Debug)]
pub struct Past {
    /// The version of this life's first send: our announcement that
    /// we joined this universe. A message whose causal history
    /// includes the announcement is live, and so is the announcement
    /// itself. Every other message, prior to or concurrent with the
    /// announcement, is replayed. A replayed event from our own
    /// baseboard came from a previous life. Not persisted; each
    /// life computes its own.
    birth: Version,

    /// The boundary record, naming what a previous life committed to
    /// executing. `None` means no life ever committed to a job here,
    /// or the record was lost and abandoned.
    committed: Option<Box<Boundary>>,

    /// The gossip universe this life entered.
    network: Network,

    /// Jobs whose replayed start events say a previous life ran them.
    /// The end of such a job may replay later and remove it from the
    /// set, so which jobs truly lack an end is known only when replay
    /// finishes.
    zombies: BTreeSet<JobId>,

    /// Zombies already declared interrupted. The interrupted event
    /// applies only after a gossip round trip, so history may still
    /// show these jobs running; this set keeps [`State::settle`] from
    /// ruling twice.
    reaped: BTreeSet<JobId>,

    /// The boundary job this life has ruled on. [`State::settle`]
    /// rules at most once per life.
    adjudicated: Option<JobId>,
}

impl Past {
    fn new(birth: Version, committed: Option<Box<Boundary>>, network: Network) -> Self {
        Past {
            birth,
            committed,
            network,
            zombies: BTreeSet::new(),
            reaped: BTreeSet::new(),
            adjudicated: None,
        }
    }

    /// Decide whether the active session may run a job here.
    /// A committed session may only resume in the network where
    /// this sled committed to it, and sessions are superseded
    /// by ones with a higher sequence number.
    fn screen(&self, session: SessionId, seq: SessionSeq, live: bool) -> Admission {
        match &self.committed {
            Some(boundary)
                if seq > boundary.seq
                    || (boundary.network == self.network && boundary.session == session) =>
            {
                Admission::Admit
            }
            Some(_) => Admission::Refuse,
            None if live => Admission::Admit,
            None => Admission::Refuse,
        }
    }

    /// Return the current boundary record for this universe.
    fn boundary(&self) -> Option<&Boundary> {
        self.committed
            .as_deref()
            .filter(|boundary| boundary.network == self.network)
    }

    /// Whether a message at `version` is live traffic rather than
    /// replayed history; see [`Past::birth`]. Equality admits the
    /// birth announcement itself.
    fn is_live(&self, version: &Version) -> bool {
        *version >= self.birth
    }
}

/// A state machine input. Everything that changes the state arrives
/// as one of these.
enum Input {
    /// The rack's cubby map changed.
    Cubbies(Cubbies),

    /// The gossip network delivered a message.
    Gossip(Version, Arc<VersionedMessage>),

    /// All ready messages have been drained.
    Drained,
}

/// A state machine output.
#[derive(Debug)]
enum Output {
    Run(Box<Run>),
    Ran(JobStatus),
    Stop(JobId),
    Gossip(Message),
}

impl Output {
    fn job_event(own_baseboard: &BaseboardId, event: JobEvent) -> Self {
        Self::Gossip(Message::Event(own_baseboard.to_owned(), Event::Job(event)))
    }
}

/// Everything the executor needs to launch a job.
#[derive(Debug)]
struct Run {
    job: VerifiedJob,
    params: JobStartParams,
    boundary: Boundary,
    attachment: watch::Sender<Option<SocketSender>>,
}

#[derive(Debug)]
pub struct State {
    /// Information about the rack in which we're running.
    rack: Rack,
    /// Status of all jobs everywhere (lossy).
    history: JobHistory,
    /// The current state of the active session, if any.
    session: SessionState,
    /// Session starts awaiting a verified job, by session ID.
    pending_starts: LruCache<SessionId, PendingStart>,
    /// Attachment points (socket senders) for interactive jobs.
    attachments: AttachmentPoints,
    /// Job request signing certificates.
    certs: Certificates,
    /// SSH identities for request attribution.
    identities: Identities,
    /// This incarnation's relationship to its own past.
    past: Past,
}

impl State {
    pub fn new(
        own_baseboard: BaseboardId,
        trust_anchors: &[Certificate],
        past: Past,
    ) -> Result<Self, KeyError> {
        Ok(Self {
            rack: Rack::new(own_baseboard),
            history: Default::default(),
            session: Default::default(),
            pending_starts: LruCache::new(MAX_PENDING_STARTS),
            attachments: Default::default(),
            certs: Certificates::new(trust_anchors)?,
            identities: Default::default(),
            past,
        })
    }

    pub fn get_attachment(&self, job_id: &JobId) -> Option<SocketSender> {
        self.attachments.get(job_id)?.borrow().to_owned()
    }

    pub fn session(&self) -> Option<&Session> {
        self.session.session()
    }

    pub fn rank(&self) -> Option<(SessionSeq, SessionId)> {
        self.session.rank()
    }

    /// Where a start of `session_id` would stand in the total order of
    /// sessions, if one is pending on this sled.
    pub fn pending_rank(&self, session_id: SessionId) -> Option<(SessionSeq, SessionId)> {
        self.pending_starts
            .peek(&session_id)
            .map(|start| (start.preimage.seq, session_id))
    }

    pub fn attach_access(&self, key_id: &KeyId) -> Option<Access> {
        self.session.attach_access(key_id)
    }

    pub fn rack(&self) -> &Rack {
        &self.rack
    }

    pub fn history(&self) -> &JobHistory {
        &self.history
    }

    pub fn certs(&self) -> &Certificates {
        &self.certs
    }

    pub fn identities(&self) -> &Identities {
        &self.identities
    }

    /// Jobs running on our own baseboard, according to our history.
    pub fn own_running_jobs(&self) -> BTreeSet<JobId> {
        self.history
            .running_jobs()
            .keys()
            .filter(|(_, baseboard)| baseboard == self.rack.own_baseboard())
            .map(|(job_id, _)| *job_id)
            .collect()
    }

    /// Jobs a previous life of this server started and left running.
    fn zombies(&self) -> BTreeSet<JobId> {
        self.past
            .zombies
            .iter()
            .filter(|job_id| {
                self.history
                    .running_jobs()
                    .contains_key(&(**job_id, self.rack.own_baseboard().clone()))
            })
            .copied()
            .collect()
    }

    fn is_live(&self, version: &Version) -> bool {
        self.past.is_live(version)
    }

    pub fn get_job_status(&self, job_id: &JobId) -> Option<&JobStatusMap> {
        self.history.get_job_status(job_id)
    }

    fn skip_queued_jobs(&self, now: DateTime<Utc>) -> Vec<Output> {
        let mut outputs = Vec::new();
        for (job_id, queued) in self.session.queued_jobs().into_iter().flatten() {
            if !queued.replayed && self.rack.runs_here(&queued.job) {
                outputs.push(Output::job_event(
                    self.rack.own_baseboard(),
                    JobEvent::Skipped(*job_id, now, SkipReason::SessionEnded),
                ));
            }
        }
        outputs
    }

    /// Rule on the jobs a previous life left unresolved. Call only
    /// once ready messages have drained: an undelivered replayed end
    /// may yet clear a zombie, and an early settle would declare a
    /// finished job interrupted.
    fn settle(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        network: Option<Network>,
    ) -> Vec<Output> {
        let mut outputs = self.reap_zombies(log, now);
        if network.is_some() {
            outputs.extend(self.adjudicate_boundary(log, now));
        }
        outputs
    }

    /// Declare interrupted every job a previous life left running,
    /// excluding jobs already reaped. Zombies come only from replayed
    /// start events, so a job this incarnation started is never a
    /// candidate.
    fn reap_zombies(&mut self, log: &Logger, now: DateTime<Utc>) -> Vec<Output> {
        let mut outputs = Vec::new();
        for job_id in self.zombies() {
            if self.past.reaped.contains(&job_id) {
                continue;
            }
            self.past.reaped.insert(job_id);
            outputs.push(Output::job_event(
                self.rack.own_baseboard(),
                JobEvent::Error(job_id, now, ProcessError::Interrupted),
            ));
            warn!(log, "interrupted job from a previous life"; "job_id" => %job_id);
        }
        outputs
    }

    /// Rule on the boundary job if replay gave it no status on our
    /// baseboard: announce its recorded ending, or interrupted when
    /// none was recorded. No status means its fate never left this
    /// sled, and no other sled can ever report it; a replayed start
    /// makes it a zombie instead, and a replayed end settles it.
    /// The ruling goes only to the universe the job started in. Any
    /// other universe never saw the job and hears nothing, and
    /// re-entering the job's own universe replays the earlier ruling
    /// as a status, which stops a second announcement.
    fn adjudicate_boundary(&mut self, log: &Logger, now: DateTime<Utc>) -> Vec<Output> {
        let Some(boundary) = self.past.boundary() else {
            return Vec::new();
        };
        let (job_id, status) = (boundary.job, boundary.status.clone());
        if self.past.adjudicated == Some(job_id) {
            return Vec::new();
        }
        self.past.adjudicated = Some(job_id);
        let witnessed = self
            .get_job_status(&job_id)
            .is_some_and(|status| status.get(self.rack.own_baseboard()).is_some());
        if witnessed {
            return Vec::new();
        }
        // A stopped ending announces the start and stop pair, so the
        // ordinary status transitions apply on every sled; a bare stop
        // with no prior start would be dropped.
        let events = match status {
            Some(JobStatus::Stopped {
                time_started,
                time_stopped,
                result,
                output,
                ..
            }) => vec![
                JobEvent::Start(job_id, time_started),
                JobEvent::Stop(job_id, time_stopped, result, output),
            ],
            Some(JobStatus::Error {
                time_error, error, ..
            }) => vec![JobEvent::Error(job_id, time_error, error)],
            Some(_) | None => {
                vec![JobEvent::Error(job_id, now, ProcessError::Interrupted)]
            }
        };
        warn!(log, "adjudicated an unwitnessed job from a previous life"; "job_id" => %job_id);
        events
            .into_iter()
            .map(|event| Output::job_event(self.rack.own_baseboard(), event))
            .collect()
    }

    /// Advance the state machine by one input, returning the outputs
    /// for the driver to interpret. `network` is `None` while the
    /// driver drains without a gossip connection.
    fn step(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        network: Option<Network>,
        input: Input,
    ) -> Vec<Output> {
        match input {
            Input::Cubbies(cubbies) => {
                self.rack.set_cubbies(cubbies);
                Vec::new()
            }
            Input::Gossip(version, message) => self.update(log, now, network, &version, &message),
            Input::Drained => self.settle(log, now, network),
        }
    }

    fn update(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        network: Option<Network>,
        incoming_version: &Version,
        message: &Arc<VersionedMessage>,
    ) -> Vec<Output> {
        match message.as_ref() {
            V0(Message::Request(request)) => {
                let actor = request.actor();
                let log = log.new(o!("actor" => actor.to_string()));
                match request {
                    Request::Identity(r) => {
                        self.identities.apply(&log, r.request());
                        Vec::new()
                    }
                    Request::Session(r) => self.handle_session_request(
                        &log,
                        now,
                        network,
                        incoming_version,
                        actor,
                        r.request(),
                    ),
                    Request::Job(r) => self.handle_job_request(
                        &log,
                        now,
                        network,
                        incoming_version,
                        actor,
                        r.request(),
                    ),
                }
            }
            V0(Message::Event(baseboard_id, event)) => {
                self.handle_event(log, incoming_version, baseboard_id, event)
            }
            Unknown { version, .. } => {
                if self.rack.unknown_version(version.clone()) {
                    warn!(log, "ignoring messages from a newer peer"; "version" => version);
                }
                Vec::new()
            }
        }
    }

    #[must_use]
    fn handle_session_request(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        network: Option<Network>,
        incoming_version: &Version,
        actor: &KeyId,
        request: &SessionRequest,
    ) -> Vec<Output> {
        use SessionState::*;

        let mut outputs = Vec::new();
        match request {
            SessionRequest::Start(preimage) => {
                let session_id = preimage.session_id();
                match &self.session {
                    // Re-announcement of the active session; ignore.
                    Active { session, .. } if session.session_id() == session_id => {
                        info!(log, "duplicate session start"; "session_id" => %session_id);
                    }

                    // This start does not outrank the active session;
                    // ignore it.
                    Active { seq, .. }
                        if Some((preimage.seq, session_id)) <= self.session.rank() =>
                    {
                        info!(
                            log, "stale session start";
                            "session_id" => %session_id,
                            "seq" => %preimage.seq,
                            "active_seq" => %seq,
                        );
                    }

                    // Ignore a resubmitted start, so its sender can't
                    // become the starter.
                    Inactive | Active { .. } if self.pending_starts.contains(&session_id) => {
                        info!(
                            log, "duplicate pending session start";
                            "session_id" => %session_id, "actor" => %actor,
                        );
                    }

                    // Keep an unsigned start pending until confirmed by
                    // a verified job.
                    Inactive | Active { .. } => {
                        info!(
                            log, "session start pending";
                            "session_id" => %session_id, "actor" => %actor,
                        );
                        self.pending_starts.put(
                            session_id,
                            PendingStart {
                                preimage: preimage.clone(),
                                actor: actor.clone(),
                                live: self.past.is_live(incoming_version),
                            },
                        );
                    }
                }
            }
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
                    && session.session_id() == *session_id
                {
                    if session.started_by() != Some(actor) {
                        warn!(
                            log, "ignoring session stop from non-starter";
                            "session_id" => %session_id, "actor" => %actor,
                        );
                    } else {
                        info!(
                            log, "session stopped";
                            "session_id" => %session_id, "actor" => %actor,
                        );
                        outputs.extend(self.skip_queued_jobs(now));
                        self.session = Inactive;
                    }
                }
            }
            SessionRequest::AllowAttach(session_id, key_id, access) => {
                if let Active {
                    session,
                    attach_grants,
                    ..
                } = &mut self.session
                    && session.session_id() == *session_id
                {
                    if session.started_by() == Some(actor) {
                        attach_grants.insert(key_id.clone(), *access);
                        info!(
                            log, "attach allowed";
                            "key_id" => %key_id, "access" => ?access, "actor" => %actor,
                        );
                    } else {
                        warn!(
                            log, "ignoring attach grant from non-starter";
                            "key_id" => %key_id, "actor" => %actor,
                        );
                    }
                }
            }
            SessionRequest::DenyAttach(session_id, key_id) => {
                if let Active {
                    session,
                    attach_grants,
                    ..
                } = &mut self.session
                    && session.session_id() == *session_id
                {
                    if session.started_by() == Some(actor) {
                        attach_grants.remove(key_id);
                        info!(
                            log, "attach denied";
                            "key_id" => %key_id, "actor" => %actor,
                        );
                    } else {
                        warn!(
                            log, "ignoring attach denial from non-starter";
                            "key_id" => %key_id, "actor" => %actor,
                        );
                    }
                }
            }
            SessionRequest::Skip(session_id, job_id) => {
                let replayed = !self.is_live(incoming_version);
                if let Some(session) = match &mut self.session {
                    SessionState::Active { session, .. } => Some(session),
                    _ => None,
                } && session.session_id() == *session_id
                {
                    if session.started_by() != Some(actor) {
                        warn!(
                            log, "ignoring job skip from non-starter";
                            "job_id" => %job_id, "actor" => %actor,
                        );
                    } else if session.skip_job(*job_id) {
                        info!(
                            log, "job skipped";
                            "job_id" => %job_id, "actor" => %actor,
                        );
                        self.cancel_job(now, job_id, actor, replayed);
                        outputs.extend(self.release_ready_jobs(log, now, network));
                    } else {
                        info!(
                            log, "ignoring inapplicable job skip";
                            "job_id" => %job_id, "actor" => %actor,
                        );
                    }
                } else {
                    info!(
                        log,
                        "skipping job in inactive or invalid session";
                        "session_id" => %session_id
                    );
                }
            }
        }
        outputs
    }

    /// Confirm a pending start of `session_id`, if it still outranks
    /// the active session. Every peer applies the same total order,
    /// so they all converge on the same session.
    #[must_use]
    fn confirm_start(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        session_id: SessionId,
    ) -> Vec<Output> {
        let Some(start) = self.pending_starts.pop(&session_id) else {
            return Vec::new();
        };
        if Some((start.preimage.seq, session_id)) <= self.session.rank() {
            info!(
                log, "stale session start";
                "session_id" => %session_id,
                "seq" => %start.preimage.seq,
                "active" => ?self.session.rank(),
            );
            return Vec::new();
        }
        info!(
            log, "session started";
            "session_id" => %session_id, "actor" => %start.actor,
        );
        let mut session = Session::started(session_id, start.actor);
        if let Some(boundary) = self
            .past
            .boundary()
            .filter(|boundary| boundary.session == session_id)
        {
            info!(
                log, "resuming committed session at its successor";
                "session_id" => %session_id,
                "successor" => %boundary.successor,
            );
            session.resume_at(boundary.successor);
        }
        let outputs = self.skip_queued_jobs(now);
        self.session = SessionState::Active {
            seq: start.preimage.seq,
            live: start.live,
            session: Box::new(session),
            queued_jobs: QueuedJobs::new(),
            attach_grants: BTreeMap::new(),
        };
        outputs
    }

    #[must_use]
    fn handle_job_request(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        network: Option<Network>,
        incoming_version: &Version,
        actor: &KeyId,
        request: &JobRequest,
    ) -> Vec<Output> {
        let mut outputs = Vec::new();
        match request {
            JobRequest::Start(signed, params) => {
                let job = match self.certs.verify(signed) {
                    Ok(job) => job,
                    Err(error) => {
                        warn!(
                            log, "refusing unverified job";
                            "job_id" => %signed.job_id(),
                            "actor" => %actor,
                            "error" => %error,
                        );
                        return outputs;
                    }
                };

                // A verified job confirms its session's pending start.
                // The job then joins the queue only if its session is
                // active; any other session was stopped or superseded.
                // A refused job that targets this sled gets a Skipped
                // status here, which tells its submitter it will not
                // run.
                let session_id = signed.payload().session_id();
                let live = self.is_live(incoming_version);
                outputs.extend(self.confirm_start(log, now, session_id));
                if self
                    .session
                    .session()
                    .is_some_and(|s| s.session_id() == session_id)
                {
                    self.enqueue_job(log, now, job, params.clone(), actor, !live);
                    outputs.extend(self.release_ready_jobs(log, now, network));
                } else {
                    let job_id = *signed.job_id();
                    warn!(
                        log, "skipping job for inactive session";
                        "job_id" => %job_id,
                        "session_id" => %session_id,
                        "actor" => %actor,
                    );
                    if live && self.rack.runs_here(signed) && !self.history.contains(&job_id) {
                        outputs.push(Output::job_event(
                            self.rack.own_baseboard(),
                            JobEvent::Skipped(job_id, now, SkipReason::SessionEnded),
                        ));
                    }
                }
            }
            JobRequest::Stop(job_id) => {
                outputs.push(Output::Stop(*job_id));
                let replayed = !self.is_live(incoming_version);
                self.cancel_job(now, job_id, actor, replayed);
            }
        }
        outputs
    }

    /// Track the active set of known-running jobs anywhere in the rack.
    #[must_use]
    fn handle_event(
        &mut self,
        log: &Logger,
        incoming_version: &Version,
        baseboard_id: &BaseboardId,
        event: &Event,
    ) -> Vec<Output> {
        let log = log.new(o!("sled" => baseboard_id.to_string()));
        let mut outputs = Vec::new();
        match event {
            Event::Job(job_event) => {
                let status = match job_event {
                    JobEvent::Start(job_id, when) => {
                        // A start never displaces a terminal status.
                        // After an identity change, an adjudicated
                        // Interrupted and a late replayed start are
                        // concurrent, and the verdict must win in
                        // both arrival orders.
                        if self
                            .history
                            .get_job_status(job_id)
                            .and_then(|status| status.get(baseboard_id))
                            .is_some_and(|status| status.is_terminal())
                        {
                            info!(log, "ignoring a start for a settled job"; "job_id" => %job_id);
                            return outputs;
                        }
                        info!(log, "job started"; "job_id" => %job_id, "when" => %when);

                        // A replayed start from our own baseboard
                        // names a job whose process died with a
                        // previous life, and no executor will ever
                        // end it. Unless replay delivers its ending,
                        // we report it interrupted once replay
                        // drains.
                        if baseboard_id == self.rack.own_baseboard()
                            && !self.past.is_live(incoming_version)
                        {
                            self.past.zombies.insert(*job_id);
                        }
                        self.history.set_job_status(
                            job_id,
                            baseboard_id,
                            JobStatus::Started {
                                job_id: *job_id,
                                time_started: *when,
                            },
                            Some(incoming_version.rank()),
                            self.session.queued_jobs(),
                        );
                        None
                    }
                    JobEvent::Stop(job_id, when, result, output) => {
                        info!(log, "job stopped"; "job_id" => %job_id, "when" => %when, "result" => ?result);
                        if baseboard_id == self.rack.own_baseboard() {
                            self.attachments.remove(job_id);
                            self.past.zombies.remove(job_id);
                        }
                        self.history.transition_job_status(
                            job_id,
                            baseboard_id,
                            Some(incoming_version.rank()),
                            |old_status| match old_status {
                                Some(JobStatus::Started { time_started, .. }) => {
                                    Some(JobStatus::Stopped {
                                        job_id: *job_id,
                                        time_started: *time_started,
                                        time_stopped: *when,
                                        result: result.clone(),
                                        output: output.clone(),
                                    })
                                }
                                // An interrupted declaration raced this stop event.
                                // The real result wins in either arrival order,
                                // though the start time died with the previous life.
                                Some(JobStatus::Error {
                                    error: ProcessError::Interrupted,
                                    time_error,
                                    ..
                                }) => Some(JobStatus::Stopped {
                                    job_id: *job_id,
                                    time_started: *time_error,
                                    time_stopped: *when,
                                    result: result.clone(),
                                    output: output.clone(),
                                }),
                                _ => None,
                            },
                            self.session.queued_jobs(),
                        )
                    }
                    JobEvent::Error(job_id, when, error) => {
                        error!(log, "job error"; "job_id" => %job_id, "when" => %when, "error" => %error);
                        if baseboard_id == self.rack.own_baseboard() {
                            self.attachments.remove(job_id);
                            self.past.zombies.remove(job_id);
                        }
                        self.history.transition_job_status(
                            job_id,
                            baseboard_id,
                            Some(incoming_version.rank()),
                            // An error never displaces a terminal status, so a
                            // stop that raced an interrupted declaration keeps
                            // the real result.
                            |old_status| match old_status {
                                None
                                | Some(JobStatus::Queued { .. })
                                | Some(JobStatus::Started { .. }) => Some(JobStatus::Error {
                                    job_id: *job_id,
                                    time_error: *when,
                                    error: error.clone(),
                                }),
                                _ => None,
                            },
                            self.session.queued_jobs(),
                        )
                    }
                    JobEvent::Skipped(job_id, when, reason) => {
                        info!(
                            log, "job skipped";
                            "job_id" => %job_id, "when" => %when, "reason" => %reason,
                        );
                        self.history.transition_job_status(
                            job_id,
                            baseboard_id,
                            Some(incoming_version.rank()),
                            // A skip is the reporting sled's decision about
                            // itself, and never displaces a terminal status it
                            // already reported.
                            |old_status| match old_status {
                                None
                                | Some(JobStatus::Queued { .. })
                                | Some(JobStatus::Started { .. }) => Some(JobStatus::Skipped {
                                    job_id: *job_id,
                                    time_skipped: *when,
                                    reason: *reason,
                                }),
                                _ => None,
                            },
                            self.session.queued_jobs(),
                        )
                    }
                };
                if let Some(status) = status
                    && status.is_terminal()
                    && baseboard_id == self.rack.own_baseboard()
                {
                    outputs.push(Output::Ran(status));
                }
            }
            Event::Version(info) => {
                if self.rack.known_version(baseboard_id.clone(), info.clone()) {
                    info!(log, "sled version"; "version" => %info);
                }
            }
        };
        outputs
    }

    fn enqueue_job(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        job: VerifiedJob,
        params: JobStartParams,
        actor: &KeyId,
        replayed: bool,
    ) {
        let SessionState::Active { queued_jobs, .. } = &mut self.session else {
            return;
        };
        let job_id = *job.job_id();
        let targeted = self.rack.runs_here(&job);

        // Adjudication can give the boundary job a status before its
        // request replays. The queue releases jobs in order, so
        // dropping that request would wedge the session behind the
        // boundary job forever. A replayed request therefore always
        // joins the queue; only a live duplicate is dropped.
        if !replayed && self.history.contains(&job_id) {
            // Note but otherwise ignore the duplicate job.
            info!(log, "already started job"; "job_id" => %job_id);
        } else if !replayed
            && queued_jobs.len() >= MAX_QUEUED_JOBS
            && !queued_jobs.contains_key(&job_id)
        {
            // We have no choice; discard the job.
            warn!(log, "too many jobs queued"; "job_id" => %job_id, "max" => MAX_QUEUED_JOBS);
        } else {
            // Insert the job into our queue. Every job joins the
            // queue to keep the causal chain whole, but only jobs
            // targeting this sled that can actually run here record
            // a local status.
            queued_jobs.insert(
                job_id,
                QueuedJob {
                    job,
                    params,
                    replayed,
                },
            );
            if targeted && !replayed {
                self.history.set_job_status(
                    &job_id,
                    self.rack.own_baseboard(),
                    JobStatus::Queued {
                        job_id,
                        time_queued: now,
                        actor: actor.clone(),
                    },
                    None,
                    Some(queued_jobs),
                );
            }
        }
    }

    fn cancel_job(&mut self, now: DateTime<Utc>, job_id: &JobId, actor: &KeyId, replayed: bool) {
        let SessionState::Active { queued_jobs, .. } = &mut self.session else {
            return;
        };
        queued_jobs.remove(job_id);
        if replayed {
            return;
        }
        self.history.transition_job_status(
            job_id,
            self.rack.own_baseboard(),
            None,
            |old_status| match old_status {
                None | Some(JobStatus::Queued { .. }) => Some(JobStatus::Cancelled {
                    job_id: *job_id,
                    time_cancelled: now,
                    actor: actor.clone(),
                }),
                _ => None,
            },
            Some(queued_jobs),
        );
    }

    /// Pull out the next job to execute (if any), repeatedly.
    /// We loop because adding or skipping a job may have "filled a hole"
    /// in the hash chain, and there may be an unbounded number of
    /// newly-ready-to-run jobs after it in the queue. Once we reach
    /// a fixed point, we have nothing further to do.
    #[must_use]
    fn release_ready_jobs(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        network: Option<Network>,
    ) -> Vec<Output> {
        let mut outputs = Vec::new();
        let SessionState::Active {
            session,
            seq,
            live,
            queued_jobs,
            ..
        } = &mut self.session
        else {
            return outputs;
        };

        // If there's no universe, just drain the queue and advance the chain.
        let Some(network) = network else {
            let mut n = 0;
            while let Some(queued) = queued_jobs.remove(&session.next_job_id()) {
                session.job_started(queued.job.into_signed());
                n += 1;
            }
            if n > 0 {
                warn!(log, "skipped queued jobs while draining"; "n" => n);
            }
            return outputs;
        };

        loop {
            let next_id = session.next_job_id();
            if !queued_jobs.contains_key(&next_id) {
                break;
            }

            let admission = self.past.screen(session.session_id(), *seq, *live);
            let QueuedJob {
                job: request,
                params,
                replayed,
            } = queued_jobs.remove(&next_id).expect("checked above");
            let job_id = request.payload().job_id().to_owned();
            if self.rack.runs_here(&request) {
                if matches!(admission, Admission::Refuse) {
                    if !replayed {
                        warn!(log, "skipping a superseded session's job"; "job_id" => %job_id);
                        outputs.push(Output::job_event(
                            self.rack.own_baseboard(),
                            JobEvent::Skipped(job_id, now, SkipReason::SessionSuperseded),
                        ));
                    }
                } else if self
                    .history
                    .get_job_status(&job_id)
                    .map(|status| {
                        matches!(
                            status.get(self.rack.own_baseboard()),
                            Some(JobStatus::Queued { .. })
                        )
                    })
                    .unwrap_or(true)
                {
                    match Executor::check_command(request.payload()) {
                        Err(error) => outputs.push(Output::job_event(
                            self.rack.own_baseboard(),
                            JobEvent::Error(job_id, now, error),
                        )),
                        Ok(()) => {
                            let (attachment, rx_attachment) = watch::channel(None);
                            self.attachments.insert(job_id, rx_attachment);
                            outputs.push(Output::Run(Box::new(Run {
                                job: request.clone(),
                                params,
                                attachment,
                                boundary: Boundary {
                                    network,
                                    session: session.session_id(),
                                    seq: *seq,
                                    job: job_id,
                                    successor: session
                                        .session_id()
                                        .next_job_id(&LastJob::Some((*request).clone())),
                                    status: None,
                                },
                            })));
                        }
                    }
                }
            }
            session.job_started(request.into_signed());
        }
        outputs
    }
}

/// Feed one input through the state machine, then apply its outputs.
///
/// We unconditionally mark the watch sender as modified even though it
/// might not be, because *most* of the inputs cause *some* modification
/// of the state, and we would rather be safe against future code changes
/// than manually tracking precisely which inputs *don't* modify state.
/// The cost is a few spurious wakeups.
fn apply(
    log: &Logger,
    tx_state: &watch::Sender<State>,
    executor: &mut Executor,
    rumors: Option<&GossipNetwork>,
    store: &Arc<BoundaryStore>,
    input: Input,
) {
    let now = Utc::now();
    let network = rumors.map(|r| r.network());
    let mut outputs = Vec::new();
    tx_state.send_modify(|state| {
        outputs = state.step(log, now, network, input);
    });
    apply_outputs(executor, rumors, store, outputs);
}

fn apply_outputs(
    executor: &mut Executor,
    rumors: Option<&GossipNetwork>,
    store: &Arc<BoundaryStore>,
    outputs: Vec<Output>,
) {
    for output in outputs {
        match output {
            Output::Run(run) => {
                let Run {
                    job,
                    params,
                    boundary,
                    attachment,
                } = *run;
                executor.job_start(job, params, attachment, boundary);
            }
            Output::Stop(job_id) => executor.job_stop(&job_id),
            Output::Ran(status) => {
                executor.job_stopped(status.job_id());
                let store = store.clone();
                spawn(async move { store.record_status(&status).await });
            }
            Output::Gossip(message) => {
                if let Some(rumors) = rumors {
                    gossip(rumors, message.into());
                }
            }
        }
    }
}

/// Apply every message already delivered locally, without waiting for
/// more. Afterwards the local set is quiescent.
fn drain_ready(
    log: &Logger,
    causal_messages: &mut CausalMessages<VersionedMessage>,
    tx_state: &watch::Sender<State>,
    executor: &mut Executor,
    rumors: Option<&GossipNetwork>,
    store: &Arc<BoundaryStore>,
) {
    while let Some(Some((version, message))) = causal_messages.next().now_or_never() {
        apply(
            log,
            tx_state,
            executor,
            rumors,
            store,
            Input::Gossip(version, message),
        );
    }
}

/// Enter a universe: judge the boundary record, announce this build,
/// and mark the birth at the announce's version.
fn enter_universe(
    own_baseboard: BaseboardId,
    anchors: &[Certificate],
    store: &BoundaryStore,
    rumors: &GossipNetwork,
) -> Result<State, KeyError> {
    let committed = store.boundary().map(Box::new);
    let birth = gossip(
        rumors,
        Message::Event(
            own_baseboard.clone(),
            Event::Version(VersionInfo::current()),
        )
        .into(),
    );
    State::new(
        own_baseboard,
        anchors,
        Past::new(birth, committed, rumors.network()),
    )
}

/// Send a message into the gossip set, returning the version it was
/// assigned. A send fails only on a payload that nests past the depth
/// limit or fails its own serde round trip. Both are properties of the
/// message type, which the wire tests pin, so a failure here indicates
/// incomplete test coverage.
fn gossip(rumors: &GossipNetwork, message: VersionedMessage) -> Version {
    rumors
        .send(message)
        .expect("sush messages have fixed, shallow encodings")
}

/// Grow a fresh gossip seed over sush's message type.
///
/// A peer that seeds its own network has no one to gossip with, so jobs run
/// only on the server that accepted them, and no server learns about any other
/// server's sessions. This stands in for joining the rack's network over
/// sprockets on the bootstrap network. Storage semantics are
/// [`Seed::grow`]'s.
pub async fn seed_gossip(log: &Logger, locker: &Locker) -> GossipSeed {
    Seed::grow(log, locker).await
}

#[derive(Debug)]
pub struct StateManager {}

impl StateManager {
    /// Run the state machine over all locally-injected `messages` and
    /// remote-received gossip messages, terminating when no further
    /// requests, events, or messages can be received. Returns a shared
    /// `State` that will be asynchronously updated in response to
    /// messages and events.
    ///
    /// `universe` follows the gossip network we belong to. When it changes,
    /// everything resets. Versions do not compare across universes, so no
    /// session or history bookkeeping can survive a migration; running
    /// jobs are killed, and the new universe hears nothing about them.
    ///
    /// `cubbies` follows the rack's cubby map, which survives migrations.
    #[allow(clippy::too_many_arguments)]
    pub fn run<R>(
        log: Logger,
        path_isolation: PathIsolation,
        output_dir: JobOutputDir,
        own_baseboard: BaseboardId,
        mut requests: R,
        mut cubbies: watch::Receiver<Cubbies>,
        mut universe: watch::Receiver<GossipUniverse>,
        anchors: &[Certificate],
        store: Arc<BoundaryStore>,
        shutdown: CancellationToken,
    ) -> Result<(watch::Receiver<State>, JoinHandle<()>), KeyError>
    where
        R: Stream<Item = Request> + Send + Unpin + 'static,
    {
        // We process messages in causal order, so that we can rely on
        // things like "the session stop happens after its corresponding
        // session start". This costs a little extra in-memory bookkeeping
        // and computation, but makes it much easier to ensure that our
        // state machine is correct, because it now only has to be correct
        // in the face of arbitrary *causal* reorderings.
        // `borrow_and_update` marks the value seen, so a migration
        // that landed before we subscribed does not replay as a swap.
        let Universe { rumors: initial } = universe.borrow_and_update().clone();
        let mut causal_messages = initial.causal_messages();

        // Decisions read a snapshot of the boundary, never the live
        // store: the launcher advances the store concurrently, and a
        // job committed after the snapshot is this incarnation's, not
        // the past's.
        let boundary = store.boundary();
        let boundary_store = store.clone();

        // We report our current state through a watch channel. The
        // placeholder birth is replaced before any message applies.
        let mut initial_state = State::new(
            own_baseboard.clone(),
            anchors,
            Past::new(Version::new(), None, initial.network()),
        )?;
        initial_state
            .rack
            .set_cubbies(cubbies.borrow_and_update().clone());
        let (tx_state, rx_state) = watch::channel(initial_state);
        let anchors = anchors.to_vec();

        // The executor needs to have access to send messages back.
        let (mut executor, mut events) = Executor::new(
            log.new(o!("component" => "executor")),
            path_isolation,
            output_dir,
            store,
            shutdown.child_token(),
        );

        // We will drop this once we want to drain the remaining messages.
        // The watch channel behind `universe` stores its own copy of the
        // network, so holding the receiver would keep the network from
        // draining while we wait for exactly that.
        let mut network = Some((initial, universe));

        Ok((
            rx_state,
            spawn(async move {
                info!(log, "managing state");

                // Enter the initial universe before any message is
                // processed, so the birth mark splits this life's
                // traffic from replayed history.
                if let Some((rumors, _)) = &network {
                    let entered =
                        enter_universe(own_baseboard.clone(), &anchors, &boundary_store, rumors)
                            .expect("trust anchors validated at startup");
                    tx_state.send_modify(|state| {
                        *state = entered;
                        state.rack.set_cubbies(cubbies.borrow_and_update().clone());
                    });
                }
                if let Some(boundary) = boundary.as_ref() {
                    info!(
                        log, "inherited an execution boundary; the committed session resumes at its stored successor";
                        "session_id" => %boundary.session, "job_id" => %boundary.job,
                    );
                }

                // These flip both to `true` once our two input streams (local
                // requests and local events from the executor) terminate or
                // we're shutting down. At this point, we must drop `network`
                // and thereby permit its own `unordered_messages` stream to
                // eventually be drained; we do this so that we fully update
                // the local state until nothing more is left to do.
                let mut requests_empty = false;
                let mut events_empty = false;

                // Jobs killed at a universe swap. Their terminal
                // events still arrive from the executor, and belong
                // to a universe we have left: drop them instead of
                // gossiping them.
                let mut doomed: BTreeSet<JobId> = BTreeSet::new();

                loop {
                    let message = causal_messages.next();

                    // Once we drain the requests and events, we drop `network` so
                    // that if there are no outstanding copies elsewhere, we will
                    // drain it and then break.
                    //
                    // If there are still gossip sessions happening, those will
                    // complete and we will process their messages into the state.
                    if requests_empty && events_empty {
                        network = None;
                    }

                    // Applied after the select, once `message` and the
                    // universe future have released their borrows.
                    let mut swap = false;

                    select! {
                        // Forward local requests into the rumors state,
                        // so they are processed by the state machine.
                        next = requests.next(), if !requests_empty => match next {
                            // When our incoming stream of locally injected messages
                            // ends, we have no more local messages to process, but
                            // we need to let all spawned tasks by the executor
                            // quiesce, updating the state all the way.
                            None => requests_empty = true,
                            Some(request) => if let Some((rumors, _)) = &network {
                                debug!(log, "forwarding request to gossip network"; "kind" => request.kind());
                                gossip(rumors, Message::Request(request).into());
                            },
                        },

                        // Handle events produced by the executor.
                        next = events.next(), if !events_empty => match next {
                            None => events_empty = true,
                            Some(event) => {
                                if let Event::Job(job_event) = &event
                                    && doomed.contains(job_event.job_id())
                                {
                                    debug!(log, "dropping event for a job killed at a universe swap"; "event" => ?event);
                                    if matches!(job_event, JobEvent::Stop(..) | JobEvent::Error(..)) {
                                        let job_id = *job_event.job_id();
                                        doomed.remove(&job_id);
                                    }
                                } else if let Some((rumors, _)) = &network {
                                    debug!(log, "forwarding event to gossip network"; "event" => ?event);
                                    gossip(
                                        rumors,
                                        Message::Event(own_baseboard.clone(), event).into(),
                                    );
                                }
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
                            Some((version, message)) => {
                                let live = tx_state.borrow().is_live(&version);
                                apply(
                                    &log,
                                    &tx_state,
                                    &mut executor,
                                    network.as_ref().map(|(rumors, _)| rumors),
                                    &boundary_store,
                                    Input::Gossip(version, message),
                                );
                                // Settle only after replayed traffic:
                                // replay is what reveals zombies, and a
                                // sled that settles before its universe
                                // has history adjudicates into a lonely
                                // universe, whose extra events can win
                                // the merge and erase rack history.
                                if !live {
                                    drain_ready(
                                        &log,
                                        &mut causal_messages,
                                        &tx_state,
                                        &mut executor,
                                        network.as_ref().map(|(rumors, _)| rumors),
                                        &boundary_store,
                                    );
                                    apply(
                                        &log,
                                        &tx_state,
                                        &mut executor,
                                        network.as_ref().map(|(rumors, _)| rumors),
                                        &boundary_store,
                                        Input::Drained,
                                    );
                                }
                            },
                        },

                        // Follow the rack's cubby map.
                        Ok(()) = cubbies.changed() => {
                            apply(
                                &log,
                                &tx_state,
                                &mut executor,
                                network.as_ref().map(|(rumors, _)| rumors),
                                &boundary_store,
                                Input::Cubbies(cubbies.borrow_and_update().clone()),
                            );
                        },

                        // Follow the gossip manager to a new universe,
                        // unless we're already draining.
                        Ok(()) = async {
                            match network.as_mut() {
                                Some((_, universe)) => universe.changed().await,
                                None => std::future::pending().await,
                            }
                        } => swap = true,

                        // Stop processing requests on shutdown.
                        _ = shutdown.cancelled(), if !requests_empty => {
                            requests_empty = true;
                        }
                    }

                    if swap {
                        let (rumors, universe) =
                            network.as_mut().expect("network present when it changes");
                        let fresh = universe.borrow_and_update().clone();
                        info!(log, "gossip universe changed, resetting state"; "network" => %fresh.rumors.network());
                        causal_messages = fresh.rumors.causal_messages();
                        *rumors = fresh.rumors;
                        // Jobs do not cross universes: kill whatever
                        // is in flight, and report nothing about it.
                        // The new universe never saw these jobs, and
                        // the old one is out of reach.
                        for job_id in executor.in_flight() {
                            info!(log, "killing job at universe swap"; "job_id" => %job_id);
                            executor.job_stop(&job_id);
                            doomed.insert(job_id);
                        }
                        let entered = enter_universe(
                            own_baseboard.clone(),
                            &anchors,
                            &boundary_store,
                            rumors,
                        )
                        .expect("trust anchors validated at startup");
                        tx_state.send_modify(|state| {
                            *state = entered;
                            state.rack.set_cubbies(cubbies.borrow().clone());
                        });
                        // The set received at join is already local:
                        // drain it, then settle.
                        drain_ready(
                            &log,
                            &mut causal_messages,
                            &tx_state,
                            &mut executor,
                            Some(&*rumors),
                            &boundary_store,
                        );
                        apply(
                            &log,
                            &tx_state,
                            &mut executor,
                            Some(&*rumors),
                            &boundary_store,
                            Input::Drained,
                        );
                    }
                }
            }),
        ))
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use x509_cert::time::Validity;

    use sush_common::jobs::{
        JobMode, JobOutputState, JobStartRequest, SessionPreimage, SessionSignerNonce,
        SessionSushNonce, SignedJob,
    };
    use sush_common::keys::{EphemeralKey, KeyType, Signer as _};
    use sush_common::targets::Target;

    use super::*;

    fn network(seed: u8) -> Network {
        serde_json::from_str(&format!("[{seed:?}{}]", ", 0".repeat(15))).unwrap()
    }

    fn baseboard() -> BaseboardId {
        BaseboardId {
            part_number: "913-0000019".to_string(),
            serial_number: "state-test".to_string(),
        }
    }

    fn state(past: Past) -> State {
        State::new(baseboard(), &[], past).unwrap()
    }

    fn root() -> EphemeralKey {
        let subject = "CN=Test Root,O=Oxide Computer Company,C=US";
        EphemeralKey::new_root(
            KeyType::P256,
            subject.parse().unwrap(),
            Validity::from_now(Duration::from_secs(60)).unwrap(),
        )
        .unwrap()
    }

    async fn signed_job(
        root: &mut EphemeralKey,
        job_id: JobId,
        session_id: SessionId,
        command: &str,
    ) -> SignedJob {
        root.sign(JobStartRequest::new(
            job_id,
            session_id,
            command,
            JobMode::Batch,
            Target::All,
        ))
        .await
        .unwrap()
    }

    fn discard() -> Logger {
        Logger::root(slog::Discard, o!())
    }

    fn start_job(state: &mut State, job_id: JobId, now: DateTime<Utc>) {
        let baseboard = state.rack.own_baseboard().clone();
        state.history.set_job_status(
            &job_id,
            &baseboard,
            JobStatus::Started {
                job_id,
                time_started: now,
            },
            None,
            None,
        );
    }

    fn committed_boundary(job: JobId) -> Boundary {
        Boundary {
            network: network(1),
            session: SessionId::random(),
            seq: seq(10),
            job,
            successor: JobId::random(),
            status: None,
        }
    }

    fn interrupted(output: &Output, job_id: JobId) -> bool {
        matches!(
            output,
            Output::Gossip(Message::Event(
                _,
                Event::Job(JobEvent::Error(id, _, ProcessError::Interrupted)),
            )) if *id == job_id
        )
    }

    fn past(committed: Option<Boundary>) -> Past {
        Past::new(Version::new(), committed.map(Box::new), network(1))
    }

    fn seq(millis: u64) -> SessionSeq {
        SessionSeq::from_unix_millis(millis).unwrap()
    }

    /// A preimage for a fresh session authorized at `millis`; tests
    /// reference the session by the derived id.
    fn preimage(millis: u64) -> SessionPreimage {
        SessionPreimage {
            baseboard: baseboard(),
            sush_nonce: SessionSushNonce::random(),
            signer_nonce: SessionSignerNonce::random(),
            seq: seq(millis),
        }
    }

    /// The admission rules: the committed session resumes even from
    /// replay, a session above the committed sequence number admits,
    /// and everything at or below it refuses, in any universe.
    #[test]
    fn admission_rules() {
        let session = SessionId::random();
        let committed = Boundary {
            network: network(1),
            session,
            seq: seq(10),
            job: JobId::random(),
            successor: JobId::random(),
            status: None,
        };
        let past = past(Some(committed));

        assert!(matches!(
            past.screen(session, seq(10), false),
            Admission::Admit
        ));
        assert!(matches!(
            past.screen(SessionId::random(), seq(11), false),
            Admission::Admit
        ));
        for at_or_below in [seq(10), seq(9)] {
            assert!(matches!(
                past.screen(SessionId::random(), at_or_below, true),
                Admission::Refuse
            ));
        }
    }

    /// With no record, a live session admits and a replayed one
    /// refuses: a sled that has never written a boundary cannot tell
    /// replay from re-run.
    #[test]
    fn recordless_admission_is_live_only() {
        let past = past(None);
        assert!(matches!(
            past.screen(SessionId::random(), seq(1), true),
            Admission::Admit
        ));
        assert!(matches!(
            past.screen(SessionId::random(), seq(1), false),
            Admission::Refuse
        ));
    }

    /// Settle declares a zombie interrupted exactly once.
    #[test]
    fn settle_reaps_zombies_once() {
        let log = discard();
        let now = Utc::now();
        let zombie = JobId::random();
        let mut state = state(past(None));
        state.past.zombies.insert(zombie);
        start_job(&mut state, zombie, now);

        let outputs = state.settle(&log, now, Some(network(1)));
        assert_eq!(outputs.len(), 1);
        assert!(interrupted(&outputs[0], zombie));
        assert!(state.settle(&log, now, Some(network(1))).is_empty());
    }

    /// A committed job that replay left without a status is
    /// adjudicated as interrupted, exactly once, and only in the
    /// universe the job started in. Any other universe never saw the
    /// job and hears nothing.
    #[test]
    fn adjudication_rules_only_in_the_jobs_universe() {
        let log = discard();
        let now = Utc::now();
        let job = JobId::random();
        // A sled that entered another universe never saw the job.
        let mut elsewhere = state(past(Some(committed_boundary(job))));
        elsewhere.past.network = network(2);
        assert!(elsewhere.settle(&log, now, Some(network(2))).is_empty());

        let mut state = state(past(Some(committed_boundary(job))));
        let outputs = state.settle(&log, now, Some(network(1)));
        assert_eq!(outputs.len(), 1);
        assert!(interrupted(&outputs[0], job));
        assert!(state.settle(&log, now, Some(network(1))).is_empty());
    }

    /// A witnessed boundary job keeps its replayed status: settle
    /// marks the ruling made and announces nothing.
    #[test]
    fn adjudication_defers_to_witnesses() {
        let log = discard();
        let now = Utc::now();
        let job = JobId::random();

        let mut witnessed = state(past(Some(committed_boundary(job))));
        start_job(&mut witnessed, job, now);
        assert!(witnessed.settle(&log, now, Some(network(1))).is_empty());
        assert_eq!(witnessed.past.adjudicated, Some(job));
    }

    /// Drive a [`State`] through [`State::step`] alone, over a real
    /// single-party gossip set: no sockets, no executor, no spawned
    /// tasks.
    struct Sim {
        log: Logger,
        now: DateTime<Utc>,
        anchors: Vec<Certificate>,
        rumors: GossipNetwork,
        messages: CausalMessages<VersionedMessage>,
        state: State,
    }

    impl Sim {
        /// Grow a fresh gossip set, send `history` (a previous life's
        /// traffic), then enter the universe exactly as the driver
        /// does. With an empty history, every later send is live.
        async fn new(anchors: &[Certificate], history: Vec<Message>) -> Sim {
            let log = discard();
            let rumors: GossipNetwork = Seed::grow(&log, &Locker::null()).await.into_rumors();
            for message in history {
                rumors.send(message.into()).unwrap();
            }
            let store = BoundaryStore::new(&log, &Locker::null());
            store.load().await;
            let state = enter_universe(baseboard(), anchors, &store, &rumors).unwrap();
            let messages = rumors.causal_messages();
            Sim {
                log,
                now: Utc::now(),
                anchors: anchors.to_vec(),
                rumors,
                messages,
                state,
            }
        }

        /// Swap into a fresh universe, as the driver does on a
        /// universe change.
        async fn swap(&mut self) {
            let rumors: GossipNetwork = Seed::grow(&self.log, &Locker::null()).await.into_rumors();
            let store = BoundaryStore::new(&self.log, &Locker::null());
            store.load().await;
            self.state = enter_universe(baseboard(), &self.anchors, &store, &rumors).unwrap();
            self.messages = rumors.causal_messages();
            self.rumors = rumors;
        }

        fn send(&mut self, message: Message) {
            self.rumors.send(message.into()).unwrap();
        }

        /// Step every ready message through the state machine,
        /// collecting the outputs.
        fn pump(&mut self) -> Vec<Output> {
            let mut outputs = Vec::new();
            while let Some(Some((version, message))) = self.messages.next().now_or_never() {
                outputs.extend(self.state.step(
                    &self.log,
                    self.now,
                    Some(self.rumors.network()),
                    Input::Gossip(version, message),
                ));
            }
            outputs
        }

        /// Step every ready message through without a network, as the
        /// driver does while draining at shutdown.
        fn pump_draining(&mut self) -> Vec<Output> {
            let mut outputs = Vec::new();
            while let Some(Some((version, message))) = self.messages.next().now_or_never() {
                outputs.extend(self.state.step(
                    &self.log,
                    self.now,
                    None,
                    Input::Gossip(version, message),
                ));
            }
            outputs
        }

        fn request(&mut self, request: Request) -> Vec<Output> {
            self.send(Message::Request(request));
            self.pump()
        }

        fn drained(&mut self) -> Vec<Output> {
            self.state.step(
                &self.log,
                self.now,
                Some(self.rumors.network()),
                Input::Drained,
            )
        }
    }

    /// A fresh universe with a pending session start, which the first
    /// verified job of the session confirms.
    async fn sim_with_session() -> (EphemeralKey, Sim, SessionId, Session) {
        let root = root();
        let anchors = vec![root.cert().clone()];
        let mut sim = Sim::new(&anchors, Vec::new()).await;
        let preimage = preimage(1);
        let session_id = preimage.session_id();
        sim.request(Request::session(
            root.key_id().clone(),
            SessionRequest::Start(preimage),
        ));
        (root, sim, session_id, Session::new(session_id))
    }

    /// The happy path through the step surface alone: a session start
    /// waits, a signed job confirms it and is released to run, the
    /// job's own events settle its status, and the session stops.
    #[tokio::test]
    async fn session_lifecycle_through_step() {
        let mut root = root();
        let anchors = vec![root.cert().clone()];
        let actor = root.key_id().clone();
        let mut sim = Sim::new(&anchors, Vec::new()).await;

        let preimage = preimage(1);
        let session_id = preimage.session_id();
        let session = Session::new(session_id);
        sim.request(Request::session(
            actor.clone(),
            SessionRequest::Start(preimage),
        ));
        assert!(sim.state.session.session().is_none());
        assert!(sim.state.pending_rank(session_id).is_some());

        let job_id = session.next_job_id();
        let signed = signed_job(&mut root, job_id, session_id, "true").await;
        let outputs = sim.request(Request::job(
            actor.clone(),
            JobRequest::Start(signed, JobStartParams::default()),
        ));
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, Output::Run(run) if *run.job.payload().job_id() == job_id))
        );
        assert!(
            sim.state
                .session
                .session()
                .is_some_and(|s| s.session_id() == session_id)
        );

        sim.send(Message::Event(
            baseboard(),
            Event::Job(JobEvent::Start(job_id, sim.now)),
        ));
        sim.pump();
        let outputs = sim.request(Request::job(actor.clone(), JobRequest::Stop(job_id)));
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, Output::Stop(id) if *id == job_id))
        );
        sim.send(Message::Event(
            baseboard(),
            Event::Job(JobEvent::Stop(
                job_id,
                sim.now,
                Ok(0),
                JobOutputState::default(),
            )),
        ));
        let outputs = sim.pump();
        assert!(outputs.iter().any(
            |o| matches!(o, Output::Ran(JobStatus::Stopped { job_id: id, .. }) if *id == job_id)
        ));

        sim.request(Request::session(actor, SessionRequest::Stop(session_id)));
        assert!(sim.state.session.session().is_none());
    }

    /// When a second start of a pending session arrives from another
    /// identity, the first submitter remains the starter once a job
    /// confirms the session.
    #[tokio::test]
    async fn duplicate_start_keeps_first_actor() {
        let mut root = root();
        let anchors = vec![root.cert().clone()];
        let mut sim = Sim::new(&anchors, Vec::new()).await;
        let starter = root.key_id().clone();
        let resubmitter = self::root().key_id().clone();
        let preimage = preimage(1);
        let session_id = preimage.session_id();
        let session = Session::new(session_id);
        for actor in [&starter, &resubmitter] {
            sim.request(Request::session(
                actor.clone(),
                SessionRequest::Start(preimage.clone()),
            ));
        }

        let job_id = session.next_job_id();
        let signed = signed_job(&mut root, job_id, session_id, "true").await;
        sim.request(Request::job(
            resubmitter,
            JobRequest::Start(signed, JobStartParams::default()),
        ));
        assert_eq!(
            sim.state.session.session().and_then(Session::started_by),
            Some(&starter)
        );
    }

    /// A forged job never joins the queue or confirms a start. The
    /// history stays untouched, and the signed job it mimics confirms
    /// the start and runs in its place.
    #[tokio::test]
    async fn unverified_job_does_not_advance_the_chain() {
        let (mut root, mut sim, session_id, session) = sim_with_session().await;
        let actor = root.key_id().clone();

        let job_id = session.next_job_id();
        let signed = signed_job(&mut root, job_id, session_id, "true").await;
        let other = signed_job(&mut root, job_id, session_id, "false").await;
        let forged = SignedJob::new(
            signed.payload().clone(),
            signed.key_id().clone(),
            other.signature().clone(),
        );
        let outputs = sim.request(Request::job(
            actor.clone(),
            JobRequest::Start(forged, JobStartParams::default()),
        ));
        assert!(outputs.is_empty());
        assert!(sim.state.session.session().is_none());
        assert!(sim.state.pending_rank(session_id).is_some());
        assert!(!sim.state.history.contains(&job_id));

        let outputs = sim.request(Request::job(
            actor,
            JobRequest::Start(signed, JobStartParams::default()),
        ));
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, Output::Run(run) if *run.job.payload().job_id() == job_id))
        );
    }

    /// Sessions must not be resumed across networks.
    #[tokio::test]
    async fn committed_session_does_not_resume_across_networks() {
        let mut root = root();
        let anchors = vec![root.cert().clone()];
        let actor = root.key_id().clone();
        let mut sim = Sim::new(&anchors, Vec::new()).await;

        // A previous life, in another network, committed to job A
        // of the session and recorded the chain position after it.
        let committed_seq = 5;
        let committed_preimage = preimage(committed_seq);
        let session_id = committed_preimage.session_id();
        let mut signer = Session::new(session_id);
        let job_a_id = signer.next_job_id();
        let job_a = signed_job(&mut root, job_a_id, session_id, "true").await;
        signer.job_started(job_a.clone());
        let successor_id = signer.next_job_id();
        let other = network(7);
        assert_ne!(sim.rumors.network(), other);
        sim.state.past.committed = Some(Box::new(Boundary {
            network: other,
            session: session_id,
            seq: committed_preimage.seq,
            job: job_a_id,
            successor: successor_id,
            status: None,
        }));

        // The session's start arrives in this network.
        sim.request(Request::session(
            actor.clone(),
            SessionRequest::Start(committed_preimage),
        ));
        assert!(sim.state.pending_rank(session_id).is_some());

        // If the committed job arrives again, it confirms the start but
        // skips as superseded instead of running.
        let outputs = sim.request(Request::job(
            actor.clone(),
            JobRequest::Start(job_a, JobStartParams::default()),
        ));
        assert!(
            sim.state
                .session
                .session()
                .is_some_and(|s| s.session_id() == session_id)
        );
        assert!(!outputs.iter().any(|o| matches!(o, Output::Run(_))));
        assert!(outputs.iter().any(|o| matches!(
            o,
            Output::Gossip(Message::Event(
                _,
                Event::Job(JobEvent::Skipped(id, _, SkipReason::SessionSuperseded)),
            )) if *id == job_a_id
        )));

        // That job's successor also does not run.
        let job_b = signed_job(&mut root, successor_id, session_id, "true").await;
        let outputs = sim.request(Request::job(
            actor.clone(),
            JobRequest::Start(job_b, JobStartParams::default()),
        ));
        assert!(!outputs.iter().any(|o| matches!(o, Output::Run(_))));

        // A newer session outranks the committed one and runs.
        let next = preimage(committed_seq + 1);
        let next_id = next.session_id();
        sim.request(Request::session(actor.clone(), SessionRequest::Start(next)));
        let job_c_id = Session::new(next_id).next_job_id();
        let job_c = signed_job(&mut root, job_c_id, next_id, "true").await;
        let outputs = sim.request(Request::job(
            actor,
            JobRequest::Start(job_c, JobStartParams::default()),
        ));
        assert!(outputs.iter().any(|o| matches!(o, Output::Run(_))));
    }

    /// A session at or below the committed sequence number is
    /// refused: its jobs skip as superseded rather than run, and the
    /// chain still advances so the session is not wedged.
    #[tokio::test]
    async fn superseded_session_skips_through_step() {
        let (mut root, mut sim, session_id, mut session) = sim_with_session().await;
        let actor = root.key_id().clone();

        // A committed boundary the active session, at sequence
        // number 1, does not exceed.
        sim.state.past.committed = Some(Box::new(Boundary {
            network: sim.rumors.network(),
            session: SessionId::random(),
            seq: seq(10),
            job: JobId::random(),
            successor: JobId::random(),
            status: None,
        }));

        let skipped = |outputs: &[Output], job_id: JobId| {
            outputs.iter().any(|o| {
                matches!(
                    o,
                    Output::Gossip(Message::Event(
                        _,
                        Event::Job(JobEvent::Skipped(id, _, SkipReason::SessionSuperseded)),
                    )) if *id == job_id
                )
            })
        };

        let job_id = session.next_job_id();
        let signed = signed_job(&mut root, job_id, session_id, "true").await;
        let outputs = sim.request(Request::job(
            actor.clone(),
            JobRequest::Start(signed.clone(), JobStartParams::default()),
        ));
        assert!(!outputs.iter().any(|o| matches!(o, Output::Run(_))));
        assert!(skipped(&outputs, job_id));

        session.job_started(signed);
        let next_id = session.next_job_id();
        let next = signed_job(&mut root, next_id, session_id, "true").await;
        let outputs = sim.request(Request::job(
            actor,
            JobRequest::Start(next, JobStartParams::default()),
        ));
        assert!(skipped(&outputs, next_id));
    }

    /// Without a network to commit through, a ready job is not
    /// launched; its chain position still advances so the session is
    /// not wedged.
    #[tokio::test]
    async fn draining_launches_nothing() {
        let (mut root, mut sim, session_id, mut session) = sim_with_session().await;
        let actor = root.key_id().clone();

        let job_id = session.next_job_id();
        let signed = signed_job(&mut root, job_id, session_id, "true").await;
        sim.send(Message::Request(Request::job(
            actor,
            JobRequest::Start(signed.clone(), JobStartParams::default()),
        )));
        let outputs = sim.pump_draining();
        assert!(!outputs.iter().any(|o| matches!(o, Output::Run(_))));

        session.job_started(signed);
        let state_session = sim.state.session.session().unwrap();
        assert_eq!(state_session.next_job_id(), session.next_job_id());
    }

    /// A command the executor cannot launch is refused at release
    /// with an invalid command error; the chain still advances.
    #[tokio::test]
    async fn invalid_command_is_refused_at_release() {
        let (mut root, mut sim, session_id, mut session) = sim_with_session().await;
        let actor = root.key_id().clone();

        let job_id = session.next_job_id();
        let signed = signed_job(&mut root, job_id, session_id, "-rf").await;
        let outputs = sim.request(Request::job(
            actor,
            JobRequest::Start(signed.clone(), JobStartParams::default()),
        ));
        assert!(!outputs.iter().any(|o| matches!(o, Output::Run(_))));
        assert!(outputs.iter().any(|o| matches!(
            o,
            Output::Gossip(Message::Event(
                _,
                Event::Job(JobEvent::Error(id, _, ProcessError::InvalidCommand)),
            )) if *id == job_id
        )));

        session.job_started(signed);
        let state_session = sim.state.session.session().unwrap();
        assert_eq!(state_session.next_job_id(), session.next_job_id());
    }

    /// Replayed traffic never releases a job, and the drain after
    /// replay declares a previous life's running job interrupted
    /// exactly once.
    #[tokio::test]
    async fn replay_reaps_zombies_through_step() {
        let mut root = root();
        let anchors = vec![root.cert().clone()];
        let actor = root.key_id().clone();
        let preimage = preimage(1);
        let session_id = preimage.session_id();
        let session = Session::new(session_id);
        let job_id = session.next_job_id();
        let signed = signed_job(&mut root, job_id, session_id, "true").await;
        let history = vec![
            Message::Request(Request::session(
                actor.clone(),
                SessionRequest::Start(preimage),
            )),
            Message::Request(Request::job(
                actor,
                JobRequest::Start(signed, JobStartParams::default()),
            )),
            Message::Event(baseboard(), Event::Job(JobEvent::Start(job_id, Utc::now()))),
        ];

        let mut sim = Sim::new(&anchors, history).await;
        let outputs = sim.pump();
        assert!(!outputs.iter().any(|o| matches!(o, Output::Run(_))));

        let outputs = sim.drained();
        assert_eq!(outputs.len(), 1);
        assert!(interrupted(&outputs[0], job_id));
        assert!(sim.drained().is_empty());
    }

    /// The boundary verdict goes only to the universe the job started
    /// in. After a swap, the new universe never saw the job and hears
    /// nothing about it.
    #[tokio::test]
    async fn swapped_universe_hears_no_ruling() {
        let root = root();
        let anchors = vec![root.cert().clone()];
        let mut sim = Sim::new(&anchors, Vec::new()).await;
        let job = JobId::random();
        let home = sim.rumors.network();
        let commit = |sim: &mut Sim| {
            let mut boundary = committed_boundary(job);
            boundary.network = home;
            sim.state.past.committed = Some(Box::new(boundary));
        };

        commit(&mut sim);
        let outputs = sim.drained();
        assert_eq!(outputs.len(), 1);
        assert!(interrupted(&outputs[0], job));
        assert!(sim.drained().is_empty());

        // The new universe replaces the commitment from the record on
        // disk, which the null store cannot supply; restore it by hand.
        sim.swap().await;
        commit(&mut sim);
        assert!(sim.drained().is_empty());
    }
}
