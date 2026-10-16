// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Session state manager.
//!
//! Manage sessions and their associated jobs by sending and receiving
//! messages via the gossip protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use futures::{FutureExt as _, Stream, StreamExt};
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
    SessionSushNonce, SignedJob, SkipReason, VerifiedJob,
};
use sush_common::keys::{KeyError, KeyId};
use sush_common::targets::Cubbies;
use sush_common::version::VersionInfo;

use crate::bloom::Bloom;
use crate::bookmark::SushBookmark;
use crate::boundary::{Boundary, BoundaryStore, Committed, JobOutcome};
use crate::certs::Certificates;
use crate::executor::{Executor, PathIsolation};
use crate::gossip::{Seed, Universe};
use crate::history::JobHistory;
use crate::identities::Identities;
use crate::job::SocketSender;
use crate::locker::Locker;
use crate::messages::v0::{Error, Event, JobEvent, JobRequest, Message, Request, SessionRequest};
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
    pub job: SignedJob,
    pub params: JobStartParams,
    pub replayed: bool,
}

#[derive(Clone, Debug)]
pub enum SessionState {
    Inactive {
        /// Join of all observed session start requests.
        starts: Version,
    },
    Active {
        /// Join of all observed session start requests.
        starts: Version,

        /// When the active session started.
        started: Version,

        /// The active session.
        session: Box<Session>,

        /// Jobs waiting to run in this session.
        queued_jobs: QueuedJobs,

        /// Keys the starter has granted attach access, and how much.
        attach_grants: BTreeMap<KeyId, Access>,
    },
}

impl SessionState {
    fn starts(&self) -> Version {
        use SessionState::*;
        match self {
            Inactive { starts } => starts.clone(),
            Active { starts, .. } => starts.clone(),
        }
    }

    pub fn session(&self) -> Option<&Session> {
        use SessionState::*;
        match self {
            Inactive { .. } => None,
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
            starts: Version::new(),
        }
    }
}

/// Whether we have a job boundary we can rely on, and if so what the
/// execution floor is.
///
/// The floor lives in memory only, since a floor written to disk would
/// reach the next life, which might join a different universe; and because
/// versions don't compare across universes, every session would look
/// concurrent with the floor, leading to a permanent lock-out. Instead,
/// we raise a fresh floor at each universe entry from messages already
/// there, so future sessions come to dominate it.
#[derive(Debug)]
enum Commitment {
    /// Tabula rasa. The floor is raised when we join a universe with
    /// history.
    Absent { floor: Option<Version> },

    /// We have a valid boundary record. The floor is raised on re-entering
    /// a universe, or by a session hop.
    Trusted {
        boundary: Box<Boundary>,
        floor: Option<Version>,
    },

    /// The boundary record is corrupt; no jobs may run here.
    Untrusted,
}

impl Commitment {
    /// Judge the boundary record at entry into a universe. On a flip-flop
    /// (re-entering a burned universe), the error to report is also returned.
    fn at_entry(
        log: &Logger,
        store: &BoundaryStore,
        rumors: &GossipNetwork,
    ) -> (Self, Option<Error>) {
        if store.untrusted() {
            return (Self::Untrusted, None);
        }

        let network = rumors.network();
        let entry = rumors.snapshot().latest().clone();
        match store.boundary() {
            Some(boundary) if boundary.network != network && boundary.is_burned(network) => {
                warn!(log, "re-entered a burned universe"; "committed" => ?boundary.job);
                (
                    Self::Trusted {
                        boundary: Box::new(boundary),
                        floor: Some(entry),
                    },
                    Some(Error::UniverseFlipFlop),
                )
            }
            Some(boundary) => (
                Self::Trusted {
                    boundary: Box::new(boundary),
                    floor: None,
                },
                None,
            ),
            None if entry != Version::new() => {
                warn!(log, "no boundary record, but this universe has history");
                (Self::Absent { floor: Some(entry) }, None)
            }
            None => (Self::Absent { floor: None }, None),
        }
    }

    /// Raise the execution floor. An untrusted commitment refuses
    /// every job already, so it carries no floor to raise.
    fn raise(&mut self, to: Version) {
        match self {
            Self::Absent { floor } | Self::Trusted { floor, .. } => *floor = Some(to),
            Self::Untrusted => {}
        }
    }
}

/// What [`Past::screen`] decides about a live job of the active
/// session.
enum Admission {
    /// Execute normally.
    Admit,

    /// The session does not start above the execution floor,
    /// so skip the job.
    Refuse,

    /// We have a boundary record, but it's incommensurate with the
    /// current session. So "hop" into the new session, and raise the
    /// execution floor.
    Hop,

    /// If we cannot trust our boundary record, we must not admit
    /// new jobs.
    Untrusted,
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

    /// The most recently seen message version. Initialized to `birth`,
    /// then joined at every state machine update.
    frontier: Version,

    /// What job, if any, this sled committed to executing. Durable
    /// across restarts.
    committed: Commitment,

    /// Jobs whose replayed start events say a previous life ran them.
    /// The end of such a job may replay later and remove it from the
    /// set, so which jobs truly lack an end is known only when replay
    /// finishes.
    zombies: BTreeSet<JobId>,

    /// Jobs that kept running through a universe swap. The executor
    /// reports their events into this universe, so they are neither
    /// zombies nor candidates for adjudication.
    survivors: BTreeSet<JobId>,

    /// Zombies already declared interrupted. The interrupted event
    /// applies only after a gossip round trip, so history may still
    /// show these jobs running; this set keeps [`State::settle`] from
    /// ruling twice and keeps [`State::remainder`] from counting them
    /// as survivors.
    reaped: BTreeSet<JobId>,

    /// The universes that have been sent this sled's verdict on its
    /// boundary job. A ruling is announced at most once per job per
    /// universe.
    adjudicated: BTreeMap<Network, JobId>,
}

/// The parts of a [`Past`] that survive a universe swap because the
/// next life cannot recompute them from replay.
#[derive(Debug, Default)]
struct Remainder {
    /// Jobs still running or launching here at the swap.
    survivors: BTreeSet<JobId>,

    /// The universes that have been sent a verdict on the boundary job.
    adjudicated: BTreeMap<Network, JobId>,
}

impl Remainder {
    fn into_past(self, birth: Version, committed: Commitment) -> Past {
        Past {
            frontier: birth.clone(),
            birth,
            committed,
            zombies: BTreeSet::new(),
            survivors: self.survivors,
            reaped: BTreeSet::new(),
            adjudicated: self.adjudicated,
        }
    }
}

/// Whether `version` strictly dominates `mark`. Equal and concurrent
/// versions do not.
fn dominates(version: &Version, mark: &Version) -> bool {
    version > mark
}

impl Past {
    fn new(birth: Version, committed: Commitment) -> Self {
        Remainder::default().into_past(birth, committed)
    }

    fn observe(&mut self, version: &Version) {
        self.frontier |= version;
    }

    /// Decide whether the active session, identified by its id and
    /// the version of its start message, may run a live job here.
    fn screen(&self, network: Network, session: SessionId, started: &Version) -> Admission {
        match &self.committed {
            // Refuse all jobs if our boundary is untrusted.
            Commitment::Untrusted => Admission::Untrusted,

            // We must also refuse anything below our floor,
            // since we cannot tell replay from re-run there.
            Commitment::Absent { floor: Some(floor) }
            | Commitment::Trusted {
                floor: Some(floor), ..
            } if !dominates(started, floor) => Admission::Refuse,

            // Allow jobs in the absence of any previous commitment.
            Commitment::Absent { .. } => Admission::Admit,

            // Jobs cannot cross universes, and anything a previous life
            // ran in this universe is below the floor checked above.
            Commitment::Trusted { boundary, .. } => {
                if boundary.network != network {
                    Admission::Admit
                } else if let Some(job) = &boundary.job
                    && job.session == session
                {
                    Admission::Admit
                } else if dominates(started, &boundary.executed) {
                    Admission::Admit
                } else {
                    Admission::Hop
                }
            }
        }
    }

    /// Construct a boundary for a verified job.
    fn commit_to(
        &self,
        network: Network,
        started: &Version,
        session_id: SessionId,
        job_id: JobId,
        successor: JobId,
    ) -> Boundary {
        Boundary {
            network,
            burned: self.burned_for(network),
            executed: self.executed_for(network, started),
            job: Some(Committed {
                session: session_id.to_owned(),
                job: job_id,
                successor,
                outcome: JobOutcome::Committed,
            }),
        }
    }

    /// The burned set for a record committed in `network`; see
    /// [`Boundary::burned_for`].
    fn burned_for(&self, network: Network) -> Bloom {
        match &self.committed {
            Commitment::Trusted { boundary, .. } => boundary.burned_for(network),
            _ => Bloom::default(),
        }
    }

    /// The executed-session join for a record committed in `network`
    /// under a session started at `started`; see
    /// [`Boundary::executed_for`].
    fn executed_for(&self, network: Network, started: &Version) -> Version {
        match &self.committed {
            Commitment::Trusted { boundary, .. } => boundary.executed_for(network, started),
            _ => started.clone(),
        }
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
    RotateNonce,
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
    pub fn zombies(&self) -> BTreeSet<JobId> {
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
        if let Some(network) = network {
            outputs.extend(self.adjudicate_boundary(log, now, network));
        }
        outputs
    }

    /// Declare interrupted every job a previous life left running,
    /// excluding survivors and jobs already reaped. Zombies come only
    /// from replayed start events, so a job this incarnation started
    /// is never a candidate.
    fn reap_zombies(&mut self, log: &Logger, now: DateTime<Utc>) -> Vec<Output> {
        let mut outputs = Vec::new();
        for job_id in self.zombies() {
            if self.past.survivors.contains(&job_id) || self.past.reaped.contains(&job_id) {
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

    /// Adjudicate the boundary job if replay gave it no status on our
    /// baseboard: announce its recorded ending, or interrupted when
    /// none was recorded. No status means its fate never left this
    /// sled, and no other sled can ever report it. A replayed start
    /// makes it a zombie instead, and a replayed end settles it.
    /// Every sled hears the ruling, but a sled that already holds a
    /// terminal status for the job keeps what it holds, so one sled
    /// may show the real ending while another shows interrupted.
    fn adjudicate_boundary(
        &mut self,
        log: &Logger,
        now: DateTime<Utc>,
        network: Network,
    ) -> Vec<Output> {
        // An absent or untrusted record commits to no job, so there
        // is nothing to rule on.
        let Commitment::Trusted { boundary, .. } = &self.past.committed else {
            return Vec::new();
        };
        let Some(Committed { job, outcome, .. }) = boundary.job.as_ref() else {
            return Vec::new();
        };
        let (job_id, outcome) = (*job, outcome.clone());
        if self.past.adjudicated.get(&network) == Some(&job_id) {
            return Vec::new();
        }
        // A survivor reports its own ending in this universe, so it
        // needs no verdict now and may need one at a later swap.
        if self.past.survivors.contains(&job_id) {
            return Vec::new();
        }
        self.past.adjudicated.insert(network, job_id);
        let witnessed = self
            .get_job_status(&job_id)
            .is_some_and(|status| status.get(self.rack.own_baseboard()).is_some());
        if witnessed {
            return Vec::new();
        }
        // A stopped ending announces the start and stop pair, so the
        // ordinary status transitions apply on every sled; a bare stop
        // with no prior start would be dropped.
        let events = match outcome {
            JobOutcome::Ended(JobStatus::Stopped {
                time_started,
                time_stopped,
                result,
                output,
                ..
            }) => vec![
                JobEvent::Start(job_id, time_started),
                JobEvent::Stop(job_id, time_stopped, result, output),
            ],
            JobOutcome::Ended(JobStatus::Error {
                time_error, error, ..
            }) => vec![JobEvent::Error(job_id, time_error, error)],
            JobOutcome::Ended(_) | JobOutcome::Committed => {
                vec![JobEvent::Error(job_id, now, ProcessError::Interrupted)]
            }
        };
        warn!(log, "adjudicated an unwitnessed job from a previous life"; "job_id" => %job_id);
        events
            .into_iter()
            .map(|event| Output::job_event(self.rack.own_baseboard(), event))
            .collect()
    }

    /// Compute what survives into the next universe. A reaped zombie
    /// may still show as running while its interrupted event is in
    /// flight; it is no survivor. A job the executor is still
    /// launching is a survivor: its start event may not have applied
    /// yet, but the executor reports its events like any running
    /// job's.
    fn remainder(&self, in_flight: BTreeSet<JobId>) -> Remainder {
        let mut survivors = self.own_running_jobs();
        survivors.extend(in_flight);
        survivors.retain(|job_id| !self.past.reaped.contains(job_id));
        Remainder {
            survivors,
            adjudicated: self.past.adjudicated.clone(),
        }
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
        self.past.observe(incoming_version);
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
            SessionRequest::Start(session_id) => match &mut self.session {
                // Re-announcement of active session; absorb and ignore.
                Active {
                    starts, session, ..
                } if session.session_id() == *session_id => {
                    *starts |= incoming_version.clone();
                    info!(log, "duplicate session start"; "session_id" => %session_id);
                }

                // If the incoming new session is in the *strict
                // causal future* of everything we have observed,
                // adopt it regardless of our current state. Every
                // other peer will make the same decision, so it
                // will come to dominate the network entirely.
                Inactive { starts } | Active { starts, .. } if *incoming_version > *starts => {
                    info!(log, "session started"; "session_id" => %session_id, "actor" => %actor);
                    let mut session = Session::started(*session_id, actor.clone());
                    if let Commitment::Trusted { boundary, .. } = &self.past.committed
                        && let Some(committed) = boundary
                            .job
                            .as_ref()
                            .filter(|committed| committed.session == *session_id)
                    {
                        info!(
                            log, "resuming committed session at its successor";
                            "session_id" => %session_id,
                            "successor" => %committed.successor,
                        );
                        session.resume_at(committed.successor);
                    }
                    outputs.extend(self.skip_queued_jobs(now));
                    outputs.push(Output::RotateNonce);
                    self.session = Active {
                        starts: self.session.starts() | incoming_version.clone(),
                        started: incoming_version.clone(),
                        session: Box::new(session),
                        queued_jobs: QueuedJobs::new(),
                        attach_grants: BTreeMap::new(),
                    };
                }

                // When the incoming session is concurrent, we can't
                // establish which is older, so we have to kill both
                // sessions. Every peer will make this same decision,
                // so as a partition resolves, both sessions will be
                // killed everywhere.
                Active {
                    starts,
                    started,
                    session,
                    ..
                } if incoming_version.partial_cmp(starts).is_none() => {
                    let starts = starts.to_owned();
                    let error = Error::ConcurrentSessions {
                        own_session: session.session_id(),
                        own_version: Box::new(started.clone()),
                        incoming_session: *session_id,
                        incoming_version: Box::new(incoming_version.clone()),
                    };
                    outputs.extend(self.skip_queued_jobs(now));
                    outputs.push(Output::Gossip(Message::Event(
                        self.rack.own_baseboard().to_owned(),
                        Event::Error(error),
                    )));
                    self.session = Inactive {
                        starts: starts | incoming_version.clone(),
                    };
                }

                // Stale or concurrent session while inactive; OBE.
                // Absorb and ignore.
                Inactive { starts, .. } | Active { starts, .. } => {
                    info!(
                        log, "stale session start";
                        "session_id" => %session_id,
                        "starts" => %starts,
                        "incoming_version" => %incoming_version,
                    );
                    *starts |= incoming_version.clone();
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
                    starts, session, ..
                } = &self.session
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
                        self.session = Inactive {
                            starts: starts.clone(),
                        };
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
                // The session must be active and must match the
                // submitted job. It is safe to refuse all other jobs.
                // By cases:
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
                //
                // Refused jobs targeting this sled record the
                // terminal skip status so the submitter learns
                // their fate.
                let session_id = signed.payload().session_id();
                let live = self.is_live(incoming_version);
                if self
                    .session
                    .session()
                    .is_some_and(|s| s.session_id() == session_id)
                {
                    self.enqueue_job(log, now, signed.clone(), params.clone(), actor, !live);
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

                        // A start on our own baseboard sent by a
                        // previous life names a job whose process
                        // died with that life. No executor here will
                        // ever end it, so the job is a zombie: unless
                        // replay delivers its ending, we report it
                        // interrupted once replay drains. The birth
                        // mark splits the lives exactly; the arrival
                        // mark would misread a previous life's start
                        // as this life's own whenever the join peer
                        // lagged behind that start.
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
            Event::Error(error) => {
                error!(log, "session error"; "error" => %error);
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
        job: SignedJob,
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
            // We have no choice; drop the job on the floor.
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
            started,
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
                session.job_started(queued.job);
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

            let admission = self.past.screen(network, session.session_id(), started);
            if matches!(admission, Admission::Hop) {
                warn!(
                    log, "hopping sessions, raising the execution floor";
                    "session_id" => %session.session_id(), "started" => ?started,
                );
                self.past.committed.raise(self.past.frontier.clone());
                outputs.push(Output::Gossip(Message::Event(
                    self.rack.own_baseboard().to_owned(),
                    Event::Error(Error::SessionHop),
                )));
                continue;
            }

            let QueuedJob {
                job: request,
                params,
                replayed,
            } = queued_jobs.remove(&next_id).expect("checked above");
            let job_id = request.payload().job_id().to_owned();
            if self.rack.runs_here(&request) {
                if matches!(admission, Admission::Untrusted) {
                    warn!(
                        log, "execution boundary is untrusted, refusing job";
                        "job_id" => %job_id,
                    );
                    outputs.push(Output::job_event(
                        self.rack.own_baseboard(),
                        JobEvent::Error(
                            job_id,
                            now,
                            ProcessError::Io {
                                what: "consulting the execution boundary".to_string(),
                                error: "the boundary records on this sled's M.2s disagree \
                                        or are corrupt; an M.2 may have failed and the sled \
                                        needs service"
                                    .to_string(),
                            },
                        ),
                    ));
                } else if matches!(admission, Admission::Refuse) {
                    // Below the floor the queue skips forward in chain
                    // order. A live job gets the terminal skip status;
                    // a replayed one is history, and re-reporting it
                    // on every rejoin would grow the message set.
                    if !replayed {
                        warn!(log, "skipping job below the execution floor"; "job_id" => %job_id);
                        outputs.push(Output::job_event(
                            self.rack.own_baseboard(),
                            JobEvent::Skipped(job_id, now, SkipReason::BelowFloor),
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
                    let checked = self
                        .certs
                        .verify(&request)
                        .map_err(|error| ProcessError::InvalidJob(error.to_string()))
                        .and_then(|job| Executor::check_command(job.payload()).map(|()| job));
                    match checked {
                        Err(error) => outputs.push(Output::job_event(
                            self.rack.own_baseboard(),
                            JobEvent::Error(job_id, now, error),
                        )),
                        Ok(job) => {
                            let (attachment, rx_attachment) = watch::channel(None);
                            self.attachments.insert(job_id, rx_attachment);
                            outputs.push(Output::Run(Box::new(Run {
                                job,
                                params,
                                attachment,
                                boundary: self.past.commit_to(
                                    network,
                                    started,
                                    session.session_id(),
                                    job_id,
                                    session
                                        .session_id()
                                        .next_job_id(&LastJob::Some(request.clone())),
                                ),
                            })));
                        }
                    }
                }
            }
            session.job_started(request);
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
    nonce: &Arc<Mutex<SessionSushNonce>>,
    input: Input,
) {
    let now = Utc::now();
    let network = rumors.map(|r| r.network());
    let mut outputs = Vec::new();
    tx_state.send_modify(|state| {
        outputs = state.step(log, now, network, input);
    });
    apply_outputs(log, executor, rumors, store, nonce, outputs);
}

fn apply_outputs(
    log: &Logger,
    executor: &mut Executor,
    rumors: Option<&GossipNetwork>,
    store: &Arc<BoundaryStore>,
    nonce: &Arc<Mutex<SessionSushNonce>>,
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
                spawn(async move { store.record_outcome(&status).await });
            }
            Output::Gossip(message) => {
                if let Some(rumors) = rumors {
                    gossip(log, rumors, message.into());
                }
            }
            Output::RotateNonce => {
                *nonce.lock().unwrap() = SessionSushNonce::random();
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
    nonce: &Arc<Mutex<SessionSushNonce>>,
) {
    while let Some(Some((version, message))) = causal_messages.next().now_or_never() {
        apply(
            log,
            tx_state,
            executor,
            rumors,
            store,
            nonce,
            Input::Gossip(version, message),
        );
    }
}

/// Enter a universe: judge the boundary record, announce this build,
/// and mark the birth. The announce is this life's first send and
/// goes out before the birth snapshot is taken, so the birth is the
/// announce's own version. A flip-flop report follows the announce.
fn enter_universe(
    log: &Logger,
    own_baseboard: BaseboardId,
    anchors: &[Certificate],
    store: &BoundaryStore,
    rumors: &GossipNetwork,
    remainder: Remainder,
) -> Result<State, KeyError> {
    let (committed, report) = Commitment::at_entry(log, store, rumors);
    gossip(
        log,
        rumors,
        Message::Event(
            own_baseboard.clone(),
            Event::Version(VersionInfo::current()),
        )
        .into(),
    );
    if let Some(report) = report {
        gossip(
            log,
            rumors,
            Message::Event(own_baseboard.clone(), Event::Error(report)).into(),
        );
    }
    let birth = rumors.snapshot().latest().clone();
    State::new(
        own_baseboard,
        anchors,
        remainder.into_past(birth, committed),
    )
}

/// Send a message into the gossip set. An error means the payload
/// exceeded the configured depth limit, which tests should catch.
fn gossip(log: &Logger, rumors: &GossipNetwork, message: VersionedMessage) {
    if let Err(error) = rumors.send(message) {
        error!(log, "the gossip set refused a message"; "error" => %error);
    }
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
    /// session or history bookkeeping can survive a migration; running jobs
    /// continue, and their events land in the new universe.
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
        session_sush_nonce: Arc<Mutex<SessionSushNonce>>,
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
            Past::new(Version::new(), Commitment::Absent { floor: None }),
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
                    let entered = enter_universe(
                        &log,
                        own_baseboard.clone(),
                        &anchors,
                        &boundary_store,
                        rumors,
                        Remainder::default(),
                    )
                    .expect("trust anchors validated at startup");
                    tx_state.send_modify(|state| {
                        *state = entered;
                        state.rack.set_cubbies(cubbies.borrow_and_update().clone());
                    });
                }
                if let Some(Committed { session, job, .. }) =
                    boundary.as_ref().and_then(|boundary| boundary.job.as_ref())
                {
                    info!(
                        log, "inherited an execution boundary; the committed session resumes at its stored successor";
                        "session_id" => %session, "job_id" => %job,
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
                                gossip(&log, rumors, Message::Request(request).into());
                            },
                        },

                        // Handle events produced by the executor.
                        next = events.next(), if !events_empty => match next {
                            None => events_empty = true,
                            Some(event) => if let Some((rumors, _)) = &network {
                                debug!(log, "forwarding event to gossip network"; "event" => ?event);
                                gossip(
                                    &log,
                                    rumors,
                                    Message::Event(own_baseboard.clone(), event).into(),
                                );
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
                                    &session_sush_nonce,
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
                                        &session_sush_nonce,
                                    );
                                    apply(
                                        &log,
                                        &tx_state,
                                        &mut executor,
                                        network.as_ref().map(|(rumors, _)| rumors),
                                        &boundary_store,
                                        &session_sush_nonce,
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
                                &session_sush_nonce,
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
                        let remainder = tx_state.borrow().remainder(executor.in_flight());
                        *rumors = fresh.rumors;
                        // TODO: re-inject local job state (policy pending).
                        let entered = enter_universe(
                            &log,
                            own_baseboard.clone(),
                            &anchors,
                            &boundary_store,
                            rumors,
                            remainder,
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
                            &session_sush_nonce,
                        );
                        apply(
                            &log,
                            &tx_state,
                            &mut executor,
                            Some(&*rumors),
                            &boundary_store,
                            &session_sush_nonce,
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

    use sush_common::jobs::{JobMode, JobOutputState, JobStartRequest};
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
            burned: Bloom::new(),
            executed: Version::new(),
            job: Some(Committed {
                session: SessionId::random(),
                job,
                successor: JobId::random(),
                outcome: JobOutcome::Committed,
            }),
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

    fn past(committed: Option<Boundary>, floor: Option<Version>) -> Past {
        let committed = match committed {
            Some(boundary) => Commitment::Trusted {
                boundary: Box::new(boundary),
                floor,
            },
            None => Commitment::Absent { floor },
        };
        Past::new(Version::new(), committed)
    }

    /// The admission rules: a sled with no record admits, a record
    /// from a foreign universe admits, the committed session admits
    /// outright, a session started strictly above the executed join
    /// admits, and everything else hops.
    #[test]
    fn admission_rules() {
        let started: Version = "(1, 1, (0, 0, 2))".parse().unwrap();
        let older: Version = "(1, 0, (0, 0, 2))".parse().unwrap();
        let newer: Version = "(2, 1, (0, 0, 3))".parse().unwrap();
        let concurrent: Version = "(1, 2, (0, 0, 1))".parse().unwrap();
        let session = SessionId::random();
        let job = JobId::random();
        let committed = Boundary {
            network: network(1),
            burned: Bloom::new(),
            executed: started.clone(),
            job: Some(Committed {
                session,
                job,
                successor: JobId::random(),
                outcome: JobOutcome::Committed,
            }),
        };

        let recordless = past(None, None);
        assert!(matches!(
            recordless.screen(network(1), session, &started),
            Admission::Admit
        ));

        let past = past(Some(committed), None);
        assert!(matches!(
            past.screen(network(2), session, &started),
            Admission::Admit
        ));
        // The committed session admits outright: it resumes at the
        // stored successor when it activates, and chain position
        // keeps every earlier job from popping.
        assert!(matches!(
            past.screen(network(1), session, &started),
            Admission::Admit
        ));
        assert!(matches!(
            past.screen(network(1), SessionId::random(), &newer),
            Admission::Admit
        ));
        for unordered in [&older, &started, &concurrent] {
            assert!(matches!(
                past.screen(network(1), SessionId::random(), unordered),
                Admission::Hop
            ));
        }
    }

    /// A floor refuses every session not started strictly above it,
    /// in every universe and under either commitment that carries one:
    /// the floor belongs to this life, not to any record.
    #[test]
    fn floors_refuse_below() {
        let floor: Version = "(1, 1, (0, 0, 2))".parse().unwrap();
        let at: Version = floor.clone();
        let below: Version = "(1, 0, (0, 0, 2))".parse().unwrap();
        let above: Version = "(2, 1, (0, 0, 3))".parse().unwrap();
        let concurrent: Version = "(1, 2, (0, 0, 1))".parse().unwrap();
        let committed = Boundary {
            network: network(1),
            burned: Bloom::new(),
            executed: floor.clone(),
            job: None,
        };

        for past in [
            past(None, Some(floor.clone())),
            past(Some(committed), Some(floor.clone())),
        ] {
            for started in [&at, &below, &concurrent] {
                for net in [network(1), network(2)] {
                    assert!(matches!(
                        past.screen(net, SessionId::random(), started),
                        Admission::Refuse
                    ));
                }
            }
            assert!(matches!(
                past.screen(network(1), SessionId::random(), &above),
                Admission::Admit
            ));
        }
    }

    /// A hop raises the floor to the frontier, so the hopped session
    /// screens as a refusal from then on: one hop report per session.
    /// A session started strictly above the frontier admits again.
    #[test]
    fn raised_floor_refuses_hopped_session() {
        let started: Version = "(1, 1, (0, 0, 2))".parse().unwrap();
        let executed: Version = "(1, 2, (0, 0, 1))".parse().unwrap();
        let above: Version = "(2, 2, (0, 0, 3))".parse().unwrap();
        let session = SessionId::random();
        let committed = Boundary {
            network: network(1),
            burned: Bloom::new(),
            executed: executed.clone(),
            job: None,
        };

        let mut past = past(Some(committed), None);
        past.observe(&started);
        past.observe(&executed);
        assert_eq!(past.frontier, &started | executed.clone());
        assert!(matches!(
            past.screen(network(1), session, &started),
            Admission::Hop
        ));

        past.committed.raise(past.frontier.clone());
        assert!(matches!(
            past.screen(network(1), session, &started),
            Admission::Refuse
        ));
        assert!(matches!(
            past.screen(network(1), session, &above),
            Admission::Admit
        ));
    }

    /// An untrusted record admits nothing in any universe, and a
    /// raise leaves it untrusted.
    #[test]
    fn untrusted_admits_nothing() {
        let started: Version = "(2, 1, (0, 0, 3))".parse().unwrap();
        let mut past = Past::new(Version::new(), Commitment::Untrusted);
        for net in [network(1), network(2)] {
            assert!(matches!(
                past.screen(net, SessionId::random(), &started),
                Admission::Untrusted
            ));
        }
        past.committed.raise(started.clone());
        assert!(matches!(
            past.screen(network(1), SessionId::random(), &started),
            Admission::Untrusted
        ));
    }

    /// Settle declares a zombie interrupted exactly once. A survivor
    /// is spared: the executor still runs it and reports its ending
    /// itself.
    #[test]
    fn settle_reaps_zombies_once_and_spares_survivors() {
        let log = discard();
        let now = Utc::now();
        let zombie = JobId::random();
        let survivor = JobId::random();
        let mut state = state(past(None, None));
        for job_id in [zombie, survivor] {
            state.past.zombies.insert(job_id);
            start_job(&mut state, job_id, now);
        }
        state.past.survivors.insert(survivor);

        let outputs = state.settle(&log, now, Some(network(1)));
        assert_eq!(outputs.len(), 1);
        assert!(interrupted(&outputs[0], zombie));
        assert!(state.settle(&log, now, Some(network(1))).is_empty());
    }

    /// A committed job that replay left without a status is
    /// adjudicated as interrupted, once per universe: a universe that
    /// never heard the ruling gets its own.
    #[test]
    fn adjudication_rules_once_per_universe() {
        let log = discard();
        let now = Utc::now();
        let job = JobId::random();
        let mut state = state(past(Some(committed_boundary(job)), None));

        for net in [network(1), network(2)] {
            let outputs = state.settle(&log, now, Some(net));
            assert_eq!(outputs.len(), 1);
            assert!(interrupted(&outputs[0], job));
            assert!(state.settle(&log, now, Some(net)).is_empty());
        }
    }

    /// A witnessed boundary job keeps its replayed status: settle
    /// marks the ruling made and announces nothing. A surviving
    /// boundary job gets no ruling at all, since it may need one at
    /// a later swap.
    #[test]
    fn adjudication_defers_to_witnesses_and_survivors() {
        let log = discard();
        let now = Utc::now();
        let job = JobId::random();
        let boundary = committed_boundary(job);

        let mut witnessed = state(past(Some(boundary.clone()), None));
        start_job(&mut witnessed, job, now);
        assert!(witnessed.settle(&log, now, Some(network(1))).is_empty());
        assert_eq!(witnessed.past.adjudicated.get(&network(1)), Some(&job));

        let mut surviving = state(past(Some(boundary), None));
        surviving.past.survivors.insert(job);
        assert!(surviving.settle(&log, now, Some(network(1))).is_empty());
        assert!(surviving.past.adjudicated.is_empty());
    }

    /// The remainder carries exactly what the next life cannot
    /// recompute from replay: jobs still running or launching, minus
    /// those already reaped, and the ruling already made.
    #[test]
    fn remainder_carries_survivors_and_ruling() {
        let now = Utc::now();
        let running = JobId::random();
        let launching = JobId::random();
        let reaped = JobId::random();
        let mut state = state(past(None, None));
        start_job(&mut state, running, now);
        start_job(&mut state, reaped, now);
        state.past.reaped.insert(reaped);
        state.past.adjudicated.insert(network(1), running);

        let remainder = state.remainder(BTreeSet::from([launching]));
        assert_eq!(remainder.survivors, BTreeSet::from([running, launching]));
        assert_eq!(
            remainder.adjudicated,
            BTreeMap::from([(network(1), running)])
        );
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
            let state = enter_universe(
                &log,
                baseboard(),
                anchors,
                &store,
                &rumors,
                Remainder::default(),
            )
            .unwrap();
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
            let remainder = self.state.remainder(BTreeSet::new());
            self.state = enter_universe(
                &self.log,
                baseboard(),
                &self.anchors,
                &store,
                &rumors,
                remainder,
            )
            .unwrap();
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

    /// A fresh universe with an adopted session, ready for jobs.
    async fn sim_with_session() -> (EphemeralKey, Sim, SessionId, Session) {
        let root = root();
        let anchors = vec![root.cert().clone()];
        let mut sim = Sim::new(&anchors, Vec::new()).await;
        let session_id = SessionId::random();
        sim.request(Request::session(
            root.key_id().clone(),
            SessionRequest::Start(session_id),
        ));
        (root, sim, session_id, Session::new(session_id))
    }

    /// The happy path through the step surface alone: a session
    /// starts, a signed job releases, the job's own events settle its
    /// status, and the session stops.
    #[tokio::test]
    async fn session_lifecycle_through_step() {
        let mut root = root();
        let anchors = vec![root.cert().clone()];
        let actor = root.key_id().clone();
        let mut sim = Sim::new(&anchors, Vec::new()).await;

        let session_id = SessionId::random();
        let session = Session::new(session_id);
        let outputs = sim.request(Request::session(
            actor.clone(),
            SessionRequest::Start(session_id),
        ));
        assert!(outputs.iter().any(|o| matches!(o, Output::RotateNonce)));
        assert!(sim.state.session.session().is_some());

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

    /// A session the boundary record cannot order hops: the floor
    /// rises, one report goes out, and the session's jobs are skipped
    /// below the floor rather than run. A later job in the same
    /// session reports no second hop.
    #[tokio::test]
    async fn hop_through_step() {
        let (mut root, mut sim, session_id, mut session) = sim_with_session().await;
        let actor = root.key_id().clone();

        // A boundary record whose executed join the session start
        // does not dominate: the current frontier, which includes
        // the start itself.
        sim.state.past.committed = Commitment::Trusted {
            boundary: Box::new(Boundary {
                network: sim.rumors.network(),
                burned: Bloom::new(),
                executed: sim.rumors.snapshot().latest().clone(),
                job: None,
            }),
            floor: None,
        };

        let hops = |outputs: &[Output]| {
            outputs
                .iter()
                .filter(|o| {
                    matches!(
                        o,
                        Output::Gossip(Message::Event(_, Event::Error(Error::SessionHop)))
                    )
                })
                .count()
        };
        let skipped = |outputs: &[Output], job_id: JobId| {
            outputs.iter().any(|o| {
                matches!(
                    o,
                    Output::Gossip(Message::Event(
                        _,
                        Event::Job(JobEvent::Skipped(id, _, SkipReason::BelowFloor)),
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
        assert_eq!(hops(&outputs), 1);
        assert!(!outputs.iter().any(|o| matches!(o, Output::Run(_))));
        assert!(skipped(&outputs, job_id));

        session.job_started(signed);
        let next_id = session.next_job_id();
        let next = signed_job(&mut root, next_id, session_id, "true").await;
        let outputs = sim.request(Request::job(
            actor,
            JobRequest::Start(next, JobStartParams::default()),
        ));
        assert_eq!(hops(&outputs), 0);
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
        let session_id = SessionId::random();
        let session = Session::new(session_id);
        let job_id = session.next_job_id();
        let signed = signed_job(&mut root, job_id, session_id, "true").await;
        let history = vec![
            Message::Request(Request::session(
                actor.clone(),
                SessionRequest::Start(session_id),
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

    /// A swap can land in a universe that never heard the boundary
    /// verdict; that universe gets its own, exactly once.
    #[tokio::test]
    async fn swapped_universe_gets_its_own_ruling() {
        let root = root();
        let anchors = vec![root.cert().clone()];
        let mut sim = Sim::new(&anchors, Vec::new()).await;
        let job = JobId::random();
        let commit = |sim: &mut Sim| {
            sim.state.past.committed = Commitment::Trusted {
                boundary: Box::new(committed_boundary(job)),
                floor: None,
            };
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
        let outputs = sim.drained();
        assert_eq!(outputs.len(), 1);
        assert!(interrupted(&outputs[0], job));
        assert!(sim.drained().is_empty());
    }
}
