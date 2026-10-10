// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Session state manager.
//!
//! Manage sessions and their associated jobs by sending and receiving
//! messages via the gossip protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use chrono::Utc;
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
    SessionSushNonce, SignedJob, SkipReason,
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
        /// Last observed session request.
        frontier: Version,
    },
    Active {
        /// Last observed session request.
        frontier: Version,
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
    fn frontier(&self) -> Version {
        use SessionState::*;
        match self {
            Inactive { frontier } => frontier.clone(),
            Active { frontier, .. } => frontier.clone(),
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
            frontier: Version::new(),
        }
    }
}

/// What [`Past::screen`] decides about a live job of the active
/// session.
enum Admission {
    /// Execute normally.
    Admit,
    /// The session does not start above the floor; skip the job.
    Refuse,
    /// The boundary record cannot order this session, so a previous
    /// life of this sled may have run its jobs. The sled reports an
    /// error and raises its floor, as if it had just entered the
    /// universe at this instant.
    Hop,
}

/// This incarnation's relationship to its own past: where it entered
/// the universe, what a previous life committed to, and what it left
/// running.
#[derive(Debug)]
pub struct Past {
    /// The frontier just before this life's first send into this
    /// universe: the general replay line. Messages that do not
    /// strictly follow it count as replayed.
    arrival: Version,
    /// The frontier just past this life's first send. Own-baseboard
    /// events at or below it belong to a previous life; everything
    /// this life sends causally follows it. Never persisted: each
    /// life computes its own, so the split is exact and independent of
    /// which peer we joined through. It is not the general replay
    /// line, because a neighbor's fresh traffic reaches us before our
    /// first send reaches the neighbor.
    birth: Version,
    /// The last job this sled committed to executing, durable across
    /// restarts.
    boundary: Arc<BoundaryStore>,
    /// The boundary record as we found it on entering this universe.
    /// The live store advances with our own jobs; [`Past::screen`]
    /// compares sessions against the previous life's commitment, so
    /// it reads this frozen copy.
    committed: Option<Boundary>,
    /// The execution floor, raised in memory at entry into a burned
    /// universe, at record-less entry into a universe with history,
    /// and on a session hop. Only sessions started strictly above it
    /// are served; below it this sled cannot tell replay from re-run.
    /// Never persisted: whatever raised it is still there after a
    /// restart and raises it again. See [`entry_floor`].
    floor: Option<Version>,
    /// Jobs whose replayed start events say a previous life ran them.
    /// The end of such a job may replay later and remove it from the
    /// set, so the survivors are known only when replay finishes.
    zombies: BTreeSet<JobId>,
}

/// Whether `version` strictly dominates `mark`. Equal and concurrent
/// versions do not.
fn dominates(version: &Version, mark: &Version) -> bool {
    version > mark
}

impl Past {
    pub fn new(
        arrival: Version,
        birth: Version,
        boundary: Arc<BoundaryStore>,
        committed: Option<Boundary>,
        floor: Option<Version>,
    ) -> Self {
        Self {
            arrival,
            birth,
            boundary,
            committed,
            floor,
            zombies: BTreeSet::new(),
        }
    }

    /// Decide whether the active session, identified by its id and
    /// the version of its start message, may run a live job here.
    fn screen(&self, network: Network, session: SessionId, started: &Version) -> Admission {
        // We must refuse anything below our floor, because we cannot
        // tell replay from re-run there.
        if self
            .floor
            .as_ref()
            .is_some_and(|floor| !dominates(started, floor))
        {
            return Admission::Refuse;
        }

        // If we have committed to nothing, anything is safe to admit.
        let Some(committed) = &self.committed else {
            return Admission::Admit;
        };

        // Jobs cannot cross universes, and anything a previous life
        // ran in this universe is below the floor checked above.
        if committed.network != network {
            return Admission::Admit;
        }

        match &committed.job {
            Some(job) if job.session == session => Admission::Admit,
            _ => {
                if dominates(started, &committed.executed) {
                    Admission::Admit
                } else {
                    Admission::Hop
                }
            }
        }
    }

    /// Report the cause of an [`Admission::Hop`] to the gossip set,
    /// then set the floor at the frontier that includes the report.
    fn hop(
        &mut self,
        log: &Logger,
        rumors: &GossipNetwork,
        own_baseboard: &BaseboardId,
        report: Error,
    ) {
        gossip(
            log,
            rumors,
            Message::Event(own_baseboard.clone(), Event::Error(report)).into(),
        );
        self.floor = Some(rumors.snapshot().latest().clone());
    }

    /// The burned set for a record committed in `network`; see
    /// [`Boundary::burned_for`].
    fn burned_for(&self, network: Network) -> Bloom {
        self.committed
            .as_ref()
            .map(|boundary| boundary.burned_for(network))
            .unwrap_or_default()
    }

    /// The executed-session join for a record committed in `network`
    /// under a session started at `started`; see
    /// [`Boundary::executed_for`].
    fn executed_for(&self, network: Network, started: &Version) -> Version {
        self.committed
            .as_ref()
            .map(|boundary| boundary.executed_for(network, started))
            .unwrap_or_else(|| started.clone())
    }

    /// Whether a message at `version` is live traffic rather than
    /// replayed history: only strict causal descendants of the
    /// arrival are live.
    fn is_live(&self, version: &Version) -> bool {
        dominates(version, &self.arrival)
    }

    /// Whether this sled's own event at `version` came from a
    /// previous life. The split is exact: nothing a previous life
    /// sent dominates the birth, and everything this life sends does.
    fn is_from_previous_life(&self, version: &Version) -> bool {
        !dominates(version, &self.birth)
    }
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
    /// The nonce binding new session IDs to this sled, shared with the
    /// manager and rotated whenever a session activates.
    session_sush_nonce: Arc<Mutex<SessionSushNonce>>,
    /// This incarnation's relationship to its own past.
    past: Past,
}

impl State {
    pub fn new(
        own_baseboard: BaseboardId,
        trust_anchors: &[Certificate],
        session_sush_nonce: Arc<Mutex<SessionSushNonce>>,
        past: Past,
    ) -> Result<Self, KeyError> {
        Ok(Self {
            rack: Rack::new(own_baseboard),
            history: Default::default(),
            session: Default::default(),
            attachments: Default::default(),
            session_sush_nonce,
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

    /// The boundary record carries the boundary job's ending, so the
    /// next life can tell the truth instead of guessing. The write is
    /// spawned because the state machine is synchronous, and losing
    /// the race to a crash only falls back to interrupted.
    fn record_boundary_outcome(&self, job_id: &JobId) {
        let Some(status) = self
            .history
            .get_job_status(job_id)
            .and_then(|map| map.get(self.rack.own_baseboard()))
            .cloned()
        else {
            return;
        };
        if !status.is_terminal() {
            return;
        }
        let store = self.past.boundary.clone();
        let job_id = *job_id;
        spawn(async move { store.record_outcome(&job_id, &status).await });
    }

    pub fn get_job_status(&self, job_id: &JobId) -> Option<&JobStatusMap> {
        self.history.get_job_status(job_id)
    }

    fn skip_queued_jobs(&self, executor: &Executor) {
        for (job_id, queued) in self.session.queued_jobs().into_iter().flatten() {
            if !queued.replayed && self.rack.runs_here(&queued.job) {
                executor.job_skipped(*job_id, SkipReason::SessionEnded);
            }
        }
    }

    fn update(
        &mut self,
        log: &Logger,
        executor: &mut Executor,
        rumors: Option<&GossipNetwork>,
        incoming_version: &Version,
        message: &Arc<VersionedMessage>,
    ) -> Result<(), Error> {
        match message.as_ref() {
            V0(Message::Request(request)) => {
                let actor = request.actor();
                let log = log.new(o!("actor" => actor.to_string()));
                match request {
                    Request::Cert(r) => self.certs.apply(&log, r.request()),
                    Request::Identity(r) => self.identities.apply(&log, r.request()),
                    Request::Session(r) => {
                        self.handle_session_request(
                            &log,
                            executor,
                            rumors,
                            incoming_version,
                            actor,
                            r.request(),
                        )?;
                    }
                    Request::Job(r) => self.handle_job_request(
                        &log,
                        executor,
                        rumors,
                        incoming_version,
                        actor,
                        r.request(),
                    ),
                }
            }
            V0(Message::Event(baseboard_id, event)) => {
                self.handle_event(log, executor, incoming_version, baseboard_id, event)
            }
            Unknown { version, .. } => {
                if self.rack.unknown_version(version.clone()) {
                    warn!(log, "ignoring messages from a newer peer"; "version" => version);
                }
            }
        }

        Ok(())
    }

    fn handle_session_request(
        &mut self,
        log: &Logger,
        executor: &mut Executor,
        rumors: Option<&GossipNetwork>,
        incoming_version: &Version,
        actor: &KeyId,
        request: &SessionRequest,
    ) -> Result<(), Error> {
        use SessionState::*;
        match request {
            SessionRequest::Start(session_id) => match &mut self.session {
                // Re-announcement of active session; absorb and ignore.
                Active {
                    frontier, session, ..
                } if session.session_id() == *session_id => {
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
                    info!(
                        log, "session started";
                        "session_id" => %session_id, "actor" => %actor,
                    );
                    self.skip_queued_jobs(executor);
                    let mut session = Session::started(*session_id, actor.clone());
                    // The committed session resumes at its
                    // stored successor: every earlier chain
                    // position was already handled by the life
                    // that stored it, and the chain needs no
                    // replay to verify the next job.
                    if let Some(committed) = self
                        .past
                        .committed
                        .as_ref()
                        .and_then(|boundary| boundary.job.as_ref())
                        .filter(|committed| committed.session == *session_id)
                    {
                        info!(
                            log, "resuming the committed session at its successor";
                            "session_id" => %session_id,
                            "successor" => %committed.successor,
                        );
                        session.resume_at(committed.successor);
                    }
                    self.session = Active {
                        frontier: self.session.frontier() | incoming_version.clone(),
                        started: incoming_version.clone(),
                        session: Box::new(session),
                        queued_jobs: QueuedJobs::new(),
                        attach_grants: BTreeMap::new(),
                    };
                    *self.session_sush_nonce.lock().unwrap() = SessionSushNonce::random();
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
                        own_session: session.session_id(),
                        own_version: Box::new(started.clone()),
                        incoming_session: *session_id,
                        incoming_version: Box::new(incoming_version.clone()),
                    };
                    let frontier = &*frontier | incoming_version.clone();
                    self.skip_queued_jobs(executor);
                    self.session = Inactive { frontier };
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
                        self.skip_queued_jobs(executor);
                        self.session = Inactive {
                            frontier: frontier.clone(),
                        }
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
                        self.cancel_job(job_id, actor, replayed);
                        self.execute_ready_jobs(log, executor, rumors);
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
        Ok(())
    }

    fn handle_job_request(
        &mut self,
        log: &Logger,
        executor: &mut Executor,
        rumors: Option<&GossipNetwork>,
        incoming_version: &Version,
        actor: &KeyId,
        request: &JobRequest,
    ) {
        match request {
            JobRequest::Start(signed, params) => {
                // TODO: When we implement
                // https://github.com/oxidecomputer/sush/issues/23, we
                // should check for revocation here before executing the
                // job. This enforces revocation globally, instead of
                // just when the job is injected first into the system.

                // The session must be active and must match the
                // submitted job.
                //
                // It is safe to refuse all other jobs. By cases:
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
                    self.enqueue_job(log, signed.clone(), params.clone(), actor, !live);
                    self.execute_ready_jobs(log, executor, rumors);
                } else {
                    let job_id = *signed.job_id();
                    warn!(
                        log, "skipping job for inactive session";
                        "job_id" => %job_id,
                        "session_id" => %session_id,
                        "actor" => %actor,
                    );
                    if live && self.rack.runs_here(signed) && !self.history.contains(&job_id) {
                        executor.job_skipped(job_id, SkipReason::SessionEnded);
                    }
                }
            }
            JobRequest::Stop(job_id) => {
                executor.job_stop(job_id);
                let replayed = !self.is_live(incoming_version);
                self.cancel_job(job_id, actor, replayed);
            }
        }
    }

    fn handle_event(
        &mut self,
        log: &Logger,
        executor: &mut Executor,
        incoming_version: &Version,
        baseboard_id: &BaseboardId,
        event: &Event,
    ) {
        let log = log.new(o!("sled" => baseboard_id.to_string()));
        match event {
            // Track the active set of known-running jobs anywhere in the rack.
            Event::Job(job_event) => match job_event {
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
                        return;
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
                        && self.past.is_from_previous_life(incoming_version)
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
                            // An interrupted declaration raced this
                            // genuine stop. The real result wins in
                            // either arrival order, though the start
                            // time died with the previous life.
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
                    );
                    if baseboard_id == self.rack.own_baseboard() {
                        executor.job_stopped(job_id);
                        self.record_boundary_outcome(job_id);
                    }
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
                        // An error never displaces a terminal
                        // status, so a stop that raced an
                        // interrupted declaration keeps the real
                        // result.
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
                    );
                    if baseboard_id == self.rack.own_baseboard() {
                        executor.job_stopped(job_id);
                        self.record_boundary_outcome(job_id);
                    }
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
                        // A skip is the reporting sled's decision
                        // about itself, and never displaces a
                        // terminal status it already reported.
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
                    );
                }
            },
            Event::Error(error) => {
                error!(log, "session error"; "error" => %error);
            }
            Event::Version(info) => {
                if self.rack.known_version(baseboard_id.clone(), info.clone()) {
                    info!(log, "sled version"; "version" => %info);
                }
            }
        }
    }

    fn enqueue_job(
        &mut self,
        log: &Logger,
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
                        time_queued: Utc::now(),
                        actor: actor.clone(),
                    },
                    None,
                    Some(queued_jobs),
                );
            }
        }
    }

    fn cancel_job(&mut self, job_id: &JobId, actor: &KeyId, replayed: bool) {
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
                    time_cancelled: Utc::now(),
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
    fn execute_ready_jobs(
        &mut self,
        log: &Logger,
        executor: &mut Executor,
        rumors: Option<&GossipNetwork>,
    ) {
        let SessionState::Active {
            session,
            started,
            queued_jobs,
            ..
        } = &mut self.session
        else {
            return;
        };
        loop {
            let next_id = session.next_job_id();
            if !queued_jobs.contains_key(&next_id) {
                break;
            }
            // A hop can raise the floor mid-drain, so screen on every pass.
            let admission = match rumors {
                None => Admission::Admit,
                Some(rumors) => self
                    .past
                    .screen(rumors.network(), session.session_id(), started),
            };
            // A hop raises the floor and screens again.
            if matches!(admission, Admission::Hop) {
                let Some(rumors) = rumors else {
                    break;
                };
                warn!(
                    log, "raising the execution floor above a session the boundary record cannot order";
                    "session_id" => %session.session_id(), "started" => ?started,
                );
                self.past
                    .hop(log, rumors, self.rack.own_baseboard(), Error::SessionHop);
                continue;
            }
            let QueuedJob {
                job: request,
                params,
                replayed,
            } = queued_jobs.remove(&next_id).expect("checked above");
            let (tx_attachment, rx_attachment) = watch::channel(None);
            let job_id = request.payload().job_id().to_owned();
            if self.rack.runs_here(&request) {
                if self.past.boundary.untrusted() {
                    warn!(
                        log, "refusing job, the execution boundary is untrusted";
                        "job_id" => %job_id,
                    );
                    executor.job_refused(
                        job_id,
                        ProcessError::Io {
                            what: "consulting the execution boundary".to_string(),
                            error: "the boundary records on this sled's M.2s disagree \
                                    or are corrupt; an M.2 may have failed and the sled \
                                    needs service"
                                .to_string(),
                        },
                    );
                } else if matches!(admission, Admission::Refuse) {
                    // Below the floor the queue skips forward in chain
                    // order. A live job gets the terminal skip status;
                    // a replayed one is history, and re-reporting it
                    // on every rejoin would grow the message set.
                    if !replayed {
                        warn!(log, "skipping job below the execution floor"; "job_id" => %job_id);
                        executor.job_skipped(job_id, SkipReason::BelowFloor);
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
                    let Some(rumors) = rumors else {
                        warn!(log, "not starting a job while draining"; "job_id" => %job_id);
                        session.job_started(request);
                        continue;
                    };
                    let successor = session
                        .session_id()
                        .next_job_id(&LastJob::Some(request.clone()));
                    let boundary = Boundary {
                        network: rumors.network(),
                        burned: self.past.burned_for(rumors.network()),
                        executed: self.past.executed_for(rumors.network(), started),
                        job: Some(Committed {
                            session: session.session_id(),
                            job: job_id,
                            successor,
                            outcome: JobOutcome::Committed,
                        }),
                    };
                    if executor.job_start(
                        &mut self.certs,
                        request.clone(),
                        params,
                        tx_attachment,
                        boundary,
                    ) {
                        self.attachments.insert(job_id, rx_attachment);
                    }
                }
            }
            session.job_started(request);
        }
    }
}

/// Apply one gossip message to the state, reporting update errors back
/// onto the network.
///
/// We unconditionally mark the watch sender as modified even though it
/// might not be, because *most* of the messages cause *some* modification
/// of the state, and we would rather be safe against future code changes
/// than manually tracking precisely which messages *don't* modify state.
/// The cost is a few spurious wakeups.
fn apply_message(
    log: &Logger,
    tx_state: &watch::Sender<State>,
    executor: &mut Executor,
    rumors: Option<&GossipNetwork>,
    own_baseboard: &BaseboardId,
    version: &Version,
    message: &Arc<VersionedMessage>,
) {
    tx_state.send_modify(|state| {
        if let Err(error) = state.update(log, executor, rumors, version, message) {
            error!(log, "state update failed"; "error" => ?error);
            // Re-gossiping a replayed message's error would grow the
            // set a little more on every rejoin by every sled.
            if state.is_live(version)
                && let Some(rumors) = rumors
            {
                debug!(log, "sending error to gossip network"; "error" => ?error);
                gossip(
                    log,
                    rumors,
                    Message::Event(own_baseboard.clone(), Event::Error(error)).into(),
                );
            }
        }
    });
}

/// Apply every message already delivered locally, without waiting for
/// more. Afterwards the local set is quiescent.
fn drain_ready(
    log: &Logger,
    causal_messages: &mut CausalMessages<VersionedMessage>,
    tx_state: &watch::Sender<State>,
    executor: &mut Executor,
    rumors: Option<&GossipNetwork>,
    own_baseboard: &BaseboardId,
) {
    while let Some(Some((version, message))) = causal_messages.next().now_or_never() {
        apply_message(
            log,
            tx_state,
            executor,
            rumors,
            own_baseboard,
            &version,
            &message,
        );
    }
}

/// Send a message into the gossip set. An error means the payload
/// exceeded the configured depth limit, which tests should catch.
fn gossip(log: &Logger, rumors: &GossipNetwork, message: VersionedMessage) {
    if let Err(error) = rumors.send(message) {
        error!(log, "the gossip set refused a message"; "error" => %error);
    }
}

/// Declare interrupted every job a previous life left running,
/// excluding `survivors` (jobs this incarnation carried across a
/// universe swap) and jobs already reaped. Zombies come only from
/// replayed start events, so a job this incarnation started is never
/// a candidate. Reap only at local quiescence (after
/// [`drain_ready`]), when a zombie whose terminal event is already
/// here has been cleared.
fn reap_zombies(
    log: &Logger,
    tx_state: &watch::Sender<State>,
    rumors: Option<&GossipNetwork>,
    own_baseboard: &BaseboardId,
    survivors: &BTreeSet<JobId>,
    reaped: &mut BTreeSet<JobId>,
) {
    let mut zombies = tx_state.borrow().zombies();
    zombies.retain(|job_id| !survivors.contains(job_id) && !reaped.contains(job_id));
    for job_id in zombies {
        reaped.insert(job_id);
        if let Some(rumors) = rumors {
            gossip(
                log,
                rumors,
                Message::Event(
                    own_baseboard.clone(),
                    Event::Job(JobEvent::Error(
                        job_id,
                        Utc::now(),
                        ProcessError::Interrupted,
                    )),
                )
                .into(),
            );
        }
        warn!(log, "interrupted job from a previous life"; "job_id" => %job_id);
    }
}

/// Adjudicate the boundary job if replay gave it no status on our
/// baseboard: announce its recorded ending, or interrupted when none
/// was recorded. No status means its fate never left this sled, and
/// no other sled can ever report it. A replayed start makes it a
/// zombie instead, and a replayed end settles it. Adjudicate only
/// after replay drains, like [`reap_zombies`], and once per universe.
/// The ruling is gossiped to every sled, but a sled that already
/// holds a terminal status for the job keeps it; only sleds with
/// none adopt the ruling, so one sled may show the real ending while
/// another shows interrupted.
fn adjudicate_boundary(
    log: &Logger,
    tx_state: &watch::Sender<State>,
    rumors: Option<&GossipNetwork>,
    own_baseboard: &BaseboardId,
    snapshot: Option<&Boundary>,
    survivors: &BTreeSet<JobId>,
    adjudicated: &mut Option<JobId>,
) {
    // A floor commits to no job, so there is nothing to rule on.
    let Some(Committed { job, outcome, .. }) = snapshot.and_then(|boundary| boundary.job.as_ref())
    else {
        return;
    };
    let job_id = *job;
    // One ruling per boundary: a sled that swaps universes again
    // without running a job must not re-adjudicate the same job.
    if *adjudicated == Some(job_id) {
        return;
    }
    // A survivor's events land in the new universe when it finishes,
    // so it needs no verdict now and may need one at a later swap.
    if survivors.contains(&job_id) {
        return;
    }
    *adjudicated = Some(job_id);
    let witnessed = {
        let state = tx_state.borrow();
        state
            .get_job_status(&job_id)
            .is_some_and(|status| status.get(own_baseboard).is_some())
    };
    if witnessed {
        return;
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
            JobEvent::Start(job_id, *time_started),
            JobEvent::Stop(job_id, *time_stopped, result.clone(), output.clone()),
        ],
        JobOutcome::Ended(JobStatus::Error {
            time_error, error, ..
        }) => vec![JobEvent::Error(job_id, *time_error, error.clone())],
        JobOutcome::Ended(_) | JobOutcome::Committed => vec![JobEvent::Error(
            job_id,
            Utc::now(),
            ProcessError::Interrupted,
        )],
    };
    if let Some(rumors) = rumors {
        for event in events {
            gossip(
                log,
                rumors,
                Message::Event(own_baseboard.clone(), Event::Job(event)).into(),
            );
        }
    }
    warn!(log, "adjudicated an unwitnessed job from a previous life"; "job_id" => %job_id);
}

/// The execution floor for entering a universe, or `None` when the
/// record can order everything this sled may meet there. Two kinds
/// of entry have history the record cannot order. Re-entering a
/// burned universe is the flip-flop: the record overwrote this
/// universe's watermark when it left, and the sled reports the
/// return as an error. Entering a universe that has history while
/// holding no record leaves the sled unable to tell a first visit
/// from a return after a clean slate: the universe may hold jobs
/// this baseboard already ran, and they must not run twice. Both
/// set the floor at the frontier that includes this life's first
/// send.
///
/// The floor must live in memory only. Its version is created by
/// sending a message, and if the sled dies before the message
/// reaches anyone, no other copy of it ever exists. A floor written
/// to disk would carry that dead version into the next life, where
/// no future session start could ever dominate it, and every one
/// would be refused until a cold boot. A floor raised fresh at each
/// entry is built from a message the living sled is actively
/// gossiping, so future sessions come to dominate it.
fn entry_floor(
    log: &Logger,
    snapshot: Option<&Boundary>,
    arrival: &Version,
    rumors: &GossipNetwork,
    own_baseboard: &BaseboardId,
) -> Option<Version> {
    let network = rumors.network();
    match snapshot {
        // A record committed in this universe is its watermark, even
        // when its burned set names this network: a sled that returns
        // and commits burns its own network into the replacement
        // record, and the Bloom set can never drop the stale entry.
        Some(boundary) if boundary.network != network && boundary.is_burned(network) => {
            warn!(
                log, "re-entered a universe this sled's boundary record burned";
                "committed" => ?boundary.job,
            );
            gossip(
                log,
                rumors,
                Message::Event(own_baseboard.clone(), Event::Error(Error::UniverseFlipFlop)).into(),
            );
        }
        None if *arrival != Version::new() => {
            warn!(log, "no boundary record, and this universe has history");
        }
        _ => return None,
    }
    Some(rumors.snapshot().latest().clone())
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
            session_sush_nonce.clone(),
            Past::new(
                Version::new(),
                Version::new(),
                store.clone(),
                boundary.clone(),
                None,
            ),
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

                // Before any message is processed: announce our build
                // (the send that starts this life's causal presence),
                // raise the floor in case the record burned the
                // initial universe, and take the birth mark that
                // splits this life's traffic from replayed history.
                let boundary = match &network {
                    Some((rumors, _)) => {
                        let arrival = rumors.snapshot().latest().clone();
                        gossip(
                            &log,
                            rumors,
                            Message::Event(
                                own_baseboard.clone(),
                                Event::Version(VersionInfo::current()),
                            )
                            .into(),
                        );
                        let floor =
                            entry_floor(&log, boundary.as_ref(), &arrival, rumors, &own_baseboard);
                        let birth = rumors.snapshot().latest().clone();
                        tx_state.send_modify(|state| {
                            state.past = Past::new(
                                arrival,
                                birth,
                                boundary_store.clone(),
                                boundary.clone(),
                                floor.clone(),
                            );
                        });
                        boundary
                    }
                    None => boundary,
                };
                if let Some(Committed { session, job, .. }) =
                    boundary.as_ref().and_then(|boundary| boundary.job.as_ref())
                {
                    info!(
                        log, "inherited an execution boundary; the committed session resumes at its stored successor";
                        "session_id" => %session, "job_id" => %job,
                    );
                }

                // Replay bookkeeping. `survivors` are jobs this
                // incarnation itself runs across a universe swap;
                // `reaped` are zombies already declared interrupted.
                let mut boundary = boundary;
                let mut survivors: BTreeSet<JobId> = BTreeSet::new();
                let mut reaped: BTreeSet<JobId> = BTreeSet::new();
                let mut adjudicated: Option<JobId> = None;

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
                                apply_message(
                                    &log,
                                    &tx_state,
                                    &mut executor,
                                    network.as_ref().map(|(rumors, _)| rumors),
                                    &own_baseboard,
                                    &version,
                                    &message,
                                );
                                // Replayed traffic can reveal zombies.
                                if !live {
                                    drain_ready(
                                        &log,
                                        &mut causal_messages,
                                        &tx_state,
                                        &mut executor,
                                        network.as_ref().map(|(rumors, _)| rumors),
                                        &own_baseboard,
                                    );
                                    reap_zombies(
                                        &log,
                                        &tx_state,
                                        network.as_ref().map(|(rumors, _)| rumors),
                                        &own_baseboard,
                                        &survivors,
                                        &mut reaped,
                                    );
                                    adjudicate_boundary(
                                        &log,
                                        &tx_state,
                                        network.as_ref().map(|(rumors, _)| rumors),
                                        &own_baseboard,
                                        boundary.as_ref(),
                                        &survivors,
                                        &mut adjudicated,
                                    );
                                }
                            },
                        },

                        // Follow the rack's cubby map.
                        Ok(()) = cubbies.changed() => {
                            tx_state.send_modify(|state| {
                                state.rack.set_cubbies(cubbies.borrow_and_update().clone());
                            });
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
                        // A reaped zombie may still show as running (its
                        // error event races the swap); it is no survivor.
                        // A job the executor is still launching is a
                        // survivor too: its start event may not have
                        // applied yet, but its events land in the new
                        // universe like any running job's.
                        survivors = tx_state.borrow().own_running_jobs();
                        survivors.extend(executor.in_flight());
                        survivors.retain(|job_id| !reaped.contains(job_id));
                        reaped = BTreeSet::new();
                        *rumors = fresh.rumors;
                        let arrival = rumors.snapshot().latest().clone();
                        gossip(
                            &log,
                            rumors,
                            Message::Event(
                                own_baseboard.clone(),
                                Event::Version(VersionInfo::current()),
                            )
                            .into(),
                        );
                        let boundary_store = tx_state.borrow().past.boundary.clone();
                        boundary = boundary_store.boundary();
                        let floor =
                            entry_floor(&log, boundary.as_ref(), &arrival, rumors, &own_baseboard);
                        let birth = rumors.snapshot().latest().clone();
                        // TODO: re-inject local job state (policy pending).
                        tx_state.send_modify(|state| {
                            *state = State::new(
                                own_baseboard.clone(),
                                &anchors,
                                state.session_sush_nonce.clone(),
                                Past::new(
                                    arrival,
                                    birth,
                                    boundary_store.clone(),
                                    boundary.clone(),
                                    floor.clone(),
                                ),
                            )
                            .expect("trust anchors validated at startup");
                            state.rack.set_cubbies(cubbies.borrow().clone());
                        });
                        // The set received at join is already local:
                        // drain it, then reap.
                        drain_ready(
                            &log,
                            &mut causal_messages,
                            &tx_state,
                            &mut executor,
                            Some(&*rumors),
                            &own_baseboard,
                        );
                        reap_zombies(
                            &log,
                            &tx_state,
                            Some(&*rumors),
                            &own_baseboard,
                            &survivors,
                            &mut reaped,
                        );
                        adjudicate_boundary(
                            &log,
                            &tx_state,
                            Some(&*rumors),
                            &own_baseboard,
                            boundary.as_ref(),
                            &survivors,
                            &mut adjudicated,
                        );
                    }
                }
            }),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn network(seed: u8) -> Network {
        serde_json::from_str(&format!("[{seed:?}{}]", ", 0".repeat(15))).unwrap()
    }

    fn past(committed: Option<Boundary>, floor: Option<Version>) -> Past {
        let log = Logger::root(slog::Discard, o!());
        Past::new(
            Version::new(),
            Version::new(),
            Arc::new(BoundaryStore::new(&log, &Locker::null())),
            committed,
            floor,
        )
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
    /// in every universe: the floor belongs to this life, not to any
    /// record.
    #[test]
    fn floors_refuse_below() {
        let floor: Version = "(1, 1, (0, 0, 2))".parse().unwrap();
        let at: Version = floor.clone();
        let below: Version = "(1, 0, (0, 0, 2))".parse().unwrap();
        let above: Version = "(2, 1, (0, 0, 3))".parse().unwrap();
        let concurrent: Version = "(1, 2, (0, 0, 1))".parse().unwrap();
        let past = past(None, Some(floor.clone()));

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
