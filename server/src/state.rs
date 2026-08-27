// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Session state manager.
//!
//! Manage sessions and their associated jobs by sending and receiving
//! messages via the gossip protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use lru::LruCache;
use rumors::{Peer, Rumors, Version};
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, error, info, o, warn};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_api::JobStartParams;
use sush_common::authn::{Identity, Nonce, RequestVerifier, SignedLogin};
use sush_common::jobs::{
    Access, JobId, JobStatus, JobStatusMap, ProcessError, Session, SessionId, SessionSushNonce,
    SignedJob,
};
use sush_common::keys::{KeyError, KeyId, Signature, SshPublicKey};
use sush_common::targets::Cubbies;
use sush_common::version::{VersionInfo, VersionMap};

use crate::executor::{Executor, PathIsolation};
use crate::gossip::Universe;
use crate::history::JobHistory;
use crate::job::SocketSender;
use crate::messages::v0::{
    CertRequest, Error, Event, IdentityRequest, JobEvent, JobRequest, Message, Request,
    SessionRequest,
};
use crate::messages::{VersionedMessage, VersionedMessage::*};
use crate::output::JobOutputDir;

pub type AttachmentPoints = BTreeMap<JobId, watch::Receiver<Option<SocketSender>>>;
pub type Certificates = BTreeMap<KeyId, CertState>;
pub type GossipNetwork = Rumors<VersionedMessage>;
pub type GossipUniverse = Universe<VersionedMessage>;
pub type QueuedJobs = BTreeMap<JobId, QueuedJob>;
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

/// Maximum number of revocations held for certificates not yet seen.
pub const MAX_TOMBSTONES: NonZeroUsize = NonZeroUsize::new(100).unwrap();

/// Maximum number of registered identities. Evicting a real login
/// only costs its holder a fresh key touch.
pub const MAX_REGISTERED_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// Maximum number of revoked SSH keys remembered for login refusal.
/// Any authenticated key may revoke, so a flood of junk revocations
/// can evict a real one. Entries never expire, so unlike nonces the
/// eviction is permanent. This is sized so the flood takes thousands
/// of authenticated, attributed, logged requests.
pub const MAX_REVOKED_KEYS: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// A rack-wide record of a verified login.
#[derive(Clone, Debug)]
pub struct RegisteredIdentity {
    pub identity: Identity,
    pub verifier: RequestVerifier,
}

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
        /// Start of this session; identity anchor.
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

/// A dynamic guard around an active session and its job queue.
struct SessionGuard<'a> {
    inner: &'a mut Session,
    queued_jobs: &'a mut QueuedJobs,
}

impl<'a> SessionGuard<'a> {
    pub fn session_id(&self) -> SessionId {
        self.inner.session_id()
    }

    pub fn started_by(&self) -> Option<&KeyId> {
        self.inner.started_by()
    }

    pub fn job_started(&mut self, job: SignedJob) {
        self.inner.job_started(job)
    }

    pub fn skip_job(&mut self, job_id: &JobId) -> bool {
        self.inner.skip_job(*job_id)
    }

    pub fn next_queued_job(&mut self) -> Option<QueuedJob> {
        self.queued_jobs.remove(&self.inner.next_job_id())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_job(
        &mut self,
        log: &Logger,
        history: &mut JobHistory,
        running: &RunningJobs,
        own_baseboard: &BaseboardId,
        cubbies: &Cubbies,
        job: SignedJob,
        params: JobStartParams,
        actor: &KeyId,
        replayed: bool,
    ) {
        let job_id = *job.job_id();
        let targeted = job.payload().runs_on(own_baseboard, cubbies);
        if history.contains(&job_id) {
            // Note but otherwise ignore the duplicate job.
            info!(log, "already started job"; "job_id" => %job_id);
        } else if self.queued_jobs.len() >= MAX_QUEUED_JOBS
            && !self.queued_jobs.contains_key(&job_id)
        {
            // We have no choice; drop the job on the floor.
            warn!(log, "too many jobs queued"; "job_id" => %job_id, "max" => MAX_QUEUED_JOBS);
        } else {
            // Insert the job into our queue. Every job joins the
            // queue to keep the causal chain whole, but only jobs
            // targeting this sled that can actually run here record
            // a local status.
            self.queued_jobs.insert(
                job_id,
                QueuedJob {
                    job,
                    params,
                    replayed,
                },
            );
            if targeted && !replayed {
                history.set_job_status(
                    &job_id,
                    own_baseboard,
                    JobStatus::Queued {
                        job_id,
                        time_queued: Utc::now(),
                        actor: actor.clone(),
                    },
                    None,
                    Some(self.queued_jobs),
                    running,
                );
            }
        }
    }

    pub fn cancel_job(
        &mut self,
        job_id: &JobId,
        actor: &KeyId,
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
                    job_id: *job_id,
                    time_cancelled: Utc::now(),
                    actor: actor.clone(),
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
    #[allow(clippy::too_many_arguments)]
    pub fn execute_ready_jobs(
        &mut self,
        log: &Logger,
        own_baseboard: &BaseboardId,
        cubbies: &Cubbies,
        certs: &mut Certificates,
        history: &mut JobHistory,
        executor: &mut Executor,
        attachments: &mut AttachmentPoints,
    ) {
        while let Some(QueuedJob {
            job: request,
            params,
            replayed,
        }) = self.next_queued_job()
        {
            let (tx_attachment, rx_attachment) = watch::channel(None);
            let job_id = request.payload().job_id().to_owned();
            if request.payload().runs_on(own_baseboard, cubbies) {
                if replayed {
                    info!(log, "not executing replayed job"; "job_id" => %job_id);
                } else if history
                    .get_job_status(&job_id)
                    .map(|status| {
                        matches!(status.get(own_baseboard), Some(JobStatus::Queued { .. }))
                    })
                    .unwrap_or(true)
                {
                    executor.job_start(certs, request.clone(), params, tx_attachment);
                    attachments.insert(job_id, rx_attachment);
                }
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
    /// The nonce binding new session IDs to this sled, shared with the
    /// manager and rotated whenever a session activates.
    session_sush_nonce: Arc<Mutex<SessionSushNonce>>,
    /// Revocations of certificates we have never seen. Bounded and
    /// apart from `certs`, so revocation spam evicts only itself.
    tombstones: LruCache<KeyId, DateTime<Utc>>,
    /// Hard-coded root certificate key IDs. Self-signed certificates
    /// not in this set will be revoked with prejudice.
    roots: Box<[KeyId]>,
    /// Baseboards by cubby number, as much of it as is known.
    cubbies: Cubbies,
    /// The causal frontier we joined this universe at, if we joined
    /// rather than seeded it. Messages at or concurrent with it are
    /// replayed history: they rebuild state but never execute here.
    join_frontier: Option<Version>,
    /// Message versions from newer builds, each warned about once.
    unknown_versions: BTreeSet<String>,
    /// Build provenance by sled.
    versions: VersionMap,
    /// Verified logins, rack-wide.
    identities: LruCache<(KeyId, Nonce), RegisteredIdentity>,
    /// SSH keys refused at login.
    revoked_keys: LruCache<KeyId, DateTime<Utc>>,
}

impl State {
    /// Fails if any root certificate is malformed or does not validate. Roots
    /// are supplied by whoever configures the server, so they are not
    /// necessarily trustworthy just because they were handed to us.
    pub fn new(
        own_baseboard: BaseboardId,
        root_certs: &[Certificate],
        session_sush_nonce: Arc<Mutex<SessionSushNonce>>,
        join_frontier: Option<Version>,
    ) -> Result<Self, KeyError> {
        let certs = root_certs
            .iter()
            .map(|cert| {
                Ok((
                    KeyId::try_from(cert)?,
                    CertState::Unknown(Box::new(cert.clone())),
                ))
            })
            .collect::<Result<BTreeMap<KeyId, CertState>, KeyError>>()?;
        let roots: Box<[KeyId]> = certs.keys().cloned().collect();
        let mut new = Self {
            versions: [(own_baseboard.clone(), VersionInfo::current())].into(),
            own_baseboard,
            running: Default::default(),
            history: Default::default(),
            session: Default::default(),
            attachments: Default::default(),
            session_sush_nonce,
            tombstones: LruCache::new(MAX_TOMBSTONES),
            certs,
            roots: roots.clone(),
            cubbies: Default::default(),
            unknown_versions: Default::default(),
            identities: LruCache::new(MAX_REGISTERED_IDENTITIES),
            revoked_keys: LruCache::new(MAX_REVOKED_KEYS),
            join_frontier,
        };
        new.validate_certs(&roots);
        for root in &roots {
            if !new.certs[root].is_valid() {
                return Err(KeyError::InvalidCert(format!(
                    "root certificate `{root}` does not validate"
                )));
            }
        }
        Ok(new)
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

    pub fn cubbies(&self) -> &Cubbies {
        &self.cubbies
    }

    pub fn versions(&self) -> &VersionMap {
        &self.versions
    }

    pub fn history(&self) -> &JobHistory {
        &self.history
    }

    pub fn get_job_status(&self, job_id: &JobId) -> Option<&JobStatusMap> {
        self.history.get_job_status(job_id)
    }

    /// Import the first certificate seen for a key. Re-importing the
    /// identical certificate is a no-op. Anything else at an occupied
    /// key ID is refused, so no import can displace an established
    /// certificate.
    fn cert_import(&mut self, cert: &Certificate) -> Result<KeyId, KeyError> {
        if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
            return Err(KeyError::SelfSigned);
        }
        let key_id = KeyId::try_from(cert)?;
        // A tombstone becomes a durable revocation once its
        // certificate shows up. `certs` may briefly exceed `MAX_CERTS`
        // by the tombstone count.
        if let Some(when) = self.tombstones.pop(&key_id) {
            self.certs
                .insert(key_id.clone(), CertState::Revoked(key_id.clone(), when));
            return Err(KeyError::Revoked(key_id, when));
        }
        match self.certs.get(&key_id) {
            Some(CertState::Revoked(_, when)) => Err(KeyError::Revoked(key_id, *when)),
            Some(existing) if existing.cert() == Some(cert) => Ok(key_id),
            Some(_) => Err(KeyError::CertConflict(key_id)),
            None if self.certs.len() >= MAX_CERTS => Err(KeyError::TooManyCerts(MAX_CERTS)),
            None => {
                self.certs
                    .insert(key_id.clone(), CertState::Unknown(Box::new(cert.clone())));
                Ok(key_id)
            }
        }
    }

    pub fn cert_chain(&self, key_id: &KeyId) -> Result<Vec<Certificate>, KeyError> {
        cert_chain(&self.certs, key_id)
    }

    pub fn num_certs(&self) -> usize {
        self.certs.len()
    }

    pub fn is_root(&self, key_id: &KeyId) -> bool {
        self.roots.contains(key_id)
    }

    pub fn is_cert_revoked(&self, key_id: &KeyId) -> bool {
        matches!(self.certs.get(key_id), Some(CertState::Revoked(..)))
            || self.tombstones.peek(key_id).is_some()
    }

    pub fn registered_identity(&self, key: &(KeyId, Nonce)) -> Option<&RegisteredIdentity> {
        self.identities.peek(key)
    }

    pub fn is_key_revoked(&self, key_id: &KeyId) -> bool {
        self.revoked_keys.peek(key_id).is_some()
    }

    #[allow(clippy::result_large_err)]
    fn update(
        &mut self,
        log: &Logger,
        executor: &mut Executor,
        incoming_version: &Version,
        message: &Arc<VersionedMessage>,
    ) -> Result<(), Error> {
        use SessionState::*;
        match message.as_ref() {
            V0(Message::Request(request)) => match request {
                Request::Cert(attributed) => match attributed.as_parts() {
                    (actor, CertRequest::Import(cert)) => match self.cert_import(cert) {
                        Ok(key_id) => {
                            info!(log, "imported certificate"; "key_id" => %key_id, "actor" => %actor);
                            self.validate_certs(&self.roots.clone());
                        }
                        Err(error) => {
                            error!(log, "ignoring invalid certificate"; "error" => %error);
                        }
                    },
                    (actor, CertRequest::Revoke(key_id, when)) => {
                        if self.roots.contains(key_id) {
                            error!(log, "refusing to revoke root certificate"; "key_id" => %key_id);
                        } else if let Some(cert) = self.certs.get_mut(key_id) {
                            *cert = CertState::Revoked(key_id.clone(), *when);
                            info!(log, "revoked known certificate"; "key_id" => %key_id, "actor" => %actor);
                        } else {
                            self.tombstones.put(key_id.clone(), *when);
                            info!(log, "revoked unknown certificate"; "key_id" => %key_id, "actor" => %actor);
                        }
                    }
                },
                Request::Session(attributed) => match attributed.as_parts() {
                    (actor, SessionRequest::Start(session_id)) => match &mut self.session {
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
                            self.session = Active {
                                frontier: self.session.frontier() | incoming_version.clone(),
                                started: incoming_version.clone(),
                                session: Box::new(Session::started(*session_id, actor.clone())),
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
                                own_version: started.clone(),
                                incoming_session: *session_id,
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
                    (actor, SessionRequest::Stop(session_id)) => {
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
                                self.session = Inactive {
                                    frontier: frontier.clone(),
                                }
                            }
                        }
                    }
                    (actor, SessionRequest::AllowAttach(session_id, key_id, access)) => {
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
                    (actor, SessionRequest::DenyAttach(session_id, key_id)) => {
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
                    (actor, SessionRequest::Skip(session_id, job_id)) => {
                        if let Some(mut session) = self.session.active_session()
                            && session.session_id() == *session_id
                        {
                            if session.started_by() != Some(actor) {
                                warn!(
                                    log, "ignoring job skip from non-starter";
                                    "job_id" => %job_id, "actor" => %actor,
                                );
                            } else if session.skip_job(job_id) {
                                info!(
                                    log, "job skipped";
                                    "job_id" => %job_id, "actor" => %actor,
                                );
                                session.cancel_job(
                                    job_id,
                                    actor,
                                    &self.own_baseboard,
                                    &mut self.history,
                                    &self.running,
                                );
                                session.execute_ready_jobs(
                                    log,
                                    &self.own_baseboard,
                                    &self.cubbies,
                                    &mut self.certs,
                                    &mut self.history,
                                    executor,
                                    &mut self.attachments,
                                );
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
                },
                Request::Job(attributed) => match attributed.as_parts() {
                    (actor, JobRequest::Start(signed, params)) => {
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
                        // Refused jobs targeting this sled record an error
                        // status so the submitter learns their fate.
                        let session_id = signed.payload().session_id();
                        let live = self
                            .join_frontier
                            .as_ref()
                            .is_none_or(|frontier| incoming_version > frontier);
                        match self.session.active_session() {
                            Some(mut session) if session.session_id() == session_id => {
                                session.enqueue_job(
                                    log,
                                    &mut self.history,
                                    &self.running,
                                    &self.own_baseboard,
                                    &self.cubbies,
                                    signed.clone(),
                                    params.clone(),
                                    actor,
                                    !live,
                                );
                                session.execute_ready_jobs(
                                    log,
                                    &self.own_baseboard,
                                    &self.cubbies,
                                    &mut self.certs,
                                    &mut self.history,
                                    executor,
                                    &mut self.attachments,
                                );
                            }
                            _ => {
                                let job_id = *signed.job_id();
                                warn!(
                                    log, "refusing job for inactive session";
                                    "job_id" => %job_id,
                                    "session_id" => %session_id,
                                    "actor" => %actor,
                                );
                                if live
                                    && signed.payload().runs_on(&self.own_baseboard, &self.cubbies)
                                    && !self.history.contains(&job_id)
                                {
                                    executor.job_refused(
                                        job_id,
                                        ProcessError::InvalidJob(format!(
                                            "session `{session_id}` is not active"
                                        )),
                                    );
                                }
                            }
                        }
                    }
                    (actor, JobRequest::Stop(job_id)) => {
                        executor.job_stop(job_id);
                        if let Some(mut session) = self.session.active_session() {
                            session.cancel_job(
                                job_id,
                                actor,
                                &self.own_baseboard,
                                &mut self.history,
                                &self.running,
                            );
                        }
                    }
                },
                Request::Identity(attributed) => match attributed.as_parts() {
                    (actor, IdentityRequest::Login(public_key, signed)) => {
                        match verify_login(public_key, signed) {
                            Ok(registered) => {
                                let identity = &registered.identity;
                                if self.revoked_keys.peek(&identity.key_id).is_some() {
                                    info!(
                                        log, "refusing login for revoked key";
                                        "key_id" => %identity.key_id, "actor" => %actor,
                                    );
                                } else {
                                    info!(
                                        log, "registered identity";
                                        "key_id" => %identity.key_id, "actor" => %actor,
                                    );
                                    let key = (identity.key_id.clone(), identity.nonce.clone());
                                    self.identities.put(key, registered);
                                }
                            }
                            Err(error) => {
                                error!(
                                    log, "ignoring invalid login";
                                    "error" => %error, "actor" => %actor,
                                );
                            }
                        }
                    }
                    (actor, IdentityRequest::Revoke(key_id, when)) => {
                        let dead: Vec<(KeyId, Nonce)> = self
                            .identities
                            .iter()
                            .filter(|((id, _), _)| id == key_id)
                            .map(|(key, _)| key.clone())
                            .collect();
                        for key in dead {
                            self.identities.pop(&key);
                        }
                        self.revoked_keys.put(key_id.clone(), *when);
                        info!(log, "revoked identity"; "key_id" => %key_id, "actor" => %actor);
                    }
                },
            },
            V0(Message::Event(baseboard_id, event)) => match event {
                // Track the active set of known-running jobs anywhere in the rack.
                Event::Job(job_event) => match job_event {
                    JobEvent::Start(job_id, when) => {
                        info!(log, "job started"; "job_id" => %job_id, "when" => %when);
                        self.running.insert((*job_id, baseboard_id.clone()), *when);
                        self.history.set_job_status(
                            job_id,
                            baseboard_id,
                            JobStatus::Started {
                                job_id: *job_id,
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
                        self.running.remove(&(*job_id, baseboard_id.clone()));
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
                        self.running.remove(&(*job_id, baseboard_id.clone()));
                        self.history.set_job_status(
                            job_id,
                            baseboard_id,
                            JobStatus::Error {
                                job_id: *job_id,
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
                Event::Version(info) => {
                    // Our own seed is authoritative, and may be newer
                    // than a replayed announce from a previous boot.
                    if *baseboard_id != self.own_baseboard {
                        info!(log, "sled version"; "sled" => %baseboard_id, "version" => %info);
                        self.versions.insert(baseboard_id.clone(), info.clone());
                    }
                }
            },
            Unknown(version) => {
                if self.unknown_versions.insert(version.clone()) {
                    warn!(log, "ignoring messages from a newer peer"; "version" => version);
                }
            }
        }

        Ok(())
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
        if let Err(error) = state.update(log, executor, version, message) {
            error!(log, "state update failed"; "error" => ?error);
            if let Some(rumors) = rumors {
                debug!(log, "sending error to gossip network"; "error" => ?error);
                rumors.send(Message::Event(own_baseboard.clone(), Event::Error(error)).into());
            }
        }
    });
}

/// Create a fresh gossip network with this server as its only peer.
///
/// A peer that seeds its own network has no one to gossip with, so jobs run
/// only on the server that accepted them, and no server learns about any other
/// server's sessions. This stands in for joining the rack's network over
/// sprockets on the bootstrap network.
pub fn seed_gossip() -> GossipNetwork {
    Peer::seed().into_rumors()
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
        universe: watch::Receiver<GossipUniverse>,
        roots: &[Certificate],
        session_sush_nonce: Arc<Mutex<SessionSushNonce>>,
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
        let Universe {
            rumors: initial,
            frontier,
        } = universe.borrow().clone();
        let mut causal_messages = initial.causal_messages();

        // We report our current state through a watch channel.
        let mut initial_state = State::new(
            own_baseboard.clone(),
            roots,
            session_sush_nonce.clone(),
            frontier,
        )?;
        initial_state.cubbies = cubbies.borrow_and_update().clone();
        let (tx_state, rx_state) = watch::channel(initial_state);
        let roots = roots.to_vec();

        // The executor needs to have access to send messages back.
        let (mut executor, mut events) = Executor::new(
            log.new(o!("component" => "executor")),
            path_isolation,
            output_dir,
            shutdown.child_token(),
        );

        // We will drop this once we want to drain the remaining messages.
        // The watch channel behind `universe` stores its own copy of the
        // network, so holding the receiver would keep the network from
        // draining while we wait for exactly that.
        let mut gossip = Some((initial, universe));

        Ok((
            rx_state,
            spawn(async move {
                info!(log, "managing state");

                // Announce our build.
                if let Some((rumors, _)) = &gossip {
                    rumors.send(
                        Message::Event(
                            own_baseboard.clone(),
                            Event::Version(VersionInfo::current()),
                        )
                        .into(),
                    );
                }

                // These flip both to `true` once our two input streams (local
                // requests and local events from the executor) terminate or
                // we're shutting down. At this point, we must drop `gossip`
                // and thereby permit its own `unordered_messages` stream to
                // eventually be drained; we do this so that we fully update
                // the local state until nothing more is left to do.
                let mut requests_empty = false;
                let mut events_empty = false;

                loop {
                    let message = causal_messages.next();

                    // Once we drain the requests and events, we drop `gossip` so
                    // that if there are no outstanding copies elsewhere, we will
                    // drain it and then break.
                    //
                    // If there are still gossip sessions happening, those will
                    // complete and we will process their messages into the state.
                    if requests_empty && events_empty {
                        gossip = None;
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
                            Some(request) => if let Some((rumors, _)) = &gossip {
                                debug!(log, "forwarding request to gossip network"; "kind" => request.kind());
                                rumors.send(Message::Request(request).into());
                            },
                        },

                        // Handle events produced by the executor.
                        next = events.next(), if !events_empty => match next {
                            None => events_empty = true,
                            Some(event) => if let Some((rumors, _)) = &gossip {
                                debug!(log, "forwarding event to gossip network"; "event" => ?event);
                                rumors.send(Message::Event(own_baseboard.clone(), event).into());
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
                                apply_message(
                                    &log,
                                    &tx_state,
                                    &mut executor,
                                    gossip.as_ref().map(|(rumors, _)| rumors),
                                    &own_baseboard,
                                    &version,
                                    &message,
                                );
                            },
                        },

                        // Follow the rack's cubby map.
                        Ok(()) = cubbies.changed() => {
                            tx_state.send_modify(|state| {
                                state.cubbies = cubbies.borrow_and_update().clone();
                            });
                        },

                        // Follow the gossip manager to a new universe,
                        // unless we're already draining.
                        Ok(()) = async {
                            match gossip.as_mut() {
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
                            gossip.as_mut().expect("gossip present when it changes");
                        let fresh = universe.borrow_and_update().clone();
                        info!(log, "gossip universe changed, resetting state"; "network" => %fresh.rumors.network());
                        causal_messages = fresh.rumors.causal_messages();
                        // TODO: re-inject local job state (policy pending).
                        tx_state.send_modify(|state| {
                            *state = State::new(
                                own_baseboard.clone(),
                                &roots,
                                state.session_sush_nonce.clone(),
                                fresh.frontier.clone(),
                            )
                            .expect("roots validated at startup");
                            state.cubbies = cubbies.borrow().clone();
                        });
                        *rumors = fresh.rumors;
                        rumors.send(
                            Message::Event(
                                own_baseboard.clone(),
                                Event::Version(VersionInfo::current()),
                            )
                            .into(),
                        );
                    }
                }
            }),
        ))
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
/// `Unknown → Unknown` while no valid issuer verifies the certificate;
/// `Unknown → Invalid` on an intrinsic failure (bad encoding, or self-signed
/// without being a root); and any state `→ Revoked`, from which no state
/// ever returns.
#[derive(Debug)]
pub enum CertState {
    Unknown(Box<Certificate>),
    /// A validated certificate and the key ID of the issuer that
    /// verified it, or `None` for a root.
    Valid(Box<Certificate>, Option<KeyId>),
    Invalid(KeyError),
    Revoked(KeyId, DateTime<Utc>),
}

impl CertState {
    fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(..))
    }

    fn cert(&self) -> Option<&Certificate> {
        match self {
            Self::Unknown(cert) | Self::Valid(cert, _) => Some(cert),
            Self::Invalid(_) | Self::Revoked(..) => None,
        }
    }

    fn map_valid<R>(&self, f: impl FnOnce(&Certificate) -> &R) -> Option<&R> {
        if let Self::Valid(cert, _) = self {
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
            // TODO: check expiry, basicConstraints, keyUsage.
            let signature = with_err!(Signature::try_from(cert.as_ref()));
            let tbs = with_err!(cert.tbs_certificate.to_der());
            let subject = &cert.tbs_certificate.subject;
            let issuer = &cert.tbs_certificate.issuer;
            if subject == issuer {
                let key_id = with_err!(KeyId::try_from(cert.as_ref()));
                if !roots.contains(&key_id) {
                    return Self::Invalid(KeyError::SelfSigned);
                }
                with_err!(
                    signature.verify_with_spki(&tbs, &cert.tbs_certificate.subject_public_key_info)
                );
                return Self::Valid(cert, None);
            }
            // The issuer name only routes: the parent is whichever valid
            // certificate of that name verifies the signature, so a
            // homonym cannot take the true parent's place. Until such a
            // parent arrives the certificate stays `Unknown`, keeping
            // the outcome independent of delivery order.
            for (key_id, candidate) in certs {
                if let Some(parent) = candidate.map_valid(|cert| cert)
                    && parent.tbs_certificate.subject == *issuer
                    && signature
                        .verify_with_spki(&tbs, &parent.tbs_certificate.subject_public_key_info)
                        .is_ok()
                {
                    return Self::Valid(cert, Some(key_id.clone()));
                }
            }
            Self::Unknown(cert)
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

/// Re-verify gossiped login evidence. Identity gossip carries the
/// signed challenge response, not another sled's conclusion, so a
/// registered identity never depends on that sled's honesty.
fn verify_login(
    public_key: &SshPublicKey,
    signed: &SignedLogin,
) -> Result<RegisteredIdentity, KeyError> {
    let verified = signed.clone().verify_with_ssh_public_key(public_key)?;
    let verifier = verified.epk().clone();
    let identity = Identity::new(public_key.clone(), verified, Utc::now())?;
    Ok(RegisteredIdentity { identity, verifier })
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
        let (cert, parent) = match certs.get(&key_id) {
            None | Some(CertState::Unknown(_)) => return Err(KeyError::MissingCert(key_id)),
            Some(CertState::Valid(cert, parent)) => (*cert.clone(), parent.clone()),
            Some(CertState::Invalid(error)) => {
                return Err(KeyError::InvalidCert(error.to_string()));
            }
            Some(CertState::Revoked(key_id, when)) => {
                return Err(KeyError::Revoked(key_id.clone(), *when));
            }
        };
        chain.push(cert);
        match parent {
            None => break,
            Some(parent) => key_id = parent,
        }
    }
    assert!(!chain.is_empty());
    chain.reverse();
    Ok(chain)
}
