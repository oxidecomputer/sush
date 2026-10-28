// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Manage job signature verification and the session state machine.
//! Does not manage jobs directly.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::Duration;

use http_range_header::SyntacticallyCorrectRange as Range;
use sled_hardware_types::BaseboardId;
use slog::{Logger, info, o};
use tokio::fs::read;
use tokio::select;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::der::DecodePem as _;

use sush_api::{JobStartParams, JobStopParams, JobWait};
use sush_common::jobs::{
    Access, JobId, JobOutputStream, JobStatusMap, Session, SessionClientNonce, SessionId,
    SessionPreimage, SessionSeq, SessionServerNonce, SessionSignerNonce, SessionSushNonce,
    SignedJob,
};
use sush_common::keys::{KeyError, KeyId};
use sush_common::targets::{Cubbies, SledHealth, SledVersion, Target, UnknownCubby};
use sush_common::version::LONG_VERSION;

use crate::error::JobError;
use crate::executor::PathIsolation;
use crate::gossip::LinkedBaseboards;
use crate::job::SocketSender;
use crate::locker::Locker;
use crate::locker::boundary::BoundaryStore;
use crate::messages::v0::{JobRequest, Request, SessionRequest};
use crate::output::{JobOutputDir, JobOutputFileStream};
use crate::state::{GossipUniverse, State, StateManager};

/// Maximum amount of time we're willing to wait for job start or stop.
const WAIT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug)]
pub struct JobManager {
    log: Logger,
    session_server_nonce: Arc<SyncMutex<SessionServerNonce>>,
    output_dir: JobOutputDir,
    own_baseboard: BaseboardId,
    linked: LinkedBaseboards,
    state: watch::Receiver<State>, // from the state manager
    tx_req: mpsc::Sender<Request>, // to the state manager
    join_state: Option<JoinHandle<()>>,
}

impl JobManager {
    /// Trust the certificates in `anchors`, one PEM-encoded certificate
    /// per file.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        log: Logger,
        path_isolation: PathIsolation,
        output_dir: JobOutputDir,
        own_baseboard: BaseboardId,
        cubbies: watch::Receiver<Cubbies>,
        universe: watch::Receiver<GossipUniverse>,
        linked: LinkedBaseboards,
        locker: &Locker,
        anchors: &[impl AsRef<Path>],
        shutdown: CancellationToken,
    ) -> Result<Self, JobError> {
        let anchors = read_certs(anchors).await?;
        Self::with_trust_anchors(
            log,
            path_isolation,
            output_dir,
            own_baseboard,
            cubbies,
            universe,
            linked,
            locker,
            &anchors,
            shutdown,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn with_trust_anchors(
        log: Logger,
        path_isolation: PathIsolation,
        output_dir: JobOutputDir,
        own_baseboard: BaseboardId,
        cubbies: watch::Receiver<Cubbies>,
        universe: watch::Receiver<GossipUniverse>,
        linked: LinkedBaseboards,
        locker: &Locker,
        anchors: &[Certificate],
        shutdown: CancellationToken,
    ) -> Result<Self, JobError> {
        info!(log, "starting sush"; "version" => LONG_VERSION);
        let (tx_req, rx_req) = mpsc::channel(16);
        let requests = ReceiverStream::new(rx_req);
        let session_server_nonce = Arc::new(SyncMutex::new(SessionServerNonce::random()));
        let boundary = Arc::new(BoundaryStore::new(&log, locker));
        boundary.load().await;
        let (rx_state, join_state) = StateManager::run(
            log.new(o!("component" => "state manager")),
            path_isolation,
            output_dir.clone(),
            own_baseboard.clone(),
            requests,
            cubbies,
            universe,
            anchors,
            boundary,
            shutdown,
        )?;
        Ok(Self {
            log: log.new(o!("component" => "job manager")),
            session_server_nonce,
            own_baseboard,
            linked,
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
        let linked = self.linked.borrow();
        let mut sleds: BTreeSet<&BaseboardId> = state.rack().versions().keys().collect();
        sleds.extend(state.rack().cubbies().values());
        let mut rows: Vec<SledVersion> = sleds
            .into_iter()
            .map(|baseboard| SledVersion {
                cubby: state
                    .rack()
                    .cubbies()
                    .iter()
                    .find_map(|(cubby, b)| (b == baseboard).then_some(*cubby)),
                baseboard: baseboard.clone(),
                version: state.rack().versions().get(baseboard).cloned(),
                health: Some(
                    if *baseboard == self.own_baseboard || linked.contains(baseboard) {
                        SledHealth::Linked
                    } else {
                        SledHealth::Unlinked
                    },
                ),
            })
            .collect();
        rows.sort_by_key(|row| (row.cubby.is_none(), row.cubby));
        rows
    }

    async fn session_request(
        &self,
        authn: &KeyId,
        request: SessionRequest,
    ) -> Result<(), JobError> {
        self.tx_req
            .send(Request::session(authn.clone(), request))
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    async fn job_request(&self, authn: &KeyId, request: JobRequest) -> Result<(), JobError> {
        self.tx_req
            .send(Request::job(authn.clone(), request))
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    // Certificate management.

    pub fn cert_chain(&self, _authn: &KeyId, key_id: &KeyId) -> Result<Vec<Certificate>, JobError> {
        Ok(self.state.borrow().certs().chain(key_id)?)
    }

    // Waiting.

    pub fn take_join_handle(&mut self) -> Option<JoinHandle<()>> {
        self.join_state.take()
    }

    /// Wait until the job's status matches `wait` on each of `sleds`
    /// that this sled still links to.
    async fn wait_for_job(
        &self,
        job_id: &JobId,
        wait: JobWait,
        sleds: BTreeSet<BaseboardId>,
    ) -> Result<(), JobError> {
        if !wait.is_some() {
            return Ok(());
        }
        let settled = |state: &State, linked: &BTreeSet<BaseboardId>| {
            let statuses = state.get_job_status(job_id);
            sleds.iter().all(|sled| {
                let gone = *sled != self.own_baseboard && !linked.contains(sled);
                gone || statuses
                    .and_then(|map| map.get(sled))
                    .is_some_and(|status| wait.matches_status(status))
            })
        };
        let mut state = self.state.clone();
        let mut linked = self.linked.clone();
        timeout(WAIT_TIMEOUT, async {
            while !settled(&state.borrow_and_update(), &linked.borrow_and_update()) {
                select! {
                    changed = state.changed() => changed.map_err(JobError::closed)?,
                    () = linked.changed() => (),
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| JobError::Timeout)?
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

    pub fn session(&self, _authn: &KeyId) -> Option<Session> {
        self.state.borrow().session().cloned()
    }

    pub async fn session_id(&self, authn: &KeyId) -> Result<SessionId, JobError> {
        let Some(session) = self.session(authn) else {
            return Err(JobError::NoSession);
        };
        Ok(session.into_session_id())
    }

    /// Replace the current server nonce with a fresh one and return
    /// it. A fetch is the only rotation, so a client must finish its
    /// ceremony before the next fetch.
    pub fn fresh_server_nonce(&self) -> SessionServerNonce {
        let nonce = SessionServerNonce::random();
        *self.session_server_nonce.lock().unwrap() = nonce;
        nonce
    }

    pub async fn session_start(
        &self,
        authn: &KeyId,
        session_id: SessionId,
        client_nonce: SessionClientNonce,
        signer_nonce: SessionSignerNonce,
        seq: SessionSeq,
    ) -> Result<(), JobError> {
        // Verify the session ID provided by the client.
        let server_nonce = *self.session_server_nonce.lock().unwrap();
        let preimage = SessionPreimage {
            baseboard: self.own_baseboard().clone(),
            sush_nonce: SessionSushNonce::compute(client_nonce, server_nonce),
            signer_nonce,
            seq,
        };
        if preimage.session_id() != session_id {
            return Err(JobError::InvalidSessionId);
        }

        // Every sled keeps the start pending until a verified job of the
        // session confirms it. Wait until it is pending here, or a session
        // that outranks it is active, so that a job sent next finds it.
        let rank = Some((seq, session_id));
        self.session_request(authn, SessionRequest::Start(preimage))
            .await?;
        self.wait_for(move |state| state.pending_rank(session_id).is_some() || state.rank() >= rank)
            .await
    }

    /// This sled accepts a job only if the job's session is active here,
    /// or if the session's start is pending here for the job to confirm.
    /// The state machine makes the final decision; this check fails fast.
    fn session_check(&self, session_id: SessionId) -> Result<(), JobError> {
        let state = self.state.borrow();
        let rank = state.rank();
        if rank.is_some_and(|(_, active)| active == session_id)
            || state.pending_rank(session_id) > rank
        {
            return Ok(());
        }
        Err(match rank {
            None => JobError::NoSession,
            Some(_) => JobError::SessionNotCurrent(session_id),
        })
    }

    pub async fn session_stop(&self, authn: &KeyId, session_id: SessionId) -> Result<(), JobError> {
        self.starter_check(authn)?;
        self.currency_check(session_id)?;
        self.session_request(authn, SessionRequest::Stop(session_id))
            .await
    }

    /// The authoritative skip is in the state machine, which ignores
    /// requests that lost a race. This check fails fast and loudly.
    pub async fn session_skip_job(
        &self,
        authn: &KeyId,
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
    fn starter_check(&self, authn: &KeyId) -> Result<(), JobError> {
        match self.state.borrow().session() {
            None => Err(JobError::NoSession),
            Some(session) if session.started_by() == Some(authn) => Ok(()),
            Some(_) => Err(JobError::NotSessionStarter),
        }
    }

    /// Don't act on a job we've never seen.
    fn known_job_check(&self, job_id: &JobId) -> Result<(), JobError> {
        if self.state.borrow().is_job_known(job_id) {
            Ok(())
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn session_allow_attach(
        &self,
        authn: &KeyId,
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
        authn: &KeyId,
        session_id: SessionId,
        key_id: KeyId,
    ) -> Result<(), JobError> {
        self.starter_check(authn)?;
        self.currency_check(session_id)?;
        self.session_request(authn, SessionRequest::DenyAttach(session_id, key_id))
            .await
    }

    // Job management.

    /// Start `job` on the sleds its target names that this sled can
    /// reach, wait until the job's status matches `params.wait` on all
    /// of them, and return them.
    pub async fn job_start(
        &self,
        authn: &KeyId,
        job: SignedJob,
        params: JobStartParams,
    ) -> Result<BTreeSet<BaseboardId>, JobError> {
        // A forged job must not take a signed job's place in the chain.
        self.state
            .borrow()
            .certs()
            .verify(&job)
            .map_err(JobError::UnverifiedJob)?;
        self.session_check(job.payload().session_id())?;

        // A broader target would orphan jobs on unattached sleds.
        let payload = job.payload();
        if payload.is_interactive() && payload.target().single_baseboard().is_none() {
            return Err(JobError::InteractiveTarget);
        }

        // Reject job IDs we already know about, rather than silently
        // queuing a resubmission that can never advance the session's
        // job chain. Without this, a caller that resubmits an
        // already-completed job ID and waits would see the *original*
        // job's status returned as if it belonged to this submission.
        let job_id = job.job_id().to_owned();
        if self.state.borrow().get_job_status(&job_id).is_some() {
            return Err(JobError::DuplicateJobId(job_id));
        }

        // Submit the job for execution.
        let sleds = self.reachable_targets(payload.target())?;
        let wait = params.wait.to_owned();
        self.job_request(authn, JobRequest::Start(job, params, sleds.clone()))
            .await?;
        self.wait_for_job(&job_id, wait, sleds.clone()).await?;
        Ok(sleds)
    }

    /// The sleds `target` names that this sled can reach: itself and
    /// the sleds it holds live gossip links to.
    fn reachable_targets(&self, target: &Target) -> Result<BTreeSet<BaseboardId>, JobError> {
        let mut reachable = self.linked.borrow().clone();
        reachable.insert(self.own_baseboard.clone());
        let sleds = target
            .resolve(&reachable, self.state.borrow().rack().cubbies())
            .map_err(|UnknownCubby(cubby)| JobError::UnknownCubby(cubby))?;
        if sleds.is_empty() {
            return Err(JobError::NoReachableTarget);
        }
        Ok(sleds)
    }

    pub async fn job_stop(
        &self,
        authn: &KeyId,
        job_id: &JobId,
        JobStopParams { wait, .. }: JobStopParams,
    ) -> Result<(), JobError> {
        self.starter_check(authn)?;
        self.known_job_check(job_id)?;
        self.job_request(authn, JobRequest::Stop(job_id.to_owned()))
            .await?;
        let sleds = self
            .state
            .borrow()
            .get_job_status(job_id)
            .map(|statuses| statuses.keys().cloned().collect())
            .unwrap_or_default();
        self.wait_for_job(job_id, wait, sleds).await
    }

    pub async fn job_status(
        &self,
        _authn: &KeyId,
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
        authn: &KeyId,
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
                "job_id" => %job_id, "stream" => %stream, "actor" => %authn,
            );
            self.output_dir.job_output(job_id, stream, range).await
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn job_attachment(
        &self,
        authn: &KeyId,
        job_id: &JobId,
        target: &BaseboardId,
    ) -> Result<(SocketSender, Access), JobError> {
        let Some(access) = self.state.borrow().attach_access(authn) else {
            return Err(JobError::AttachDenied);
        };
        if self.own_baseboard() == target
            && let Some(attachment) = self.state.borrow().get_attachment(job_id)
        {
            info!(
                self.log, "job attach";
                "job_id" => %job_id, "access" => ?access, "actor" => %authn,
            );
            Ok((attachment.to_owned(), access))
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn job_history(
        &self,
        _authn: &KeyId,
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

/// Read one PEM-encoded certificate from each of `paths`. Trust
/// anchors load in the order given, which [`Certificates::new`]
/// requires to be root-to-leaf.
pub async fn read_certs(paths: &[impl AsRef<Path>]) -> Result<Vec<Certificate>, JobError> {
    let mut anchors = Vec::with_capacity(paths.len());
    for path in paths {
        let path = path.as_ref();
        let pem = read(path).await.map_err(JobError::file_io_for(path))?;
        anchors.push(Certificate::from_pem(&pem).map_err(KeyError::from)?);
    }
    Ok(anchors)
}

// See tests in `tests/src/manager_tests.rs`
