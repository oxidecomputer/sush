// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Manage job signature verification and the session state machine.
//! Does not manage jobs directly.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
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

use sush_api::{JobStartParams, JobStopParams, JobWait, SessionDetails};
use sush_common::authn::Nonce;
use sush_common::jobs::{
    Access, JobId, JobOutputStream, JobRecord, JobStatusMap, Session, SessionId, SessionPreimage,
    SessionServerNonce, SessionSushNonce, SessionView, SignedJob,
};
use sush_common::keys::{KeyError, KeyId, Verified};
use sush_common::targets::{Cubbies, SledHealth, SledVersion, Target, UnknownCubby};
use sush_common::version::LONG_VERSION;

use crate::error::JobError;
use crate::executor::PathIsolation;
use crate::gossip::ConnectedBaseboards;
use crate::job::SocketSender;
use crate::locker::Locker;
use crate::locker::boundary::BoundaryStore;
use crate::messages::v0::{JobRequest, Request, SessionRequest};
use crate::output::{JobOutputDir, JobOutputFileStream};
use crate::state::{GossipNetwork, State, StateManager};

/// Maximum amount of time we're willing to wait for job start or stop.
const WAIT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug)]
pub struct JobManager {
    log: Logger,
    secret: Nonce,
    output_dir: JobOutputDir,
    own_baseboard: BaseboardId,
    connected: ConnectedBaseboards,
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
        network: watch::Receiver<GossipNetwork>,
        connected: ConnectedBaseboards,
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
            network,
            connected,
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
        network: watch::Receiver<GossipNetwork>,
        connected: ConnectedBaseboards,
        locker: &Locker,
        anchors: &[Certificate],
        shutdown: CancellationToken,
    ) -> Result<Self, JobError> {
        info!(log, "starting sush"; "version" => LONG_VERSION);
        let (tx_req, rx_req) = mpsc::channel(16);
        let requests = ReceiverStream::new(rx_req);
        let secret = Nonce::random();
        let boundary = Arc::new(BoundaryStore::new(&log, locker));
        boundary.load().await;
        let (rx_state, join_state) = StateManager::run(
            log.new(o!("component" => "state manager")),
            path_isolation,
            output_dir.clone(),
            own_baseboard.clone(),
            requests,
            cubbies,
            network,
            anchors,
            boundary,
            shutdown,
        )?;
        Ok(Self {
            log: log.new(o!("component" => "job manager")),
            secret,
            own_baseboard,
            connected,
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
        let connected = self.connected.borrow();
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
                    if *baseboard == self.own_baseboard || connected.contains(baseboard) {
                        SledHealth::Connected
                    } else {
                        SledHealth::Disconnected
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
    /// that this sled is still connected to.
    async fn wait_for_job(
        &self,
        job_id: &JobId,
        wait: JobWait,
        sleds: BTreeSet<BaseboardId>,
    ) -> Result<(), JobError> {
        if !wait.is_some() {
            return Ok(());
        }
        let settled = |state: &State, connected: &BTreeSet<BaseboardId>| {
            let statuses = state.get_job_status(job_id);
            sleds.iter().all(|sled| {
                let gone = *sled != self.own_baseboard && !connected.contains(sled);
                gone || statuses
                    .and_then(|map| map.get(sled))
                    .is_some_and(|status| wait.matches_status(status))
            })
        };
        let mut state = self.state.clone();
        let mut connected = self.connected.clone();
        timeout(WAIT_TIMEOUT, async {
            while !settled(&state.borrow_and_update(), &connected.borrow_and_update()) {
                select! {
                    changed = state.changed() => changed.map_err(JobError::closed)?,
                    () = connected.changed() => (),
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

    pub fn session_view(&self, authn: &KeyId) -> Option<SessionView> {
        let state = self.state.borrow();
        let session = state.session()?;
        let session_id = session.session_id();
        Some(
            if state
                .history()
                .session_access(&session_id)
                .and_then(|access| access.access(authn))
                .is_some()
            {
                SessionView::Visible(Box::new(session.clone()))
            } else {
                SessionView::Hidden(session_id)
            },
        )
    }

    pub async fn session_id(&self, authn: &KeyId) -> Result<SessionId, JobError> {
        let Some(session) = self.session(authn) else {
            return Err(JobError::NoSession);
        };
        Ok(session.into_session_id())
    }

    pub fn server_nonce(&self, authn: &KeyId) -> SessionServerNonce {
        let latest = self.state.borrow().history().latest_session();
        SessionServerNonce::compute(&self.secret, authn, latest)
    }

    fn session_preimage(
        &self,
        authn: &KeyId,
        session_id: SessionId,
        details: Option<&SessionDetails>,
    ) -> Result<Option<SessionPreimage>, JobError> {
        let Some(SessionDetails {
            baseboard,
            client_nonce,
            signer_nonce,
            seq,
        }) = details
        else {
            return Ok(None);
        };
        if self
            .state
            .borrow()
            .session()
            .is_some_and(|session| session.session_id() == session_id)
        {
            return Ok(None);
        }
        if baseboard != self.own_baseboard() {
            return Err(JobError::OtherSled(session_id, baseboard.clone()));
        }
        let preimage = SessionPreimage {
            baseboard: baseboard.clone(),
            sush_nonce: SessionSushNonce::compute(*client_nonce, self.server_nonce(authn)),
            signer_nonce: *signer_nonce,
            seq: *seq,
        };
        if preimage.session_id() != session_id {
            return Err(JobError::StaleNonce(session_id));
        }
        Ok(Some(preimage))
    }

    /// This sled accepts a job only if the job's session is active here,
    /// or if the job carries its session's details to begin it.
    /// The state machine makes the final decision; this check fails fast.
    pub fn session_check(
        &self,
        session_id: SessionId,
        preimage: Option<&SessionPreimage>,
    ) -> Result<(), JobError> {
        let state = self.state.borrow();
        let rank = state.rank();
        if rank.is_some_and(|(_, active)| active == session_id)
            || preimage.is_some_and(|preimage| Some((preimage.seq, session_id)) > rank)
        {
            return Ok(());
        }
        Err(match rank {
            None => JobError::NoSession,
            Some(_) => JobError::SessionNotCurrent(session_id),
        })
    }

    pub async fn session_stop(&self, authn: &KeyId, session_id: SessionId) -> Result<(), JobError> {
        self.currency_check(session_id)?;
        self.starter_check(authn, session_id)?;
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
        self.currency_check(session_id)?;
        self.write_check(authn, session_id, None)?;
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

    /// Only the identity that started a session may stop it, skip or stop
    /// its jobs, or grant and deny access to it. The authoritative check
    /// is in the state machine; this one fails fast.
    fn starter_check(&self, authn: &KeyId, session_id: SessionId) -> Result<(), JobError> {
        match self.state.borrow().history().session_access(&session_id) {
            None => Err(JobError::SessionNotFound(session_id)),
            Some(access) if access.started_by() == authn => Ok(()),
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

    /// Check that an identity has at least read-only access to a job.
    fn read_check(&self, authn: &KeyId, job_id: &JobId) -> Result<Access, JobError> {
        self.state
            .borrow()
            .history()
            .job_access(job_id, authn)
            .ok_or_else(|| JobError::JobNotFound(job_id.to_owned()))
    }

    /// Check that an identity has full read-write access to a session.
    fn write_check(
        &self,
        authn: &KeyId,
        session_id: SessionId,
        preimage: Option<&SessionPreimage>,
    ) -> Result<(), JobError> {
        let state = self.state.borrow();
        let access = match state.history().session_access(&session_id) {
            Some(access) => access.access(authn),
            None => preimage.is_some().then_some(Access::ReadWrite),
        };
        match access {
            Some(Access::ReadWrite) => Ok(()),
            _ => Err(JobError::NoWriteAccess),
        }
    }

    pub async fn session_allow(
        &self,
        authn: &KeyId,
        session_id: SessionId,
        key_id: KeyId,
        access: Access,
    ) -> Result<(), JobError> {
        self.starter_check(authn, session_id)?;
        self.session_request(authn, SessionRequest::Allow(session_id, key_id, access))
            .await
    }

    pub async fn session_deny(
        &self,
        authn: &KeyId,
        session_id: SessionId,
        key_id: KeyId,
    ) -> Result<(), JobError> {
        self.starter_check(authn, session_id)?;
        self.session_request(authn, SessionRequest::Deny(session_id, key_id))
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
        details: Option<&SessionDetails>,
    ) -> Result<BTreeSet<BaseboardId>, JobError> {
        // Check the job signature.
        self.state
            .borrow()
            .certs()
            .verify(&job)
            .map_err(JobError::UnverifiedJob)?;

        // Reject jobs we already know about.
        let job_id = job.job_id().to_owned();
        if self.state.borrow().get_job_status(&job_id).is_some() {
            return Err(JobError::DuplicateJobId(job_id));
        }

        // Check the session and target.
        let payload = job.payload();
        if !payload.target_matches_mode() {
            return Err(JobError::InteractiveTarget);
        }
        let session_id = payload.session_id();
        let preimage = self.session_preimage(authn, session_id, details)?;
        let sleds = self.preflight(authn, session_id, payload.target(), preimage.as_ref())?;

        // Submit the job for execution.
        let wait = params.wait.to_owned();
        let params = JobStartParams {
            via: None,
            ..params
        };
        let rank = preimage.as_ref().map(|preimage| (preimage.seq, session_id));
        let request = JobRequest::Start(job, params, sleds.clone(), preimage);
        self.job_request(authn, request).await?;
        if let Some(rank) = rank {
            self.wait_for(|state| {
                state.history().session_access(&session_id).is_some() || state.rank() > Some(rank)
            })
            .await?;
        }
        self.wait_for_job(&job_id, wait, sleds.clone()).await?;
        Ok(sleds)
    }

    /// Check that this sled would accept a job in `session_id` for `target`.
    pub fn job_preflight(
        &self,
        authn: &KeyId,
        session_id: SessionId,
        target: &Target,
        details: Option<&SessionDetails>,
    ) -> Result<BTreeSet<BaseboardId>, JobError> {
        let preimage = self.session_preimage(authn, session_id, details)?;
        self.preflight(authn, session_id, target, preimage.as_ref())
    }

    fn preflight(
        &self,
        authn: &KeyId,
        session_id: SessionId,
        target: &Target,
        preimage: Option<&SessionPreimage>,
    ) -> Result<BTreeSet<BaseboardId>, JobError> {
        self.session_check(session_id, preimage)?;
        self.write_check(authn, session_id, preimage)?;
        self.reachable_targets(target)
    }

    /// Return the sleds in `target` that match either this sled or any of
    /// its live gossip peers.
    fn reachable_targets(&self, target: &Target) -> Result<BTreeSet<BaseboardId>, JobError> {
        let mut reachable = self.connected.borrow().clone();
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
        self.known_job_check(job_id)?;
        let session_id = self
            .state
            .borrow()
            .history()
            .job_session(job_id)
            .ok_or_else(|| JobError::JobNotFound(job_id.to_owned()))?;
        self.write_check(authn, session_id, None)?;
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
        authn: &KeyId,
        job_id: &JobId,
    ) -> Result<JobStatusMap, JobError> {
        self.read_check(authn, job_id)?;
        if let Some(status) = self.state.borrow().get_job_status(job_id) {
            Ok(status.to_owned())
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn job_record(&self, authn: &KeyId, job_id: &JobId) -> Result<JobRecord, JobError> {
        self.read_check(authn, job_id)?;
        let state = self.state.borrow();
        let status = state
            .get_job_status(job_id)
            .ok_or_else(|| JobError::JobNotFound(job_id.to_owned()))?;
        Ok(JobRecord {
            request: state
                .get_job_request(job_id)
                .cloned()
                .map(Verified::into_signed),
            status: status.to_owned(),
        })
    }

    pub async fn job_output(
        &self,
        authn: &KeyId,
        job_id: &JobId,
        target: &BaseboardId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<JobOutputFileStream, JobError> {
        self.read_check(authn, job_id)?;
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
        let access = self.read_check(authn, job_id)?;
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
        authn: &KeyId,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<JobRecord>, JobError> {
        let state = self.state.borrow();
        let history = state.history();
        Ok(history
            .iter()
            .filter(|(job_id, ..)| history.job_access(job_id, authn).is_some())
            .skip(offset as usize)
            .take(if limit == 0 {
                usize::MAX
            } else {
                limit as usize
            })
            .map(|(_, request, status)| JobRecord {
                request: request.cloned().map(Verified::into_signed),
                status: status.to_owned(),
            })
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
