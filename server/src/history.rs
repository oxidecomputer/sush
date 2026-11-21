// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Job history and status.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use rumors::before::Rank;
use sled_hardware_types::BaseboardId;

use sush_common::jobs::{Access, JobId, JobStatus, JobStatusMap, SessionId, VerifiedJob};
use sush_common::keys::KeyId;

use crate::state::QueuedJobs;

/// Maximum number of historical job statuses to retain before evicting them.
/// This is specified as 32 (maximum sleds per rack) times 2,048 (maximum
/// "scrollback" per sled).
const MAX_HISTORY: usize = 32 * 2048;

/// Bounded job status history.
#[derive(Debug, Default)]
pub struct JobHistory {
    /// The set of *all* jobs (running or stopped) *everywhere*, causally
    /// ordered. We use causal ordering to garbage-collect jobs which are the
    /// causally oldest, once the memory representation of our state gets big.
    causal_jobs: BTreeSet<(Rank, JobId, BaseboardId)>,

    /// Lookup table for job status of *all* jobs *everywhere*, pruned by the
    /// causal ordering in `causal_jobs`, and indexed first by job ID so that
    /// it's possible to ask "what's the status of this job across the rack?"
    job_status: BTreeMap<JobId, JobStatusMap>,

    /// The set of running jobs *everywhere*, tagged by start wall-clock time.
    running: BTreeMap<(JobId, BaseboardId), DateTime<Utc>>,

    /// Lookup table for all *locally* verified job requests. Job status
    /// may arrive before the request, after it, or instead of it (e.g.,
    /// for a skipped job).
    requests: BTreeMap<JobId, VerifiedJob>,

    /// Map skipped jobs to their sessions (since they don't have a request).
    skipped: BTreeMap<JobId, SessionId>,

    /// Access control for known sessions.
    session_access: BTreeMap<SessionId, SessionAccess>,

    /// The most recently started session.
    latest_session: Option<SessionId>,
}

#[derive(Clone, Debug)]
pub struct SessionAccess {
    started_by: KeyId,
    grants: BTreeMap<KeyId, Access>,
}

impl SessionAccess {
    pub fn started_by(&self) -> &KeyId {
        &self.started_by
    }

    pub fn access(&self, key_id: &KeyId) -> Option<Access> {
        if *key_id == self.started_by {
            Some(Access::ReadWrite)
        } else {
            self.grants.get(key_id).copied()
        }
    }

    pub fn allow(&mut self, key_id: &KeyId, access: Access) {
        self.grants.insert(key_id.clone(), access);
    }

    pub fn deny(&mut self, key_id: &KeyId) {
        self.grants.remove(key_id);
    }
}

impl JobHistory {
    /// Return true if a status is known for the given job.
    pub fn contains(&self, job_id: &JobId) -> bool {
        self.job_status.contains_key(job_id)
    }

    /// Get the last known status of a job.
    pub fn get_job_status(&self, job_id: &JobId) -> Option<&JobStatusMap> {
        self.job_status.get(job_id)
    }

    pub fn get_job_request(&self, job_id: &JobId) -> Option<&VerifiedJob> {
        self.requests.get(job_id)
    }

    pub fn set_job_request(&mut self, request: &VerifiedJob, queued: Option<&QueuedJobs>) {
        self.requests
            .entry(*request.job_id())
            .or_insert_with(|| request.to_owned());
        self.gc(queued);
    }

    pub fn set_skipped(&mut self, job_id: &JobId, session_id: SessionId) {
        self.skipped.entry(*job_id).or_insert(session_id);
    }

    pub fn start_session(&mut self, session_id: SessionId, started_by: &KeyId) {
        self.session_access
            .entry(session_id)
            .or_insert_with(|| SessionAccess {
                started_by: started_by.clone(),
                grants: BTreeMap::new(),
            });
        self.latest_session = Some(session_id);
    }

    pub fn latest_session(&self) -> Option<SessionId> {
        self.latest_session
    }

    pub fn session_access(&self, session_id: &SessionId) -> Option<&SessionAccess> {
        self.session_access.get(session_id)
    }

    pub fn session_access_mut(&mut self, session_id: &SessionId) -> Option<&mut SessionAccess> {
        self.session_access.get_mut(session_id)
    }

    pub fn is_starter(&self, session_id: &SessionId, key_id: &KeyId) -> bool {
        self.session_access
            .get(session_id)
            .is_some_and(|access| access.started_by() == key_id)
    }

    pub fn job_session(&self, job_id: &JobId) -> Option<SessionId> {
        self.requests
            .get(job_id)
            .map(|request| request.payload().session_id())
            .or_else(|| self.skipped.get(job_id).copied())
    }

    pub fn job_access(&self, job_id: &JobId, key_id: &KeyId) -> Option<Access> {
        self.job_session(job_id)
            .and_then(|session_id| self.session_access.get(&session_id))
            .and_then(|access| access.access(key_id))
    }

    /// Set the (causal) status of a job.
    pub fn set_job_status(
        &mut self,
        job_id: &JobId,
        target: &BaseboardId,
        status: JobStatus,
        rank: Option<Rank>,
        queued: Option<&QueuedJobs>,
    ) {
        if let JobStatus::Started { time_started, .. } = &status {
            self.running
                .insert((job_id.to_owned(), target.to_owned()), *time_started);
        } else {
            self.running.remove(&(job_id.to_owned(), target.to_owned()));
        }

        self.job_status
            .entry(job_id.to_owned())
            .or_default()
            .insert(target.to_owned(), status);

        if let Some(rank) = rank {
            self.causal_jobs
                .insert((rank, job_id.to_owned(), target.to_owned()));
        }

        self.gc(queued);
    }

    /// Set the local (causal) status of a job if it has an entry that
    /// matches a predicate.
    pub fn transition_job_status(
        &mut self,
        job_id: &JobId,
        target: &BaseboardId,
        rank: Option<Rank>,
        transition: impl FnOnce(Option<&JobStatus>) -> Option<JobStatus>,
        queued: Option<&QueuedJobs>,
    ) -> Option<JobStatus> {
        let old = self.get_job_status(job_id).and_then(|map| map.get(target));
        if let Some(new) = transition(old) {
            self.set_job_status(job_id, target, new.clone(), rank, queued);
            Some(new)
        } else {
            None
        }
    }

    pub fn running_jobs(&self) -> &BTreeMap<(JobId, BaseboardId), DateTime<Utc>> {
        &self.running
    }

    /// Evict causally-oldest job status entries once we exceed
    /// `MAX_HISTORY`. A job may appear more than once in `causal_jobs`
    /// (once per causal event: start, and stop or error), so the
    /// causally-oldest entry isn't automatically safe to evict;
    /// it may be the *start* event of a job that's still running,
    /// whose terminal event (and thus later `causal_jobs` entry)
    /// hasn't happened yet. We only ever evict full job entries,
    /// and only for jobs that aren't currently running anywhere
    /// or queued locally.
    fn gc(&mut self, queued: Option<&QueuedJobs>) {
        // Do nothing if we've still got room.
        if self.job_status.len() <= MAX_HISTORY && self.requests.len() <= MAX_HISTORY {
            return;
        }

        // Collect jobs ineligible for eviction.
        let mut ineligible = BTreeSet::new();
        if let Some(queued) = queued {
            ineligible.extend(queued.keys().cloned());
        }
        ineligible.extend(self.running.iter().map(|((id, _), _)| *id));

        // Cache causal jobs.
        let causal = self
            .causal_jobs
            .iter()
            .map(|(_, id, _)| id)
            .cloned()
            .collect::<BTreeSet<JobId>>();

        // Try to evict non-causal (locally generated) entries first,
        // then the causally-oldest ones. Keep evicting until we reach
        // a low-water mark to amortize the cost of the setup above.
        let low_water_mark = MAX_HISTORY - MAX_HISTORY / 16;
        while self.job_status.len() > low_water_mark
            && let Some(job_id) = self
                .job_status
                .keys()
                .find(|&id| !ineligible.contains(id) && !causal.contains(id))
                .cloned()
                .or_else(|| {
                    self.causal_jobs
                        .iter()
                        .map(|(_, id, _)| id)
                        .find(|&id| !ineligible.contains(id) && self.job_status.contains_key(id))
                        .cloned()
                })
        {
            self.job_status.remove(&job_id);
            self.requests.remove(&job_id);
            self.skipped.remove(&job_id);
            self.causal_jobs.retain(|(_, id, _)| id != &job_id);
        }
        if self.requests.len() > low_water_mark {
            let job_status = &self.job_status;
            self.requests
                .retain(|id, _| job_status.contains_key(id) || ineligible.contains(id));
            self.skipped
                .retain(|id, _| job_status.contains_key(id) || ineligible.contains(id));
        }

        // Drop access for now-empty sessions.
        let referenced = self
            .requests
            .values()
            .map(|request| request.payload().session_id())
            .chain(self.skipped.values().copied())
            .collect::<BTreeSet<_>>();
        let latest = self.latest_session;
        self.session_access
            .retain(|id, _| referenced.contains(id) || Some(*id) == latest);
    }

    /// Iterate over each job's ID, request, and status map, acausal
    /// (locally generated) first by "wall clock time", then causally
    /// newest to oldest.
    pub fn iter(&self) -> impl Iterator<Item = (&JobId, Option<&VerifiedJob>, &JobStatusMap)> {
        let causal = BTreeSet::from_iter(self.causal_jobs.iter().map(|(_, id, _)| id));
        let mut acausal = self
            .job_status
            .keys()
            .filter(|id| !causal.contains(id))
            .collect::<Vec<_>>();
        acausal.sort_by_key(|id| Reverse(self.job_status[*id].values().map(JobStatus::time).max()));
        let mut seen = BTreeSet::new();
        acausal
            .into_iter()
            .chain(
                self.causal_jobs
                    .iter()
                    .rev()
                    .filter_map(move |(_, id, _)| seen.insert(id).then_some(id)),
            )
            .filter_map(|id| {
                self.job_status
                    .get(id)
                    .map(|status| (id, self.requests.get(id), status))
            })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sush_common::jobs::{JobMode, JobStartRequest, ProcessError, SessionId, SkipReason};
    use sush_common::keys::{EphemeralKey, KeyType, Signer as _};
    use sush_common::targets::Target;
    use x509_cert::time::Validity;

    use super::*;

    async fn request(job_id: JobId, session_id: SessionId) -> VerifiedJob {
        let mut root = EphemeralKey::new_root(
            KeyType::P256,
            "CN=Test Root,O=Oxide Computer Company,C=US"
                .parse()
                .unwrap(),
            Validity::from_now(Duration::from_secs(60)).unwrap(),
        )
        .unwrap();
        let cert = root.cert().clone();
        root.sign(JobStartRequest::new(
            job_id,
            session_id,
            "true",
            JobMode::Batch,
            Target::All,
        ))
        .await
        .unwrap()
        .verify_with_cert(&cert)
        .unwrap()
    }

    fn baseboard(n: u32) -> BaseboardId {
        BaseboardId {
            part_number: "913-0000019".into(),
            serial_number: format!("BRM{n:08}"),
        }
    }

    fn started(job_id: JobId) -> JobStatus {
        JobStatus::Started {
            job_id,
            time_started: Utc::now(),
        }
    }

    fn error(job_id: JobId) -> JobStatus {
        JobStatus::Error {
            job_id,
            time_error: Utc::now(),
            error: ProcessError::Interrupted,
        }
    }

    fn skipped(job_id: JobId) -> JobStatus {
        JobStatus::Skipped {
            job_id,
            time_skipped: Utc::now(),
            reason: SkipReason::SessionEnded,
        }
    }

    #[test]
    fn running_index_follows_status() {
        let mut history = JobHistory::default();
        let job = JobId::random();
        for sled in [baseboard(1), baseboard(2)] {
            history.set_job_status(&job, &sled, started(job), None, None);
        }
        assert_eq!(history.running_jobs().len(), 2);
        history.set_job_status(&job, &baseboard(1), error(job), None, None);
        history.set_job_status(&job, &baseboard(2), skipped(job), None, None);
        assert!(history.running_jobs().is_empty());
        assert!(history.contains(&job));
    }

    #[test]
    fn transitions_apply_only_on_match() {
        let mut history = JobHistory::default();
        let job = JobId::random();
        let sled = baseboard(1);
        let stop_running = |old: Option<&JobStatus>| match old {
            Some(JobStatus::Started { .. }) => Some(skipped(job)),
            _ => None,
        };
        history.transition_job_status(&job, &sled, None, stop_running, None);
        assert!(!history.contains(&job));
        history.set_job_status(&job, &sled, started(job), None, None);
        history.transition_job_status(&job, &sled, None, stop_running, None);
        assert!(matches!(
            history.get_job_status(&job).unwrap().get(&sled),
            Some(JobStatus::Skipped { .. })
        ));
        history.transition_job_status(&job, &sled, None, stop_running, None);
        assert!(matches!(
            history.get_job_status(&job).unwrap().get(&sled),
            Some(JobStatus::Skipped { .. })
        ));
        assert!(history.running_jobs().is_empty());
    }

    #[tokio::test]
    async fn request_may_follow_status() {
        let mut history = JobHistory::default();
        let job = JobId::random();
        history.set_job_status(&job, &baseboard(1), started(job), None, None);
        assert!(history.get_job_request(&job).is_none());
        history.set_job_request(&request(job, SessionId::random()).await, None);
        assert!(history.get_job_request(&job).is_some());
    }

    #[tokio::test]
    async fn request_alone_is_not_history() {
        let mut history = JobHistory::default();
        let job = JobId::random();
        history.set_job_request(&request(job, SessionId::random()).await, None);
        assert!(!history.contains(&job));
        assert_eq!(history.iter().count(), 0);
    }

    #[tokio::test]
    async fn job_access_follows_session() {
        let mut history = JobHistory::default();
        let session = SessionId::random();
        let starter = KeyId::random();
        let grantee = KeyId::random();
        let stranger = KeyId::random();
        let job = JobId::random();
        history.set_job_request(&request(job, session).await, None);
        assert_eq!(history.job_access(&job, &starter), None);
        history.start_session(session, &starter);
        history
            .session_access_mut(&session)
            .unwrap()
            .allow(&grantee, Access::ReadOnly);
        assert_eq!(history.job_access(&job, &starter), Some(Access::ReadWrite));
        assert_eq!(history.job_access(&job, &grantee), Some(Access::ReadOnly));
        assert_eq!(history.job_access(&job, &stranger), None);
        history.session_access_mut(&session).unwrap().deny(&grantee);
        assert_eq!(history.job_access(&job, &grantee), None);
    }

    #[test]
    fn skipped_job_follows_session() {
        let mut history = JobHistory::default();
        let session = SessionId::random();
        let starter = KeyId::random();
        let job = JobId::random();
        history.start_session(session, &starter);
        history.set_skipped(&job, session);
        assert_eq!(history.job_access(&job, &starter), Some(Access::ReadWrite));
    }

    #[test]
    fn restarted_session_keeps_starter() {
        let mut history = JobHistory::default();
        let session = SessionId::random();
        let starter = KeyId::random();
        history.start_session(session, &starter);
        history.start_session(session, &KeyId::random());
        assert_eq!(
            history.session_access(&session).unwrap().access(&starter),
            Some(Access::ReadWrite)
        );
    }

    #[test]
    fn eviction_drops_sessions_without_jobs() {
        let mut history = JobHistory::default();
        let sled = baseboard(1);
        let old_session = SessionId::random();
        let old_job = JobId::random();
        history.start_session(old_session, &KeyId::random());
        history.set_skipped(&old_job, old_session);
        history.set_job_status(&old_job, &sled, error(old_job), None, None);
        let latest_session = SessionId::random();
        history.start_session(latest_session, &KeyId::random());
        for _ in 0..=MAX_HISTORY {
            let job = JobId::random();
            history.set_job_status(&job, &sled, started(job), None, None);
        }
        assert!(!history.contains(&old_job));
        assert!(history.session_access(&old_session).is_none());
        assert!(history.session_access(&latest_session).is_some());
    }

    #[test]
    fn eviction_spares_running_jobs() {
        let mut history = JobHistory::default();
        let sled = baseboard(1);
        let runner = JobId::random();
        history.set_job_status(&runner, &sled, started(runner), None, None);
        for _ in 0..=MAX_HISTORY {
            let job = JobId::random();
            history.set_job_status(&job, &sled, error(job), None, None);
        }
        assert!(history.contains(&runner));
        assert!(history.job_status.len() <= MAX_HISTORY);
        assert!(history.running_jobs().contains_key(&(runner, sled)));
    }
}
