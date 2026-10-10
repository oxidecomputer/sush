// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Job history and status.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use rumors::before::Rank;
use sled_hardware_types::BaseboardId;

use sush_common::jobs::{JobId, JobStatus, JobStatusMap};

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

    /// The set of running jobs everywhere, tagged by start wall-clock time.
    running: BTreeMap<(JobId, BaseboardId), DateTime<Utc>>,
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
        if self.job_status.len() <= MAX_HISTORY {
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
            self.causal_jobs.retain(|(_, id, _)| id != &job_id);
        }
    }

    /// Iterate job status maps, one per job, acausal (locally generated)
    /// first by "wall clock time", then causally newest to oldest.
    pub fn iter(&self) -> impl Iterator<Item = &JobStatusMap> {
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
            .filter_map(|id| self.job_status.get(id))
    }
}

#[cfg(test)]
mod tests {
    use sush_common::jobs::{ProcessError, SkipReason};

    use super::*;

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
