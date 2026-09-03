// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The boundary between jobs we executed and jobs we only heard about.
//!
//! The gossip frontier answers "what have I heard"; the boundary
//! answers "where was I when I last committed to running a job." One
//! record, overwritten in chain order before each spawn, carries the
//! job, its session, our causal frontier at the moment of commitment,
//! and the job's ending, once it has one.
//!
//! After a restart, compare the recorded frontier with the join
//! frontier. If the join frontier covers it, every request we had
//! processed was witnessed: replay refuses old jobs, the session
//! chain never releases a resubmitted one, and zombie reaping reports
//! what we left running. If not, a suffix of our history died with
//! us: jobs may have run here that no sled can name, and their signed
//! artifacts could be resubmitted and run again. The state machine
//! then refuses jobs of the recorded session until a new session
//! supersedes it, and adjudicates the recorded job itself: the
//! recorded ending if the job got one, and interrupted if it did not.
//!
//! A boundary that cannot be written means the job must not run. A
//! boundary that cannot be trusted means no job may run at all, since
//! we cannot tell what the previous life committed to. Recovery is an
//! M.2 swap or a clean slate.

use std::sync::Mutex as SyncMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ciborium::{de::from_reader, ser::into_writer};
use rumors::{Network, Version};
use serde::{Deserialize, Serialize};
use slog::{Logger, o, warn};
use thiserror::Error;

use sush_common::jobs::{JobId, JobStatus, ProcessError, SessionId};

use crate::locker::{Locker, StoreError, Tenant, TenantSpec, Verdict};

pub const BOUNDARY: TenantSpec = TenantSpec {
    file: "sush-boundary",
    magic: b"SUSHBOUNDARY",
};

/// The execution boundary: the last job this sled committed to
/// running, everything it had seen when it committed, and how far the
/// job got.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Boundary {
    pub network: Network,
    pub session: SessionId,
    pub job: JobId,
    #[serde(with = "version_bytes")]
    pub frontier: Version,
    pub outcome: JobOutcome,
}

/// How far the boundary job got.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum JobOutcome {
    /// Committed to run, with no ending recorded. After a crash,
    /// interrupted is the truth.
    Committed,
    /// The job's terminal status.
    Ended(JobStatus),
}

impl Boundary {
    /// Whether the rack already knows everything we knew at
    /// commitment. Covered means no committed job can be lost.
    /// Anything else means a suffix of our history died with us.
    /// The comparison includes third-party traffic we had seen, so a
    /// join through a lagging peer can look uncovered; the cost is a
    /// session refused on this sled until a new one supersedes it.
    pub fn covered_by(&self, network: Network, join_frontier: Option<&Version>) -> bool {
        self.network == network && join_frontier.is_some_and(|frontier| self.frontier <= *frontier)
    }
}

mod version_bytes {
    use rumors::Version;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(version: &Version, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&version.encode())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Version, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Version::decode(bytes.as_slice()).map_err(D::Error::custom)
    }
}

fn encode(boundary: &Boundary) -> Vec<u8> {
    let mut bytes = Vec::new();
    into_writer(boundary, &mut bytes).expect("writing to a Vec cannot fail");
    bytes
}

fn decode(record: &[u8]) -> Option<Boundary> {
    from_reader(record).ok()
}

#[derive(Debug, Error)]
pub enum BoundaryError {
    #[error("the boundary store is untrusted")]
    Untrusted,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Durable storage for the [`Boundary`].
#[derive(Debug)]
pub struct BoundaryStore {
    log: Logger,
    tenant: Tenant,
    /// The record, readable synchronously by the state machine.
    boundary: SyncMutex<Option<Boundary>>,
    /// Untrusted until loaded, and forever if the load discards:
    /// writing would launder the disagreement into false agreement.
    untrusted: AtomicBool,
    loaded: AtomicBool,
}

impl BoundaryStore {
    pub fn new(log: &Logger, locker: &Locker) -> Self {
        Self {
            log: log.new(o!("component" => "boundary")),
            tenant: locker.tenant(BOUNDARY),
            boundary: SyncMutex::new(None),
            untrusted: AtomicBool::new(true),
            loaded: AtomicBool::new(false),
        }
    }

    /// Load the stored record once, at startup, before any job runs.
    /// A later load could regress the in-memory record below a
    /// spawned job, so a second call panics.
    pub async fn load(&self) {
        assert!(
            !self.loaded.swap(true, Ordering::SeqCst),
            "the boundary store loads once, at startup",
        );
        let boundary = match self.tenant.load().await {
            Verdict::Adopt(record) | Verdict::Restore(record) => match decode(&record) {
                Some(boundary) => Some(boundary),
                None => {
                    warn!(self.log, "undecodable boundary record");
                    return;
                }
            },
            Verdict::Empty => None,
            Verdict::Discard(_) => return,
        };
        *self.boundary.lock().unwrap() = boundary;
        self.untrusted.store(false, Ordering::SeqCst);
    }

    pub fn untrusted(&self) -> bool {
        self.untrusted.load(Ordering::SeqCst)
    }

    pub fn boundary(&self) -> Option<Boundary> {
        self.boundary.lock().unwrap().clone()
    }

    /// Record how the boundary job ended, so the next life can tell
    /// the truth instead of guessing. A stop displaces an adjudicated
    /// Interrupted, mirroring the status arms in the state machine;
    /// nothing else is overwritten, and a record that has moved on to
    /// a newer job ignores the old job's ending.
    pub async fn record_outcome(&self, job_id: &JobId, outcome: &JobStatus) {
        debug_assert!(outcome.is_terminal());
        if self.untrusted() {
            return;
        }
        let mut guard = self.tenant.lock().await;
        let updated = {
            let recorded = self.boundary.lock().unwrap();
            let Some(boundary) = recorded.as_ref().filter(|b| b.job == *job_id) else {
                return;
            };
            let displaces = matches!(
                (&boundary.outcome, outcome),
                (JobOutcome::Committed, _)
                    | (
                        JobOutcome::Ended(JobStatus::Error {
                            error: ProcessError::Interrupted,
                            ..
                        }),
                        JobStatus::Stopped { .. },
                    )
            );
            if !displaces {
                return;
            }
            Boundary {
                outcome: JobOutcome::Ended(outcome.clone()),
                ..boundary.clone()
            }
        };
        if let Err(error) = guard.store(&encode(&updated)).await {
            warn!(
                self.log, "failed to record the boundary job's outcome";
                "job_id" => %job_id, "error" => %error,
            );
            return;
        }
        *self.boundary.lock().unwrap() = Some(updated);
    }

    /// Commit to executing the job at `boundary`. On failure the
    /// caller must not run the job.
    pub async fn advance(&self, boundary: &Boundary) -> Result<(), BoundaryError> {
        if self.untrusted() {
            // Defense in depth: the state machine already refuses
            // execution when the store is untrusted, so no launch
            // reaches this arm.
            return Err(BoundaryError::Untrusted);
        }
        let mut guard = self.tenant.lock().await;
        guard.store(&encode(boundary)).await?;
        *self.boundary.lock().unwrap() = Some(boundary.clone());
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs::create_dir;

    use camino::Utf8PathBuf;
    use slog::Discard;
    use tempfile::TempDir;

    /// Two M.2 slots.
    fn slots(dir: &TempDir) -> Vec<Utf8PathBuf> {
        ["m2a", "m2b"]
            .iter()
            .map(|m2| {
                let slot = Utf8PathBuf::from_path_buf(dir.path().join(m2)).unwrap();
                create_dir(&slot).unwrap();
                slot
            })
            .collect()
    }

    fn test_log() -> Logger {
        Logger::root(Discard, o!())
    }

    async fn store(slots: Vec<Utf8PathBuf>) -> BoundaryStore {
        let store = BoundaryStore::new(&test_log(), &Locker::new(&test_log(), slots));
        store.load().await;
        store
    }

    fn network(seed: u8) -> Network {
        serde_json::from_str(&format!("[{seed:?}{}]", ", 0".repeat(15))).unwrap()
    }

    fn boundary(seed: u8) -> Boundary {
        Boundary {
            network: network(seed),
            session: SessionId::random(),
            job: JobId::random(),
            frontier: "(1, 1, (0, 0, 2))".parse().unwrap(),
            outcome: JobOutcome::Committed,
        }
    }

    #[tokio::test]
    async fn commitments_survive_restarts() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        let first = store(slots.clone()).await;
        assert!(first.boundary().is_none());

        let (a, b) = (boundary(1), boundary(2));
        first.advance(&a).await.unwrap();
        first.advance(&b).await.unwrap();

        let next = store(slots).await;
        assert!(!next.untrusted());
        let recorded = next.boundary().unwrap();
        assert_eq!(recorded.network, b.network);
        assert_eq!(recorded.session, b.session);
        assert_eq!(recorded.job, b.job);
        assert_eq!(recorded.frontier, b.frontier);
        assert!(matches!(recorded.outcome, JobOutcome::Committed));
    }

    /// The boundary job's recorded ending survives into the next life.
    /// A stop displaces an adjudicated interrupted; nothing else does, and
    /// an ending for a superseded job is ignored.
    #[tokio::test]
    async fn outcomes_survive_and_heal() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        let first = store(slots.clone()).await;
        let b = boundary(1);
        first.advance(&b).await.unwrap();

        let interrupted = JobStatus::Error {
            job_id: b.job,
            time_error: chrono::Utc::now(),
            error: ProcessError::Interrupted,
        };
        let killed = JobStatus::Error {
            job_id: b.job,
            time_error: chrono::Utc::now(),
            error: ProcessError::Killed(9),
        };
        first.record_outcome(&JobId::random(), &killed).await;
        assert!(matches!(
            first.boundary().unwrap().outcome,
            JobOutcome::Committed
        ));

        first.record_outcome(&b.job, &interrupted).await;
        first.record_outcome(&b.job, &killed).await;
        let next = store(slots).await;
        assert!(matches!(
            next.boundary().unwrap().outcome,
            JobOutcome::Ended(JobStatus::Error {
                error: ProcessError::Interrupted,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn coverage_requires_frontier_and_universe() {
        let boundary = boundary(1);
        let covered: Version = "(2, 2, (0, 0, 3))".parse().unwrap();
        let behind: Version = "(1, 0, (0, 0, 2))".parse().unwrap();

        assert!(boundary.covered_by(network(1), Some(&boundary.frontier)));
        assert!(boundary.covered_by(network(1), Some(&covered)));
        assert!(!boundary.covered_by(network(1), Some(&behind)));
        assert!(!boundary.covered_by(network(2), Some(&covered)));
        assert!(!boundary.covered_by(network(1), None));
    }

    #[tokio::test]
    async fn disagreement_is_untrusted_and_pins() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        for (slot, seed) in slots.iter().zip([1, 2]) {
            let lone = store(vec![slot.clone()]).await;
            lone.advance(&boundary(seed)).await.unwrap();
        }

        let untrusted = store(slots.clone()).await;
        assert!(untrusted.untrusted());
        assert!(untrusted.boundary().is_none());
        assert!(matches!(
            untrusted.advance(&boundary(3)).await,
            Err(BoundaryError::Untrusted)
        ));

        let reload = store(slots).await;
        assert!(reload.untrusted());
    }

    #[tokio::test]
    async fn undecodable_record_is_untrusted() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        let scratch = Locker::new(&test_log(), slots.clone());
        scratch.tenant(BOUNDARY).store(b"scribble").await.unwrap();

        let store = BoundaryStore::new(&test_log(), &Locker::new(&test_log(), slots));
        store.load().await;
        assert!(store.untrusted());
    }

    #[tokio::test]
    async fn unloaded_is_untrusted() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let store = BoundaryStore::new(&test_log(), &Locker::new(&test_log(), slots(&dir)));
        assert!(store.untrusted());
        assert!(matches!(
            store.advance(&boundary(1)).await,
            Err(BoundaryError::Untrusted)
        ));
    }
}
