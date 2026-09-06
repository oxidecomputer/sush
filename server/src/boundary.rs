// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The boundary between jobs we executed and jobs we only heard about.
//!
//! One record, rewritten before each spawn, carries what this sled
//! last committed to: the job, its session, the chain position after
//! the job, the universe they belong to, and the job's ending once
//! it has one. A universe is one shared gossip history, identified
//! by its network; sleds join universes, leave them, and sometimes
//! return. Alongside the commitment, the record keeps the join
//! of every session start this sled has executed under in that
//! universe, and the set of universes it burned by leaving. The
//! record is this sled's execution watermark: nothing at or below it
//! may run again.
//!
//! After a restart, replayed gossip rebuilds the sessions. When the
//! committed session activates, the sled resumes its chain at the
//! stored successor. The previous life had already moved the chain
//! past every earlier position, so the session's queue never
//! releases them here, and the chain continues from the successor
//! whether its request arrives by replay or by resubmission. A
//! session that starts strictly above the executed join has never
//! run here and is served. A session the record cannot order makes
//! the sled hop: the sled reports the hop to the gossip set as an
//! error and sets a floor, in memory, at the frontier that includes
//! the report. A session that does not start above the floor has
//! its jobs skipped; a session started after the hop is served. The
//! join folds in every session this sled has executed under in this
//! universe, so a session it once ran under can never screen as
//! new: the sled hops, and the session's jobs are skipped rather
//! than re-run. If replay gives the recorded job no status, the sled
//! adjudicates it: it announces the recorded ending when the record
//! holds one, and an interrupted ending when it does not.
//!
//! Universes have no order. The record instead keeps a burned set,
//! holding the network of every universe whose watermark it
//! overwrote by moving on. A sled that re-enters a burned universe
//! has flip-flopped, and raises its floor: it reports the flip-flop
//! to the gossip set and sets the floor, in memory, at the frontier
//! that includes the report. No older message can contain a version
//! born at that instant, so a session started before the re-entry
//! never lies above the floor, and its jobs are skipped. A sled that
//! enters a universe with history while holding no record for it
//! raises a floor the same way. The floor is never persisted: the
//! burn, the missing record, or the unordered session is still there
//! after a restart, and raises it again. A floor written to disk
//! could carry a version that died with the life that created it;
//! no later session could ever dominate such a floor.
//!
//! A boundary that cannot be written means the job must not run. A
//! boundary that cannot be trusted means no job may run at all, since
//! we cannot tell what the previous life committed to. Recovery is an
//! M.2 swap or a clean slate.

use std::sync::Mutex as SyncMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ciborium::ser::into_writer as into_cbor;
use rumors::{Network, Version};
use serde::{Deserialize, Serialize};
use slog::{Logger, o, warn};
use thiserror::Error;

use sush_common::jobs::{JobId, JobStatus, ProcessError, SessionId};

use crate::bloom::Bloom;
use crate::format::{self, NoFormat, Record, Versioned};
use crate::locker::{Locker, StoreError, Tenant, TenantSpec, Verdict};

pub const BOUNDARY: TenantSpec = TenantSpec {
    file: "boundary",
    magic: b"SUSHBOUNDARY",
};

/// The execution boundary: what this sled last committed to, in which
/// universe, and which universes it has left behind ("burned").
///
/// Versions do not compare across universes, so `network` scopes every
/// version in the record. `burned` holds the network of every
/// universe whose watermark this record overwrote by moving on: a
/// sled re-entering one raises its floor in memory, and the record on
/// disk stays the displaced universe's true watermark until a commit
/// overwrites it.
///
/// `executed` is the join of the start versions of every session
/// this sled has executed under in this universe. A single stored
/// start would forget the sessions before it, and a third session
/// could then replay the first session's jobs; the join never
/// forgets. Session starts are witnessed messages, and only those
/// keep their meaning across a crash. A start that only this sled
/// ever saw belongs to a session whose history is lost, and refusal
/// is the right answer there anyway.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Boundary {
    pub network: Network,
    pub burned: Bloom,
    #[serde(with = "version_bytes")]
    pub executed: Version,
    pub job: Option<Committed>,
}

/// The last job this sled committed to running, and how far it got.
/// We also store the chain position *after* `job`, computed from the
/// request's signed bytes at commit time, to allow session resumption.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Committed {
    pub session: SessionId,
    pub job: JobId,
    pub successor: JobId,
    pub outcome: JobOutcome,
}

impl Boundary {
    /// Whether this record burned `network`: left its universe behind
    /// and overwrote its watermark.
    pub fn is_burned(&self, network: Network) -> bool {
        self.burned.contains(&network_key(network))
    }

    /// The burned set for the replacement record, committed in
    /// `network`. A replacement in a different universe burns this
    /// record's own network.
    pub fn burned_for(&self, network: Network) -> Bloom {
        let mut burned = self.burned.clone();
        if self.network != network {
            burned.insert(&network_key(self.network));
        }
        burned
    }

    /// The executed-session join for the replacement record,
    /// committed in `network` and folding in `started`. Joins never
    /// cross universes, so a replacement elsewhere starts its join
    /// fresh.
    pub fn executed_for(&self, network: Network, started: &Version) -> Version {
        if self.network == network {
            self.executed.clone() | started.clone()
        } else {
            started.clone()
        }
    }
}

/// A network's Bloom key is its CBOR bytes.
fn network_key(network: Network) -> Vec<u8> {
    let mut bytes = Vec::new();
    into_cbor(&network, &mut bytes).expect("writing to a Vec cannot fail");
    bytes
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

/// How far the boundary job got.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum JobOutcome {
    /// Committed to run, with no ending recorded.
    Committed,
    /// The job's terminal status, error endings included.
    Ended(JobStatus),
}

/// Version 0 is the shipped baseline. The pinned record snapshot in
/// this module's tests freezes its bytes; see [`crate::format`] for
/// the steps a format change requires.
impl Versioned for Boundary {
    const VERSION: u16 = 0;
}

impl Record for Boundary {
    type Previous = NoFormat;
}

impl TryFrom<NoFormat> for Boundary {
    type Error = &'static str;
    fn try_from(none: NoFormat) -> Result<Self, Self::Error> {
        match none {}
    }
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
    /// Untrusted until loaded, and forever if the load discards: a
    /// write would overwrite the disagreeing slots, and the next load
    /// would see agreement that never happened.
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
            Verdict::Adopt(record) | Verdict::Restore(record) => {
                match format::decode::<Boundary>(&record) {
                    Ok(boundary) => Some(boundary),
                    // An unreadable record is not an absent one:
                    // absent would mean a clean slate, forgetting the
                    // previous life's commitments. The store stays
                    // untrusted instead, and no job runs.
                    Err(error) => {
                        warn!(self.log, "unusable boundary record"; "error" => %error);
                        return;
                    }
                }
            }
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

    /// Record how the boundary job ended. A stop displaces an adjudicated
    /// `Interrupted`, mirroring the status arms in the state machine.
    /// Nothing else is overwritten, and a record that has moved on to
    /// a newer job ignores the old job's ending.
    pub async fn record_outcome(&self, job_id: &JobId, outcome: &JobStatus) {
        debug_assert!(outcome.is_terminal());
        if self.untrusted() {
            return;
        }
        let mut guard = self.tenant.lock().await;
        let updated = {
            let recorded = self.boundary.lock().unwrap();
            let Some(boundary) = recorded.as_ref() else {
                return;
            };
            let Some(committed) = boundary.job.as_ref().filter(|c| c.job == *job_id) else {
                return;
            };
            let displaces = matches!(
                (&committed.outcome, outcome),
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
                job: Some(Committed {
                    outcome: JobOutcome::Ended(outcome.clone()),
                    ..committed.clone()
                }),
                network: boundary.network,
                burned: boundary.burned.clone(),
                executed: boundary.executed.clone(),
            }
        };
        if let Err(error) = guard.store(&format::encode(&updated)).await {
            warn!(
                self.log, "failed to record the boundary job's outcome";
                "job_id" => %job_id, "error" => %error,
            );
            return;
        }
        *self.boundary.lock().unwrap() = Some(updated);
    }

    /// Commit to executing the job in `boundary`. On failure the
    /// caller must not run the job.
    pub async fn advance(&self, boundary: &Boundary) -> Result<(), BoundaryError> {
        if self.untrusted() {
            // Defense in depth: the state machine already refuses
            // execution when the store is untrusted, so no launch
            // reaches this arm.
            return Err(BoundaryError::Untrusted);
        }
        let mut guard = self.tenant.lock().await;
        guard.store(&format::encode(boundary)).await?;
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

    fn boundary() -> Boundary {
        Boundary {
            network: network(1),
            burned: Bloom::new(),
            executed: "(1, 1, (0, 0, 2))".parse().unwrap(),
            job: Some(Committed {
                session: SessionId::random(),
                job: JobId::random(),
                successor: JobId::random(),
                outcome: JobOutcome::Committed,
            }),
        }
    }

    fn job_of(boundary: &Boundary) -> JobId {
        boundary.job.as_ref().expect("a committed job").job
    }

    /// The record's bytes are on-disk format, frozen at version 0. If
    /// this fails, STOP: do not re-pin. Copy the old shape into a
    /// frozen module and add a new version instead; see
    /// [`crate::format`].
    #[test]
    fn pin_record_format_v0() {
        let record = Boundary {
            network: network(1),
            burned: {
                let mut burned = Bloom::new();
                burned.insert(&network_key(network(2)));
                burned
            },
            executed: "(1, 1, (0, 0, 2))".parse().unwrap(),
            job: Some(Committed {
                session: "abandon-ability".parse().unwrap(),
                job: "zoo-zero".parse().unwrap(),
                successor: "able-about".parse().unwrap(),
                outcome: JobOutcome::Committed,
            }),
        };
        let bytes = format::encode(&record);
        let path = "tests/output/boundary-record-v0.bin";
        if std::env::var("EXPECTORATE").as_deref() == Ok("overwrite") {
            std::fs::write(path, &bytes).unwrap();
        } else {
            let expected = std::fs::read(path).expect("missing snapshot");
            assert_eq!(bytes, expected, "record format changed: {bytes:02x?}");
        }
        let decoded: Boundary = format::decode(&bytes).unwrap();
        assert_eq!(decoded.network, record.network);
        assert!(decoded.is_burned(network(2)));
        assert_eq!(decoded.executed, record.executed);
        assert_eq!(
            decoded.job.unwrap().successor,
            record.job.unwrap().successor
        );
    }

    /// A record from a newer software version loads as untrusted, and
    /// the sled reports it instead of guessing at the format.
    #[tokio::test]
    async fn future_record_is_untrusted() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        #[derive(Serialize)]
        struct Envelope(u16, #[serde(with = "crate::format::cbor_bytes")] Vec<u8>);
        let mut bytes = Vec::new();
        into_cbor(&Envelope(1, b"from the future".to_vec()), &mut bytes).unwrap();
        let scratch = Locker::new(&test_log(), slots.clone());
        scratch.tenant(BOUNDARY).store(&bytes).await.unwrap();

        let store = store(slots).await;
        assert!(store.untrusted());
    }

    /// The burned set's keys are on-disk format: a change to the
    /// network's serde shape would silently forget every burn, and a
    /// forgotten burn admits a flip-flop instead of refusing it. If
    /// this fails, STOP, and see the warning on [`crate::bloom`].
    #[test]
    fn pin_network_keys() {
        assert_eq!(
            network_key(network(1)),
            [0x50, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn commitments_survive_restarts() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        let first = store(slots.clone()).await;
        assert!(first.boundary().is_none());

        let (a, mut b) = (boundary(), boundary());
        b.network = network(2);
        b.burned = a.burned_for(b.network);
        first.advance(&a).await.unwrap();
        first.advance(&b).await.unwrap();

        let next = store(slots).await;
        assert!(!next.untrusted());
        let recorded = next.boundary().unwrap();
        assert_eq!(recorded.network, b.network);
        assert_eq!(job_of(&recorded), job_of(&b));
        assert!(recorded.is_burned(network(1)));
        assert!(!recorded.is_burned(network(3)));
        assert_eq!(recorded.executed, b.executed);
        let (recorded, expected) = (recorded.job.unwrap(), b.job.unwrap());
        assert_eq!(recorded.session, expected.session);
        assert_eq!(recorded.successor, expected.successor);
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
        let b = boundary();
        let job = job_of(&b);
        first.advance(&b).await.unwrap();

        let interrupted = JobStatus::Error {
            job_id: job,
            time_error: chrono::Utc::now(),
            error: ProcessError::Interrupted,
        };
        let killed = JobStatus::Error {
            job_id: job,
            time_error: chrono::Utc::now(),
            error: ProcessError::Killed(9),
        };
        first.record_outcome(&JobId::random(), &killed).await;
        assert!(matches!(
            first.boundary().unwrap().job.unwrap().outcome,
            JobOutcome::Committed
        ));

        first.record_outcome(&job, &interrupted).await;
        first.record_outcome(&job, &killed).await;
        let next = store(slots).await;
        assert!(matches!(
            next.boundary().unwrap().job.unwrap().outcome,
            JobOutcome::Ended(JobStatus::Error {
                error: ProcessError::Interrupted,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn disagreement_is_untrusted_and_pins() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        for slot in &slots {
            let lone = store(vec![slot.clone()]).await;
            lone.advance(&boundary()).await.unwrap();
        }

        let untrusted = store(slots.clone()).await;
        assert!(untrusted.untrusted());
        assert!(untrusted.boundary().is_none());
        assert!(matches!(
            untrusted.advance(&boundary()).await,
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
            store.advance(&boundary()).await,
            Err(BoundaryError::Untrusted)
        ));
    }
}
