// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The boundary between jobs we executed and jobs we only heard about.
//!
//! One record, rewritten before each spawn, carries what this sled
//! last committed to: the job, its session and that session's
//! sequence number, the chain position after the job, the universe
//! they belong to, and the job's ending once it has one. The record
//! is this sled's execution floor: the signer assigns every session
//! a sequence number from its wall clock, so sequence numbers order
//! sessions totally, across restarts and across universes, and no
//! session at or below the committed sequence number may run jobs
//! here again.
//!
//! After a restart, replayed gossip rebuilds the sessions. When the
//! committed session activates, the sled resumes its chain at the
//! stored successor. The previous life had already moved the chain
//! past every earlier position, so the session's queue never
//! releases those jobs here, and the chain continues from the
//! successor whether its request arrives by replay or by
//! resubmission. A session whose sequence number exceeds the
//! committed one has never run jobs here and is served; any other
//! session's jobs are skipped. If replay gives the recorded job no
//! status, the sled adjudicates it: it announces the recorded ending
//! when the record holds one, and an interrupted ending when it does
//! not.
//!
//! A sled with no record cannot tell replay from re-run, so it
//! serves only sessions that start as live traffic.
//!
//! A boundary that cannot be written means the job must not run. A
//! boundary that cannot be trusted means no job may run at all, since
//! we cannot tell what the previous life committed to. Recovery is an
//! M.2 swap or a clean slate.

use std::sync::Mutex as SyncMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use rumors::Network;
use serde::{Deserialize, Serialize};
use slog::{Logger, o, warn};
use thiserror::Error;

use sush_common::jobs::{JobId, JobStatus, ProcessError, SessionId, SessionSeq};

use crate::format::{self, Record, Versioned};
use crate::locker::{Locker, StoreError, Tenant, TenantSpec, Verdict};

pub const BOUNDARY: TenantSpec = TenantSpec {
    file: "boundary",
    magic: b"SUSHBOUNDARY",
};

/// The execution boundary: what this sled last committed to, and in
/// which universe. The committed job's sequence number is the sled's
/// global execution floor: the signer orders sessions totally and
/// across universes, so every session a previous life could have run
/// jobs under sits at or below this one stored number.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Boundary {
    pub network: Network,
    pub job: Option<Committed>,
}

/// The last job this sled committed to running, and how far it got.
/// We also store the chain position *after* `job`, computed from the
/// request's signed bytes at commit time, to allow session resumption.
///
/// The sequence number itself travels unsigned, in the gossiped
/// session preimage, yet a forged one cannot reach this record: the
/// sled writes the record only when it commits to a signed job, the
/// job's signed bytes name the session id, and the id hashes over
/// the preimage, sequence number included. A preimage with a
/// different sequence number hashes to a different session id, and
/// no signed job names that id.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Committed {
    pub session: SessionId,
    pub seq: SessionSeq,
    pub job: JobId,
    pub successor: JobId,
    pub outcome: JobOutcome,
}

/// How far the boundary job got.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum JobOutcome {
    /// Committed to run, with no ending recorded.
    Committed,
    /// The job's terminal status, error endings included.
    Ended(JobStatus),
}

/// Version 1 replaced the executed-session join and the burned set
/// with the committed sequence number. The pinned record snapshots in this
/// module's tests freeze both versions' bytes; see [`crate::format`]
/// for the steps a format change requires.
impl Versioned for Boundary {
    const VERSION: u16 = 1;
}

impl Record for Boundary {
    type Previous = v0::Boundary;
}

impl TryFrom<v0::Boundary> for Boundary {
    type Error = &'static str;

    /// A v0 record kept a per-universe join of session-start versions
    /// instead of a sequence number, and the join yields no sequence
    /// number, so the committed job converts with a floor of zero:
    /// the session still resumes, and the floor refuses nothing. The
    /// zero floor readmits nothing a previous life ran, because every
    /// v0 record predates sequence numbers and only sessions that
    /// carry one can start now.
    fn try_from(old: v0::Boundary) -> Result<Self, Self::Error> {
        Ok(Self {
            network: old.network,
            job: old.job.map(|job| Committed {
                session: job.session,
                seq: SessionSeq::from_unix_seconds(0).expect("zero is encodable"),
                job: job.job,
                successor: job.successor,
                outcome: job.outcome,
            }),
        })
    }
}

/// The version 0 record shapes, kept only to decode records written
/// before sessions carried sequence numbers.
pub mod v0 {
    use super::{JobId, JobOutcome, Network, SessionId};
    use crate::format::{NoFormat, Record, Versioned};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use sush_common::wire::ExactBytes;

    #[derive(Deserialize, Serialize)]
    pub struct Boundary {
        pub network: Network,
        pub burned: Burned,
        #[serde(with = "version_bytes")]
        pub executed: rumors::Version,
        pub job: Option<Committed>,
    }

    /// The v0 burned set: the Bloom filter's 1024 bytes, decoded but
    /// never read.
    pub struct Burned(Box<[u8; 1024]>);

    impl Serialize for Burned {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(&self.0[..])
        }
    }

    impl<'de> Deserialize<'de> for Burned {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Ok(Self(Box::new(
                deserializer.deserialize_bytes(ExactBytes::<1024>)?,
            )))
        }
    }

    #[derive(Deserialize, Serialize)]
    pub struct Committed {
        pub session: SessionId,
        pub job: JobId,
        pub successor: JobId,
        pub outcome: JobOutcome,
    }

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

    mod version_bytes {
        use rumors::Version;
        use serde::de::Error as _;
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(
            version: &Version,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(&version.encode())
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Version, D::Error> {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            Version::decode(bytes.as_slice()).map_err(D::Error::custom)
        }
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
    pub async fn record_outcome(&self, status: &JobStatus) {
        assert!(status.is_terminal());
        if self.untrusted() {
            return;
        }
        let mut guard = self.tenant.lock().await;
        let updated = {
            let recorded = self.boundary.lock().unwrap();
            let Some(boundary) = recorded.as_ref() else {
                return;
            };
            let Some(committed) = boundary.job.as_ref().filter(|c| c.job == *status.job_id())
            else {
                return;
            };
            let displaces = matches!(
                (&committed.outcome, status),
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
                    outcome: JobOutcome::Ended(status.clone()),
                    ..committed.clone()
                }),
                network: boundary.network,
            }
        };
        if let Err(error) = guard.store(&format::encode(&updated)).await {
            warn!(
                self.log, "failed to record the boundary job's outcome";
                "job_id" => status.job_id(), "error" => %error,
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
    use ciborium::ser::into_writer as into_cbor;
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
        let store = BoundaryStore::new(&test_log(), &Locker::new(&test_log(), slots).unwrap());
        store.load().await;
        store
    }

    fn network(seed: u8) -> Network {
        serde_json::from_str(&format!("[{seed:?}{}]", ", 0".repeat(15))).unwrap()
    }

    fn seq(seconds: u64) -> SessionSeq {
        SessionSeq::from_unix_seconds(seconds).unwrap()
    }

    fn boundary() -> Boundary {
        Boundary {
            network: network(1),
            job: Some(Committed {
                session: SessionId::random(),
                seq: seq(1_760_000_000),
                job: JobId::random(),
                successor: JobId::random(),
                outcome: JobOutcome::Committed,
            }),
        }
    }

    fn job_of(boundary: &Boundary) -> JobId {
        boundary.job.as_ref().expect("a committed job").job
    }

    /// The frozen v0 snapshot decodes and converts: the commitment
    /// survives with a floor of zero. Nothing can regenerate the
    /// snapshot; the code that wrote it is gone, and git keeps the
    /// bytes.
    #[test]
    fn v0_record_converts() {
        let bytes = std::fs::read("tests/output/boundary-record-v0.bin").expect("missing snapshot");
        let decoded: Boundary = format::decode(&bytes).unwrap();
        assert_eq!(decoded.network, network(1));
        let job = decoded.job.unwrap();
        assert_eq!(job.session, "abandon-ability".parse().unwrap());
        assert_eq!(job.successor, "able-about".parse().unwrap());
        assert_eq!(job.seq, seq(0));
    }

    /// The record's bytes are on-disk format, frozen at version 1. If
    /// this fails, STOP: do not re-pin. Copy the old shape into a
    /// frozen module and add a new version instead; see
    /// [`crate::format`].
    #[test]
    fn pin_record_format_v1() {
        let record = Boundary {
            network: network(1),
            job: Some(Committed {
                session: "abandon-ability".parse().unwrap(),
                seq: seq(1_760_000_000),
                job: "zoo-zero".parse().unwrap(),
                successor: "able-about".parse().unwrap(),
                outcome: JobOutcome::Committed,
            }),
        };
        let bytes = format::encode(&record);
        let path = "tests/output/boundary-record-v1.bin";
        if std::env::var("EXPECTORATE").as_deref() == Ok("overwrite") {
            std::fs::write(path, &bytes).unwrap();
        } else {
            let expected = std::fs::read(path).expect("missing snapshot");
            assert_eq!(bytes, expected, "record format changed: {bytes:02x?}");
        }
        let decoded: Boundary = format::decode(&bytes).unwrap();
        assert_eq!(decoded.network, record.network);
        let (decoded, expected) = (decoded.job.unwrap(), record.job.unwrap());
        assert_eq!(decoded.session, expected.session);
        assert_eq!(decoded.seq, expected.seq);
        assert_eq!(decoded.successor, expected.successor);
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
        into_cbor(&Envelope(2, b"from the future".to_vec()), &mut bytes).unwrap();
        let scratch = Locker::new(&test_log(), slots.clone()).unwrap();
        scratch.tenant(BOUNDARY).store(&bytes).await.unwrap();
        drop(scratch);

        let store = store(slots).await;
        assert!(store.untrusted());
    }

    #[tokio::test]
    async fn commitments_survive_restarts() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        let first = store(slots.clone()).await;
        assert!(first.boundary().is_none());

        let (a, mut b) = (boundary(), boundary());
        b.network = network(2);
        first.advance(&a).await.unwrap();
        first.advance(&b).await.unwrap();
        drop(first);

        let next = store(slots).await;
        assert!(!next.untrusted());
        let recorded = next.boundary().unwrap();
        assert_eq!(recorded.network, b.network);
        assert_eq!(job_of(&recorded), job_of(&b));
        let (recorded, expected) = (recorded.job.unwrap(), b.job.unwrap());
        assert_eq!(recorded.session, expected.session);
        assert_eq!(recorded.seq, expected.seq);
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
        let stray = JobStatus::Error {
            job_id: JobId::random(),
            time_error: chrono::Utc::now(),
            error: ProcessError::Killed(9),
        };
        first.record_outcome(&stray).await;
        assert!(matches!(
            first.boundary().unwrap().job.unwrap().outcome,
            JobOutcome::Committed
        ));

        first.record_outcome(&interrupted).await;
        first.record_outcome(&killed).await;
        drop(first);
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
        drop(untrusted);

        let reload = store(slots).await;
        assert!(reload.untrusted());
    }

    #[tokio::test]
    async fn undecodable_record_is_untrusted() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        let scratch = Locker::new(&test_log(), slots.clone()).unwrap();
        scratch.tenant(BOUNDARY).store(b"scribble").await.unwrap();
        drop(scratch);

        let store = BoundaryStore::new(&test_log(), &Locker::new(&test_log(), slots).unwrap());
        store.load().await;
        assert!(store.untrusted());
    }

    #[tokio::test]
    async fn unloaded_is_untrusted() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let store =
            BoundaryStore::new(&test_log(), &Locker::new(&test_log(), slots(&dir)).unwrap());
        assert!(store.untrusted());
        assert!(matches!(
            store.advance(&boundary()).await,
            Err(BoundaryError::Untrusted)
        ));
    }
}
