// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The boundary between jobs we've committed to executing, and jobs
//! we've only heard about via gossip.
//!
//! A singleton boundary record is written before each job execution.
//! It includes the job ID, session ID and sequence number, the chain
//! position after the job, the universe they belong to, and the job's
//! status (once it has one).
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
//! A boundary that cannot be written means the job must not run;
//! a boundary that cannot be read is treated as absent. In the
//! absence of a boundary record, the sled cannot guarantee that
//! any replayed job requests are safe to run (because they may
//! already have run here), and so only serves sessions that start
//! as observably live traffic.

use std::sync::Mutex as SyncMutex;

use rumors::Network;
use serde::{Deserialize, Serialize};
use slog::{Logger, o, warn};

use sush_common::jobs::{JobId, JobStatus, ProcessError, SessionId, SessionSeq};

use crate::format::{self, Record, Versioned};
use crate::locker::{Locker, StoreError, Tenant, TenantSpec, Verdict};

pub const BOUNDARY: TenantSpec = TenantSpec {
    file: "boundary",
    magic: b"SUSHBOUNDARY",
};

/// The execution boundary: what this sled last committed to, and in
/// which universe. The committed session supersedes every session at
/// or below its sequence number: the signer orders sessions totally
/// and across universes, so every session a previous life could have
/// run jobs under sits at or below this one stored number.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Boundary {
    pub network: Network,
    pub job: Option<Committed>,
}

/// The last job this sled committed to running, and how far it got.
/// We also store the chain position *after* `job`, computed from the
/// request's signed bytes at commit time, to allow session resumption
/// across a crash or reboot.
///
/// Suppose we didn't store the successor, and this sled received
/// job ID `J` with `command = reboot`. The sled could easily die
/// before gossiping the full job; it would have written `J` to its
/// boundary record, but would not have any way to compute the successor
/// ID `K` unless *re-presented* with the full job for `J`. Thus,
/// the session would be wedged unless the operator took the (unusual,
/// undesirable) step of re-submitting a job just to advance the chain.
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

/// Record version 1 replaces the v0 executed-session join and burned set
/// with the committed sequence number from the session-v2 protocol.
/// Don't confuse a "session-v2" (one with a sequence number) with a
/// boundary record version 2 (which doesn't yet exist).
///
/// See [`crate::format`] for instructions on adding this version's
/// successor.
impl Versioned for Boundary {
    const VERSION: u16 = 1;
}

impl Record for Boundary {
    type Previous = v0::Boundary;
}

impl TryFrom<v0::Boundary> for Boundary {
    type Error = &'static str;

    fn try_from(old: v0::Boundary) -> Result<Self, Self::Error> {
        let v0::Boundary {
            network,
            burned: _,   // dropped with session-v2 protocol
            executed: _, // also dropped with session-v2
            job,
        } = old;
        Ok(Self {
            network,
            job: job.map(|job| {
                let v0::Committed {
                    session,
                    job,
                    successor,
                    outcome,
                } = job;
                Committed {
                    session,
                    seq: SessionSeq::zero(), // any valid session-v2 will supersede this one
                    job,
                    successor,
                    outcome,
                }
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

/// Durable storage for the [`Boundary`].
#[derive(Debug)]
pub struct BoundaryStore {
    log: Logger,
    tenant: Tenant,
    /// The record, readable synchronously by the state machine.
    boundary: SyncMutex<Option<Boundary>>,
}

impl BoundaryStore {
    pub fn new(log: &Logger, locker: &Locker) -> Self {
        Self {
            log: log.new(o!("component" => "boundary")),
            tenant: locker.tenant(BOUNDARY),
            boundary: SyncMutex::new(None),
        }
    }

    /// Load the stored record once, at startup, before any job runs.
    pub async fn load(&self) {
        let boundary = match self.tenant.load().await {
            Verdict::Adopt(record) | Verdict::Restore(record) => {
                match format::decode::<Boundary>(&record) {
                    Ok(boundary) => Some(boundary),
                    Err(error) => {
                        warn!(self.log, "unusable boundary record"; "error" => %error);
                        None
                    }
                }
            }
            Verdict::Empty => None,
            // The locker warned about the discard. Starting over is
            // safe: a sled without a record serves only live-started
            // sessions, which no previous life can have run.
            Verdict::Discard(_) => None,
        };
        *self.boundary.lock().unwrap() = boundary;
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
    pub async fn advance(&self, boundary: &Boundary) -> Result<(), StoreError> {
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

    use sush_common::jobs::BaseboardId;

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

    fn locker(slots: Vec<Utf8PathBuf>) -> Locker {
        let baseboard = BaseboardId {
            part_number: "913".to_string(),
            serial_number: "test".to_string(),
        };
        Locker::new(&test_log(), baseboard, slots).unwrap()
    }

    async fn store(slots: Vec<Utf8PathBuf>) -> BoundaryStore {
        let store = BoundaryStore::new(&test_log(), &locker(slots));
        store.load().await;
        store
    }

    fn network(seed: u8) -> Network {
        serde_json::from_str(&format!("[{seed:?}{}]", ", 0".repeat(15))).unwrap()
    }

    fn seq(millis: u64) -> SessionSeq {
        SessionSeq::from_unix_millis(millis).unwrap()
    }

    fn boundary() -> Boundary {
        Boundary {
            network: network(1),
            job: Some(Committed {
                session: SessionId::random(),
                seq: seq(1_760_000_000_000),
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
    /// survives with a sequence number of zero. Nothing can regenerate
    /// the snapshot; the code that wrote it is gone, and git keeps the
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
                seq: seq(1_760_000_000_000),
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

    /// The store starts over on a record from newer software rather
    /// than guessing at its format.
    #[tokio::test]
    async fn future_record_starts_over() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        #[derive(Serialize)]
        struct Envelope(u16, #[serde(with = "crate::format::cbor_bytes")] Vec<u8>);
        let mut bytes = Vec::new();
        into_cbor(&Envelope(2, b"from the future".to_vec()), &mut bytes).unwrap();
        let scratch = locker(slots.clone());
        scratch.tenant(BOUNDARY).store(&bytes).await.unwrap();
        drop(scratch);

        let store = store(slots).await;
        assert!(store.boundary().is_none());
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

    /// The store starts over on disagreeing slots, and the next
    /// commit writes a fresh record.
    #[tokio::test]
    async fn disagreement_starts_over() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        for slot in &slots {
            let lone = store(vec![slot.clone()]).await;
            lone.advance(&boundary()).await.unwrap();
        }

        let fresh = store(slots.clone()).await;
        assert!(fresh.boundary().is_none());
        let committed = boundary();
        fresh.advance(&committed).await.unwrap();
        drop(fresh);

        let reload = store(slots).await;
        assert_eq!(job_of(&reload.boundary().unwrap()), job_of(&committed));
    }

    /// The store starts over on a record that does not decode.
    #[tokio::test]
    async fn undecodable_record_starts_over() {
        let dir = TempDir::with_prefix("sush-boundary-").unwrap();
        let slots = slots(&dir);
        let scratch = locker(slots.clone());
        scratch.tenant(BOUNDARY).store(b"scribble").await.unwrap();
        drop(scratch);

        let store = store(slots).await;
        assert!(store.boundary().is_none());
    }
}
