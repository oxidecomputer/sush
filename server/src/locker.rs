// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Durable per-sled state that is never stale.
//!
//! A [`Locker`] spans the boot M.2s. Each M.2 contributes one *slot*
//! directory, and each [`Tenant`] owns one file in every slot. A store
//! writes every slot and returns `Ok` only when all of them hold the
//! new record. A load applies the pair rules:
//!
//! | slot A        | slot B                  | verdict                  |
//! |---------------|-------------------------|--------------------------|
//! | record R      | record R                | adopt R                  |
//! | record R      | missing                 | restore R (an M.2 swap)  |
//! | missing       | missing                 | fresh                    |
//! | R, nonce N, n | S ≠ R, nonce N, seq > n | adopt S (a torn write)   |
//! | record R      | record S ≠ R            | discard                  |
//! | corrupt       | anything                | discard                  |
//! | I/O error     | anything                | discard                  |
//!
//! Every write carries a nonce drawn once per [`Locker`]. Slots that
//! disagree under one nonce were torn by a single process, so the
//! higher sequence number is that process's newest write, and a
//! newer-than-acknowledged record is safe to adopt: a store that
//! never returned had no effects.
//!
//! Discarding is a verdict, not an error, since each tenant decides
//! what starting over means.
//!
//! All of this is necessary to ensure the basic constraint that
//! **we must never adopt stale data**.

use std::collections::BTreeSet;
use std::fs::Permissions;
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex as SyncMutex};

use atomicwrites::{AtomicFile, OverwriteBehavior};
use camino::Utf8PathBuf;
use futures::TryFutureExt as _;
use slog::{Logger, o, warn};
use thiserror::Error;
use tokio::fs::{read, remove_file, write};
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::spawn_blocking;

use sush_common::authn::Nonce;
use sush_common::hash::Hasher;

const MAGIC_LEN: usize = 12;
const NONCE_LEN: usize = 32;
const SEQ_LEN: usize = 8;
const DIGEST_LEN: usize = 32;

fn digest(nonce: &[u8; NONCE_LEN], seq: u64, record: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(nonce);
    hasher.update(&seq.to_be_bytes());
    hasher.update(record);
    *hasher.finalize().as_bytes()
}

/// A file name and an envelope magic.
#[derive(Clone, Copy, Debug)]
pub struct TenantSpec {
    pub file: &'static str,
    pub magic: &'static [u8; MAGIC_LEN],
}

/// What a load found across the slots.
#[derive(Debug)]
pub enum Verdict {
    /// Every slot holds this record.
    Adopt(Vec<u8>),
    /// A slot is missing, but the survivors agree on this record.
    Restore(Vec<u8>),
    /// No slot holds a record.
    Empty,
    /// The slots cannot be trusted.
    Discard(Discard),
}

#[derive(Debug, Error)]
pub enum Discard {
    #[error("the slots disagree")]
    Disagree,
    #[error("`{path}` is corrupt")]
    Corrupt { path: Utf8PathBuf },
    #[error("reading `{path}` failed: {error}")]
    Io {
        path: Utf8PathBuf,
        #[source]
        error: io::Error,
    },
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("storing `{path}` failed: {error}")]
    Io {
        path: Utf8PathBuf,
        #[source]
        error: io::Error,
    },
    #[error("superseded by a newer record")]
    Superseded,
    #[error("the store task died: {0}")]
    Task(String),
}

/// This sled's durable state storage.
#[derive(Clone, Debug)]
pub struct Locker {
    log: Logger,
    slots: Arc<Vec<Utf8PathBuf>>,
    /// Stamped on every envelope this process writes; see the torn
    /// write rule in the module doc.
    nonce: Nonce,
    /// Files already claimed by a tenant. A second tenant over one
    /// file would have its own sequence state, silently defeating
    /// the straggler guard.
    claimed: Arc<SyncMutex<BTreeSet<&'static str>>>,
}

impl Locker {
    /// A locker spans `slots`. Empty means nothing persists
    /// (the standalone server, tests).
    pub fn new(log: &Logger, slots: Vec<Utf8PathBuf>) -> Self {
        Self {
            log: log.new(o!("component" => "locker")),
            slots: Arc::new(slots),
            nonce: Nonce::random(),
            claimed: Arc::new(SyncMutex::new(BTreeSet::new())),
        }
    }

    /// A locker that loads and persists nothing.
    pub fn null() -> Self {
        Self::new(&Logger::root(slog::Discard, o!()), Vec::new())
    }

    /// A tenant of this locker, described by a (constant) specification.
    /// Each file supports one tenant; a duplicate claim panics.
    pub fn tenant(&self, spec: TenantSpec) -> Tenant {
        assert!(
            self.claimed.lock().unwrap().insert(spec.file),
            "tenant `{}` is already claimed",
            spec.file,
        );
        Tenant {
            log: self.log.new(o!("tenant" => spec.file)),
            spec,
            paths: self.slots.iter().map(|slot| slot.join(spec.file)).collect(),
            nonce: self.nonce.clone(),
            reserved: Mutex::new(0),
            committed: Arc::new(SyncMutex::new(0)),
        }
    }

    /// Prove that every slot is writable by writing to every slot.
    pub async fn probe(&self) -> Result<(), StoreError> {
        for slot in self.slots.iter() {
            let probe = slot.join("probe");
            if let Err(error) = write(&probe, b"").and_then(|()| remove_file(&probe)).await {
                warn!(self.log, "unusable slot"; "path" => %probe);
                return Err(StoreError::Io { path: probe, error });
            }
        }
        Ok(())
    }
}

/// One tenant's files across the slots, with a two-stage
/// reserve/commit sequence number.
#[derive(Debug)]
pub struct Tenant {
    log: Logger,
    spec: TenantSpec,
    paths: Vec<Utf8PathBuf>,
    nonce: Nonce,
    /// The newest sequence number reserved or observed by this process.
    reserved: Mutex<u64>,
    /// The newest sequence number written to all slots.
    committed: Arc<SyncMutex<u64>>,
}

impl Tenant {
    /// Serialize loads and stores. Admission checks belong under the
    /// guard.
    pub async fn lock(&self) -> Guard<'_> {
        Guard {
            tenant: self,
            reserved: self.reserved.lock().await,
        }
    }

    pub async fn load(&self) -> Verdict {
        self.lock().await.load().await
    }

    pub async fn store(&self, record: &[u8]) -> Result<(), StoreError> {
        self.lock().await.store(record).await
    }

    fn parse(&self, bytes: &[u8]) -> Option<(Nonce, u64, Vec<u8>)> {
        let payload = bytes.strip_prefix(self.spec.magic.as_slice())?;
        let (nonce, rest) = payload.split_first_chunk::<NONCE_LEN>()?;
        let (seq, rest) = rest.split_first_chunk::<SEQ_LEN>()?;
        let (sum, record) = rest.split_first_chunk::<DIGEST_LEN>()?;
        let seq = u64::from_be_bytes(*seq);
        (digest(nonce, seq, record) == *sum)
            .then(|| (Nonce::from_be_bytes(*nonce), seq, record.to_vec()))
    }

    fn envelope(&self, seq: u64, record: &[u8]) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(MAGIC_LEN + NONCE_LEN + SEQ_LEN + DIGEST_LEN + record.len());
        bytes.extend_from_slice(self.spec.magic);
        let nonce = self.nonce.to_be_bytes();
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(&digest(&nonce, seq, record));
        bytes.extend_from_slice(record);
        bytes
    }
}

pub struct Guard<'a> {
    tenant: &'a Tenant,
    reserved: MutexGuard<'a, u64>,
}

impl Guard<'_> {
    pub async fn load(&mut self) -> Verdict {
        let tenant = self.tenant;
        if tenant.paths.is_empty() {
            return Verdict::Empty;
        }

        let mut found: Vec<(Nonce, u64, Vec<u8>)> = Vec::new();
        for path in &tenant.paths {
            let bytes = match read(path).await {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return self.discard(Discard::Io {
                        path: path.clone(),
                        error,
                    });
                }
            };
            match tenant.parse(&bytes) {
                Some(parsed) => found.push(parsed),
                None => return self.discard(Discard::Corrupt { path: path.clone() }),
            }
        }
        if found.is_empty() {
            return Verdict::Empty;
        }
        let restored = found.len() < tenant.paths.len();
        if !found.iter().all(|(_, _, record)| *record == found[0].2) {
            // Slots torn by one process resolve to its newest write;
            // see the module doc. Anything else is a genuine
            // disagreement.
            let (nonce, seq, record) = found
                .iter()
                .max_by_key(|(_, seq, _)| *seq)
                .cloned()
                .expect("found is non-empty");
            let torn = found.iter().all(|(n, ..)| *n == nonce)
                && found.iter().filter(|(_, s, _)| *s == seq).count() == 1;
            if !torn {
                return self.discard(Discard::Disagree);
            }
            warn!(tenant.log, "adopted the newest write of a torn pair"; "seq" => seq);
            if seq > *self.reserved {
                *self.reserved = seq;
            }
            if let Err(error) = self.store(&record).await {
                warn!(tenant.log, "failed to repair the torn pair"; "error" => %error);
            }
            return Verdict::Adopt(record);
        }

        let (_, seq, record) = found.swap_remove(0);
        let newest = found.iter().fold(seq, |max, (_, seq, _)| max.max(*seq));

        // A reserved sequence number outranks a re-read of the disk.
        // Regressing would let a cancelled write's straggler collide
        // with a fresh reservation.
        if newest > *self.reserved {
            *self.reserved = newest;
        }
        if restored {
            warn!(tenant.log, "restored from a lone slot");
            // Repair now: the survivor must not stay lone until the
            // next natural store.
            if let Err(error) = self.store(&record).await {
                warn!(tenant.log, "failed to repair the lone slot"; "error" => %error);
            }
            Verdict::Restore(record)
        } else {
            Verdict::Adopt(record)
        }
    }

    pub async fn store(&mut self, record: &[u8]) -> Result<(), StoreError> {
        let tenant = self.tenant;
        if tenant.paths.is_empty() {
            return Ok(());
        }

        *self.reserved += 1;
        let seq = *self.reserved;
        let envelope = tenant.envelope(seq, record);
        let paths = tenant.paths.clone();
        let committed = tenant.committed.clone();
        spawn_blocking(move || commit(&committed, &paths, seq, &envelope))
            .await
            .map_err(|join| StoreError::Task(join.to_string()))?
    }

    fn discard(&self, reason: Discard) -> Verdict {
        warn!(self.tenant.log, "discarding stored state"; "reason" => %reason);
        Verdict::Discard(reason)
    }
}

/// Rename `envelope` into every slot iff `seq` is newer than the
/// latest committed version. A cancelled store drops only the async
/// side of the write; the blocking side is already detached, runs
/// to completion regardless, and must not overwrite a newer record.
fn commit(
    committed: &SyncMutex<u64>,
    paths: &[Utf8PathBuf],
    seq: u64,
    envelope: &[u8],
) -> Result<(), StoreError> {
    let mut committed = committed.lock().unwrap();
    if seq <= *committed {
        return Err(StoreError::Superseded);
    }
    for path in paths {
        AtomicFile::new(path, OverwriteBehavior::AllowOverwrite)
            .write(|file| {
                file.set_permissions(Permissions::from_mode(0o600))?;
                file.write_all(envelope)
            })
            .map_err(|error| StoreError::Io {
                path: path.clone(),
                error: match error {
                    atomicwrites::Error::Internal(error) | atomicwrites::Error::User(error) => {
                        error
                    }
                },
            })?;
    }
    *committed = seq;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs::{create_dir, metadata, read, remove_file as remove, write};

    use tempfile::TempDir;

    const SPEC: TenantSpec = TenantSpec {
        file: "record",
        magic: b"SUSHLOCKTEST",
    };

    /// Two slot directories, like two M.2s.
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
        Logger::root(slog::Discard, o!())
    }

    fn locker(slots: Vec<Utf8PathBuf>) -> Locker {
        Locker::new(&test_log(), slots)
    }

    fn files(slots: &[Utf8PathBuf]) -> Vec<Utf8PathBuf> {
        slots.iter().map(|slot| slot.join(SPEC.file)).collect()
    }

    /// A store lands the same envelope in every slot, sequenced and
    /// private, and loads back adopted.
    #[tokio::test]
    async fn round_trip_writes_every_slot() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);

        assert!(matches!(tenant.load().await, Verdict::Empty));
        tenant.store(b"who we are").await.unwrap();
        assert!(matches!(
            tenant.load().await,
            Verdict::Adopt(record) if record == b"who we are"
        ));

        let expected = tenant.envelope(1, b"who we are");
        for path in files(&slots) {
            assert_eq!(read(&path).unwrap(), expected);
            let mode = metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A missing slot restores from the survivor, and the next store
    /// repairs it.
    #[tokio::test]
    async fn lone_slot_restores_and_repairs() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);
        tenant.store(b"kept").await.unwrap();

        let files = files(&slots);
        remove(&files[0]).unwrap();
        assert!(matches!(
            tenant.load().await,
            Verdict::Restore(record) if record == b"kept"
        ));

        tenant.store(b"repaired").await.unwrap();
        assert_eq!(read(&files[0]).unwrap(), read(&files[1]).unwrap());
        assert!(matches!(
            tenant.load().await,
            Verdict::Adopt(record) if record == b"repaired"
        ));
    }

    /// Disagreeing slots are discarded, not arbitrated by sequence
    /// number.
    #[tokio::test]
    async fn disagreement_discards() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let a = locker(vec![slots[0].clone()]).tenant(SPEC);
        a.store(b"one world").await.unwrap();
        let b = locker(vec![slots[1].clone()]).tenant(SPEC);
        b.store(b"junk").await.unwrap();
        b.store(b"another").await.unwrap();

        let tenant = locker(slots).tenant(SPEC);
        assert!(matches!(
            tenant.load().await,
            Verdict::Discard(Discard::Disagree)
        ));
    }

    /// Equal records adopt even when their sequence numbers differ,
    /// and new stores outnumber the highest.
    #[tokio::test]
    async fn legacy_sequence_skew_is_benign() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let a = locker(vec![slots[0].clone()]).tenant(SPEC);
        a.store(b"same").await.unwrap();
        let b = locker(vec![slots[1].clone()]).tenant(SPEC);
        b.store(b"junk").await.unwrap();
        b.store(b"same").await.unwrap();

        let tenant = locker(slots.clone()).tenant(SPEC);
        assert!(matches!(
            tenant.load().await,
            Verdict::Adopt(record) if record == b"same"
        ));
        tenant.store(b"next").await.unwrap();
        let expected = tenant.envelope(3, b"next");
        for path in files(&slots) {
            assert_eq!(read(&path).unwrap(), expected);
        }
    }

    /// A corrupt slot is discarded even beside a valid one.
    #[tokio::test]
    async fn corruption_discards() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);
        tenant.store(b"good").await.unwrap();

        write(slots[0].join(SPEC.file), b"scribble").unwrap();
        assert!(matches!(
            tenant.load().await,
            Verdict::Discard(Discard::Corrupt { .. })
        ));
    }

    /// A damaged nonce or sequence number fails the digest rather
    /// than parsing.
    #[tokio::test]
    async fn flipped_envelope_bytes_are_corruption() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);
        let path = slots[0].join(SPEC.file);
        for offset in [MAGIC_LEN, MAGIC_LEN + NONCE_LEN] {
            tenant.store(b"good").await.unwrap();
            let mut bytes = read(&path).unwrap();
            bytes[offset] ^= 0x80;
            write(&path, bytes).unwrap();
            assert!(matches!(
                tenant.load().await,
                Verdict::Discard(Discard::Corrupt { .. })
            ));
        }
    }

    /// Slots torn by one process resolve to its newest write, both
    /// in that process and in the next.
    #[tokio::test]
    async fn torn_pair_resolves_to_newest_write() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);
        tenant.store(b"old").await.unwrap();
        write(slots[0].join(SPEC.file), tenant.envelope(2, b"new")).unwrap();

        assert!(matches!(
            tenant.load().await,
            Verdict::Adopt(record) if record == b"new"
        ));

        let next = locker(slots.clone()).tenant(SPEC);
        assert!(matches!(
            next.load().await,
            Verdict::Adopt(record) if record == b"new"
        ));
        next.store(b"repaired").await.unwrap();
        assert_eq!(
            read(slots[0].join(SPEC.file)).unwrap(),
            read(slots[1].join(SPEC.file)).unwrap(),
        );
    }

    /// Equal sequence numbers cannot be arbitrated, even in one life.
    #[tokio::test]
    async fn torn_pair_with_equal_sequence_numbers_discards() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);
        write(slots[0].join(SPEC.file), tenant.envelope(2, b"x")).unwrap();
        write(slots[1].join(SPEC.file), tenant.envelope(2, b"y")).unwrap();

        assert!(matches!(
            tenant.load().await,
            Verdict::Discard(Discard::Disagree)
        ));
    }

    /// A store failing partway errs, and the survivor still loads:
    /// the record was never acknowledged, so either version is sound.
    #[tokio::test]
    async fn partial_store_fails_loudly() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let good = slots(&dir).swap_remove(0);
        let gone = Utf8PathBuf::from_path_buf(dir.path().join("gone")).unwrap();
        let tenant = locker(vec![good.clone(), gone]).tenant(SPEC);

        assert!(matches!(
            tenant.store(b"half").await,
            Err(StoreError::Io { .. })
        ));
        assert!(matches!(
            tenant.load().await,
            Verdict::Restore(record) if record == b"half"
        ));
    }

    /// A straggling write from a dropped store future cannot land on
    /// top of a newer committed record.
    #[tokio::test]
    async fn stragglers_cannot_clobber_newer_commits() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);
        let paths = files(&slots);

        let newer = tenant.envelope(7, b"newer");
        let straggler = tenant.envelope(6, b"stale");
        commit(&tenant.committed, &paths, 7, &newer).unwrap();
        assert!(matches!(
            commit(&tenant.committed, &paths, 6, &straggler),
            Err(StoreError::Superseded)
        ));
        assert_eq!(read(&paths[0]).unwrap(), newer);
    }

    /// Probing proves every slot writable by writing.
    #[tokio::test]
    async fn probe_requires_every_slot() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let mut slots = slots(&dir);
        locker(slots.clone()).probe().await.unwrap();

        slots.push(Utf8PathBuf::from("/nonexistent/sush"));
        assert!(matches!(
            locker(slots).probe().await,
            Err(StoreError::Io { .. })
        ));
    }

    /// A null locker persists nothing and never fails.
    #[tokio::test]
    async fn null_touches_nothing() {
        let tenant = Locker::null().tenant(SPEC);
        tenant.store(b"lost").await.unwrap();
        assert!(matches!(tenant.load().await, Verdict::Empty));
        Locker::null().probe().await.unwrap();
    }
}
