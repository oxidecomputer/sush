// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Durable per-sled state that must not mistake old records for new.
//!
//! A [`Locker`] spans the M.2 drives. Each M.2 contributes one
//! *slot* directory, and each [`Tenant`] owns one *record*,
//! stored as one file in every slot:
//!
//! ```text
//! baseboard                the sled's identity
//! └── Locker               state storage handle
//!     ├── Tenant           record x
//!     │   ├── slot (M.2 A)   m2a/x = (envelope, record)
//!     │   └── slot (M.2 B)   m2b/x = (envelope, record)
//!     └── Tenant           record y
//!         ├── slot (M.2 A)   m2a/y = (envelope, record)
//!         └── slot (M.2 B)   m2b/y = (envelope, record)
//! ```
//!
//! The basic operations on tenants are load and store.
//! A store writes every slot and returns `Ok` only when all
//! of them have the new record. A load applies the pair rules
//! to obtain a [`Verdict`]:
//!
//! | slot A        | slot B                  | verdict   |
//! |---------------|-------------------------|-----------|
//! | record R      | record R                | adopt R   |
//! | record R      | missing                 | restore R |
//! | missing       | missing                 | empty     |
//! | R, nonce N, n | S ≠ R, nonce N, seq > n | adopt S   |
//! | record R      | record S ≠ R            | discard   |
//! | foreign sled  | anything                | discard   |
//! | corrupt       | anything                | discard   |
//! | I/O error     | anything                | discard   |
//!
//! Each slot file holds a record preceded by an `Envelope`,
//! which includes a random per-locker nonce, a sequence
//! number, and the baseboard ID of the sled that wrote it.
//! Envelopes are also versioned to let the format evolve.
//!
//! A locker holds an advisory lock on every slot until it and all
//! of its tenants drop, so a locker in another process that tries
//! to claim any of the same slots will fail. If a slot directory
//! is removed, it will be *healed* by recreating it (with lock file)
//! through a handle taken at startup on the slot's parent directory
//! (so that we don't accidentally recreate the slot directory on
//! the wrong filesystem).
//!
//! Current tenants are the execution [`boundary`] and the rumors
//! [`bookmark`].

pub mod bookmark;
pub mod boundary;

use std::fs::{File, Permissions};
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex as SyncMutex};

use atomicwrites::{AtomicFile, OverwriteBehavior};
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use camino::Utf8PathBuf;
use futures::TryFutureExt as _;
use rustix::fs::{FlockOperation, Mode, fcntl_lock, mkdirat};
use rustix::io::Errno;
use slog::{Logger, o, warn};
use thiserror::Error;
use tokio::fs::{read, remove_file, write};
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::spawn_blocking;

use sush_common::authn::Nonce;
use sush_common::hash::Hasher;
use sush_common::jobs::BaseboardId;

use crate::format::{NoFormat, Versioned, Wire};

const LOCK_FILE: &str = "lock";
const MAGIC_LEN: usize = 12;
const NONCE_LEN: usize = 32;
const DIGEST_LEN: usize = 32;

#[derive(Clone)]
struct Envelope {
    nonce: Nonce,
    seq: u64,
    baseboard: BaseboardId,
    record: Vec<u8>,
}

/// See [`crate::format`] for instructions on adding this version's
/// successor, following the usual conventions for infallible (wire)
/// conversions. (An unversioned, pre-release version 0 existed; its
/// records read as corrupt and discard.)
impl Versioned for Envelope {
    const VERSION: u16 = 1;
}

impl Wire for Envelope {
    type Previous = NoFormat;
}

impl From<NoFormat> for Envelope {
    fn from(none: NoFormat) -> Self {
        match none {}
    }
}

impl Envelope {
    /// Append one length-prefixed envelope field, truncated to the
    /// prefix's 16-bit width.
    fn put(bytes: &mut BytesMut, field: &[u8]) {
        let field = &field[..field.len().min(usize::from(u16::MAX))];
        bytes.put_u16(field.len() as u16);
        bytes.put_slice(field);
    }

    /// Split off one length-prefixed envelope field.
    fn take<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
        let len = usize::from(bytes.try_get_u16().ok()?);
        let (field, rest) = bytes.split_at_checked(len)?;
        *bytes = rest;
        Some(field)
    }

    /// Hash the envelope bytes before the digest field,
    /// then the record after it.
    fn digest(prefix: &[u8], record: &[u8]) -> [u8; DIGEST_LEN] {
        let mut hasher = Hasher::new();
        hasher.update_with_len(prefix);
        hasher.update_with_len(record);
        *hasher.finalize().as_bytes()
    }

    fn encode(
        magic: &[u8; MAGIC_LEN],
        nonce: &Nonce,
        seq: u64,
        baseboard: &BaseboardId,
        record: &[u8],
    ) -> Bytes {
        let nonce = nonce.to_be_bytes();
        let seq = seq.to_be_bytes();
        let fields: [&[u8]; 4] = [
            &nonce,
            &seq,
            baseboard.part_number.as_bytes(),
            baseboard.serial_number.as_bytes(),
        ];
        let prefixed = fields.iter().map(|f| size_of::<u16>() + f.len());
        let mut bytes = BytesMut::with_capacity(
            MAGIC_LEN
                + size_of::<u16>()
                + prefixed.sum::<usize>()
                + size_of::<u16>()
                + DIGEST_LEN
                + record.len(),
        );
        bytes.put_slice(magic);
        bytes.put_u16(Self::VERSION);
        for field in fields {
            Self::put(&mut bytes, field);
        }
        let digest = Self::digest(&bytes, record);
        Self::put(&mut bytes, &digest);
        bytes.put_slice(record);
        bytes.freeze()
    }

    fn decode(magic: &[u8; MAGIC_LEN], bytes: &[u8]) -> Option<Self> {
        let mut rest = bytes.strip_prefix(magic.as_slice())?;
        if rest.try_get_u16().ok()? != Self::VERSION {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = Self::take(&mut rest)?.try_into().ok()?;
        let seq = u64::from_be_bytes(Self::take(&mut rest)?.try_into().ok()?);
        let part = Self::take(&mut rest)?;
        let serial = Self::take(&mut rest)?;
        let prefix = &bytes[..bytes.len() - rest.len()];
        let digest: [u8; DIGEST_LEN] = Self::take(&mut rest)?.try_into().ok()?;
        let record = rest;
        let baseboard = BaseboardId {
            part_number: String::from_utf8(part.to_vec()).ok()?,
            serial_number: String::from_utf8(serial.to_vec()).ok()?,
        };
        (Self::digest(prefix, record) == digest).then(|| Self {
            nonce: Nonce::from_be_bytes(nonce),
            seq,
            baseboard,
            record: record.to_vec(),
        })
    }
}

/// A file name and an envelope magic. The name `lock` is reserved
/// for the slot lock file.
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
    #[error("`{path}` was written by sled {baseboard}")]
    Foreign {
        path: Utf8PathBuf,
        baseboard: BaseboardId,
    },
    #[error("`{path}` is corrupt")]
    Corrupt { path: Utf8PathBuf },
    #[error("reading `{path}` failed: {error}")]
    Io {
        path: Utf8PathBuf,
        #[source]
        error: io::Error,
    },
}

/// Some other locker holds a requested slot.
#[derive(Debug, Error)]
#[error("another locker holds `{path}`: {error}")]
pub struct Locked {
    path: Utf8PathBuf,
    #[source]
    error: io::Error,
}

/// An advisory slot lock, held until the file closes.
#[derive(Debug)]
struct LockFile {
    _file: File,
}

impl LockFile {
    /// Take the lock at `path`. If the lock file cannot be
    /// created, log why and return `Ok(None)`; the slot is
    /// broken.
    fn take(log: &Logger, path: &Utf8PathBuf) -> Result<Option<Self>, Locked> {
        let file = match File::create(path) {
            Ok(file) => file,
            Err(error) => {
                warn!(log, "cannot create slot lock file"; "path" => %path, "error" => %error);
                return Ok(None);
            }
        };
        match fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(errno) => Err(Locked {
                path: path.clone(),
                error: errno.into(),
            }),
        }
    }
}

/// One slot directory and this locker's claim on it.
#[derive(Debug)]
struct Slot {
    path: Utf8PathBuf,
    state: SlotState,
}

#[derive(Debug)]
enum SlotState {
    /// The slot could not be claimed at startup, usually because its
    /// directory was missing. A broken slot is only ever read; it is
    /// never written and can never heal.
    Broken,

    /// The slot is locked and healable. We serialize writes so that
    /// concurrent heals can't race and accidentally drop the lock.
    Claimed {
        parent: File,
        lock: SyncMutex<LockFile>,
    },
}

impl Slot {
    /// Try to lock the slot and obtain a handle to its parent.
    fn claim(log: &Logger, path: Utf8PathBuf) -> Result<Self, Locked> {
        let state = match LockFile::take(log, &path.join(LOCK_FILE))? {
            Some(lock) => match path.parent().map(File::open) {
                Some(Ok(parent)) => SlotState::Claimed {
                    parent,
                    lock: SyncMutex::new(lock),
                },
                Some(Err(error)) => {
                    warn!(log, "cannot open the slot's parent"; "slot" => %path, "error" => %error);
                    SlotState::Broken
                }
                None => {
                    warn!(log, "the slot path has no parent"; "slot" => %path);
                    SlotState::Broken
                }
            },
            None => SlotState::Broken,
        };
        Ok(Self { path, state })
    }

    /// Write `envelope` to `path` inside this slot. If the write
    /// fails because the directory is gone, recreate it and retry.
    fn write(&self, log: &Logger, path: &Utf8PathBuf, envelope: &[u8]) -> io::Result<()> {
        let SlotState::Claimed { parent, lock } = &self.state else {
            return Err(io::Error::other("broken slot"));
        };
        let mut held = lock.lock().unwrap();
        match write_envelope(path, envelope) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.heal(parent, &mut held, log)?;
                write_envelope(path, envelope)
            }
            result => result,
        }
    }

    /// Recreate this slot's wiped directory and its lock.
    /// Fail if another process claims the fresh slot first.
    fn heal(&self, parent: &File, lock: &mut LockFile, log: &Logger) -> io::Result<()> {
        let name = self
            .path
            .file_name()
            .ok_or_else(|| io::Error::other("slot path has no final component"))?;
        match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(errno) => return Err(errno.into()),
        }
        *lock = LockFile::take(log, &self.path.join(LOCK_FILE))
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("cannot create the slot lock file"))?;
        warn!(log, "healed a wiped slot"; "slot" => %self.path);
        Ok(())
    }
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
///
/// NB: There must be only one locker instance per process, since
/// our advisory locks only protect against *other* processes opening
/// the slot files.
#[derive(Clone, Debug)]
pub struct Locker {
    log: Logger,
    baseboard: BaseboardId,
    nonce: Nonce,
    slots: Arc<Vec<Slot>>,
}

impl Locker {
    /// A locker spans `slots` and binds every record to `baseboard`.
    /// Empty slots mean nothing persists (the standalone server,
    /// tests). Fails if another locker has claimed any of the slots.
    pub fn new(
        log: &Logger,
        baseboard: BaseboardId,
        slots: Vec<Utf8PathBuf>,
    ) -> Result<Self, Locked> {
        let log = log.new(o!("component" => "locker"));
        let mut claimed_slots = Vec::with_capacity(slots.len());
        for path in slots {
            claimed_slots.push(Slot::claim(&log, path)?);
        }
        Ok(Self {
            log,
            baseboard,
            nonce: Nonce::random(),
            slots: Arc::new(claimed_slots),
        })
    }

    /// A locker that loads and persists nothing.
    pub fn null() -> Self {
        let fake = BaseboardId {
            part_number: String::new(),
            serial_number: String::new(),
        };
        Self::new(&Logger::root(slog::Discard, o!()), fake, Vec::new())
            .expect("a locker without slots takes no locks")
    }

    /// A tenant of this locker, described by a (constant)
    /// specification. No two tenants may share a file.
    pub fn tenant(&self, spec: TenantSpec) -> Tenant {
        Tenant {
            log: self.log.new(o!("tenant" => spec.file)),
            spec,
            slots: Arc::clone(&self.slots),
            baseboard: self.baseboard.clone(),
            nonce: self.nonce.clone(),
            reserved: Mutex::new(0),
            committed: Arc::new(SyncMutex::new(0)),
        }
    }

    /// Prove that every slot is writable by writing to every slot.
    pub async fn probe(&self) -> Result<(), StoreError> {
        for slot in self.slots.iter() {
            let probe = slot.path.join("probe");
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
    slots: Arc<Vec<Slot>>,
    baseboard: BaseboardId,
    nonce: Nonce,
    reserved: Mutex<u64>,
    committed: Arc<SyncMutex<u64>>,
}

impl Tenant {
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

    fn envelope(&self, seq: u64, record: &[u8]) -> Bytes {
        Envelope::encode(self.spec.magic, &self.nonce, seq, &self.baseboard, record)
    }
}

pub struct Guard<'a> {
    tenant: &'a Tenant,
    reserved: MutexGuard<'a, u64>,
}

impl Guard<'_> {
    pub async fn load(&mut self) -> Verdict {
        let tenant = self.tenant;
        if tenant.slots.is_empty() {
            return Verdict::Empty;
        }

        let mut found: Vec<Envelope> = Vec::new();
        for slot in tenant.slots.iter() {
            let path = slot.path.join(tenant.spec.file);
            let bytes = match read(&path).await {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return self.discard(Discard::Io { path, error });
                }
            };
            match Envelope::decode(tenant.spec.magic, &bytes) {
                Some(envelope) => {
                    if envelope.baseboard != tenant.baseboard {
                        return self.discard(Discard::Foreign {
                            path,
                            baseboard: envelope.baseboard,
                        });
                    }
                    found.push(envelope);
                }
                None => return self.discard(Discard::Corrupt { path }),
            }
        }
        if found.is_empty() {
            return Verdict::Empty;
        }
        let restored = found.len() < tenant.slots.len();
        if !found.iter().all(|e| e.record == found[0].record) {
            // Slots torn by one process resolve to its newest write;
            // see the module doc. Anything else is a genuine
            // disagreement.
            let Envelope {
                nonce, seq, record, ..
            } = found
                .iter()
                .max_by_key(|e| e.seq)
                .cloned()
                .expect("found is non-empty");
            let torn = found.iter().all(|e| e.nonce == nonce)
                && found.iter().filter(|e| e.seq == seq).count() == 1;
            if !torn {
                return self.discard(Discard::Disagree);
            }
            warn!(tenant.log, "adopted the newest write of a torn pair"; "seq" => seq);
            *self.reserved = seq.max(*self.reserved);
            if let Err(error) = self.store(&record).await {
                warn!(tenant.log, "failed to repair the torn pair"; "error" => %error);
            }
            return Verdict::Adopt(record);
        }

        let Envelope { seq, record, .. } = found.swap_remove(0);
        let newest = found.iter().fold(seq, |max, e| max.max(e.seq));
        *self.reserved = newest.max(*self.reserved);

        if restored {
            warn!(tenant.log, "restored from a lone slot");
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
        if tenant.slots.is_empty() {
            return Ok(());
        }

        *self.reserved += 1;
        let seq = *self.reserved;
        let envelope = tenant.envelope(seq, record);
        let slots = Arc::clone(&tenant.slots);
        let committed = tenant.committed.clone();
        let (log, file) = (tenant.log.clone(), tenant.spec.file);
        spawn_blocking(move || commit(&log, &committed, &slots, file, seq, &envelope))
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
    log: &Logger,
    committed: &SyncMutex<u64>,
    slots: &[Slot],
    file: &str,
    seq: u64,
    envelope: &[u8],
) -> Result<(), StoreError> {
    let mut committed = committed.lock().unwrap();
    if seq <= *committed {
        return Err(StoreError::Superseded);
    }
    for slot in slots {
        let path = slot.path.join(file);
        slot.write(log, &path, envelope)
            .map_err(|error| StoreError::Io { path, error })?;
    }
    *committed = seq;
    Ok(())
}

fn write_envelope(path: &Utf8PathBuf, envelope: &[u8]) -> io::Result<()> {
    AtomicFile::new(path, OverwriteBehavior::AllowOverwrite)
        .write(|file| {
            file.set_permissions(Permissions::from_mode(0o600))?;
            file.write_all(envelope)
        })
        .map_err(|error| match error {
            atomicwrites::Error::Internal(error) | atomicwrites::Error::User(error) => error,
        })
}

#[cfg(test)]
mod test {
    use super::*;

    use std::env::{current_exe, var};
    use std::fs::{create_dir, metadata, read, remove_dir_all, remove_file as remove, write};
    use std::process::{Command, exit};

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

    fn baseboard() -> BaseboardId {
        BaseboardId {
            part_number: "913".to_string(),
            serial_number: "test".to_string(),
        }
    }

    fn locker(slots: Vec<Utf8PathBuf>) -> Locker {
        Locker::new(&test_log(), baseboard(), slots).unwrap()
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
        drop((a, b));

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
        drop((a, b));

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

    /// A damaged envelope field reads as corruption, never as a
    /// parse of the damaged bytes and never as another sled's record.
    #[tokio::test]
    async fn flipped_envelope_bytes_are_corruption() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);
        let path = slots[0].join(SPEC.file);
        let seq_field = MAGIC_LEN + 2 + 2 + NONCE_LEN;
        let part_field = seq_field + 2 + 8;
        for offset in [
            MAGIC_LEN,
            MAGIC_LEN + 2,
            MAGIC_LEN + 4,
            seq_field + 2,
            part_field + 2,
        ] {
            tenant.store(b"good").await.unwrap();
            let mut bytes = read(&path).unwrap();
            bytes[offset] ^= 0x80;
            write(&path, bytes).unwrap();
            let verdict = tenant.load().await;
            assert!(
                matches!(verdict, Verdict::Discard(Discard::Corrupt { .. })),
                "offset {offset}: {verdict:?}",
            );
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
        drop(tenant);

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

    /// A stale write from a dropped store future cannot land on
    /// top of a newer committed record.
    #[tokio::test]
    async fn stragglers_cannot_clobber_newer_commits() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let tenant = locker(slots.clone()).tenant(SPEC);
        let paths = files(&slots);

        let newer = tenant.envelope(7, b"newer");
        let straggler = tenant.envelope(6, b"stale");
        commit(
            &test_log(),
            &tenant.committed,
            &tenant.slots,
            SPEC.file,
            7,
            &newer,
        )
        .unwrap();
        assert!(matches!(
            commit(
                &test_log(),
                &tenant.committed,
                &tenant.slots,
                SPEC.file,
                6,
                &straggler
            ),
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

    const SLOT_VAR: &str = "SUSH_TEST_LOCK_SLOT";
    const ACQUIRED: i32 = 43;
    const REFUSED: i32 = 44;

    /// The child half of the cross-process lock tests: when the
    /// environment names a slot, try to claim it and exit. Both
    /// outcomes exit non-zero, so a stale test filter (exit zero)
    /// fails loudly rather than reading as a lock the child never
    /// took.
    fn maybe_child() {
        if let Ok(slot) = var(SLOT_VAR) {
            match Locker::new(&test_log(), baseboard(), vec![slot.into()]) {
                Ok(_) => exit(ACQUIRED),
                Err(_) => exit(REFUSED),
            }
        }
    }

    /// Re-execute this test binary as `test`, pointed at `slot`.
    fn reexec(test: &str, slot: &Utf8PathBuf) -> Option<i32> {
        Command::new(current_exe().unwrap())
            .args(["--exact", test])
            .env(SLOT_VAR, slot)
            .output()
            .unwrap()
            .status
            .code()
    }

    /// A locker in another process is locked out until this one and
    /// its tenants drop.
    #[test]
    fn second_process_is_locked_out() {
        maybe_child();
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let child = |slot| reexec("locker::test::second_process_is_locked_out", slot);

        let locker = locker(slots.clone());
        assert_eq!(child(&slots[0]), Some(REFUSED));

        let tenant = locker.tenant(SPEC);
        drop(locker);
        assert_eq!(child(&slots[0]), Some(REFUSED));

        drop(tenant);
        assert_eq!(child(&slots[0]), Some(ACQUIRED));
    }

    /// A store heals a slot directory wiped at runtime: the slots
    /// agree again, and the healed slot is locked against other
    /// processes.
    #[tokio::test]
    async fn wiped_slot_heals_and_stays_locked() {
        maybe_child();
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let child = |slot| reexec("locker::test::wiped_slot_heals_and_stays_locked", slot);

        let tenant = locker(slots.clone()).tenant(SPEC);
        tenant.store(b"before").await.unwrap();
        remove_dir_all(&slots[0]).unwrap();

        tenant.store(b"healed").await.unwrap();
        assert_eq!(
            read(slots[0].join(SPEC.file)).unwrap(),
            read(slots[1].join(SPEC.file)).unwrap(),
        );
        assert!(matches!(
            tenant.load().await,
            Verdict::Adopt(record) if record == b"healed"
        ));
        assert_eq!(child(&slots[0]), Some(REFUSED));

        drop(tenant);
        assert_eq!(child(&slots[0]), Some(ACQUIRED));
    }

    /// A record written by another sled discards. A lone one is not
    /// restored onto the missing slot either.
    #[tokio::test]
    async fn foreign_records_discard() {
        let dir = TempDir::with_prefix("sush-locker-").unwrap();
        let slots = slots(&dir);
        let donor = BaseboardId {
            part_number: "913".to_string(),
            serial_number: "donor".to_string(),
        };
        let tenant = Locker::new(&test_log(), donor.clone(), slots.clone())
            .unwrap()
            .tenant(SPEC);
        tenant.store(b"someone else's").await.unwrap();
        drop(tenant);

        let tenant = locker(slots.clone()).tenant(SPEC);
        assert!(matches!(
            tenant.load().await,
            Verdict::Discard(Discard::Foreign { baseboard, .. }) if baseboard == donor
        ));
        drop(tenant);

        remove(slots[0].join(SPEC.file)).unwrap();
        let tenant = locker(slots).tenant(SPEC);
        assert!(matches!(
            tenant.load().await,
            Verdict::Discard(Discard::Foreign { .. })
        ));
    }

    /// Version 1 envelope bytes, pinned; see [`crate::format`]
    /// before changing them.
    #[test]
    fn pin_envelope_format_v1() {
        const PINNED: [u8; 109] = [
            0x53, 0x55, 0x53, 0x48, 0x4c, 0x4f, 0x43, 0x4b, 0x54, 0x45, 0x53, 0x54, 0x00, 0x01,
            0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x07, 0x00, 0x03, 0x39, 0x31, 0x33, 0x00, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
            0x20, 0xc6, 0xbe, 0x19, 0x2f, 0xbf, 0x89, 0x66, 0x72, 0xf3, 0xde, 0xab, 0x73, 0xb5,
            0xe0, 0xa0, 0x11, 0x58, 0xeb, 0x27, 0x7a, 0x52, 0x15, 0x6b, 0xba, 0x1d, 0x0d, 0xb5,
            0x0f, 0x42, 0x9b, 0x54, 0x04, 0x70, 0x69, 0x6e, 0x6e, 0x65, 0x64,
        ];
        let mut nonce = [0u8; NONCE_LEN];
        nonce[24..].fill(0x42);
        let encoded = Envelope::encode(
            SPEC.magic,
            &Nonce::from_be_bytes(nonce),
            7,
            &baseboard(),
            b"pinned",
        );
        assert_eq!(encoded, PINNED.as_slice());

        let decoded = Envelope::decode(SPEC.magic, &PINNED).unwrap();
        assert_eq!(decoded.baseboard, baseboard());
        assert_eq!(decoded.seq, 7);
        assert_eq!(decoded.record, b"pinned");
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
