// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Durable gossip peer identity across restarts.
//!
//! A rumors [`Bookmark`] records a peer's identity and how far it has
//! advanced, so that a restarted sled may reclaim its previous identity
//! instead of stranding it. The invariant is (as usual) that we must
//! never adopt stale data, because in this case it could lead to causality
//! violations (which are bad).
//!
//! The record format and when to load & store are dictated by rumors.
//! We use a [`Tenant`] of a [`Locker`] to store it on disk(s);
//! if a load fails or the slots disagree, we assume a new identity
//! rather than risk resuming with a stale one. The record keeps every
//! universe's identities, so a lost write costs at most a stranded
//! identity, never a stale one.

use std::io::{self, Cursor};
use std::sync::Arc;

use rumors::{Bookmark, BookmarkError, Serialized};
use slog::{Discard, Logger, o, warn};
use thiserror::Error;
use tokio::io::AsyncWrite;

use crate::format::{self, NoFormat, Record, Versioned};
use crate::locker::{Locker, StoreError, Tenant, TenantSpec, Verdict};

pub const BOOKMARK: TenantSpec = TenantSpec {
    file: "sush-bookmark",
    magic: b"SUSHBOOKMARK",
};

/// Wrap the opaque bytes rumors writes.
#[derive(serde::Deserialize, serde::Serialize)]
struct BookmarkRecord(#[serde(with = "format::cbor_bytes")] Vec<u8>);

impl Versioned for BookmarkRecord {
    const VERSION: u16 = 0;
}

impl Record for BookmarkRecord {
    type Previous = NoFormat;
}

impl TryFrom<NoFormat> for BookmarkRecord {
    type Error = &'static str;
    fn try_from(none: NoFormat) -> Result<Self, Self::Error> {
        match none {}
    }
}

/// What a bookmark load or store failed at.
#[derive(Debug, Error)]
pub enum BookmarkIoError {
    #[error("serializing the bookmark record failed: {0}")]
    Serialize(#[source] io::Error),
    #[error("storing the bookmark failed: {0}")]
    Store(#[source] StoreError),
}

/// This server's bookmark storage. Every handle shares the one record.
#[derive(Clone, Debug)]
pub struct BookmarkSource {
    log: Logger,
    tenant: Arc<Tenant>,
}

impl BookmarkSource {
    /// A source persisting to `locker`.
    /// [`Seed::grow`](crate::gossip::Seed::grow) makes the one source
    /// a locker gets per process.
    pub fn new(log: &Logger, locker: &Locker) -> Self {
        Self {
            log: log.new(o!("component" => "bookmark")),
            tenant: Arc::new(locker.tenant(BOOKMARK)),
        }
    }

    /// A source that loads and persists nothing.
    pub fn null() -> Self {
        Self::new(&Logger::root(Discard, o!()), &Locker::null())
    }

    /// A persisting handle for a peer. Rumors persists a bookmark only
    /// when a gossip session starts, and the gossip manager stops
    /// every session before it hands a new peer its handle, so no two
    /// peers persist concurrently; see the migration notes in
    /// [`gossip`](crate::gossip).
    pub fn handle(&self) -> SushBookmark {
        SushBookmark {
            log: self.log.clone(),
            tenant: self.tenant.clone(),
            shed: false,
        }
    }

    /// A handle that never touches storage, for a peer that must keep
    /// gossiping after its real bookmark failed.
    pub fn shed_handle(&self) -> SushBookmark {
        SushBookmark {
            log: self.log.clone(),
            tenant: self.tenant.clone(),
            shed: true,
        }
    }
}

/// One peer's handle on the [`BookmarkSource`].
#[derive(Debug)]
pub struct SushBookmark {
    log: Logger,
    tenant: Arc<Tenant>,
    shed: bool,
}

impl BookmarkError for SushBookmark {
    type Error = BookmarkIoError;
}

impl Bookmark for SushBookmark {
    type Reader = Cursor<Vec<u8>>;

    async fn load(&self) -> Result<Option<Self::Reader>, Self::Error> {
        if self.shed {
            return Ok(None);
        }
        let mut guard = self.tenant.lock().await;
        match guard.load().await {
            Verdict::Adopt(record) | Verdict::Restore(record) => {
                match format::decode::<BookmarkRecord>(&record) {
                    Ok(BookmarkRecord(bytes)) => Ok(Some(Cursor::new(bytes))),
                    // Stranding the old identity is harmless;
                    // resuming from a misread record is not.
                    Err(error) => {
                        warn!(self.log, "assuming a fresh identity"; "reason" => %error);
                        Ok(None)
                    }
                }
            }
            Verdict::Empty => Ok(None),
            Verdict::Discard(reason) => {
                warn!(self.log, "assuming a fresh identity"; "reason" => %reason);
                Ok(None)
            }
        }
    }

    async fn store<F>(&self, write: F) -> Result<(), Self::Error>
    where
        F: for<'a> FnOnce(&'a mut (dyn AsyncWrite + Unpin + Send)) -> Serialized<'a> + Send,
    {
        if self.shed {
            return Ok(());
        }
        let mut buf = Cursor::new(Vec::new());
        write(&mut buf).await.map_err(BookmarkIoError::Serialize)?;
        let record = BookmarkRecord(buf.into_inner());

        let mut guard = self.tenant.lock().await;
        guard
            .store(&format::encode(&record))
            .await
            .map_err(BookmarkIoError::Store)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs::create_dir;

    use camino::Utf8PathBuf;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A serializer closure writing fixed bytes, shaped like rumors'.
    fn record(
        bytes: &'static [u8],
    ) -> impl for<'a> FnOnce(&'a mut (dyn AsyncWrite + Unpin + Send)) -> Serialized<'a> + Send {
        move |w| Box::pin(async move { w.write_all(bytes).await })
    }

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
        Logger::root(Discard, o!())
    }

    fn source(slots: Vec<Utf8PathBuf>) -> BookmarkSource {
        BookmarkSource::new(&test_log(), &Locker::new(&test_log(), slots))
    }

    async fn read_back(handle: &SushBookmark) -> Option<Vec<u8>> {
        let mut reader = handle.load().await.unwrap()?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        Some(bytes)
    }

    /// A stored record loads back verbatim.
    #[tokio::test]
    async fn round_trip() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let source = source(slots(&dir));

        let handle = source.handle();
        assert!(read_back(&handle).await.is_none());
        handle.store(record(b"who we are")).await.unwrap();
        assert_eq!(read_back(&handle).await.unwrap(), b"who we are");
    }

    /// A discarded verdict is a fresh start, not an error.
    #[tokio::test]
    async fn discard_assumes_fresh_identity() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let slots = slots(&dir);
        for (slot, bytes) in slots.iter().zip([b"one", b"two"]) {
            let lone = source(vec![slot.clone()]);
            lone.handle().store(record(bytes)).await.unwrap();
        }
        assert!(read_back(&source(slots).handle()).await.is_none());
    }

    /// Handles share the record: one stores, another reads it back.
    #[tokio::test]
    async fn handles_share_record() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let source = source(slots(&dir));

        source.handle().store(record(b"shared")).await.unwrap();
        assert_eq!(read_back(&source.handle()).await.unwrap(), b"shared");
    }

    /// A null source and a shed handle persist nothing and never fail,
    /// and a shed handle ignores even an existing record.
    #[tokio::test]
    async fn null_and_shed_touch_nothing() {
        let null = BookmarkSource::null();
        let handle = null.handle();
        handle.store(record(b"lost")).await.unwrap();
        assert!(read_back(&handle).await.is_none());

        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let source = source(slots(&dir));
        source.handle().store(record(b"kept")).await.unwrap();
        let shed = source.shed_handle();
        assert!(read_back(&shed).await.is_none());
        shed.store(record(b"dropped")).await.unwrap();
        assert_eq!(read_back(&source.handle()).await.unwrap(), b"kept");
    }
}
