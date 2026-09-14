// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Store Rumors restart bookkeeping in this server's locker.
//!
//! Rumors supplies an opaque record that lets it reclaim a departed peer's
//! identity after catching up. The locker stores the record across local disks
//! and rejects stale or conflicting copies. An unusable record starts fresh
//! bookkeeping; it must never cause us to reuse an uncertain identity.

use std::io::Cursor;
use std::sync::Arc;

use rumors::Bookmark;
use slog::{Discard, Logger, o, warn};

use crate::format::{self, NoFormat, Record, Versioned};
use crate::locker::{Locker, StoreError, Tenant, TenantSpec, Verdict};

/// Locker namespace and format marker for Rumors bookmark records.
pub const BOOKMARK: TenantSpec = TenantSpec {
    file: "bookmark",
    magic: b"SUSHBOOKMARK",
};

/// Wrap the opaque bytes rumors writes.
#[derive(serde::Deserialize, serde::Serialize)]
struct BookmarkRecord(#[serde(with = "format::cbor_bytes")] Vec<u8>);

/// Identify the outer Sush record format.
impl Versioned for BookmarkRecord {
    /// Version of this wrapper, independent of Rumors’ opaque payload format.
    const VERSION: u16 = 0;
}

/// This wrapper has no older representation to migrate.
impl Record for BookmarkRecord {
    /// No prior wrapper format exists.
    type Previous = NoFormat;
}

/// Complete the migration interface for a format with no predecessor.
impl TryFrom<NoFormat> for BookmarkRecord {
    /// Required by the migration interface; this conversion cannot fail.
    type Error = &'static str;
    /// No value of the source type exists.
    fn try_from(none: NoFormat) -> Result<Self, Self::Error> {
        match none {}
    }
}

/// This server's bookmark storage. Every handle shares the one record.
#[derive(Clone, Debug)]
pub struct BookmarkSource {
    /// Logger carrying this bookmark’s component context.
    log: Logger,
    /// Shared locker record for this server across peer replacements.
    tenant: Arc<Tenant>,
}

/// Create storage handles for the gossip manager.
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

    /// A persisting handle for one peer. Before replacing it during migration,
    /// the gossip manager waits for all sessions using the old handle to stop.
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
    /// Logger carrying this bookmark’s component context.
    log: Logger,
    /// Shared locker record for this server across peer replacements.
    tenant: Arc<Tenant>,
    /// Whether this handle bypasses storage after a persistence failure.
    shed: bool,
}

/// Read locker records and store the complete bytes supplied by Rumors.
impl Bookmark for SushBookmark {
    /// Failure to durably store the locker record.
    type Error = StoreError;
    /// An owned snapshot of the stored Rumors record.
    type Reader = Cursor<Vec<u8>>;

    /// Load a usable record, starting fresh if locker recovery rejects it.
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

    /// Store the encoded Rumors record unless this handle has shed persistence.
    async fn store(&self, bytes: Vec<u8>) -> Result<(), Self::Error> {
        if self.shed {
            return Ok(());
        }
        let record = BookmarkRecord(bytes);
        let mut guard = self.tenant.lock().await;
        guard.store(&format::encode(&record)).await
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs::create_dir;

    use camino::Utf8PathBuf;
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt as _;

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

    /// Silence routine logging in storage tests.
    fn test_log() -> Logger {
        Logger::root(Discard, o!())
    }

    /// Create a bookmark source backed by the requested disk slots.
    fn source(slots: Vec<Utf8PathBuf>) -> BookmarkSource {
        BookmarkSource::new(&test_log(), &Locker::new(&test_log(), slots).unwrap())
    }

    /// Read the exact bytes visible through the public Bookmark interface.
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
        handle.store(b"who we are".to_vec()).await.unwrap();
        assert_eq!(read_back(&handle).await.unwrap(), b"who we are");
    }

    /// A discarded verdict is a fresh start, not an error.
    #[tokio::test]
    async fn discard_assumes_fresh_identity() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let slots = slots(&dir);
        for (slot, bytes) in slots.iter().zip([b"one", b"two"]) {
            let lone = source(vec![slot.clone()]);
            lone.handle().store(bytes.to_vec()).await.unwrap();
        }
        assert!(read_back(&source(slots).handle()).await.is_none());
    }

    /// Handles share the record: one stores, another reads it back.
    #[tokio::test]
    async fn handles_share_record() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let source = source(slots(&dir));

        source.handle().store(b"shared".to_vec()).await.unwrap();
        assert_eq!(read_back(&source.handle()).await.unwrap(), b"shared");
    }

    /// A null source and a shed handle persist nothing and never fail,
    /// and a shed handle ignores even an existing record.
    #[tokio::test]
    async fn null_and_shed_touch_nothing() {
        let null = BookmarkSource::null();
        let handle = null.handle();
        handle.store(b"lost".to_vec()).await.unwrap();
        assert!(read_back(&handle).await.is_none());

        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let source = source(slots(&dir));
        source.handle().store(b"kept".to_vec()).await.unwrap();
        let shed = source.shed_handle();
        assert!(read_back(&shed).await.is_none());
        shed.store(b"dropped".to_vec()).await.unwrap();
        assert_eq!(read_back(&source.handle()).await.unwrap(), b"kept");
    }
}
