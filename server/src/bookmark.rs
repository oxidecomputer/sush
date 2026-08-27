// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Durable gossip peer identity across restarts.
//!
//! A rumors [`Bookmark`] records who a peer is and how far it has
//! advanced, so a restarted sled reclaims its old identity instead of
//! stranding it. Rumors owns the record format and decides when to load
//! and store. We supply raw byte storage obeying two constraints: stores
//! are atomic, and a load never returns a record older than the newest
//! store we reported `Ok` (stale records corrupt causality, whereas
//! lost records merely strand identities).
//!
//! Storage is one small file per configured (M.2) slot. Loads read every
//! slot, and take the record with the highest sequence number; that slot
//! becomes the *home*. Stores go only to the home, since writing both
//! would either make the server dependent on the health of both or, done
//! merely best-effort, let a stale record load after a fresher disk dies,
//! violating the constraint above. The slots must never both be written
//! by live peers, and a record must never be restored from a backup.
//! A [`BookmarkSource`] hands out one handle per peer, with generation
//! numbers ensuring that a straggler from an abandoned universe can't
//! clobber its successor's record.

use std::fs::Permissions;
use std::io::{self, Cursor, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use atomicwrites::{AtomicFile, OverwriteBehavior};
use camino::{Utf8Path, Utf8PathBuf};
use rumors::{Bookmark, BookmarkError, Serialized};
use slog::{Logger, o, warn};
use thiserror::Error;
use tokio::fs::read;
use tokio::io::AsyncWrite;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

/// The envelope magic. The payload includes its own magic.
/// A change to our envelope means a new magic.
const MAGIC: &[u8; 8] = b"SUSHBKMK";

/// What a bookmark load or store failed at.
#[derive(Debug, Error)]
pub enum BookmarkIoError {
    #[error("bookmark I/O failed on `{path}`: {error}")]
    Io {
        path: Utf8PathBuf,
        #[source]
        error: io::Error,
    },
    #[error("every bookmark slot is corrupt (last: `{path}`)")]
    Corrupt { path: Utf8PathBuf },
    #[error("serializing the bookmark record failed: {0}")]
    Serialize(#[source] io::Error),
    #[error("no bookmark slot is writable")]
    NoSlot,
    #[error("the bookmark was handed to a newer peer")]
    Fenced,
}

/// This server's bookmark storage. Hands out one fenced handle per
/// peer.
#[derive(Clone, Debug)]
pub struct BookmarkSource {
    shared: Arc<SharedStore>,
}

#[derive(Debug)]
struct SharedStore {
    log: Logger,
    /// Candidate record files, one per boot M.2. Empty means this
    /// server persists no identity (the standalone server, tests).
    slots: Vec<Utf8PathBuf>,
    /// The newest generation. A handle from an older one may load
    /// but not store.
    generation: AtomicU64,
    /// Serializes loads and stores across handles, so the newest
    /// record on disk is always the newest store anyone `Ok`'d.
    state: Mutex<StoreState>,
}

#[derive(Debug, Default)]
struct StoreState {
    /// The slot holding the newest record, once known.
    home: Option<usize>,
    /// The sequence number of the newest record.
    seq: u64,
}

impl BookmarkSource {
    /// A source persisting to `slots`, each on its own device.
    pub fn new(log: &Logger, slots: Vec<Utf8PathBuf>) -> Self {
        Self {
            shared: Arc::new(SharedStore {
                log: log.new(o!("component" => "bookmark")),
                slots,
                generation: AtomicU64::new(0),
                state: Mutex::new(StoreState::default()),
            }),
        }
    }

    /// A source that loads and persists nothing.
    pub fn null() -> Self {
        Self::new(&Logger::root(slog::Discard, o!()), Vec::new())
    }

    /// A ratcheting handle for the next peer.
    /// All earlier handles are superseded.
    pub fn next_handle(&self) -> SushBookmark {
        let generation = self.shared.generation.fetch_add(1, Ordering::SeqCst) + 1;
        SushBookmark {
            shared: self.shared.clone(),
            generation,
            shed: false,
        }
    }

    /// A handle that never touches storage, for a peer that must keep
    /// gossiping after its real bookmark failed.
    pub fn shed_handle(&self) -> SushBookmark {
        SushBookmark {
            shared: self.shared.clone(),
            generation: 0,
            shed: true,
        }
    }

    /// A probing handle: reads like a real one, but without incrementing
    /// the generation.
    fn probe_handle(&self) -> SushBookmark {
        SushBookmark {
            shared: self.shared.clone(),
            generation: 0,
            shed: false,
        }
    }

    /// Does the storage look reasonable?
    pub async fn probe(&self) -> Result<(), BookmarkIoError> {
        if self.shared.slots.is_empty() {
            return Ok(());
        }
        let usable = match self.probe_handle().load().await {
            Ok(_) => {
                if self.shared.slots.iter().any(|path| {
                    path.parent()
                        .is_some_and(|parent| parent.as_std_path().is_dir())
                }) {
                    Ok(())
                } else {
                    Err(BookmarkIoError::NoSlot)
                }
            }
            Err(error) => Err(error),
        };
        if let Err(error) = &usable {
            warn!(self.shared.log, "no usable bookmark storage"; "error" => %error);
        }
        usable
    }
}

/// One peer's handle on the [`BookmarkSource`].
#[derive(Debug)]
pub struct SushBookmark {
    shared: Arc<SharedStore>,
    generation: u64,
    shed: bool,
}

impl SushBookmark {
    /// Has this bookmark been overtaken by events?
    fn obe(&self) -> bool {
        self.generation < self.shared.generation.load(Ordering::SeqCst)
    }

    /// Split an envelope into its sequence number and record.
    fn parse(bytes: &[u8]) -> Option<(u64, Vec<u8>)> {
        let payload = bytes.strip_prefix(MAGIC)?;
        let (seq, record) = payload.split_first_chunk::<8>()?;
        Some((u64::from_be_bytes(*seq), record.to_vec()))
    }
}

impl BookmarkError for SushBookmark {
    type Error = BookmarkIoError;
}

impl Bookmark for SushBookmark {
    type Reader = Cursor<Vec<u8>>;

    async fn load(&self) -> Result<Option<Self::Reader>, Self::Error> {
        if self.shed || self.shared.slots.is_empty() {
            return Ok(None);
        }
        let mut state = self.shared.state.lock().await;
        let mut newest: Option<(u64, usize, Vec<u8>)> = None;
        let mut corrupt: Option<&Utf8Path> = None;
        for (index, path) in self.shared.slots.iter().enumerate() {
            let bytes = match read(path).await {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(BookmarkIoError::Io {
                        path: path.clone(),
                        error,
                    });
                }
            };
            match Self::parse(&bytes) {
                Some((seq, record)) => {
                    if newest.as_ref().is_none_or(|(newest, ..)| seq > *newest) {
                        newest = Some((seq, index, record));
                    }
                }
                None => {
                    warn!(
                        self.shared.log, "skipping corrupt bookmark slot";
                        "path" => %path,
                    );
                    corrupt = Some(path);
                }
            }
        }
        match newest {
            Some((seq, home, record)) => {
                state.home = Some(home);
                state.seq = seq;
                Ok(Some(Cursor::new(record)))
            }
            // A present-but-unreadable record is an error:
            // rumors must not mistake it for a fresh start.
            None => match corrupt {
                Some(path) => Err(BookmarkIoError::Corrupt { path: path.into() }),
                None => Ok(None),
            },
        }
    }

    async fn store<F>(&self, write: F) -> Result<(), Self::Error>
    where
        F: for<'a> FnOnce(&'a mut (dyn AsyncWrite + Unpin + Send)) -> Serialized<'a> + Send,
    {
        if self.shed || self.shared.slots.is_empty() {
            return Ok(());
        }

        let mut buf = Cursor::new(Vec::new());
        write(&mut buf).await.map_err(BookmarkIoError::Serialize)?;
        let record = buf.into_inner();

        let mut state = self.shared.state.lock().await;
        if self.obe() {
            return Err(BookmarkIoError::Fenced);
        }
        let home = match state.home {
            Some(home) => home,
            None => self
                .shared
                .slots
                .iter()
                .position(|path| {
                    path.parent()
                        .is_some_and(|parent| parent.as_std_path().is_dir())
                })
                .ok_or(BookmarkIoError::NoSlot)?,
        };
        let path = self.shared.slots[home].clone();

        // Reserve the sequence number first: a cancelled write may
        // still land and must be outnumbered.
        state.seq += 1;
        let mut envelope = Vec::with_capacity(MAGIC.len() + 8 + record.len());
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&state.seq.to_be_bytes());
        envelope.extend_from_slice(&record);

        let target = path.clone();
        let written = spawn_blocking(move || {
            AtomicFile::new(target, OverwriteBehavior::AllowOverwrite)
                .write(|file| {
                    file.set_permissions(Permissions::from_mode(0o600))?;
                    file.write_all(&envelope)
                })
                .map_err(|error| match error {
                    atomicwrites::Error::Internal(error) | atomicwrites::Error::User(error) => {
                        error
                    }
                })
        })
        .await
        .map_err(|join| io::Error::other(join.to_string()))
        .and_then(|result| result);

        match written {
            Ok(()) => {
                state.home = Some(home);
                Ok(())
            }
            Err(error) => Err(BookmarkIoError::Io { path, error }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs::{create_dir, metadata, read, write};

    use camino::Utf8PathBuf;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A serializer closure writing fixed bytes, shaped like rumors'.
    fn record(
        bytes: &'static [u8],
    ) -> impl for<'a> FnOnce(&'a mut (dyn AsyncWrite + Unpin + Send)) -> Serialized<'a> + Send {
        move |w| Box::pin(async move { w.write_all(bytes).await })
    }

    /// Two slot paths in separate directories, like two M.2s.
    fn slots(dir: &TempDir) -> Vec<Utf8PathBuf> {
        ["m2a", "m2b"]
            .iter()
            .map(|m2| {
                let parent = Utf8PathBuf::from_path_buf(dir.path().join(m2)).unwrap();
                create_dir(&parent).unwrap();
                parent.join("bookmark")
            })
            .collect()
    }

    fn envelope(seq: u64, record: &[u8]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(record);
        bytes
    }

    async fn read_back(handle: &SushBookmark) -> Option<Vec<u8>> {
        let mut reader = handle.load().await.unwrap()?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        Some(bytes)
    }

    fn test_log() -> Logger {
        Logger::root(slog::Discard, o!())
    }

    /// A stored record loads back verbatim, sequenced and private.
    #[tokio::test]
    async fn round_trip() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let slots = slots(&dir);
        let source = BookmarkSource::new(&test_log(), slots.clone());

        let handle = source.next_handle();
        assert!(read_back(&handle).await.is_none());
        handle.store(record(b"who we are")).await.unwrap();
        assert_eq!(read_back(&handle).await.unwrap(), b"who we are");

        let bytes = read(&slots[0]).unwrap();
        assert_eq!(bytes, envelope(1, b"who we are"));
        let mode = metadata(&slots[0]).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// The newest record wins the load regardless of slot, and its
    /// slot becomes the home every store then writes.
    #[tokio::test]
    async fn newest_slot_is_home() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let slots = slots(&dir);
        write(&slots[0], envelope(5, b"stale")).unwrap();
        write(&slots[1], envelope(9, b"fresh")).unwrap();

        let source = BookmarkSource::new(&test_log(), slots.clone());
        let handle = source.next_handle();
        assert_eq!(read_back(&handle).await.unwrap(), b"fresh");

        handle.store(record(b"fresher")).await.unwrap();
        assert_eq!(read(&slots[0]).unwrap(), envelope(5, b"stale"));
        assert_eq!(read(&slots[1]).unwrap(), envelope(10, b"fresher"));
    }

    /// Minting a new handle fences the old one's stores.
    #[tokio::test]
    async fn stale_generations_cannot_store() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let source = BookmarkSource::new(&test_log(), slots(&dir));

        let old = source.next_handle();
        old.store(record(b"before")).await.unwrap();
        let new = source.next_handle();
        assert!(matches!(
            old.store(record(b"after")).await,
            Err(BookmarkIoError::Fenced)
        ));
        assert_eq!(read_back(&new).await.unwrap(), b"before");
    }

    /// A corrupt slot is skipped when another is valid, and is an
    /// error rather than absence when nothing valid remains.
    #[tokio::test]
    async fn corruption_is_never_absence() {
        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let slots = slots(&dir);
        write(&slots[0], b"scribble").unwrap();
        write(&slots[1], envelope(3, b"good")).unwrap();

        let source = BookmarkSource::new(&test_log(), slots.clone());
        assert_eq!(read_back(&source.next_handle()).await.unwrap(), b"good");

        write(&slots[1], b"more scribble").unwrap();
        assert!(matches!(
            source.next_handle().load().await,
            Err(BookmarkIoError::Corrupt { .. })
        ));
    }

    /// A slotless source and a shed handle persist nothing and never
    /// fail, and a shed handle ignores even an existing record.
    #[tokio::test]
    async fn none_and_shed_touch_nothing() {
        let source = BookmarkSource::null();
        let handle = source.next_handle();
        assert!(read_back(&handle).await.is_none());
        handle.store(record(b"lost")).await.unwrap();
        assert!(read_back(&handle).await.is_none());

        let dir = TempDir::with_prefix("sush-bookmark-").unwrap();
        let slots = slots(&dir);
        write(&slots[0], envelope(7, b"kept")).unwrap();
        let source = BookmarkSource::new(&test_log(), slots.clone());
        let shed = source.shed_handle();
        assert!(read_back(&shed).await.is_none());
        shed.store(record(b"dropped")).await.unwrap();
        assert_eq!(read(&slots[0]).unwrap(), envelope(7, b"kept"));
    }
}
