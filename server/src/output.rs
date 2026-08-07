// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Abstract job output directories.
//!
//! We use a trivial hierarchy: `{base}/jobs/{job_id}`. The base may move over
//! the life of a server; see [`OutputDirs`].

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytesize::ByteSize;
use futures::Stream;
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use tokio::fs::{File, metadata};
use tokio::io;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, SeekFrom, Take};
use tokio::sync::{Semaphore, SemaphorePermit, watch};
use tokio_util::io::ReaderStream;

use sush_common::jobs::{ExecutionError, JobId, JobLimits, JobOutputStream};

use crate::JobError;

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = ByteSize::mb(128).as_u64();

/// Maximum number of superseded output directories we keep around to read from.
const MAX_PREVIOUS_DIRS: usize = 4;

/// Limit concurrent output requests.
const MAX_OUTPUT_PERMITS: usize = 100;
static OUTPUT_PERMITS: Semaphore = Semaphore::const_new(MAX_OUTPUT_PERMITS);

/// Stream a chunk of output file.
#[derive(Debug)]
pub struct JobOutputFileStream {
    stream: ReaderStream<Take<File>>,
    length: u64,
    _permit: SemaphorePermit<'static>,
}

impl JobOutputFileStream {
    const BUFFER_SIZE: usize = 0x4000;

    fn new(file: File, length: u64, permit: SemaphorePermit<'static>) -> Self {
        Self {
            stream: ReaderStream::with_capacity(file.take(length), Self::BUFFER_SIZE),
            length,
            _permit: permit,
        }
    }

    pub fn length(&self) -> u64 {
        self.length
    }
}

impl Stream for JobOutputFileStream {
    type Item = <ReaderStream<Take<File>> as Stream>::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().stream).poll_next(cx)
    }
}

/// Where job output is written, and how much of it we will record.
///
/// New jobs are written under [`current`](Self::current). `previous` holds
/// bases this server wrote to earlier in its life, retained so that output
/// recorded before a move stays readable. `max_fsize` is the ceiling on
/// per-job output size while `current` is in force; it belongs here because
/// it is a property of the filesystem being written to, not of the job.
///
/// The sled-agent embedding needs all of these to change at runtime: it starts
/// out writing to a ramdisk, where a large limit would be charged to global
/// zone memory, and moves to an encrypted dataset with a larger limit once one
/// is mounted (which is to say, once trust quorum has been established).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputDirs {
    current: PathBuf,
    previous: Vec<PathBuf>,
    max_fsize: u64,
}

impl OutputDirs {
    pub fn new(current: impl Into<PathBuf>, max_fsize: u64) -> Self {
        Self {
            current: current.into(),
            previous: Vec::new(),
            max_fsize,
        }
    }

    /// The base that new jobs are written under.
    pub fn current(&self) -> &Path {
        &self.current
    }

    /// The ceiling on per-job output size under [`current`](Self::current).
    pub fn max_fsize(&self) -> u64 {
        self.max_fsize
    }

    /// Move to a new base, retaining this one to read old output from.
    pub fn moved_to(&self, current: impl Into<PathBuf>, max_fsize: u64) -> Self {
        let current = current.into();
        let mut previous = Vec::with_capacity(self.previous.len() + 1);
        if current != self.current {
            previous.push(self.current.clone());
        }
        previous.extend(self.previous.iter().filter(|dir| **dir != current).cloned());
        previous.truncate(MAX_PREVIOUS_DIRS);
        Self {
            current,
            previous,
            max_fsize,
        }
    }

    /// Every base we may have written output to, most recent first.
    pub fn bases(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.current.as_path()).chain(self.previous.iter().map(PathBuf::as_path))
    }

    pub fn job_output_dir(&self, job_id: &JobId) -> PathBuf {
        job_output_dir_in(&self.current, job_id)
    }

    pub fn job_output_path(&self, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
        self.job_output_dir(job_id).join(stream.as_str())
    }
}

fn job_output_dir_in(base: &Path, job_id: &JobId) -> PathBuf {
    base.join("jobs").join(job_id.to_string())
}

#[derive(Clone, Debug)]
pub struct JobOutputDir(watch::Receiver<OutputDirs>);

impl JobOutputDir {
    /// Follow a set of output directories that may move at runtime.
    pub fn new(dirs: watch::Receiver<OutputDirs>) -> Self {
        Self(dirs)
    }

    /// A base that never moves, with the default output size limit: for the
    /// standalone server, which has one directory for its whole life.
    pub fn fixed(dir: impl Into<PathBuf>) -> Self {
        // A receiver keeps serving the last value after its sender is dropped,
        // and we only ever read, so there is nothing to keep alive here.
        let (_tx, rx) = watch::channel(OutputDirs::new(dir, JobLimits::default().max_fsize));
        Self(rx)
    }

    /// Snapshot the directories in force right now. Callers that derive more
    /// than one path for a job must do it through a single snapshot, so that
    /// a move can't leave a job's files split across two bases.
    pub fn current(&self) -> OutputDirs {
        self.0.borrow().clone()
    }

    pub fn root(&self) -> PathBuf {
        self.0.borrow().current.clone()
    }

    pub fn job_output_dir(&self, job_id: &JobId) -> PathBuf {
        self.0.borrow().job_output_dir(job_id)
    }

    pub fn job_output_path(&self, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
        self.0.borrow().job_output_path(job_id, stream)
    }

    /// The path recording this job's `stream`, which may be under a base we
    /// have since moved away from. Falls back to the current base, so that
    /// there is always a path to name in an error.
    async fn find_job_output(&self, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
        let dirs = self.current();
        for base in dirs.bases() {
            let path = job_output_dir_in(base, job_id).join(stream.as_str());
            match metadata(&path).await {
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                _ => return path,
            }
        }
        dirs.job_output_path(job_id, stream)
    }

    async fn job_output_len(job_id: &JobId, path: &Path) -> Result<u64, ExecutionError> {
        match metadata(path).await.map(|m| m.len()) {
            Ok(len) => Ok(len),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(err) => Err(ExecutionError::io(
                job_id.clone(),
                format!("getting length of {}", path.display()),
                err,
            )),
        }
    }

    pub async fn job_output(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<JobOutputFileStream, JobError> {
        let Ok(permit) = OUTPUT_PERMITS.try_acquire() else {
            return Err(JobError::TooManyOutputRequests(MAX_OUTPUT_PERMITS));
        };

        let job_id = job_id.to_owned();
        let path = self.find_job_output(&job_id, stream).await;
        let len = Self::job_output_len(&job_id, &path).await?;
        let io_error = JobError::file_io_for(&path);
        let mut file = match File::open(&path).await {
            Ok(file) => file,
            Err(err) if len == 0 && err.kind() == io::ErrorKind::NotFound => {
                return Err(JobError::OutputFileMissing(job_id.to_owned()));
            }
            Err(err) => return Err(JobError::file_io_for(&path)(err)),
        };
        if let Some(Range { start, end }) = range {
            // HTTP Ranges include both their endpoints.
            let start = if let StartPosition::Index(start) = start
                && start < len
            {
                file.seek(SeekFrom::Start(start)).await.map_err(&io_error)?
            } else {
                return Err(JobError::InvalidRange(len));
            };
            let n = match end {
                EndPosition::Index(end) if end < len && end >= start => end - start + 1,
                EndPosition::LastByte => len - start,
                _ => return Err(JobError::InvalidRange(len)),
            };
            if n > len.min(OUTPUT_THRESHOLD) {
                return Err(JobError::InvalidRange(len));
            }
            Ok(JobOutputFileStream::new(file, n, permit))
        } else if len > OUTPUT_THRESHOLD {
            Err(JobError::OutputTooBig)
        } else {
            Ok(JobOutputFileStream::new(file, len, permit))
        }
    }
}
