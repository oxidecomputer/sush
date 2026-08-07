//! Abstract job output directories.
//!
//! We use a trivial hierarchy: `{base}/jobs/{job_id}`.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use bytesize::ByteSize;
use futures::{Stream, TryStreamExt as _};
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use tokio::fs::{File, metadata};
use tokio::io;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, SeekFrom, Take};
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio_util::io::ReaderStream;

use sush_common::jobs::{ExecutionError, JobId, JobOutputStream};

use crate::JobError;

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = ByteSize::mb(128).as_u64();

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

    #[cfg(feature = "test-support")]
    pub async fn into_bytes(self) -> Vec<u8> {
        self.stream
            .try_collect::<Vec<Bytes>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect()
    }
}

impl Stream for JobOutputFileStream {
    type Item = <ReaderStream<Take<File>> as Stream>::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().stream).poll_next(cx)
    }
}

#[derive(Clone, Debug)]
pub struct JobOutputDir(PathBuf);

impl JobOutputDir {
    pub fn new(output_dir: PathBuf) -> Self {
        Self(output_dir)
    }

    pub fn root(&self) -> &Path {
        &self.0
    }

    pub fn job_output_dir(&self, job_id: &JobId) -> PathBuf {
        self.0.join("jobs").join(job_id.to_string())
    }

    pub fn job_output_path(&self, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
        self.job_output_dir(job_id).join(stream.as_str())
    }

    async fn job_output_len(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
    ) -> Result<u64, ExecutionError> {
        let path = self.job_output_path(job_id, stream);
        match metadata(&path).await.map(|m| m.len()) {
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
        let len = self.job_output_len(&job_id, stream).await?;
        let path = self.job_output_path(&job_id, stream);
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
