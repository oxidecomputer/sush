//! Abstract job output directories.
//!
//! We use a trivial hierarchy: `{base}/jobs/{job_id}`.

use std::path::PathBuf;

use bytesize::ByteSize;
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use tokio::fs::{File, metadata};
use tokio::io;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, SeekFrom};

use sush_common::jobs::{ExecutionError, JobId, JobOutputStream};

use crate::JobError;

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = ByteSize::mb(128).as_u64();

#[derive(Clone, Debug)]
pub struct JobOutputDir(PathBuf);

impl JobOutputDir {
    pub fn new(output_dir: PathBuf) -> Self {
        Self(output_dir)
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
    ) -> Result<Vec<u8>, JobError> {
        let job_id = job_id.to_owned();
        let len = self.job_output_len(&job_id, stream).await?;
        let path = self.job_output_path(&job_id, stream);
        let io_error = JobError::file_io_for(&path);
        let mut file = match File::open(&path).await {
            Ok(file) => file,
            Err(err) if len == 0 && err.kind() == io::ErrorKind::NotFound => {
                return Ok(Vec::new());
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
                Err(JobError::InvalidRange(len))
            } else if n == 0 {
                Ok(vec![])
            } else {
                let mut buf = vec![0; n as usize];
                file.read_exact(&mut buf).await.map_err(&io_error)?;
                Ok(buf)
            }
        } else if len > OUTPUT_THRESHOLD {
            Err(JobError::OutputTooBig)
        } else {
            let mut buf = Vec::with_capacity(len as usize);
            file.read_to_end(&mut buf).await.map_err(&io_error)?;
            Ok(buf)
        }
    }
}
