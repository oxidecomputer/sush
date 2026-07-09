//! Abstract job output directories.
//!
//! We use a trivial hierarchy: `{base}/jobs/{job_id}`.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::PathBuf;
use std::{fs::File, io};

use blake3::Hasher;
use bytesize::ByteSize;
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};

use sush_common::jobs::{ExecutionError, JobId, JobOutputHash, JobOutputStream};
use tokio::task::spawn_blocking;

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

    fn job_output_len(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
    ) -> Result<u64, ExecutionError> {
        let path = self.job_output_path(job_id, stream);
        match path.metadata().map(|m| m.len()) {
            Ok(len) => Ok(len),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(err) => Err(ExecutionError::io(
                job_id.clone(),
                format!("getting length of {}", path.display()),
                err,
            )),
        }
    }

    fn job_output_hash(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
    ) -> Result<JobOutputHash, ExecutionError> {
        let mut hasher = Hasher::new();
        let path = self.job_output_path(job_id, stream);
        match hasher.update_mmap_rayon(&path) {
            Ok(_) => (),
            Err(err) if err.kind() == io::ErrorKind::NotFound => (),
            Err(err) => {
                return Err(ExecutionError::io(
                    job_id.clone(),
                    format!("getting length of {}", path.display()),
                    err,
                ));
            }
        }
        Ok(hasher.finalize().into())
    }

    pub async fn job_output(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        let out = self.clone();
        let job_id = job_id.to_owned();
        spawn_blocking(move || {
            let len = out.job_output_len(&job_id, stream)?;
            let path = out.job_output_path(&job_id, stream);
            let io_error = JobError::file_io_for(&path);
            let mut file = match File::open(&path) {
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
                    file.seek(SeekFrom::Start(start)).map_err(&io_error)?
                } else {
                    return Err(JobError::InvalidRange(len));
                };
                let n = match end {
                    EndPosition::Index(end) => end - start + 1,
                    EndPosition::LastByte => len - start + 1,
                };
                if n > len.min(OUTPUT_THRESHOLD) {
                    Err(JobError::InvalidRange(len))
                } else if n == 0 {
                    Ok(vec![])
                } else {
                    let mut buf = vec![0; n as usize];
                    file.read_exact(&mut buf).map_err(&io_error)?;
                    Ok(buf)
                }
            } else if len > OUTPUT_THRESHOLD {
                Err(JobError::OutputTooBig)
            } else {
                let mut buf = Vec::with_capacity(len as usize);
                file.read_to_end(&mut buf).map_err(&io_error)?;
                Ok(buf)
            }
        })
        .await?
    }

    pub fn job_output_state(&self, job_id: &JobId) -> Result<JobOutputState, ExecutionError> {
        use JobOutputStream::*;
        Ok(JobOutputState {
            stdout_len: self.job_output_len(job_id, Stdout)?,
            stderr_len: self.job_output_len(job_id, Stderr)?,
            stdout_hash: self.job_output_hash(job_id, Stdout)?,
            stderr_hash: self.job_output_hash(job_id, Stderr)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct JobOutputState {
    pub stdout_len: u64,
    pub stderr_len: u64,
    pub stdout_hash: JobOutputHash,
    pub stderr_hash: JobOutputHash,
}
