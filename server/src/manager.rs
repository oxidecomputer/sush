//! Manage a set of jobs.
//!
//! The manager runs as an agent loop with exclusive access to the sole
//! database connection. It services requests and sends responses via
//! oneshot channels (included in the requests). Jobs are spawned onto
//! new tokio tasks, which the manager loop watches for completion.
//!
//! We store the standard output and error of all jobs as BLOBs in the
//! database. Because SQLite does not support resizing BLOBs via its
//! incremental I/O interface, we first collect them into anonymous
//! temporary files, then slurp them into BLOBs.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::io::Seek as _;
use std::ops::Range;
use std::process::{ExitStatus, Stdio};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use chrono::{DateTime, Utc};
use dropshot::{ClientErrorStatusCode, HttpError};
use rusqlite::{Connection, OptionalExtension as _, blob::ZeroBlob};
use tempfile::tempfile;
use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinError, JoinHandle, JoinSet, spawn};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};

use sush_common::blob::{BlobError, file_len, get_blob, read_blob_chunk, read_blob_from_file};
use sush_common::certs::{CertError, KeyId, ROOT_CERTS, Signature};
use sush_common::jobs::{JobId, JobStartRequest, JobStatus, JobsReserved, SignedJob, VerifiedJob};

#[derive(Debug, Error)]
pub enum JobError {
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error("Can't send job request: receiver dropped")]
    ChannelClosed,
    #[error("DER encoding error: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("Invalid command `{0}`")]
    InvalidCommand(String),
    #[error("Invalid or duplicate job ID")]
    InvalidJobId(JobId),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Can't find certificate for key `{}`", BASE64.encode(.0.as_slice()))]
    MissingCert(KeyId),
    #[error("Can't receive response: sender dropped")]
    Recv(#[from] oneshot::error::RecvError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("Unable to start job")]
    Start,
    #[error(transparent)]
    Task(#[from] JoinError),
    #[error("Unable to wait for job end")]
    Wait,
}

impl From<JobError> for HttpError {
    fn from(err: JobError) -> Self {
        HttpError::for_client_error(None, ClientErrorStatusCode::BAD_REQUEST, err.to_string())
    }
}

#[derive(Debug)]
pub struct JobStart {
    pub job: SignedJob,
    pub time_started: DateTime<Utc>,
    pub child: Child,
    pub stdout: File,
    pub stderr: File,
}

impl JobStart {
    /// Execute commands via a shell to allow pipelines, redirects, etc.
    pub fn new(job: SignedJob) -> Result<Self, JobError> {
        if job.command().starts_with('-') {
            return Err(JobError::InvalidCommand(job.command().to_owned()));
        }
        let stdout = tempfile()?;
        let stderr = tempfile()?;
        let time_started = Utc::now();
        let child = Command::new("bash")
            .arg("-c")
            .arg(job.command())
            .env("SUSH_JOB_ID", job.job_id.to_string())
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .kill_on_drop(true)
            .spawn()?;
        Ok(Self {
            job,
            time_started,
            child,
            stdout,
            stderr,
        })
    }

    pub fn job_id(&self) -> JobId {
        self.job.job_id()
    }

    pub async fn wait(mut self) -> Result<JobEnd, JobError> {
        let status = self.child.wait().await?;
        let time_ended = Utc::now();
        let Self {
            job,
            time_started,
            child: _,
            mut stdout,
            mut stderr,
        } = self;
        stdout.sync_all()?;
        stderr.sync_all()?;
        stdout.rewind()?;
        stderr.rewind()?;
        Ok(JobEnd {
            job,
            time_started,
            time_ended,
            status,
            stdout,
            stderr,
        })
    }
}

#[derive(Debug)]
pub struct JobEnd {
    pub job: SignedJob,
    pub time_started: DateTime<Utc>,
    pub time_ended: DateTime<Utc>,
    pub status: ExitStatus,
    pub stdout: File,
    pub stderr: File,
}

impl JobEnd {
    pub fn job_id(&self) -> JobId {
        self.job.job_id()
    }
}

#[derive(Debug)]
pub enum JobRequest {
    // Certificate requests.
    ImportCert {
        cert: Box<Certificate>,
        response: oneshot::Sender<Result<KeyId, JobError>>,
        /// **For tests only:** Override the usual refusal to import
        /// a self-signed (root) certficate via a request.
        #[cfg(test)]
        root: bool,
    },
    CertChain {
        key_id: KeyId,
        response: oneshot::Sender<Result<Vec<Certificate>, JobError>>,
    },

    // Job reservation requests.
    Reserve {
        number: u8,
        response: oneshot::Sender<Result<JobsReserved, JobError>>,
    },
    GetReserved {
        response: oneshot::Sender<Result<BTreeMap<JobId, DateTime<Utc>>, JobError>>,
    },
    RevokeReserved {
        job_ids: Vec<JobId>,
        response: oneshot::Sender<Result<Vec<JobId>, JobError>>,
    },

    // Job management requests.
    Start {
        request: Box<JobStart>,
        response: oneshot::Sender<Result<JobStatus, JobError>>,
    },
    Status {
        job_id: JobId,
        response: oneshot::Sender<Result<JobStatus, JobError>>,
    },
    Stdout {
        job_id: JobId,
        range: Option<Range<i32>>,
        response: oneshot::Sender<Result<Vec<u8>, JobError>>,
    },
    Stderr {
        job_id: JobId,
        range: Option<Range<i32>>,
        response: oneshot::Sender<Result<Vec<u8>, JobError>>,
    },
    Abort {
        job_id: JobId,
    },
}

#[derive(Debug)]
pub struct JobManager {
    channel: mpsc::Sender<JobRequest>,
    task: JoinHandle<Result<(), JobError>>,
}

impl JobManager {
    /// Spawn a task that processes job requests and monitors jobs for completion.
    pub async fn new(mut db: Connection) -> Result<Self, JobError> {
        // Import the root certificates.
        for root in ROOT_CERTS {
            let cert = Certificate::from_der(root)?;
            import_cert(&db, &cert, true)?;
        }

        // Accept and process job requests.
        let (tx, mut rx) = mpsc::channel::<JobRequest>(1);
        let task = spawn(async move {
            let mut tasks = JoinSet::<Result<JobEnd, JobError>>::new();
            let mut abort = BTreeMap::<JobId, AbortHandle>::new();
            loop {
                select! {
                    Some(end) = tasks.join_next() => {
                        // A job has finished.
                        // TODO: Revoke reservations on error.
                        // TODO: Ensure killed jobs are reaped.
                        match end {
                            Err(err) if err.is_cancelled() => (),
                            Err(err) => return Err(err.into()),
                            Ok(Err(_)) => continue,
                            Ok(Ok(end)) => {
                                assert!(abort.remove(&end.job_id()).is_some());
                                job_ended(
                                    &mut db,
                                    end.job_id(),
                                    end.status.code(),
                                    end.stdout,
                                    end.stderr,
                                    end.time_ended,
                                )?;
                            }
                        }
                    }

                    request = rx.recv() => {
                        // Process the next request.
                        match request {
                            None => return Ok(()),
                            Some(JobRequest::ImportCert {
                                cert,
                                #[cfg(test)]
                                root,
                                response,
                            }) => {
                                #[cfg(not(test))]
                                let root = false;
                                let _ = response.send(import_cert(&db, &cert, root));
                            }
                            Some(JobRequest::CertChain { key_id, response }) => {
                                let _ = response.send(get_cert_chain(&db, key_id));
                            }
                            Some(JobRequest::Reserve { number, response }) => {
                                let _ = response.send(reserve_jobs(&mut db, number));
                            }
                            Some(JobRequest::GetReserved { response }) => {
                                let _ = response.send(get_reserved(&db));
                            }
                            Some(JobRequest::RevokeReserved { job_ids, response }) => {
                                let _ = response.send(revoke_reserved(&mut db, &job_ids));
                            }
                            Some(JobRequest::Start{ request: start, response }) => {
                                let job_id = start.job_id();
                                match start_job(&mut db, *start, response, &mut tasks) {
                                    Ok(handle) => assert!(abort.insert(job_id, handle).is_none()),
                                    Err(JobError::Start) => continue,
                                    Err(err) => return Err(err),
                                }
                            }
                            Some(JobRequest::Status { job_id, response }) => {
                                let _ = response.send(job_status(&db, job_id));
                            }
                            Some(JobRequest::Stdout { job_id, range, response }) => {
                                let _ = response.send(job_stdout(&db, job_id, range));
                            }
                            Some(JobRequest::Stderr { job_id, range, response }) => {
                                let _ = response.send(job_stderr(&db, job_id, range));
                            }
                            Some(JobRequest::Abort { job_id }) => {
                                if let Some(job) = abort.remove(&job_id) {
                                    job.abort();
                                    job_aborted(&db, job_id, Utc::now())?;
                                }
                            }
                        }
                    }
                }
            }
        });
        Ok(Self { channel: tx, task })
    }

    pub async fn wait(self) -> Result<(), JobError> {
        self.task.await?
    }

    async fn request(&self, request: JobRequest) -> Result<(), JobError> {
        self.channel
            .send(request)
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    pub async fn import_cert_bytes(&self, bytes: &[u8]) -> Result<KeyId, JobError> {
        self.import_cert(
            &Certificate::from_der(bytes)?,
            #[cfg(test)]
            false,
        )
        .await
    }

    async fn import_cert(
        &self,
        cert: &Certificate,
        #[cfg(test)] root: bool,
    ) -> Result<KeyId, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::ImportCert {
            cert: Box::new(cert.to_owned()),
            #[cfg(test)]
            root,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn cert_chain(&self, key_id: KeyId) -> Result<Vec<Certificate>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::CertChain {
            key_id,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn reserve_jobs(&self, number: u8) -> Result<JobsReserved, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Reserve {
            number,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn reserve_one(&self) -> Result<(JobId, DateTime<Utc>), JobError> {
        let JobsReserved {
            mut job_ids,
            time_reserved,
        } = self.reserve_jobs(1).await?;
        let n = job_ids.len();
        assert_eq!(n, 1, "requested one job, got {n}");
        Ok((job_ids.pop().unwrap(), time_reserved))
    }

    pub async fn get_reserved(&self) -> Result<BTreeMap<JobId, DateTime<Utc>>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::GetReserved { response: tx })
            .await?;
        rx.await?
    }

    pub async fn revoke_reserved(&self, job_ids: Vec<JobId>) -> Result<Vec<JobId>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::RevokeReserved {
            job_ids,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_start(
        &self,
        job: SignedJob,
    ) -> Result<oneshot::Receiver<Result<JobStatus, JobError>>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Start {
            request: Box::new(JobStart::new(job)?),
            response: tx,
        })
        .await?;
        Ok(rx)
    }

    pub async fn job_status(&self, job_id: JobId) -> Result<JobStatus, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Status {
            job_id,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_abort(&self, job_id: JobId) -> Result<(), JobError> {
        self.request(JobRequest::Abort { job_id }).await
    }

    pub async fn job_stdout(
        &self,
        job_id: JobId,
        range: Option<Range<i32>>,
    ) -> Result<Vec<u8>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Stdout {
            job_id,
            range,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_stderr(
        &self,
        job_id: JobId,
        range: Option<Range<i32>>,
    ) -> Result<Vec<u8>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Stderr {
            job_id,
            range,
            response: tx,
        })
        .await?;
        rx.await?
    }
}

fn start_job(
    db: &mut Connection,
    start: JobStart,
    response: oneshot::Sender<Result<JobStatus, JobError>>,
    tasks: &mut JoinSet<Result<JobEnd, JobError>>,
) -> Result<AbortHandle, JobError> {
    macro_rules! with_err_response {
        ($expr:expr) => {
            with_err_response!($expr, JobError::Start)
        };
        ($expr:expr, $err:expr) => {
            match $expr {
                Ok(x) => x,
                Err(e) => {
                    let _ = response.send(Err(e.into()));
                    return Err($err);
                }
            }
        };
    }

    let txn = db.transaction()?;
    let job = start.job.clone();
    let job_id = job.job_id();
    let time_reserved = with_err_response!(verify_reservation(&txn, job_id));
    let cert = with_err_response!(get_cert(&txn, job.key_id()));
    let job = with_err_response!(job.verify(&cert));
    with_err_response!(job_started(&txn, job, start.time_started));
    txn.commit()?;

    Ok(tasks.spawn(async move {
        let end = with_err_response!(start.wait().await, JobError::Wait);
        assert_eq!(job_id, end.job_id());
        let _ = response.send(Ok(JobStatus::Ended {
            job: end.job.clone(),
            time_reserved,
            time_started: end.time_started,
            time_ended: end.time_ended,
            status: end.status.code(),
            stdout_len: file_len(&end.stdout)?,
            stderr_len: file_len(&end.stderr)?,
        }));
        Ok(end)
    }))
}

fn get_cert(db: &Connection, key_id: KeyId) -> Result<Certificate, JobError> {
    if let Some(cert) = db
        .query_one(
            "SELECT cert FROM certs WHERE key_id = ?1",
            // `--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?)
            [key_id],
            |row| -> Result<Vec<u8>, _> { row.get(0) },
        )
        .optional()?
    {
        Ok(Certificate::from_der(&cert)?)
    } else {
        Err(JobError::MissingCert(key_id))
    }
}

fn get_cert_chain(db: &Connection, mut key_id: KeyId) -> Result<Vec<Certificate>, JobError> {
    let mut chain = Vec::new();
    loop {
        let cert = get_cert(db, key_id)?;
        let self_signed = cert.tbs_certificate.subject == cert.tbs_certificate.issuer;
        key_id = KeyId::try_from(&cert.tbs_certificate.issuer)?;
        chain.push(cert);
        if self_signed {
            break;
        }
    }
    chain.reverse();
    Ok(chain)
}

fn import_cert(db: &Connection, cert: &Certificate, root: bool) -> Result<KeyId, JobError> {
    let subject = &cert.tbs_certificate.subject;
    let issuer = &cert.tbs_certificate.issuer;
    let signature = Signature::new(cert.signature.raw_bytes().to_vec());
    if subject == issuer {
        if !root {
            return Err(JobError::Cert(CertError::SelfSigned));
        }
        signature.verify(&cert.tbs_certificate.to_der()?, cert)?;
    } else {
        let issuer_cert = get_cert(db, KeyId::try_from(issuer)?)?;
        signature.verify(&cert.tbs_certificate.to_der()?, &issuer_cert)?;
    }

    let key_id = KeyId::try_from(subject)?;
    db.execute(
        "INSERT INTO certs(key_id, cert) VALUES(?1, ?2) \
         ON CONFLICT(key_id) DO UPDATE SET cert = ?2",
        (key_id, cert.to_der()?),
    )?;
    Ok(key_id)
}

fn reserve_jobs(db: &mut Connection, number: u8) -> Result<JobsReserved, JobError> {
    let time_reserved = Utc::now();
    let txn = db.transaction()?;
    let mut job_ids = Vec::new();
    let mut stmt = txn.prepare(
        "INSERT INTO jobs(job_id, time_reserved, stdout, stderr) \
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for _ in 0..number {
        let job_id = JobId::new();
        stmt.execute((job_id, time_reserved, ZeroBlob(0), ZeroBlob(0)))?;
        job_ids.push(job_id);
    }
    stmt.finalize()?;
    txn.commit()?;
    Ok(JobsReserved {
        job_ids,
        time_reserved,
    })
}

fn get_reserved(db: &Connection) -> Result<BTreeMap<JobId, DateTime<Utc>>, JobError> {
    let mut reserved = BTreeMap::new();
    let mut stmt = db.prepare(
        "SELECT job_id, time_reserved FROM jobs WHERE time_started IS NULL",
        // `--SCAN jobs USING COVERING INDEX jobs_reserved_only
    )?;
    for row in stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))? {
        let (job_id, time_reserved) = row?;
        assert!(reserved.insert(job_id, time_reserved).is_none());
    }
    Ok(reserved)
}

fn revoke_reserved(db: &mut Connection, job_ids: &[JobId]) -> Result<Vec<JobId>, JobError> {
    let txn = db.transaction()?;
    let job_ids = if !job_ids.is_empty() {
        job_ids.to_vec()
    } else {
        get_reserved(&txn)?.keys().copied().collect()
    };
    let mut stmt = txn.prepare(
        "DELETE FROM jobs WHERE job_id = ?1 AND time_started IS NULL",
        // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
    )?;
    let mut revoked = Vec::new();
    for job_id in job_ids {
        if stmt.execute([job_id])? == 1 {
            revoked.push(job_id);
        }
    }
    stmt.finalize()?;
    txn.commit()?;
    Ok(revoked)
}

fn verify_reservation(db: &Connection, job_id: JobId) -> Result<DateTime<Utc>, JobError> {
    if let Some(time_reserved) = db
        .query_one(
            "SELECT time_reserved FROM jobs WHERE job_id = ?1",
            // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
            [job_id],
            |row| -> Result<DateTime<Utc>, _> { row.get(0) },
        )
        .optional()?
    {
        Ok(time_reserved)
    } else {
        Err(JobError::InvalidJobId(job_id))
    }
}

fn job_started(
    db: &Connection,
    job: VerifiedJob,
    time_started: DateTime<Utc>,
) -> Result<(), JobError> {
    if db.execute(
        "UPDATE jobs SET key_id = ?2, command = ?3, signature = ?4, time_started = ?5 \
         WHERE job_id = ?1 AND time_started IS NULL",
        // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        (
            job.job_id(),
            job.key_id(),
            job.command(),
            job.signature(),
            time_started,
        ),
    )? == 1
    {
        Ok(())
    } else {
        Err(JobError::InvalidJobId(job.job_id()))
    }
}

fn job_stdout(
    db: &Connection,
    job_id: JobId,
    range: Option<Range<i32>>,
) -> Result<Vec<u8>, JobError> {
    job_output(db, job_id, range, c"stdout")
}

fn job_stderr(
    db: &Connection,
    job_id: JobId,
    range: Option<Range<i32>>,
) -> Result<Vec<u8>, JobError> {
    job_output(db, job_id, range, c"stderr")
}

fn job_output(
    db: &Connection,
    job_id: JobId,
    range: Option<Range<i32>>,
    column: &'static CStr,
) -> Result<Vec<u8>, JobError> {
    if let Some(range) = range {
        let blob = get_blob(db, c"jobs", column, c"job_id", job_id)?;
        Ok(read_blob_chunk(&blob, range)?)
    } else if let Some(output) = db
        .query_one(
            &format!(
                "SELECT {} FROM jobs WHERE job_id = ?1",
                // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
                column.to_string_lossy()
            ),
            [job_id],
            |row| -> Result<Vec<u8>, _> { row.get(0) },
        )
        .optional()?
    {
        Ok(output)
    } else {
        Err(JobError::InvalidJobId(job_id))
    }
}

fn job_status(db: &Connection, job_id: JobId) -> Result<JobStatus, JobError> {
    if let Some(status) = db
        .query_one(
            "SELECT job_id, key_id, command, signature, \
                    time_reserved, time_started, time_ended, \
                    status, length(stdout), length(stderr) \
             FROM jobs WHERE job_id = ?1",
            // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
            [job_id],
            |row| {
                assert_eq!(row.get("job_id"), Ok(job_id));
                if let Ok(time_ended) = row.get("time_ended") {
                    Ok(JobStatus::Ended {
                        job: SignedJob::new(
                            JobStartRequest {
                                job_id,
                                command: row.get("command")?,
                            },
                            row.get("key_id")?,
                            row.get("signature")?,
                        ),
                        time_reserved: row.get("time_reserved")?,
                        time_started: row.get("time_started")?,
                        time_ended,
                        status: row.get("status")?,
                        stdout_len: row.get("length(stdout)")?,
                        stderr_len: row.get("length(stderr)")?,
                    })
                } else if let Ok(time_started) = row.get("time_started") {
                    Ok(JobStatus::Started {
                        job: SignedJob::new(
                            JobStartRequest {
                                job_id,
                                command: row.get("command")?,
                            },
                            row.get("key_id")?,
                            row.get("signature")?,
                        ),
                        time_reserved: row.get("time_reserved")?,
                        time_started,
                    })
                } else if let Ok(time_reserved) = row.get("time_reserved") {
                    Ok(JobStatus::Reserved {
                        job_id,
                        time_reserved,
                    })
                } else {
                    unreachable!("time_reserved should be NOT NULL")
                }
            },
        )
        .optional()?
    {
        Ok(status)
    } else {
        Ok(JobStatus::NotFound)
    }
}

fn job_ended(
    db: &mut Connection,
    job_id: JobId,
    status: Option<i32>,
    mut stdout: File,
    mut stderr: File,
    time_ended: DateTime<Utc>,
) -> Result<(), BlobError> {
    let stdout_len = file_len(&stdout)?;
    let stderr_len = file_len(&stderr)?;
    let txn = db.transaction()?;
    txn.execute(
        "UPDATE jobs SET status = ?2, stdout = ?3, stderr = ?4, time_ended = ?5 \
         WHERE job_id = ?1 AND time_started IS NOT NULL AND time_ended IS NULL",
        // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        (
            job_id,
            status,
            ZeroBlob(stdout_len),
            ZeroBlob(stderr_len),
            time_ended,
        ),
    )?;
    {
        let blob = read_blob_from_file(&mut stdout, &txn, c"jobs", c"stdout", c"job_id", job_id)?;
        assert_eq!(blob.size(), stdout_len);
    }
    {
        let blob = read_blob_from_file(&mut stderr, &txn, c"jobs", c"stderr", c"job_id", job_id)?;
        assert_eq!(blob.size(), stderr_len);
    }
    txn.commit()?;
    Ok(())
}

fn job_aborted(db: &Connection, job_id: JobId, time_ended: DateTime<Utc>) -> Result<(), JobError> {
    db.execute(
        "UPDATE jobs SET time_ended = ?2 \
         WHERE job_id = ?1 \
         AND time_started IS NOT NULL \
         AND time_ended IS NULL",
        // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        (job_id, time_ended),
    )?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::io::{Write as _, read_to_string};
    use std::time::Duration;

    use rand_core::{OsRng, RngCore as _};
    use tempfile::NamedTempFile;
    use x509_cert::name::Name;
    use x509_cert::time::Validity;

    use sush_common::certs::{EphemeralKey, KeyType, Signer as _};
    #[allow(unused_imports)]
    use sush_common::database::{open_database, open_database_in_memory};

    use super::*;

    trait SignJobRequest {
        async fn sign_job_request<S: AsRef<str>>(&self, job_id: JobId, command: S) -> SignedJob;
    }

    impl SignJobRequest for EphemeralKey {
        async fn sign_job_request<S: AsRef<str>>(&self, job_id: JobId, command: S) -> SignedJob {
            self.sign(JobStartRequest::new(job_id, command))
                .await
                .unwrap()
        }
    }

    /// Inject some randomness into the subject DN to ensure unique key IDs.
    fn ephemeral_test_subject() -> Name {
        let mut buf = [0; 8];
        OsRng.fill_bytes(&mut buf);
        format!(
            "CN=Ephemeral Test Key {},O=Oxide Computer Company,C=US",
            BASE64.encode(buf),
        )
        .parse()
        .unwrap()
    }

    fn ephemeral_test_root() -> EphemeralKey {
        EphemeralKey::new_root(
            KeyType::Ed25519,
            ephemeral_test_subject(),
            Validity::from_now(Duration::from_secs(60)).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn false_() {
        let key = ephemeral_test_root();
        let job = key.sign_job_request(JobId::new(), "false").await;
        let start = JobStart::new(job).unwrap();
        let end = start.wait().await.unwrap();
        assert!(!end.status.success());
        assert_eq!(end.stdout.metadata().unwrap().len(), 0);
        assert_eq!(end.stderr.metadata().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn true_() {
        let key = ephemeral_test_root();
        let job = key.sign_job_request(JobId::new(), "true").await;
        let start = JobStart::new(job).unwrap();
        let end = start.wait().await.unwrap();
        assert!(end.status.success());
        assert_eq!(end.stdout.metadata().unwrap().len(), 0);
        assert_eq!(end.stderr.metadata().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn stderr() {
        let key = ephemeral_test_root();
        let job = key.sign_job_request(JobId::new(), "echo error >&2").await;
        let start = JobStart::new(job).unwrap();
        let end = start.wait().await.unwrap();
        assert!(end.status.success());
        assert_eq!(end.stdout.metadata().unwrap().len(), 0);
        assert_eq!(read_to_string(end.stderr).unwrap(), "error\n");
    }

    #[tokio::test]
    async fn cat_temp_file() {
        let content = "Lorem ipsum dolor sit amet.";
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{content}").unwrap();

        let key = ephemeral_test_root();
        let path = file.path().display().to_string();
        let command = format!("cat {}", &path);
        let job = key.sign_job_request(JobId::new(), command).await;
        let start = JobStart::new(job).unwrap();
        let end = start.wait().await.unwrap();
        assert!(end.status.success());
        assert_eq!(end.stdout.metadata().unwrap().len() as usize, content.len());
        assert_eq!(read_to_string(end.stdout).unwrap(), content);
        assert_eq!(end.stderr.metadata().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn pipeline() {
        let key = ephemeral_test_root();
        let job = key.sign_job_request(JobId::new(), "yes | head -n 1").await;
        let start = JobStart::new(job).unwrap();
        let end = start.wait().await.unwrap();
        assert!(end.status.success());
        assert_eq!(read_to_string(end.stdout).unwrap(), "y\n");
        assert_eq!(end.stderr.metadata().unwrap().len(), 0);
    }

    fn check_status_started(
        status: JobStatus,
        cert: &Certificate,
        expected_job_id: JobId,
        expected_command: &str,
    ) {
        let JobStatus::Started {
            job,
            time_reserved,
            time_started,
        } = status
        else {
            panic!("expected job to be started");
        };
        assert_eq!(job.job_id, expected_job_id);
        let job = job.verify(cert).unwrap();
        assert_eq!(job.command, expected_command);
        assert!(time_reserved < time_started);
        assert!(time_started < Utc::now());
    }

    fn check_status_ended(
        status: JobStatus,
        cert: &Certificate,
        expected_job_id: JobId,
        expected_command: &str,
        expected_status: Option<i32>,
        expected_stdout_len: i32,
        expected_stderr_len: i32,
    ) {
        let JobStatus::Ended {
            job,
            time_reserved,
            time_started,
            time_ended,
            status,
            stdout_len,
            stderr_len,
        } = status
        else {
            panic!("expected job to be finished");
        };
        assert_eq!(job.job_id, expected_job_id);
        let job = job.verify(cert).unwrap();
        assert_eq!(job.command, expected_command);
        assert!(time_reserved < time_started);
        assert!(time_started < time_ended);
        assert!(time_ended < Utc::now());
        assert_eq!(status, expected_status);
        assert_eq!(stdout_len, expected_stdout_len);
        assert_eq!(stderr_len, expected_stderr_len);
    }

    async fn manager_and_test_root(db: Option<&str>) -> (JobManager, EphemeralKey) {
        let db = if let Some(db) = db {
            open_database(db).unwrap()
        } else {
            open_database_in_memory().unwrap()
        };
        let mgr = JobManager::new(db).await.unwrap();
        let root = ephemeral_test_root();
        let key_id = mgr.import_cert(root.cert(), true).await.unwrap();
        assert_eq!(key_id, root.key_id().await.unwrap());
        (mgr, root)
    }

    #[tokio::test]
    async fn jobs() {
        let (mgr, root) = manager_and_test_root(None).await;
        let JobsReserved {
            mut job_ids,
            time_reserved,
        } = mgr.reserve_jobs(5).await.unwrap();
        assert_eq!(job_ids.len(), 5);
        assert!(time_reserved < Utc::now());

        let reserved = mgr.get_reserved().await.unwrap();
        for job_id in &job_ids {
            assert_eq!(reserved[job_id], time_reserved);
        }

        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(job_id, "true").await;
        assert!(matches!(
            mgr.job_status(job_id).await.unwrap(),
            JobStatus::Reserved { job_id: id, time_reserved }
            if id == job_id && time_reserved < Utc::now(),
        ));

        let rx = mgr.job_start(job.clone()).await.unwrap();
        let status = rx.await.unwrap().unwrap();
        check_status_ended(status, root.cert(), job_id, "true", Some(0), 0, 0);

        let rx = mgr.job_start(job).await.unwrap();
        assert!(
            matches!(
                rx.await.unwrap().unwrap_err(),
                JobError::InvalidJobId(id) if id == job_id
            ),
            "should not be allowed to reuse a job ID"
        );

        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(job_id, "false").await;
        let rx = mgr.job_start(job).await.unwrap();
        let status = rx.await.unwrap().unwrap();
        check_status_ended(status, root.cert(), job_id, "false", Some(1), 0, 0);

        let job_id = job_ids.pop().unwrap();
        let job_id_string = job_id.to_string();
        let job_id_bytes = job_id_string.as_bytes();
        let job = root.sign_job_request(job_id, "echo -n $SUSH_JOB_ID").await;
        let rx = mgr.job_start(job).await.unwrap();
        let status = rx.await.unwrap().unwrap();
        check_status_ended(
            status,
            root.cert(),
            job_id,
            "echo -n $SUSH_JOB_ID",
            Some(0),
            job_id_bytes.len() as i32,
            0,
        );
        assert_eq!(mgr.job_stdout(job_id, None).await.unwrap(), job_id_bytes);
        assert!(mgr.job_stderr(job_id, None).await.unwrap().is_empty());

        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
    }

    #[tokio::test]
    async fn revoke() {
        let (mgr, root) = manager_and_test_root(None).await;
        let (job_id, time_reserved) = mgr.reserve_one().await.unwrap();
        let job_ids = vec![job_id];
        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
        assert!(mgr.revoke_reserved(job_ids).await.unwrap().is_empty());

        let job = root.sign_job_request(job_id, "false").await;
        let rx = mgr.job_start(job).await.unwrap();
        assert!(
            matches!(
                rx.await.unwrap().unwrap_err(),
                JobError::InvalidJobId(id) if id == job_id
            ),
            "should not be allowed to start a revoked job"
        );

        let status = mgr.job_status(job_id).await.unwrap();
        assert!(matches!(status, JobStatus::NotFound));

        let (new_job_id, new_time_reserved) = mgr.reserve_one().await.unwrap();
        assert_ne!(new_job_id, job_id);
        assert!(new_time_reserved > time_reserved);

        let job_ids = vec![job_id, new_job_id];
        assert_eq!(
            mgr.revoke_reserved(job_ids.clone()).await.unwrap(),
            vec![new_job_id],
            "old job was previously revoked"
        );
        assert!(mgr.revoke_reserved(job_ids).await.unwrap().is_empty());

        let JobsReserved {
            job_ids,
            time_reserved: _,
        } = mgr.reserve_jobs(100).await.unwrap();
        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
        assert!(mgr.revoke_reserved(job_ids).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn abort() {
        let (mgr, root) = manager_and_test_root(None).await;
        let (job_id, time_reserved) = mgr.reserve_one().await.unwrap();

        let mark = Utc::now();
        assert!(time_reserved < mark);
        let job = root.sign_job_request(job_id, "yes").await;
        let rx = mgr.job_start(job).await.unwrap();

        let status = mgr.job_status(job_id).await.unwrap();
        check_status_started(status, root.cert(), job_id, "yes");

        mgr.job_abort(job_id).await.unwrap();
        assert!(rx.await.is_err());
        assert!((Utc::now() - mark).as_seconds_f32() < 1.0);

        let status = mgr.job_status(job_id).await.unwrap();
        check_status_ended(status, root.cert(), job_id, "yes", None, 0, 0);
    }

    #[tokio::test]
    async fn cert_chain() {
        let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
        let root =
            EphemeralKey::new_root(KeyType::Ed25519, ephemeral_test_subject(), validity).unwrap();
        let root_key_id = root.key_id().await.unwrap();
        let root_cert = root.cert().to_owned();
        let issuer = root.subject();
        let subject = ephemeral_test_subject();
        let child = EphemeralKey::new_child(KeyType::P256, subject, issuer, validity, &root)
            .await
            .unwrap();
        assert_ne!(child.key_id().await.unwrap(), root_key_id);

        let db = open_database_in_memory().unwrap();
        let mgr = JobManager::new(db).await.unwrap();
        assert!(
            matches!(
                mgr.import_cert(&root_cert, false).await.unwrap_err(),
                JobError::Cert(CertError::SelfSigned),
            ),
            "should not accept root cert without override"
        );
        assert!(
            matches!(
                mgr.import_cert(child.cert(), false).await.unwrap_err(),
                JobError::MissingCert(key_id) if key_id == root_key_id,
            ),
            "should not accept child cert without root"
        );
        assert_eq!(
            mgr.import_cert(&root_cert, true).await.unwrap(),
            root_key_id
        );
        assert_eq!(
            mgr.cert_chain(root_key_id).await.unwrap(),
            vec![root_cert.clone()]
        );
        assert_eq!(
            mgr.import_cert(child.cert(), false).await.unwrap(),
            child.key_id().await.unwrap()
        );
        assert_eq!(
            mgr.cert_chain(child.key_id().await.unwrap()).await.unwrap(),
            vec![root_cert.clone(), child.cert().clone()]
        );

        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();
        let job = child.sign_job_request(job_id, "true").await;
        let rx = mgr.job_start(job).await.unwrap();
        let status = rx.await.unwrap().unwrap();
        check_status_ended(status, child.cert(), job_id, "true", Some(0), 0, 0);
    }
}
