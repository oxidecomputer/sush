//! Manage a set of jobs.
//!
//! The manager runs as an agent loop with exclusive access to the
//! database. It services requests and sends responses via oneshot
//! channels (included in the requests). Jobs are spawned onto new
//! tokio tasks, which the manager loop watches for completion.
//! Standard output and standard error are saved as files.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use blake3::{Hasher, hash};
use bytesize::MIB;
use chrono::{DateTime, Utc};
use dropshot::{ClientErrorStatusCode, HttpError};
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use rusqlite::{Connection, OptionalExtension as _, prepare_cached_and_bind};
use slog::{Logger, error, info};
use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle, JoinSet, spawn};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};

use sush_common::certs::{CertError, KeyId, Signature};
use sush_common::codephrases::generate_id;
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
use sush_common::jobs::{
    JobId, JobLimits, JobOutputHash, JobStartRequest, JobStatus, JobsReserved, SignedJob,
    VerifiedJob,
};

/// Self-signed (root) X.509 certificates. Self-signed certificates may
/// not be imported (except in test code), and so must be included here.
pub const ROOT_CERTS: &[&[u8]] = &[
    // TODO: replace with a trusted root
    include_bytes!("../certs/untrusted.crt"),
];

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = 128 * MIB;

/// An asynchronous kill signal, delivered by the abort request.
type KillShot = oneshot::Sender<JobId>;

#[derive(Debug, Error)]
pub enum JobError {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error("Can't send job request: receiver dropped")]
    ChannelClosed,
    #[error("DER encoding error: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error("Invalid command `{0}`")]
    InvalidCommand(String),
    #[error("Invalid or duplicate job ID")]
    InvalidJobId(JobId),
    #[error("Invalid range, please use absolute byte positions < {0}")]
    InvalidRange(u64),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("Can't find certificate for key `{0}`")]
    MissingCert(KeyId),
    #[error("Job output hash mismatch, file may be corrupt")]
    OutputHashMismatch(JobId, JobOutputHash),
    #[error("Output not yet available")]
    OutputPending,
    #[error("Output too big, please use range requests")]
    OutputTooBig,
    #[error("Can't receive response: sender dropped")]
    Recv(#[from] oneshot::error::RecvError),
    #[error(transparent)]
    Slice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Task(#[from] JoinError),
    #[error("Unable to wait for job end")]
    Wait,
}

impl From<JobError> for HttpError {
    fn from(error: JobError) -> Self {
        use JobError::*;
        let message = error.to_string();
        match error {
            Cert(_)
            | ChannelClosed
            | Der(_)
            | Execution(_)
            | Io(_)
            | OutputHashMismatch(_, _)
            | Recv(_)
            | Sqlite(_)
            | Task(_)
            | Slice(_)
            | Wait => HttpError::for_internal_error(message),
            InvalidRange(length) => {
                let mut error = HttpError::for_client_error(
                    None,
                    ClientErrorStatusCode::RANGE_NOT_SATISFIABLE,
                    message,
                );
                error
                    .add_header("content-range", format!("bytes */{length}"))
                    .expect("should be able to add content-range header");
                error
            }
            OutputTooBig => {
                HttpError::for_client_error(None, ClientErrorStatusCode::PAYLOAD_TOO_LARGE, message)
            }
            InvalidCommand(_) | InvalidJobId(_) | OutputPending | Json(_) | MissingCert(_) => {
                HttpError::for_client_error(None, ClientErrorStatusCode::BAD_REQUEST, message)
            }
        }
    }
}

#[derive(Clone, Debug, Error)]
#[error("{error}")]
pub struct ExecutionError {
    job_id: JobId,
    time: DateTime<Utc>,
    error: Arc<JobError>,
}

impl ExecutionError {
    fn new(job_id: JobId, error: JobError) -> Self {
        let time = Utc::now();
        Self {
            job_id,
            time,
            error: Arc::new(error),
        }
    }

    #[cfg(test)]
    fn error(&self) -> &JobError {
        &self.error
    }
}

#[derive(Debug)]
struct JobStart {
    job: SignedJob,
    limits: JobLimits,
    output_dir: PathBuf,
}

impl JobStart {
    fn new(job: SignedJob, limits: JobLimits, output_dir: PathBuf) -> Self {
        Self {
            job,
            limits,
            output_dir,
        }
    }

    fn start(self) -> Result<JobStarted, JobError> {
        let Self {
            job,
            limits,
            output_dir,
        } = self;
        if job.command().starts_with('-') {
            return Err(JobError::InvalidCommand(job.command().to_owned()));
        }
        let job_id = &job.job_id;
        let job_dir = job_output_dir(&output_dir, job_id);
        DirBuilder::new().recursive(true).create(job_dir)?;
        let stdout_path = job_output_path(&output_dir, job_id, Stdout);
        let stderr_path = job_output_path(&output_dir, job_id, Stderr);
        let stdout = File::create_new(stdout_path)?;
        let stderr = File::create_new(stderr_path)?;
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(job.command())
            .env("SUSH_JOB_ID", job_id.to_string())
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true);
        unsafe {
            command.pre_exec(move || limits.apply());
        }
        Ok(JobStarted {
            time_started: Utc::now(),
            child: command.spawn()?,
        })
    }

    fn job_id(&self) -> &JobId {
        self.job.job_id()
    }
}

#[derive(Debug)]
struct JobStarted {
    time_started: DateTime<Utc>,
    child: Child,
}

#[derive(Clone, Debug)]
pub struct JobEnd {
    job: VerifiedJob,
    time_ended: DateTime<Utc>,
    status: Option<ExitStatus>,
    stdout_hash: JobOutputHash,
    stderr_hash: JobOutputHash,
}

#[derive(Debug)]
enum JobRequest {
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
        response: oneshot::Sender<Result<JobEnd, ExecutionError>>,
    },
    Status {
        job_id: JobId,
        response: oneshot::Sender<Result<JobStatus, JobError>>,
    },
    Output {
        job_id: JobId,
        stream: JobOutputStream,
        range: Option<Range>,
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
    output_dir: PathBuf,
}

impl JobManager {
    /// Spawn a task that processes job requests and monitors jobs for completion.
    pub async fn new(mut db: Connection, output_dir: &Path, log: Logger) -> Result<Self, JobError> {
        // Import the root certificates.
        for root in ROOT_CERTS {
            let cert = Certificate::from_der(root)?;
            let key_id = import_cert(&db, &cert, true)?;
            info!(log, "imported root certificate"; "key_id" => %key_id);
        }

        // Accept and process job requests and end events.
        let (tx_requests, mut rx_requests) = mpsc::channel::<JobRequest>(8);
        let task = spawn({
            let output_dir = output_dir.to_owned();
            async move {
                let mut tasks = JoinSet::<Result<JobEnd, ExecutionError>>::new();
                let mut killers = BTreeMap::<JobId, KillShot>::new();
                loop {
                    select! {
                        Some(request) = rx_requests.recv() => {
                            client_request(
                                &mut db,
                                &log,
                                request,
                                &mut tasks,
                                &mut killers,
                                &output_dir,
                            )?
                        }
                        Some(end) = tasks.join_next() => {
                            job_ended(&db, &output_dir, &log, end, &mut killers)?
                        }
                        else => {
                            info!(log, "job manager shutting down");
                            return Ok(());
                        }
                    }
                }
            }
        });
        Ok(Self {
            channel: tx_requests,
            output_dir: output_dir.to_owned(),
            task,
        })
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
        limits: JobLimits,
    ) -> Result<oneshot::Receiver<Result<JobEnd, ExecutionError>>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Start {
            request: Box::new(JobStart::new(job, limits, self.output_dir.to_owned())),
            response: tx,
        })
        .await?;
        Ok(rx)
    }

    pub async fn job_status(&self, job_id: &JobId) -> Result<JobStatus, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Status {
            job_id: job_id.to_owned(),
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_abort(&self, job_id: &JobId) -> Result<(), JobError> {
        self.request(JobRequest::Abort {
            job_id: job_id.to_owned(),
        })
        .await
    }

    pub async fn job_output(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Output {
            job_id: job_id.to_owned(),
            stream,
            range,
            response: tx,
        })
        .await?;
        rx.await?
    }
}

fn job_output_dir(base_dir: &Path, job_id: &JobId) -> PathBuf {
    base_dir.join("jobs").join(job_id.to_string())
}

fn job_output_path(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
    job_output_dir(base_dir, job_id).join(stream.as_str())
}

fn job_output_len(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> u64 {
    job_output_path(base_dir, job_id, stream)
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0)
}

fn job_output_hash(
    base_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
) -> Result<JobOutputHash, JobError> {
    let mut hasher = Hasher::new();
    hasher.update_mmap_rayon(job_output_path(base_dir, job_id, stream))?;
    Ok(hasher.finalize().into())
}

fn job_ended(
    db: &Connection,
    output_dir: &Path,
    log: &Logger,
    end: Result<Result<JobEnd, ExecutionError>, JoinError>,
    killers: &mut BTreeMap<JobId, KillShot>,
) -> Result<(), JobError> {
    match end {
        Err(error) if error.is_cancelled() => {
            info!(log, "job aborted"; "error" => %error);
        }
        Err(error) => {
            error!(log, "job failed"; "error" => %error);
        }
        Ok(Err(ExecutionError {
            job_id,
            time,
            error,
        })) => {
            error!(log, "job execution failed"; "error" => %error, "job_id" => %job_id, "time" => %time);
            assert!(killers.remove(&job_id).is_some());
            job_aborted(db, output_dir, &job_id, time)?;
        }
        Ok(Ok(JobEnd {
            job,
            time_ended,
            status,
            stdout_hash,
            stderr_hash,
        })) => {
            let job_id = job.job_id();
            let status = status.map(|status| status.code());
            prepare_cached_and_bind!(
                db,
                "UPDATE jobs \
                 SET time_ended = $time_ended, \
                     status = $status, \
                     stdout_hash = $stdout_hash, \
                     stderr_hash = $stderr_hash \
                 WHERE job_id = $job_id AND \
                       time_started IS NOT NULL AND \
                       time_ended IS NULL"
            )
            .raw_execute()?;
        }
    }
    Ok(())
}

fn job_aborted(
    db: &Connection,
    output_dir: &Path,
    job_id: &JobId,
    time_ended: DateTime<Utc>,
) -> Result<(), JobError> {
    let stdout_hash = job_output_hash(output_dir, job_id, Stdout)?;
    let stderr_hash = job_output_hash(output_dir, job_id, Stderr)?;
    prepare_cached_and_bind!(
        db,
        "UPDATE jobs \
         SET time_ended = $time_ended, \
             stdout_hash = $stdout_hash, \
             stderr_hash = $stderr_hash \
         WHERE job_id = $job_id AND \
               time_started IS NOT NULL AND \
               time_ended IS NULL"
    )
    .raw_execute()?;
    Ok(())
}

fn client_request(
    db: &mut Connection,
    log: &Logger,
    request: JobRequest,
    tasks: &mut JoinSet<Result<JobEnd, ExecutionError>>,
    killers: &mut BTreeMap<JobId, KillShot>,
    output_dir: &Path,
) -> Result<(), JobError> {
    match request {
        JobRequest::ImportCert {
            cert,
            #[cfg(test)]
            root,
            response,
        } => {
            #[cfg(not(test))]
            let root = false;
            let _ = response.send(import_cert(db, &cert, root));
        }
        JobRequest::CertChain { key_id, response } => {
            let _ = response.send(get_cert_chain(db, key_id));
        }
        JobRequest::Reserve { number, response } => {
            let _ = response.send(reserve_jobs(db, number));
        }
        JobRequest::GetReserved { response } => {
            let _ = response.send(get_reserved(db));
        }
        JobRequest::RevokeReserved { job_ids, response } => {
            let _ = response.send(revoke_reserved(db, &job_ids));
        }
        JobRequest::Start {
            request: start,
            response,
        } => {
            let job_id = start.job_id().to_owned();
            match start_job(db, output_dir, *start, response, tasks) {
                Ok(kill) => assert!(killers.insert(job_id, kill).is_none()),
                Err(error) => {
                    error!(log, "job execution error"; "error" => %error, "job_id" => %job_id);
                }
            }
        }
        JobRequest::Abort { job_id } => {
            if let Some(kill) = killers.remove(&job_id)
                && let Err(job_id) = kill.send(job_id)
            {
                error!(log, "can't kill job"; "job_id" => %job_id);
            }
        }
        JobRequest::Status { job_id, response } => {
            let _ = response.send(get_job_status(db, output_dir, &job_id));
        }
        JobRequest::Output {
            job_id,
            stream,
            range,
            response,
        } => {
            let _ = response.send(get_job_output(db, output_dir, &job_id, stream, range));
        }
    }
    Ok(())
}

/// Verify and start a job, spawn a task to wait for it and report its end,
/// and return a oneshot channel to kill it.
fn start_job(
    db: &mut Connection,
    output_dir: &Path,
    start: JobStart,
    response: oneshot::Sender<Result<JobEnd, ExecutionError>>,
    tasks: &mut JoinSet<Result<JobEnd, ExecutionError>>,
) -> Result<KillShot, ExecutionError> {
    let job = start.job.clone();
    let job_id = job.job_id().to_owned();
    macro_rules! exe {
        ($expr:expr) => {
            match $expr {
                Ok(x) => x,
                Err(e) => {
                    let e = ExecutionError::new(job_id, e.into());
                    let _ = response.send(Err(e.clone()));
                    return Err(e);
                }
            }
        };
    }

    // Verify the job request.
    let txn = exe!(db.transaction());
    let _time_reserved = exe!(verify_reservation(&txn, &job_id));
    let cert = exe!(get_cert(&txn, job.key_id()));
    let job = exe!(job.verify(&cert));

    // Start the job.
    let JobStarted {
        time_started,
        mut child,
    } = exe!(start.start());
    exe!(job_started(&txn, &job, time_started));
    exe!(txn.commit());

    // Wait for the job to die or be killed.
    let output_dir = output_dir.to_owned();
    let (kill, die) = oneshot::channel();
    tasks.spawn(async move {
        let status = select! {
            status = child.wait() => Some(exe!(status)),
            target = die => {
                assert_eq!(exe!(target), job_id);
                exe!(child.kill().await);
                None
            }
        };
        let stdout_hash = exe!(job_output_hash(&output_dir, &job_id, Stdout));
        let stderr_hash = exe!(job_output_hash(&output_dir, &job_id, Stderr));
        let time_ended = Utc::now();
        let end = JobEnd {
            job,
            time_ended,
            status,
            stdout_hash,
            stderr_hash,
        };
        let _ = response.send(Ok(end.clone()));
        Ok(end)
    });

    Ok(kill)
}

fn get_cert(db: &Connection, key_id: &KeyId) -> Result<Certificate, JobError> {
    let mut stmt = db.prepare_cached(
        "SELECT cert FROM certs WHERE key_id = ?1",
        // `--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?)
    )?;
    if let Some(cert) = stmt
        .query_one([key_id], |row| -> Result<Vec<u8>, _> { row.get(0) })
        .optional()?
    {
        Ok(Certificate::from_der(&cert)?)
    } else {
        Err(JobError::MissingCert(key_id.to_owned()))
    }
}

fn get_cert_chain(db: &Connection, mut key_id: KeyId) -> Result<Vec<Certificate>, JobError> {
    let mut chain = Vec::new();
    loop {
        let cert = get_cert(db, &key_id)?;
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
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let signature = Signature::try_from(cert)?;
    if subject == issuer {
        if !root {
            return Err(JobError::Cert(CertError::SelfSigned));
        }
        signature.verify(&cert.tbs_certificate.to_der()?, spki)?;
    } else {
        let issuer_cert = get_cert(db, &KeyId::try_from(issuer)?)?;
        let issuer_pki = &issuer_cert.tbs_certificate.subject_public_key_info;
        signature.verify(&cert.tbs_certificate.to_der()?, issuer_pki)?;
    }

    let key_id = KeyId::try_from(subject)?;
    db.execute(
        "INSERT INTO certs(key_id, cert) VALUES(?1, ?2) \
         ON CONFLICT(key_id) DO UPDATE SET cert = ?2",
        (&key_id, cert.to_der()?),
    )?;
    Ok(key_id)
}

fn reserve_jobs(db: &mut Connection, number: u8) -> Result<JobsReserved, JobError> {
    let time_reserved = Utc::now();
    let txn = db.transaction()?;
    let mut job_ids = Vec::new();
    {
        let mut stmt =
            txn.prepare_cached("INSERT INTO jobs(job_id, time_reserved) VALUES(?1, ?2)")?;
        for _ in 0..number {
            let job_id = JobId::from(&generate_id());
            stmt.execute((&job_id, time_reserved))?;
            job_ids.push(job_id);
        }
    }
    txn.commit()?;
    Ok(JobsReserved {
        job_ids,
        time_reserved,
    })
}

fn get_reserved(db: &Connection) -> Result<BTreeMap<JobId, DateTime<Utc>>, JobError> {
    let mut reserved = BTreeMap::new();
    let mut stmt = db.prepare_cached(
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
        get_reserved(&txn)?.keys().cloned().collect()
    };
    let mut revoked = Vec::new();
    {
        let mut stmt = txn.prepare_cached(
            "DELETE FROM jobs WHERE job_id = ?1 AND time_started IS NULL",
            // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        )?;
        for job_id in job_ids {
            if stmt.execute([&job_id])? == 1 {
                revoked.push(job_id);
            }
        }
    }
    txn.commit()?;
    Ok(revoked)
}

fn verify_reservation(db: &Connection, job_id: &JobId) -> Result<DateTime<Utc>, JobError> {
    let mut stmt = db.prepare_cached(
        "SELECT time_reserved FROM jobs WHERE job_id = ?1 AND time_started IS NULL",
        // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
    )?;
    if let Some(time_reserved) = stmt
        .query_one([job_id], |row| -> Result<DateTime<Utc>, _> { row.get(0) })
        .optional()?
    {
        Ok(time_reserved)
    } else {
        Err(JobError::InvalidJobId(job_id.to_owned()))
    }
}

fn job_started(
    db: &Connection,
    job: &VerifiedJob,
    time_started: DateTime<Utc>,
) -> Result<(), JobError> {
    let job_id = job.job_id();
    let key_id = job.key_id();
    let command = job.command();
    let signature = job.signature();
    let mut stmt = prepare_cached_and_bind!(
        db,
        "UPDATE jobs \
         SET key_id = $key_id, command = $command, signature = $signature, time_started = $time_started \
         WHERE job_id = $job_id AND time_started IS NULL"
    );
    if stmt.raw_execute()? == 1 {
        Ok(())
    } else {
        Err(JobError::InvalidJobId(job.job_id().to_owned()))
    }
}

fn get_job_output_hash(
    db: &Connection,
    job_id: &JobId,
    stream: JobOutputStream,
) -> Result<Option<JobOutputHash>, JobError> {
    let query = format!(
        "SELECT {stream}_hash FROM jobs WHERE job_id = ?1",
        // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
    );
    let mut stmt = db.prepare_cached(&query)?;
    if let Some(hash) = stmt
        .query_one([job_id], |row| -> Result<Option<_>, _> { row.get(0) })
        .optional()?
    {
        hash.ok_or(JobError::OutputPending)
    } else {
        Err(JobError::InvalidJobId(job_id.to_owned()))
    }
}

fn get_job_output(
    db: &Connection,
    output_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
    range: Option<Range>,
) -> Result<Vec<u8>, JobError> {
    let len = job_output_len(output_dir, job_id, stream);
    let path = job_output_path(output_dir, job_id, stream);
    let mut file = File::open(&path).map_err(|_| JobError::InvalidJobId(job_id.to_owned()))?;
    if let Some(Range { start, end }) = range {
        // HTTP Ranges include both their endpoints.
        let start = if let StartPosition::Index(start) = start
            && start < len
        {
            file.seek(SeekFrom::Start(start))?
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
            file.read_exact(&mut buf)?;
            Ok(buf)
        }
    } else if len > OUTPUT_THRESHOLD {
        Err(JobError::OutputTooBig)
    } else {
        let mut buf = Vec::with_capacity(len as usize);
        file.read_to_end(&mut buf)?;
        if let Some(expected_hash) = get_job_output_hash(db, job_id, stream)?
            && JobOutputHash::from(hash(&buf)) != expected_hash
        {
            Err(JobError::OutputHashMismatch(job_id.clone(), expected_hash))
        } else {
            Ok(buf)
        }
    }
}

fn get_job_status(
    db: &mut Connection,
    output_dir: &Path,
    job_id: &JobId,
) -> Result<JobStatus, JobError> {
    let stdout_len = job_output_len(output_dir, job_id, Stdout);
    let stderr_len = job_output_len(output_dir, job_id, Stderr);
    let txn = db.transaction()?;
    if let Some(status) = txn
        .prepare_cached(
            "SELECT * FROM jobs WHERE job_id = ?1",
            // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        )?
        .query_one([job_id], |row| {
            assert_eq!(row.get("job_id").as_ref(), Ok(job_id));
            if let Ok(time_ended) = row.get("time_ended") {
                let key_id: KeyId = row.get("key_id")?;
                Ok(JobStatus::Ended {
                    job: SignedJob::new(
                        JobStartRequest {
                            job_id: job_id.clone(),
                            command: row.get("command")?,
                        },
                        key_id.clone(),
                        row.get("signature")?,
                    ),
                    time_reserved: row.get("time_reserved")?,
                    time_started: row.get("time_started")?,
                    time_ended,
                    status: row.get("status")?,
                    stdout_len,
                    stderr_len,
                    stdout_hash: row.get("stdout_hash")?,
                    stderr_hash: row.get("stderr_hash")?,
                })
            } else if let Ok(time_started) = row.get("time_started") {
                Ok(JobStatus::Started {
                    job: SignedJob::new(
                        JobStartRequest {
                            job_id: job_id.clone(),
                            command: row.get("command")?,
                        },
                        row.get("key_id")?,
                        row.get("signature")?,
                    ),
                    time_reserved: row.get("time_reserved")?,
                    time_started,
                    stdout_len,
                    stderr_len,
                })
            } else if let Ok(time_reserved) = row.get("time_reserved") {
                Ok(JobStatus::Reserved {
                    job_id: job_id.clone(),
                    time_reserved,
                })
            } else {
                unreachable!("time_reserved should be NOT NULL")
            }
        })
        .optional()?
    {
        Ok(status)
    } else {
        Ok(JobStatus::NotFound)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use function_name::named;
    use rand_core::{OsRng, RngCore as _};
    use rusqlite::limits::Limit;
    use slog::Drain as _;
    use slog_term::{FullFormat, PlainSyncDecorator, TestStdoutWriter};
    use tempfile::TempDir;
    use x509_cert::name::Name;
    use x509_cert::time::Validity;

    use sush_common::certs::{EphemeralKey, KeyType, Signer as _};

    #[allow(unused_imports)]
    use crate::database::{open_database, open_database_in_memory};

    use super::*;

    trait SignJobRequest {
        async fn sign_job_request<S: AsRef<str>>(&self, job_id: &JobId, command: S) -> SignedJob;
    }

    impl SignJobRequest for EphemeralKey {
        async fn sign_job_request<S: AsRef<str>>(&self, job_id: &JobId, command: S) -> SignedJob {
            self.sign(JobStartRequest::new(job_id.to_owned(), command))
                .await
                .unwrap()
        }
    }

    /// Inject some randomness into the subject DN to ensure unique key IDs.
    fn ephemeral_test_subject() -> Name {
        let mut buf = [0; 8];
        OsRng.fill_bytes(&mut buf);
        let id = generate_id();
        format!("CN=Ephemeral Test Key {id},O=Oxide Computer Company,C=US")
            .parse()
            .unwrap()
    }

    fn ephemeral_test_root() -> EphemeralKey {
        EphemeralKey::new_root(
            KeyType::P256,
            ephemeral_test_subject(),
            Validity::from_now(Duration::from_secs(60)).unwrap(),
        )
        .unwrap()
    }

    fn check_status_started(
        status: JobStatus,
        cert: &Certificate,
        expected_job_id: &JobId,
        expected_command: &str,
    ) {
        let JobStatus::Started {
            job,
            time_reserved,
            time_started,
            stdout_len: _,
            stderr_len: _,
        } = status
        else {
            panic!("expected job to be started");
        };
        assert_eq!(job.job_id, *expected_job_id);
        let job = job.verify(cert).unwrap();
        assert_eq!(job.command, expected_command);
        assert!(time_reserved < time_started);
        assert!(time_started < Utc::now());
    }

    fn check_status_ended(
        status: JobStatus,
        expected_job_id: &JobId,
        expected_command: &str,
        expected_status: Option<i32>,
        expected_stdout_len: u64,
        expected_stderr_len: u64,
    ) {
        let JobStatus::Ended {
            job,
            time_reserved,
            time_started,
            time_ended,
            status,
            stdout_len,
            stderr_len,
            stdout_hash: _,
            stderr_hash: _,
        } = status
        else {
            panic!("expected job to be finished");
        };
        assert_eq!(job.job_id, *expected_job_id);
        assert_eq!(job.command, expected_command);
        assert!(time_reserved < time_started);
        assert!(time_started < time_ended);
        assert!(time_ended < Utc::now());
        assert_eq!(status, expected_status);
        assert_eq!(stdout_len, expected_stdout_len);
        assert_eq!(stderr_len, expected_stderr_len);
    }

    async fn manager_and_test_root(
        db: Option<&str>,
        test_name: &'static str,
    ) -> (JobManager, EphemeralKey, TempDir) {
        let db = if let Some(db) = db {
            open_database(db).unwrap()
        } else {
            open_database_in_memory().unwrap()
        };
        db.set_limit(Limit::SQLITE_LIMIT_LENGTH, 10_000).unwrap();
        let decorator = PlainSyncDecorator::new(TestStdoutWriter);
        let drain = FullFormat::new(decorator).build().fuse();
        let dir = TempDir::with_prefix("sush-").unwrap();
        let log = Logger::root(drain, slog::o!("test" => test_name));
        let mgr = JobManager::new(db, dir.path(), log).await.unwrap();
        let root = ephemeral_test_root();
        let key_id = mgr.import_cert(root.cert(), true).await.unwrap();
        assert_eq!(key_id, root.key_id().await.unwrap());
        (mgr, root, dir)
    }

    #[named]
    #[tokio::test]
    async fn jobs() {
        let (mgr, root, _dir) = manager_and_test_root(None, function_name!()).await;
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
        let job = root.sign_job_request(&job_id, "true").await;
        assert!(matches!(
            mgr.job_status(&job_id).await.unwrap(),
            JobStatus::Reserved { job_id: id, time_reserved }
            if id == job_id && time_reserved < Utc::now(),
        ));

        let rx = mgr
            .job_start(job.clone(), JobLimits::default())
            .await
            .unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);

        let rx = mgr.job_start(job, JobLimits::default()).await.unwrap();
        assert!(
            matches!(
                rx.await.unwrap().unwrap_err().error(),
                JobError::InvalidJobId(id) if *id == job_id
            ),
            "should not be allowed to reuse a job ID"
        );

        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, "false").await;
        let rx = mgr.job_start(job, JobLimits::default()).await.unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_ended(status, &job_id, "false", Some(1), 0, 0);

        let job_id = job_ids.pop().unwrap();
        let job_id_string = job_id.to_string();
        let job_id_bytes = job_id_string.as_bytes();
        let job = root.sign_job_request(&job_id, "echo -n $SUSH_JOB_ID").await;
        let rx = mgr.job_start(job, JobLimits::default()).await.unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_ended(
            status,
            &job_id,
            "echo -n $SUSH_JOB_ID",
            Some(0),
            job_id_bytes.len() as u64,
            0,
        );
        assert_eq!(
            mgr.job_output(&job_id, Stdout, None).await.unwrap(),
            job_id_bytes
        );
        assert!(
            mgr.job_output(&job_id, Stderr, None)
                .await
                .unwrap()
                .is_empty()
        );

        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
    }

    #[named]
    #[tokio::test]
    async fn revoke() {
        let (mgr, root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, time_reserved) = mgr.reserve_one().await.unwrap();
        let job_ids = vec![job_id.clone()];
        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
        assert!(mgr.revoke_reserved(job_ids).await.unwrap().is_empty());

        let job = root.sign_job_request(&job_id, "false").await;
        let rx = mgr.job_start(job, JobLimits::default()).await.unwrap();
        assert!(
            matches!(
                rx.await.unwrap().unwrap_err().error(),
                JobError::InvalidJobId(id) if *id == job_id
            ),
            "should not be allowed to start a revoked job"
        );

        let status = mgr.job_status(&job_id).await.unwrap();
        assert!(matches!(status, JobStatus::NotFound));

        let (new_job_id, new_time_reserved) = mgr.reserve_one().await.unwrap();
        assert_ne!(new_job_id, job_id);
        assert!(new_time_reserved > time_reserved);

        let job_ids = vec![job_id.clone(), new_job_id.clone()];
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

    #[named]
    #[tokio::test]
    async fn abort() {
        let (mgr, root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();

        let command = "sleep 10";
        let job = root.sign_job_request(&job_id, command).await;
        let rx = mgr.job_start(job, JobLimits::default()).await.unwrap();

        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_started(status, root.cert(), &job_id, command);

        mgr.job_abort(&job_id).await.unwrap();
        assert_eq!(rx.await.unwrap().unwrap().job.job_id(), &job_id);

        let status = mgr.job_status(&job_id).await.unwrap();
        assert!(status.time_elapsed().unwrap().to_std().unwrap() < Duration::from_secs(1));
        check_status_ended(status, &job_id, command, None, 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn cert_chain() {
        let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
        let root =
            EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
        let root_key_id = root.key_id().await.unwrap();
        let root_cert = root.cert().to_owned();
        let issuer = root.subject();
        let subject = ephemeral_test_subject();
        let child = EphemeralKey::new_child(KeyType::Ed25519, subject, issuer, validity, &root)
            .await
            .unwrap();
        assert_ne!(child.key_id().await.unwrap(), root_key_id);

        let db = open_database_in_memory().unwrap();
        let dir = TempDir::with_prefix("sush-").unwrap();
        let log = Logger::root(slog::Discard, slog::o!("test" => function_name!()));
        let mgr = JobManager::new(db, dir.path(), log).await.unwrap();
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
        let job = child.sign_job_request(&job_id, "true").await;
        let rx = mgr.job_start(job, JobLimits::default()).await.unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn too_much_cpu() {
        let (mgr, root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();
        let command = "openssl speed sha1";
        let job = root.sign_job_request(&job_id, command).await;
        let rx = mgr
            .job_start(
                job,
                JobLimits {
                    max_cpu: 1,
                    max_fsize: 100,
                    ..JobLimits::default()
                },
            )
            .await
            .unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        assert!(status.time_elapsed().unwrap().to_std().unwrap() < Duration::from_secs(2));

        // The output of `openssl speed` changed between v3.0 and v3.5.
        let stderr = mgr.job_output(&job_id, Stderr, None).await.unwrap();
        let stderr = String::from_utf8_lossy(&stderr);
        match status {
            JobStatus::Ended { stderr_len: 37, .. } => {
                check_status_ended(status, &job_id, command, None, 0, 37);
                assert_eq!(stderr, "Doing sha1 for 3s on 16 size blocks: ");
            }
            JobStatus::Ended { stderr_len: 41, .. } => {
                check_status_ended(status, &job_id, command, None, 0, 41);
                assert_eq!(stderr, "Doing sha1 ops for 3s on 16 size blocks: ");
            }
            _ => todo!("what does `{command}` produce on your system?"),
        }
    }

    #[named]
    #[tokio::test]
    async fn output_ranges() {
        let (mgr, root, _dir) = manager_and_test_root(None, function_name!()).await;
        let JobsReserved {
            mut job_ids,
            time_reserved: _,
        } = mgr.reserve_jobs(1).await.unwrap();

        // Read some random bytes.
        let n = 1000;
        let command = &format!("head -c {n} /dev/urandom");
        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, command).await;
        let rx = mgr.job_start(job, JobLimits::default()).await.unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_ended(status, &job_id, command, Some(0), n, 0);

        // No range, i.e., full output.
        let r = mgr.job_output(&job_id, Stdout, None).await.unwrap();

        // One byte too big.
        assert!(matches!(
            mgr.job_output(
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(0),
                    end: EndPosition::Index(n),
                })
            )
            .await
            .unwrap_err(),
            JobError::InvalidRange(m) if m == n,
        ));

        // Whole range.
        assert_eq!(
            mgr.job_output(
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(0),
                    end: EndPosition::Index(n - 1),
                })
            )
            .await
            .unwrap(),
            r
        );

        // Two half-ranges.
        let mut o = mgr
            .job_output(
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(0),
                    end: EndPosition::Index(n / 2 - 1),
                }),
            )
            .await
            .unwrap();
        o.extend(
            mgr.job_output(
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(n / 2),
                    end: EndPosition::Index(n - 1),
                }),
            )
            .await
            .unwrap(),
        );
        assert_eq!(o, r);

        // Various ranges, from one byte to half.
        for l in 1..n / 2 {
            let mut i = 0;
            let mut o = vec![];
            while i + l < n {
                o.extend(
                    mgr.job_output(
                        &job_id,
                        Stdout,
                        Some(Range {
                            start: StartPosition::Index(i),
                            end: EndPosition::Index(i + l - 1),
                        }),
                    )
                    .await
                    .unwrap(),
                );
                i += l;
            }
            o.extend(
                mgr.job_output(
                    &job_id,
                    Stdout,
                    Some(Range {
                        start: StartPosition::Index(i),
                        end: EndPosition::Index(n - 1),
                    }),
                )
                .await
                .unwrap(),
            );
            assert_eq!(o, r);
        }
    }
}
