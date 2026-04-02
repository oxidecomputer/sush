//! Manage a set of jobs.
//!
//! The manager has exclusive access to the SQLite database. Jobs are
//! spawned onto new tokio tasks and passed to the monitor to wait for
//! completion. Standard output and standard error are saved in files.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::num::NonZeroU32;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use blake3::Hasher;
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use pwd::Passwd;
use rusqlite::{Connection, OptionalExtension as _, Row, prepare_cached_and_bind};
use rustix::io::close;
use rustix::process::{ioctl_tiocsctty, setsid};
use slog::{Logger, error, info, o};
use terminfo::Database as Terminfo;
use tokio::process::Command;
use tokio::spawn;
use tokio::sync::{mpsc, oneshot};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, DecodePem as _, Encode as _};

use sush_api::JobStartParams;
use sush_common::authn::{Credentials, Identity, Nonce};
use sush_common::codephrases::generate_id;
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
use sush_common::jobs::{
    JobId, JobOutputHash, JobStartRequest, JobStatus, JobsReserved, SignedJob, VerifiedJob,
};
use sush_common::keys::{KeyError, KeyId, Signature, SshPublicKey};
use sush_common::session::WindowSize;

use crate::error::{ExecutionError, JobError};
use crate::monitor::{ExecutionResult, JobEnded, JobMonitor, JobStarted, MonitorRequest};
use crate::pty::Pty;
use crate::session::SocketSender;

/// Self-signed (root) X.509 certificates. Self-signed certificates may
/// not be imported (except in test code), and so must be included here.
pub const ROOT_CERTS: &[&[u8]] = &[
    // export PERMSLIP_URL="https://permslip.inickles.0xeng.dev"
    // export SUSH_PERMSLIP_KEY="UNTRUSTED Support Shell Prototype"
    include_bytes!("../certs/sandbox.pem"),
];

/// Maximum certificate chain length.
const MAX_CERT_CHAIN_LEN: usize = 10;

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = ByteSize::mb(128).as_u64();

#[derive(Debug)]
pub struct JobManager {
    log: Logger,
    db: Arc<Mutex<Connection>>,
    output_dir: PathBuf,
    tx_monitor: mpsc::Sender<MonitorRequest>,
}

/// Call a closure with a new transaction, and commit it if the
/// closure returns success. We special-case `Unauthorized` so
/// that we may commit the new nonce.
macro_rules! with_transaction {
    ($db:expr, $f:expr) => {{
        let mut db = $db.lock().unwrap();
        let txn = db.transaction()?;
        match $f(&txn) {
            Ok(result) => {
                txn.commit()?;
                Ok(result)
            }
            Err(JobError::Unauthorized(nonce)) => {
                txn.rollback()?;
                insert_nonce(&db, &nonce)?;
                Err(JobError::Unauthorized(nonce))
            }
            Err(err) => {
                txn.rollback()?;
                Err(err)
            }
        }
    }};
}

impl JobManager {
    pub async fn new(log: Logger, mut db: Connection, output_dir: &Path) -> Result<Self, JobError> {
        // Import the root certificates.
        let txn = db.transaction()?;
        for root in ROOT_CERTS {
            let cert = Certificate::from_pem(root).or_else(|_| Certificate::from_der(root))?;
            let key_id = import_cert(&txn, &cert, true)?;
            info!(log, "imported root certificate"; "key_id" => %key_id);
        }
        txn.commit()?;
        let db = Arc::new(Mutex::new(db));

        // Start the monitor and listen for job-end events.
        let (tx_monitor, mut rx_monitor) =
            JobMonitor::start(log.new(o!("component" => "monitor")), output_dir.to_owned());
        spawn({
            let db = db.clone();
            let output_dir = output_dir.to_owned();
            async move {
                while let Some(end) = rx_monitor.recv().await {
                    with_transaction!(db, |txn| job_ended(txn, &output_dir, end))?;
                }
                Ok::<_, JobError>(())
            }
        });

        Ok(Self {
            log: log.new(o!("component" => "manager")),
            db,
            output_dir: output_dir.to_owned(),
            tx_monitor,
        })
    }

    #[cfg(test)]
    async fn import_root(&self, root: &Certificate) -> Result<KeyId, JobError> {
        with_transaction!(self.db, |txn| import_cert(txn, root, true))
    }

    pub async fn import_cert(&self, cert: &Certificate) -> Result<KeyId, JobError> {
        with_transaction!(self.db, |txn| import_cert(txn, cert, false))
    }

    pub async fn cert_chain(&self, key_id: &KeyId) -> Result<Vec<Certificate>, JobError> {
        with_transaction!(self.db, |txn| get_cert_chain(txn, key_id))
    }

    pub async fn iam(
        &self,
        authorization: Option<String>,
        public_key: Option<SshPublicKey>,
    ) -> Result<Identity, JobError> {
        with_transaction!(self.db, |txn| iam(
            &self.log,
            txn,
            authorization,
            public_key
        ))
    }

    pub async fn identities(
        &self,
        start: Option<KeyId>,
        limit: NonZeroU32,
        _authn: &Identity,
    ) -> Result<Vec<Identity>, JobError> {
        with_transaction!(self.db, |txn| get_identities(txn, start, limit))
    }

    pub async fn revoke_identity(&self, key_id: KeyId, _authn: &Identity) -> Result<(), JobError> {
        let sessions = with_transaction!(self.db, |txn| {
            revoke_identity(&self.log, txn, &key_id)?;
            get_sessions(txn, &key_id)
        })?;
        for job_id in sessions {
            self.monitor(MonitorRequest::Stop(job_id)).await?;
        }
        Ok(())
    }

    pub async fn reserve_jobs(&self, number: u8) -> Result<JobsReserved, JobError> {
        with_transaction!(self.db, |txn| reserve_jobs(txn, number))
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
        with_transaction!(self.db, get_reserved_jobs)
    }

    pub async fn revoke_reserved(&self, job_ids: Vec<JobId>) -> Result<Vec<JobId>, JobError> {
        with_transaction!(self.db, |txn| revoke_reserved_jobs(txn, &job_ids))
    }

    pub async fn job_start(
        &self,
        job: SignedJob,
        params: JobStartParams,
        authn: Option<Identity>,
    ) -> Result<Option<ExecutionResult>, JobError> {
        let wait = params.wait;
        let started = with_transaction!(self.db, |txn| job_start(
            &self.log,
            txn,
            &self.output_dir,
            job,
            params,
            authn
        ))?;

        let (tx, rx) = oneshot::channel();
        self.monitor(MonitorRequest::started(started, tx)).await?;
        if wait { Ok(Some(rx.await?)) } else { Ok(None) }
    }

    pub async fn job_session(
        &self,
        job_id: &JobId,
        authn: &Identity,
    ) -> Result<SocketSender, JobError> {
        with_transaction!(self.db, |txn| {
            let key_id = get_interactive(txn, job_id)?;
            if authn.key_id == key_id {
                Ok(())
            } else {
                error!(self.log, "incorrect identity for interactive job"; "key_id" => %key_id, "authn" => %authn.key_id);
                Err(JobError::unauthorized())
            }
        })?;

        let (tx_sender, rx_sender) = oneshot::channel();
        self.monitor(MonitorRequest::Session(job_id.to_owned(), tx_sender))
            .await?;
        rx_sender.await?
    }

    pub async fn job_status(&self, job_id: &JobId) -> Result<JobStatus, JobError> {
        with_transaction!(self.db, |txn| get_job_status(txn, &self.output_dir, job_id))
    }

    pub async fn job_abort(&self, job_id: &JobId) -> Result<(), JobError> {
        self.monitor(MonitorRequest::Stop(job_id.to_owned())).await
    }

    pub async fn job_output(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        get_job_output(&self.output_dir, job_id, stream, range)
    }

    pub async fn job_output_delete(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<u64, JobError> {
        delete_job_output(&self.output_dir, job_id, stream, range)
    }

    pub async fn job_history(
        &self,
        start: Option<JobId>,
        limit: NonZeroU32,
    ) -> Result<Vec<JobStatus>, JobError> {
        with_transaction!(self.db, |txn| get_job_history(
            txn,
            &self.output_dir,
            start,
            limit
        ))
    }

    async fn monitor(&self, request: MonitorRequest) -> Result<(), JobError> {
        self.tx_monitor
            .send(request)
            .await
            .map_err(JobError::closed)
    }
}

pub fn job_output_dir(base_dir: &Path, job_id: &JobId) -> PathBuf {
    base_dir.join("jobs").join(job_id.to_string())
}

pub fn job_output_path(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
    job_output_dir(base_dir, job_id).join(stream.as_str())
}

pub fn job_output_len(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> u64 {
    job_output_path(base_dir, job_id, stream)
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0)
}

pub fn job_output_hash(
    base_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
) -> Result<JobOutputHash, JobError> {
    let mut hasher = Hasher::new();
    let path = job_output_path(base_dir, job_id, stream);
    hasher
        .update_mmap_rayon(&path)
        .map_err(|err| JobError::file_io(path, err))?;
    Ok(hasher.finalize().into())
}

fn job_ended(db: &Connection, output_dir: &Path, result: ExecutionResult) -> Result<(), JobError> {
    match result {
        Err(ExecutionError {
            job_id,
            time,
            error: _,
        }) => {
            job_aborted(db, output_dir, &job_id, time)?;
        }
        Ok(JobEnded {
            job,
            time_reserved: _,
            time_started: _,
            time_ended,
            status,
            stdout_len: _,
            stderr_len: _,
            stdout_hash,
            stderr_hash,
        }) => {
            let job_id = job.job_id();
            let status = status.code();
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

fn job_start(
    log: &Logger,
    db: &Connection,
    output_dir: &Path,
    job: SignedJob,
    params: JobStartParams,
    authn: Option<Identity>,
) -> Result<JobStarted, JobError> {
    let job_id = job.job_id().to_owned();

    // Verify the job request.
    let time_reserved = verify_reservation(db, &job_id)?;
    let cert = get_cert(db, job.key_id())?;
    let job = job.verify_with_cert(&cert)?;
    if let Some(key_id) = job.interactive() {
        let Some(ref authn) = authn else {
            return Err(JobError::unauthorized());
        };
        if authn.key_id != *key_id {
            return Err(JobError::IdentityMismatch {
                interactive: key_id.to_owned(),
                authn: authn.key_id.to_owned(),
            });
        }
    }

    // Set up the job.
    let JobStartParams {
        limits,
        term,
        rows,
        cols,
        wait: _,
    } = params;
    let key_id = job.key_id().to_owned();
    let signature = job.signature().to_owned();
    let JobStartRequest {
        job_id,
        command,
        interactive,
    } = job.clone().into_payload();
    if command.starts_with('-') {
        return Err(JobError::InvalidCommand(command));
    }

    // Set up output files.
    let job_dir = job_output_dir(output_dir, &job_id);
    DirBuilder::new()
        .recursive(true)
        .create(&job_dir)
        .map_err(|err| JobError::file_io(job_dir, err))?;
    let stdout_path = job_output_path(output_dir, &job_id, Stdout);
    let stderr_path = job_output_path(output_dir, &job_id, Stderr);
    let stdout_file =
        File::create_new(&stdout_path).map_err(|err| JobError::file_io(&stdout_path, err))?;
    let stderr_file =
        File::create_new(&stderr_path).map_err(|err| JobError::file_io(&stderr_path, err))?;

    // Set up the job child process.
    let mut child = Command::new("bash");
    child
        .arg("-c")
        .arg(&command)
        .env_clear()
        .env("SSH_CLIENT", "sush") // read bashrc
        .env("SUSH_JOB_ID", job_id.to_string())
        .env("SUSH_COMMAND", &command)
        .kill_on_drop(true);

    // Set basic user environment.
    if let Some(pwd) = Passwd::current_user() {
        child
            .current_dir(&pwd.dir)
            .env("HOME", &pwd.dir)
            .env("LOGNAME", &pwd.name)
            .env("USER", &pwd.name);
    }

    let key_and_pty = if let Some(ref key_id) = interactive {
        // Create a pseudoterminal for interactive jobs and wire
        // the child up to it.
        let (pty, pts, pts_path) = Pty::open().map_err(|err| JobError::io("pty open", err))?;
        let pts_error = JobError::file_io_for(&pts_path);
        let pts_clone = || pts.try_clone().map_err(&pts_error);
        child
            .env("SUSH_IDENTITY", key_id.to_string())
            .env("SUSH_TTY", &pts_path)
            .stdin(pts_clone()?)
            .stdout(pts_clone()?)
            .stderr(pts_clone()?);

        unsafe {
            let pty = pty.as_raw_fd();
            child.pre_exec(move || {
                close(pty); // not needed in the child
                setsid()?; // create new process session
                ioctl_tiocsctty(&pts)?; // set controlling terminal
                limits.apply() // set process limits
            });
        }

        // If it has a valid terminfo database, set `TERM` and the
        // initial pseudoterminal window size.
        if let Some(term) = term
            && Terminfo::from_name(&term).is_ok()
        {
            child.env("TERM", term);
            if let Some(rows) = rows
                && let Some(cols) = cols
            {
                pty.set_window_size(WindowSize { rows, cols })
                    .map_err(|err| JobError::io("pty window resize", err))?;
            }
        };

        Some((key_id.to_owned(), pty))
    } else {
        // For batch jobs, close stdin and send output directly to files.
        child
            .stdin(Stdio::null())
            .stdout(stdout_file)
            .stderr(stderr_file);
        unsafe {
            child.pre_exec(move || limits.apply());
        }
        None
    };

    // Record the job start event.
    let time_started = Utc::now();
    let mut stmt = prepare_cached_and_bind!(
        db,
        "UPDATE jobs \
         SET key_id = $key_id, command = $command, interactive = $interactive, signature = $signature, time_started = $time_started \
         WHERE job_id = $job_id AND time_started IS NULL"
    );
    if stmt.raw_execute()? != 1 {
        return Err(JobError::InvalidJobId(job_id));
    }

    // Go!
    let child = child.spawn().map_err(|err| JobError::io("spawn", err))?;
    info!(log, "job started"; "job_id" => %job_id);
    Ok(JobStarted {
        job,
        time_reserved,
        time_started,
        child,
        interactive: key_and_pty,
    })
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

/// Return the cert chain in root-to-leaf order.
fn get_cert_chain(db: &Connection, key_id: &KeyId) -> Result<Vec<Certificate>, JobError> {
    let mut key_id = key_id.to_owned();
    let mut chain = Vec::new();
    loop {
        if chain.len() >= MAX_CERT_CHAIN_LEN {
            return Err(JobError::CertChainTooLong);
        }

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
            return Err(JobError::Key(KeyError::SelfSigned));
        }
        signature.verify_with_spki(&cert.tbs_certificate.to_der()?, spki)?;
    } else {
        let key_id = KeyId::try_from(issuer)?;
        let chain = get_cert_chain(db, &key_id)?;
        let issuer_cert = match chain.len() {
            0 => return Err(JobError::MissingCert(key_id)),
            n if n < MAX_CERT_CHAIN_LEN => chain.last().unwrap(),
            _ => return Err(JobError::CertChainTooLong),
        };
        let issuer_pki = &issuer_cert.tbs_certificate.subject_public_key_info;
        signature.verify_with_spki(&cert.tbs_certificate.to_der()?, issuer_pki)?;
    }

    let key_id = KeyId::try_from(subject)?;
    db.execute(
        "INSERT INTO certs(key_id, cert) VALUES(?1, ?2) \
         ON CONFLICT(key_id) DO UPDATE SET cert = ?2",
        (&key_id, cert.to_der()?),
    )?;
    Ok(key_id)
}

fn iam(
    log: &Logger,
    db: &Connection,
    authorization: Option<String>,
    key: Option<SshPublicKey>,
) -> Result<Identity, JobError> {
    // The client should (probably) not get detailed information back about
    // authentication failures, but debugging is much easier if we log full
    // errors here on the server.
    macro_rules! try_authn {
        ($expr:expr) => {
            match $expr {
                Ok(value) => Ok(value),
                Err(error) => {
                    error!(log, "authentication failed"; "error" => %error);
                    Err(error)
                }
            }
        }
    }

    if let Some(authorization) = authorization
        && let Ok(credentials) = try_authn!(authorization.parse())
        && let Credentials { key_id, nonce, .. } = &credentials
        && let Ok(key) = try_authn!(get_public_key(db, &key, key_id.clone(), nonce.clone()))
        && let response = credentials.into_challenge_response()
        && let Ok(verified) = try_authn!(response.verify_with_ssh_public_key(&key))
        && let Ok(identity) = try_authn!(Identity::new(key, verified))
    {
        let Identity {
            key_id,
            public_key,
            nonce,
            time_authenticated,
            time_revoked,
        } = &identity;
        assert!(
            time_revoked.is_none(),
            "should not authenticate a revoked identity"
        );
        prepare_cached_and_bind!(
            db,
            "INSERT OR REPLACE INTO authn (key_id, public_key, nonce, time_authenticated) \
             VALUES ($key_id, $public_key, $nonce, $time_authenticated)"
        )
        .raw_execute()?;
        info!(log, "authenticated credentials"; "nonce" => %nonce, "key_id" => %key_id);
        Ok(identity)
    } else {
        Err(JobError::unauthorized())
    }
}

fn insert_nonce(db: &Connection, nonce: &Nonce) -> Result<(), JobError> {
    prepare_cached_and_bind!(db, "INSERT INTO challenges VALUES ($nonce)").raw_execute()?;
    Ok(())
}

fn claim_nonce(db: &Connection, nonce: Nonce) -> Result<(), JobError> {
    let mut stmt = prepare_cached_and_bind!(db, "DELETE FROM challenges WHERE nonce = $nonce");
    if stmt.raw_execute()? == 1 {
        Ok(())
    } else {
        Err(JobError::NoSuchNonce(nonce))
    }
}

fn get_public_key(
    db: &Connection,
    public_key: &Option<SshPublicKey>,
    key_id: KeyId,
    nonce: Nonce,
) -> Result<SshPublicKey, JobError> {
    if let Some((stored_key, stored_nonce, time_revoked)) = db
        .prepare_cached(
            "SELECT public_key, nonce, time_revoked FROM authn WHERE key_id = ?1",
            // `--SEARCH authn USING INDEX sqlite_autoindex_authn_1 (key_id=?)
        )?
        .query_one(
            [&key_id],
            |row| -> Result<(SshPublicKey, Nonce, Option<DateTime<Utc>>), _> {
                Ok((
                    row.get("public_key")?,
                    row.get("nonce")?,
                    row.get("time_revoked")?,
                ))
            },
        )
        .optional()?
    {
        assert_eq!(
            stored_key
                .key_id()
                .expect("stored keys should have a valid ID"),
            key_id,
            "stored key ID does not match public key, database may be corrupt"
        );

        if let Some(time_revoked) = time_revoked {
            return Err(JobError::PublicKeyRevoked {
                key_id,
                time_revoked,
            });
        }

        if let Some(public_key) = public_key
            && *public_key != stored_key
        {
            return Err(JobError::PublicKeyMismatch(key_id.to_owned()));
        }

        if nonce != stored_nonce {
            claim_nonce(db, nonce)?;
        }

        Ok(stored_key)
    } else if let Some(public_key) = public_key
        && public_key.key_id().map(|id| id == key_id).unwrap_or(false)
    {
        claim_nonce(db, nonce)?;
        Ok(public_key.to_owned())
    } else {
        Err(JobError::PublicKeyNotFound(key_id.to_owned()))
    }
}

fn get_interactive(db: &Connection, job_id: &JobId) -> Result<KeyId, JobError> {
    if let Some(interactive) = db
        .prepare_cached(
            "SELECT interactive FROM jobs WHERE job_id = ?1 AND time_started IS NOT NULL",
        )?
        .query_one([job_id], |row| -> Result<KeyId, _> { row.get(0) })
        .optional()?
    {
        Ok(interactive)
    } else {
        Err(JobError::InvalidJobId(job_id.to_owned()))
    }
}

fn get_sessions(db: &Connection, key_id: &KeyId) -> Result<Vec<JobId>, JobError> {
    let mut stmt = prepare_cached_and_bind!(
        db,
        "SELECT job_id FROM jobs \
         WHERE interactive = $key_id AND \
               time_started IS NOT NULL AND \
               time_ended IS NULL"
    );
    // `--SCAN jobs USING COVERING INDEX current_sessions
    let mut rows = stmt.raw_query();
    let mut sessions = Vec::new();
    while let Some(row) = rows.next()? {
        sessions.push(row.get("job_id")?);
    }
    Ok(sessions)
}

fn get_identities(
    db: &Connection,
    start: Option<KeyId>,
    limit: NonZeroU32,
) -> Result<Vec<Identity>, JobError> {
    let mut stmt = if let Some(start) = start {
        prepare_cached_and_bind!(
            db,
            "SELECT * FROM authn WHERE key_id > $start ORDER BY key_id LIMIT $limit"
        )
        // `--SEARCH authn USING INDEX sqlite_autoindex_authn_1 (key_id<?)
    } else {
        prepare_cached_and_bind!(db, "SELECT * FROM authn ORDER BY key_id LIMIT $limit")
        // `--SCAN authn USING INDEX sqlite_autoindex_authn_1
    };
    let mut rows = stmt.raw_query();
    let mut identities = Vec::new();
    while let Some(row) = rows.next()? {
        identities.push(Identity {
            key_id: row.get("key_id")?,
            public_key: row.get("public_key")?,
            nonce: row.get("nonce")?,
            time_authenticated: row.get("time_authenticated")?,
            time_revoked: row.get("time_revoked")?,
        });
    }
    Ok(identities)
}

fn revoke_identity(log: &Logger, db: &Connection, key_id: &KeyId) -> Result<(), JobError> {
    let time_revoked = Utc::now();
    let mut stmt = prepare_cached_and_bind!(
        db,
        "UPDATE authn SET time_revoked = $time_revoked WHERE key_id = $key_id"
    );
    // `--SEARCH authn USING INDEX sqlite_autoindex_authn_1 (key_id=?)
    if stmt.raw_execute()? == 1 {
        info!(log, "revoked identity"; "key_id" => %key_id);
        Ok(())
    } else {
        Err(JobError::PublicKeyNotFound(key_id.to_owned()))
    }
}

fn reserve_jobs(db: &Connection, number: u8) -> Result<JobsReserved, JobError> {
    let time_reserved = Utc::now();
    let mut job_ids = Vec::new();
    {
        let mut stmt =
            db.prepare_cached("INSERT INTO jobs(job_id, time_reserved) VALUES(?1, ?2)")?;
        for _ in 0..number {
            let job_id = JobId::from(&generate_id());
            stmt.execute((&job_id, time_reserved))?;
            job_ids.push(job_id);
        }
    }
    Ok(JobsReserved {
        job_ids,
        time_reserved,
    })
}

fn get_reserved_jobs(db: &Connection) -> Result<BTreeMap<JobId, DateTime<Utc>>, JobError> {
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

fn revoke_reserved_jobs(db: &Connection, job_ids: &[JobId]) -> Result<Vec<JobId>, JobError> {
    let job_ids = if !job_ids.is_empty() {
        job_ids.to_vec()
    } else {
        get_reserved_jobs(db)?.keys().cloned().collect()
    };
    let mut revoked = Vec::new();
    {
        let mut stmt = db.prepare_cached(
            "DELETE FROM jobs WHERE job_id = ?1 AND time_started IS NULL",
            // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        )?;
        for job_id in job_ids {
            if stmt.execute([&job_id])? == 1 {
                revoked.push(job_id);
            }
        }
    }
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

fn get_job_output(
    output_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
    range: Option<Range>,
) -> Result<Vec<u8>, JobError> {
    let len = job_output_len(output_dir, job_id, stream);
    let path = job_output_path(output_dir, job_id, stream);
    let io_error = JobError::file_io_for(&path);
    let mut file = File::open(&path).map_err(|_| JobError::InvalidJobId(job_id.to_owned()))?;
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
}

fn delete_job_output(
    output_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
    range: Option<Range>,
) -> Result<u64, JobError> {
    let len = job_output_len(output_dir, job_id, stream);
    if let Some(Range {
        start: StartPosition::Index(n),
        end: EndPosition::LastByte,
    }) = range
        && n <= len
    {
        let path = job_output_path(output_dir, job_id, stream);
        let Ok(file) = OpenOptions::new().write(true).open(&path) else {
            return Ok(0);
        };
        file.set_len(n)
            .map_err(|err| JobError::file_io(&path, err))?;
        Ok(n)
    } else {
        Err(JobError::InvalidRange(len))
    }
}

fn get_job_status(
    db: &Connection,
    output_dir: &Path,
    job_id: &JobId,
) -> Result<JobStatus, JobError> {
    let mut stmt = prepare_cached_and_bind!(
        db,
        "SELECT * FROM jobs NATURAL LEFT JOIN certs WHERE job_id = $job_id"
    );
    // |--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
    // `--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?) LEFT-JOIN
    let mut rows = stmt.raw_query();
    if let Ok(Some(row)) = rows.next() {
        let status = make_job_row_to_status(output_dir)(row)?;
        assert!(
            rows.next()?.is_none(),
            "query on primary key should return at most one row"
        );
        Ok(status)
    } else {
        Err(JobError::InvalidJobId(job_id.to_owned()))
    }
}

fn get_job_history(
    db: &Connection,
    output_dir: &Path,
    start: Option<JobId>,
    limit: NonZeroU32,
) -> Result<Vec<JobStatus>, JobError> {
    let mut stmt = if let Some(start) = start {
        prepare_cached_and_bind!(
            db,
            "SELECT * FROM jobs NATURAL LEFT JOIN certs \
             WHERE time_started < (SELECT time_started FROM jobs WHERE job_id=$start) \
             ORDER by time_started DESC, time_reserved DESC \
             LIMIT $limit"
        )
        // |--SEARCH jobs USING INDEX jobs_time_started (time_started<?)
        // |--SCALAR SUBQUERY 1
        // |  `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        // |--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?) LEFT-JOIN
        // `--USE TEMP B-TREE FOR LAST TERM OF ORDER BY
    } else {
        prepare_cached_and_bind!(
            db,
            "SELECT * FROM jobs NATURAL LEFT JOIN certs \
             ORDER BY time_started DESC \
             LIMIT $limit"
        )
        // |--SCAN jobs USING INDEX jobs_time_started
        // `--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?) LEFT-JOIN
    };

    let job_row_to_status = make_job_row_to_status(output_dir);
    let mut rows = stmt.raw_query();
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        entries.push(job_row_to_status(row)?);
    }
    Ok(entries)
}

/// Return a closure over `output_dir` that constructs a [`JobStatus`]
/// from a row in the `jobs` table.
fn make_job_row_to_status(output_dir: &Path) -> impl Fn(&Row<'_>) -> Result<JobStatus, JobError> {
    move |row| {
        let job_id: JobId = row.get("job_id")?;
        let get_verified_job = || -> Result<VerifiedJob, JobError> {
            let cert = Certificate::from_der(&row.get::<_, Vec<u8>>("cert")?)?;
            Ok(SignedJob::new(
                JobStartRequest {
                    job_id: job_id.clone(),
                    command: row.get("command")?,
                    interactive: row.get("interactive")?,
                },
                row.get("key_id")?,
                row.get("signature")?,
            )
            .verify_with_cert(&cert)?)
        };

        if let Ok(time_ended) = row.get("time_ended") {
            Ok(JobStatus::Ended {
                job: get_verified_job()?,
                time_reserved: row.get("time_reserved")?,
                time_started: row.get("time_started")?,
                time_ended,
                status: row.get("status")?,
                stdout_len: job_output_len(output_dir, &job_id, Stdout),
                stderr_len: job_output_len(output_dir, &job_id, Stderr),
                stdout_hash: row.get("stdout_hash")?,
                stderr_hash: row.get("stderr_hash")?,
            })
        } else if let Ok(time_started) = row.get("time_started") {
            Ok(JobStatus::Started {
                job: get_verified_job()?,
                time_reserved: row.get("time_reserved")?,
                time_started,
                stdout_len: job_output_len(output_dir, &job_id, Stdout),
                stderr_len: job_output_len(output_dir, &job_id, Stderr),
            })
        } else if let Ok(time_reserved) = row.get("time_reserved") {
            Ok(JobStatus::Reserved {
                job_id: job_id.clone(),
                time_reserved,
            })
        } else {
            panic!("time_reserved should be NOT NULL")
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use function_name::named;
    use pwd::Passwd;
    use rand_core::{OsRng, RngCore as _};
    use rusqlite::limits::Limit;
    use slog::{Drain as _, o};
    use slog_term::{FullFormat, PlainSyncDecorator, TestStdoutWriter};
    use tempfile::TempDir;
    use tokio::time::sleep;
    use x509_cert::name::Name;
    use x509_cert::time::Validity;

    use sush_common::authn::{Challenge, ChallengeResponse};
    use sush_common::jobs::JobLimits;
    use sush_common::keys::{EphemeralKey, KeyType, Signer as _};

    #[allow(unused_imports)]
    use crate::database::{open_database, open_database_in_memory};

    use super::*;

    trait SignJobRequest {
        async fn sign_job_request<S: AsRef<str>>(
            &mut self,
            job_id: &JobId,
            command: S,
            interactive: Option<KeyId>,
        ) -> SignedJob;
    }

    impl SignJobRequest for EphemeralKey {
        async fn sign_job_request<S: AsRef<str>>(
            &mut self,
            job_id: &JobId,
            command: S,
            interactive: Option<KeyId>,
        ) -> SignedJob {
            self.sign(JobStartRequest::new(
                job_id.to_owned(),
                command,
                interactive,
            ))
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
        assert_eq!(job.command, expected_command);
        assert!(time_reserved < time_started);
        assert!(time_started < Utc::now());
        job.into_signed().verify_with_cert(cert).unwrap();
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
        let log = Logger::root(drain, o!("test" => test_name));
        let mgr = JobManager::new(log, db, dir.path()).await.unwrap();
        let root = ephemeral_test_root();
        let key_id = mgr.import_root(root.cert()).await.unwrap();
        assert_eq!(&key_id, root.key_id());
        (mgr, root, dir)
    }

    async fn job_status(mgr: &JobManager, job: SignedJob) -> JobStatus {
        mgr.job_start(job, JobStartParams::wait(), None)
            .await
            .expect("should be able to start job")
            .expect("should be waiting for job")
            .expect("job should end successfully")
            .into()
    }

    async fn job_error(mgr: &JobManager, job: SignedJob) -> JobError {
        mgr.job_start(job, JobStartParams::wait(), None)
            .await
            .expect_err("job should end with an error")
    }

    #[named]
    #[tokio::test]
    async fn jobs() {
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
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
        let job = root.sign_job_request(&job_id, "true", None).await;
        assert!(matches!(
            mgr.job_status(&job_id).await.unwrap(),
            JobStatus::Reserved { job_id: id, time_reserved }
            if id == job_id && time_reserved < Utc::now(),
        ));
        let status = job_status(&mgr, job.clone()).await;
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);

        assert!(
            matches!(
                job_error(&mgr, job).await,
                JobError::InvalidJobId(ref id) if *id == job_id
            ),
            "should not be allowed to reuse a job ID"
        );

        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, "false", None).await;
        let status = job_status(&mgr, job).await;
        check_status_ended(status, &job_id, "false", Some(1), 0, 0);

        let job_id = job_ids.pop().unwrap();
        let job_id_string = job_id.to_string();
        let job_id_bytes = job_id_string.as_bytes();
        let job = root
            .sign_job_request(&job_id, "echo -n $SUSH_JOB_ID", None)
            .await;
        let status = job_status(&mgr, job).await;
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

        let home = Passwd::current_user().unwrap().dir;
        let pwd = format!("{home}\n");
        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, "pwd", None).await;
        let status = job_status(&mgr, job).await;
        check_status_ended(status, &job_id, "pwd", Some(0), pwd.len() as u64, 0);
        assert_eq!(
            mgr.job_output(&job_id, Stdout, None).await.unwrap(),
            pwd.as_bytes(),
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
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, time_reserved) = mgr.reserve_one().await.unwrap();
        let job_ids = vec![job_id.clone()];
        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
        assert!(mgr.revoke_reserved(job_ids).await.unwrap().is_empty());

        let job = root.sign_job_request(&job_id, "false", None).await;
        assert!(
            matches!(
                job_error(&mgr, job).await,
                JobError::InvalidJobId(ref id) if *id == job_id
            ),
            "should not be allowed to start a revoked job"
        );
        assert!(
            matches!(
                mgr.job_status(&job_id).await.unwrap_err(),
                JobError::InvalidJobId(id) if id == job_id
            ),
            "revoked jobs should not have a status"
        );

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
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();

        // Start a long-running job.
        let command = "sleep 10";
        let job = root.sign_job_request(&job_id, command, None).await;
        assert!(
            mgr.job_start(job, JobStartParams::default(), None)
                .await
                .expect("should be able to start job")
                .is_none(),
            "should not be waiting for job"
        );

        // Check that the job is alive.
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_started(status, root.cert(), &job_id, command);

        // Kill the job and wait for it to die.
        mgr.job_abort(&job_id).await.unwrap();
        sleep(Duration::from_millis(10)).await;

        // Check that it's dead and that it didn't live for long.
        let status = mgr.job_status(&job_id).await.unwrap();
        assert!(status.time_elapsed().unwrap().to_std().unwrap() < Duration::from_secs(1));
        check_status_ended(status, &job_id, command, None, 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn cert_chain() {
        let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
        let mut root =
            EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
        let root_key_id = root.key_id().to_owned();
        let root_cert = root.cert().to_owned();
        let issuer = root.subject();
        let signature_algorithm = root.signature_algorithm();
        let subject = ephemeral_test_subject();
        let mut child = EphemeralKey::new_child(
            KeyType::Ed25519,
            subject,
            issuer,
            validity,
            &mut root,
            signature_algorithm,
        )
        .await
        .unwrap();
        assert_ne!(child.key_id(), &root_key_id);
        let child_key_id = child.key_id().to_owned();

        let db = open_database_in_memory().unwrap();
        let dir = TempDir::with_prefix("sush-").unwrap();
        let log = Logger::root(slog::Discard, slog::o!("test" => function_name!()));
        let mgr = JobManager::new(log, db, dir.path()).await.unwrap();
        assert!(
            matches!(
                mgr.import_cert(&root_cert).await.unwrap_err(),
                JobError::Key(KeyError::SelfSigned),
            ),
            "should not accept root cert without override"
        );
        assert!(
            matches!(
                mgr.import_cert(child.cert()).await.unwrap_err(),
                JobError::MissingCert(key_id) if key_id == root_key_id,
            ),
            "should not accept child cert without root"
        );
        assert_eq!(mgr.import_root(&root_cert).await.unwrap(), root_key_id);
        assert_eq!(
            mgr.cert_chain(&root_key_id).await.unwrap(),
            vec![root_cert.clone()]
        );
        assert_eq!(mgr.import_cert(child.cert()).await.unwrap(), child_key_id);
        assert_eq!(
            mgr.cert_chain(&child_key_id).await.unwrap(),
            vec![root_cert.clone(), child.cert().clone()]
        );

        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();
        let job = child.sign_job_request(&job_id, "true", None).await;
        let status = job_status(&mgr, job).await;
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn too_much_cpu() {
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();
        let command = "openssl speed sha1";
        let job = root.sign_job_request(&job_id, command, None).await;
        let status = JobStatus::from(
            mgr.job_start(
                job,
                JobStartParams {
                    limits: JobLimits {
                        max_cpu: 1,
                        max_fsize: 100,
                        ..Default::default()
                    },
                    wait: true,
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("should be able to start job")
            .expect("should be waiting for job")
            .expect("job should end successfully"),
        );
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
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let JobsReserved {
            mut job_ids,
            time_reserved: _,
        } = mgr.reserve_jobs(1).await.unwrap();

        // Read some random bytes.
        let n = 1000;
        let command = &format!("head -c {n} /dev/urandom");
        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, command, None).await;
        let status = job_status(&mgr, job).await;
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

    #[named]
    #[tokio::test]
    async fn iam() {
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let JobError::Unauthorized(nonce) = mgr.iam(None, None).await.unwrap_err() else {
            panic!("should not be authorized yet");
        };

        // Construct credentials.
        let challenge = Challenge::new(nonce.clone());
        let response = ChallengeResponse::new(challenge);
        let signed = root.sign(response).await.unwrap();
        let verified = signed.verify_with_cert(root.cert()).unwrap();
        let mut credentials = Credentials::new(verified);
        let public_key = root.ssh_public_key();
        let key_id = public_key.key_id().unwrap();
        credentials.key_id = key_id.clone(); // override cert key ID

        // Register our identity.
        let identity = mgr
            .iam(Some(credentials.to_string()), Some(public_key.clone()))
            .await
            .unwrap();
        let Identity {
            key_id: iam_key_id,
            public_key: iam_public_key,
            nonce: iam_nonce,
            time_authenticated: iam_authenticated,
            time_revoked: iam_revoked,
        } = identity.clone();
        assert_eq!(iam_key_id, key_id);
        assert_eq!(iam_public_key, public_key);
        assert_eq!(iam_nonce, nonce);
        assert!(iam_authenticated <= Utc::now());
        assert!(iam_revoked.is_none());

        // Authenticate successfully.
        assert_eq!(
            mgr.iam(Some(credentials.to_string()), None)
                .await
                .unwrap()
                .key_id,
            key_id,
        );

        // Revoke and check failure.
        mgr.revoke_identity(key_id.clone(), &identity)
            .await
            .unwrap();
        let JobError::Unauthorized(new_nonce) = mgr
            .iam(Some(credentials.to_string()), None)
            .await
            .unwrap_err()
        else {
            panic!("should no longer be authorized");
        };
        assert_ne!(new_nonce, nonce);

        // Even fresh credentials fail.
        let challenge = Challenge::new(new_nonce);
        let response = ChallengeResponse::new(challenge);
        let signed = root.sign(response).await.unwrap();
        let verified = signed.verify_with_cert(root.cert()).unwrap();
        let mut credentials = Credentials::new(verified);
        credentials.key_id = key_id.clone(); // override cert key ID
        mgr.iam(Some(credentials.to_string()), Some(public_key.clone()))
            .await
            .unwrap_err();
    }
}
