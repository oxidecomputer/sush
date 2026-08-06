// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Job manager tests.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::slice::from_ref;
use std::time::Duration;

use chrono::Utc;
use function_name::named;
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use pwd::Passwd;
use rumors::Peer;
use sled_hardware_types::BaseboardId;
use slog::{Discard, Logger, o};
use tempfile::TempDir;
use tokio::fs::{metadata, write};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use x509_cert::time::Validity;

use sush_api::{JobStartParams, JobStopParams, JobWait};
use sush_client::context::Authz;
use sush_common::authn::{Challenge, ChallengeResponse, Credentials, Identity, RequestKey};
use sush_common::jobs::{
    Access, JobId, JobLimits, JobOutputState, JobOutputStream::*, JobStatus, ProcessError, Session,
    SessionId,
};
use sush_common::keys::{EphemeralKey, KeyError, KeyId, KeyType, Signer as _, pem_cert_chain};
use sush_server::io::BATCH_OUTPUT_BUFFER_SIZE;
use sush_server::messages::v0::{CertRequest, Message, Request, SessionRequest};
use sush_server::output::{JobOutputDir, OutputDirs};
use sush_server::{JobError, JobManager, seed_gossip};

use crate::test_utils::{
    IntoBytes as _, SignJobRequest as _, ephemeral_test_root, ephemeral_test_subject,
    fake_identity, manager_and_test_root, manager_login, manager_test_root_and_peer,
    test_baseboard_id, test_logger,
};
use sush_server::executor::PathIsolation;

// Signal numbers for killed jobs.
const SIGKILL: i32 = 9;
const SIGXCPU: i32 = 24;

#[track_caller]
fn check_status_started(status: JobStatus, expected_job_id: &JobId) {
    let JobStatus::Started {
        job_id,
        time_started,
        ..
    } = status
    else {
        panic!("expected job to be started, instead it's {status:?}");
    };
    assert_eq!(job_id, *expected_job_id);
    assert!(time_started <= Utc::now());
}

#[track_caller]
fn check_status_stopped(
    status: JobStatus,
    expected_job_id: &JobId,
    expected_result: Result<i32, ProcessError>,
    expected_stdout_len: Option<u64>,
    expected_stderr_len: Option<u64>,
) {
    let JobStatus::Stopped {
        job_id,
        time_started,
        time_stopped,
        result,
        output:
            JobOutputState {
                stdout_len,
                stderr_len,
                ..
            },
    } = status
    else {
        panic!("expected job to be stopped, instead it's {status:?}");
    };
    assert_eq!(job_id, *expected_job_id);
    assert!(time_started < time_stopped);
    assert!(time_stopped <= Utc::now());
    assert_eq!(result, expected_result);
    if let Some(expected_len) = expected_stdout_len {
        assert_eq!(stdout_len, expected_len);
    }
    if let Some(expected_len) = expected_stderr_len {
        assert_eq!(stderr_len, expected_len);
    }
}

#[named]
#[tokio::test]
async fn jobs() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let mut session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();

    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "true", false).await;
    assert!(matches!(
        mgr.job_status(&authn, &job_id).await.unwrap_err(),
        JobError::JobNotFound(jid) if jid == job_id
    ));
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job.clone().into_signed());
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(status, &job_id, Ok(0), Some(0), Some(0));

    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "false", false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job.clone().into_signed());
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(status, &job_id, Ok(1), Some(0), Some(0));

    let job_id = session.next_job_id();
    let job_id_string = job_id.to_string();
    let job_id_bytes = job_id_string.as_bytes();
    let job = root
        .sign_job_request(&job_id, "echo -n $SUSH_JOB_ID", false)
        .await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job.clone().into_signed());
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[baseboard_id].clone();
    check_status_stopped(
        status,
        &job_id,
        Ok(0),
        Some(job_id_bytes.len() as u64),
        Some(0),
    );
    assert_eq!(
        mgr.job_output(&authn, &job_id, baseboard_id, Stdout, None)
            .await
            .unwrap()
            .into_bytes()
            .await,
        job_id_bytes
    );
    assert!(
        mgr.job_output(&authn, &job_id, baseboard_id, Stderr, None)
            .await
            .unwrap()
            .into_bytes()
            .await
            .is_empty()
    );

    let home = Passwd::current_user().unwrap().dir;
    let output = format!("{home}\n");
    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "pwd", false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job.clone().into_signed());
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[baseboard_id].clone();
    check_status_stopped(status, &job_id, Ok(0), Some(output.len() as u64), Some(0));
    assert_eq!(
        mgr.job_output(&authn, &job_id, baseboard_id, Stdout, None)
            .await
            .unwrap()
            .into_bytes()
            .await,
        output.as_bytes(),
    );
    assert!(
        mgr.job_output(&authn, &job_id, baseboard_id, Stderr, None)
            .await
            .unwrap()
            .into_bytes()
            .await
            .is_empty()
    );
}

#[named]
#[tokio::test]
async fn job_stop() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let mut session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();

    // Stopping a nonexistent job should mark it cancelled, and so succeed
    // immediately.
    let job_id = session.next_job_id();
    mgr.job_stop(
        &authn,
        &job_id,
        JobStopParams {
            wait: JobWait::Stop,
        },
    )
    .await
    .expect("should be able to stop a nonexistent job");

    assert!(matches!(
        &mgr.job_status(&authn, &job_id).await.unwrap()[baseboard_id],
        JobStatus::Cancelled { job_id: jid, time_cancelled, .. } if *jid == job_id && *time_cancelled <= Utc::now()
    ));

    // Skip the cancelled job.
    session.skip_job(job_id.clone());
    mgr.session_skip_job(&authn, session_id.clone(), job_id.clone())
        .await
        .expect("should be able to skip cancelled job");

    // Start a new (potentially) long-running job.
    let command = "sleep 10";
    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, command, false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Start,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job.clone().into_signed());

    // Check that the job is alive.
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[baseboard_id].clone();
    check_status_started(status, &job_id);

    // Kill the job and wait for it to die.
    mgr.job_stop(
        &authn,
        &job_id,
        JobStopParams {
            wait: JobWait::Stop,
        },
    )
    .await
    .expect("should be able to stop job");

    // Check that it's dead and that it didn't live for long.
    let status = mgr
        .job_status(&authn, &job_id)
        .await
        .expect("should be able to get status")
        .remove(baseboard_id)
        .expect("should have job status");
    assert!(status.time_elapsed().to_std().unwrap() < Duration::from_secs(1));
    check_status_stopped(
        status,
        &job_id,
        Err(ProcessError::Killed(SIGKILL)),
        Some(0),
        Some(0),
    );
}

#[named]
#[tokio::test]
async fn cancel_queued_job() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let mut session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();

    // Queue job A, which won't finish soon.
    let command_a = "sleep 10";
    let job_id_a = session.next_job_id();
    let job_a = root.sign_job_request(&job_id_a, command_a, false).await;
    mgr.job_start(
        &authn,
        job_a.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Start,
            ..Default::default()
        },
    )
    .await
    .expect("should be able to start job A");
    session.job_started(job_a.into_signed());

    // Queue job B ...
    let command_b = "false";
    let job_id_b = session.next_job_id();
    let job_b = root.sign_job_request(&job_id_b, command_b, false).await;
    mgr.job_start(
        &authn,
        job_b.clone().into_signed(),
        JobStartParams::default(),
    )
    .await
    .expect("should be able to queue job B");
    session.job_started(job_b.into_signed());
    mgr.wait_for_job_status(&job_id_b).await.unwrap();
    assert!(matches!(
        &mgr.job_status(&authn, &job_id_b).await.unwrap()[mgr.own_baseboard()],
        JobStatus::Queued { job_id: jid, time_queued, .. } if *jid == job_id_b && *time_queued <= Utc::now()
    ));

    // ... but immediately cancel it.
    mgr.job_stop(
        &authn,
        &job_id_b,
        JobStopParams {
            wait: JobWait::Stop,
        },
    )
    .await
    .expect("should be able to stop queued job");
    assert!(matches!(
        &mgr.job_status(&authn, &job_id_b).await.unwrap()[mgr.own_baseboard()],
        JobStatus::Cancelled { job_id: jid, time_cancelled, .. } if *jid == job_id_b && *time_cancelled <= Utc::now()
    ));

    // Clean up.
    mgr.job_stop(
        &authn,
        &job_id_a,
        JobStopParams {
            wait: JobWait::Stop,
        },
    )
    .await
    .expect("should be able to stop job A");
}

#[named]
#[tokio::test]
async fn job_output_perms() {
    let log = test_logger(function_name!());
    let (mgr, mut root, dir, _shutdown) = manager_and_test_root(log).await;
    let dir_perms = metadata(&dir).await.unwrap().permissions();
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();

    // Run a job with some output on both streams.
    let command = "echo -n foo && echo -n bar >&2";
    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, command, false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .expect("should be able to start job");
    let status = mgr
        .job_status(&authn, &job_id)
        .await
        .expect("should be able to get status")
        .remove(baseboard_id)
        .expect("should have job status");
    check_status_stopped(status, &job_id, Ok(0), Some(3), Some(3));

    // Job output root should not be changed.
    let out = JobOutputDir::fixed(dir.as_ref());
    assert_eq!(metadata(out.root()).await.unwrap().permissions(), dir_perms);

    // Check output directory and file permissions.
    async fn mode(path: &Path) -> u32 {
        metadata(path).await.unwrap().permissions().mode() & 0o777
    }
    assert_eq!(mode(&out.job_output_dir(&job_id)).await, 0o700);
    assert_eq!(mode(&out.job_output_path(&job_id, Stdout)).await, 0o600);
    assert_eq!(mode(&out.job_output_path(&job_id, Stderr)).await, 0o600);
}

#[named]
#[tokio::test]
async fn root_certs_from_files() {
    // The sled-agent embedding configures roots as paths, so the manager reads
    // them itself.
    let log = test_logger(function_name!());
    let dir = TempDir::with_prefix("sush-").unwrap();
    let mut root = ephemeral_test_root();
    let path = dir.path().join("root.pem");
    write(&path, pem_cert_chain(vec![root.cert().to_owned()]).unwrap())
        .await
        .unwrap();
    let mgr = JobManager::new(
        log,
        PathIsolation::InsecureDisable,
        JobOutputDir::fixed(dir.path()),
        test_baseboard_id(),
        seed_gossip(),
        &[path],
        CancellationToken::new(),
    )
    .await
    .unwrap();

    // A job signed by the configured root runs.
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();
    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "true", false).await;
    mgr.job_start(
        &authn,
        job.into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(status, &job_id, Ok(0), Some(0), Some(0));
}

#[named]
#[tokio::test]
async fn bad_root_cert_files() {
    // A trust store we can't read is an error, not an empty trust store.
    let log = test_logger(function_name!());
    let dir = TempDir::with_prefix("sush-").unwrap();
    let undecodable = dir.path().join("undecodable.pem");
    write(&undecodable, "not a certificate").await.unwrap();
    for path in [undecodable, dir.path().join("missing.pem")] {
        assert!(
            JobManager::new(
                log.clone(),
                PathIsolation::InsecureDisable,
                JobOutputDir::fixed(dir.path()),
                test_baseboard_id(),
                seed_gossip(),
                &[path],
                CancellationToken::new(),
            )
            .await
            .is_err()
        );
    }
}

#[named]
#[tokio::test]
async fn job_output_dir_moves() {
    // A server may move its output base part way through its life: sled-agent
    // records job output on a ramdisk until an encrypted dataset is mounted,
    // then moves to it. Output recorded before a move must stay readable.
    let log = test_logger(function_name!());
    let ramdisk = TempDir::with_prefix("sush-ramdisk-").unwrap();
    let encrypted = TempDir::with_prefix("sush-encrypted-").unwrap();
    let (tx_dirs, rx_dirs) = watch::channel(OutputDirs::new(
        ramdisk.path(),
        JobLimits::default().max_fsize,
    ));
    let mut root = ephemeral_test_root();
    let mgr = JobManager::with_root_certs(
        log,
        PathIsolation::InsecureDisable,
        JobOutputDir::new(rx_dirs),
        test_baseboard_id(),
        seed_gossip(),
        &[root.cert().to_owned()],
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let mut session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();

    // Record a job's output under the first base.
    let first = session.next_job_id();
    let job = root.sign_job_request(&first, "echo -n foo", false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job.clone().into_signed());
    assert!(
        metadata(ramdisk.path().join("jobs").join(first.to_string()))
            .await
            .is_ok()
    );

    // Move to the second base.
    tx_dirs.send_modify(|dirs| {
        *dirs = dirs.moved_to(encrypted.path(), JobLimits::default().max_fsize)
    });

    // The first job's output is still readable, from the base it was written to.
    assert_eq!(
        mgr.job_output(&authn, &first, baseboard_id, Stdout, None)
            .await
            .unwrap()
            .into_bytes()
            .await,
        b"foo".as_slice()
    );

    // New jobs are recorded under the new base.
    let second = session.next_job_id();
    let job = root.sign_job_request(&second, "echo -n bar", false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job.clone().into_signed());
    assert!(
        metadata(encrypted.path().join("jobs").join(second.to_string()))
            .await
            .is_ok()
    );
    assert_eq!(
        mgr.job_output(&authn, &second, baseboard_id, Stdout, None)
            .await
            .unwrap()
            .into_bytes()
            .await,
        b"bar".as_slice()
    );
}

#[named]
#[tokio::test]
async fn shutdown() {
    let log = test_logger(function_name!());
    let (mut mgr, mut root, _dir, shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();

    let command = "sleep 30";
    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, command, false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            limits: JobLimits::default(),
            wait: JobWait::Start,
            ..Default::default()
        },
    )
    .await
    .expect("should be able to start job");

    shutdown.cancel();
    timeout(Duration::from_secs(5), mgr.take_join_handle().unwrap())
        .await
        .expect("state manager failed to drain")
        .unwrap();

    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(
        status,
        &job_id,
        Err(ProcessError::Killed(SIGKILL)),
        Some(0),
        Some(0),
    );
}

#[named]
#[tokio::test]
async fn cert_chain() {
    // Build a two-level chain.
    let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
    let mut root =
        EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
    let root_key_id = root.key_id().to_owned();
    let root_cert = root.cert().to_owned();
    let roots = vec![root_cert.clone()];
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

    // Set up the manager.
    let authn = fake_identity(&mut root).await;
    let dir = TempDir::with_prefix("sush-").unwrap();
    let log = Logger::root(Discard, o!("test" => function_name!()));
    let baseboard = BaseboardId {
        part_number: "test part".to_string(),
        serial_number: "0000".to_string(),
    };
    let gossip = Peer::seed().into_rumors();
    let shutdown = CancellationToken::new();
    let mgr = JobManager::with_root_certs(
        log,
        PathIsolation::InsecureDisable,
        JobOutputDir::fixed(dir.path()),
        baseboard,
        gossip,
        &roots,
        shutdown,
    )
    .await
    .unwrap();

    // Test failure modes.
    assert!(
        matches!(
            mgr.cert_import(&authn, root_cert.clone(), false)
                .await
                .unwrap_err(),
            JobError::Key(KeyError::SelfSigned),
        ),
        "should not import root cert"
    );
    assert_eq!(
        mgr.cert_chain(&authn, &root_key_id).unwrap(),
        vec![root_cert.clone()]
    );
    timeout(
        Duration::from_secs(1),
        mgr.cert_import(&authn, child.cert().clone(), true),
    )
    .await
    .expect("timed out importing child")
    .expect("could not import child");
    assert_eq!(
        mgr.cert_chain(&authn, &child_key_id).unwrap(),
        vec![root_cert.clone(), child.cert().clone()]
    );

    // Start a job signed with the child.
    let session_id = SessionId::new();
    let mut session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id, true).await.unwrap();
    let job_id = session.next_job_id();
    let job = child.sign_job_request(&job_id, "true", false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job.clone().into_signed());
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(status, &job_id, Ok(0), Some(0), Some(0));
}

/// Requests record the verified key that made them: the session names
/// its starter, and queued and cancelled jobs name their actors.
#[named]
#[tokio::test]
async fn attribution() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let mut session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        mgr.session(&authn).unwrap().started_by(),
        Some(&authn.key_id)
    );

    // Job B queues behind a hole in the job chain, attributed. The
    // executor only runs the job whose id the chain expects next, and
    // it never sees this one, so B stays queued until cancelled.
    let job_id_a = session.next_job_id();
    let job_a = root.sign_job_request(&job_id_a, "sleep 60", false).await;
    mgr.job_start(
        &authn,
        job_a.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Start,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    session.job_started(job_a.into_signed());
    let hole_id = session.next_job_id();
    let hole = root.sign_job_request(&hole_id, "true", false).await;
    session.job_started(hole.into_signed());
    let job_id_b = session.next_job_id();
    let job_b = root.sign_job_request(&job_id_b, "true", false).await;
    mgr.job_start(
        &authn,
        job_b.clone().into_signed(),
        JobStartParams::default(),
    )
    .await
    .unwrap();
    session.job_started(job_b.into_signed());
    mgr.wait_for_job_status(&job_id_b).await.unwrap();
    let status = mgr.job_status(&authn, &job_id_b).await.unwrap()[mgr.own_baseboard()].clone();
    assert!(
        matches!(&status, JobStatus::Queued { actor, .. } if *actor == authn.key_id),
        "expected job B queued by us, got {status:?}"
    );

    // Cancelling B records the canceller.
    mgr.job_stop(
        &authn,
        &job_id_b,
        JobStopParams {
            wait: JobWait::Stop,
        },
    )
    .await
    .unwrap();
    let status = mgr.job_status(&authn, &job_id_b).await.unwrap()[mgr.own_baseboard()].clone();
    assert!(
        matches!(&status, JobStatus::Cancelled { actor, .. } if *actor == authn.key_id),
        "expected job B cancelled by us, got {status:?}"
    );
    mgr.job_stop(
        &authn,
        &job_id_a,
        JobStopParams {
            wait: JobWait::Stop,
        },
    )
    .await
    .unwrap();
}

/// A revocation that precedes its certificate still lands, and
/// revocation spam for made-up key IDs cannot block imports.
#[named]
#[tokio::test]
async fn revocation_tombstones() {
    let log = test_logger(function_name!());
    let (mgr, mut root, peer, _dir, _shutdown) = manager_test_root_and_peer(log).await;
    let authn = fake_identity(&mut root).await;
    let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
    let issuer = root.subject();
    let algorithm = root.signature_algorithm();
    let doomed = EphemeralKey::new_child(
        KeyType::P256,
        ephemeral_test_subject(),
        issuer.clone(),
        validity,
        &mut root,
        algorithm.clone(),
    )
    .await
    .unwrap();
    let spared = EphemeralKey::new_child(
        KeyType::P256,
        ephemeral_test_subject(),
        issuer,
        validity,
        &mut root,
        algorithm,
    )
    .await
    .unwrap();

    // Spam revocations for keys that will never exist, then revoke the
    // doomed child before anyone has seen its certificate.
    let revoke = |key_id: KeyId| {
        Message::Request(Request::cert(
            authn.key_id.clone(),
            CertRequest::Revoke(key_id, Utc::now()),
        ))
        .into()
    };
    for i in 0..200 {
        peer.send(revoke(KeyId::from(format!("bogus-{i}"))));
    }
    peer.send(revoke(doomed.key_id().clone()));

    // The revocation outlives the spam and refuses the import. The
    // spam blocks nothing else.
    peer.send(
        Message::Request(Request::cert(
            authn.key_id.clone(),
            CertRequest::Import(doomed.cert().clone()),
        ))
        .into(),
    );
    timeout(Duration::from_secs(30), async {
        loop {
            match mgr.cert_chain(&authn, doomed.key_id()) {
                Err(JobError::Key(KeyError::Revoked(..))) => break,
                _ => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("revocation never landed");
    timeout(
        Duration::from_secs(30),
        mgr.cert_import(&authn, spared.cert().clone(), true),
    )
    .await
    .expect("timed out importing spared child")
    .expect("could not import spared child");
}

/// Certificate revocation through the API: roots are refused, known
/// certificates stop validating, and unseen certificates are
/// tombstoned so their eventual import is refused.
#[named]
#[tokio::test]
async fn cert_revoke() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
    let issuer = root.subject();
    let algorithm = root.signature_algorithm();
    let child = EphemeralKey::new_child(
        KeyType::P256,
        ephemeral_test_subject(),
        issuer.clone(),
        validity,
        &mut root,
        algorithm.clone(),
    )
    .await
    .unwrap();
    let unseen = EphemeralKey::new_child(
        KeyType::P256,
        ephemeral_test_subject(),
        issuer,
        validity,
        &mut root,
        algorithm,
    )
    .await
    .unwrap();

    assert!(matches!(
        mgr.cert_revoke(&authn, root.key_id().clone(), false).await,
        Err(JobError::RootRevocation(_)),
    ));

    mgr.cert_import(&authn, child.cert().clone(), true)
        .await
        .unwrap();
    mgr.cert_revoke(&authn, child.key_id().clone(), true)
        .await
        .unwrap();
    assert!(matches!(
        mgr.cert_chain(&authn, child.key_id()),
        Err(JobError::Key(KeyError::Revoked(..))),
    ));

    mgr.cert_revoke(&authn, unseen.key_id().clone(), true)
        .await
        .unwrap();
    mgr.cert_import(&authn, unseen.cert().clone(), false)
        .await
        .unwrap();
    timeout(Duration::from_secs(30), async {
        loop {
            match mgr.cert_chain(&authn, unseen.key_id()) {
                Err(JobError::Key(KeyError::Revoked(..))) => break,
                _ => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("tombstone never consumed the import");
}

/// Identity revocation: live bound credentials die and the key may
/// not log back in.
#[named]
#[tokio::test]
async fn iam_revoke() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authz = manager_login(&mgr, &mut root).await.unwrap();
    let key_id = root.ssh_public_key().key_id().unwrap();
    let header = authz.header("GET", "/sessions");
    let authn = mgr
        .iam(Some(header), None, ("GET", "/sessions"))
        .await
        .unwrap();

    mgr.iam_revoke(&authn, key_id).await.unwrap();
    let header = authz.header("GET", "/sessions");
    assert!(
        mgr.iam(Some(header), None, ("GET", "/sessions"))
            .await
            .is_err()
    );
    assert!(manager_login(&mgr, &mut root).await.is_err());
}

/// Attach access: strangers are refused, the starter grants and
/// withdraws guest access mid-session, only the starter may grant, and
/// grants from non-starters over gossip are ignored.
#[named]
#[tokio::test]
async fn attach_grants() {
    let log = test_logger(function_name!());
    let (mgr, mut root, peer, _dir, _shutdown) = manager_test_root_and_peer(log).await;
    let owner = fake_identity(&mut root).await;
    let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
    let mut guest_key =
        EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
    let guest = fake_identity(&mut guest_key).await;

    let session_id = SessionId::new();
    let session = Session::new(session_id.clone());
    mgr.session_start(&owner, session_id.clone(), true)
        .await
        .unwrap();
    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "sleep 10", false).await;
    mgr.job_start(
        &owner,
        job.into_signed(),
        JobStartParams {
            wait: JobWait::Start,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // The starter attaches read-write; a stranger not at all; a guest
    // may not grant.
    let target = mgr.own_baseboard().clone();
    let attach = async |authn: Identity| mgr.job_attachment(&authn, &job_id, &target).await;
    assert!(matches!(
        attach(owner.clone()).await,
        Ok((_, Access::ReadWrite))
    ));
    assert!(matches!(
        attach(guest.clone()).await,
        Err(JobError::AttachDenied)
    ));
    assert!(matches!(
        mgr.session_allow_attach(
            &guest,
            session_id.clone(),
            owner.key_id.clone(),
            Access::ReadOnly
        )
        .await,
        Err(JobError::NotSessionStarter)
    ));

    // The starter grants read-only, upgrades to read-write, then
    // withdraws, all mid-session.
    let granted = async |authn: Identity, want: Option<Access>| {
        timeout(Duration::from_secs(30), async {
            loop {
                let access = match attach(authn.clone()).await {
                    Ok((_, access)) => Some(access),
                    Err(JobError::AttachDenied) => None,
                    Err(err) => panic!("unexpected attach error: {err}"),
                };
                if access == want {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("grant never took effect")
    };
    mgr.session_allow_attach(
        &owner,
        session_id.clone(),
        guest.key_id.clone(),
        Access::ReadOnly,
    )
    .await
    .unwrap();
    granted(guest.clone(), Some(Access::ReadOnly)).await;
    mgr.session_allow_attach(
        &owner,
        session_id.clone(),
        guest.key_id.clone(),
        Access::ReadWrite,
    )
    .await
    .unwrap();
    granted(guest.clone(), Some(Access::ReadWrite)).await;
    mgr.session_deny_attach(&owner, session_id.clone(), guest.key_id.clone())
        .await
        .unwrap();
    granted(guest.clone(), None).await;

    // A grant whose actor is not the starter is ignored. The starter's
    // grant of a third key, sent after it on the same handle, marks it
    // processed.
    let mut third_key =
        EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
    let third = fake_identity(&mut third_key).await;
    peer.send(
        Message::Request(Request::session(
            guest.key_id.clone(),
            SessionRequest::AllowAttach(
                session_id.clone(),
                guest.key_id.clone(),
                Access::ReadWrite,
            ),
        ))
        .into(),
    );
    peer.send(
        Message::Request(Request::session(
            owner.key_id.clone(),
            SessionRequest::AllowAttach(session_id, third.key_id.clone(), Access::ReadOnly),
        ))
        .into(),
    );
    granted(third.clone(), Some(Access::ReadOnly)).await;
    assert!(matches!(
        attach(guest.clone()).await,
        Err(JobError::AttachDenied)
    ));

    mgr.job_stop(
        &owner,
        &job_id,
        JobStopParams {
            wait: JobWait::Stop,
        },
    )
    .await
    .unwrap();
}

/// Hostile certificate imports over gossip cannot displace the trust
/// anchor or any established certificate.
#[named]
#[tokio::test]
async fn hostile_imports_cannot_displace() {
    let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
    let mut root =
        EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
    let root_cert = root.cert().to_owned();
    let root_key_id = root.key_id().to_owned();
    let issuer = root.subject();
    let algorithm = root.signature_algorithm();
    let mut child = EphemeralKey::new_child(
        KeyType::P256,
        ephemeral_test_subject(),
        issuer,
        validity,
        &mut root,
        algorithm.clone(),
    )
    .await
    .unwrap();

    let dir = TempDir::with_prefix("sush-").unwrap();
    let log = Logger::root(Discard, o!("test" => function_name!()));
    let baseboard = BaseboardId {
        part_number: "test part".to_string(),
        serial_number: "0000".to_string(),
    };
    let gossip = Peer::seed().into_rumors();
    let peer = gossip.clone();
    let shutdown = CancellationToken::new();
    let mgr = JobManager::new(
        log,
        PathIsolation::InsecureDisable,
        dir.path().to_owned(),
        baseboard,
        gossip,
        from_ref(&root_cert),
        shutdown,
    )
    .await
    .unwrap();
    let authn = fake_identity(&mut root).await;
    timeout(
        Duration::from_secs(1),
        mgr.cert_import(&authn, child.cert().clone(), true),
    )
    .await
    .expect("timed out importing child")
    .expect("could not import child");

    // A self-signed homonym of the root: same subject, different key,
    // and therefore a different key ID.
    let fake_root = EphemeralKey::new_root(KeyType::P256, root.subject(), validity).unwrap();
    assert_ne!(fake_root.key_id(), &root_key_id);
    let import = |key: &EphemeralKey| {
        Message::Request(Request::cert(
            key.key_id().clone(),
            CertRequest::Import(key.cert().clone()),
        ))
        .into()
    };
    peer.send(import(&fake_root));

    // A homonym of the root issued by an outsider.
    let mut outsider =
        EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
    let outsider_issuer = outsider.subject();
    let outsider_algorithm = outsider.signature_algorithm();
    let fake_delegate = EphemeralKey::new_child(
        KeyType::P256,
        root.subject(),
        outsider_issuer,
        validity,
        &mut outsider,
        outsider_algorithm,
    )
    .await
    .unwrap();
    peer.send(import(&fake_delegate));

    // A different certificate bearing the child's key.
    let mut conflict = child.cert().clone();
    conflict.tbs_certificate.validity = Validity::from_now(Duration::from_secs(120)).unwrap();
    peer.send(
        Message::Request(Request::cert(
            child.key_id().clone(),
            CertRequest::Import(conflict),
        ))
        .into(),
    );

    // A grandchild sent on the same handle marks the batch processed
    // once it validates.
    let child_issuer = child.subject();
    let grandchild = EphemeralKey::new_child(
        KeyType::P256,
        ephemeral_test_subject(),
        child_issuer,
        validity,
        &mut child,
        algorithm,
    )
    .await
    .unwrap();
    peer.send(import(&grandchild));
    timeout(Duration::from_secs(30), async {
        while mgr.cert_chain(&authn, grandchild.key_id()).is_err() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("grandchild never validated");

    // The anchor and the established chain are intact, and neither
    // homonym ever became usable.
    assert_eq!(
        mgr.cert_chain(&authn, &root_key_id).unwrap(),
        vec![root_cert.clone()]
    );
    assert_eq!(
        mgr.cert_chain(&authn, child.key_id()).unwrap(),
        vec![root_cert, child.cert().clone()]
    );
    assert!(mgr.cert_chain(&authn, fake_root.key_id()).is_err());
    assert!(mgr.cert_chain(&authn, fake_delegate.key_id()).is_err());
}

/// A certificate whose subject name matches another's cannot take its
/// place as an issuer: chains resolve through the key that verifies.
#[named]
#[tokio::test]
async fn homonym_issuer_resolves_to_true_parent() {
    let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
    let mut root =
        EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
    let root_cert = root.cert().to_owned();
    let issuer = root.subject();
    let algorithm = root.signature_algorithm();
    let shared_subject = ephemeral_test_subject();
    let mut child = EphemeralKey::new_child(
        KeyType::P256,
        shared_subject.clone(),
        issuer,
        validity,
        &mut root,
        algorithm.clone(),
    )
    .await
    .unwrap();
    let mut outsider =
        EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
    let outsider_issuer = outsider.subject();
    let outsider_algorithm = outsider.signature_algorithm();
    let homonym = EphemeralKey::new_child(
        KeyType::P256,
        shared_subject,
        outsider_issuer,
        validity,
        &mut outsider,
        outsider_algorithm,
    )
    .await
    .unwrap();
    assert_ne!(homonym.key_id(), child.key_id());

    let dir = TempDir::with_prefix("sush-").unwrap();
    let log = Logger::root(Discard, o!("test" => function_name!()));
    let baseboard = BaseboardId {
        part_number: "test part".to_string(),
        serial_number: "0000".to_string(),
    };
    let gossip = Peer::seed().into_rumors();
    let peer = gossip.clone();
    let shutdown = CancellationToken::new();
    let mgr = JobManager::new(
        log,
        PathIsolation::InsecureDisable,
        dir.path().to_owned(),
        baseboard,
        gossip,
        from_ref(&root_cert),
        shutdown,
    )
    .await
    .unwrap();
    let authn = fake_identity(&mut root).await;

    // The homonym arrives before the certificate it mimics, then the
    // real intermediate and a grandchild that names their shared
    // subject as its issuer.
    peer.send(
        Message::Request(Request::cert(
            homonym.key_id().clone(),
            CertRequest::Import(homonym.cert().clone()),
        ))
        .into(),
    );
    timeout(
        Duration::from_secs(1),
        mgr.cert_import(&authn, child.cert().clone(), true),
    )
    .await
    .expect("timed out importing child")
    .expect("could not import child");
    let child_issuer = child.subject();
    let grandchild = EphemeralKey::new_child(
        KeyType::P256,
        ephemeral_test_subject(),
        child_issuer,
        validity,
        &mut child,
        algorithm,
    )
    .await
    .unwrap();
    timeout(
        Duration::from_secs(1),
        mgr.cert_import(&authn, grandchild.cert().clone(), true),
    )
    .await
    .expect("timed out importing grandchild")
    .expect("could not import grandchild");

    // The chain runs through the key that verifies, and the homonym
    // never becomes usable, its issuer being a stranger.
    assert_eq!(
        mgr.cert_chain(&authn, grandchild.key_id()).unwrap(),
        vec![root_cert, child.cert().clone(), grandchild.cert().clone()]
    );
    assert!(mgr.cert_chain(&authn, homonym.key_id()).is_err());
}

#[named]
#[tokio::test]
async fn too_much_cpu() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();
    let job_id = session.next_job_id();
    let command = "openssl speed sha1";
    let job = root.sign_job_request(&job_id, command, false).await;
    let job_id = job.job_id().to_owned();
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            limits: JobLimits {
                max_cpu: 1,
                max_fsize: 100,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .expect("should be able to start job");
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    assert!(status.time_elapsed().to_std().unwrap() < Duration::from_secs(2));

    // The output of `openssl speed` changed between v3.0 and v3.5.
    let stderr = mgr
        .job_output(&authn, &job_id, baseboard_id, Stderr, None)
        .await
        .unwrap()
        .into_bytes()
        .await;
    let stderr = String::from_utf8_lossy(&stderr);
    match status {
        JobStatus::Stopped {
            output: JobOutputState { stderr_len: 37, .. },
            ..
        } => {
            check_status_stopped(
                status,
                &job_id,
                Err(ProcessError::Killed(SIGXCPU)),
                Some(0),
                Some(37),
            );
            assert_eq!(stderr, "Doing sha1 for 3s on 16 size blocks: ");
        }
        JobStatus::Stopped {
            output: JobOutputState { stderr_len: 41, .. },
            ..
        } => {
            check_status_stopped(
                status,
                &job_id,
                Err(ProcessError::Killed(SIGXCPU)),
                Some(0),
                Some(41),
            );
            assert_eq!(stderr, "Doing sha1 ops for 3s on 16 size blocks: ");
        }
        _ => todo!("what does `{command}` produce on your system?"),
    }
}

#[named]
#[tokio::test]
async fn too_much_output() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let mut session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();

    let job_id = session.next_job_id();
    let command = "yes";
    let job = root.sign_job_request(&job_id, command, false).await;
    let job_id = job.job_id().to_owned();
    let max_fsize = 0x10000;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            limits: JobLimits {
                max_fsize,
                ..Default::default()
            },
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .expect("should be able to start job");
    session.job_started(job.clone().into_signed());
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(
        status.clone(),
        &job_id,
        Err(ProcessError::OutputLimitExceeded {
            stream: Stdout,
            limit: max_fsize,
        }),
        None,
        Some(0),
    );
    assert!(matches!(
        status,
        JobStatus::Stopped {
            output: JobOutputState { stdout_len, .. },
            ..
        } if stdout_len >= max_fsize && stdout_len <= max_fsize + BATCH_OUTPUT_BUFFER_SIZE as u64
    ));

    let job_id = session.next_job_id();
    let command = "yes >&2";
    let job = root.sign_job_request(&job_id, command, false).await;
    let job_id = job.job_id().to_owned();
    let max_fsize = 0x10000;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            limits: JobLimits {
                max_fsize,
                ..Default::default()
            },
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .expect("should be able to start job");
    session.job_started(job.clone().into_signed());
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(
        status.clone(),
        &job_id,
        Err(ProcessError::OutputLimitExceeded {
            stream: Stderr,
            limit: max_fsize,
        }),
        Some(0),
        None,
    );
    assert!(matches!(
        status,
        JobStatus::Stopped {
            output: JobOutputState { stderr_len, .. },
            ..
        } if stderr_len >= max_fsize && stderr_len <= max_fsize + BATCH_OUTPUT_BUFFER_SIZE as u64
    ));
}

#[named]
#[tokio::test]
async fn output_ranges() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let session_id = SessionId::new();
    let session = Session::new(session_id.clone());
    mgr.session_start(&authn, session_id.clone(), true)
        .await
        .unwrap();
    let job_id = session.next_job_id();

    // Read some random bytes.
    let n = 1000;
    let command = &format!("head -c {n} /dev/urandom");
    let job = root.sign_job_request(&job_id, command, false).await;
    mgr.job_start(
        &authn,
        job.clone().into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(status, &job_id, Ok(0), Some(n), Some(0));

    // No range, i.e., full output.
    let r = mgr
        .job_output(&authn, &job_id, baseboard_id, Stdout, None)
        .await
        .unwrap()
        .into_bytes()
        .await;

    // One byte too big.
    assert!(matches!(
        mgr.job_output(
            &authn,
            &job_id,
                    baseboard_id,
            Stdout,
            Some(Range {
                start: StartPosition::Index(0),
                end: EndPosition::Index(n),
            }),
        )
        .await
        .unwrap_err(),
        JobError::InvalidRange(m) if m == n,
    ));

    // Whole range.
    assert_eq!(
        mgr.job_output(
            &authn,
            &job_id,
            baseboard_id,
            Stdout,
            Some(Range {
                start: StartPosition::Index(0),
                end: EndPosition::Index(n - 1),
            }),
        )
        .await
        .unwrap()
        .into_bytes()
        .await,
        r
    );

    // Two half-ranges.
    let mut o = mgr
        .job_output(
            &authn,
            &job_id,
            baseboard_id,
            Stdout,
            Some(Range {
                start: StartPosition::Index(0),
                end: EndPosition::Index(n / 2 - 1),
            }),
        )
        .await
        .unwrap()
        .into_bytes()
        .await;
    o.extend(
        mgr.job_output(
            &authn,
            &job_id,
            baseboard_id,
            Stdout,
            Some(Range {
                start: StartPosition::Index(n / 2),
                end: EndPosition::Index(n - 1),
            }),
        )
        .await
        .unwrap()
        .into_bytes()
        .await,
    );
    assert_eq!(o, r);

    // The first ten bytes, then the rest.
    let mut o = vec![];
    o.extend(
        mgr.job_output(
            &authn,
            &job_id,
            baseboard_id,
            Stdout,
            Some(Range {
                start: StartPosition::Index(0),
                end: EndPosition::Index(9),
            }),
        )
        .await
        .unwrap()
        .into_bytes()
        .await,
    );
    o.extend(
        mgr.job_output(
            &authn,
            &job_id,
            baseboard_id,
            Stdout,
            Some(Range {
                start: StartPosition::Index(10),
                end: EndPosition::LastByte,
            }),
        )
        .await
        .unwrap()
        .into_bytes()
        .await,
    );
    assert_eq!(o, r);

    // Just the last byte.
    let mut o = vec![];
    o.extend(
        mgr.job_output(
            &authn,
            &job_id,
            baseboard_id,
            Stdout,
            Some(Range {
                start: StartPosition::Index(n - 1),
                end: EndPosition::LastByte,
            }),
        )
        .await
        .unwrap()
        .into_bytes()
        .await,
    );
    assert_eq!(o, r[(n - 1) as usize..]);

    // Various ranges, from one byte to half.
    for l in 1..n / 2 {
        let mut i = 0;
        let mut o = vec![];
        while i + l < n {
            o.extend(
                mgr.job_output(
                    &authn,
                    &job_id,
                    baseboard_id,
                    Stdout,
                    Some(Range {
                        start: StartPosition::Index(i),
                        end: EndPosition::Index(i + l - 1),
                    }),
                )
                .await
                .unwrap()
                .into_bytes()
                .await,
            );
            i += l;
        }
        o.extend(
            mgr.job_output(
                &authn,
                &job_id,
                baseboard_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(i),
                    end: EndPosition::Index(n - 1),
                }),
            )
            .await
            .unwrap()
            .into_bytes()
            .await,
        );
        assert_eq!(o, r);
    }
}

#[named]
#[tokio::test]
async fn iam() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let JobError::Unauthorized(nonce) = mgr.iam(None, None, ("POST", "/iam")).await.unwrap_err()
    else {
        panic!("should not be authorized yet");
    };

    // Construct credentials.
    let challenge = Challenge::new(nonce.clone());
    let request_key = RequestKey::new();
    let response = ChallengeResponse::new(challenge, request_key.verifier());
    let signed = root.sign(response).await.unwrap();
    let verified = signed.verify_with_cert(root.cert()).unwrap();
    let mut credentials = Credentials::new(verified);
    let public_key = root.ssh_public_key();
    let key_id = public_key.key_id().unwrap();
    credentials.key_id = key_id.clone(); // override cert key ID

    // Register our identity. Initial credentials work only at `iam`.
    assert!(
        mgr.iam(
            Some(credentials.to_string()),
            Some(public_key.clone()),
            ("GET", "/sessions"),
        )
        .await
        .is_err()
    );
    let identity = mgr
        .iam(
            Some(credentials.to_string()),
            Some(public_key.clone()),
            ("POST", "/iam"),
        )
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
    assert_eq!(iam_nonce, credentials.nonce);
    assert!(iam_authenticated <= Utc::now());
    assert!(iam_revoked.is_none());

    // A bound request authorizes; replaying its header does not, nor
    // does presenting it against a different request line.
    let authz = Authz::new(credentials.clone(), request_key);
    let header = authz.header("GET", "/sessions");
    assert_eq!(
        mgr.iam(Some(header.clone()), None, ("GET", "/sessions"))
            .await
            .unwrap()
            .key_id,
        key_id,
    );
    assert!(
        mgr.iam(Some(header), None, ("GET", "/sessions"))
            .await
            .is_err()
    );
    let header = authz.header("GET", "/sessions");
    assert!(mgr.iam(Some(header), None, ("GET", "/jobs")).await.is_err());

    // Replayed initial credentials are rejected: the nonce is spent.
    assert!(
        mgr.iam(Some(credentials.to_string()), None, ("POST", "/iam"))
            .await
            .is_err()
    );
}
