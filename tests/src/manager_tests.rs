//! Job manager tests.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use function_name::named;
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use pwd::Passwd;
use rumors::Peer;
use sled_hardware_types::BaseboardId;
use slog::{Discard, Logger, o};
use tempfile::TempDir;
use tokio::fs::metadata;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use x509_cert::time::Validity;

use sush_api::{JobStartParams, JobStopParams, JobWait};
use sush_common::authn::{Challenge, ChallengeResponse, Credentials, Identity};
use sush_common::jobs::{
    JobId, JobLimits, JobOutputState, JobOutputStream::*, JobStatus, ProcessError, Session,
    SessionId,
};
use sush_common::keys::{EphemeralKey, KeyError, KeyType, Signer as _};
use sush_server::io::BATCH_OUTPUT_BUFFER_SIZE;
use sush_server::output::JobOutputDir;
use sush_server::{JobError, JobManager};

use crate::test_utils::{
    SignJobRequest as _, ephemeral_test_subject, fake_identity, manager_and_test_root, test_logger,
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
        JobStatus::Cancelled { job_id: jid, time_cancelled } if *jid == job_id && *time_cancelled <= Utc::now()
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
        JobStatus::Queued { job_id: jid, time_queued, } if *jid == job_id_b && *time_queued <= Utc::now()
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
        JobStatus::Cancelled { job_id: jid, time_cancelled } if *jid == job_id_b && *time_cancelled <= Utc::now()
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
    let out = JobOutputDir::new(dir.as_ref().to_owned());
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
    let mgr = JobManager::new(
        log,
        PathIsolation::InsecureDisable,
        dir.path().to_owned(),
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
            mgr.import_cert(&authn, root_cert.clone(), false)
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
        mgr.import_cert(&authn, child.cert().clone(), true),
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
    assert_eq!(iam_nonce, credentials.nonce);
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
}
