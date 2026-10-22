// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Job manager tests.

use std::mem::MaybeUninit;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::ptr::null_mut;
use std::time::Duration;

use chrono::Utc;
use function_name::named;
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use libc::{SIGTERM, SIGXCPU};
use pwd::Passwd;
use tempfile::TempDir;
use tokio::fs::{metadata, read, write};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use x509_cert::time::Validity;

use sush_api::{JobStartParams, JobStopParams, JobWait};
use sush_client::context::Authz;
use sush_common::authn::{Challenge, ChallengeResponse, Credentials, Identity, Nonce, RequestKey};
use sush_common::jobs::{
    Access, JobId, JobLimits, JobMode, JobOutputState, JobOutputStream::*, JobStartRequest,
    JobStatus, ProcessError, Session, SessionId, SessionPreimage, SessionSeq, SessionSignerNonce,
    SignedJob, SkipReason,
};
use sush_common::keys::{EphemeralKey, KeyError, KeyType, Signer as _, pem_cert_chain};
use sush_common::targets::{Cubbies, Target};
use sush_server::gossip::{LinkedBaseboards, Universe};
use sush_server::io::BATCH_OUTPUT_BUFFER_SIZE;
use sush_server::locker::Locker;
use sush_server::messages::v0::{IdentityRequest, Message, Request, SessionRequest};
use sush_server::output::{JobOutputDir, OutputDirs};
use sush_server::{JobError, JobManager};

use crate::test_utils::{
    IntoBytes as _, SessionCeremony, SignJobRequest as _, ephemeral_test_root,
    ephemeral_test_subject, fake_identity, manager_and_test_root, manager_test_root_and_peer,
    no_cubbies, null_gossip, session_ceremony, test_baseboard_id, test_logger,
};
use sush_server::executor::PathIsolation;

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
    let (mgr, mut root, dir, _shutdown) = manager_and_test_root(log).await;
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session_id, "true", false)
        .await;
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
    let job = root
        .sign_job_request(job_id, session_id, "false", false)
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
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(status, &job_id, Ok(1), Some(0), Some(0));

    let job_id = session.next_job_id();
    let job_id_string = job_id.to_string();
    let job_id_bytes = job_id_string.as_bytes();
    let job = root
        .sign_job_request(job_id, session_id, "echo -n $SUSH_JOB_ID", false)
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
    let job = root
        .sign_job_request(job_id, session_id, "pwd", false)
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

    let job_id = session.next_job_id();
    let output = dir
        .path()
        .join("jobs")
        .join(job_id.to_string())
        .display()
        .to_string();
    let job = root
        .sign_job_request(
            job_id,
            session.session_id(),
            "printf %s \"$SUSH_JOB_OUTPUT_DIR\"",
            false,
        )
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
    check_status_stopped(status, &job_id, Ok(0), Some(output.len() as u64), Some(0));
    assert_eq!(
        mgr.job_output(&authn, &job_id, baseboard_id, Stdout, None)
            .await
            .unwrap()
            .into_bytes()
            .await,
        output.as_bytes(),
    );
}

/// A job signed for anything but the active session is refused with
/// an error status, not silently discarded.
#[named]
#[tokio::test]
async fn job_session_enforced() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;

    // With no active session, submission fails at the front door.
    let ghost = Session::new(SessionId::random());
    let job = root
        .sign_job_request(ghost.next_job_id(), ghost.session_id(), "true", false)
        .await;
    assert!(matches!(
        mgr.job_start(&authn, job.clone().into_signed(), JobStartParams::default())
            .await,
        Err(JobError::NoSession)
    ));

    // With some other session active, likewise.
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();
    assert!(matches!(
        mgr.job_start(&authn, job.into_signed(), JobStartParams::default())
            .await,
        Err(JobError::SessionNotCurrent(id)) if id == ghost.session_id()
    ));
}

/// Only the next fetch consumes the server nonce: a failed start
/// leaves it alone, and so does activation.
#[named]
#[tokio::test]
async fn fetch_rotates_server_nonce() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;

    let ceremony = session_ceremony(&mgr, 1);
    let bogus = SessionId::random();
    assert!(matches!(
        mgr.session_start(
            &authn,
            bogus,
            ceremony.client_nonce,
            ceremony.signer_nonce,
            ceremony.seq,
            true,
        )
        .await,
        Err(JobError::InvalidSessionId)
    ));

    // The failed start left the server nonce alone, so the ceremony
    // still verifies.
    mgr.session_start(
        &authn,
        ceremony.session_id,
        ceremony.client_nonce,
        ceremony.signer_nonce,
        ceremony.seq,
        true,
    )
    .await
    .unwrap();

    // Activation leaves it alone too: a later grant over the same
    // sush nonce verifies and supersedes.
    let second = SessionPreimage {
        baseboard: mgr.own_baseboard().clone(),
        sush_nonce: ceremony.sush_nonce,
        signer_nonce: SessionSignerNonce::random(),
        seq: SessionSeq::from_unix_millis(2).unwrap(),
    };
    mgr.session_start(
        &authn,
        second.session_id(),
        ceremony.client_nonce,
        second.signer_nonce,
        second.seq,
        true,
    )
    .await
    .unwrap();

    // A fetch rotates: everything built over the old nonce is stale.
    mgr.fresh_server_nonce();
    let stale = SessionPreimage {
        baseboard: mgr.own_baseboard().clone(),
        sush_nonce: ceremony.sush_nonce,
        signer_nonce: SessionSignerNonce::random(),
        seq: ceremony.seq,
    };
    assert!(matches!(
        mgr.session_start(
            &authn,
            stale.session_id(),
            ceremony.client_nonce,
            stale.signer_nonce,
            stale.seq,
            true,
        )
        .await,
        Err(JobError::InvalidSessionId)
    ));
}

#[named]
#[tokio::test]
async fn job_stop() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
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
            ..Default::default()
        },
    )
    .await
    .expect("should be able to stop a nonexistent job");

    assert!(matches!(
        &mgr.job_status(&authn, &job_id).await.unwrap()[baseboard_id],
        JobStatus::Cancelled { job_id: jid, time_cancelled, .. } if *jid == job_id && *time_cancelled <= Utc::now()
    ));

    // Skip the cancelled job.
    session.skip_job(job_id);
    mgr.session_skip_job(&authn, session_id, job_id)
        .await
        .expect("should be able to skip cancelled job");

    // Start a new (potentially) long-running job.
    let command = "sleep 10";
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session_id, command, false)
        .await;
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
            ..Default::default()
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
        Err(ProcessError::Killed(SIGTERM)),
        Some(0),
        Some(0),
    );
}

/// Queue a job behind a hole in the job chain: the executor only runs
/// the job whose id the chain expects next, and it never sees the
/// hole's, so the queued job cannot start.
async fn queue_job_behind_hole(
    mgr: &JobManager,
    root: &mut EphemeralKey,
    authn: &Identity,
    session: &mut Session,
) -> JobId {
    let session_id = session.session_id();
    let hole_id = session.next_job_id();
    let hole = root
        .sign_job_request(hole_id, session_id, "true", false)
        .await;
    session.job_started(hole.into_signed());
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session_id, "false", false)
        .await;
    mgr.job_start(authn, job.clone().into_signed(), JobStartParams::default())
        .await
        .expect("should be able to queue the job");
    session.job_started(job.into_signed());
    mgr.wait_for_job_status(&job_id).await.unwrap();
    job_id
}

#[named]
#[tokio::test]
async fn cancel_queued_job() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    // Queue job A, which won't finish soon.
    let command_a = "sleep 10";
    let job_id_a = session.next_job_id();
    let job_a = root
        .sign_job_request(job_id_a, session_id, command_a, false)
        .await;
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

    let job_id_b = queue_job_behind_hole(&mgr, &mut root, &authn, &mut session).await;
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
            ..Default::default()
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
            ..Default::default()
        },
    )
    .await
    .expect("should be able to stop job A");
}

async fn wait_for_session_ended_skip(mgr: &JobManager, authn: &Identity, job_id: &JobId) {
    timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(map) = mgr.job_status(authn, job_id).await
                && matches!(
                    map.get(mgr.own_baseboard()),
                    Some(JobStatus::Skipped {
                        reason: SkipReason::SessionEnded,
                        ..
                    })
                )
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("job skipped for ended session");
}

#[named]
#[tokio::test]
async fn session_stop_skips_queued_jobs() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let job_id_a = session.next_job_id();
    let job_a = root
        .sign_job_request(job_id_a, session_id, "sleep 10", false)
        .await;
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

    let job_id_b = queue_job_behind_hole(&mgr, &mut root, &authn, &mut session).await;

    mgr.session_stop(&authn, session_id)
        .await
        .expect("should be able to stop the session");
    wait_for_session_ended_skip(&mgr, &authn, &job_id_b).await;

    assert!(matches!(
        &mgr.job_status(&authn, &job_id_a).await.unwrap()[mgr.own_baseboard()],
        JobStatus::Started { .. }
    ));

    mgr.job_stop(
        &authn,
        &job_id_a,
        JobStopParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .expect("should be able to stop job A");
}

#[named]
#[tokio::test]
async fn superseding_session_skips_queued_jobs() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let job_id = queue_job_behind_hole(&mgr, &mut root, &authn, &mut session).await;

    let SessionCeremony {
        session_id: new_session_id,
        client_nonce: new_client_nonce,
        signer_nonce: new_signer_nonce,
        seq: new_seq,
        ..
    } = session_ceremony(&mgr, 2);
    mgr.session_start(
        &authn,
        new_session_id,
        new_client_nonce,
        new_signer_nonce,
        new_seq,
        true,
    )
    .await
    .expect("should be able to start a superseding session");
    wait_for_session_ended_skip(&mgr, &authn, &job_id).await;
}

#[named]
#[tokio::test]
async fn job_output_perms() {
    let log = test_logger(function_name!());
    let (mgr, mut root, dir, _shutdown) = manager_and_test_root(log).await;
    let dir_perms = metadata(&dir).await.unwrap().permissions();
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    // Run a job with some output on both streams.
    let command = "echo -n foo && echo -n bar >&2";
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session_id, command, false)
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
async fn cubby_targets() {
    // A cubby target only matches through the rack's cubby map.
    let log = test_logger(function_name!());
    let dir = TempDir::with_prefix("sush-").unwrap();
    let mut root = ephemeral_test_root();
    let (cubbies, cubbies_rx) = watch::channel(Cubbies::new());
    let mgr = JobManager::with_trust_anchors(
        log,
        PathIsolation::InsecureDisable,
        JobOutputDir::fixed(dir.path()),
        test_baseboard_id(),
        cubbies_rx,
        Universe::isolated(null_gossip().await),
        LinkedBaseboards::lonely(),
        &Locker::null(),
        &[root.cert().to_owned()],
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();
    let target: Target = "14".parse().unwrap();

    // With the map empty, a cubby-targeted job records no status here.
    // The all-target job behind it in the session's job chain proves
    // it was processed, not merely still queued.
    let skipped_id = session.next_job_id();
    let job = root
        .sign_job_request_for(skipped_id, session_id, "true", false, target.clone())
        .await;
    mgr.job_start(&authn, job.clone().into_signed(), JobStartParams::default())
        .await
        .unwrap();
    session.job_started(job.into_signed());
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session_id, "true", false)
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
    session.job_started(job.into_signed());
    assert!(matches!(
        mgr.job_status(&authn, &skipped_id).await.unwrap_err(),
        JobError::JobNotFound(jid) if jid == skipped_id
    ));

    // Name this baseboard in the map. The update lands whenever the
    // state task gets to it, so probe with fresh jobs until one takes.
    cubbies
        .send(Cubbies::from([(14, test_baseboard_id())]))
        .unwrap();
    loop {
        let job_id = session.next_job_id();
        let job = root
            .sign_job_request_for(job_id, session_id, "true", false, target.clone())
            .await;
        mgr.job_start(&authn, job.clone().into_signed(), JobStartParams::default())
            .await
            .unwrap();
        session.job_started(job.into_signed());
        sleep(Duration::from_millis(50)).await;
        if mgr.job_status(&authn, &job_id).await.is_ok() {
            break;
        }
    }

    // Now cubby-targeted jobs run here.
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request_for(job_id, session_id, "true", false, target)
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
    session.job_started(job.into_signed());
    let status = mgr.job_status(&authn, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(status, &job_id, Ok(0), Some(0), Some(0));
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
        no_cubbies(),
        Universe::isolated(null_gossip().await),
        LinkedBaseboards::lonely(),
        &Locker::null(),
        &[path],
        CancellationToken::new(),
    )
    .await
    .unwrap();

    // A job signed by the configured root runs.
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session_id, "true", false)
        .await;
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
                no_cubbies(),
                Universe::isolated(null_gossip().await),
                LinkedBaseboards::lonely(),
                &Locker::null(),
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
    let mgr = JobManager::with_trust_anchors(
        log,
        PathIsolation::InsecureDisable,
        JobOutputDir::new(rx_dirs),
        test_baseboard_id(),
        no_cubbies(),
        Universe::isolated(null_gossip().await),
        LinkedBaseboards::lonely(),
        &Locker::null(),
        &[root.cert().to_owned()],
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    // Record a job's output under the first base.
    let first = session.next_job_id();
    let job = root
        .sign_job_request(first, session_id, "echo -n foo", false)
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
    let job = root
        .sign_job_request(second, session_id, "echo -n bar", false)
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
async fn universe_swap() {
    // A universe migration resets the state machine. Sessions,
    // history, and in-flight jobs die with the old universe, nothing
    // about them reaches the new one, and the manager keeps serving.
    let log = test_logger(function_name!());
    let dir = TempDir::with_prefix("sush-").unwrap();
    let mut root = ephemeral_test_root();
    let (universe, universe_rx) = watch::channel(Universe::genesis(null_gossip().await));
    let mgr = JobManager::with_trust_anchors(
        log,
        PathIsolation::InsecureDisable,
        JobOutputDir::fixed(dir.path()),
        test_baseboard_id(),
        no_cubbies(),
        universe_rx,
        LinkedBaseboards::lonely(),
        &Locker::null(),
        &[root.cert().to_owned()],
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let authn = fake_identity(&mut root).await;

    async fn run_job(
        mgr: &JobManager,
        root: &mut EphemeralKey,
        authn: &Identity,
        seq: u64,
    ) -> JobId {
        let SessionCeremony {
            session_id,
            client_nonce,
            signer_nonce,
            seq,
            ..
        } = session_ceremony(mgr, seq);
        let session = Session::new(session_id);
        mgr.session_start(authn, session_id, client_nonce, signer_nonce, seq, true)
            .await
            .unwrap();
        let job_id = session.next_job_id();
        let job = root
            .sign_job_request(job_id, session_id, "true", false)
            .await;
        mgr.job_start(
            authn,
            job.into_signed(),
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        job_id
    }

    // Run a job to completion in the first universe, and leave a
    // second one running at the swap.
    let job_id = run_job(&mgr, &mut root, &authn, 1).await;
    assert!(mgr.job_status(&authn, &job_id).await.is_ok());
    let session = mgr.session(&authn).expect("live session");
    let lingering = session.next_job_id();
    let job = root
        .sign_job_request(lingering, session.session_id(), "sleep 600", false)
        .await;
    mgr.job_start(
        &authn,
        job.into_signed(),
        JobStartParams {
            wait: JobWait::Start,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Migrate. The session and the jobs die with the old universe.
    universe
        .send(Universe::genesis(null_gossip().await))
        .unwrap();
    timeout(Duration::from_secs(30), async {
        while mgr.session(&authn).is_some() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("state reset");

    // The manager serves the new universe. Running a fresh job also
    // orders this check after the swap has fully settled.
    run_job(&mgr, &mut root, &authn, 2).await;

    // Nothing about the old universe's jobs crossed over: not the
    // completed job's history, and not the killed job's ending.
    for old in [job_id, lingering] {
        assert!(matches!(
            mgr.job_status(&authn, &old).await,
            Err(JobError::JobNotFound(_)),
        ));
    }
}

#[named]
#[tokio::test]
async fn shutdown() {
    let log = test_logger(function_name!());
    let (mut mgr, mut root, _dir, shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let command = "sleep 30";
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session_id, command, false)
        .await;
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
        Err(ProcessError::Killed(SIGTERM)),
        Some(0),
        Some(0),
    );
}

/// A root anchor's chain is the anchor itself, and a key outside the
/// baked anchor set has no chain.
#[named]
#[tokio::test]
async fn cert_chain() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    assert_eq!(
        mgr.cert_chain(&authn, root.key_id()).unwrap(),
        vec![root.cert().clone()]
    );
    let other = EphemeralKey::new_root(
        KeyType::P256,
        ephemeral_test_subject(),
        Validity::from_now(Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        mgr.cert_chain(&authn, other.key_id()),
        Err(JobError::Key(KeyError::MissingCert(_))),
    ));
}

/// Requests record the verified key that made them: the session names
/// its starter, and queued and cancelled jobs name their actors.
#[named]
#[tokio::test]
async fn attribution() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
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
    let job_a = root
        .sign_job_request(job_id_a, session_id, "sleep 60", false)
        .await;
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
    let hole = root
        .sign_job_request(hole_id, session_id, "true", false)
        .await;
    session.job_started(hole.into_signed());
    let job_id_b = session.next_job_id();
    let job_b = root
        .sign_job_request(job_id_b, session_id, "true", false)
        .await;
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
            ..Default::default()
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
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

/// A job runs only on the sleds its signed target names. Jobs naming
/// another baseboard, or a cubby while no mapping is known, are
/// processed but never run here, and the causal chain moves on.
#[named]
#[tokio::test]
async fn job_targets() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let mut start = async |command: &str, target: &str| {
        let job_id = session.next_job_id();
        let request = JobStartRequest::new(
            job_id,
            session_id,
            command,
            JobMode::Batch,
            target.parse().unwrap(),
        );
        let job = root
            .sign(request)
            .await
            .unwrap()
            .verify_with_cert(root.cert())
            .unwrap();
        mgr.job_start(&authn, job.clone().into_signed(), JobStartParams::default())
            .await
            .unwrap();
        session.job_started(job.into_signed());
        job_id
    };

    let elsewhere = start("true", "913-0000019:BRM00000000").await;
    let by_cubby = start("true", "14").await;
    let here = start("true", &test_baseboard_id().to_string()).await;

    // The targeted job runs, which proves the untargeted ones were
    // already processed and skipped.
    timeout(Duration::from_secs(30), mgr.wait_for_job_status(&here))
        .await
        .expect("timed out waiting for targeted job")
        .unwrap();
    for skipped in [elsewhere, by_cubby] {
        assert!(matches!(
            mgr.job_status(&authn, &skipped).await,
            Err(JobError::JobNotFound(_)),
        ));
    }
}

/// A login gossips as evidence every sled verifies for itself: real
/// evidence authorizes bound requests with no local login, and
/// fabricated evidence registers nothing.
#[named]
#[tokio::test]
async fn gossiped_identities() {
    let log = test_logger(function_name!());
    let (mgr, mut root, peer, _dir, _shutdown) = manager_test_root_and_peer(log).await;
    let mut liar = ephemeral_test_root();
    let root_pk = root.ssh_public_key();
    let root_key_id = root_pk.key_id().unwrap();

    // A liar claims root's key with evidence signed by their own.
    let bogus_key = RequestKey::new();
    let bogus = ChallengeResponse::new(Challenge::new(Nonce::random()), bogus_key.verifier());
    let signed_by_liar = liar.sign(bogus).await.unwrap();
    let bogus_verified = signed_by_liar
        .clone()
        .verify_with_ssh_public_key(&liar.ssh_public_key())
        .unwrap();
    let mut bogus_credentials = Credentials::new(bogus_verified);
    bogus_credentials.key_id = root_key_id.clone();
    let bogus_authz = Authz::new(bogus_credentials, bogus_key);
    peer.send(
        Message::Request(Request::identity(
            root_key_id.clone(),
            IdentityRequest::Login(root_pk.to_openssh().unwrap(), signed_by_liar),
        ))
        .into(),
    )
    .unwrap();

    // Real evidence authorizes here without ever logging in here.
    let request_key = RequestKey::new();
    let response = ChallengeResponse::new(Challenge::new(Nonce::random()), request_key.verifier());
    let signed = root.sign(response).await.unwrap();
    let verified = signed.clone().verify_with_ssh_public_key(&root_pk).unwrap();
    let mut credentials = Credentials::new(verified);
    credentials.key_id = root_key_id.clone();
    peer.send(
        Message::Request(Request::identity(
            root_key_id.clone(),
            IdentityRequest::Login(root_pk.to_openssh().unwrap(), signed),
        ))
        .into(),
    )
    .unwrap();
    let authz = Authz::new(credentials, request_key);
    let authn = timeout(Duration::from_secs(30), async {
        loop {
            let header = authz.header("GET", "/sessions");
            match mgr.iam(Some(header), None, ("GET", "/sessions")).await {
                Ok(authn) => break authn,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("gossiped login never registered");
    assert_eq!(authn.key_id, root_key_id);

    // The fabricated login was processed before the real one on the
    // same handle, and registered nothing.
    let header = bogus_authz.header("GET", "/sessions");
    assert!(
        mgr.iam(Some(header), None, ("GET", "/sessions"))
            .await
            .is_err()
    );
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

    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let session = Session::new(session_id);
    mgr.session_start(&owner, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session_id, "sleep 10", false)
        .await;
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
        mgr.session_allow_attach(&guest, session_id, owner.key_id.clone(), Access::ReadOnly)
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
    mgr.session_allow_attach(&owner, session_id, guest.key_id.clone(), Access::ReadOnly)
        .await
        .unwrap();
    granted(guest.clone(), Some(Access::ReadOnly)).await;
    mgr.session_allow_attach(&owner, session_id, guest.key_id.clone(), Access::ReadWrite)
        .await
        .unwrap();
    granted(guest.clone(), Some(Access::ReadWrite)).await;
    mgr.session_deny_attach(&owner, session_id, guest.key_id.clone())
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
            SessionRequest::AllowAttach(session_id, guest.key_id.clone(), Access::ReadWrite),
        ))
        .into(),
    )
    .unwrap();
    peer.send(
        Message::Request(Request::session(
            owner.key_id.clone(),
            SessionRequest::AllowAttach(session_id, third.key_id.clone(), Access::ReadOnly),
        ))
        .into(),
    )
    .unwrap();
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
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

/// Only the session starter may skip or stop a session, a skip must
/// name the session's next job, and non-starter requests over gossip
/// are ignored.
#[named]
#[tokio::test]
async fn skip_and_stop_are_starter_only() {
    let log = test_logger(function_name!());
    let (mgr, mut root, peer, _dir, _shutdown) = manager_test_root_and_peer(log).await;
    let owner = fake_identity(&mut root).await;
    let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
    let mut guest_key =
        EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
    let guest = fake_identity(&mut guest_key).await;

    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let job_id = Session::new(session_id).next_job_id();
    mgr.session_start(&owner, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    assert!(matches!(
        mgr.session_skip_job(&guest, session_id, job_id).await,
        Err(JobError::NotSessionStarter)
    ));
    assert!(matches!(
        mgr.session_stop(&guest, session_id).await,
        Err(JobError::NotSessionStarter)
    ));
    assert!(matches!(
        mgr.session_skip_job(&owner, session_id, JobId::random())
            .await,
        Err(JobError::NotNextJob(_))
    ));

    // Requests naming a stale session fail rather than enqueue.
    let stale = SessionId::random();
    assert!(matches!(
        mgr.session_stop(&owner, stale).await,
        Err(JobError::SessionNotCurrent(_))
    ));
    assert!(matches!(
        mgr.session_skip_job(&owner, stale, job_id).await,
        Err(JobError::SessionNotCurrent(_))
    ));
    assert!(matches!(
        mgr.session_allow_attach(&owner, stale, guest.key_id.clone(), Access::ReadOnly)
            .await,
        Err(JobError::SessionNotCurrent(_))
    ));
    assert!(matches!(
        mgr.session_deny_attach(&owner, stale, guest.key_id.clone())
            .await,
        Err(JobError::SessionNotCurrent(_))
    ));

    // A stop and a skip from a non-starter over gossip are ignored.
    // The starter's skip, sent after them on the same handle, marks
    // them processed. Convergence proves the session outlived the
    // stop, and the cancellation actor proves whose skip applied.
    peer.send(
        Message::Request(Request::session(
            guest.key_id.clone(),
            SessionRequest::Stop(session_id),
        ))
        .into(),
    )
    .unwrap();
    peer.send(
        Message::Request(Request::session(
            guest.key_id.clone(),
            SessionRequest::Skip(session_id, job_id),
        ))
        .into(),
    )
    .unwrap();
    peer.send(
        Message::Request(Request::session(
            owner.key_id.clone(),
            SessionRequest::Skip(session_id, job_id),
        ))
        .into(),
    )
    .unwrap();
    timeout(Duration::from_secs(30), async {
        loop {
            if let Some(session) = mgr.session(&owner)
                && session.next_job_id() != job_id
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("skip never took effect");
    let status = mgr.job_status(&owner, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    assert!(matches!(
        status,
        JobStatus::Cancelled { actor, .. } if actor == owner.key_id
    ));

    assert!(matches!(
        mgr.session_skip_job(&owner, session_id, job_id).await,
        Err(JobError::NotNextJob(_))
    ));
    mgr.session_stop(&owner, session_id).await.unwrap();
}

/// A skip that races its job's start over gossip converges the chain:
/// a sled that already ran the job rewinds to the burned position,
/// keeping the execution in history. A deliberate skip of an executed
/// job stays refused up front.
#[named]
#[tokio::test]
async fn skip_racing_start_converges() {
    let log = test_logger(function_name!());
    let (mgr, mut root, peer, _dir, _shutdown) = manager_test_root_and_peer(log).await;
    let owner = fake_identity(&mut root).await;

    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut mirror = Session::new(session_id);
    let job_id = mirror.next_job_id();
    mgr.session_start(&owner, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let job = root
        .sign_job_request(job_id, session_id, "true", false)
        .await;
    mgr.job_start(
        &owner,
        job.into_signed(),
        JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        mgr.session_skip_job(&owner, session_id, job_id).await,
        Err(JobError::NotNextJob(_))
    ));

    peer.send(
        Message::Request(Request::session(
            owner.key_id.clone(),
            SessionRequest::Skip(session_id, job_id),
        ))
        .into(),
    )
    .unwrap();
    assert!(mirror.skip_job(job_id));
    timeout(Duration::from_secs(30), async {
        loop {
            if let Some(session) = mgr.session(&owner)
                && session.next_job_id() == mirror.next_job_id()
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the racing skip never converged");

    let status = mgr.job_status(&owner, &job_id).await.unwrap()[mgr.own_baseboard()].clone();
    check_status_stopped(status, &job_id, Ok(0), Some(0), Some(0));
}

#[named]
#[tokio::test]
async fn too_much_cpu() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();
    let job_id = session.next_job_id();
    let command = "while :; do :; done";
    let job = root
        .sign_job_request(job_id, session_id, command, false)
        .await;
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
    check_status_stopped(
        status,
        &job_id,
        Err(ProcessError::Killed(SIGXCPU)),
        Some(0),
        Some(0),
    );
}

#[named]
#[tokio::test]
async fn too_much_output() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let job_id = session.next_job_id();
    let command = "yes";
    let job = root
        .sign_job_request(job_id, session_id, command, false)
        .await;
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
    let job = root
        .sign_job_request(job_id, session_id, command, false)
        .await;
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
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();
    let job_id = session.next_job_id();

    // Read some random bytes.
    let n = 1000;
    let command = &format!("head -c {n} /dev/urandom");
    let job = root
        .sign_job_request(job_id, session_id, command, false)
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
    } = identity.clone();
    assert_eq!(iam_key_id, key_id);
    assert_eq!(iam_public_key, public_key);
    assert_eq!(iam_nonce, credentials.nonce);
    assert!(iam_authenticated <= Utc::now());

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

/// Jobs must not inherit ignored signal dispositions. The embedding
/// process may ignore SIGINT, and a shell cannot trap a signal that
/// was ignored at entry, which turns ^C into a no-op in every job.
#[named]
#[tokio::test]
async fn job_signal_dispositions() {
    // Ignore and block SIGINT, as an embedding daemon might.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        let mut set = MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigemptyset(set.as_mut_ptr());
        libc::sigaddset(set.as_mut_ptr(), libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, set.as_ptr(), null_mut());
    }
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let baseboard_id = mgr.own_baseboard();
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(
            job_id,
            session.session_id(),
            "trap 'echo caught' INT; kill -INT $$; echo after",
            false,
        )
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
    let stdout = mgr
        .job_output(&authn, &job_id, baseboard_id, Stdout, None)
        .await
        .unwrap()
        .into_bytes()
        .await;
    let stdout = String::from_utf8(stdout.to_vec()).unwrap();
    assert!(stdout.contains("caught"), "stdout: {stdout:?}");
}

/// Interactive jobs must target exactly one sled.
#[named]
#[tokio::test]
async fn interactive_target_required() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session.session_id(), "bash", true)
        .await;
    assert!(matches!(
        mgr.job_start(&authn, job.into_signed(), JobStartParams::default())
            .await,
        Err(JobError::InteractiveTarget)
    ));
}

/// Each job's directory records the signed request beside its output.
#[named]
#[tokio::test]
async fn job_json() {
    let log = test_logger(function_name!());
    let (mgr, mut root, dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(job_id, session.session_id(), "true", false)
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

    let path = dir
        .path()
        .join("jobs")
        .join(job_id.to_string())
        .join("job.json");
    let recorded: SignedJob = serde_json::from_slice(&read(&path).await.unwrap()).unwrap();
    assert_eq!(recorded, job.into_signed());
}

#[named]
#[tokio::test]
async fn streaming_validation() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let SessionCeremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
        ..
    } = session_ceremony(&mgr, 1);
    let mut session = Session::new(session_id);
    mgr.session_start(&authn, session_id, client_nonce, signer_nonce, seq, true)
        .await
        .unwrap();

    let mut expect_invalid = async |mode: JobMode, target: Target| {
        let job_id = session.next_job_id();
        let job = root
            .sign_full_job_request(job_id, session.session_id(), "true", mode, target)
            .await;
        session.job_started(job.clone().into_signed());
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
        assert!(matches!(status, JobStatus::Error { .. }), "{status:?}");
    };

    expect_invalid(JobMode::StreamOutput, Target::All).await;
    expect_invalid(
        JobMode::StreamOutput,
        format!("{},14", test_baseboard_id()).parse().unwrap(),
    )
    .await;
    expect_invalid(JobMode::StreamInput, test_baseboard_id().into()).await;
}
