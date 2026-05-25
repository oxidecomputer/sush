//! Job manager tests.

use std::time::Duration;

use chrono::Utc;
use function_name::named;
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use pwd::Passwd;
use slog::{Discard, Logger, o};
use tempfile::TempDir;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::time::Validity;

use sush_api::JobStartParams;
use sush_common::authn::{Challenge, ChallengeResponse, Credentials, Identity};
use sush_common::jobs::{
    JobId, JobLimits, JobOutputStream, JobStatus, ProcessError, Session, SignedJob,
};
use sush_common::keys::{EphemeralKey, KeyError, KeyType, Signer as _};
use sush_server::{JobError, JobManager, JobOutputState};

use crate::test_utils::{
    SignJobRequest as _, ephemeral_test_subject, fake_identity, manager_and_test_root, test_logger,
};

// Signal numbers for killed jobs.
const SIGKILL: i32 = 9;
const SIGXCPU: i32 = 24;

fn check_status_started(
    status: JobStatus,
    cert: &Certificate,
    expected_job_id: &JobId,
    expected_command: &str,
) {
    let JobStatus::Started {
        job, time_started, ..
    } = status
    else {
        panic!("expected job to be started");
    };
    assert_eq!(job.job_id, *expected_job_id);
    assert_eq!(job.command, expected_command);
    assert!(time_started < Utc::now());
    job.into_signed().verify_with_cert(cert).unwrap();
}

fn check_status_ended(
    status: JobStatus,
    expected_job_id: &JobId,
    expected_command: &str,
    expected_status: Result<i32, ProcessError>,
    expected_stdout_len: u64,
    expected_stderr_len: u64,
) {
    let JobStatus::Ended {
        job,
        time_started,
        time_ended,
        status,
        stdout_len,
        stderr_len,
        ..
    } = status
    else {
        panic!("expected job to be finished");
    };
    assert_eq!(job.job_id, *expected_job_id);
    assert_eq!(job.command, expected_command);
    assert!(time_started < time_ended);
    assert!(time_ended < Utc::now());
    assert_eq!(status, expected_status);
    assert_eq!(stdout_len, expected_stdout_len);
    assert_eq!(stderr_len, expected_stderr_len);
}

async fn job_status(
    authn: &Identity,
    mgr: &JobManager,
    session: &mut Session,
    job: SignedJob,
) -> JobStatus {
    let status = mgr
        .job_start(authn, job.clone(), JobStartParams::wait())
        .await
        .expect("should be able to start job")
        .expect("should be waiting for job")
        .expect("job should end successfully")
        .into_status(
            JobOutputState::new(mgr.output_dir(), job.job_id())
                .expect("should be able to get job output state"),
        );
    session.job_started(job);
    status
}

async fn job_error(authn: &Identity, mgr: &JobManager, job: SignedJob) -> JobError {
    mgr.job_start(authn, job, JobStartParams::wait())
        .await
        .expect_err("job should end with an error")
}

#[named]
#[tokio::test]
async fn jobs() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let mut session = mgr.session_start(&authn).await.unwrap();
    let session_id = session.session_id().to_owned();
    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "true", false).await;
    assert!(matches!(
        mgr.job_status(&authn, &job_id).await.unwrap_err(),
        JobError::JobNotFound(id) if id == job_id
    ));
    let status = job_status(&authn, &mgr, &mut session, job.clone()).await;
    check_status_ended(status, &job_id, "true", Ok(0), 0, 0);

    assert!(
        matches!(
            job_error(&authn, &mgr, job.clone()).await,
            JobError::InvalidJobId(ref id) if *id == job_id
        ),
        "should not be allowed to reuse a job ID"
    );

    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "false", false).await;
    let status = job_status(&authn, &mgr, &mut session, job.clone()).await;
    check_status_ended(status, &job_id, "false", Ok(1), 0, 0);

    let job_id = session.next_job_id();
    let job_id_string = job_id.to_string();
    let job_id_bytes = job_id_string.as_bytes();
    let job = root
        .sign_job_request(&job_id, "echo -n $SUSH_JOB_ID", false)
        .await;
    let status = job_status(&authn, &mgr, &mut session, job.clone()).await;
    check_status_ended(
        status,
        &job_id,
        "echo -n $SUSH_JOB_ID",
        Ok(0),
        job_id_bytes.len() as u64,
        0,
    );
    assert_eq!(
        mgr.job_output(&authn, &job_id, JobOutputStream::Stdout, None)
            .await
            .unwrap(),
        job_id_bytes
    );
    assert!(
        mgr.job_output(&authn, &job_id, JobOutputStream::Stderr, None)
            .await
            .unwrap()
            .is_empty()
    );

    let home = Passwd::current_user().unwrap().dir;
    let output = format!("{home}\n");
    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "pwd", false).await;
    let status = job_status(&authn, &mgr, &mut session, job.clone()).await;
    check_status_ended(status, &job_id, "pwd", Ok(0), output.len() as u64, 0);
    assert_eq!(
        mgr.job_output(&authn, &job_id, JobOutputStream::Stdout, None)
            .await
            .unwrap(),
        output.as_bytes(),
    );
    assert!(
        mgr.job_output(&authn, &job_id, JobOutputStream::Stderr, None)
            .await
            .unwrap()
            .is_empty()
    );

    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "foo", false).await;
    let new_session = mgr.session_start(&authn).await.unwrap();
    assert_ne!(*new_session.session_id(), session_id);
    assert!(
        matches!(
            job_error(&authn, &mgr, job).await,
            JobError::InvalidJobId(ref id) if *id == job_id
        ),
        "session has ended, should not be able to start job"
    );

    let job_id = session.next_job_id();
    let job = root.sign_job_request(&job_id, "bar", false).await;
    assert!(
        matches!(
            job_error(&authn, &mgr, job.clone()).await,
            JobError::InvalidJobId(ref id) if *id == job_id
        ),
        "should not be able to use old session job ID in new session"
    );

    let job_id = new_session.next_job_id();
    let job = root.sign_job_request(&job_id, "true", false).await;
    let status = job_status(&authn, &mgr, &mut session, job).await;
    check_status_ended(status, &job_id, "true", Ok(0), 0, 0);
}

#[named]
#[tokio::test]
async fn abort() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let session = mgr.session_start(&authn).await.unwrap();
    let job_id = session.next_job_id();

    // Start a (potentially) long-running job.
    let command = "sleep 10";
    let job = root.sign_job_request(&job_id, command, false).await;
    assert!(
        mgr.job_start(&authn, job, JobStartParams::default())
            .await
            .expect("should be able to start job")
            .is_none(),
        "should not be waiting for job"
    );

    // Check that the job is alive.
    let status = mgr.job_status(&authn, &job_id).await.unwrap();
    check_status_started(status, root.cert(), &job_id, command);

    // Kill the job and wait for it to die.
    mgr.job_stop(&authn, &job_id).await.unwrap();
    sleep(Duration::from_millis(10)).await;

    // Check that it's dead and that it didn't live for long.
    let status = mgr.job_status(&authn, &job_id).await.unwrap();
    assert!(status.time_elapsed().to_std().unwrap() < Duration::from_secs(1));
    check_status_ended(
        status,
        &job_id,
        command,
        Err(ProcessError::Killed(SIGKILL)),
        0,
        0,
    );
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

    let authn = fake_identity(&mut root).await;
    let dir = TempDir::with_prefix("sush-").unwrap();
    let log = Logger::root(Discard, o!("test" => function_name!()));
    let shutdown = CancellationToken::new();
    let mgr = JobManager::new(log, dir.path(), shutdown).await.unwrap();
    assert!(
        matches!(
            mgr.import_cert(&authn, root_cert.clone())
                .await
                .unwrap_err(),
            JobError::Key(KeyError::SelfSigned),
        ),
        "should not accept root cert without override"
    );
    assert!(
        matches!(
            mgr.import_cert(&authn, child.cert().clone()).await.unwrap_err(),
            JobError::MissingCert(key_id) if key_id == root_key_id,
        ),
        "should not accept child cert without root"
    );
    assert_eq!(
        mgr.import_root(root_cert.clone()).await.unwrap(),
        root_key_id
    );
    assert_eq!(
        mgr.cert_chain(&authn, &root_key_id).await.unwrap(),
        vec![root_cert.clone()]
    );
    assert_eq!(
        mgr.import_cert(&authn, child.cert().clone()).await.unwrap(),
        child_key_id
    );
    assert_eq!(
        mgr.cert_chain(&authn, &child_key_id).await.unwrap(),
        vec![root_cert.clone(), child.cert().clone()]
    );

    let mut session = mgr.session_start(&authn).await.unwrap();
    let job_id = session.next_job_id();
    let job = child.sign_job_request(&job_id, "true", false).await;
    let status = job_status(&authn, &mgr, &mut session, job).await;
    check_status_ended(status, &job_id, "true", Ok(0), 0, 0);
}

#[named]
#[tokio::test]
async fn too_much_cpu() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let session = mgr.session_start(&authn).await.unwrap();
    let job_id = session.next_job_id();
    let command = "openssl speed sha1";
    let job = root.sign_job_request(&job_id, command, false).await;
    let job_id = job.job_id().to_owned();
    let end = mgr
        .job_start(
            &authn,
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
        )
        .await
        .expect("should be able to start job")
        .expect("should be waiting for job")
        .expect("job should end successfully");
    let status = end.into_status(
        JobOutputState::new(mgr.output_dir(), &job_id).expect("should get job output state"),
    );
    assert!(status.time_elapsed().to_std().unwrap() < Duration::from_secs(2));

    // The output of `openssl speed` changed between v3.0 and v3.5.
    let stderr = mgr
        .job_output(&authn, &job_id, JobOutputStream::Stderr, None)
        .await
        .unwrap();
    let stderr = String::from_utf8_lossy(&stderr);
    match status {
        JobStatus::Ended { stderr_len: 37, .. } => {
            check_status_ended(
                status,
                &job_id,
                command,
                Err(ProcessError::Killed(SIGXCPU)),
                0,
                37,
            );
            assert_eq!(stderr, "Doing sha1 for 3s on 16 size blocks: ");
        }
        JobStatus::Ended { stderr_len: 41, .. } => {
            check_status_ended(
                status,
                &job_id,
                command,
                Err(ProcessError::Killed(SIGXCPU)),
                0,
                41,
            );
            assert_eq!(stderr, "Doing sha1 ops for 3s on 16 size blocks: ");
        }
        _ => todo!("what does `{command}` produce on your system?"),
    }
}

#[named]
#[tokio::test]
async fn output_ranges() {
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log).await;
    let authn = fake_identity(&mut root).await;
    let mut session = mgr.session_start(&authn).await.unwrap();
    let job_id = session.next_job_id();

    // Read some random bytes.
    let n = 1000;
    let command = &format!("head -c {n} /dev/urandom");
    let job = root.sign_job_request(&job_id, command, false).await;
    let status = job_status(&authn, &mgr, &mut session, job).await;
    check_status_ended(status, &job_id, command, Ok(0), n, 0);

    // No range, i.e., full output.
    let r = mgr
        .job_output(&authn, &job_id, JobOutputStream::Stdout, None)
        .await
        .unwrap();

    // One byte too big.
    assert!(matches!(
        mgr.job_output(
            &authn,
            &job_id,
            JobOutputStream::Stdout,
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
            JobOutputStream::Stdout,
            Some(Range {
                start: StartPosition::Index(0),
                end: EndPosition::Index(n - 1),
            }),
        )
        .await
        .unwrap(),
        r
    );

    // Two half-ranges.
    let mut o = mgr
        .job_output(
            &authn,
            &job_id,
            JobOutputStream::Stdout,
            Some(Range {
                start: StartPosition::Index(0),
                end: EndPosition::Index(n / 2 - 1),
            }),
        )
        .await
        .unwrap();
    o.extend(
        mgr.job_output(
            &authn,
            &job_id,
            JobOutputStream::Stdout,
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
                    &authn,
                    &job_id,
                    JobOutputStream::Stdout,
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
                &authn,
                &job_id,
                JobOutputStream::Stdout,
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
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log).await;
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
