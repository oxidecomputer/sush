//! Oxide Support Shell integration tests.

use dropshot::{ConfigDropshot, ServerBuilder};
use function_name::named;
use futures::StreamExt as _;
use tokio::test;

use sush_api::sush_api_mod::api_description;
use sush_client::{Client, Error as ClientError};
use sush_common::jobs::{JobLimits, JobOutputStream, JobStatus};
use sush_server::{ApiServer, ProxyServer};

use crate::test_utils::{SignJobRequest as _, authz, manager_and_test_root, test_logger};

#[named]
#[test]
async fn client_server() {
    // Spin up a server.
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log.clone()).await;
    let api = api_description::<ApiServer>().unwrap();
    let server = ServerBuilder::new(api, mgr, log)
        .config(ConfigDropshot::default())
        .start()
        .expect("failed to start server");

    // Connect and authenticate to the server.
    let addr = server.local_addr();
    let client = Client::new(&format!("http://{addr}"));
    let ClientError::ErrorResponse(unauthz) = client.iam().body(None).send().await.unwrap_err()
    else {
        panic!("expected error response")
    };
    assert_eq!(unauthz.status(), 401, "expected 401 Unauthorized");
    let (identity, credentials) = authz(&client, unauthz, &mut root).await;
    let iam = client
        .iam()
        .authorization(credentials.to_string())
        .body(None)
        .send()
        .await
        .unwrap()
        .into_inner();
    assert_eq!(iam, identity, "who am I?");

    // Start a session and run a job.
    let session_id = client
        .session_start()
        .authorization(credentials.to_string())
        .send()
        .await
        .unwrap()
        .into_inner();
    let job_id = session_id.first_job_id();
    let job = root
        .sign_job_request(&job_id, "echo -n $SUSH_JOB_ID", false)
        .await;
    let JobLimits {
        max_cpu,
        max_mem,
        max_fsize,
    } = JobLimits::default();
    let status = client
        .job_start()
        .authorization(credentials.to_string())
        .job_id(&job_id)
        .max_cpu(max_cpu)
        .max_mem(max_mem)
        .max_fsize(max_fsize)
        .wait(true)
        .body(job)
        .send()
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        status,
        JobStatus::Ended {
            job: j,
            session_id: sid,
            status: Some(0),
            ..
        } if *j.job_id() == job_id && sid == session_id
    ));

    // Check the job output.
    let mut output = client
        .job_output()
        .authorization(credentials.to_string())
        .job_id(&job_id)
        .stream(JobOutputStream::Stdout)
        .send()
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        output.next().await.unwrap().unwrap(),
        job_id.to_string().as_bytes()
    );
}

#[named]
#[test]
async fn client_proxy_server() {
    // Spin up a full server.
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log.clone()).await;
    let api = api_description::<ApiServer>().unwrap();
    let server = ServerBuilder::new(api, mgr, log.clone())
        .config(ConfigDropshot::default())
        .start()
        .expect("failed to start server");
    let server_addr = server.local_addr();

    // Spin up a proxy server.
    let proxy = ProxyServer::start(
        &log,
        "127.0.0.1:0".parse().expect("can't parse local address"),
        server.local_addr(),
    )
    .await
    .expect("can't start proxy server");
    let proxy_addr = proxy.local_addr();
    assert_ne!(server_addr, proxy_addr);

    // Connect and authenticate to the server via the proxy.
    let client = Client::new(&format!("http://{proxy_addr}"));
    let ClientError::ErrorResponse(unauthz) = client.iam().body(None).send().await.unwrap_err()
    else {
        panic!("expected error response")
    };
    assert_eq!(unauthz.status(), 401, "expected 401 Unauthorized");
    let (identity, credentials) = authz(&client, unauthz, &mut root).await;
    let iam = client
        .iam()
        .authorization(credentials.to_string())
        .body(None)
        .send()
        .await
        .unwrap()
        .into_inner();
    assert_eq!(iam, identity, "who am I?");
}
