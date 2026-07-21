//! Oxide Support Shell integration tests.

use std::net::SocketAddr;

use bytes::Bytes;
use dropshot::{ConfigDropshot, ServerBuilder};
use function_name::named;
use futures::{SinkExt as _, StreamExt as _};
use tokio::test;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;

use sush_api::JobWait;
use sush_api::sush_api_mod::api_description;
use sush_client::{Client, Error as ClientError};
use sush_common::interactive::{
    InteractiveJobDecoder, InteractiveJobEncoder, InteractiveJobMessage,
};
use sush_common::jobs::{JobLimits, JobOutputStream, Session, SessionId};
use sush_server::{ApiServer, ProxyServer};

use crate::test_utils::{
    SignJobRequest as _, authz, manager_and_test_root, test_baseboard_id, test_logger,
};

fn local_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[named]
#[test]
async fn client_server() {
    // Spin up a server.
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log.clone()).await;
    let api = api_description::<ApiServer>().unwrap();
    let server = ServerBuilder::new(api, mgr, log)
        .config(ConfigDropshot {
            bind_address: local_addr(),
            ..Default::default()
        })
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
        .expect("can't authenticate")
        .into_inner();
    assert_eq!(iam, identity, "who am I?");

    // Start a session and run a job.
    let session = Session::new(SessionId::new());
    client
        .session_start()
        .session_id(session.session_id())
        .authorization(credentials.to_string())
        .send()
        .await
        .expect("can't start session");
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(&job_id, "echo -n $SUSH_JOB_ID", false)
        .await;
    let JobLimits {
        max_cpu,
        max_mem,
        max_fsize,
    } = JobLimits::default();
    client
        .job_start()
        .authorization(credentials.to_string())
        .job_id(&job_id)
        .max_cpu(max_cpu)
        .max_mem(max_mem)
        .max_fsize(max_fsize)
        .wait(JobWait::Stop)
        .body(job.into_signed())
        .send()
        .await
        .expect("can't start job");

    // Check the job output.
    let mut output = client
        .job_output()
        .job_id(&job_id)
        .stream(JobOutputStream::Stdout)
        .target("*")
        .authorization(credentials.to_string())
        .send()
        .await
        .expect("can't get job output")
        .into_inner();
    assert_eq!(
        output
            .next()
            .await
            .expect("can't get next output item")
            .expect("can't get output bytes"),
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
        .config(ConfigDropshot {
            bind_address: local_addr(),
            ..Default::default()
        })
        .start()
        .expect("failed to start server");
    let server_addr = server.local_addr();

    // Spin up a proxy server.
    let proxy = ProxyServer::start(&log, local_addr(), server.local_addr())
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
        .expect("can't authenticate")
        .into_inner();
    assert_eq!(iam, identity, "who am I?");
}

#[named]
#[test]
async fn interactive_job() {
    // Spin up a server.
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir) = manager_and_test_root(log.clone()).await;
    let api = api_description::<ApiServer>().unwrap();
    let server = ServerBuilder::new(api, mgr, log)
        .config(ConfigDropshot {
            bind_address: local_addr(),
            ..Default::default()
        })
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
        .expect("can't authenticate")
        .into_inner();
    assert_eq!(iam, identity, "who am I?");

    // Start a session and run an interactive job.
    let session = Session::new(SessionId::new());
    client
        .session_start()
        .session_id(session.session_id())
        .authorization(credentials.to_string())
        .send()
        .await
        .expect("can't start session");
    let job_id = session.next_job_id();
    let job = root
        .sign_job_request(&job_id, "cat > /dev/null", true)
        .await;
    let JobLimits {
        max_cpu,
        max_mem,
        max_fsize,
    } = JobLimits::default();
    client
        .job_start()
        .authorization(credentials.to_string())
        .job_id(&job_id)
        .max_cpu(max_cpu)
        .max_mem(max_mem)
        .max_fsize(max_fsize)
        .wait(JobWait::Start)
        .body(job.into_signed())
        .send()
        .await
        .expect("can't start job");

    // Attach to the job and rekey.
    let socket = client
        .job_attach()
        .job_id(&job_id)
        .target(test_baseboard_id().to_string())
        .authorization(credentials.to_string())
        .send()
        .await
        .expect("can't attach to job")
        .into_inner();
    let mut stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
    let mut decoder = InteractiveJobDecoder::default();
    let mut encoder = InteractiveJobEncoder::default();
    let InteractiveJobMessage::Ping(bytes) = decoder
        .decode(
            stream
                .next()
                .await
                .expect("can't get first item")
                .expect("can't get first message"),
        )
        .expect("can't decode first message")
    else {
        panic!("expected first message to be ping");
    };
    let pong = encoder.rekey(Some(&bytes)).expect("can't rekey encoder");
    stream
        .send(encoder.encode(pong).expect("can't encode pong"))
        .await
        .expect("can't send pong");
    decoder.rekey(bytes, None);

    // Send a message and ensure that we can see it echoed.
    let hello = Bytes::from(format!("Hello, {job_id}!"));
    stream
        .send(
            encoder
                .encode(InteractiveJobMessage::Data(hello.clone()))
                .expect("can't encode message"),
        )
        .await
        .expect("can't send message");
    let recvd = stream
        .next()
        .await
        .expect("can't get next stream item")
        .expect("can't get next message");
    let InteractiveJobMessage::Data(bytes) = decoder
        .decode(recvd)
        .expect("can't decode received message")
    else {
        panic!("expected data message");
    };
    assert_eq!(bytes, hello);

    // Detach from the job.
    stream.close(None).await.expect("can't close stream");

    // Stop the job.
    client
        .job_stop()
        .authorization(credentials.to_string())
        .job_id(&job_id)
        .wait(JobWait::Stop)
        .send()
        .await
        .expect("can't stop job");

    // Check the output for our message.
    let mut output = client
        .job_output()
        .authorization(credentials.to_string())
        .job_id(&job_id)
        .stream(JobOutputStream::Stdout)
        .target(test_baseboard_id().to_string())
        .send()
        .await
        .expect("can't get job output")
        .into_inner();
    assert_eq!(
        output
            .next()
            .await
            .expect("can't get next output item")
            .expect("can't get output bytes"),
        hello,
    );
}
