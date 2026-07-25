//! Oxide Support Shell integration tests.

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use dropshot::{ConfigDropshot, ServerBuilder};
use function_name::named;
use futures::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::test;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;

use sush_api::JobWait;
use sush_api::sush_api_mod::api_description;
use sush_client::{Client, Error as ClientError};
use sush_common::interactive::{InteractiveJobControl, InteractiveJobMessage};
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

async fn next_data_message<S>(stream: &mut WebSocketStream<S>) -> Bytes
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let recvd = stream
        .next()
        .await
        .expect("can't get next stream item")
        .expect("can't get next message");
    let InteractiveJobMessage::Data(bytes) = recvd.try_into().expect("can't decode message") else {
        panic!("expected data message");
    };
    bytes
}

async fn next_control_message<S>(stream: &mut WebSocketStream<S>) -> InteractiveJobControl
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let recvd = stream
        .next()
        .await
        .expect("can't get next stream item")
        .expect("can't get next message");
    let InteractiveJobMessage::Control(message) = recvd.try_into().expect("can't decode message")
    else {
        panic!("expected control message");
    };
    message
}

#[named]
#[test]
async fn interactive_job() {
    // The one true terminal size.
    const ROWS: u16 = 24;
    const COLS: u16 = 80;

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
        .rows(ROWS)
        .cols(COLS)
        .wait(JobWait::Start)
        .body(job.into_signed())
        .send()
        .await
        .expect("can't start job");

    // Attach to the job.
    let socket1 = client
        .job_attach()
        .job_id(&job_id)
        .target(test_baseboard_id().to_string())
        .authorization(credentials.to_string())
        .send()
        .await
        .expect("can't attach to job")
        .into_inner();
    let mut stream1 = WebSocketStream::from_raw_socket(socket1, Role::Client, None).await;

    // Ensure that we get an initial window size message.
    let InteractiveJobControl::WindowChange(size1) = next_control_message(&mut stream1).await;
    assert_eq!(size1.rows, ROWS);
    assert_eq!(size1.cols, COLS);

    // Send a message and ensure that we can see it echoed.
    let hello = Bytes::from(format!("Hello, {job_id}!"));
    stream1
        .send(
            InteractiveJobMessage::Data(hello.clone())
                .try_into()
                .expect("can't encode message"),
        )
        .await
        .expect("can't send message");
    assert_eq!(next_data_message(&mut stream1).await, &hello);

    // Attach a second client and ensure that it gets a window size
    // and playback.
    let socket2 = client
        .job_attach()
        .job_id(&job_id)
        .target(test_baseboard_id().to_string())
        .authorization(credentials.to_string())
        .send()
        .await
        .expect("can't attach second client to job")
        .into_inner();
    let mut stream2 = WebSocketStream::from_raw_socket(socket2, Role::Client, None).await;
    let InteractiveJobControl::WindowChange(size2) = next_control_message(&mut stream2).await;
    assert_eq!(size2, size1);
    assert_eq!(next_data_message(&mut stream2).await, &hello);

    // Send a message from the second client.
    let again = Bytes::from(format!("And hello again, {job_id}!"));
    stream2
        .send(
            InteractiveJobMessage::Data(again.clone())
                .try_into()
                .expect("can't encode message"),
        )
        .await
        .expect("can't send message");

    // Ensure both clients get the new message.
    assert_eq!(next_data_message(&mut stream1).await, &again);
    assert_eq!(next_data_message(&mut stream2).await, &again);

    // Detach from the job.
    stream1.close(None).await.expect("can't close stream1");
    stream2.close(None).await.expect("can't close stream2");

    // Stop the job.
    client
        .job_stop()
        .authorization(credentials.to_string())
        .job_id(&job_id)
        .wait(JobWait::Stop)
        .send()
        .await
        .expect("can't stop job");

    // Check that the output contains both messages.
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
    let mut hello_again = BytesMut::new();
    hello_again.extend(hello);
    hello_again.extend(again);
    assert_eq!(
        output
            .next()
            .await
            .expect("can't get next output item")
            .expect("can't get output bytes"),
        hello_again,
    );
}
