// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Oxide Support Shell integration tests.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dropshot::{ConfigDropshot, ServerBuilder};
use function_name::named;
use futures::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::test;
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_util::sync::CancellationToken;

use sush_api::JobWait;
use sush_api::sush_api_mod::api_description;
use sush_client::{AuthzSigner, Client, Error as ClientError};
use sush_common::interactive::{InteractiveJobControl, InteractiveJobMessage};
use sush_common::jobs::{Access, JobLimits, JobOutputStream, Session, SessionId};
use sush_common::targets::Cubbies;
use sush_server::proxy::Targets;
use sush_server::{ApiServer, ProxyServer};

use crate::test_utils::{
    SignJobRequest as _, authz, ephemeral_test_root, manager_and_test_root, test_baseboard_id,
    test_logger,
};

const TIMEOUT: Duration = Duration::from_secs(10);

fn local_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[named]
#[test]
async fn client_server() {
    // Spin up a server.
    let log = test_logger(function_name!());
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log.clone()).await;
    let api = api_description::<ApiServer>().unwrap();
    let server = ServerBuilder::new(api, Arc::new(mgr), log)
        .config(ConfigDropshot {
            bind_address: local_addr(),
            ..Default::default()
        })
        .start()
        .expect("failed to start server");

    // Connect and authenticate to the server.
    let addr = server.local_addr();
    let signer = AuthzSigner::default();
    let client = Client::new(&format!("http://{addr}"), signer.clone());
    let ClientError::ErrorResponse(unauthz) = client.iam().body(None).send().await.unwrap_err()
    else {
        panic!("expected error response")
    };
    assert_eq!(unauthz.status(), 401, "expected 401 Unauthorized");
    let (identity, credentials) = authz(&client, unauthz, &mut root).await;
    signer.set(Some(credentials));
    let iam = client
        .iam()
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
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log.clone()).await;
    let api = api_description::<ApiServer>().unwrap();
    let server = ServerBuilder::new(api, Arc::new(mgr), log.clone())
        .config(ConfigDropshot {
            bind_address: local_addr(),
            ..Default::default()
        })
        .start()
        .expect("failed to start server");
    let server_addr = server.local_addr();

    // Spin up a proxy server routing to it.
    let (tx_targets, rx_targets) = watch::channel(Targets {
        sleds: BTreeMap::from([(test_baseboard_id(), server_addr)]),
        cubbies: Cubbies::from([(14, test_baseboard_id())]),
    });
    let shutdown_proxy = CancellationToken::new();
    let proxy = ProxyServer::start(&log, local_addr(), rx_targets, shutdown_proxy.clone())
        .await
        .expect("can't start proxy server");
    let proxy_addr = proxy.local_addr();
    assert_ne!(server_addr, proxy_addr);

    // Connect and authenticate to the server via the proxy.
    let signer = AuthzSigner::default();
    let client = Client::new(&format!("http://{proxy_addr}"), signer.clone());
    let ClientError::ErrorResponse(unauthz) = client.iam().body(None).send().await.unwrap_err()
    else {
        panic!("expected error response")
    };
    assert_eq!(unauthz.status(), 401, "expected 401 Unauthorized");
    let (identity, credentials) = authz(&client, unauthz, &mut root).await;
    signer.set(Some(credentials));
    let iam = client
        .iam()
        .body(None)
        .send()
        .await
        .expect("can't authenticate")
        .into_inner();
    assert_eq!(iam, identity, "who am I?");

    // Attach to an interactive job through the proxy, routed by the
    // target path segment, and echo bytes over the bridged upgrade.
    let session = Session::new(SessionId::new());
    client
        .session_start()
        .session_id(session.session_id())
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
        .job_id(&job_id)
        .max_cpu(max_cpu)
        .max_mem(max_mem)
        .max_fsize(max_fsize)
        .rows(24)
        .cols(80)
        .wait(JobWait::Start)
        .body(job.into_signed())
        .send()
        .await
        .expect("can't start job");
    let socket = client
        .job_attach()
        .job_id(&job_id)
        .target(test_baseboard_id().to_string())
        .send()
        .await
        .expect("can't attach via proxy")
        .into_inner();
    let mut stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
    let InteractiveJobControl::WindowChange(_) = next_control_message(&mut stream).await;
    let hello = Bytes::from(format!("Hello, {job_id}!"));
    stream
        .send(
            InteractiveJobMessage::Data(hello.clone())
                .try_into()
                .expect("can't encode message"),
        )
        .await
        .expect("can't send message");
    assert_eq!(next_data_message(&mut stream).await, &hello);

    // A target the proxy cannot route is refused at the proxy.
    let Err(unrouted) = client
        .job_output()
        .job_id(&job_id)
        .stream(JobOutputStream::Stdout)
        .target("913-0000019:BRM99999999")
        .send()
        .await
    else {
        panic!("expected no route to an unknown baseboard");
    };
    if let ClientError::UnexpectedResponse(response) = unrouted {
        assert_eq!(response.status(), 502);
    }

    // `/target` needs no login and, through the proxy, resolves
    // routing expressions.
    let anon = Client::new(&format!("http://{proxy_addr}"), AuthzSigner::default());
    let resolved = anon
        .target()
        .via("14")
        .send()
        .await
        .expect("can't resolve a cubby via the proxy")
        .into_inner();
    assert_eq!(resolved, test_baseboard_id());

    // With no sleds in the table, everything is refused.
    tx_targets.send(Targets::default()).unwrap();
    let unavailable = client.iam().body(None).send().await.unwrap_err();
    if let ClientError::UnexpectedResponse(response) = unavailable {
        assert_eq!(response.status(), 503);
    }

    shutdown_proxy.cancel();
    server.close().await.expect("can't shutdown server");
}

async fn next_data_message<S>(stream: &mut WebSocketStream<S>) -> Bytes
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let recvd = timeout(TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for data message")
        .expect("can't get next stream item")
        .expect("can't get next data message");
    let InteractiveJobMessage::Data(bytes) = recvd.try_into().expect("can't decode message") else {
        panic!("expected data message");
    };
    bytes
}

async fn next_control_message<S>(stream: &mut WebSocketStream<S>) -> InteractiveJobControl
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let recvd = timeout(TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for control message")
        .expect("can't get next stream item")
        .expect("can't get next control message");
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
    let (mgr, mut root, _dir, _shutdown) = manager_and_test_root(log.clone()).await;
    let api = api_description::<ApiServer>().unwrap();
    let server = ServerBuilder::new(api, Arc::new(mgr), log)
        .config(ConfigDropshot {
            bind_address: local_addr(),
            ..Default::default()
        })
        .start()
        .expect("failed to start server");

    // Connect and authenticate to the server.
    let addr = server.local_addr();
    let signer = AuthzSigner::default();
    let client = Client::new(&format!("http://{addr}"), signer.clone());
    let ClientError::ErrorResponse(unauthz) = client.iam().body(None).send().await.unwrap_err()
    else {
        panic!("expected error response")
    };
    assert_eq!(unauthz.status(), 401, "expected 401 Unauthorized");
    let (identity, credentials) = authz(&client, unauthz, &mut root).await;
    signer.set(Some(credentials));
    let iam = client
        .iam()
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

    // A guest key authenticates, on its own client, but cannot attach
    // until granted.
    let mut guest_key = ephemeral_test_root();
    let guest_signer = AuthzSigner::default();
    let guest_client = Client::new(&format!("http://{addr}"), guest_signer.clone());
    let ClientError::ErrorResponse(unauthz) =
        guest_client.iam().body(None).send().await.unwrap_err()
    else {
        panic!("expected error response")
    };
    let (guest, guest_authz) = authz(&guest_client, unauthz, &mut guest_key).await;
    guest_signer.set(Some(guest_authz));
    let guest_attach = async || {
        guest_client
            .job_attach()
            .job_id(&job_id)
            .target(test_baseboard_id().to_string())
            .send()
            .await
    };
    let denied = guest_attach().await.unwrap_err();
    assert!(
        matches!(denied.status(), Some(status) if status.as_u16() == 403),
        "expected 403 Forbidden, got {denied:?}"
    );

    // Grant the guest read-only access and attach.
    client
        .session_allow_attach()
        .session_id(session.session_id())
        .key_id(guest.key_id.clone())
        .access(Access::ReadOnly)
        .send()
        .await
        .expect("can't allow attach");
    let socket3 = timeout(TIMEOUT, async {
        loop {
            match guest_attach().await {
                Ok(socket) => break socket.into_inner(),
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("grant never took effect");
    let mut stream3 = WebSocketStream::from_raw_socket(socket3, Role::Client, None).await;
    let InteractiveJobControl::WindowChange(size3) = next_control_message(&mut stream3).await;
    assert_eq!(size3, size1);
    let _playback = next_data_message(&mut stream3).await;

    // The read-only guest's input is dropped: the starter's marker,
    // sent after it, echoes without it.
    let intrusion = Bytes::from("intruder input");
    stream3
        .send(
            InteractiveJobMessage::Data(intrusion.clone())
                .try_into()
                .expect("can't encode message"),
        )
        .await
        .expect("can't send message");
    let marker = Bytes::from(format!("Marker, {job_id}!"));
    stream1
        .send(
            InteractiveJobMessage::Data(marker.clone())
                .try_into()
                .expect("can't encode message"),
        )
        .await
        .expect("can't send message");
    assert_eq!(next_data_message(&mut stream1).await, &marker);
    assert_eq!(next_data_message(&mut stream3).await, &marker);

    // Withdraw the grant, so that the next successful attach can only
    // mean the read-write grant that follows.
    client
        .session_deny_attach()
        .session_id(session.session_id())
        .key_id(guest.key_id.clone())
        .send()
        .await
        .expect("can't deny attach");
    timeout(TIMEOUT, async {
        while guest_attach().await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("denial never took effect");

    // Granted read-write, the guest's input echoes everywhere, and the
    // old read-only socket keeps the access it attached with.
    client
        .session_allow_attach()
        .session_id(session.session_id())
        .key_id(guest.key_id.clone())
        .access(Access::ReadWrite)
        .send()
        .await
        .expect("can't allow attach");
    let socket4 = timeout(TIMEOUT, async {
        loop {
            match guest_attach().await {
                Ok(socket) => break socket.into_inner(),
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("upgrade never took effect");
    let mut stream4 = WebSocketStream::from_raw_socket(socket4, Role::Client, None).await;
    let InteractiveJobControl::WindowChange(_) = next_control_message(&mut stream4).await;
    let _playback = next_data_message(&mut stream4).await;
    let welcome = Bytes::from(format!("Welcome, {job_id}!"));
    stream4
        .send(
            InteractiveJobMessage::Data(welcome.clone())
                .try_into()
                .expect("can't encode message"),
        )
        .await
        .expect("can't send message");
    assert_eq!(next_data_message(&mut stream1).await, &welcome);
    assert_eq!(next_data_message(&mut stream3).await, &welcome);
    assert_eq!(next_data_message(&mut stream4).await, &welcome);

    // Detach from the job.
    stream1.close(None).await.expect("can't close stream1");
    stream2.close(None).await.expect("can't close stream2");
    stream3.close(None).await.expect("can't close stream3");
    stream4.close(None).await.expect("can't close stream4");

    // Stop the job.
    client
        .job_stop()
        .job_id(&job_id)
        .wait(JobWait::Stop)
        .send()
        .await
        .expect("can't stop job");

    // Check that the output contains every echoed message, and nothing
    // from the read-only guest.
    let mut output = client
        .job_output()
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
    hello_again.extend(marker);
    hello_again.extend(welcome);
    assert_eq!(
        output
            .next()
            .await
            .expect("can't get next output item")
            .expect("can't get output bytes"),
        hello_again,
    );
}
