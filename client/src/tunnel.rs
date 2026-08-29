// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Transparent tunneling through Nexus.
//!
//! Given `--nexus`, the client listens on an ephemeral loopback port,
//! carries each accepted connection over an authenticated websocket
//! to Nexus, and points itself at the listener. The sprockets-TLS
//! and signed requests inside are forwarded untouched, so the tech
//! port and the tunnel carry the same traffic. The far end of each
//! WebSocket is the sush proxy in a switch zone. The Nexus half lives
//! in Omicron's `nexus/src/app/support_shell.rs`.

use std::fs::read;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http::Uri;
use http::header::{AUTHORIZATION, HeaderValue};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::spawn;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{interval, sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use x509_cert::Certificate;
use x509_cert::der::Encode;

/// How long to wait for TCP toward Nexus.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to back off a failed accept (say, EMFILE) rather than
/// retrying it hot.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// How often to ping, so NAT and LB idle timers see a live flow
/// while the operator thinks. The far side auto-pongs.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// What went wrong starting or probing the tunnel.
#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("can't listen on loopback: {0}")]
    Listen(io::Error),
    #[error("invalid Nexus URL `{url}`: {reason}")]
    NexusUrl { url: String, reason: &'static str },
    #[error("can't read root certificate `{path}`: {error}")]
    Root { path: PathBuf, error: io::Error },
    #[error("can't parse root certificate `{0}`")]
    RootPem(PathBuf),
    #[error("an https Nexus URL needs `--nexus-root`")]
    MissingRoots,
    #[error("tunnel probe failed: {0}")]
    Probe(String),
}

/// Where the websockets go and how they authenticate.
struct Target {
    host: String,
    port: u16,
    resolve: Option<SocketAddr>,
    uri: Uri,
    token: String,
    tls: Option<TlsConnector>,
}

/// A running tunnel. Dropping it closes the listener and every
/// connection in flight.
pub struct Tunnel {
    /// The loopback URL standing in for the sush proxy.
    pub url: String,
    listener_task: JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.listener_task.abort();
    }
}

impl Tunnel {
    /// Start forwarding loopback connections to the rack's sush proxy
    /// by way of Nexus, probing the path once before accepting any.
    pub async fn start(
        nexus: &str,
        rack_id: &str,
        token: &str,
        roots: &[PathBuf],
        resolve: Option<SocketAddr>,
    ) -> Result<Tunnel, TunnelError> {
        let target = Arc::new(target(nexus, rack_id, token, roots, resolve)?);

        // A dead path should fail the command now, not as a
        // connection reset from the listener later.
        probe(&target).await.map_err(TunnelError::Probe)?;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(TunnelError::Listen)?;
        let url = format!(
            "https://{}",
            listener.local_addr().map_err(TunnelError::Listen)?
        );
        let listener_task = spawn(async move {
            // Connections outlive neither this task nor the JoinSet.
            let mut connections = JoinSet::new();
            loop {
                match listener.accept().await {
                    Ok((stream, _peer)) => {
                        let target = Arc::clone(&target);
                        connections.spawn(async move {
                            if let Err(error) = forward(&target, stream).await {
                                eprintln!("⚠️ Tunnel connection failed: {error}");
                            }
                        });
                    }
                    Err(_) => sleep(ACCEPT_RETRY).await,
                }
                while connections.try_join_next().is_some() {}
            }
        });
        Ok(Tunnel { url, listener_task })
    }
}

/// Resolve the flags into a connection target.
fn target(
    nexus: &str,
    rack_id: &str,
    token: &str,
    roots: &[PathBuf],
    resolve: Option<SocketAddr>,
) -> Result<Target, TunnelError> {
    let invalid = |reason| TunnelError::NexusUrl {
        url: nexus.to_string(),
        reason,
    };
    let uri = nexus.parse::<Uri>().map_err(|_| invalid("unparseable"))?;
    let secure = match uri.scheme_str() {
        None | Some("https") => true,
        Some("http") => false,
        Some(_) => return Err(invalid("scheme must be http or https")),
    };
    // The bare host connects and names the server; the authority form
    // keeps its brackets for the request URI.
    let raw = uri.host().ok_or_else(|| invalid("no host"))?;
    let host = raw
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let scheme = if secure { "wss" } else { "ws" };
    if !rack_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(invalid("bad rack id"));
    }
    let uri = format!(
        "{scheme}://{authority}:{port}/v1/system/hardware/racks/{rack_id}/support-shell/tunnel"
    )
    .parse::<Uri>()
    .map_err(|_| invalid("bad rack id"))?;

    let tls = if secure {
        if roots.is_empty() {
            return Err(TunnelError::MissingRoots);
        }
        let mut store = RootCertStore::empty();
        for path in roots {
            let pem = read(path).map_err(|error| TunnelError::Root {
                path: path.clone(),
                error,
            })?;
            // Roots often arrive bundled; take every certificate.
            let chain = Certificate::load_pem_chain(&pem)
                .map_err(|_| TunnelError::RootPem(path.clone()))?;
            for cert in chain {
                let der = cert
                    .to_der()
                    .map_err(|_| TunnelError::RootPem(path.clone()))?;
                store
                    .add(CertificateDer::from(der))
                    .map_err(|_| TunnelError::RootPem(path.clone()))?;
            }
        }
        let config = ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth();
        Some(TlsConnector::from(Arc::new(config)))
    } else {
        None
    };
    Ok(Target {
        host,
        port,
        resolve,
        uri,
        token: token.to_string(),
        tls,
    })
}

/// Upgrade an established stream into an authenticated WebSocket.
async fn handshake<S>(target: &Target, stream: S) -> Result<WebSocketStream<S>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = target
        .uri
        .clone()
        .into_client_request()
        .map_err(|e| e.to_string())?;
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {}", target.token)
            .parse::<HeaderValue>()
            .map_err(|e| e.to_string())?,
    );
    let (ws, _response) = client_async(request, stream).await.map_err(describe)?;
    Ok(ws)
}

/// Keep a refusal's response body: Nexus says why in it.
fn describe(error: WsError) -> String {
    match error {
        WsError::Http(response) => {
            let status = response.status();
            match response.into_body() {
                Some(body) if !body.is_empty() => {
                    format!("{status}: {}", String::from_utf8_lossy(&body))
                }
                _ => status.to_string(),
            }
        }
        other => other.to_string(),
    }
}

/// Connect TCP toward Nexus, impatiently.
async fn dial(target: &Target) -> Result<TcpStream, String> {
    let connect = async {
        match target.resolve {
            Some(addr) => TcpStream::connect(addr).await,
            None => TcpStream::connect((target.host.as_str(), target.port)).await,
        }
    };
    match timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(tcp)) => {
            let _ = tcp.set_nodelay(true);
            Ok(tcp)
        }
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(String::from("connect timed out")),
    }
}

/// Prove the path to Nexus once, before standing behind it.
async fn probe(target: &Target) -> Result<(), String> {
    let tcp = dial(target).await?;
    match &target.tls {
        Some(tls) => {
            let name = ServerName::try_from(target.host.clone()).map_err(|e| e.to_string())?;
            let stream = tls.connect(name, tcp).await.map_err(|e| e.to_string())?;
            let _ = handshake(target, stream).await?.close(None).await;
        }
        None => {
            let _ = handshake(target, tcp).await?.close(None).await;
        }
    }
    Ok(())
}

/// Carry one loopback connection over a fresh WebSocket to Nexus.
async fn forward(target: &Target, conn: TcpStream) -> Result<(), String> {
    let tcp = dial(target).await?;
    match &target.tls {
        Some(tls) => {
            let name = ServerName::try_from(target.host.clone()).map_err(|e| e.to_string())?;
            let stream = tls.connect(name, tcp).await.map_err(|e| e.to_string())?;
            pipe(conn, handshake(target, stream).await?).await;
        }
        None => pipe(conn, handshake(target, tcp).await?).await,
    }
    Ok(())
}

/// Copy bytes both ways until either side finishes. The mirror of the
/// Nexus half's pipe: when one direction ends, both are torn down.
pub async fn pipe<S>(tcp: TcpStream, ws: WebSocketStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tcp.set_nodelay(true);
    let (mut ws_sink, mut ws_source) = ws.split();
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let inbound = async {
        while let Some(message) = ws_source.next().await {
            match message {
                Ok(Message::Binary(data)) => {
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
        // As on the Nexus side, teardown drops the other direction:
        // no half-close support, by design.
        let _ = tcp_write.shutdown().await;
    };

    let outbound = async {
        let mut buf = [0; 0x2000];
        let mut keepalive = interval(PING_INTERVAL);
        keepalive.tick().await;
        loop {
            select! {
                _ = keepalive.tick() => {
                    if ws_sink.send(Message::Ping(Bytes::new())).await.is_err() {
                        break;
                    }
                }
                read = tcp_read.read(&mut buf) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if ws_sink
                            .send(Message::binary(buf[..n].to_vec()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                },
            }
        }
        let _ = ws_sink.send(Message::Close(None)).await;
    };

    select! {
        _ = inbound => {}
        _ = outbound => {}
    }
}
