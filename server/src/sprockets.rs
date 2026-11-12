// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Attested sprockets connections for gossip peers.

use std::error::Error;
use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use camino::Utf8PathBuf;
use sled_hardware_types::BaseboardId;
use slog::{Logger, o, warn};
use sprockets_tls::keys::SprocketsConfig;
use sprockets_tls::{Client as TlsClient, Server as TlsServer, Stream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::spawn_blocking;
use tokio::time::{sleep, timeout};
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

/// Produce the paths to the attestation corpus. Called once per handshake.
pub type CorpusSource = Arc<dyn Fn() -> Vec<Utf8PathBuf> + Send + Sync>;

const HANDSHAKE_QUEUE_DEPTH: usize = 32;
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// A sprockets connection to a gossip peer, and the baseboard the peer
/// attested to in the handshake. Closed on drop.
pub struct AttestedPeerConnection {
    peer: BaseboardId,
    stream: Option<Stream<TcpStream>>,
}

impl AttestedPeerConnection {
    /// Set up an attested stream for a gossip peer.
    fn new(mut stream: Stream<TcpStream>) -> io::Result<Self> {
        let peer = platform_id_to_baseboard_id(stream.peer_platform_id().as_str())?;
        stream.inner().get_ref().0.set_nodelay(true)?;
        Ok(AttestedPeerConnection {
            peer,
            stream: Some(stream),
        })
    }

    /// The baseboard the peer attested to.
    pub fn peer(&self) -> &BaseboardId {
        &self.peer
    }

    fn stream(&mut self) -> Pin<&mut Stream<TcpStream>> {
        Pin::new(self.stream.as_mut().expect("stream present until drop"))
    }
}

impl AsyncRead for AttestedPeerConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.stream().poll_read(cx, buf)
    }
}

impl AsyncWrite for AttestedPeerConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream().poll_shutdown(cx)
    }
}

impl Drop for AttestedPeerConnection {
    fn drop(&mut self) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        // A dropped TLS connection sends a bare FIN, which rustls
        // reports to the peer as an unexpected end of file, so the drop
        // hands the connection to a task that shuts it down properly.
        // Outside a runtime there is no one left to read the closing
        // alert either, so let the connection drop abruptly.
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Convert a platform ID to a baseboard ID.
pub fn platform_id_to_baseboard_id(platform_id: &str) -> io::Result<BaseboardId> {
    let fields: Vec<&str> = platform_id.split(':').collect();
    match fields[..] {
        [_, part_number, _, serial_number] => Ok(BaseboardId {
            part_number: part_number.to_string(),
            serial_number: serial_number.to_string(),
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unparseable platform id: {platform_id}"),
        )),
    }
}

/// Run a sprockets handshake on a blocking thread, giving up after
/// `duration`.
///
/// Sprockets makes blocking IPCC calls to the RoT from inside rustls
/// callbacks.
async fn handshake<F, T, E>(duration: Duration, future: F) -> io::Result<T>
where
    F: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Into<Box<dyn Error + Send + Sync>> + Send + 'static,
{
    let runtime = Handle::current();
    let task = spawn_blocking(move || runtime.block_on(timeout(duration, future)));
    match task.await {
        Ok(Ok(result)) => result.map_err(io::Error::other),
        Ok(Err(_)) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "handshake timed out",
        )),
        Err(err) => Err(io::Error::other(err)),
    }
}

/// Dials gossip peers. Each dial appraises the peer against the current
/// corpus, and gives up after `timeout`.
#[derive(Clone)]
pub struct Dialer {
    log: Logger,
    config: SprocketsConfig,
    corpus: CorpusSource,
    timeout: Duration,
}

impl Dialer {
    pub fn new(
        log: &Logger,
        config: SprocketsConfig,
        corpus: CorpusSource,
        timeout: Duration,
    ) -> Self {
        Dialer {
            log: log.new(o!("component" => "sprockets dial")),
            config,
            corpus,
            timeout,
        }
    }

    /// Connect to the peer listening at `addr`, returning an attested connection.
    pub async fn dial(&self, addr: SocketAddrV6) -> io::Result<AttestedPeerConnection> {
        let config = self.config.clone();
        let corpus = self.corpus.clone();
        let log = self.log.clone();
        let stream = handshake(self.timeout, async move {
            TlsClient::connect(config, addr, (corpus)(), log).await
        })
        .await?;
        AttestedPeerConnection::new(stream)
    }
}

/// Accepts connections from gossip peers.
pub struct Listener {
    connections: mpsc::Receiver<AttestedPeerConnection>,
    local_addr: SocketAddrV6,
}

impl Listener {
    /// Listen on `listen_addr` until `shutdown`. Each incoming connection
    /// gets its own handshake, so one slow handshake does not hold up the
    /// others; each gives up after `timeout`.
    pub async fn bind(
        log: &Logger,
        config: SprocketsConfig,
        corpus: CorpusSource,
        listen_addr: SocketAddrV6,
        timeout: Duration,
        shutdown: CancellationToken,
    ) -> io::Result<Self> {
        let log = log.new(o!("component" => "sprockets listen"));
        let server = TlsServer::new(config, listen_addr, log.clone())
            .await
            .map_err(io::Error::other)?;
        let local_addr = match server.listen_addr()? {
            SocketAddr::V6(addr) => addr,
            SocketAddr::V4(addr) => {
                return Err(io::Error::other(format!("listening on IPv4 {addr}")));
            }
        };
        let (tx, connections) = mpsc::channel(HANDSHAKE_QUEUE_DEPTH);
        spawn(accept_connections(
            log, server, corpus, timeout, tx, shutdown,
        ));
        Ok(Listener {
            connections,
            local_addr,
        })
    }

    /// The address the listener bound, which peers dial us at.
    pub fn local_addr(&self) -> SocketAddrV6 {
        self.local_addr
    }

    /// The next attested connection, or `None` once the listener has
    /// stopped. Cancel safe.
    pub async fn accept(&mut self) -> Option<AttestedPeerConnection> {
        self.connections.recv().await
    }
}

/// Accept connections until `shutdown`, run each one's handshake in its
/// own task, and send them on `connections`.
async fn accept_connections(
    log: Logger,
    server: TlsServer,
    corpus: CorpusSource,
    timeout: Duration,
    connections: mpsc::Sender<AttestedPeerConnection>,
    shutdown: CancellationToken,
) {
    loop {
        select! {
            _ = shutdown.cancelled() => break,
            accepted = server.accept((corpus)()) => match accepted {
                Ok(acceptor) => {
                    let log = log.clone();
                    let connections = connections.clone();
                    let addr = acceptor.addr();
                    spawn(async move {
                        let conn = handshake(timeout, acceptor.handshake())
                            .await
                            .and_then(|(stream, _)| AttestedPeerConnection::new(stream));
                        match conn {
                            Ok(conn) => {
                                let _ = connections.send(conn).await;
                            }
                            Err(err) => {
                                warn!(log, "sprockets handshake failed"; "addr" => %addr, "error" => %err);
                            }
                        }
                    });
                }
                Err(err) => {
                    warn!(log, "accept failed"; "error" => %err);
                    sleep(ACCEPT_RETRY).await;
                }
            },
        }
    }
}
