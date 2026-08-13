// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sprockets as a rumors [`routed`] transport.
//!
//! [`rumors::link::routed`] adapts an accept/connect transport to the link
//! contract, mapping every link stream to its own connection so that flow
//! control and half-close are the transport's own. This module supplies the
//! sprockets end of that adapter: a dialer, a listener, and the connection
//! type they exchange. Peers are authenticated and attested by sprockets,
//! which is what rumors asks of a transport it trusts.
//!
//! The price of the shape is a full sprockets handshake per stream, which
//! RFD 620 accepts.

use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use camino::Utf8PathBuf;
use rumors::link::routed::{Config, Dial, Endpoint, Incoming, Listen, RoutedLink};
use slog::{Logger, o, warn};
use sprockets_tls::keys::SprocketsConfig;
use sprockets_tls::{Client, Server};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

/// The [`Link`](rumors::link::Link) this transport builds.
pub type SprocketsLink = RoutedLink<SprocketsDial>;

/// Where the attestation corpus comes from, consulted per handshake.
pub type CorpusSource = Arc<dyn Fn() -> Vec<Utf8PathBuf> + Send + Sync>;

/// Completed handshakes the listener holds while the router catches up.
const HANDSHAKE_QUEUE_DEPTH: usize = 64;

/// How long to wait after a failed accept before accepting again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// One sprockets connection, carrying one link stream.
///
/// Dropping this must leave the peer at end-of-stream, because that is how
/// the session closes a data stream. A dropped TLS connection sends a bare
/// FIN, which rustls reports to the peer as an unexpected end of file, so
/// the drop hands the connection to a task that shuts it down properly.
pub struct SprocketsConn {
    stream: Option<sprockets_tls::Stream<TcpStream>>,
}

impl SprocketsConn {
    fn new(stream: sprockets_tls::Stream<TcpStream>) -> Self {
        SprocketsConn {
            stream: Some(stream),
        }
    }

    fn stream(&mut self) -> Pin<&mut sprockets_tls::Stream<TcpStream>> {
        Pin::new(self.stream.as_mut().expect("stream present until drop"))
    }
}

impl AsyncRead for SprocketsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.stream().poll_read(cx, buf)
    }
}

impl AsyncWrite for SprocketsConn {
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

impl Drop for SprocketsConn {
    fn drop(&mut self) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        // Outside a runtime there is no one left to read the closing alert
        // either, so let the connection drop abruptly.
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Dials one attested sprockets connection per link stream.
#[derive(Clone)]
pub struct SprocketsDial {
    log: Logger,
    config: SprocketsConfig,
    corpus: CorpusSource,
    timeout: Duration,
}

impl SprocketsDial {
    /// Dial with `config`, appraising peers against the corpus of the
    /// moment, and giving up on any one dial after `timeout`.
    pub fn new(
        log: &Logger,
        config: SprocketsConfig,
        corpus: CorpusSource,
        timeout: Duration,
    ) -> Self {
        SprocketsDial {
            log: log.new(o!("component" => "sprockets dial")),
            config,
            corpus,
            timeout,
        }
    }
}

impl Dial for SprocketsDial {
    type Addr = SocketAddr;
    type Conn = SprocketsConn;

    async fn dial(&self, addr: &SocketAddr) -> io::Result<SprocketsConn> {
        let SocketAddr::V6(addr) = *addr else {
            return Err(io::Error::other(format!("sush gossip needs IPv6: {addr}")));
        };
        let config = self.config.clone();
        let corpus = (self.corpus)();
        let log = self.log.clone();
        // Sprockets connects are not cancel safe, so the handshake runs in
        // its own task and this future only awaits the result.
        let dial = spawn(async move {
            Client::connect(config, addr, corpus, log)
                .await
                .map_err(io::Error::other)
        });
        match timeout(self.timeout, dial).await {
            Ok(joined) => Ok(SprocketsConn::new(joined.map_err(io::Error::other)??)),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dialing {addr} timed out"),
            )),
        }
    }
}

/// This process's gossip transport: the sprockets endpoint peers link to,
/// and the links they establish toward us.
pub struct Transport {
    endpoint: Endpoint<SprocketsDial>,
    incoming: Incoming<SprocketsDial>,
    bound: SocketAddrV6,
}

impl Transport {
    /// Listen on `listen_addr` and stand up the routing endpoint. Its
    /// router runs until `shutdown`, or until the listener fails.
    pub async fn new(
        log: &Logger,
        config: SprocketsConfig,
        corpus: CorpusSource,
        listen_addr: SocketAddrV6,
        dial_timeout: Duration,
        shutdown: CancellationToken,
    ) -> io::Result<Self> {
        let (listen, bound) = SprocketsListen::bind(
            log,
            config.clone(),
            corpus.clone(),
            listen_addr,
            shutdown.clone(),
        )
        .await?;
        let dial = SprocketsDial::new(log, config, corpus, dial_timeout);
        let (endpoint, incoming, router) =
            Endpoint::new(listen, SocketAddr::V6(bound), dial, Config::default())
                .map_err(io::Error::other)?;
        let log = log.new(o!("component" => "link router"));
        spawn(async move {
            select! {
                _ = shutdown.cancelled() => {}
                stopped = router => {
                    warn!(log, "router stopped, gossip is down"; "result" => ?stopped);
                }
            }
        });
        Ok(Transport {
            endpoint,
            incoming,
            bound,
        })
    }

    /// The address the listener bound, which peers dial us at.
    pub fn bound(&self) -> SocketAddrV6 {
        self.bound
    }

    /// A cheap handle for establishing links, free to move into tasks.
    pub fn endpoint(&self) -> Endpoint<SprocketsDial> {
        self.endpoint.clone()
    }

    /// Receive the next link a peer established toward us, with the name it
    /// advertised, or `None` once the router has stopped.
    pub async fn accept(&mut self) -> Option<(SocketAddr, SprocketsLink)> {
        let (info, link) = self.incoming.accept().await?;
        Some((info.peer, link))
    }
}

/// Yields this endpoint's inbound sprockets connections.
///
/// Accepting is two phases, and the second attests the peer, so this runs a
/// pump: one task accepts and hands each connection to its own handshake
/// task, and completed connections queue here. Handshakes therefore proceed
/// concurrently, and [`Listen::accept`] is a queue receive, which the
/// router may cancel freely.
pub struct SprocketsListen {
    connections: mpsc::Receiver<SprocketsConn>,
}

impl SprocketsListen {
    /// Listen on `listen_addr`, returning the listener and the address it
    /// actually bound, which is the name to advertise to peers.
    pub async fn bind(
        log: &Logger,
        config: SprocketsConfig,
        corpus: CorpusSource,
        listen_addr: SocketAddrV6,
        shutdown: CancellationToken,
    ) -> io::Result<(Self, SocketAddrV6)> {
        let log = log.new(o!("component" => "sprockets listen"));
        let server = Server::new(config, listen_addr, log.clone())
            .await
            .map_err(io::Error::other)?;
        let bound = match server.listen_addr()? {
            SocketAddr::V6(addr) => addr,
            SocketAddr::V4(addr) => {
                return Err(io::Error::other(format!("listening on IPv4 {addr}")));
            }
        };
        let (tx, connections) = mpsc::channel(HANDSHAKE_QUEUE_DEPTH);
        spawn(pump(server, corpus, tx, log, shutdown));
        Ok((SprocketsListen { connections }, bound))
    }
}

impl Listen for SprocketsListen {
    type Conn = SprocketsConn;

    async fn accept(&mut self) -> io::Result<SprocketsConn> {
        self.connections
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "sprockets listener stopped"))
    }
}

/// Accept connections and attest them until `shutdown`.
async fn pump(
    server: Server,
    corpus: CorpusSource,
    connections: mpsc::Sender<SprocketsConn>,
    log: Logger,
    shutdown: CancellationToken,
) {
    loop {
        select! {
            _ = shutdown.cancelled() => break,
            accepted = server.accept((corpus)()) => match accepted {
                Ok(acceptor) => {
                    let connections = connections.clone();
                    let log = log.clone();
                    spawn(async move {
                        match acceptor.handshake().await {
                            // A closed queue means the endpoint is gone.
                            Ok((stream, _)) => {
                                let _ = connections.send(SprocketsConn::new(stream)).await;
                            }
                            Err(err) => {
                                warn!(log, "handshake failed"; "error" => %err);
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
