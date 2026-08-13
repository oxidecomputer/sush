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
//! A fresh connection costs a full attested handshake, most of a second
//! with the RoT in the loop, and the RoT serializes them. The dialer
//! therefore pools. rumors hands a completed stream's connection back
//! through [`Dial::recycle`], a qorb pool per peer holds it, and the next
//! stream to that peer draws it instead of dialing. Only clean returns
//! are reused: a connection dropped mid-stream is discarded at the
//! pool's door.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use camino::Utf8PathBuf;
use qorb::backend::{self, Backend};
use qorb::claim;
use qorb::policy::{Policy, SetConfig};
use qorb::pool::Pool;
use qorb::resolvers::fixed::FixedResolver;
use rumors::link::STREAM_COUNT;
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

/// Inbound connections the router holds mid-header. Recycled idle
/// connections park here between streams, so the bound admits a whole
/// rack's stream complements at once.
const PENDING_HEADERS: usize = STREAM_COUNT * 32;

/// How long to wait after a failed accept before accepting again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Connections per peer. The link contract's worst case is one control
/// stream plus a full complement for each of a pair's two links. Slots
/// are created on demand, so the cap is free when idle.
const MAX_SLOTS: usize = 2 * STREAM_COUNT + 1;

/// Idle connections kept warm per peer. Taking one stream leaves a
/// spare, so qorb fires no refill and reuses the recycled connection
/// rather than culling it.
const SPARES_WANTED: usize = 2;

/// Floor between one slot's reconnect attempts after a failure,
/// matched to the RoT's roughly one-per-second handshake rate.
const MIN_CONNECTION_BACKOFF: Duration = Duration::from_secs(1);

/// How often qorb re-checks an idle connection. The check is a no-op
/// (no ping), so the tick only bounces slot state. It must be finite:
/// qorb arms the timer by adding this to the current instant, and
/// `Duration::MAX`, which its docs suggest for disabling checks,
/// overflows the addition and kills the slot task.
const HEALTH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// One attested connection as a peer's pool holds it.
struct PooledConn {
    stream: Option<sprockets_tls::Stream<TcpStream>>,
    /// qorb returns a dropped claim to the pool no matter how its
    /// stream ended, so this bit tells a clean return from an abort:
    /// set as the connection is claimed, cleared only by
    /// [`Dial::recycle`], and checked at the pool's door, where a dirty
    /// connection is discarded.
    dirty: bool,
}

impl Drop for PooledConn {
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

/// One sprockets connection, carrying one link stream at a time.
///
/// A dialed connection is a claim on its peer's pool: dropping it
/// returns it, and the pool reuses it only if [`Dial::recycle`] marked
/// it clean first. An accepted connection belongs to the router, and
/// dropping it closes it.
pub struct SprocketsConn(Conn);

enum Conn {
    /// Accepted by the listener.
    Direct(Option<sprockets_tls::Stream<TcpStream>>),
    /// Claimed from a peer's pool.
    Pooled(claim::Handle<PooledConn>),
}

impl SprocketsConn {
    fn stream(&mut self) -> Pin<&mut sprockets_tls::Stream<TcpStream>> {
        let stream = match &mut self.0 {
            Conn::Direct(stream) => stream.as_mut(),
            Conn::Pooled(handle) => handle.stream.as_mut(),
        };
        Pin::new(stream.expect("stream present until drop"))
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
        // A pooled connection's drop is its return to the pool, which
        // discards it (shutting it down) unless it was recycled clean.
        let Conn::Direct(stream) = &mut self.0 else {
            return;
        };
        let Some(mut stream) = stream.take() else {
            return;
        };
        // As for `PooledConn`: shut down properly inside a runtime.
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Establishes a peer pool's connections, one attested handshake each.
struct PoolConnector {
    log: Logger,
    config: SprocketsConfig,
    corpus: CorpusSource,
    /// Ceiling on one handshake.
    timeout: Duration,
}

#[async_trait]
impl backend::Connector for PoolConnector {
    type Connection = PooledConn;

    async fn connect(&self, backend: &Backend) -> Result<PooledConn, backend::Error> {
        // The resolver only ever names IPv6 backends; see `Dial::dial`.
        let SocketAddr::V6(addr) = backend.address else {
            return Err(backend::Error::from(io::Error::other(format!(
                "sush gossip needs IPv6: {}",
                backend.address
            ))));
        };
        let config = self.config.clone();
        let corpus = self.corpus.clone();
        let log = self.log.clone();
        // Sprockets connects are not cancel safe, and qorb may cancel
        // this future, so the handshake runs in its own task and this
        // future only awaits the result. The deadline lives inside the
        // task, so an abandoned handshake still terminates at it
        // instead of holding the RoT unbounded. The corpus source is
        // consulted inside the task: if it panics, this connect fails,
        // not the pool.
        let deadline = self.timeout;
        let dial = spawn(async move {
            match timeout(deadline, Client::connect(config, addr, (corpus)(), log)).await {
                Ok(connected) => connected.map_err(io::Error::other),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("dialing {addr} timed out"),
                )),
            }
        });
        let stream = dial.await.map_err(io::Error::other)??;
        Ok(PooledConn {
            stream: Some(stream),
            dirty: false,
        })
    }

    async fn on_acquire(&self, conn: &mut PooledConn) -> Result<(), backend::Error> {
        // Pessimistic: only a clean recycle clears it.
        conn.dirty = true;
        Ok(())
    }

    async fn on_recycle(&self, conn: &mut PooledConn) -> Result<(), backend::Error> {
        if conn.dirty {
            return Err(backend::Error::from(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection was dropped mid-stream",
            )));
        }
        Ok(())
    }
}

/// Dials attested sprockets connections, pooled per peer.
#[derive(Clone)]
pub struct SprocketsDial {
    log: Logger,
    config: SprocketsConfig,
    corpus: CorpusSource,
    timeout: Duration,
    /// One pool per peer, created at first dial and dropped at prune.
    pools: Arc<Mutex<HashMap<SocketAddrV6, Arc<Pool<PooledConn>>>>>,
}

impl SprocketsDial {
    /// Dial with `config`, appraising peers against the corpus of the
    /// moment, and giving up on any one handshake or claim after
    /// `timeout`.
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
            pools: Arc::default(),
        }
    }

    /// The pool dialing `addr`, created on first use.
    fn pool(&self, addr: SocketAddrV6) -> Arc<Pool<PooledConn>> {
        self.pools
            .lock()
            .expect("pool table lock")
            .entry(addr)
            .or_insert_with(|| Arc::new(self.build(addr)))
            .clone()
    }

    fn build(&self, addr: SocketAddrV6) -> Pool<PooledConn> {
        let connector = Arc::new(PoolConnector {
            log: self.log.clone(),
            config: self.config.clone(),
            corpus: self.corpus.clone(),
            timeout: self.timeout,
        });
        let resolver = Box::new(FixedResolver::new([SocketAddr::V6(addr)]));
        let policy = Policy {
            spares_wanted: SPARES_WANTED,
            max_slots: MAX_SLOTS,
            claim_timeout: self.timeout,
            set_config: SetConfig {
                max_count: MAX_SLOTS,
                min_connection_backoff: MIN_CONNECTION_BACKOFF,
                // No liveness probing: a pooled connection that died
                // idle is discovered by the stream that draws it, and
                // the failed session re-links.
                health_interval: HEALTH_INTERVAL,
                ..SetConfig::default()
            },
            ..Policy::default()
        };
        match Pool::new(format!("gossip {addr}"), resolver, connector, policy) {
            Ok(pool) => pool,
            // Registration is telemetry-only; the pool works either way.
            Err(err) => err.into_inner(),
        }
    }

    /// Drop the pools of peers outside `peers`, closing their idle
    /// connections.
    fn retain(&self, peers: &BTreeSet<SocketAddrV6>) {
        self.pools
            .lock()
            .expect("pool table lock")
            .retain(|addr, _| peers.contains(addr));
    }
}

impl Dial for SprocketsDial {
    type Addr = SocketAddr;
    type Conn = SprocketsConn;

    async fn dial(&self, addr: &SocketAddr) -> io::Result<SprocketsConn> {
        let SocketAddr::V6(addr) = *addr else {
            return Err(io::Error::other(format!("sush gossip needs IPv6: {addr}")));
        };
        let handle =
            self.pool(addr).claim().await.map_err(|err| {
                io::Error::other(format!("claiming a connection to {addr}: {err}"))
            })?;
        Ok(SprocketsConn(Conn::Pooled(handle)))
    }

    fn recycle(&self, _peer: &SocketAddr, mut conn: SprocketsConn) {
        // The stream completed cleanly, so the connection may be
        // reused: clear the bit and let the drop return the claim.
        if let Conn::Pooled(handle) = &mut conn.0 {
            handle.dirty = false;
        }
    }
}

/// This process's gossip transport: the sprockets endpoint peers link to,
/// and the links they establish toward us.
pub struct Transport {
    endpoint: Endpoint<SprocketsDial>,
    incoming: Incoming<SprocketsDial>,
    dial: SprocketsDial,
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
        let router_config = Config {
            pending_headers: PENDING_HEADERS,
            ..Config::default()
        };
        let (endpoint, incoming, router) =
            Endpoint::new(listen, SocketAddr::V6(bound), dial.clone(), router_config)
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
            dial,
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

    /// Drop the connection pools of peers outside `peers`.
    pub fn retain_pools(&self, peers: &BTreeSet<SocketAddrV6>) {
        self.dial.retain(peers)
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
                                let conn = SprocketsConn(Conn::Direct(Some(stream)));
                                let _ = connections.send(conn).await;
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
