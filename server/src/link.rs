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
//! RFD 620 accepts. A per-peer stash of warm connections keeps that price
//! off the critical path during bursts: dials pop a pre-established
//! connection when one is ready, and refills run in the background only
//! while a peer stays active. Expiry is enforced at dial time, so the
//! last connection of a burst may linger well past its TTL.
//!
//! A stashed connection can die while it waits, most plausibly when the
//! peer restarts or its router evicts a connection that never spoke. A
//! stream built on such a connection fails its whole session and the
//! link is re-established, the same recovery as any other transport
//! failure. A silently dead path is worse: a warm connection skips the
//! dial timeout, leaving the session timeout as the backstop, which is
//! the routed contract's own answer for established connections that
//! go dark.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use camino::Utf8PathBuf;
use rumors::link::routed::{Config, Dial, Endpoint, Incoming, Listen, RoutedLink};
use slog::{Logger, info, o, warn};
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

/// Inbound connections the link router holds mid-header. Every peer
/// may park a stashed connection on our router, on top of the usual
/// dial bursts, so this needs room for a whole rack of both.
const PENDING_HEADERS: usize = 128;

/// Per-peer warm connections.
const STASH_DEPTH: usize = 1;

/// How long a stashed connection stays usable.
const STASH_TTL: Duration = Duration::from_secs(60);

/// How recently a peer must have been dialed for refills to continue.
/// Refills stop outside this window, so an idle rack makes no
/// handshakes at all.
const STASH_ACTIVITY: Duration = Duration::from_secs(30);

/// Warm connections held per peer, ready to become streams. A dial
/// pays a full attested handshake, with the RoT in the loop over IPCC,
/// so a burst of streams should run against connections established
/// off the critical path.
struct Stash<C> {
    peers: HashMap<SocketAddrV6, PeerStash<C>>,
}

struct PeerStash<C> {
    conns: VecDeque<(C, Instant)>,
    last_dial: Instant,
    refill: Refill,
}

/// Whether a refill task is in flight for a peer.
enum Refill {
    Idle,
    Pending,
}

impl<C> Stash<C> {
    fn new() -> Self {
        Stash {
            peers: HashMap::new(),
        }
    }

    /// Take the freshest warm connection for `addr`, noting the dial.
    fn pop(&mut self, addr: &SocketAddrV6, now: Instant) -> Option<C> {
        let peer = self.peers.get_mut(addr)?;
        peer.last_dial = now;
        while let Some((conn, born)) = peer.conns.pop_back() {
            if now.duration_since(born) < STASH_TTL {
                return Some(conn);
            }
        }
        None
    }

    /// Note a fresh dial to `addr`, opening its activity window.
    fn note_dial(&mut self, addr: SocketAddrV6, now: Instant) {
        let peer = self.peers.entry(addr).or_insert_with(|| PeerStash {
            conns: VecDeque::new(),
            last_dial: now,
            refill: Refill::Idle,
        });
        peer.last_dial = now;
    }

    /// Whether a refill for `addr` should start now. Claims the refill
    /// slot when it returns true; the caller must report back with
    /// [`refilled`](Self::refilled).
    fn want_refill(&mut self, addr: &SocketAddrV6, now: Instant) -> bool {
        let Some(peer) = self.peers.get_mut(addr) else {
            return false;
        };
        if matches!(peer.refill, Refill::Pending)
            || peer.conns.len() >= STASH_DEPTH
            || now.duration_since(peer.last_dial) > STASH_ACTIVITY
        {
            return false;
        }
        peer.refill = Refill::Pending;
        true
    }

    /// Report a claimed refill's result.
    fn refilled(&mut self, addr: &SocketAddrV6, conn: Option<C>, now: Instant) {
        if let Some(peer) = self.peers.get_mut(addr) {
            assert!(matches!(peer.refill, Refill::Pending));
            peer.refill = Refill::Idle;
            if let Some(conn) = conn
                && peer.conns.len() < STASH_DEPTH
            {
                peer.conns.push_back((conn, now));
            }
        }
    }

    /// Drop expired connections and forget idle peers.
    fn sweep(&mut self, now: Instant) {
        for peer in self.peers.values_mut() {
            peer.conns
                .retain(|(_, born)| now.duration_since(*born) < STASH_TTL);
        }
        self.peers.retain(|_, peer| {
            matches!(peer.refill, Refill::Pending)
                || !peer.conns.is_empty()
                || now.duration_since(peer.last_dial) <= STASH_ACTIVITY
        });
    }
}

/// Dials one attested sprockets connection per link stream, keeping a
/// warm stash per active peer so bursts skip the handshake latency.
#[derive(Clone)]
pub struct SprocketsDial {
    log: Logger,
    config: SprocketsConfig,
    corpus: CorpusSource,
    timeout: Duration,
    stash: Arc<Mutex<Stash<SprocketsConn>>>,
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
            stash: Arc::new(Mutex::new(Stash::new())),
        }
    }

    /// One full sprockets handshake to `addr`.
    async fn connect(&self, addr: SocketAddrV6) -> io::Result<SprocketsConn> {
        let started = Instant::now();
        let config = self.config.clone();
        let corpus = self.corpus.clone();
        let log = self.log.clone();
        // Sprockets connects are not cancel safe, so the handshake runs in
        // its own task and this future only awaits the result. The corpus
        // closure runs in the task too, so a panic there surfaces as a
        // failed dial instead of unwinding the caller.
        let dial = spawn(async move {
            Client::connect(config, addr, corpus(), log)
                .await
                .map_err(io::Error::other)
        });
        match timeout(self.timeout, dial).await {
            Ok(joined) => {
                let conn = SprocketsConn::new(joined.map_err(io::Error::other)??);
                info!(
                    self.log, "handshake complete";
                    "peer" => %addr,
                    "elapsed_ms" => started.elapsed().as_millis(),
                );
                Ok(conn)
            }
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dialing {addr} timed out"),
            )),
        }
    }

    /// Start a background refill for `addr` if its stash wants one.
    fn refill(&self, addr: SocketAddrV6) {
        if !self
            .stash
            .lock()
            .unwrap()
            .want_refill(&addr, Instant::now())
        {
            return;
        }
        let this = self.clone();
        spawn(async move {
            let conn = match this.connect(addr).await {
                Ok(conn) => Some(conn),
                Err(err) => {
                    warn!(this.log, "stash refill failed"; "peer" => %addr, "error" => %err);
                    None
                }
            };
            this.stash
                .lock()
                .unwrap()
                .refilled(&addr, conn, Instant::now());
        });
    }
}

impl Dial for SprocketsDial {
    type Addr = SocketAddr;
    type Conn = SprocketsConn;

    async fn dial(&self, addr: &SocketAddr) -> io::Result<SprocketsConn> {
        let SocketAddr::V6(addr) = *addr else {
            return Err(io::Error::other(format!("sush gossip needs IPv6: {addr}")));
        };
        let warm = {
            let mut stash = self.stash.lock().unwrap();
            let now = Instant::now();
            stash.sweep(now);
            stash.pop(&addr, now)
        };
        let conn = if let Some(conn) = warm {
            conn
        } else {
            let conn = self.connect(addr).await?;
            self.stash.lock().unwrap().note_dial(addr, Instant::now());
            conn
        };
        self.refill(addr);
        Ok(conn)
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
        let (endpoint, incoming, router) = Endpoint::new(
            listen,
            SocketAddr::V6(bound),
            dial,
            Config {
                pending_headers: PENDING_HEADERS,
                ..Config::default()
            },
        )
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

#[cfg(test)]
mod test {
    use super::*;

    const ADDR: SocketAddrV6 = SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 1, 0, 0);

    #[test]
    fn stash_lifecycle() {
        let mut stash: Stash<u32> = Stash::new();
        let t0 = Instant::now();

        // Unknown peers neither pop nor refill.
        assert_eq!(stash.pop(&ADDR, t0), None);
        assert!(!stash.want_refill(&ADDR, t0));

        // A fresh dial opens the activity window and claims one refill.
        stash.note_dial(ADDR, t0);
        assert!(stash.want_refill(&ADDR, t0));
        assert!(!stash.want_refill(&ADDR, t0), "refill slot is claimed");
        stash.refilled(&ADDR, Some(7), t0);

        // The stash is full, so no further refill; the warm connection
        // pops and then wants refilling again.
        assert!(!stash.want_refill(&ADDR, t0));
        assert_eq!(stash.pop(&ADDR, t0), Some(7));
        assert_eq!(stash.pop(&ADDR, t0), None);
        assert!(stash.want_refill(&ADDR, t0));
        stash.refilled(&ADDR, None, t0);

        // Expired connections do not pop.
        assert!(stash.want_refill(&ADDR, t0));
        stash.refilled(&ADDR, Some(8), t0);
        assert_eq!(stash.pop(&ADDR, t0 + STASH_TTL), None);

        // The expired pop counted as a dial, so the window is open just
        // inside its boundary and closed just outside; only then does a
        // sweep forget the peer.
        let edge = t0 + STASH_TTL + STASH_ACTIVITY;
        assert!(stash.want_refill(&ADDR, edge));
        stash.refilled(&ADDR, None, edge);
        let late = edge + Duration::from_secs(1);
        assert!(!stash.want_refill(&ADDR, late));
        stash.sweep(late);
        assert!(stash.peers.is_empty());
    }

    /// A sweep must keep a peer whose refill is in flight, or the
    /// refill would report to a forgotten peer and drop its connection.
    #[test]
    fn sweep_keeps_pending_refills() {
        let mut stash: Stash<u32> = Stash::new();
        let t0 = Instant::now();
        stash.note_dial(ADDR, t0);
        assert!(stash.want_refill(&ADDR, t0));

        let late = t0 + STASH_TTL + STASH_ACTIVITY + Duration::from_secs(1);
        stash.sweep(late);
        assert!(!stash.peers.is_empty(), "pending refill retains the peer");
        stash.refilled(&ADDR, Some(9), late);
        assert_eq!(stash.pop(&ADDR, late), Some(9));

        // Reporting a refill for a forgotten peer drops the connection.
        stash.sweep(late + STASH_TTL + STASH_ACTIVITY + Duration::from_secs(1));
        assert!(stash.peers.is_empty());
        stash.refilled(&ADDR, Some(10), late);
        assert_eq!(stash.pop(&ADDR, late), None);
    }
}
