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
//! with the RoT in the loop, and the RoT serializes them. rumors itself
//! holds a completed stream's connection idle and reuses it for the next
//! stream on that link. [`Dial::dial`] therefore pays that handshake
//! only when a link needs a connection it does not already hold.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use camino::Utf8PathBuf;
use rumors::link::STREAM_COUNT;
use rumors::link::routed::{Config, Dial, Endpoint, Incoming, Listen, RoutedLink};
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, o, warn};
use sprockets_tls::keys::SprocketsConfig;
use sprockets_tls::{Client, Server};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

/// The [`Link`](rumors::link::Link) this transport builds.
pub type SprocketsLink = RoutedLink<SprocketsDial>;

/// Where the attestation corpus comes from, consulted per handshake.
pub type CorpusSource = Arc<dyn Fn() -> Vec<Utf8PathBuf> + Send + Sync>;

/// Completed handshakes the listener holds while the router catches up.
const HANDSHAKE_QUEUE_DEPTH: usize = 64;

/// Inbound connections that the router holds mid-header. Enough
/// for a whole rack opening full stream complements at once; idle
/// connections parked between streams do not count against this.
const PENDING_HEADERS: usize = STREAM_COUNT * 32;

/// How long to wait after a failed accept before accepting again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// One sprockets connection, closed on drop.
pub struct SprocketsConn(Option<sprockets_tls::Stream<TcpStream>>);

impl SprocketsConn {
    fn stream(&mut self) -> Pin<&mut sprockets_tls::Stream<TcpStream>> {
        Pin::new(self.0.as_mut().expect("stream present until drop"))
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
        let Some(mut stream) = self.0.take() else {
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

/// The baseboards peers have attested at handshake, kept on a watch
/// channel so consumers follow the table as it changes.
#[derive(Clone)]
pub struct Baseboards {
    known: watch::Sender<AttestedBaseboards>,
}

/// The attestation tables: a dialed connection names its peer's listen
/// address exactly; an accepted one names only its source IP. The
/// bootstrap network keeps IPs one-to-one with sleds, but localhost
/// tests stack peers on one IP, so an ambiguous IP resolves to no one.
/// [`Baseboards::retain`] bounds both tables to the peer set.
#[derive(Default)]
pub struct AttestedBaseboards {
    dialed: BTreeMap<SocketAddrV6, BaseboardId>,
    accepted: BTreeMap<Ipv6Addr, BTreeSet<BaseboardId>>,
}

impl AttestedBaseboards {
    /// The baseboard attested at `addr`: seen on a dialed connection,
    /// or the only baseboard to have connected from the same IP.
    pub fn resolve(&self, addr: &SocketAddr) -> Option<BaseboardId> {
        let SocketAddr::V6(addr) = addr else {
            return None;
        };
        if let Some(id) = self.dialed.get(addr) {
            return Some(id.clone());
        }
        match self.accepted.get(addr.ip()) {
            Some(ids) if ids.len() == 1 => ids.first().cloned(),
            _ => None,
        }
    }
}

impl Baseboards {
    fn new() -> Self {
        Baseboards {
            known: watch::Sender::new(AttestedBaseboards::default()),
        }
    }

    /// Record the peer attested on a connection dialed to `addr`.
    fn dialed(&self, log: &Logger, addr: SocketAddrV6, platform_id: &str) {
        let Some(id) = baseboard(log, platform_id) else {
            return;
        };
        self.known.send_if_modified(|known| {
            let grew = known.dialed.get(&addr) != Some(&id);
            if grew {
                debug!(log, "attested by dial"; "addr" => %addr, "baseboard" => %id);
                known.dialed.insert(addr, id);
            }
            grew
        });
    }

    /// Record the peer attested on a connection accepted from `ip`.
    fn accepted(&self, log: &Logger, ip: Ipv6Addr, platform_id: &str) {
        let Some(id) = baseboard(log, platform_id) else {
            return;
        };
        self.known.send_if_modified(|known| {
            if known.accepted.entry(ip).or_default().insert(id.clone()) {
                debug!(log, "attested by accept"; "ip" => %ip, "baseboard" => %id);
                true
            } else {
                false
            }
        });
    }

    /// A receiver following the attestation tables.
    pub fn watch(&self) -> watch::Receiver<AttestedBaseboards> {
        self.known.subscribe()
    }

    /// Forget the baseboards of peers outside `peers`.
    fn retain(&self, peers: &BTreeSet<SocketAddrV6>) {
        let ips: BTreeSet<&Ipv6Addr> = peers.iter().map(|addr| addr.ip()).collect();
        self.known.send_if_modified(|known| {
            let before = (known.dialed.len(), known.accepted.len());
            known.dialed.retain(|addr, _| peers.contains(addr));
            known.accepted.retain(|ip, _| ips.contains(ip));
            (known.dialed.len(), known.accepted.len()) != before
        });
    }
}

/// The baseboard a platform id names (`prefix:part:revision:serial`).
pub(crate) fn baseboard(log: &Logger, platform_id: &str) -> Option<BaseboardId> {
    let mut fields = platform_id.split(':');
    match (fields.nth(1), fields.nth(1)) {
        (Some(part_number), Some(serial_number)) => Some(BaseboardId {
            part_number: part_number.to_string(),
            serial_number: serial_number.to_string(),
        }),
        _ => {
            warn!(log, "unparseable platform id"; "platform_id" => platform_id);
            None
        }
    }
}

/// Dials attested sprockets connections, one handshake each.
#[derive(Clone)]
pub struct SprocketsDial {
    log: Logger,
    config: SprocketsConfig,
    corpus: CorpusSource,
    baseboards: Baseboards,
    timeout: Duration,
}

impl SprocketsDial {
    /// Dial with `config`, appraising peers against the corpus of the
    /// moment, and giving up on any one handshake after `timeout`.
    pub fn new(
        log: &Logger,
        config: SprocketsConfig,
        corpus: CorpusSource,
        baseboards: Baseboards,
        timeout: Duration,
    ) -> Self {
        SprocketsDial {
            log: log.new(o!("component" => "sprockets dial")),
            config,
            corpus,
            baseboards,
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
        let corpus = self.corpus.clone();
        let log = self.log.clone();
        // Sprockets connects are not cancel safe, and the router may
        // cancel this future, so the handshake runs in its own task and
        // this future only awaits the result. The deadline lives inside
        // the task, so an abandoned handshake still terminates at it
        // instead of holding the RoT unbounded. The corpus source is
        // consulted inside the task, so a panic there fails this dial
        // instead of unwinding the caller.
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
        self.baseboards
            .dialed(&self.log, addr, stream.peer_platform_id().as_str());
        Ok(SprocketsConn(Some(stream)))
    }
}

/// This process's gossip transport: the sprockets endpoint peers link to,
/// and the links they establish toward us.
pub struct Transport {
    endpoint: Endpoint<SprocketsDial>,
    incoming: Incoming<SprocketsDial>,
    baseboards: Baseboards,
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
        let baseboards = Baseboards::new();
        let (listen, bound) = SprocketsListen::bind(
            log,
            config.clone(),
            corpus.clone(),
            baseboards.clone(),
            listen_addr,
            dial_timeout,
            shutdown.clone(),
        )
        .await?;
        let dial = SprocketsDial::new(log, config, corpus, baseboards.clone(), dial_timeout);
        let router_config = Config {
            pending_headers: PENDING_HEADERS,
            ..Config::default()
        };
        let (endpoint, incoming, router) =
            Endpoint::new(listen, SocketAddr::V6(bound), dial, router_config)
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
            baseboards,
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

    /// The baseboards peers have attested to this transport.
    pub fn baseboards(&self) -> &Baseboards {
        &self.baseboards
    }

    /// Drop the recorded baseboards of peers outside `peers`. Their
    /// idle connections live in rumors' links and close with them.
    pub fn retain_peers(&self, peers: &BTreeSet<SocketAddrV6>) {
        self.baseboards.retain(peers);
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
    /// How long an accepted connection may take to route its first
    /// stream before the router drops it and frees its slot.
    routing_deadline: Duration,
}

impl SprocketsListen {
    /// Listen on `listen_addr`, returning the listener and the address it
    /// actually bound, which is the name to advertise to peers.
    pub async fn bind(
        log: &Logger,
        config: SprocketsConfig,
        corpus: CorpusSource,
        baseboards: Baseboards,
        listen_addr: SocketAddrV6,
        routing_deadline: Duration,
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
        spawn(pump(server, corpus, baseboards, tx, log, shutdown));
        Ok((
            SprocketsListen {
                connections,
                routing_deadline,
            },
            bound,
        ))
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

    // Left at the never-expiring default, a stalled peer could hold a
    // routing slot forever.
    fn routing_deadline(&self) -> impl Future<Output = ()> + Send + 'static {
        sleep(self.routing_deadline)
    }
}

/// Accept connections and attest them until `shutdown`.
async fn pump(
    server: Server,
    corpus: CorpusSource,
    baseboards: Baseboards,
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
                    let baseboards = baseboards.clone();
                    let log = log.clone();
                    spawn(async move {
                        match acceptor.handshake().await {
                            // A closed queue means the endpoint is gone.
                            Ok((stream, peer)) => {
                                if let SocketAddr::V6(peer) = peer {
                                    let id = stream.peer_platform_id().as_str();
                                    baseboards.accepted(&log, *peer.ip(), id);
                                }
                                let conn = SprocketsConn(Some(stream));
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
