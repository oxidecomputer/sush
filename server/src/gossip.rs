// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Drive a set of peers to converge into one gossip network.
//!
//! Each peer seeds its own network at startup, so peers in different
//! networks meet with [`Mismatch::Network`]. Both sides apply the same
//! rule to that error to pick which survives (see `remote_dominates`),
//! and the loser joins the winner's network. The process repeats until
//! only one network remains.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::pending;
use std::io;
use std::net::SocketAddrV6;
use std::time::Duration;

use futures::StreamExt as _;
use futures::stream::{self, Stream};
use rumors::error::Mismatch;
use rumors::{
    Changes, Connection, Count, Error, Gossip, Joined, Network, NoBookmark, Peer, Rumors,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, info, o, warn};
use sprockets_tls::keys::SprocketsConfig;
use tokio::io::{BufReader, ReadHalf, WriteHalf, split};
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior, interval, interval_at, sleep};
use tokio::{select, spawn};
use tokio_stream::wrappers::IntervalStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::JoinMap;

use crate::locker::Locker;
use crate::locker::bookmark::{BookmarkSource, SushBookmark};
use crate::sprockets::{AttestedPeerConnection, CorpusSource, Dialer, Listener};

/// The attested baseboards of our live gossip peers.
#[derive(Clone, Debug)]
pub struct ConnectedBaseboards(watch::Receiver<BTreeSet<BaseboardId>>);

impl ConnectedBaseboards {
    /// An empty set that never changes, for a server that does not gossip
    /// (see [`Seed::without_gossip`]).
    pub fn empty() -> Self {
        let (_tx, rx) = watch::channel(BTreeSet::new());
        Self(rx)
    }

    pub fn borrow(&self) -> watch::Ref<'_, BTreeSet<BaseboardId>> {
        self.0.borrow()
    }

    pub fn borrow_and_update(&mut self) -> watch::Ref<'_, BTreeSet<BaseboardId>> {
        self.0.borrow_and_update()
    }

    /// Wait for the set to change. Once the gossip manager is gone, the
    /// set can no longer change, so this never returns.
    pub async fn changed(&mut self) {
        if self.0.changed().await.is_err() {
            pending().await
        }
    }
}

/// Gossip manager timing.
#[derive(Clone, Debug)]
pub struct GossipConfig {
    pub reconnect: Duration,
    pub handshake_timeout: Duration,
    pub heartbeat: Duration,
    pub session_deadline: Duration,
}

impl Default for GossipConfig {
    /// These defaults suit a rack; tests should shrink them.
    fn default() -> Self {
        Self {
            reconnect: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(30),
            heartbeat: Duration::from_secs(30),
            session_deadline: Duration::from_secs(60),
        }
    }
}

/// A driver initiates a gossip session on every local change,
/// and on every `heartbeat` whether or not anything changed.
fn policy<T: Send + Sync + 'static>(
    changes: Changes<T>,
    heartbeat: Duration,
) -> impl Stream<Item = Gossip> + Send + 'static {
    let mut heartbeats = interval_at(Instant::now() + heartbeat, heartbeat);
    heartbeats.set_missed_tick_behavior(MissedTickBehavior::Delay);
    stream::select(
        changes.map(Gossip::from),
        IntervalStream::new(heartbeats).map(|_| Gossip::Unconditionally),
    )
}

/// A seeded network and its persistent identity.
#[derive(Debug)]
pub struct Seed<T: Send + Sync + 'static> {
    peer: Peer<T, SushBookmark>,
    bookmarks: BookmarkSource,
}

impl<T: Send + Sync + 'static> Seed<T> {
    /// Seed a fresh network with this server as its only peer.
    pub async fn grow(log: &Logger, locker: &Locker) -> Self
    where
        T: DeserializeOwned + Serialize + Eq + Send + Sync + 'static,
    {
        let bookmarks = BookmarkSource::new(log, locker);
        let handle = match locker.probe().await {
            Ok(()) => bookmarks.handle(),
            Err(_) => bookmarks.shed_handle(),
        };
        let peer = match Peer::seed().bookmark(handle).await {
            Ok(peer) => peer,
            Err(unbookmarked) => shed(&bookmarks, unbookmarked.peer).await,
        };
        Self { peer, bookmarks }
    }

    /// Return the network that this seed started.
    pub fn network(&self) -> Network {
        self.peer.network()
    }

    /// Convert this seed into a gossip network handle.
    pub fn into_rumors(self) -> Rumors<T, SushBookmark> {
        self.peer.into_rumors()
    }

    /// Convert this seed into a trivial, unchanging network for an
    /// isolated server.
    pub fn without_gossip(self) -> watch::Receiver<Rumors<T, SushBookmark>> {
        let (_tx, rx) = watch::channel(self.into_rumors());
        rx
    }
}

/// Attach a bookmark handle to `peer` that doesn't write anything.
async fn shed<T>(bookmarks: &BookmarkSource, peer: Peer<T, NoBookmark>) -> Peer<T, SushBookmark>
where
    T: DeserializeOwned + Serialize + Eq + Send + Sync + 'static,
{
    match peer.bookmark(bookmarks.shed_handle()).await {
        Ok(peer) => peer,
        Err(_) => unreachable!("shed bookmarks do not touch storage, so cannot fail"),
    }
}

/// Whether the peer's network dominates ours, by the rule in rumors'
/// [Bootstrapping without consensus](Peer#bootstrapping-without-consensus).
/// Any total order on networks breaks ties, as long as both sides use
/// the same one.
fn remote_dominates(
    local_events: &Count,
    remote_events: &Count,
    local_network: Network,
    remote_network: Network,
) -> bool {
    match remote_events.cmp(local_events) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => remote_network < local_network,
    }
}

/// Listen for sprockets connections on `listen_addr` and run a gossip
/// manager until `shutdown`. The manager connects to the addresses on
/// `peers`, drives gossip on every connection, and resolves network
/// collisions. Returns the address the listener bound, the channel
/// following the current network (starting at `seed`), and the channel
/// following the baseboards we hold live connections to. A caller that
/// cannot bind may fall back to a new seed's [`Seed::without_gossip`].
#[allow(clippy::too_many_arguments)]
pub async fn spawn_gossip<T>(
    log: &Logger,
    config: GossipConfig,
    sprockets: SprocketsConfig,
    corpus: CorpusSource,
    listen_addr: SocketAddrV6,
    peers: watch::Receiver<BTreeSet<SocketAddrV6>>,
    seed: Seed<T>,
    shutdown: CancellationToken,
) -> io::Result<(
    SocketAddrV6,
    watch::Receiver<Rumors<T, SushBookmark>>,
    ConnectedBaseboards,
)>
where
    T: DeserializeOwned + Serialize + Eq + Send + Sync + 'static,
{
    let listener = Listener::bind(
        log,
        sprockets.clone(),
        corpus.clone(),
        listen_addr,
        config.handshake_timeout,
        shutdown.clone(),
    )
    .await?;
    let local_addr = listener.local_addr();
    let dialer = Dialer::new(log, sprockets, corpus, config.handshake_timeout);
    let Seed { peer, bookmarks } = seed;
    let heartbeat = config.heartbeat;
    let deadline = config.session_deadline;
    let rumors = peer
        .gossip_when(move |changes| policy(changes, heartbeat))
        .session_deadline(move || sleep(deadline))
        .into_rumors();
    let (publish, subscribe) = watch::channel(rumors.clone());
    let (connected, subscribe_connected) = watch::channel(BTreeSet::new());
    let manager = Manager {
        log: log.new(o!("component" => "gossip manager")),
        config,
        dialer,
        listener,
        peers,
        rumors,
        bookmarks,
        publish,
        connected,
        dialing: JoinMap::new(),
        last_dialed_addrs: HashMap::new(),
        drivers: JoinMap::new(),
        winners: HashSet::new(),
        shutdown,
    };
    spawn(manager.run());
    Ok((
        local_addr,
        subscribe,
        ConnectedBaseboards(subscribe_connected),
    ))
}

/// The buffered read half a session reads from.
type Reader = BufReader<ReadHalf<AttestedPeerConnection>>;

/// The write half a session writes to.
type Writer = WriteHalf<AttestedPeerConnection>;

/// A connection's halves, ready for sessions.
fn halves(conn: AttestedPeerConnection) -> (Reader, Writer) {
    let (read, write) = split(conn);
    (BufReader::new(read), write)
}

/// Why a connection's driver stopped.
enum Stopped {
    /// Its session found a network that dominates ours; we must join it.
    Dominated,
    /// The connection failed, or a failed session left it unusable.
    Failed,
}

struct Manager<T: Send + Sync + 'static> {
    log: Logger,
    config: GossipConfig,
    dialer: Dialer,
    listener: Listener,
    peers: watch::Receiver<BTreeSet<SocketAddrV6>>,
    rumors: Rumors<T, SushBookmark>,
    bookmarks: BookmarkSource,
    publish: watch::Sender<Rumors<T, SushBookmark>>,
    connected: watch::Sender<BTreeSet<BaseboardId>>,
    dialing: JoinMap<SocketAddrV6, io::Result<AttestedPeerConnection>>,
    last_dialed_addrs: HashMap<BaseboardId, SocketAddrV6>,
    drivers: JoinMap<BaseboardId, Stopped>,
    winners: HashSet<BaseboardId>,
    shutdown: CancellationToken,
}

impl<T> Manager<T>
where
    T: DeserializeOwned + Serialize + Eq + Send + Sync + 'static,
{
    async fn run(mut self) {
        let mut tick = interval(self.config.reconnect);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            select! {
                _ = self.shutdown.cancelled() => break,
                _ = tick.tick() => self.dial_unconnected_peers(),
                Ok(()) = self.peers.changed() => self.dial_unconnected_peers(),
                Some(conn) = self.listener.accept() => self.on_connection(conn).await,
                Some((addr, dialed)) = self.dialing.join_next() => {
                    match dialed.map_err(io::Error::other).flatten() {
                        Ok(conn) => {
                            self.last_dialed_addrs.insert(conn.peer().clone(), addr);
                            self.on_connection(conn).await;
                        }
                        Err(err) => {
                            debug!(self.log, "dial failed"; "addr" => %addr, "error" => %err);
                        }
                    }
                }
                Some((peer, stopped)) = self.drivers.join_next() => {
                    match stopped {
                        Ok(Stopped::Dominated) => {
                            self.winners.insert(peer);
                        }
                        Ok(Stopped::Failed) => {
                            debug!(self.log, "connection driver stopped"; "peer" => %peer);
                        }
                        Err(err) => {
                            if err.is_panic() {
                                warn!(
                                    self.log, "connection driver panicked";
                                    "peer" => %peer, "error" => %err,
                                );
                            }
                        }
                    }
                    // Redial now instead of waiting for the next tick.
                    self.dial_unconnected_peers();
                }
            }
            self.publish_connected();
        }
    }

    /// Publish the baseboards of the peers with live connections.
    fn publish_connected(&self) {
        let connected: BTreeSet<BaseboardId> = self.drivers.keys().cloned().collect();
        if *self.connected.borrow() != connected {
            debug!(self.log, "connected baseboards changed"; "connected" => ?connected);
            self.connected.send_replace(connected);
        }
    }

    /// Dial every peer with a lower address than ours that we are neither
    /// connected to nor already dialing. Only the peer with the higher
    /// address dials, so each pair ends up with one connection.
    fn dial_unconnected_peers(&mut self) {
        let ours = self.listener.local_addr();
        for &addr in self.peers.borrow().iter().filter(|addr| **addr < ours) {
            let connected = self
                .drivers
                .keys()
                .any(|peer| self.last_dialed_addrs.get(peer) == Some(&addr));
            if connected || self.dialing.contains_key(&addr) {
                continue;
            }
            let dialer = self.dialer.clone();
            self.dialing
                .spawn(addr, async move { dialer.dial(addr).await });
        }
    }

    /// Gossip on a fresh connection, or use it to join a network that
    /// beat ours.
    async fn on_connection(&mut self, conn: AttestedPeerConnection) {
        let peer = conn.peer().clone();
        let (read, write) = halves(conn);
        if self.winners.contains(&peer) {
            self.migrate(peer, read, write).await;
        } else {
            self.drive(peer, read, write);
        }
    }

    /// Spawn a driver owning a connection.
    fn drive(&mut self, peer: BaseboardId, read: Reader, write: Writer) {
        debug!(self.log, "driving gossip connection"; "peer" => %peer);
        let log = self.log.clone();
        let rumors = self.rumors.clone();
        self.drivers
            .spawn(peer, async move { drive(&log, &rumors, read, write).await });
    }

    /// Abandon our network and join the one `peer` belongs to.
    /// Our new local rumors peer gets a fresh identity and bookmark
    /// handle; all other peers are dropped.
    async fn migrate(&mut self, peer: BaseboardId, read: Reader, write: Writer) {
        self.drivers.shutdown().await;
        debug!(
            self.log, "joining dominating network";
            "peer" => %peer,
            "ours" => %self.rumors.network(),
        );
        let heartbeat = self.config.heartbeat;
        let deadline = self.config.session_deadline;
        let bootstrap = Peer::bootstrap()
            .gossip_when(move |changes| policy(changes, heartbeat))
            .session_deadline(move || sleep(deadline))
            .bookmark(self.bookmarks.handle());
        let connection = match bootstrap.join(read, write).await {
            Joined::Joined { peer, connection } => {
                self.joined(peer);
                Some(connection)
            }
            Joined::Unbookmarked {
                unbookmarked,
                connection,
            } => {
                warn!(self.log, "gossiping without a bookmark"; "error" => %unbookmarked.error);
                let peer = shed(&self.bookmarks, unbookmarked.peer).await;
                self.joined(peer);
                Some(connection)
            }
            Joined::Bailed { .. } => {
                warn!(self.log, "mutual bootstrap, retrying");
                None
            }
            Joined::Failed { error, .. } => {
                warn!(self.log, "unable to join gossip network"; "error" => %error);
                None
            }
        };
        match connection {
            Some(Connection::Reusable { read, write }) => self.drive(peer, read, write),
            Some(Connection::Lost { error }) => {
                debug!(self.log, "joined, but lost the connection"; "error" => %error);
            }
            None => {}
        }
        self.dial_unconnected_peers();
    }

    fn joined(&mut self, peer: Peer<T, SushBookmark>) {
        self.rumors = peer.into_rumors();
        let _ = self.publish.send(self.rumors.clone());
        self.winners.clear();
        info!(self.log, "migrated to new gossip network"; "network" => %self.rumors.network());
    }
}

/// Drive gossip sessions until one fails, reporting why.
async fn drive<T>(
    log: &Logger,
    rumors: &Rumors<T, SushBookmark>,
    read: Reader,
    write: Writer,
) -> Stopped
where
    T: DeserializeOwned + Serialize + Eq + Send + Sync + 'static,
{
    let ours = rumors.network();
    let mut driver = rumors.gossip(read, write);
    while let Some(session) = driver.next().await {
        match session {
            Ok(_) => {}
            Err(Error::Mismatch(Mismatch::Network {
                remote_network,
                remote_min_events,
                local_min_events,
                ..
            })) => {
                let dominated =
                    remote_dominates(&local_min_events, &remote_min_events, ours, remote_network);
                debug!(
                    log, "network mismatch";
                    "ours" => %ours, "theirs" => %remote_network,
                    "our_events" => %local_min_events,
                    "their_events" => %remote_min_events,
                    "we_lose" => dominated,
                );
                return if dominated {
                    Stopped::Dominated
                } else {
                    Stopped::Failed
                };
            }
            Err(Error::Bookmark(error)) => {
                warn!(log, "bookmark failed, unable to gossip"; "error" => %error);
                return Stopped::Failed;
            }
            Err(err) => {
                debug!(log, "gossip session failed"; "error" => %err);
                return Stopped::Failed;
            }
        }
    }
    Stopped::Failed
}
