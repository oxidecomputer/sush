// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Converge a peer address set into one gossip universe.
//!
//! Every peer seeds its own universe at startup, so peers meet across
//! unrelated universes and their sessions fail with
//! [`Error::NetworkMismatch`]. That error carries everything both sides need
//! to agree on which universe survives, without coordination: the greater
//! minimum event count wins, and the lesser network id breaks ties. rumors
//! documents the rule under `Peer`, "Bootstrapping without consensus". The
//! losing side abandons its universe by bootstrap-joining the winner's
//! through a fresh link to the peer that beat it, and the process repeats
//! until one universe remains.
//!
//! The manager publishes its current [`Rumors`] handle on a watch channel.
//! A migration replaces the handle entirely; consumers must re-subscribe,
//! and everything the old universe carried is gone.
//!
//! TODO: re-inject local state into the new universe after a migration
//! (policy pending with the sush team).

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::time::Duration;

use borsh::{BorshDeserialize, BorshSerialize};
use futures::StreamExt as _;
use rumors::{Error, Network, Peer, Rumors, Ticks};
use slog::{Logger, debug, info, o, warn};
use sprockets_tls::keys::SprocketsConfig;
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

use rumors::link::routed::Endpoint;

use crate::link::{CorpusSource, SprocketsDial, SprocketsLink, Transport};

/// Manager timing. The defaults suit a rack; tests shrink them.
#[derive(Clone, Debug)]
pub struct GossipConfig {
    /// How often absent links are re-established.
    pub reconnect: Duration,
    /// Ceiling on establishing one link, and on each data-stream dial
    /// inside a live one.
    pub connect_timeout: Duration,
    /// Ceiling on one bootstrap join.
    pub join_timeout: Duration,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            reconnect: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(30),
            join_timeout: Duration::from_secs(60),
        }
    }
}

/// A single-peer universe that never changes. The standalone server uses
/// this, as does a sled that cannot gossip. The receiver outlives its
/// sender.
pub fn isolated<T>(seed: Rumors<T>) -> watch::Receiver<Rumors<T>> {
    let (_tx, rx) = watch::channel(seed);
    rx
}

/// Whether the peer's universe dominates ours, by rumors' documented rule.
fn remote_dominates(
    local_events: &Ticks,
    remote_events: &Ticks,
    local_network: Network,
    remote_network: Network,
) -> bool {
    match remote_events.cmp(local_events) {
        Ordering::Greater => true,
        Ordering::Less => false,
        // Any total order serves, as long as both sides use the same one.
        Ordering::Equal => remote_network < local_network,
    }
}

/// Bind a sprockets transport on `listen_addr` and run a gossip manager
/// over it until `shutdown`. Returns the address the listener bound and
/// the channel following the current universe. A caller that cannot bind
/// may fall back to [`isolated`].
#[allow(clippy::too_many_arguments)]
pub async fn spawn_gossip<T>(
    log: &Logger,
    config: GossipConfig,
    sprockets: SprocketsConfig,
    corpus: CorpusSource,
    listen_addr: SocketAddrV6,
    peers: watch::Receiver<BTreeSet<SocketAddrV6>>,
    seed: Rumors<T>,
    shutdown: CancellationToken,
) -> io::Result<(SocketAddrV6, watch::Receiver<Rumors<T>>)>
where
    T: BorshDeserialize + BorshSerialize + Send + Sync + 'static,
{
    let transport = Transport::new(
        log,
        sprockets,
        corpus,
        listen_addr,
        config.connect_timeout,
        shutdown.clone(),
    )
    .await?;
    let bound = transport.bound();
    let universe = spawn_gossip_manager(log, config, transport, peers, seed, shutdown);
    Ok((bound, universe))
}

/// Run a gossip manager until `shutdown`. Establishes and serves links for
/// the addresses on `peers`, drives gossip on every link, and resolves
/// universe collisions. The returned channel follows the current universe,
/// starting at `seed`.
pub fn spawn_gossip_manager<T>(
    log: &Logger,
    config: GossipConfig,
    transport: Transport,
    peers: watch::Receiver<BTreeSet<SocketAddrV6>>,
    seed: Rumors<T>,
    shutdown: CancellationToken,
) -> watch::Receiver<Rumors<T>>
where
    T: BorshDeserialize + BorshSerialize + Send + Sync + 'static,
{
    let (publish, subscribe) = watch::channel(seed.clone());
    let manager = Manager {
        log: log.new(o!("component" => "gossip manager")),
        config,
        endpoint: transport.endpoint(),
        transport,
        peers,
        rumors: seed,
        publish,
        drivers: JoinSet::new(),
        live: HashMap::new(),
        dials: JoinSet::new(),
        dialing: HashMap::new(),
        joins: HashSet::new(),
        shutdown,
    };
    spawn(manager.run());
    subscribe
}

/// A link establishment that finished, and the peer it was aimed at.
type Established = (SocketAddr, Result<SprocketsLink, String>);

/// Why a link's driver stopped.
enum Stopped {
    /// Its session found a universe that dominates ours; we must join it.
    Dominated,
    /// The link failed, or was poisoned by a session.
    Failed,
}

struct Manager<T> {
    log: Logger,
    config: GossipConfig,
    endpoint: Endpoint<SprocketsDial>,
    transport: Transport,
    peers: watch::Receiver<BTreeSet<SocketAddrV6>>,
    rumors: Rumors<T>,
    publish: watch::Sender<Rumors<T>>,
    drivers: JoinSet<(SocketAddr, Stopped)>,
    live: HashMap<SocketAddr, AbortHandle>,
    dials: JoinSet<Established>,
    dialing: HashMap<SocketAddr, AbortHandle>,
    /// Peers whose universes beat ours, to be joined through.
    joins: HashSet<SocketAddr>,
    shutdown: CancellationToken,
}

impl<T> Manager<T>
where
    T: BorshDeserialize + BorshSerialize + Send + Sync + 'static,
{
    async fn run(mut self) {
        let mut tick = interval(self.config.reconnect);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            select! {
                _ = self.shutdown.cancelled() => break,
                _ = tick.tick() => self.link_absent(),
                Ok(()) = self.peers.changed() => {
                    self.prune();
                    self.link_absent();
                }
                Some((peer, link)) = self.transport.accept() => {
                    self.on_link(peer, link).await;
                }
                Some(done) = self.dials.join_next() => {
                    if let Ok((peer, result)) = done {
                        self.dialing.remove(&peer);
                        match result {
                            Ok(link) => self.on_link(peer, link).await,
                            Err(err) => {
                                debug!(self.log, "link failed"; "peer" => %peer, "error" => err);
                            }
                        }
                    }
                }
                Some(done) = self.drivers.join_next() => {
                    if let Ok((peer, stopped)) = done {
                        self.live.remove(&peer);
                        if matches!(stopped, Stopped::Dominated) {
                            self.joins.insert(peer);
                        }
                    }
                }
            }
        }
    }

    /// The addresses the dial tiebreak makes ours to establish, so that a
    /// pair of peers ends up with one link rather than two.
    fn wanted(&self) -> BTreeSet<SocketAddr> {
        let ours = *self.endpoint.local_addr();
        self.peers
            .borrow()
            .iter()
            .map(|addr| SocketAddr::V6(*addr))
            .filter(|addr| *addr < ours)
            .collect()
    }

    /// Establish a link to every wanted peer without one already.
    fn link_absent(&mut self) {
        for peer in self.wanted() {
            if self.live.contains_key(&peer) || self.dialing.contains_key(&peer) {
                continue;
            }
            let deadline = self.config.connect_timeout;
            let endpoint = self.endpoint.clone();
            let handle = self.dials.spawn(async move {
                let result = match timeout(deadline, endpoint.link(peer)).await {
                    Ok(Ok(link)) => Ok(link),
                    Ok(Err(err)) => Err(err.to_string()),
                    Err(_) => Err("link establishment timed out".to_string()),
                };
                (peer, result)
            });
            self.dialing.insert(peer, handle);
        }
    }

    /// Tear down links and dials to peers no longer in the peer set, and
    /// forgive any debt owed to them.
    fn prune(&mut self) {
        let want: BTreeSet<_> = self
            .peers
            .borrow()
            .iter()
            .map(|addr| SocketAddr::V6(*addr))
            .collect();
        let cull = |peer: &SocketAddr, handle: &mut AbortHandle| {
            if want.contains(peer) {
                return true;
            }
            handle.abort();
            false
        };
        self.live.retain(cull);
        self.dialing.retain(cull);
        self.joins.retain(|peer| want.contains(peer));
    }

    /// Gossip on a fresh link, or use it to join a universe that beat ours.
    async fn on_link(&mut self, peer: SocketAddr, link: SprocketsLink) {
        if self.joins.contains(&peer) {
            self.migrate(peer, link).await;
        } else {
            self.drive(peer, link);
        }
    }

    /// Spawn a session driver owning `link`: push our changes, and serve
    /// whatever the peer initiates, until the link fails.
    fn drive(&mut self, peer: SocketAddr, link: SprocketsLink) {
        let rumors = self.rumors.clone();
        let log = self.log.clone();
        let handle = self
            .drivers
            .spawn(async move { (peer, sessions(&rumors, link, &log).await) });
        if let Some(stale) = self.live.insert(peer, handle) {
            stale.abort();
        }
    }

    /// Abandon our universe for the one `peer` belongs to, joining over the
    /// fresh link to it. Every driver stops first: none may gossip across
    /// the swap. On failure our universe is intact and the debt stands, so
    /// the next link retries; either way all links are rebuilt, since the
    /// old ones belong to the universe we are leaving.
    async fn migrate(&mut self, peer: SocketAddr, mut link: SprocketsLink) {
        self.drivers.abort_all();
        self.live.clear();
        info!(
            self.log, "joining the universe that beat ours";
            "peer" => %peer, "ours" => %self.rumors.network(),
        );
        match timeout(self.config.join_timeout, Peer::bootstrap().join(&mut link)).await {
            Ok(Ok(Some(joined))) => {
                self.rumors = joined.into_rumors();
                let _ = self.publish.send(self.rumors.clone());
                self.joins.clear();
                info!(self.log, "migrated"; "network" => %self.rumors.network());
            }
            Ok(Ok(None)) => warn!(self.log, "mutual bootstrap, retrying"),
            Ok(Err(err)) => warn!(self.log, "join failed"; "error" => %err),
            Err(_) => warn!(self.log, "join timed out"),
        }
        drop(link);
        self.link_absent();
    }
}

/// Drive sessions on one link until it fails, reporting why.
async fn sessions<T>(rumors: &Rumors<T>, mut link: SprocketsLink, log: &Logger) -> Stopped
where
    T: BorshDeserialize + BorshSerialize + Send + Sync + 'static,
{
    let ours = rumors.network();
    let mut driver = rumors.gossip_when(rumors.changes(), &mut link);
    while let Some(session) = driver.next().await {
        match session {
            Ok(_) => {}
            Err(Error::NetworkMismatch {
                remote_network,
                remote_min_events,
                local_min_events,
            }) => {
                let dominated =
                    remote_dominates(&local_min_events, &remote_min_events, ours, remote_network);
                debug!(
                    log, "universe mismatch";
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
            Err(err) => {
                debug!(log, "session failed"; "error" => %err);
                return Stopped::Failed;
            }
        }
    }
    Stopped::Failed
}
