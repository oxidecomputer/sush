// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The gossip manager converging localhost meshes, with real attested
//! handshakes throughout.

mod common;

use std::collections::BTreeSet;
use std::net::SocketAddrV6;

use camino::Utf8PathBuf;
use function_name::named;
use rumors::{Network, Rumors};
use slog::Logger;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use sush_common::jobs::BaseboardId;
use sush_server::bookmark::SushBookmark;
use sush_server::gossip::{LinkedBaseboards, Seed, Universe, spawn_gossip};
use sush_server::locker::Locker;

use common::{
    baseboard, corpus, eventually, gossip_config, localhost, pki, sprockets_config, test_logger,
};

struct Node {
    addr: SocketAddrV6,
    initial: Network,
    peers: watch::Sender<BTreeSet<SocketAddrV6>>,
    universe: watch::Receiver<Universe<String>>,
    linked: LinkedBaseboards,
    shutdown: CancellationToken,
}

impl Node {
    async fn start(log: &Logger, dir: &Utf8PathBuf, identity: usize) -> Node {
        let shutdown = CancellationToken::new();
        let seed: Seed<String> = Seed::grow(log, &Locker::null()).await;
        let initial = seed.rumors().network();
        let (peers, peers_rx) = watch::channel(BTreeSet::new());
        let (addr, universe, linked) = spawn_gossip(
            log,
            gossip_config(),
            sprockets_config(dir, identity),
            corpus(dir),
            localhost(),
            peers_rx,
            seed,
            shutdown.clone(),
        )
        .await
        .unwrap();
        Node {
            addr,
            initial,
            peers,
            universe,
            linked,
            shutdown,
        }
    }

    fn network(&self) -> Network {
        self.universe.borrow().rumors.network()
    }

    fn rumors(&self) -> Rumors<String, SushBookmark> {
        self.universe.borrow().rumors.clone()
    }

    fn contains(&self, message: &str) -> bool {
        self.rumors()
            .snapshot()
            .iter()
            .any(|(_, m)| m.as_str() == message)
    }

    fn linked(&self) -> BTreeSet<BaseboardId> {
        self.linked.borrow().clone()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Point every node at every other.
fn mesh(nodes: &[&Node]) {
    let all: BTreeSet<_> = nodes.iter().map(|n| n.addr).collect();
    for node in nodes {
        let mut peers = all.clone();
        peers.remove(&node.addr);
        node.peers.send(peers).unwrap();
    }
}

/// The single network every node agrees on, if they agree.
fn converged(nodes: &[&Node]) -> Option<Network> {
    let first = nodes.first()?.network();
    nodes.iter().all(|n| n.network() == first).then_some(first)
}

#[named]
#[tokio::test]
async fn cold_start_converges() {
    let (_tmp, dir) = pki("sush-gossip-", 3);
    let log = test_logger(function_name!());
    let a = Node::start(&log, &dir, 1).await;
    let b = Node::start(&log, &dir, 2).await;
    let c = Node::start(&log, &dir, 3).await;
    let nodes = [&a, &b, &c];
    let min = nodes.iter().map(|n| n.initial).min().unwrap();
    mesh(&nodes);

    eventually("universe convergence", 120, async || {
        converged(&nodes) == Some(min)
    })
    .await;

    a.rumors().send("hello".to_string()).unwrap();
    eventually("message everywhere", 60, async || {
        nodes.iter().all(|n| n.contains("hello"))
    })
    .await;
}

#[named]
#[tokio::test]
async fn staggered_start_converges() {
    let (_tmp, dir) = pki("sush-gossip-", 3);
    let log = test_logger(function_name!());
    let a = Node::start(&log, &dir, 1).await;
    let b = Node::start(&log, &dir, 2).await;
    mesh(&[&a, &b]);
    eventually("pair convergence", 120, async || {
        converged(&[&a, &b]).is_some()
    })
    .await;

    let c = Node::start(&log, &dir, 3).await;
    let nodes = [&a, &b, &c];
    mesh(&nodes);
    let min = nodes.iter().map(|n| n.initial).min().unwrap();
    eventually("universe convergence", 120, async || {
        converged(&nodes) == Some(min)
    })
    .await;

    c.rumors().send("late but heard".to_string()).unwrap();
    eventually("message everywhere", 60, async || {
        nodes.iter().all(|n| n.contains("late but heard"))
    })
    .await;
}

#[named]
#[tokio::test]
async fn node_replacement_reconverges() {
    let (_tmp, dir) = pki("sush-gossip-", 4);
    let log = test_logger(function_name!());
    let a = Node::start(&log, &dir, 1).await;
    let b = Node::start(&log, &dir, 2).await;
    let c = Node::start(&log, &dir, 3).await;
    mesh(&[&a, &b, &c]);
    eventually("initial convergence", 120, async || {
        converged(&[&a, &b, &c]).is_some()
    })
    .await;

    // Node b dies; a fresh node (new identity, new seed, no persistence)
    // takes its place in the mesh.
    b.shutdown.cancel();
    drop(b);
    let d = Node::start(&log, &dir, 4).await;
    let nodes = [&a, &c, &d];
    mesh(&nodes);
    eventually("re-convergence", 120, async || converged(&nodes).is_some()).await;

    a.rumors().send("after the funeral".to_string()).unwrap();
    eventually("message everywhere", 60, async || {
        nodes.iter().all(|n| n.contains("after the funeral"))
    })
    .await;
}

#[named]
#[tokio::test]
async fn linked_follows_live_links() {
    let (_tmp, dir) = pki("sush-gossip-", 2);
    let log = test_logger(function_name!());
    let a = Node::start(&log, &dir, 1).await;
    let b = Node::start(&log, &dir, 2).await;
    assert!(a.linked().is_empty());
    mesh(&[&a, &b]);

    // Both sides resolving proves the dialed and the accepted paths.
    eventually("mutual attested links", 120, async || {
        a.linked() == BTreeSet::from([baseboard(2)]) && b.linked() == BTreeSet::from([baseboard(1)])
    })
    .await;

    b.shutdown.cancel();
    drop(b);
    eventually("dead peer unlinked", 120, async || a.linked().is_empty()).await;
}

/// Idle links probe every ten seconds without delaying changes or bursting
/// after a pause; a silent peer then trips the one-second session deadline.
#[tokio::test(start_paused = true)]
async fn idle_heartbeats_detect_a_silent_peer() {
    use std::time::Duration;

    use futures::{FutureExt as _, StreamExt as _};
    use rumors::{Error, Joined, Led, Peer};
    use tokio::time::advance;

    let a: Rumors<String, SushBookmark> = Seed::grow(
        &test_logger("idle_heartbeats_detect_a_silent_peer"),
        &Locker::null(),
    )
    .await
    .into_rumors();
    let (mut near, mut far) = rumors::link::memory();
    let (served, joined) = futures::join!(
        a.gossip_once(&mut near),
        Peer::<String>::bootstrap().join(&mut far),
    );
    served.unwrap();
    let Joined::Joined { peer } = joined else {
        panic!("join succeeds")
    };
    let b = peer.into_rumors();
    let mut sessions = a.gossip(&mut near);
    let (sent, received) = futures::join!(sessions.next(), b.gossip_once(&mut far));
    assert_eq!(sent.unwrap().unwrap().led, Led::Local);
    received.unwrap();

    advance(Duration::from_secs(9)).await;
    assert!(sessions.next().now_or_never().is_none());
    a.send("a change before the heartbeat".into()).unwrap();
    let (sent, received) = futures::join!(sessions.next(), b.gossip_once(&mut far));
    sent.unwrap().unwrap();
    received.unwrap();
    assert_eq!(a.snapshot().hash(), b.snapshot().hash());

    // The heartbeat still fires at ten seconds, even though the set is current.
    advance(Duration::from_secs(1)).await;
    assert!(sessions.next().now_or_never().is_none());
    let (sent, received) = futures::join!(sessions.next(), b.gossip_once(&mut far));
    assert_eq!(sent.unwrap().unwrap().led, Led::Local);
    received.unwrap();

    // Several missed intervals produce one probe, followed by a full interval.
    advance(Duration::from_secs(35)).await;
    assert!(sessions.next().now_or_never().is_none());
    let (sent, received) = futures::join!(sessions.next(), b.gossip_once(&mut far));
    assert_eq!(sent.unwrap().unwrap().led, Led::Local);
    received.unwrap();
    assert!(sessions.next().now_or_never().is_none());
    advance(Duration::from_secs(9)).await;
    assert!(sessions.next().now_or_never().is_none());

    // Keep the remote link open but stop serving it: no EOF can expose failure.
    advance(Duration::from_secs(1)).await;
    assert!(sessions.next().now_or_never().is_none());
    advance(Duration::from_secs(1)).await;
    assert!(matches!(
        sessions.next().await,
        Some(Err(Error::DeadlineExceeded))
    ));
    assert!(sessions.next().await.is_none());
}
