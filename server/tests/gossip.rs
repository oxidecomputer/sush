// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The gossip manager converging localhost meshes, with real attested
//! handshakes throughout.

mod common;

use std::collections::BTreeSet;
use std::net::SocketAddrV6;

use camino::Utf8PathBuf;
use rumors::{Network, Peer, Rumors};
use slog::Logger;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use sush_server::gossip::{Universe, spawn_gossip};

use common::{corpus, eventually, gossip_config, localhost, pki, sprockets_config, test_logger};

struct Node {
    addr: SocketAddrV6,
    initial: Network,
    peers: watch::Sender<BTreeSet<SocketAddrV6>>,
    universe: watch::Receiver<Universe<String>>,
    shutdown: CancellationToken,
}

impl Node {
    async fn start(log: &Logger, dir: &Utf8PathBuf, identity: usize) -> Node {
        let shutdown = CancellationToken::new();
        let seed: Rumors<String> = Peer::seed().into_rumors();
        let initial = seed.network();
        let (peers, peers_rx) = watch::channel(BTreeSet::new());
        let (addr, universe) = spawn_gossip(
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
            shutdown,
        }
    }

    fn network(&self) -> Network {
        self.universe.borrow().rumors.network()
    }

    fn rumors(&self) -> Rumors<String> {
        self.universe.borrow().rumors.clone()
    }

    fn contains(&self, message: &str) -> bool {
        self.rumors()
            .snapshot()
            .iter()
            .any(|(_, m)| m.as_str() == message)
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

#[tokio::test]
async fn cold_start_converges() {
    let (_tmp, dir) = pki("sush-gossip-", 3);
    let log = test_logger("cold_start_converges");
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

    a.rumors().send("hello".to_string());
    eventually("message everywhere", 60, async || {
        nodes.iter().all(|n| n.contains("hello"))
    })
    .await;
}

#[tokio::test]
async fn staggered_start_converges() {
    let (_tmp, dir) = pki("sush-gossip-", 3);
    let log = test_logger("staggered_start_converges");
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

    c.rumors().send("late but heard".to_string());
    eventually("message everywhere", 60, async || {
        nodes.iter().all(|n| n.contains("late but heard"))
    })
    .await;
}

#[tokio::test]
async fn node_replacement_reconverges() {
    let (_tmp, dir) = pki("sush-gossip-", 4);
    let log = test_logger("node_replacement_reconverges");
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

    a.rumors().send("after the funeral".to_string());
    eventually("message everywhere", 60, async || {
        nodes.iter().all(|n| n.contains("after the funeral"))
    })
    .await;
}
