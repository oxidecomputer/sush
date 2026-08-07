// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The sprockets transport against the rumors link contract, and a
//! two-peer gossip smoke test over it.

mod common;

use std::time::Duration;

use camino::Utf8PathBuf;
use futures::StreamExt as _;
use futures::stream;
use slog::Logger;
use tempfile::TempDir;
use tokio::time::timeout;
use tokio::{join, spawn};
use tokio_util::sync::CancellationToken;

use rumors::conformance::link::check;
use rumors::{Peer, Rumors};
use sush_server::link::{SprocketsLink, Transport};

use common::{corpus, dial_timeout, localhost, pki, sprockets_config, test_logger};

struct TestNet {
    a: Transport,
    b: Transport,
    shutdown: CancellationToken,
    _dir: TempDir,
}

async fn transport(
    log: &Logger,
    dir: &Utf8PathBuf,
    identity: usize,
    shutdown: &CancellationToken,
) -> Transport {
    Transport::new(
        log,
        sprockets_config(dir, identity),
        corpus(dir),
        localhost(),
        dial_timeout(),
        shutdown.clone(),
    )
    .await
    .unwrap()
}

impl TestNet {
    async fn new(test_name: &'static str) -> TestNet {
        let (tmp, dir) = pki("sush-link-", 2);
        let log = test_logger(test_name);
        let shutdown = CancellationToken::new();
        let a = transport(&log, &dir, 1, &shutdown).await;
        let b = transport(&log, &dir, 2, &shutdown).await;
        TestNet {
            a,
            b,
            shutdown,
            _dir: tmp,
        }
    }

    /// One fresh connected link pair: node 1 establishes, node 2 accepts.
    async fn link_pair(&mut self) -> (SprocketsLink, SprocketsLink) {
        let linker = self.a.linker();
        let peer = self.b.linker().advertised();
        let (linked, accepted) = join!(linker.link(peer), self.b.accept());
        let link_a = linked.expect("peer router accepts the link");
        let (from, link_b) = accepted.expect("router is live");
        assert_eq!(from, linker.advertised());
        (link_a, link_b)
    }
}

impl Drop for TestNet {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

#[tokio::test]
async fn conformance() {
    let mut net = TestNet::new("conformance").await;
    timeout(
        Duration::from_secs(600),
        check(async || net.link_pair().await),
    )
    .await
    .expect("conformance suite timed out");
}

#[tokio::test]
async fn gossip_convergence() {
    let mut net = TestNet::new("gossip_convergence").await;
    let (link_a, mut link_b) = net.link_pair().await;

    // Alice seeds a universe with one message and serves sessions on her
    // end of the link.
    let alice: Rumors<String> = Peer::seed().into_rumors();
    alice.send("from alice".to_string());
    let server = spawn({
        let alice = alice.clone();
        async move {
            let mut link_a = link_a;
            let mut driver = alice.gossip_when(stream::pending::<()>(), &mut link_a);
            while let Some(session) = driver.next().await {
                session.expect("serving gossip session");
            }
        }
    });

    // Bob joins Alice's universe through the link and hears her message.
    let bob = timeout(
        Duration::from_secs(60),
        Peer::<String>::bootstrap().join(&mut link_b),
    )
    .await
    .expect("bootstrap timed out")
    .expect("bootstrap failed")
    .expect("mutual bootstrap bail")
    .into_rumors();
    assert_eq!(bob.network(), alice.network());
    assert_eq!(bob.snapshot().len(), 1);

    // Bob's own message reaches Alice within one gossip session.
    bob.send("from bob".to_string());
    timeout(Duration::from_secs(60), bob.gossip(&mut link_b))
        .await
        .expect("gossip timed out")
        .expect("gossip failed");
    assert_eq!(bob.snapshot().len(), 2);
    assert_eq!(alice.snapshot().len(), 2);

    server.abort();
}
