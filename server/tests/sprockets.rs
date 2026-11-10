// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Attested sprockets connections, and a two-peer gossip smoke test over
//! one.

mod common;

use std::time::Duration;

use futures::StreamExt as _;
use futures::stream;
use tokio::io::{BufReader, split};
use tokio::time::timeout;
use tokio::{join, spawn};
use tokio_util::sync::CancellationToken;

use rumors::{Connection, Gossip, Joined, Peer, Rumors};
use sush_server::sprockets::{AttestedPeerConnection, Dialer, Listener};

use common::{baseboard, corpus, dial_timeout, localhost, pki, sprockets_config, test_logger};

/// One connection between nodes 1 and 2: node 1 dials, node 2 accepts.
async fn connect(
    test_name: &'static str,
    shutdown: &CancellationToken,
) -> (AttestedPeerConnection, AttestedPeerConnection) {
    let (_tmp, dir) = pki("sush-sprockets-", 2);
    let log = test_logger(test_name);
    let mut listener = Listener::bind(
        &log,
        sprockets_config(&dir, 2),
        corpus(&dir),
        localhost(),
        dial_timeout(),
        shutdown.clone(),
    )
    .await
    .unwrap();
    let dialer = Dialer::new(
        &log,
        sprockets_config(&dir, 1),
        corpus(&dir),
        dial_timeout(),
    );
    let (dialed, accepted) = join!(dialer.dial(listener.local_addr()), listener.accept());
    (
        dialed.expect("dial succeeds"),
        accepted.expect("listener is live"),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn attested_baseboards() {
    let shutdown = CancellationToken::new();
    let (dialed, accepted) = connect("attested_baseboards", &shutdown).await;
    assert_eq!(*dialed.peer(), baseboard(2));
    assert_eq!(*accepted.peer(), baseboard(1));
    shutdown.cancel();
}

#[tokio::test(flavor = "multi_thread")]
async fn gossip_convergence() {
    let shutdown = CancellationToken::new();
    let (dialed, accepted) = connect("gossip_convergence", &shutdown).await;

    // Alice seeds a network with one message and serves sessions on her
    // end of the connection, never initiating one herself.
    let alice: Rumors<String> = Peer::seed()
        .gossip_when(|_| stream::pending::<Gossip>())
        .into_rumors();
    alice.send("from alice".to_string()).unwrap();
    let server = spawn({
        let alice = alice.clone();
        async move {
            let (read, write) = split(accepted);
            let mut driver = alice.gossip(BufReader::new(read), write);
            while let Some(session) = driver.next().await {
                session.expect("serving gossip session");
            }
        }
    });

    // Bob joins Alice's network over the connection and hears her message.
    let (read, write) = split(dialed);
    let joined = timeout(
        Duration::from_secs(60),
        Peer::<String>::bootstrap().join(BufReader::new(read), write),
    )
    .await
    .expect("bootstrap timed out");
    let Joined::Joined {
        peer,
        connection: Connection::Reusable { read, write },
    } = joined
    else {
        panic!("bootstrap failed: {joined:?}");
    };
    let bob = peer.into_rumors();
    assert_eq!(bob.network(), alice.network());
    assert_eq!(bob.snapshot().len(), 1);

    // Bob's own message reaches Alice within one gossip session on the
    // same connection.
    bob.send("from bob".to_string()).unwrap();
    timeout(Duration::from_secs(60), bob.gossip_once(read, write))
        .await
        .expect("gossip timed out")
        .expect("gossip failed");
    assert_eq!(bob.snapshot().len(), 2);
    assert_eq!(alice.snapshot().len(), 2);

    server.abort();
    shutdown.cancel();
}
