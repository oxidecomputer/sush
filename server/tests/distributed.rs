// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Two job managers on two gossiping sleds. What one accepts, both know.

mod common;

use std::collections::BTreeSet;
use std::net::SocketAddrV6;

use camino::Utf8PathBuf;
use sled_hardware_types::BaseboardId;
use slog::Logger;
use tempfile::TempDir;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use sush_api::{JobStartParams, JobWait};
use sush_common::jobs::{JobStatus, Session, SessionId, SessionSignerNonce};
use sush_common::keys::pem_cert_chain;
use sush_common::targets::Cubbies;
use sush_server::executor::PathIsolation;
use sush_server::gossip::spawn_gossip;
use sush_server::output::JobOutputDir;
use sush_server::state::GossipNetwork;
use sush_server::{JobManager, seed_gossip};

use common::{
    corpus, eventually, fake_identity, gossip_config, localhost, pki, sign_job, sprockets_config,
    test_logger,
};

struct Sled {
    mgr: JobManager,
    universe: watch::Receiver<GossipNetwork>,
    peers: watch::Sender<BTreeSet<SocketAddrV6>>,
    addr: SocketAddrV6,
    baseboard: BaseboardId,
    _output: TempDir,
}

impl Sled {
    async fn start(
        log: &Logger,
        dir: &Utf8PathBuf,
        identity: usize,
        root_pem: &Utf8PathBuf,
        shutdown: &CancellationToken,
    ) -> Sled {
        let (peers, peers_rx) = watch::channel(BTreeSet::new());
        let (addr, universe) = spawn_gossip(
            log,
            gossip_config(),
            sprockets_config(dir, identity),
            corpus(dir),
            localhost(),
            peers_rx,
            seed_gossip(),
            shutdown.clone(),
        )
        .await
        .unwrap();
        let output = TempDir::with_prefix("sush-out-").unwrap();
        let baseboard = BaseboardId {
            part_number: "sled".to_string(),
            serial_number: identity.to_string(),
        };
        let (_cubbies, cubbies) = watch::channel(Cubbies::new());
        let mgr = JobManager::new(
            log.clone(),
            PathIsolation::InsecureDisable,
            JobOutputDir::fixed(output.path()),
            baseboard.clone(),
            cubbies,
            universe.clone(),
            std::slice::from_ref(root_pem),
            shutdown.clone(),
        )
        .await
        .unwrap();
        Sled {
            mgr,
            universe,
            peers,
            addr,
            baseboard,
            _output: output,
        }
    }
}

#[tokio::test]
async fn jobs_gossip_between_sleds() {
    let (_tmp, dir) = pki("sush-distributed-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    std::fs::write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger("jobs_gossip_between_sleds");
    let shutdown = CancellationToken::new();
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let b = Sled::start(&log, &dir, 2, &root_pem, &shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();

    // The sleds converge on one universe, resetting the losing job manager.
    eventually("universe convergence", 120, async || {
        a.universe.borrow().network() == b.universe.borrow().network()
    })
    .await;

    // A session started on sled A becomes B's active session too.
    let authn_a = fake_identity(&mut root).await;
    let authn_b = fake_identity(&mut root).await;
    let signer_nonce = SessionSignerNonce::random();
    let session_id = SessionId::compute(
        a.mgr.own_baseboard(),
        a.mgr.regenerate_session_sush_nonce(),
        signer_nonce,
    );
    let session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, signer_nonce, true)
        .await
        .unwrap();
    eventually("session gossips to B", 60, async || {
        b.mgr
            .session(&authn_b)
            .is_some_and(|s| s.session_id() == session_id)
    })
    .await;

    // A job submitted to A runs on both sleds, and each sled learns the
    // other's result.
    let job_id = session.next_job_id();
    let job = sign_job(&mut root, job_id, session_id, "true").await;
    a.mgr
        .job_start(
            &authn_a,
            job,
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let stopped = async |mgr: &JobManager, authn, baseboard: &BaseboardId| {
        mgr.job_status(authn, &job_id).await.is_ok_and(|map| {
            map.get(baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { .. }))
        })
    };
    eventually("A's run visible on B", 60, async || {
        stopped(&b.mgr, &authn_b, &a.baseboard).await
    })
    .await;
    eventually("B's run visible on A", 60, async || {
        stopped(&a.mgr, &authn_a, &b.baseboard).await
    })
    .await;

    // A session started on B supersedes A's everywhere.
    let successor_nonce = SessionSignerNonce::random();
    let successor = SessionId::compute(
        b.mgr.own_baseboard(),
        b.mgr.regenerate_session_sush_nonce(),
        successor_nonce,
    );
    b.mgr
        .session_start(&authn_b, successor, successor_nonce, true)
        .await
        .unwrap();
    eventually("supersession gossips to A", 60, async || {
        a.mgr
            .session(&authn_a)
            .is_some_and(|s| s.session_id() == successor)
    })
    .await;

    shutdown.cancel();
}
