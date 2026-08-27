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
use sush_common::version::VersionInfo;
use sush_server::executor::PathIsolation;
use sush_server::gossip::spawn_gossip;
use sush_server::output::JobOutputDir;
use sush_server::state::GossipUniverse;
use sush_server::{JobManager, seed_gossip};

use common::{
    corpus, eventually, fake_identity, gossip_config, localhost, pki, sign_job, sprockets_config,
    test_logger,
};

struct Sled {
    mgr: JobManager,
    universe: watch::Receiver<GossipUniverse>,
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
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;

    // Each sled learns the other's build.
    eventually("versions gossip", 60, async || {
        [&a, &b].iter().all(|sled| {
            let versions = sled.mgr.versions();
            [&a.baseboard, &b.baseboard].iter().all(|baseboard| {
                versions.iter().any(|row| {
                    row.baseboard == **baseboard
                        && row.version.as_ref() == Some(&VersionInfo::current())
                })
            })
        })
    })
    .await;

    // A session started on sled A becomes B's active session too.
    let authn_a = fake_identity(&mut root).await;
    let authn_b = fake_identity(&mut root).await;
    let signer_nonce = SessionSignerNonce::random();
    let session_id = SessionId::compute(
        a.mgr.own_baseboard(),
        a.mgr.session_sush_nonce(),
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
        b.mgr.session_sush_nonce(),
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

#[tokio::test]
async fn rejoining_replays_without_reexecuting() {
    let (_tmp, dir) = pki("sush-replay-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    std::fs::write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger("rejoining_replays_without_reexecuting");
    let shutdown = CancellationToken::new();

    // Sled A runs a whole job before B exists.
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;
    let signer_nonce = SessionSignerNonce::random();
    let session_id = SessionId::compute(
        a.mgr.own_baseboard(),
        a.mgr.session_sush_nonce(),
        signer_nonce,
    );
    let session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, signer_nonce, true)
        .await
        .unwrap();
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

    // B joins later and receives the whole history as replay: it learns
    // what happened, but the executed job must not run again here.
    let b = Sled::start(&log, &dir, 2, &root_pem, &shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    let authn_b = fake_identity(&mut root).await;
    eventually("A's history replays on B", 120, async || {
        b.mgr.job_status(&authn_b, &job_id).await.is_ok_and(|map| {
            map.get(&a.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { .. }))
        })
    })
    .await;
    assert!(
        !b.mgr
            .job_status(&authn_b, &job_id)
            .await
            .unwrap()
            .contains_key(&b.baseboard),
        "replayed job executed on the joining sled"
    );

    // Live traffic still executes everywhere: a fresh session's job runs
    // on both sleds.
    let successor_nonce = SessionSignerNonce::random();
    let successor = SessionId::compute(
        a.mgr.own_baseboard(),
        a.mgr.session_sush_nonce(),
        successor_nonce,
    );
    let fresh = Session::new(successor);
    a.mgr
        .session_start(&authn_a, successor, successor_nonce, true)
        .await
        .unwrap();
    let live_job = fresh.next_job_id();
    let job = sign_job(&mut root, live_job, successor, "true").await;
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
    eventually("the live job runs on B too", 120, async || {
        a.mgr
            .job_status(&authn_a, &live_job)
            .await
            .is_ok_and(|map| {
                map.get(&b.baseboard)
                    .is_some_and(|s| matches!(s, JobStatus::Stopped { .. }))
            })
    })
    .await;

    // With B provably executing live jobs, the replayed one still never
    // ran there.
    assert!(
        !b.mgr
            .job_status(&authn_b, &job_id)
            .await
            .unwrap()
            .contains_key(&b.baseboard),
        "replayed job executed late on the joining sled"
    );

    shutdown.cancel();
}
