// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Two job managers on two gossiping sleds. What one accepts, both know.

mod common;

use std::collections::BTreeSet;
use std::fs::{read, read_to_string, write};
use std::net::SocketAddrV6;
use std::slice::from_ref;
use std::time::Duration;

use camino::Utf8PathBuf;
use function_name::named;
use sled_hardware_types::BaseboardId;
use slog::{Logger, o};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use chrono::Utc;
use sush_api::{JobStartParams, JobWait};
use sush_common::authn::Identity;
use sush_common::jobs::{
    JobId, JobMode, JobOutputState, JobStartRequest, JobStatus, ProcessError, Session,
    SessionClientNonce, SessionId, SessionPreimage, SessionSeq, SessionSignerNonce,
    SessionSushNonce, SignedJob, SkipReason,
};
use sush_common::keys::{EphemeralKey, Signer as _, pem_cert_chain};
use sush_common::targets::{Cubbies, SledHealth, SledId, Target};
use sush_common::version::VersionInfo;
use sush_server::executor::PathIsolation;
use sush_server::gossip::spawn_gossip;
use sush_server::locker::Locker;
use sush_server::locker::bookmark::BOOKMARK;
use sush_server::messages::v0::{Event, JobEvent, Message};
use sush_server::output::JobOutputDir;
use sush_server::state::GossipUniverse;
use sush_server::{JobError, JobManager, seed_gossip};

use common::{
    baseboard, corpus, eventually, fake_identity, gossip_config, localhost, pki, sign_job,
    sprockets_config, test_logger,
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
        Self::start_with_locker(log, dir, identity, root_pem, Locker::null(), shutdown).await
    }

    async fn start_with_locker(
        log: &Logger,
        dir: &Utf8PathBuf,
        identity: usize,
        root_pem: &Utf8PathBuf,
        locker: Locker,
        shutdown: &CancellationToken,
    ) -> Sled {
        let log = log.new(o!("sled" => identity));
        let seed = seed_gossip(&log, &locker).await;
        let (peers, peers_rx) = watch::channel(BTreeSet::new());
        let (addr, universe, linked) = spawn_gossip(
            &log,
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
        let output = TempDir::with_prefix("sush-out-").unwrap();
        // The manager's baseboard must be the one sprockets attests,
        // as it is on a sled, or the health join can never match.
        let baseboard = baseboard(identity);
        let (_cubbies, cubbies) = watch::channel(Cubbies::new());
        let mgr = JobManager::new(
            log.clone(),
            PathIsolation::InsecureDisable,
            JobOutputDir::fixed(output.path()),
            baseboard.clone(),
            cubbies,
            universe.clone(),
            linked,
            &locker,
            from_ref(root_pem),
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

#[named]
#[tokio::test]
async fn jobs_gossip_between_sleds() {
    let (_tmp, dir) = pki("sush-distributed-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
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

    // Each sled learns the other's build, and sees it linked.
    eventually("versions gossip", 120, async || {
        [&a, &b].iter().all(|sled| {
            let versions = sled.mgr.versions();
            [&a.baseboard, &b.baseboard].iter().all(|baseboard| {
                versions.iter().any(|row| {
                    row.baseboard == **baseboard
                        && row.version.as_ref() == Some(&VersionInfo::current())
                        && row.health == Some(SledHealth::Linked)
                })
            })
        })
    })
    .await;

    // A session started on sled A becomes B's active session too,
    // once a signed job confirms it.
    let authn_a = fake_identity(&mut root).await;
    let authn_b = fake_identity(&mut root).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    let session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();

    // That job, submitted to A, runs on both sleds, and each sled
    // learns the other's result.
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
    eventually("session gossips to B", 60, async || {
        b.mgr
            .session(&authn_b)
            .is_some_and(|s| s.session_id() == session_id)
    })
    .await;
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
    let Ceremony {
        session_id: successor,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&b.mgr, 2);
    b.mgr
        .session_start(&authn_b, successor, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    confirm_start(&b, &authn_b, &mut root, &mut Session::new(successor)).await;
    eventually("supersession gossips to A", 60, async || {
        a.mgr
            .session(&authn_a)
            .is_some_and(|s| s.session_id() == successor)
    })
    .await;

    shutdown.cancel();
}

/// A session's first job confirms its start on whichever sled receives
/// the job, not only on the sled that took the start.
#[named]
#[tokio::test]
async fn first_job_confirms_start_on_another_sled() {
    let (_tmp, dir) = pki("sush-distributed-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let b = Sled::start(&log, &dir, 2, &root_pem, &shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe convergence", 120, async || {
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;

    // A takes the start.
    let authn_a = fake_identity(&mut root).await;
    let authn_b = fake_identity(&mut root).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();

    // B accepts the first job once the pending start reaches it, and
    // the job confirms the session on both sleds.
    let job_id = Session::new(session_id).next_job_id();
    let job = sign_job(&mut root, job_id, session_id, "true").await;
    eventually("B accepts the first job", 60, async || {
        b.mgr
            .job_start(&authn_b, job.clone(), JobStartParams::default())
            .await
            .is_ok()
    })
    .await;
    for (name, sled, authn) in [("A", &a, &authn_a), ("B", &b, &authn_b)] {
        eventually(&format!("session active on {name}"), 60, async || {
            sled.mgr
                .session(authn)
                .is_some_and(|s| s.session_id() == session_id)
        })
        .await;
    }

    shutdown.cancel();
}

/// The front door refuses a forged job, and the signed job it mimics
/// still runs.
#[named]
#[tokio::test]
async fn unverified_job_is_refused() {
    let (_tmp, dir) = pki("sush-unverified-", 1);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn = fake_identity(&mut root).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    a.mgr
        .session_start(&authn, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();

    // The sled refuses a job carrying another job's signature, records
    // nothing under its id, and leaves the start pending.
    let job_id = Session::new(session_id).next_job_id();
    let job = sign_job(&mut root, job_id, session_id, "true").await;
    let other = sign_job(&mut root, job_id, session_id, "false").await;
    let forged = SignedJob::new(
        job.payload().clone(),
        job.key_id().clone(),
        other.signature().clone(),
    );
    assert!(matches!(
        a.mgr
            .job_start(&authn, forged, JobStartParams::default())
            .await,
        Err(JobError::UnverifiedJob(_))
    ));
    assert!(a.mgr.job_status(&authn, &job_id).await.is_err());
    assert!(a.mgr.session(&authn).is_none());

    // The signed job then runs in its place.
    a.mgr
        .job_start(
            &authn,
            job,
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(a.mgr.job_status(&authn, &job_id).await.is_ok_and(|map| {
        map.get(&a.baseboard)
            .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
    }));

    shutdown.cancel();
}

/// A forged start neither displaces the active session nor blocks
/// the next genuine one. The sled refuses the jobs of a pending start
/// the active session outranks, and any verified job confirms a
/// pending start.
#[named]
#[tokio::test]
async fn forged_start_never_takes_effect() {
    let (_tmp, dir) = pki("sush-forged-start-", 1);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn = fake_identity(&mut root).await;
    let mut forger = common::ephemeral_root();
    let authn_forger = fake_identity(&mut forger).await;

    // A genuine session's first job confirms it.
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 2);
    let mut session = Session::new(session_id);
    a.mgr
        .session_start(&authn, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    confirm_start(&a, &authn, &mut root, &mut session).await;
    assert!(
        a.mgr
            .session(&authn)
            .is_some_and(|s| s.session_id() == session_id)
    );

    // A forged start changes nothing.
    let forged = ceremony(&a.mgr, SessionSeq::MAX_MILLIS);
    a.mgr
        .session_start(
            &authn_forger,
            forged.session_id,
            forged.client_nonce,
            forged.signer_nonce,
            forged.seq,
        )
        .await
        .unwrap();
    assert!(
        a.mgr
            .session(&authn)
            .is_some_and(|s| s.session_id() == session_id)
    );

    // The next genuine session takes the slot regardless.
    let Ceremony {
        session_id: next_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 3);
    let mut next = Session::new(next_id);
    a.mgr
        .session_start(&authn, next_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    confirm_start(&a, &authn, &mut root, &mut next).await;
    assert!(
        a.mgr
            .session(&authn)
            .is_some_and(|s| s.session_id() == next_id)
    );

    // The sled refuses the first job of a start the active session
    // outranks.
    let Ceremony {
        session_id: stale_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    a.mgr
        .session_start(&authn, stale_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    let stale = Session::new(stale_id);
    let job = sign_job(&mut root, stale.next_job_id(), stale_id, "true").await;
    assert!(matches!(
        a.mgr.job_start(&authn, job, JobStartParams::default()).await,
        Err(JobError::SessionNotCurrent(id)) if id == stale_id
    ));

    // A verified job past the first confirms a pending session just
    // as well, and queues behind the hole until the first job fills it.
    let Ceremony {
        session_id: last_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 4);
    a.mgr
        .session_start(&authn, last_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    let mut last = Session::new(last_id);
    let first = sign_job(&mut root, last.next_job_id(), last_id, "true").await;
    last.job_started(first.clone());
    let second_id = last.next_job_id();
    let second = sign_job(&mut root, second_id, last_id, "true").await;
    a.mgr
        .job_start(&authn, second, JobStartParams::default())
        .await
        .unwrap();
    a.mgr
        .job_start(
            &authn,
            first,
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        a.mgr
            .session(&authn)
            .is_some_and(|s| s.session_id() == last_id)
    );
    eventually("the queued job runs after the hole fills", 60, async || {
        a.mgr.job_status(&authn, &second_id).await.is_ok_and(|map| {
            map.get(&a.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        })
    })
    .await;

    shutdown.cancel();
}

#[named]
#[tokio::test]
async fn partitioned_sessions_converge_on_higher_seq() {
    let (_tmp, dir) = pki("sush-concurrent-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let b = Sled::start(&log, &dir, 2, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;
    let authn_b = fake_identity(&mut root).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe convergence", 120, async || {
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;
    sees(&a, &b).await;
    sees(&b, &a).await;

    // Partitioned, each sled starts its own session. Neither start
    // can hear the other, but the signer-assigned order still ranks
    // them.
    a.peers.send(BTreeSet::new()).unwrap();
    b.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;
    let a_ceremony = ceremony(&a.mgr, 1);
    let session_a = a_ceremony.session_id;
    let mut session = Session::new(session_a);
    a.mgr
        .session_start(
            &authn_a,
            session_a,
            a_ceremony.client_nonce,
            a_ceremony.signer_nonce,
            a_ceremony.seq,
        )
        .await
        .unwrap();
    confirm_start(&a, &authn_a, &mut root, &mut session).await;
    let b_ceremony = ceremony(&b.mgr, 2);
    let session_b = b_ceremony.session_id;
    b.mgr
        .session_start(
            &authn_b,
            session_b,
            b_ceremony.client_nonce,
            b_ceremony.signer_nonce,
            b_ceremony.seq,
        )
        .await
        .unwrap();
    confirm_start(&b, &authn_b, &mut root, &mut Session::new(session_b)).await;

    // A job on A sits queued behind a hole in the chain, so it can
    // never run before B's session supersedes A's.
    let hole_id = session.next_job_id();
    let hole = sign_job_for(&mut root, hole_id, session_a, "true", &a.baseboard).await;
    session.job_started(hole);
    let job_id = session.next_job_id();
    let job = sign_job_for(&mut root, job_id, session_a, "true", &a.baseboard).await;
    a.mgr
        .job_start(&authn_a, job, JobStartParams::default())
        .await
        .unwrap();
    eventually("the job queues on A", 60, async || {
        a.mgr.job_status(&authn_a, &job_id).await.is_ok_and(|map| {
            map.get(&a.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Queued { .. }))
        })
    })
    .await;

    // The partition heals. B's session carries the higher sequence
    // number, so every sled converges on it, and A's queued job is
    // skipped rather than left queued forever.
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually(
        "the higher sequence number wins everywhere",
        120,
        async || {
            a.mgr
                .session(&authn_a)
                .is_some_and(|s| s.session_id() == session_b)
                && b.mgr
                    .session(&authn_b)
                    .is_some_and(|s| s.session_id() == session_b)
        },
    )
    .await;
    eventually("the queued job is skipped", 60, async || {
        a.mgr.job_status(&authn_a, &job_id).await.is_ok_and(|map| {
            map.get(&a.baseboard).is_some_and(|s| {
                matches!(
                    s,
                    JobStatus::Skipped {
                        reason: SkipReason::SessionEnded,
                        ..
                    }
                )
            })
        })
    })
    .await;

    shutdown.cancel();
}

#[named]
#[tokio::test]
async fn rejoining_replays_without_reexecuting() {
    let (_tmp, dir) = pki("sush-replay-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();

    // Sled A runs a whole job before B exists.
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    let session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
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
    sees(&a, &b).await;
    let Ceremony {
        session_id: successor,
        client_nonce,
        signer_nonce: successor_nonce,
        seq,
    } = ceremony(&a.mgr, 2);
    let fresh = Session::new(successor);
    a.mgr
        .session_start(&authn_a, successor, client_nonce, successor_nonce, seq)
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

#[named]
#[tokio::test]
async fn interrupted_jobs_get_stopped() {
    let (_tmp, dir) = pki("sush-interrupted-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;

    // A previous life of sled 2 started a job and died before stopping
    // it: the rack's history shows it running forever.
    let job_id: JobId = "abandon-abandon-abandon-abandon-abandon-abandon-abandon-ability"
        .parse()
        .unwrap();
    let ghost = baseboard(2);
    a.universe
        .borrow()
        .rumors
        .clone()
        .send(
            Message::Event(
                ghost.clone(),
                Event::Job(JobEvent::Start(job_id, Utc::now())),
            )
            .into(),
        )
        .unwrap();
    eventually("A records the orphaned start", 60, async || {
        a.mgr.job_status(&authn_a, &job_id).await.is_ok_and(|map| {
            map.get(&ghost)
                .is_some_and(|s| matches!(s, JobStatus::Started { .. }))
        })
    })
    .await;

    // Sled 2's next incarnation joins, finds its own job running in
    // replayed history with no executor to ever stop it, and declares
    // it interrupted for the whole rack to see.
    let b = Sled::start(&log, &dir, 2, &root_pem, &shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("the orphan is interrupted", 120, async || {
        a.mgr.job_status(&authn_a, &job_id).await.is_ok_and(|map| {
            map.get(&ghost).is_some_and(|s| {
                matches!(
                    s,
                    JobStatus::Error {
                        error: ProcessError::Interrupted,
                        ..
                    }
                )
            })
        })
    })
    .await;

    // The job's genuine stop was in flight all along. When it lands,
    // the real result supersedes the interrupted declaration.
    let output = JobOutputState::default();
    a.universe
        .borrow()
        .rumors
        .clone()
        .send(
            Message::Event(
                ghost.clone(),
                Event::Job(JobEvent::Stop(job_id, Utc::now(), Ok(0), output)),
            )
            .into(),
        )
        .unwrap();
    eventually("the late stop supersedes the interrupt", 120, async || {
        a.mgr.job_status(&authn_a, &job_id).await.is_ok_and(|map| {
            map.get(&ghost)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        })
    })
    .await;

    shutdown.cancel();
}

#[named]
#[tokio::test]
async fn stragglers_do_not_interrupt_live_jobs() {
    let (_tmp, dir) = pki("sush-straggler-", 3);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();

    // A and C converge; C then holds a message A never sees.
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let c = Sled::start(&log, &dir, 3, &root_pem, &shutdown).await;
    a.peers.send(BTreeSet::from([c.addr])).unwrap();
    c.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("A and C converge", 120, async || {
        a.universe.borrow().rumors.network() == c.universe.borrow().rumors.network()
    })
    .await;
    a.peers.send(BTreeSet::new()).unwrap();
    c.peers.send(BTreeSet::new()).unwrap();
    let marooned = BaseboardId {
        part_number: "sled".to_string(),
        serial_number: "marooned".to_string(),
    };
    c.universe
        .borrow()
        .rumors
        .clone()
        .send(Message::Event(marooned.clone(), Event::Version(VersionInfo::current())).into())
        .unwrap();
    // A also advances on its own side of the split, so the marooned
    // message is genuinely concurrent with (not under) B's frontier.
    let split_marker = BaseboardId {
        part_number: "sled".to_string(),
        serial_number: "split-marker".to_string(),
    };
    a.universe
        .borrow()
        .rumors
        .clone()
        .send(Message::Event(split_marker, Event::Version(VersionInfo::current())).into())
        .unwrap();

    // B joins through A alone, so C's message is concurrent with B's
    // join frontier, and starts a live job that keeps running.
    let b = Sled::start(&log, &dir, 2, &root_pem, &shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("B joins A", 120, async || {
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;
    sees(&a, &b).await;
    let authn_a = fake_identity(&mut root).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    let session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    let job_id = session.next_job_id();
    let job = sign_job(&mut root, job_id, session_id, "sleep 30").await;
    a.mgr
        .job_start(
            &authn_a,
            job,
            JobStartParams {
                wait: JobWait::Start,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    eventually("the live job starts on B", 120, async || {
        a.mgr.job_status(&authn_a, &job_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Started { .. }))
        })
    })
    .await;

    // C reconnects. Its marooned message reaches B as replayed
    // traffic and triggers a reap, which the live job must survive.
    a.peers.send(BTreeSet::from([b.addr, c.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr, c.addr])).unwrap();
    c.peers.send(BTreeSet::from([a.addr, b.addr])).unwrap();
    let authn_b = fake_identity(&mut root).await;
    eventually("the marooned message reaches B", 120, async || {
        b.mgr.versions().iter().any(|row| row.baseboard == marooned)
    })
    .await;
    assert!(
        b.mgr.job_status(&authn_b, &job_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Started { .. }))
        }),
        "a straggler-triggered scan interrupted a live job"
    );

    shutdown.cancel();
}

/// Wait until `anchor` has applied `joiner`'s build announcement. A
/// session started on `anchor` afterward causally follows everything
/// `joiner` held at entry, so the joiner serves it.
/// Everything one sled hears at session start: a client nonce, a
/// signer nonce, the signer's clock reading, and the session id over
/// them all.
struct Ceremony {
    session_id: SessionId,
    client_nonce: SessionClientNonce,
    signer_nonce: SessionSignerNonce,
    seq: SessionSeq,
}

/// Build a [`Ceremony`] against one sled. Fetches a fresh server
/// nonce, so earlier ceremonies against that sled go stale.
fn ceremony(mgr: &JobManager, seq: u64) -> Ceremony {
    let client_nonce = SessionClientNonce::random();
    let preimage = SessionPreimage {
        baseboard: mgr.own_baseboard().clone(),
        sush_nonce: SessionSushNonce::compute(client_nonce, mgr.fresh_server_nonce()),
        signer_nonce: SessionSignerNonce::random(),
        seq: SessionSeq::from_unix_millis(seq).unwrap(),
    };
    Ceremony {
        session_id: preimage.session_id(),
        client_nonce,
        signer_nonce: preimage.signer_nonce,
        seq: preimage.seq,
    }
}

async fn sees(anchor: &Sled, joiner: &Sled) {
    eventually("the anchor sees the joiner", 60, async || {
        anchor
            .mgr
            .versions()
            .iter()
            .any(|row| row.baseboard == joiner.baseboard)
    })
    .await;
}

/// Sign a job aimed at one sled, so a retry cannot legitimately run
/// anywhere else.
async fn sign_job_for(
    root: &mut EphemeralKey,
    job_id: JobId,
    session_id: SessionId,
    command: &str,
    sled: &BaseboardId,
) -> SignedJob {
    root.sign(JobStartRequest::new(
        job_id,
        session_id,
        command,
        JobMode::Batch,
        Target::Sleds(vec![SledId::Baseboard(sled.clone())]),
    ))
    .await
    .unwrap()
}

/// Confirm the start pending on `sled` with the session's first job,
/// and advance `session` past it.
async fn confirm_start(
    sled: &Sled,
    authn: &Identity,
    root: &mut EphemeralKey,
    session: &mut Session,
) {
    let job_id = session.next_job_id();
    let job = sign_job_for(root, job_id, session.session_id(), "true", &sled.baseboard).await;
    sled.mgr
        .job_start(
            authn,
            job.clone(),
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    session.job_started(job);
}

#[named]
#[tokio::test]
async fn lost_suffix_never_reruns() {
    let (_tmp, dir) = pki("sush-lost-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();

    // Sled A anchors the session and survives throughout.
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;
    // Sled B keeps its boundary in a locker. It joins before the
    // session starts: a record-less sled serves only sessions
    // that started after it arrived.
    let boundary_dir = TempDir::with_prefix("sush-boundary-").unwrap();
    let slot = Utf8PathBuf::from_path_buf(boundary_dir.path().to_path_buf()).unwrap();
    let b_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let b = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &b_shutdown).await;
    let authn_b = fake_identity(&mut root).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe convergence", 120, async || {
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;
    sees(&a, &b).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    let mut session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    confirm_start(&a, &authn_a, &mut root, &mut session).await;
    eventually("the session gossips to B", 120, async || {
        b.mgr
            .session(&authn_b)
            .is_some_and(|s| s.session_id() == session_id)
    })
    .await;
    a.peers.send(BTreeSet::new()).unwrap();
    b.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;

    // Two jobs run on B through its front door. No one else hears of
    // them. The first leaves a footprint we can count.
    let footprint = boundary_dir.path().join("footprint");
    let j1_id = session.next_job_id();
    let j1 = sign_job_for(
        &mut root,
        j1_id,
        session_id,
        &format!("echo run >> {}", footprint.display()),
        &b.baseboard,
    )
    .await;
    b.mgr
        .job_start(
            &authn_b,
            j1.clone(),
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    session.job_started(j1.clone());
    let j2_id = session.next_job_id();
    let j2 = sign_job_for(&mut root, j2_id, session_id, "true", &b.baseboard).await;
    b.mgr
        .job_start(
            &authn_b,
            j2,
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(read_to_string(&footprint).unwrap(), "run\n");

    // B dies with both jobs unwitnessed and rejoins. Its boundary
    // proves the rack is missing part of the session's history.
    b_shutdown.cancel();
    drop(b);
    sleep(Duration::from_millis(500)).await;
    let locker = Locker::new(&log, baseboard(2), vec![slot]).unwrap();
    let b = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &shutdown).await;
    let authn_b = fake_identity(&mut root).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();

    // The recorded job finished before the crash, so B adjudicates
    // its true ending on its sole authority.
    eventually("the boundary job is adjudicated", 120, async || {
        a.mgr.job_status(&authn_a, &j2_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        })
    })
    .await;

    // A retry of the first job's preserved artifact stays queued
    // instead of running: the stored successor resumes the chain past
    // it, so its position never pops, and the footprint file still
    // shows one run.
    b.mgr
        .job_start(&authn_b, j1, JobStartParams::default())
        .await
        .unwrap();
    eventually("the retry queues", 60, async || {
        b.mgr.job_status(&authn_b, &j1_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Queued { .. }))
        })
    })
    .await;
    sleep(Duration::from_secs(1)).await;
    assert!(
        b.mgr.job_status(&authn_b, &j1_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Queued { .. }))
        }),
        "a job below the stored successor must stay queued"
    );
    assert_eq!(read_to_string(&footprint).unwrap(), "run\n");

    // A new session, confirmed by a job for B, serves immediately.
    let Ceremony {
        session_id: session2_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 2);
    let session2 = Session::new(session2_id);
    a.mgr
        .session_start(&authn_a, session2_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    let j3_id = session2.next_job_id();
    let j3 = sign_job_for(&mut root, j3_id, session2_id, "true", &b.baseboard).await;
    a.mgr
        .job_start(&authn_a, j3, JobStartParams::default())
        .await
        .unwrap();
    eventually("a new session must not be held", 120, async || {
        b.mgr.job_status(&authn_b, &j3_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        })
    })
    .await;

    shutdown.cancel();
}

#[named]
#[tokio::test]
async fn session_resumes_at_stored_successor() {
    let (_tmp, dir) = pki("sush-resume-", 3);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();

    // Three sleds converge, then the session starts, so everyone
    // serves it. B keeps its boundary in a locker.
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;
    let c = Sled::start(&log, &dir, 3, &root_pem, &shutdown).await;
    let authn_c = fake_identity(&mut root).await;
    let boundary_dir = TempDir::with_prefix("sush-boundary-").unwrap();
    let slot = Utf8PathBuf::from_path_buf(boundary_dir.path().to_path_buf()).unwrap();
    let b_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let b = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &b_shutdown).await;
    let authn_b = fake_identity(&mut root).await;
    a.peers.send(BTreeSet::from([b.addr, c.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    c.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe convergence", 120, async || {
        let network = a.universe.borrow().rumors.network();
        b.universe.borrow().rumors.network() == network
            && c.universe.borrow().rumors.network() == network
    })
    .await;
    sees(&a, &b).await;
    sees(&a, &c).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    let mut session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    confirm_start(&a, &authn_a, &mut root, &mut session).await;
    eventually("the session gossips to B and C", 120, async || {
        [(&b.mgr, &authn_b), (&c.mgr, &authn_c)]
            .iter()
            .all(|(mgr, authn)| {
                mgr.session(authn)
                    .is_some_and(|s| s.session_id() == session_id)
            })
    })
    .await;

    // C falls behind: it hears nothing of what follows.
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    c.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;

    // B runs two jobs submitted through its own API; only A
    // witnesses them.
    let j1_id = session.next_job_id();
    let j1 = sign_job_for(&mut root, j1_id, session_id, "true", &b.baseboard).await;
    b.mgr
        .job_start(
            &authn_b,
            j1.clone(),
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    session.job_started(j1);
    let j2_id = session.next_job_id();
    let j2 = sign_job_for(&mut root, j2_id, session_id, "true", &b.baseboard).await;
    b.mgr
        .job_start(
            &authn_b,
            j2.clone(),
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    session.job_started(j2);
    eventually("A witnesses the runs", 60, async || {
        a.mgr.job_status(&authn_a, &j2_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        })
    })
    .await;

    // B dies and rejoins through lagging C alone. C holds none of the
    // jobs, but B's record stores the successor of its last
    // commitment, so the session resumes there with no witness at
    // all: the next job runs immediately.
    b_shutdown.cancel();
    drop(b);
    a.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;
    let locker = Locker::new(&log, baseboard(2), vec![slot]).unwrap();
    let b = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &shutdown).await;
    let authn_b = fake_identity(&mut root).await;
    b.peers.send(BTreeSet::from([c.addr])).unwrap();
    c.peers.send(BTreeSet::from([b.addr])).unwrap();
    eventually("the session replays to B", 120, async || {
        b.mgr
            .session(&authn_b)
            .is_some_and(|s| s.session_id() == session_id)
    })
    .await;
    let j3_id = session.next_job_id();
    let j3 = sign_job_for(&mut root, j3_id, session_id, "true", &b.baseboard).await;
    b.mgr
        .job_start(
            &authn_b,
            j3,
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        b.mgr.job_status(&authn_b, &j3_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        }),
        "the resumed session must serve its next job without a witness"
    );

    // A returns, and the resumed chain reconciles rack-wide.
    a.peers.send(BTreeSet::from([b.addr, c.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr, c.addr])).unwrap();
    c.peers.send(BTreeSet::from([a.addr, b.addr])).unwrap();
    eventually("the resumed run reaches A", 120, async || {
        a.mgr.job_status(&authn_a, &j3_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        })
    })
    .await;

    shutdown.cancel();
}

#[named]
#[tokio::test]
async fn supersession_crosses_universes() {
    let (_tmp, dir) = pki("sush-flipflop-", 3);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();

    // Two universes that never meet: A anchors one session, D another.
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;
    let d = Sled::start(&log, &dir, 3, &root_pem, &shutdown).await;
    let authn_d = fake_identity(&mut root).await;
    let Ceremony {
        session_id: session2_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&d.mgr, 2);
    let mut session2 = Session::new(session2_id);
    d.mgr
        .session_start(&authn_d, session2_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    confirm_start(&d, &authn_d, &mut root, &mut session2).await;

    // X joins A's universe and runs a job there.
    let boundary_dir = TempDir::with_prefix("sush-boundary-").unwrap();
    let slot = Utf8PathBuf::from_path_buf(boundary_dir.path().to_path_buf()).unwrap();
    let x_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let x = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &x_shutdown).await;
    let authn_x = fake_identity(&mut root).await;
    a.peers.send(BTreeSet::from([x.addr])).unwrap();
    x.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe convergence", 120, async || {
        a.universe.borrow().rumors.network() == x.universe.borrow().rumors.network()
    })
    .await;
    sees(&a, &x).await;
    let Ceremony {
        session_id: session1_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    let mut session1 = Session::new(session1_id);
    a.mgr
        .session_start(&authn_a, session1_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    confirm_start(&a, &authn_a, &mut root, &mut session1).await;
    eventually("session one gossips to X", 120, async || {
        x.mgr
            .session(&authn_x)
            .is_some_and(|s| s.session_id() == session1_id)
    })
    .await;
    let j1_id = session1.next_job_id();
    let j1 = sign_job_for(&mut root, j1_id, session1_id, "true", &x.baseboard).await;
    x.mgr
        .job_start(
            &authn_x,
            j1.clone(),
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    session1.job_started(j1);
    // A must witness the job: X's replayed chain in its third life
    // can only be rebuilt from what A holds.
    eventually("A witnesses the first job", 60, async || {
        a.mgr.job_status(&authn_a, &j1_id).await.is_ok_and(|map| {
            map.get(&x.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        })
    })
    .await;

    // X dies and rejoins D's universe instead, running a job there.
    // That commit burns A's universe out of X's record.
    x_shutdown.cancel();
    drop(x);
    a.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;
    let x_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let x = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &x_shutdown).await;
    let authn_x = fake_identity(&mut root).await;
    d.peers.send(BTreeSet::from([x.addr])).unwrap();
    x.peers.send(BTreeSet::from([d.addr])).unwrap();
    eventually("session two gossips to X", 120, async || {
        x.mgr
            .session(&authn_x)
            .is_some_and(|s| s.session_id() == session2_id)
    })
    .await;
    let j2_id = session2.next_job_id();
    let j2 = sign_job_for(&mut root, j2_id, session2_id, "true", &x.baseboard).await;
    x.mgr
        .job_start(
            &authn_x,
            j2.clone(),
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    session2.job_started(j2);
    // D must witness the job: X's replayed chain in its fourth life
    // can only be rebuilt from what D holds.
    eventually("D witnesses the second job", 60, async || {
        d.mgr.job_status(&authn_d, &j2_id).await.is_ok_and(|map| {
            map.get(&x.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        })
    })
    .await;

    // X dies again and returns to A's universe. Its record holds
    // session two's sequence number, which session one does not
    // exceed, even from another universe: session one's next job is
    // refused, and nothing re-runs.
    x_shutdown.cancel();
    drop(x);
    d.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;
    let x_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let x = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &x_shutdown).await;
    let authn_x = fake_identity(&mut root).await;
    a.peers.send(BTreeSet::from([x.addr])).unwrap();
    x.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("session one replays to X", 120, async || {
        x.mgr
            .session(&authn_x)
            .is_some_and(|s| s.session_id() == session1_id)
    })
    .await;
    let j3_id = session1.next_job_id();
    let j3 = sign_job_for(&mut root, j3_id, session1_id, "true", &x.baseboard).await;
    x.mgr
        .job_start(&authn_x, j3, JobStartParams::default())
        .await
        .unwrap();
    eventually("the old session is superseded", 120, async || {
        a.mgr.job_status(&authn_a, &j3_id).await.is_ok_and(|map| {
            map.get(&x.baseboard).is_some_and(|s| {
                matches!(
                    s,
                    JobStatus::Skipped {
                        reason: SkipReason::SessionSuperseded,
                        ..
                    }
                )
            })
        })
    })
    .await;

    // A session with a sequence number above the committed one serves
    // X again.
    let Ceremony {
        session_id: session3_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 3);
    let mut session3 = Session::new(session3_id);
    a.mgr
        .session_start(&authn_a, session3_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();
    confirm_start(&a, &authn_a, &mut root, &mut session3).await;
    eventually("session three gossips to X", 120, async || {
        x.mgr
            .session(&authn_x)
            .is_some_and(|s| s.session_id() == session3_id)
    })
    .await;
    let j4_id = session3.next_job_id();
    let j4 = sign_job_for(&mut root, j4_id, session3_id, "true", &x.baseboard).await;
    x.mgr
        .job_start(
            &authn_x,
            j4,
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        x.mgr.job_status(&authn_x, &j4_id).await.is_ok_and(|map| {
            map.get(&x.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
        }),
        "a session above the committed one must serve"
    );

    // X flops back to D's universe a second time. The job X served in
    // A's universe displaced D's watermark, so that write must have
    // burned D: session two's next job is skipped there, never re-run.
    x_shutdown.cancel();
    drop(x);
    a.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;
    let locker = Locker::new(&log, baseboard(2), vec![slot]).unwrap();
    let x = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &shutdown).await;
    let authn_x = fake_identity(&mut root).await;
    d.peers.send(BTreeSet::from([x.addr])).unwrap();
    x.peers.send(BTreeSet::from([d.addr])).unwrap();
    eventually("session two replays to X", 120, async || {
        x.mgr
            .session(&authn_x)
            .is_some_and(|s| s.session_id() == session2_id)
    })
    .await;
    let j5_id = session2.next_job_id();
    let j5 = sign_job_for(&mut root, j5_id, session2_id, "true", &x.baseboard).await;
    x.mgr
        .job_start(&authn_x, j5, JobStartParams::default())
        .await
        .unwrap();
    eventually("session two is superseded as well", 120, async || {
        x.mgr.job_status(&authn_x, &j5_id).await.is_ok_and(|map| {
            map.get(&x.baseboard).is_some_and(|s| {
                matches!(
                    s,
                    JobStatus::Skipped {
                        reason: SkipReason::SessionSuperseded,
                        ..
                    }
                )
            })
        })
    })
    .await;

    shutdown.cancel();
}

#[named]
#[tokio::test]
async fn witnessed_session_survives_restart() {
    let (_tmp, dir) = pki("sush-witness-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();

    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;

    let boundary_dir = TempDir::with_prefix("sush-boundary-").unwrap();
    let slot = Utf8PathBuf::from_path_buf(boundary_dir.path().to_path_buf()).unwrap();
    let b_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let b = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &b_shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe convergence", 120, async || {
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;
    sees(&a, &b).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    let mut session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();

    // A job runs on B and its request is witnessed by A, so replay
    // reaches B's boundary when it returns. The job must be live
    // traffic on B: a replayed job never executes.
    let j1_id = session.next_job_id();
    let j1 = sign_job_for(&mut root, j1_id, session_id, "true", &b.baseboard).await;
    a.mgr
        .job_start(&authn_a, j1.clone(), JobStartParams::default())
        .await
        .unwrap();
    eventually("B's result reaches A", 120, async || {
        a.mgr.job_status(&authn_a, &j1_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { .. }))
        })
    })
    .await;

    // B restarts. The session's history is intact, so the session
    // keeps working on B.
    b_shutdown.cancel();
    drop(b);
    sleep(Duration::from_millis(500)).await;
    let locker = Locker::new(&log, baseboard(2), vec![slot]).unwrap();
    let b = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe reconvergence", 120, async || {
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;

    session.job_started(j1);
    let j2_id = session.next_job_id();
    let j2 = sign_job_for(&mut root, j2_id, session_id, "true", &b.baseboard).await;
    a.mgr
        .job_start(&authn_a, j2, JobStartParams::default())
        .await
        .unwrap();
    eventually("the session's next job runs on B", 120, async || {
        a.mgr.job_status(&authn_a, &j2_id).await.is_ok_and(|map| {
            map.get(&b.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { .. }))
        })
    })
    .await;

    shutdown.cancel();
}

#[named]
#[tokio::test]
async fn bookmarks_survive_restart() {
    let (_tmp, dir) = pki("sush-bookmark-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();

    // Sled A holds session history, so it wins every dominance contest.
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();

    // Sled 2 keeps its identity in a bookmark; joining records it.
    let bookmark_dir = TempDir::with_prefix("sush-bookmark-").unwrap();
    let slot = Utf8PathBuf::from_path_buf(bookmark_dir.path().to_path_buf()).unwrap();
    let record = slot.join(BOOKMARK.file);
    let b_shutdown = CancellationToken::new();
    let b = Sled::start_with_locker(
        &log,
        &dir,
        2,
        &root_pem,
        Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap(),
        &b_shutdown,
    )
    .await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("the joining sled records its identity", 120, async || {
        record.as_std_path().exists()
    })
    .await;
    let before = read(&record).unwrap();

    // The next incarnation reads the record back, rejoins, and
    // advances it, reclaiming the previous life's identity.
    b_shutdown.cancel();
    drop(b);
    a.peers.send(BTreeSet::new()).unwrap();
    // Let the dead incarnation's tasks quiesce, as a real reboot
    // would. Two live sources over one slot are the store's one
    // forbidden misuse.
    sleep(Duration::from_millis(500)).await;
    let b = Sled::start_with_locker(
        &log,
        &dir,
        2,
        &root_pem,
        Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap(),
        &shutdown,
    )
    .await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe convergence", 120, async || {
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;
    eventually(
        "the record advances past the previous life",
        120,
        async || read(&record).unwrap() != before,
    )
    .await;

    shutdown.cancel();
}

#[named]
#[tokio::test]
async fn gossip_survives_bookmark_failure() {
    let (_tmp, dir) = pki("sush-nobookmark-", 2);
    let mut root = common::ephemeral_root();
    let root_pem = dir.join("job-root.pem");
    write(
        &root_pem,
        pem_cert_chain(vec![root.cert().to_owned()]).unwrap(),
    )
    .unwrap();

    let log = test_logger(function_name!());
    let shutdown = CancellationToken::new();

    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = fake_identity(&mut root).await;

    // Sled 2's bookmark points into a directory that does not exist.
    // It sheds the bookmark and gossips anyway, stranding identities
    // rather than the rack.
    let b = Sled::start_with_locker(
        &log,
        &dir,
        2,
        &root_pem,
        Locker::new(
            &log,
            baseboard(2),
            vec![Utf8PathBuf::from("/nonexistent/sush")],
        )
        .unwrap(),
        &shutdown,
    )
    .await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("universe convergence", 120, async || {
        a.universe.borrow().rumors.network() == b.universe.borrow().rumors.network()
    })
    .await;
    sees(&a, &b).await;
    let Ceremony {
        session_id,
        client_nonce,
        signer_nonce,
        seq,
    } = ceremony(&a.mgr, 1);
    let session = Session::new(session_id);
    a.mgr
        .session_start(&authn_a, session_id, client_nonce, signer_nonce, seq)
        .await
        .unwrap();

    // The degraded sled refuses live jobs rather than run one it
    // cannot record, and gossips the refusal. The healthy sled still
    // runs it.
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
    eventually("the degraded sled refuses the job", 120, async || {
        a.mgr.job_status(&authn_a, &job_id).await.is_ok_and(|map| {
            map.get(&b.baseboard).is_some_and(|s| {
                matches!(
                    s,
                    JobStatus::Error {
                        error: ProcessError::Io { .. },
                        ..
                    }
                )
            })
        })
    })
    .await;
    eventually("the healthy sled runs the job", 120, async || {
        a.mgr.job_status(&authn_a, &job_id).await.is_ok_and(|map| {
            map.get(&a.baseboard)
                .is_some_and(|s| matches!(s, JobStatus::Stopped { .. }))
        })
    })
    .await;

    shutdown.cancel();
}
