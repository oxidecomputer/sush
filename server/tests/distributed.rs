// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Two job managers on two gossiping sleds. What one accepts, both know.

mod common;

use std::collections::BTreeSet;
use std::fs::{read, write};
use std::net::SocketAddrV6;
use std::slice::from_ref;
use std::time::Duration;

use camino::Utf8PathBuf;
use function_name::named;
use sled_hardware_types::BaseboardId;
use slog::{Logger, o};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

use chrono::Utc;
use sush_api::{JobStartParams, JobStopParams, JobWait, SessionDetails};
use sush_common::jobs::{
    JobId, JobMode, JobOutputState, JobStartRequest, JobStatus, ProcessError, Session,
    SessionClientNonce, SessionId, SessionPreimage, SessionSeq, SessionSignerNonce,
    SessionSushNonce, SignedJob, SkipReason,
};
use sush_common::keys::{EphemeralKey, KeyId, Signer as _, pem_cert_chain};
use sush_common::targets::{Cubbies, SledHealth, SledId, Target};
use sush_common::version::VersionInfo;
use sush_server::executor::PathIsolation;
use sush_server::gossip::spawn_gossip;
use sush_server::locker::Locker;
use sush_server::locker::bookmark::BOOKMARK;
use sush_server::messages::v0::{Event, JobEvent, JobRequest, Message, Request};
use sush_server::output::JobOutputDir;
use sush_server::state::GossipNetwork;
use sush_server::{JobError, JobManager, seed_gossip};

use common::{
    baseboard, corpus, eventually, gossip_config, localhost, pki, requester, sign_job,
    sprockets_config, test_logger,
};

struct Sled {
    mgr: JobManager,
    network: watch::Receiver<GossipNetwork>,
    peers: watch::Sender<BTreeSet<SocketAddrV6>>,
    addr: SocketAddrV6,
    baseboard: BaseboardId,
    cubbies: watch::Sender<Cubbies>,
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
        let (addr, network, connected) = spawn_gossip(
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
        let (cubbies, cubbies_rx) = watch::channel(Cubbies::new());
        let mgr = JobManager::new(
            log.clone(),
            PathIsolation::InsecureDisable,
            JobOutputDir::fixed(output.path()),
            baseboard.clone(),
            cubbies_rx,
            network.clone(),
            connected,
            &locker,
            from_ref(root_pem),
            shutdown.clone(),
        )
        .await
        .unwrap();
        Sled {
            mgr,
            network,
            peers,
            addr,
            baseboard,
            cubbies,
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

    // The sleds converge on one network, resetting the losing job manager.
    eventually("network convergence", 120, async || {
        a.network.borrow().network() == b.network.borrow().network()
    })
    .await;

    // Each sled learns the other's build, and sees it connected.
    eventually("versions gossip", 120, async || {
        [&a, &b].iter().all(|sled| {
            let versions = sled.mgr.versions();
            [&a.baseboard, &b.baseboard].iter().all(|baseboard| {
                versions.iter().any(|row| {
                    row.baseboard == **baseboard
                        && row.version.as_ref() == Some(&VersionInfo::current())
                        && row.health == Some(SledHealth::Connected)
                })
            })
        })
    })
    .await;

    // A session that begins on sled A with its first job becomes
    // B's active session too.
    let authn_a = requester(&root);
    let authn_b = requester(&root);
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    let session = Session::new(session_id);

    // That job, submitted to A, runs on both sleds. A waits for both
    // results before it returns, and B learns A's result too.
    let job_id = session.next_job_id();
    let job = sign_job(&mut root, job_id, session_id, "true").await;
    let sleds = a
        .mgr
        .job_start(
            &authn_a,
            job,
            JobStartParams {
                wait: JobWait::Stop,
                ..Default::default()
            },
            Some(&details),
        )
        .await
        .unwrap();
    assert_eq!(
        sleds,
        BTreeSet::from([a.baseboard.clone(), b.baseboard.clone()])
    );
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
    assert!(stopped(&a.mgr, &authn_a, &b.baseboard).await);
    eventually("A's run visible on B", 60, async || {
        stopped(&b.mgr, &authn_b, &a.baseboard).await
    })
    .await;

    // A session started on B supersedes A's everywhere.
    let Ceremony {
        session_id: successor,
        details,
        ..
    } = ceremony(&b.mgr, &authn_b, 2);
    start_session(
        &b,
        &authn_b,
        &mut root,
        &mut Session::new(successor),
        details,
    )
    .await;
    eventually("supersession gossips to A", 60, async || {
        a.mgr
            .session(&authn_a)
            .is_some_and(|s| s.session_id() == successor)
    })
    .await;

    shutdown.cancel();
}

/// A session's details name the sled whose server nonce they were built
/// over, so another sled refuses the first job. The sled that issued
/// the nonce accepts it, and the session begins on both.
#[named]
#[tokio::test]
async fn first_job_needs_ceremony_sled() {
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
    eventually("network convergence", 120, async || {
        a.network.borrow().network() == b.network.borrow().network()
    })
    .await;

    // The ceremony runs over A's server nonce.
    let authn_a = requester(&root);
    let authn_b = requester(&root);
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    let job_id = Session::new(session_id).next_job_id();
    let job = sign_job(&mut root, job_id, session_id, "true").await;
    let params = JobStartParams::default();
    assert!(matches!(
        b.mgr.job_start(&authn_b, job.clone(), params.clone(), Some(&details)).await,
        Err(JobError::OtherSled(id, sled)) if id == session_id && sled == a.baseboard
    ));
    a.mgr
        .job_start(&authn_a, job, params, Some(&details))
        .await
        .unwrap();
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

/// The sled that accepts a cubby-targeted job resolves the cubby, but
/// the listed sled runs the job only if it knows its own cubby and the
/// signed target names it. Otherwise the listed sled skips the job.
#[named]
#[tokio::test]
async fn listed_sled_checks_own_cubby() {
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
    eventually("network convergence", 120, async || {
        a.network.borrow().network() == b.network.borrow().network()
    })
    .await;
    sees(&a, &b).await;

    let authn = requester(&root);
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn, 1);
    let mut session = Session::new(session_id);

    // Start a job naming `cubby` on A, and return B's status for it.
    // A's map update lands whenever its state task gets to it, so
    // retry the job until A accepts it.
    let mut run = async |cubby: u8| {
        let job = root
            .sign(JobStartRequest::new(
                session.next_job_id(),
                session_id,
                "true",
                JobMode::Batch,
                cubby.to_string().parse().unwrap(),
            ))
            .await
            .unwrap();
        let wait = JobStartParams {
            wait: JobWait::Stop,
            ..Default::default()
        };
        let sleds = loop {
            match a
                .mgr
                .job_start(&authn, job.clone(), wait.clone(), Some(&details))
                .await
            {
                Ok(sleds) => break sleds,
                Err(JobError::UnknownCubby(_)) => sleep(Duration::from_millis(50)).await,
                Err(error) => panic!("job start failed: {error}"),
            }
        };
        assert_eq!(sleds, BTreeSet::from([b.baseboard.clone()]));
        let mut status = a.mgr.job_status(&authn, job.job_id()).await.unwrap();
        assert!(!status.contains_key(&a.baseboard));
        session.job_started(job);
        status.remove(&b.baseboard).unwrap()
    };
    let skipped = |status: &JobStatus| match status {
        JobStatus::Skipped { reason, .. } => Some(*reason),
        _ => None,
    };

    // Only A knows that B is in cubby 14, so B cannot tell whether the
    // job names it.
    a.cubbies
        .send(Cubbies::from([(14, b.baseboard.clone())]))
        .unwrap();
    assert_eq!(skipped(&run(14).await), Some(SkipReason::CubbyUnknown));

    // B knows it is in cubby 15, so A's map is wrong.
    b.cubbies
        .send(Cubbies::from([(15, b.baseboard.clone())]))
        .unwrap();
    eventually("B learns its cubby", 60, async || {
        b.mgr
            .versions()
            .iter()
            .any(|row| row.baseboard == b.baseboard && row.cubby == Some(15))
    })
    .await;
    assert_eq!(skipped(&run(14).await), Some(SkipReason::NotTargeted));

    // With A's map corrected, the job names B and runs there.
    a.cubbies
        .send(Cubbies::from([(15, b.baseboard.clone())]))
        .unwrap();
    assert!(matches!(run(15).await, JobStatus::Stopped { .. }));

    shutdown.cancel();
}

/// A stop waits for the sleds the job runs on, even when the sled that
/// takes the stop is not one of them.
#[named]
#[tokio::test]
async fn stop_waits_for_remote_sleds() {
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
    eventually("network convergence", 120, async || {
        a.network.borrow().network() == b.network.borrow().network()
    })
    .await;
    sees(&a, &b).await;

    let authn = requester(&root);
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn, 1);

    // A takes a job that runs only on B, and waits for it to start.
    let job_id = Session::new(session_id).next_job_id();
    let job = sign_job_for(&mut root, job_id, session_id, "sleep 1000", &b.baseboard).await;
    a.mgr
        .job_start(
            &authn,
            job,
            JobStartParams {
                wait: JobWait::Start,
                ..Default::default()
            },
            Some(&details),
        )
        .await
        .unwrap();

    // A takes the stop, and returns once B has stopped the job.
    let stop = JobStopParams {
        wait: JobWait::Stop,
        ..Default::default()
    };
    timeout(
        Duration::from_secs(60),
        a.mgr.job_stop(&authn, &job_id, stop),
    )
    .await
    .expect("the stop waits only for B")
    .unwrap();
    let status = a.mgr.job_status(&authn, &job_id).await.unwrap();
    assert!(status[&b.baseboard].is_terminal());
    assert!(!status.contains_key(&a.baseboard));

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
    let authn = requester(&root);
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn, 1);

    // The sled refuses a job carrying another job's signature, records
    // nothing under its id, and does not begin the session.
    let job_id = Session::new(session_id).next_job_id();
    let job = sign_job(&mut root, job_id, session_id, "true").await;
    let other = sign_job(&mut root, job_id, session_id, "false").await;
    let forged = SignedJob::new(
        job.payload().clone(),
        job.key_id().clone(),
        other.signature().clone(),
    );
    let params = JobStartParams {
        wait: JobWait::Stop,
        ..Default::default()
    };
    assert!(matches!(
        a.mgr
            .job_start(&authn, forged, params.clone(), Some(&details))
            .await,
        Err(JobError::UnverifiedJob(_))
    ));
    assert!(a.mgr.job_status(&authn, &job_id).await.is_err());
    assert!(a.mgr.session(&authn).is_none());

    // The signed job then runs in its place.
    a.mgr
        .job_start(&authn, job, params, Some(&details))
        .await
        .unwrap();
    assert!(a.mgr.job_status(&authn, &job_id).await.is_ok_and(|map| {
        map.get(&a.baseboard)
            .is_some_and(|s| matches!(s, JobStatus::Stopped { result: Ok(0), .. }))
    }));

    shutdown.cancel();
}

/// The session check passes with the active session, or with details
/// for a session that outranks it. It fails with a session the sled
/// has never seen, or with one that a later session superseded.
#[named]
#[tokio::test]
async fn session_check_admits_session_details() {
    let (_tmp, dir) = pki("sush-session-check-", 1);
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
    let authn = requester(&root);
    let Ceremony {
        session_id,
        details,
        preimage,
    } = ceremony(&a.mgr, &authn, 1);
    assert!(matches!(
        a.mgr.session_check(session_id, None),
        Err(JobError::NoSession)
    ));
    a.mgr.session_check(session_id, Some(&preimage)).unwrap();

    let mut session = Session::new(session_id);
    start_session(&a, &authn, &mut root, &mut session, details).await;
    a.mgr.session_check(session_id, None).unwrap();

    let Ceremony {
        session_id: successor,
        details,
        ..
    } = ceremony(&a.mgr, &authn, 2);
    start_session(&a, &authn, &mut root, &mut Session::new(successor), details).await;
    assert!(matches!(
        a.mgr.session_check(session_id, None),
        Err(JobError::SessionNotCurrent(_))
    ));
    assert!(matches!(
        a.mgr.session_check(session_id, Some(&preimage)),
        Err(JobError::SessionNotCurrent(_))
    ));

    shutdown.cancel();
}

/// Another identity cannot begin a session with a stolen first job,
/// because the session's details verify only over the starter's server
/// nonce. A stranger's own details pass a preflight but change nothing.
/// The sled refuses the first job of a session the active session
/// outranks, and any verified job with details begins its session.
#[named]
#[tokio::test]
async fn stolen_first_job_never_starts_session() {
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
    let authn = requester(&root);
    let forger = common::ephemeral_root();
    let authn_forger = requester(&forger);

    // A genuine session begins with its first job.
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn, 2);
    let mut session = Session::new(session_id);
    start_session(&a, &authn, &mut root, &mut session, details).await;
    assert!(
        a.mgr
            .session(&authn)
            .is_some_and(|s| s.session_id() == session_id)
    );

    // The forger replays the next genuine session's first job and
    // details, which do not verify over the forger's server nonce.
    let Ceremony {
        session_id: next_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn, 3);
    let mut next = Session::new(next_id);
    let stolen = sign_job(&mut root, next.next_job_id(), next_id, "true").await;
    assert!(matches!(
        a.mgr
            .job_start(&authn_forger, stolen, JobStartParams::default(), Some(&details))
            .await,
        Err(JobError::StaleNonce(id)) if id == next_id
    ));

    // The forger's own details pass a preflight and change nothing.
    let forged = ceremony(&a.mgr, &authn_forger, SessionSeq::MAX_MILLIS);
    a.mgr
        .job_preflight(
            &authn_forger,
            forged.session_id,
            &Target::All,
            Some(&forged.details),
        )
        .unwrap();
    assert!(
        a.mgr
            .session(&authn)
            .is_some_and(|s| s.session_id() == session_id)
    );

    // The next genuine session takes the slot regardless.
    start_session(&a, &authn, &mut root, &mut next, details).await;
    assert!(
        a.mgr
            .session(&authn)
            .is_some_and(|s| s.session_id() == next_id)
    );

    // The sled refuses the first job of a session the active session
    // outranks.
    let Ceremony {
        session_id: stale_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn, 1);
    let stale = Session::new(stale_id);
    let job = sign_job(&mut root, stale.next_job_id(), stale_id, "true").await;
    assert!(matches!(
        a.mgr
            .job_start(&authn, job, JobStartParams::default(), Some(&details))
            .await,
        Err(JobError::SessionNotCurrent(id)) if id == stale_id
    ));

    // A verified job past the first begins its session just as well,
    // and queues behind the hole until the first job fills it.
    let Ceremony {
        session_id: last_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn, 4);
    let mut last = Session::new(last_id);
    let first = sign_job(&mut root, last.next_job_id(), last_id, "true").await;
    last.job_started(first.clone());
    let second_id = last.next_job_id();
    let second = sign_job(&mut root, second_id, last_id, "true").await;
    a.mgr
        .job_start(
            &authn,
            second,
            JobStartParams {
                ..Default::default()
            },
            Some(&details),
        )
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
            None,
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
    let authn_a = requester(&root);
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    let session = Session::new(session_id);
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
            Some(&details),
        )
        .await
        .unwrap();

    // B joins later and receives the whole history as replay: it learns
    // what happened, but the executed job must not run again here.
    let b = Sled::start(&log, &dir, 2, &root_pem, &shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    let authn_b = requester(&root);
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
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 2);
    let fresh = Session::new(successor);
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
            Some(&details),
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
    let authn_a = requester(&root);

    // A previous life of sled 2 accepted a job that runs only there,
    // started it, and died before stopping it: the rack's history
    // shows it running forever.
    let Ceremony {
        session_id,
        preimage,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    let ghost = baseboard(2);
    let job_id = Session::new(session_id).next_job_id();
    let job = sign_job_for(&mut root, job_id, session_id, "true", &ghost).await;
    a.network
        .borrow()
        .clone()
        .send(
            Message::Request(Request::job(
                authn_a.clone(),
                JobRequest::Start(
                    job,
                    JobStartParams::default(),
                    BTreeSet::from([ghost.clone()]),
                    Some(preimage),
                ),
            ))
            .into(),
        )
        .unwrap();
    a.network
        .borrow()
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
    a.network
        .borrow()
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

/// Everything a session's first job carries to one sled: the session
/// id, the details that start the session, and the preimage the sled
/// rebuilds from them.
struct Ceremony {
    session_id: SessionId,
    details: SessionDetails,
    preimage: SessionPreimage,
}

/// Build a [`Ceremony`] against one sled for `authn`.
fn ceremony(mgr: &JobManager, authn: &KeyId, seq: u64) -> Ceremony {
    let client_nonce = SessionClientNonce::random();
    let preimage = SessionPreimage {
        baseboard: mgr.own_baseboard().clone(),
        sush_nonce: SessionSushNonce::compute(client_nonce, mgr.server_nonce(authn)),
        signer_nonce: SessionSignerNonce::random(),
        seq: SessionSeq::from_unix_millis(seq).unwrap(),
    };
    Ceremony {
        session_id: preimage.session_id(),
        details: SessionDetails {
            baseboard: preimage.baseboard.clone(),
            client_nonce,
            signer_nonce: preimage.signer_nonce,
            seq: preimage.seq,
        },
        preimage,
    }
}

/// Wait until `anchor` has received `joiner`'s birth announcement and
/// holds a live connection to it.
async fn sees(anchor: &Sled, joiner: &Sled) {
    eventually("the anchor sees the joiner", 60, async || {
        anchor.mgr.versions().iter().any(|row| {
            row.baseboard == joiner.baseboard && row.health == Some(SledHealth::Connected)
        })
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

/// Start a session on `sled` with a first job that runs `true` there,
/// and advance `session` past it.
async fn start_session(
    sled: &Sled,
    authn: &KeyId,
    root: &mut EphemeralKey,
    session: &mut Session,
    details: SessionDetails,
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
            Some(&details),
        )
        .await
        .unwrap();
    session.job_started(job);
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
    let authn_a = requester(&root);
    let c = Sled::start(&log, &dir, 3, &root_pem, &shutdown).await;
    let authn_c = requester(&root);
    let boundary_dir = TempDir::with_prefix("sush-boundary-").unwrap();
    let slot = Utf8PathBuf::from_path_buf(boundary_dir.path().to_path_buf()).unwrap();
    let b_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let b = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &b_shutdown).await;
    let authn_b = requester(&root);
    a.peers.send(BTreeSet::from([b.addr, c.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    c.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("network convergence", 120, async || {
        let network = a.network.borrow().network();
        b.network.borrow().network() == network && c.network.borrow().network() == network
    })
    .await;
    sees(&a, &b).await;
    sees(&a, &c).await;
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    let mut session = Session::new(session_id);
    start_session(&a, &authn_a, &mut root, &mut session, details).await;
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
            None,
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
            None,
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
    let authn_b = requester(&root);
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
            None,
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
async fn supersession_crosses_networks() {
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

    // Two networks that never meet: A anchors one session, D another.
    let a = Sled::start(&log, &dir, 1, &root_pem, &shutdown).await;
    let authn_a = requester(&root);
    let d = Sled::start(&log, &dir, 3, &root_pem, &shutdown).await;
    let authn_d = requester(&root);
    let Ceremony {
        session_id: session2_id,
        details,
        ..
    } = ceremony(&d.mgr, &authn_d, 2);
    let mut session2 = Session::new(session2_id);
    start_session(&d, &authn_d, &mut root, &mut session2, details).await;

    // X joins A's network and runs a job there.
    let boundary_dir = TempDir::with_prefix("sush-boundary-").unwrap();
    let slot = Utf8PathBuf::from_path_buf(boundary_dir.path().to_path_buf()).unwrap();
    let x_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let x = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &x_shutdown).await;
    let authn_x = requester(&root);
    a.peers.send(BTreeSet::from([x.addr])).unwrap();
    x.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("network convergence", 120, async || {
        a.network.borrow().network() == x.network.borrow().network()
    })
    .await;
    sees(&a, &x).await;
    let Ceremony {
        session_id: session1_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    let mut session1 = Session::new(session1_id);
    start_session(&a, &authn_a, &mut root, &mut session1, details).await;
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
            None,
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

    // X dies and rejoins D's network instead, running a job there.
    // That commit burns A's network out of X's record.
    x_shutdown.cancel();
    drop(x);
    a.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;
    let x_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let x = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &x_shutdown).await;
    let authn_x = requester(&root);
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
            None,
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

    // X dies again and returns to A's network. Its record holds
    // session two's sequence number, which session one does not
    // exceed, even from another network: session one's next job is
    // refused, and nothing re-runs.
    x_shutdown.cancel();
    drop(x);
    d.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;
    let x_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let x = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &x_shutdown).await;
    let authn_x = requester(&root);
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
        .job_start(&authn_x, j3, JobStartParams::default(), None)
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
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 3);
    let mut session3 = Session::new(session3_id);
    start_session(&a, &authn_a, &mut root, &mut session3, details).await;
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
            None,
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

    // X flops back to D's network a second time. The job X served in
    // A's network displaced D's watermark, so that write must have
    // burned D: session two's next job is skipped there, never re-run.
    x_shutdown.cancel();
    drop(x);
    a.peers.send(BTreeSet::new()).unwrap();
    sleep(Duration::from_millis(500)).await;
    let locker = Locker::new(&log, baseboard(2), vec![slot]).unwrap();
    let x = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &shutdown).await;
    let authn_x = requester(&root);
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
        .job_start(&authn_x, j5, JobStartParams::default(), None)
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
    let authn_a = requester(&root);

    let boundary_dir = TempDir::with_prefix("sush-boundary-").unwrap();
    let slot = Utf8PathBuf::from_path_buf(boundary_dir.path().to_path_buf()).unwrap();
    let b_shutdown = CancellationToken::new();
    let locker = Locker::new(&log, baseboard(2), vec![slot.clone()]).unwrap();
    let b = Sled::start_with_locker(&log, &dir, 2, &root_pem, locker, &b_shutdown).await;
    a.peers.send(BTreeSet::from([b.addr])).unwrap();
    b.peers.send(BTreeSet::from([a.addr])).unwrap();
    eventually("network convergence", 120, async || {
        a.network.borrow().network() == b.network.borrow().network()
    })
    .await;
    sees(&a, &b).await;
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    let mut session = Session::new(session_id);

    // A job runs on B and its request is witnessed by A, so replay
    // reaches B's boundary when it returns. The job must be live
    // traffic on B: a replayed job never executes.
    let j1_id = session.next_job_id();
    let j1 = sign_job_for(&mut root, j1_id, session_id, "true", &b.baseboard).await;
    a.mgr
        .job_start(
            &authn_a,
            j1.clone(),
            JobStartParams {
                ..Default::default()
            },
            Some(&details),
        )
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
    eventually("network reconvergence", 120, async || {
        a.network.borrow().network() == b.network.borrow().network()
    })
    .await;
    sees(&a, &b).await;

    session.job_started(j1);
    let j2_id = session.next_job_id();
    let j2 = sign_job_for(&mut root, j2_id, session_id, "true", &b.baseboard).await;
    a.mgr
        .job_start(&authn_a, j2, JobStartParams::default(), None)
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
    let authn_a = requester(&root);
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    start_session(
        &a,
        &authn_a,
        &mut root,
        &mut Session::new(session_id),
        details,
    )
    .await;

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
    eventually("network convergence", 120, async || {
        a.network.borrow().network() == b.network.borrow().network()
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
    let authn_a = requester(&root);

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
    eventually("network convergence", 120, async || {
        a.network.borrow().network() == b.network.borrow().network()
    })
    .await;
    sees(&a, &b).await;
    let Ceremony {
        session_id,
        details,
        ..
    } = ceremony(&a.mgr, &authn_a, 1);
    let session = Session::new(session_id);

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
            Some(&details),
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
