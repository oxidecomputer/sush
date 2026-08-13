// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shared harness for sprockets-backed tests: a local PKI with fake
//! measurements, exactly as trust-quorum's tests build one.

#![allow(dead_code)] // each test crate uses a subset

use std::fs;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use attest_mock::{corim, log};
use camino::Utf8PathBuf;
use chrono::Utc;
use rand_core::{OsRng, RngCore as _};
use slog::{Drain as _, Logger, o};
use slog_term::{FullFormat, PlainSyncDecorator, TestStdoutWriter};
use sprockets_tls::keys::{
    AttestConfig, MeasurementConnectionPolicy, ResolveSetting, SprocketsConfig,
};
use sprockets_tls_test_utils::{
    OutputFileExistsBehavior, alias_prefix, cert_path, certlist_path, generate_config,
    private_key_path, root_prefix, sprockets_auth_prefix,
};
use sush_common::authn::{Challenge, ChallengeResponse, Identity, Nonce, RequestKey};
use sush_common::codephrases::Codephrase;
use sush_common::jobs::{JobId, JobStartRequest, SessionId, SignedJob};
use sush_common::keys::{EphemeralKey, KeyType, Signer as _};
use sush_common::targets::Target;
use sush_server::gossip::GossipConfig;
use sush_server::link::CorpusSource;
use tempfile::TempDir;
use tokio::time::{Instant, sleep};
use x509_cert::time::Validity;

pub fn test_logger(test_name: &'static str) -> Logger {
    let decorator = PlainSyncDecorator::new(TestStdoutWriter);
    let drain = FullFormat::new(decorator).build().fuse();
    Logger::root(drain, o!("test" => test_name))
}

pub fn localhost() -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)
}

/// A PKI plus fake measurements for `num_nodes` nodes, in a fresh temp dir.
pub fn pki(prefix: &'static str, num_nodes: usize) -> (TempDir, Utf8PathBuf) {
    let tmp = TempDir::with_prefix(prefix).unwrap();
    let dir = Utf8PathBuf::from_path_buf(tmp.path().to_owned()).unwrap();
    write_keys_and_measurements(dir.clone(), num_nodes);
    (tmp, dir)
}

/// Generate a PKI plus fake measurements for `num_nodes` nodes.
pub fn write_keys_and_measurements(dir: Utf8PathBuf, num_nodes: usize) {
    let file_behavior = OutputFileExistsBehavior::Overwrite;
    let doc = generate_config(num_nodes);
    doc.write_key_pairs(dir.clone(), file_behavior).unwrap();
    doc.write_certificates(dir.clone(), file_behavior).unwrap();
    doc.write_certificate_lists(dir.clone(), file_behavior)
        .unwrap();

    let digest = "be4df4e085175f3de0c8ac4837e1c2c9a34e8983209dac6b549e94154f7cdd9c";
    let attest_log_doc = log::Document {
        measurements: vec![log::Measurement {
            algorithm: "sha3-256".into(),
            digest: digest.into(),
        }],
    };
    let out = log::mock(attest_log_doc).unwrap();
    fs::write(dir.join("log.bin"), &out).unwrap();

    let corim_doc = corim::Document {
        vendor: "Test Bed".into(),
        tag_id: "test-v0.0.99999".into(),
        id: "corim-test-v0.0.99999".into(),
        measurements: vec![
            corim::Measurement {
                mkey: "fake-sp".into(),
                algorithm: 10,
                digest: digest.into(),
            },
            corim::Measurement {
                mkey: "fake-fwid".into(),
                algorithm: 10,
                digest: "72fa8f8ea84a42251031366002cbb36281d0131f78cd680436116a720cdd9de5".into(),
            },
        ],
    };
    let corim = corim::mock(corim_doc).unwrap();
    fs::write(dir.join("corim.cbor"), &corim).unwrap();
}

pub fn corpus(dir: &Utf8PathBuf) -> CorpusSource {
    let corpus = vec![dir.join("corim.cbor")];
    Arc::new(move || corpus.clone())
}

/// Dial ceiling for localhost handshakes.
pub fn dial_timeout() -> Duration {
    Duration::from_secs(10)
}

/// Gossip timing shrunk for localhost.
pub fn gossip_config() -> GossipConfig {
    GossipConfig {
        reconnect: Duration::from_millis(250),
        connect_timeout: Duration::from_secs(10),
        join_timeout: Duration::from_secs(30),
    }
}

/// Poll `condition` until it holds or `secs` elapse.
pub async fn eventually(what: &str, secs: u64, mut condition: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !condition().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(100)).await;
    }
}

/// A fresh self-signed job-signing root.
pub fn ephemeral_root() -> EphemeralKey {
    let mut buf = [0; 8];
    OsRng.fill_bytes(&mut buf);
    let id = Codephrase::random().truncate();
    EphemeralKey::new_root(
        KeyType::P256,
        format!("CN=Ephemeral Test Key {id},O=Oxide Computer Company,C=US")
            .parse()
            .unwrap(),
        Validity::from_now(Duration::from_secs(600)).unwrap(),
    )
    .unwrap()
}

/// An authenticated identity for `key`, as `iam` would produce.
pub async fn fake_identity(key: &mut EphemeralKey) -> Identity {
    let challenge = Challenge::new(Nonce::random());
    let response = ChallengeResponse::new(challenge, RequestKey::new().verifier());
    let signed = key.sign(response).await.unwrap();
    let verified = signed
        .verify_with_ssh_public_key(&key.ssh_public_key())
        .unwrap();
    Identity::new(key.ssh_public_key(), verified, Utc::now()).unwrap()
}

/// Sign a batch job request with `root`.
pub async fn sign_job(
    root: &mut EphemeralKey,
    job_id: JobId,
    session_id: SessionId,
    command: &str,
) -> SignedJob {
    root.sign(JobStartRequest::new(
        job_id,
        session_id,
        command,
        false,
        Target::All,
    ))
    .await
    .unwrap()
}

pub fn sprockets_config(dir: &Utf8PathBuf, node: usize) -> SprocketsConfig {
    let sprockets_auth_key_name = sprockets_auth_prefix(node);
    let alias_key_name = alias_prefix(node);
    SprocketsConfig {
        resolve: ResolveSetting::Local {
            priv_key: private_key_path(dir.clone(), &sprockets_auth_key_name),
            cert_chain: certlist_path(dir.clone(), &sprockets_auth_key_name),
        },
        attest: AttestConfig::Local {
            priv_key: private_key_path(dir.clone(), &alias_key_name),
            cert_chain: certlist_path(dir.clone(), &alias_key_name),
            log: dir.join("log.bin"),
            test_corpus: vec![dir.join("corim.cbor")],
        },
        roots: vec![cert_path(dir.clone(), &root_prefix())],
        enforce: MeasurementConnectionPolicy::Enforced,
    }
}
