// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Integration test utilities.

use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use camino::Utf8PathBuf;
use chrono::Utc;
use futures::TryStreamExt as _;
use rand_core::{OsRng, RngCore as _};
use sled_hardware_types::BaseboardId;
use slog::{Drain as _, Logger, o};
use slog_term::{FullFormat, PlainSyncDecorator, TestStdoutWriter};
use sprockets_tls_test_utils::{OutputFileExistsBehavior, generate_config};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use x509_cert::name::Name;
use x509_cert::time::Validity;

use sush_client::context::Authz;
use sush_client::{Client, ResponseValue};
use sush_common::authn::{Challenge, ChallengeResponse, Credentials, Identity, Nonce, RequestKey};
use sush_common::codephrases::Codephrase;
use sush_common::jobs::{JobId, JobStartRequest, SessionId, VerifiedJob};
use sush_common::keys::{EphemeralKey, KeyType, Signer};
use sush_common::targets::{Cubbies, Target};
use sush_server::executor::PathIsolation;
use sush_server::gossip::isolated;
use sush_server::output::{JobOutputDir, JobOutputFileStream};
use sush_server::state::GossipNetwork;
use sush_server::{JobError, JobManager, seed_gossip};

static TEST_BASEBOARD_ID: OnceLock<BaseboardId> = OnceLock::new();

pub fn test_baseboard_id() -> BaseboardId {
    TEST_BASEBOARD_ID
        .get_or_init(|| BaseboardId {
            part_number: "test part".to_string(),
            serial_number: "0000".to_string(),
        })
        .clone()
}

/// Collect a job output stream into memory. Convenient for tests, which know
/// their output is small; the server deliberately streams instead.
#[allow(async_fn_in_trait)]
pub trait IntoBytes {
    async fn into_bytes(self) -> Vec<u8>;
}

impl IntoBytes for JobOutputFileStream {
    async fn into_bytes(self) -> Vec<u8> {
        self.try_collect::<Vec<Bytes>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect()
    }
}

#[allow(async_fn_in_trait)]
pub trait SignJobRequest {
    async fn sign_job_request<S: AsRef<str>>(
        &mut self,
        job_id: JobId,
        session_id: SessionId,
        command: S,
        interactive: bool,
    ) -> VerifiedJob {
        self.sign_job_request_for(job_id, session_id, command, interactive, Target::All)
            .await
    }

    async fn sign_job_request_for<S: AsRef<str>>(
        &mut self,
        job_id: JobId,
        session_id: SessionId,
        command: S,
        interactive: bool,
        target: Target,
    ) -> VerifiedJob;
}

impl SignJobRequest for EphemeralKey {
    async fn sign_job_request_for<S: AsRef<str>>(
        &mut self,
        job_id: JobId,
        session_id: SessionId,
        command: S,
        interactive: bool,
        target: Target,
    ) -> VerifiedJob {
        self.sign(JobStartRequest::new(
            job_id,
            session_id,
            command,
            interactive,
            target,
        ))
        .await
        .expect("failed to sign job")
        .verify_with_cert(self.cert())
        .expect("failed to verify job signature")
    }
}

/// Inject some randomness into the subject DN to ensure unique key IDs.
pub fn ephemeral_test_subject() -> Name {
    let mut buf = [0; 8];
    OsRng.fill_bytes(&mut buf);
    let id = Codephrase::random().truncate();
    format!("CN=Ephemeral Test Key {id},O=Oxide Computer Company,C=US")
        .parse()
        .unwrap()
}

pub fn ephemeral_test_root() -> EphemeralKey {
    EphemeralKey::new_root(
        KeyType::P256,
        ephemeral_test_subject(),
        Validity::from_now(Duration::from_secs(60)).unwrap(),
    )
    .unwrap()
}

pub fn test_logger(test_name: &'static str) -> Logger {
    let decorator = PlainSyncDecorator::new(TestStdoutWriter);
    let drain = FullFormat::new(decorator).build().fuse();
    Logger::root(drain, o!("test" => test_name))
}

/// A one-node local PKI in a fresh temp dir, standing in for the
/// platform identity a real sled resolves from its RoT.
pub fn test_pki(prefix: &'static str) -> (TempDir, Utf8PathBuf) {
    let tmp = TempDir::with_prefix(prefix).unwrap();
    let dir = Utf8PathBuf::from_path_buf(tmp.path().to_owned()).unwrap();
    let behavior = OutputFileExistsBehavior::Overwrite;
    let doc = generate_config(1);
    doc.write_key_pairs(dir.clone(), behavior).unwrap();
    doc.write_certificates(dir.clone(), behavior).unwrap();
    doc.write_certificate_lists(dir.clone(), behavior).unwrap();
    (tmp, dir)
}

pub async fn fake_identity(key: &mut EphemeralKey) -> Identity {
    let nonce = Nonce::random();
    let challenge = Challenge::new(nonce.clone());
    let response = ChallengeResponse::new(challenge, RequestKey::new().verifier());
    let signed = key.sign(response).await.unwrap();
    let verified = signed
        .verify_with_ssh_public_key(&key.ssh_public_key())
        .unwrap();
    Identity::new(key.ssh_public_key(), verified, Utc::now()).unwrap()
}

/// Log in at the manager layer, without a client or server.
pub async fn manager_login(mgr: &JobManager, key: &mut EphemeralKey) -> Result<Authz, JobError> {
    let JobError::Unauthorized(nonce) = mgr.iam(None, None, ("POST", "/iam")).await.unwrap_err()
    else {
        panic!("expected a challenge");
    };
    let challenge = Challenge::new(nonce);
    let request_key = RequestKey::new();
    let response = ChallengeResponse::new(challenge, request_key.verifier());
    let signed = key.sign(response).await.unwrap();
    let public_key = key.ssh_public_key();
    let verified = signed.verify_with_ssh_public_key(&public_key).unwrap();
    let mut credentials = Credentials::new(verified);
    credentials.key_id = public_key.key_id().unwrap();
    mgr.iam(
        Some(credentials.to_string()),
        Some(public_key),
        ("POST", "/iam"),
    )
    .await?;
    Ok(Authz::new(credentials, request_key))
}

pub async fn manager_and_test_root(
    log: Logger,
) -> (JobManager, EphemeralKey, TempDir, CancellationToken) {
    let (mgr, root, _peer, dir, shutdown) = manager_test_root_and_peer(log).await;
    (mgr, root, dir, shutdown)
}

/// Like [`manager_and_test_root`], but also hands back a clone of the
/// manager's gossip network, for tests that play a peer.
pub async fn manager_test_root_and_peer(
    log: Logger,
) -> (
    JobManager,
    EphemeralKey,
    GossipNetwork,
    TempDir,
    CancellationToken,
) {
    let dir = TempDir::with_prefix("sush-").unwrap();
    let seed = seed_gossip();
    let peer = seed.clone();
    let gossip = isolated(seed);
    let shutdown = CancellationToken::new();
    let root = ephemeral_test_root();
    let mgr = JobManager::with_root_certs(
        log,
        PathIsolation::InsecureDisable,
        JobOutputDir::fixed(dir.path()),
        test_baseboard_id(),
        no_cubbies(),
        gossip,
        &[root.cert().to_owned()],
        shutdown.clone(),
    )
    .await
    .unwrap();
    (mgr, root, peer, dir, shutdown)
}

/// A cubby map that will never be known.
pub fn no_cubbies() -> watch::Receiver<Cubbies> {
    watch::channel(Cubbies::new()).1
}

pub async fn authz<E>(
    client: &Client,
    response: ResponseValue<E>,
    key: &mut EphemeralKey,
) -> (Identity, Authz) {
    let challenge = response
        .headers()
        .get("WWW-Authenticate")
        .expect("missing WWW-Authenticate header")
        .to_str()
        .expect("invalid WWW-Authenticate header")
        .parse::<Challenge>()
        .expect("malformed WWW-Authenticate header");
    let request_key = RequestKey::new();
    let response = ChallengeResponse::new(challenge, request_key.verifier());
    let signed = key.sign(response).await.unwrap();
    let verified = signed
        .verify_with_ssh_public_key(&key.ssh_public_key())
        .unwrap();
    let mut credentials = Credentials::new(verified);
    let public_key = key.ssh_public_key();
    credentials.key_id = public_key.key_id().unwrap(); // override cert key ID
    let identity = client
        .iam()
        .authorization(credentials.to_string())
        .body(public_key.to_string())
        .send()
        .await
        .unwrap()
        .into_inner();
    (identity, Authz::new(credentials, request_key))
}
