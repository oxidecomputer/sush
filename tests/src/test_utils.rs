//! Integration test utilities.

use std::time::Duration;

use chrono::Utc;
use rand_core::{OsRng, RngCore as _};
use slog::{Drain as _, Logger, o};
use slog_term::{FullFormat, PlainSyncDecorator, TestStdoutWriter};
use tempfile::TempDir;
use x509_cert::name::Name;
use x509_cert::time::Validity;

use sush_client::{Client, ResponseValue};
use sush_common::authn::{Challenge, ChallengeResponse, Credentials, Identity, Nonce};
use sush_common::codephrases::generate_id;
use sush_common::jobs::{JobId, JobStartRequest, SignedJob};
use sush_common::keys::{EphemeralKey, KeyType, Signer};
use sush_server::JobManager;

#[allow(async_fn_in_trait)]
pub trait SignJobRequest {
    async fn sign_job_request<S: AsRef<str>>(
        &mut self,
        job_id: &JobId,
        command: S,
        interactive: bool,
    ) -> SignedJob;
}

impl SignJobRequest for EphemeralKey {
    async fn sign_job_request<S: AsRef<str>>(
        &mut self,
        job_id: &JobId,
        command: S,
        interactive: bool,
    ) -> SignedJob {
        self.sign(JobStartRequest::new(
            job_id.to_owned(),
            command,
            interactive,
        ))
        .await
        .unwrap()
    }
}

/// Inject some randomness into the subject DN to ensure unique key IDs.
pub fn ephemeral_test_subject() -> Name {
    let mut buf = [0; 8];
    OsRng.fill_bytes(&mut buf);
    let id = generate_id();
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

pub async fn fake_identity(key: &mut EphemeralKey) -> Identity {
    let nonce = Nonce::generate();
    let challenge = Challenge::new(nonce.clone());
    let response = ChallengeResponse::new(challenge);
    let signed = key.sign(response).await.unwrap();
    let verified = signed.verify_with_cert(key.cert()).unwrap();
    Identity::new(key.ssh_public_key(), verified, Utc::now()).unwrap()
}

pub async fn manager_and_test_root(log: Logger) -> (JobManager, EphemeralKey, TempDir) {
    let dir = TempDir::with_prefix("sush-").unwrap();
    let mgr = JobManager::new(log, dir.path()).await.unwrap();
    let root = ephemeral_test_root();
    let key_id = mgr.import_root(root.cert().to_owned()).unwrap();
    assert_eq!(&key_id, root.key_id());
    (mgr, root, dir)
}

pub async fn authz<E>(
    client: &Client,
    response: ResponseValue<E>,
    key: &mut EphemeralKey,
) -> (Identity, Credentials) {
    let challenge = response
        .headers()
        .get("WWW-Authenticate")
        .expect("missing WWW-Authenticate header")
        .to_str()
        .expect("invalid WWW-Authenticate header")
        .parse::<Challenge>()
        .expect("malformed WWW-Authenticate header");
    let response = ChallengeResponse::new(challenge);
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
    (identity, credentials)
}
