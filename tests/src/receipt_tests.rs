// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A login receipt verifies only for the login it signs, and only with
//! a key that the platform identity vouches for as a server key. A
//! server adopts a receipted login only from a sled it links to.

use std::collections::BTreeSet;
use std::time::Duration;

use function_name::named;
use tokio::test;
use x509_cert::time::Validity;

use sush_api::{IamRequest, IamResponse};
use sush_client::context::Authz;
use sush_common::authn::{
    Challenge, ChallengeResponse, Credentials, LoginReceipt, Nonce, RequestKey,
};
use sush_common::keys::{EphemeralKey, KeyError, KeyType, Signer as _};
use sush_common::vouchers::VoucherRole;
use sush_server::gossip::LinkedBaseboards;
use sush_server::receipts::{ReceiptError, Receipts};
use sush_server::{JobError, JobManager};

use crate::test_utils::{
    fake_credentials, manager_with_receipts, pki_baseboard, pki_roots, test_logger, test_pki,
    vouched_key,
};

fn user_key() -> EphemeralKey {
    EphemeralKey::new_root(
        KeyType::Ed25519,
        "CN=user".parse().unwrap(),
        Validity::from_now(Duration::from_secs(60)).unwrap(),
    )
    .unwrap()
}

#[test]
async fn receipt_verifies() {
    let (_tmp, pki) = test_pki("receipt-verifies");
    let (mut key, platform) = vouched_key(&pki, VoucherRole::Server);
    let credentials = fake_credentials(&mut user_key()).await;
    let receipt = LoginReceipt::new(&mut key, &platform, &credentials)
        .await
        .unwrap();
    assert_eq!(receipt.verify(&credentials).unwrap(), platform);
}

#[test]
async fn receipt_for_another_login_is_refused() {
    let (_tmp, pki) = test_pki("receipt-other-login");
    let (mut key, platform) = vouched_key(&pki, VoucherRole::Server);
    let credentials = fake_credentials(&mut user_key()).await;
    let receipt = LoginReceipt::new(&mut key, &platform, &credentials)
        .await
        .unwrap();
    let mut other = credentials.clone();
    other.nonce = Nonce::random();
    assert!(matches!(
        receipt.verify(&other).unwrap_err(),
        KeyError::Signature(_),
    ));
}

#[test]
async fn receipt_from_proxy_key_is_refused() {
    let (_tmp, pki) = test_pki("receipt-proxy-key");
    let (mut key, platform) = vouched_key(&pki, VoucherRole::Proxy);
    let credentials = fake_credentials(&mut user_key()).await;
    let receipt = LoginReceipt::new(&mut key, &platform, &credentials)
        .await
        .unwrap();
    assert!(matches!(
        receipt.verify(&credentials).unwrap_err(),
        KeyError::Signature(_),
    ));
}

/// Answer a fresh challenge from `mgr` by signing with `key`.
async fn answer_challenge(mgr: &JobManager, key: &mut EphemeralKey) -> (Credentials, RequestKey) {
    let JobError::Unauthorized(nonce) = mgr.iam(None, ("POST", "/iam")).await.unwrap_err() else {
        panic!("expected a challenge");
    };
    let request_key = RequestKey::new();
    let response = ChallengeResponse::new(Challenge::new(nonce), request_key.verifier());
    let verified = key
        .sign(response)
        .await
        .unwrap()
        .verify_with_ssh_public_key(&key.ssh_public_key())
        .unwrap();
    let mut credentials = Credentials::new(verified);
    credentials.key_id = key.ssh_public_key().key_id().unwrap(); // override cert key ID
    (credentials, request_key)
}

/// Log in at `mgr` with `credentials`, presenting `receipt` if given.
async fn login(
    mgr: &JobManager,
    key: &EphemeralKey,
    credentials: &Credentials,
    receipt: Option<LoginReceipt>,
) -> Result<IamResponse, JobError> {
    let request = IamRequest::new(key.ssh_public_key(), receipt);
    mgr.login(Some(credentials.to_string()), request, ("POST", "/iam"))
        .await
}

/// Two servers: one that issues receipts, and one that accepts them.
/// The second links to the first only if `linked` is true.
async fn issuer_and_receiver(
    test_name: &'static str,
    linked: bool,
) -> (JobManager, JobManager, EphemeralKey, impl Sized) {
    let log = test_logger(test_name);
    let (tmp, pki) = test_pki("receipts");
    let issuer = Receipts::new(
        &log,
        pki_roots(&pki),
        Some(vouched_key(&pki, VoucherRole::Server)),
    );
    let (issuer, user, _, issuer_dir, issuer_shutdown) =
        manager_with_receipts(log.clone(), LinkedBaseboards::lonely(), issuer).await;
    let sleds = if linked {
        BTreeSet::from([pki_baseboard()])
    } else {
        BTreeSet::new()
    };
    let receiver = Receipts::new(&log, pki_roots(&pki), None);
    let (receiver, _, _, receiver_dir, receiver_shutdown) =
        manager_with_receipts(log, LinkedBaseboards::fixed(sleds), receiver).await;
    let guard = (
        tmp,
        issuer_dir,
        receiver_dir,
        issuer_shutdown.drop_guard(),
        receiver_shutdown.drop_guard(),
    );
    (issuer, receiver, user, guard)
}

#[named]
#[test]
async fn receipt_from_linked_sled_logs_in() {
    let (issuer, receiver, mut user, _guard) = issuer_and_receiver(function_name!(), true).await;
    let (credentials, request_key) = answer_challenge(&issuer, &mut user).await;
    let receipt = login(&issuer, &user, &credentials, None)
        .await
        .unwrap()
        .receipt
        .expect("an issuing server returns a receipt");

    let response = login(&receiver, &user, &credentials, Some(receipt))
        .await
        .unwrap();
    assert_eq!(response.identity.nonce, credentials.nonce);
    assert_eq!(response.receipt, None);

    let authz = Authz::new(credentials, request_key);
    let header = authz.header("GET", "/sessions");
    receiver
        .iam(Some(header), ("GET", "/sessions"))
        .await
        .unwrap();
}

#[named]
#[test]
async fn receipt_from_unlinked_sled_is_refused() {
    let (issuer, receiver, mut user, _guard) = issuer_and_receiver(function_name!(), false).await;
    let (credentials, _) = answer_challenge(&issuer, &mut user).await;
    let receipt = login(&issuer, &user, &credentials, None)
        .await
        .unwrap()
        .receipt;
    assert!(matches!(
        login(&receiver, &user, &credentials, receipt).await,
        Err(JobError::Unauthorized(_)),
    ));
}

/// A receipt signed with a key that another rack's platform identity
/// vouches for fails the platform root check, though its signature is
/// valid.
#[named]
#[test]
async fn receipt_from_another_rack_is_refused() {
    let log = test_logger(function_name!());
    let (_tmp, pki) = test_pki("receipt-rack");
    let (_other_tmp, other) = test_pki("receipt-other-rack");
    let (mut key, platform) = vouched_key(&other, VoucherRole::Server);
    let credentials = fake_credentials(&mut user_key()).await;
    let receipt = LoginReceipt::new(&mut key, &platform, &credentials)
        .await
        .unwrap();
    let receipts = Receipts::new(&log, pki_roots(&pki), None);
    assert!(matches!(
        receipts.verify(&receipt, &credentials).unwrap_err(),
        ReceiptError::Chain(_),
    ));
}

/// Presenting a receipt for a login the server already holds leaves
/// that login's spent sequence numbers spent.
#[named]
#[test]
async fn presenting_again_keeps_spent_sequence_numbers() {
    let (issuer, receiver, mut user, _guard) = issuer_and_receiver(function_name!(), true).await;
    let (credentials, request_key) = answer_challenge(&issuer, &mut user).await;
    let receipt = login(&issuer, &user, &credentials, None)
        .await
        .unwrap()
        .receipt;
    login(&receiver, &user, &credentials, receipt.clone())
        .await
        .unwrap();

    let authz = Authz::new(credentials.clone(), request_key);
    let header = authz.header("GET", "/sessions");
    receiver
        .iam(Some(header.clone()), ("GET", "/sessions"))
        .await
        .unwrap();
    login(&receiver, &user, &credentials, receipt)
        .await
        .unwrap();
    assert!(matches!(
        receiver.iam(Some(header), ("GET", "/sessions")).await,
        Err(JobError::Unauthorized(_)),
    ));
}

#[named]
#[test]
async fn server_refuses_receipt_for_another_login() {
    let (issuer, receiver, mut user, _guard) = issuer_and_receiver(function_name!(), true).await;
    let (first, _) = answer_challenge(&issuer, &mut user).await;
    let receipt = login(&issuer, &user, &first, None).await.unwrap().receipt;
    let (second, _) = answer_challenge(&issuer, &mut user).await;
    assert!(matches!(
        login(&receiver, &user, &second, receipt).await,
        Err(JobError::Unauthorized(_)),
    ));
}
