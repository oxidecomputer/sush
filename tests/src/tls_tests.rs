// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The proxy serves a self-signed cert vouched for by the platform
//! identity, here a local test PKI, and the client accepts exactly
//! the vouchers that verify against its roots; see RFD 620 §4.6.2.1.

use std::collections::BTreeMap;
use std::fs::{read, read_to_string};
use std::net::SocketAddr;
use std::sync::Arc;

use camino::Utf8PathBuf;
use dropshot::{ConfigDropshot, HttpServer, ServerBuilder};
use function_name::named;
use slog::Logger;
use sprockets_tls_test_utils::{
    cert_path, certlist_path, device_id_prefix, platform_id_prefix, private_key_path, root_prefix,
    signer_prefix, sprockets_auth_prefix,
};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::test;
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::der::DecodePem as _;

use sush_api::sush_api_mod::api_description;
use sush_client::tls::client as tls_client;
use sush_client::{AuthzSigner, Client, Error as ClientError};
use sush_common::keys::EphemeralKey;
use sush_common::targets::Cubbies;
use sush_server::proxy::{Sleds, Targets, platform_tls};
use sush_server::{ApiServer, JobManager, ProxyServer};

use crate::test_utils::{
    authz, crafted_proxy_pems, manager_and_test_root, test_baseboard_id, test_logger, test_pki,
    vouched_proxy_pems,
};

fn local_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A full server behind a TLS proxy serving the given key and chain.
struct ProxiedServer {
    url: String,
    root: EphemeralKey,
    server: HttpServer<Arc<JobManager>>,
    shutdown_proxy: CancellationToken,
    _tx_targets: watch::Sender<Sleds>,
    _tx_cubbies: watch::Sender<Cubbies>,
    _dir: TempDir,
    _shutdown: CancellationToken,
}

impl ProxiedServer {
    async fn start(log: Logger, key_path: &Utf8PathBuf, chain_path: &Utf8PathBuf) -> Self {
        let (mgr, root, _dir, _shutdown) = manager_and_test_root(log.clone()).await;
        let api = api_description::<ApiServer>().unwrap();
        let server = ServerBuilder::new(api, Arc::new(mgr), log.clone())
            .config(ConfigDropshot {
                bind_address: local_addr(),
                ..Default::default()
            })
            .start()
            .expect("failed to start server");
        let tls = platform_tls(key_path, chain_path).expect("can't build TLS config");
        let (_tx_targets, _tx_cubbies, targets) = Targets::channel();
        _tx_targets.send_replace(BTreeMap::from([(test_baseboard_id(), server.local_addr())]));
        let shutdown_proxy = CancellationToken::new();
        let proxy = ProxyServer::start(
            &log,
            local_addr(),
            Some(tls),
            targets,
            None,
            shutdown_proxy.clone(),
        )
        .await
        .expect("can't start TLS proxy server");
        ProxiedServer {
            url: format!("https://{}", proxy.local_addr()),
            root,
            server,
            shutdown_proxy,
            _tx_targets,
            _tx_cubbies,
            _dir,
            _shutdown,
        }
    }

    async fn stop(self) {
        self.shutdown_proxy.cancel();
        self.server.close().await.expect("can't shutdown server");
    }
}

/// The root cert of `pki`, as the platform roots a client takes.
fn pki_roots(pki: &Utf8PathBuf) -> Vec<Certificate> {
    let pem = read(cert_path(pki.clone(), &root_prefix())).unwrap();
    vec![Certificate::from_pem(&pem).unwrap()]
}

/// A client rooted at `roots` must fail its handshake with `url`.
/// Only a transport-level error counts: an HTTP response, even an
/// error, means the handshake succeeded.
async fn refuse_handshake(url: &str, roots: Vec<Certificate>) {
    let client = Client::new_with_client(
        url,
        tls_client(roots, None).unwrap(),
        AuthzSigner::default(),
    );
    match client.iam().body(None).send().await {
        Err(ClientError::CommunicationError(_)) => (),
        Err(other) => panic!("expected a refused handshake: {other}"),
        Ok(_) => panic!("expected a refused handshake, request succeeded"),
    }
}

/// The client accepts a vouched cert and authenticates through
/// the proxy.
#[named]
#[test]
async fn client_tls_proxy_server() {
    let log = test_logger(function_name!());
    let (_pki_dir, pki) = test_pki("sush-tls-");
    let (key_path, chain_path) = vouched_proxy_pems(&pki);
    let mut proxied = ProxiedServer::start(log, &key_path, &chain_path).await;

    let signer = AuthzSigner::default();
    let client = Client::new_with_client(
        &proxied.url,
        tls_client(pki_roots(&pki), None).unwrap(),
        signer.clone(),
    );
    let ClientError::ErrorResponse(unauthz) = client.iam().body(None).send().await.unwrap_err()
    else {
        panic!("expected error response")
    };
    assert_eq!(unauthz.status(), 401, "expected 401 Unauthorized");
    let (identity, credentials) = authz(&client, unauthz, &mut proxied.root).await;
    signer.set(Some(credentials));
    let iam = client
        .iam()
        .body(None)
        .send()
        .await
        .expect("can't authenticate")
        .into_inner();
    assert_eq!(iam, identity, "who am I?");

    proxied.stop().await;
}

/// A client rooted elsewhere refuses the handshake.
#[named]
#[test]
async fn stranger_roots_refuse_handshake() {
    let log = test_logger(function_name!());
    let (_pki_dir, pki) = test_pki("sush-tls-");
    let (key_path, chain_path) = vouched_proxy_pems(&pki);
    let proxied = ProxiedServer::start(log, &key_path, &chain_path).await;

    let (_other_dir, other) = test_pki("sush-tls-other-");
    refuse_handshake(&proxied.url, pki_roots(&other)).await;
    proxied.stop().await;
}

/// The client refuses a cert served with a valid platform chain
/// but vouched for by the wrong key.
#[named]
#[test]
async fn forged_voucher_is_refused() {
    let log = test_logger(function_name!());
    let (_pki_dir, pki) = test_pki("sush-tls-");
    let (_other_dir, other) = test_pki("sush-tls-other-");
    let forger_pem = read_to_string(private_key_path(other.clone(), &sprockets_auth_prefix(1)))
        .expect("can't read the forger's key");
    let chain_pem = read_to_string(certlist_path(pki.clone(), &sprockets_auth_prefix(1)))
        .expect("can't read the platform chain");
    let (key_path, chain_path) = crafted_proxy_pems(&other, &forger_pem, &chain_pem);
    let proxied = ProxiedServer::start(log, &key_path, &chain_path).await;

    refuse_handshake(&proxied.url, pki_roots(&pki)).await;
    proxied.stop().await;
}

/// The client refuses a voucher signed by a CA in the platform
/// chain: every CA cert verifies against the roots just as the end
/// entity does, but none carries the DICE measurement extension.
#[named]
#[test]
async fn ca_voucher_is_refused() {
    let log = test_logger(function_name!());
    let (_pki_dir, pki) = test_pki("sush-tls-");
    let ca_pem = read_to_string(private_key_path(pki.clone(), &device_id_prefix(1)))
        .expect("can't read the device-id key");
    let chain_pem: String = [device_id_prefix(1), platform_id_prefix(1), signer_prefix()]
        .iter()
        .map(|prefix| read_to_string(cert_path(pki.clone(), prefix)).unwrap())
        .collect();
    let (key_path, chain_path) = crafted_proxy_pems(&pki, &ca_pem, &chain_pem);
    let proxied = ProxiedServer::start(log, &key_path, &chain_path).await;

    refuse_handshake(&proxied.url, pki_roots(&pki)).await;
    proxied.stop().await;
}
