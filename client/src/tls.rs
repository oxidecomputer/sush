// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS for reaching a proxy, whose certificate chain leads to the
//! sled's platform identity, verified against the platform PKI roots.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::version::TLS13;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha3::{Digest as _, Sha3_256};
use slog::{Discard, Logger, o};
use sprockets_tls::keys::RotCertVerifier;
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};

/// The same request timeout as the generated default client.
const TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Error)]
pub enum ProxyTlsError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error("TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("platform identity verifier: {0}")]
    Verifier(String),
}

/// A `reqwest` client that accepts servers whose certificate chains
/// to one of `roots`.
pub fn client(roots: Vec<Certificate>) -> Result<reqwest::Client, ProxyTlsError> {
    let inner = RotCertVerifier::new(roots, Logger::root(Discard, o!()))
        .map_err(|err| ProxyTlsError::Verifier(err.to_string()))?;
    let config = ClientConfig::builder_with_provider(Arc::new(sprockets_tls::crypto_provider()))
        .with_protocol_versions(&[&TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PlatformVerifier { inner }))
        .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .timeout(TIMEOUT)
        .build()?)
}

/// Accept a certificate chain that is the platform identity itself,
/// or an ephemeral leaf the platform identity vouched for once, in
/// the RoT's signing convention: Ed25519 over the SHA3-256 digest.
/// Delegation is one level deep by construction; a delegated leaf
/// cannot vouch for further certificates.
#[derive(Debug)]
struct PlatformVerifier {
    inner: RotCertVerifier,
}

impl ServerCertVerifier for PlatformVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.inner.verify_cert(end_entity, intermediates).is_ok() {
            return Ok(ServerCertVerified::assertion());
        }
        let [platform, rest @ ..] = intermediates else {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        };
        self.inner.verify_cert(platform, rest)?;
        verify_delegated_leaf(end_entity, platform)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Verify that `platform` signed `leaf`'s TBS certificate.
fn verify_delegated_leaf(
    leaf: &CertificateDer<'_>,
    platform: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let encoding = |_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding);
    let bad = rustls::Error::InvalidCertificate(CertificateError::BadSignature);
    let leaf = Certificate::from_der(leaf).map_err(encoding)?;
    let platform = Certificate::from_der(platform).map_err(encoding)?;
    let tbs = leaf.tbs_certificate.to_der().map_err(encoding)?;
    let key: [u8; 32] = platform
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .try_into()
        .map_err(|_| bad.clone())?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| bad.clone())?;
    let signature = Signature::from_slice(leaf.signature.raw_bytes()).map_err(|_| bad.clone())?;
    key.verify_strict(&Sha3_256::digest(&tbs), &signature)
        .map_err(|_| bad)
}
