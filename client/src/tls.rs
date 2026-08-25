// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS for reaching a proxy, whose certificate chain leads to the
//! sled's platform identity, verified against the platform PKI roots.
//!
//! Verification proves only that the server holds a key some RoT
//! vouched for. TLS only provides transport privacy for job traffic.
//! We do not support expiration, revocation, or server-name binding.

use std::ffi::CString;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
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
use x509_cert::der::{Decode as _, DecodePem as _, Encode as _};

/// The same request timeout as the generated default client.
const TIMEOUT: Duration = Duration::from_secs(600);

/// The platform identity roots baked into the client: the same
/// idcerts the sled OS ships.
const PLATFORM_ROOTS: &[&[u8]] = &[
    include_bytes!("../certs/staging.pem"),
    include_bytes!("../certs/production.pem"),
];

#[derive(Debug, Error)]
pub enum ProxyTlsError {
    #[error("certificate: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error("TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("platform identity verifier: {0}")]
    Verifier(String),
    #[error("invalid server URL `{0}`")]
    Url(String),
    #[error("unknown interface `{0}`")]
    Interface(String),
}

/// Placeholder host for scoped link-local URLs.
const SCOPED_HOST: &str = "link-local.sush";

/// Split a `%zone` scope out of a bracketed IPv6 host: URLs cannot
/// carry zone IDs, so the address maps to [`SCOPED_HOST`] and the
/// zone becomes the scope ID of the resolved socket address. A
/// numeric zone starting with `25` needs the RFC 6874 `%25` prefix.
pub fn descope_url(url: &str) -> Result<(String, Option<SocketAddrV6>), ProxyTlsError> {
    let (Some(open), Some(close)) = (url.find('['), url.find(']')) else {
        return Ok((url.to_string(), None));
    };
    let Some((addr, zone)) = url.get(open + 1..close).and_then(|h| h.split_once('%')) else {
        return Ok((url.to_string(), None));
    };
    // RFC 6874 escapes the `%` itself as `%25`.
    let zone = zone
        .strip_prefix("25")
        .filter(|z| !z.is_empty())
        .unwrap_or(zone);
    let ip: Ipv6Addr = addr
        .parse()
        .map_err(|_| ProxyTlsError::Url(url.to_string()))?;
    let scope = match zone.parse() {
        // Zone 0 is no zone; the kernel would be back to guessing.
        Ok(0) => return Err(ProxyTlsError::Url(url.to_string())),
        Ok(scope) => scope,
        Err(_) => {
            let name = CString::new(zone).map_err(|_| ProxyTlsError::Url(url.to_string()))?;
            match unsafe { libc::if_nametoindex(name.as_ptr()) } {
                0 => return Err(ProxyTlsError::Interface(zone.to_string())),
                scope => scope,
            }
        }
    };
    let rest = &url[close + 1..];
    let port = match rest
        .strip_prefix(':')
        .map(|r| r.split(['/', '?']).next().unwrap_or(r).parse::<u16>())
    {
        Some(Ok(port)) => port,
        Some(Err(_)) => return Err(ProxyTlsError::Url(url.to_string())),
        None if url[..open].starts_with("http:") => 80,
        None => 443,
    };
    Ok((
        format!("{}{SCOPED_HOST}{rest}", &url[..open]),
        Some(SocketAddrV6::new(ip, port, 0, scope)),
    ))
}

/// The baked-in platform roots.
pub fn platform_roots() -> Result<Vec<Certificate>, ProxyTlsError> {
    PLATFORM_ROOTS
        .iter()
        .map(|pem| Ok(Certificate::from_pem(pem)?))
        .collect()
}

/// A `reqwest` client that accepts servers whose certificate chains
/// to one of `roots`. With `resolve`, [`SCOPED_HOST`] resolves there.
pub fn client(
    roots: Vec<Certificate>,
    resolve: Option<SocketAddrV6>,
) -> Result<reqwest::Client, ProxyTlsError> {
    let inner = RotCertVerifier::new(roots, Logger::root(Discard, o!()))
        .map_err(|err| ProxyTlsError::Verifier(err.to_string()))?;
    let config = ClientConfig::builder_with_provider(Arc::new(sprockets_tls::crypto_provider()))
        .with_protocol_versions(&[&TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PlatformVerifier { inner }))
        .with_no_client_auth();
    let mut builder = reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .timeout(TIMEOUT);
    if let Some(addr) = resolve {
        // An external proxy would bypass the override entirely.
        builder = builder
            .resolve(SCOPED_HOST, SocketAddr::V6(addr))
            .no_proxy();
    }
    Ok(builder.build()?)
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn descoped_urls() {
        let (url, resolve) = descope_url("https://[fe80::1%3]:12352").unwrap();
        assert_eq!(url, "https://link-local.sush:12352");
        let addr = SocketAddrV6::new("fe80::1".parse().unwrap(), 12352, 0, 3);
        assert_eq!(resolve, Some(addr));

        let (url, resolve) = descope_url("https://[fe80::1%3]").unwrap();
        assert_eq!(url, "https://link-local.sush");
        assert_eq!(resolve.unwrap().port(), 443);

        let (url, resolve) = descope_url("https://[fe80::1%253]:12352").unwrap();
        assert_eq!(url, "https://link-local.sush:12352");
        assert_eq!(resolve.unwrap().scope_id(), 3);

        let (url, resolve) = descope_url("https://[fe80::1%3]:12352/some/path?q=1").unwrap();
        assert_eq!(url, "https://link-local.sush:12352/some/path?q=1");
        assert_eq!(resolve.unwrap().port(), 12352);

        let (url, resolve) = descope_url("https://[fdb0::1]:12352").unwrap();
        assert_eq!(url, "https://[fdb0::1]:12352");
        assert_eq!(resolve, None);

        let (url, resolve) = descope_url("https://permslip.example").unwrap();
        assert_eq!(url, "https://permslip.example");
        assert_eq!(resolve, None);

        assert!(descope_url("https://[nonsense%3]:1").is_err());
        assert!(descope_url("https://[fe80::1%0]:1").is_err());
        assert!(descope_url("https://[fe80::1%nosuchif0]:1").is_err());
        assert!(descope_url("https://[fe80::1%3]:notaport").is_err());
    }
}
