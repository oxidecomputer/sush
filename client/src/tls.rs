// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS for sush client ↔ proxy communication. The proxy serves an
//! ephemeral certificate that is self-signed but includes an RoT's
//! _voucher_ for its key (a signature with the Trust Quorum key);
//! see RFD 620 §4.6.2.1. It serves its platform identity chain
//! alongside, which is used to validate the voucher.

use std::ffi::CString;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use attest_data::{DICE_TCB_INFO, DiceTcbInfo};
use ed25519_dalek::{Signature, VerifyingKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::version::TLS13;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use slog::{Discard, Logger, o};
use sprockets_tls::keys::RotCertVerifier;
use sush_common::keys::{VOUCHER_OID, voucher_digest};
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, DecodePem as _};
use x509_cert::ext::pkix::BasicConstraints;

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

/// Accept a self-signed cert with an RoT voucher. The voucher only covers
/// the cert's public key, so it cannot extend to further certificates.
/// Replaying it is useless without possession of the private key, which
/// `CertificateVerify` proves on every handshake.
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
        let [platform, rest @ ..] = intermediates else {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        };
        self.inner.verify_cert(platform, rest)?;
        verify_vouched_cert(end_entity, platform)?;
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
        // The sprockets verifier parses the certificate as webpki,
        // which refuses the voucher's critical extension. But a vouched
        // key can sign a standard Ed25519 `CertificateVerify`, so check
        // the signature directly against the public key.
        if dss.scheme == SignatureScheme::ED25519 {
            let cert = Certificate::from_der(cert).map_err(|_| bad_encoding())?;
            let signature = Signature::from_slice(dss.signature()).map_err(|_| bad_signature())?;
            spki_key(&cert)?
                .verify_strict(message, &signature)
                .map_err(|_| bad_signature())?;
            Ok(HandshakeSignatureValid::assertion())
        } else {
            self.inner.verify_tls13_signature(message, cert, dss)
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Verify the voucher (RFD 620 §4.6.2.1) on a certificate.
/// The cert must include a [`VOUCHER_OID`] extension containing
/// a valid signature over its tagged SPKI.
fn verify_vouched_cert(
    cert: &CertificateDer<'_>,
    platform: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let cert = Certificate::from_der(cert).map_err(|_| bad_encoding())?;
    let platform = Certificate::from_der(platform).map_err(|_| bad_encoding())?;
    verify_vouching_cert(&platform)?;
    let mut voucher = None;
    for extension in cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default()
    {
        if extension.extn_id == VOUCHER_OID {
            voucher = Some(extension.extn_value.as_bytes());
        } else if extension.critical {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::InvalidPurpose,
            ));
        }
    }
    let Some(voucher) = voucher else {
        return Err(bad_signature());
    };
    let digest = voucher_digest(&cert.tbs_certificate.subject_public_key_info)
        .map_err(|_| bad_encoding())?;
    let signature = Signature::from_slice(voucher).map_err(|_| bad_signature())?;
    spki_key(&platform)?
        .verify_strict(&digest, &signature)
        .map_err(|_| bad_signature())
}

/// Verify that a platform identity cert may vouch for the proxy key.
/// Any cert that chains to a platform root passes [`RotCertVerifier`],
/// including the CAs above the Trust Quorum cert, but only the RoT
/// may sign a voucher. We check that the vouching cert is *not* a CA
/// but *does* contain a plausible DICE TCB info constraint.
fn verify_vouching_cert(platform: &Certificate) -> Result<(), rustls::Error> {
    let constraints = platform.tbs_certificate.get::<BasicConstraints>();
    let tcb_info = platform
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|ext| ext.extn_id == DICE_TCB_INFO)
        .and_then(|ext| DiceTcbInfo::from_der(ext.extn_value.as_bytes()).ok());
    match (constraints, tcb_info) {
        (
            Ok(Some((_, BasicConstraints { ca: false, .. }))),
            Some(DiceTcbInfo { fwids: Some(fwids) }),
        ) if !fwids.is_empty() => Ok(()),
        _ => Err(rustls::Error::InvalidCertificate(
            CertificateError::InvalidPurpose,
        )),
    }
}

/// The Ed25519 key in a certificate's SPKI.
fn spki_key(cert: &Certificate) -> Result<VerifyingKey, rustls::Error> {
    let key: [u8; 32] = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .try_into()
        .map_err(|_| bad_signature())?;
    VerifyingKey::from_bytes(&key).map_err(|_| bad_signature())
}

fn bad_encoding() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::BadEncoding)
}

fn bad_signature() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::BadSignature)
}

#[cfg(test)]
mod test {
    use super::*;

    /// The DICE TCB info extension from hubris's trust-quorum-dhe
    /// cert template (lib/dice/src/trust_quorum_dhe_cert_tmpl.rs)
    /// decodes as the type the voucher check requires.
    #[test]
    fn tq_dhe_tcb_info_decodes() {
        let mut extn_value = vec![
            0x30, 0x31, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x08, 0x04, 0x20,
        ];
        extn_value.extend([0; 32]);
        let tcb_info = DiceTcbInfo::from_der(&extn_value).unwrap();
        assert_eq!(tcb_info.fwids.unwrap().len(), 1);
    }

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
