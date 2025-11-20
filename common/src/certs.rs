//! Public key and certificate management.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use ed25519_dalek::{
    Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519VerifyingKey,
};
use p256::ecdsa;
use schemars::JsonSchema;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;
use x509_cert::der::oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1};
use x509_cert::der::oid::db::rfc8410::ID_ED_25519;
use x509_cert::name::Name;
use x509_cert::spki::AlgorithmIdentifier;

/// Self-signed (root) X.509 certificates.
pub const ROOT_CERTS: &[&[u8]] = &[
    //include_bytes!("../certs/root.der"),
    // Add new root certificates here.
];

#[derive(Debug, Error)]
pub enum CertError {
    #[error("base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("DER encoding error: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("Ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),
    #[error("invalid key ID: should be 16 bytes")]
    InvalidKeyId,
    #[error("invalid subject public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("can't import a self-signed (root) certificate")]
    SelfSigned,
}

/// Upper half of the SHA-256 of a certificate subject,
/// encoded with base64 for storage and transport.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd)]
pub struct KeyId(#[schemars(with = "String")] [u8; 16]);

impl Deref for KeyId {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64.encode(**self))
    }
}

impl FromStr for KeyId {
    type Err = CertError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            BASE64
                .decode(s)?
                .try_into()
                .map_err(|_| CertError::InvalidKeyId)?,
        ))
    }
}

impl TryFrom<&Name> for KeyId {
    type Error = CertError;

    fn try_from(name: &Name) -> Result<KeyId, Self::Error> {
        let hash = Sha256::digest(&name.to_der()?);
        Ok(KeyId(hash[..16].try_into().unwrap()))
    }
}

impl_to_from_sql_and_serde!(KeyId);

/// Base64 encoded signature.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd)]
pub struct Signature(#[schemars(with = "String")] Vec<u8>);

impl Signature {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for Signature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64.encode(&**self))
    }
}

impl FromStr for Signature {
    type Err = CertError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(BASE64.decode(s)?))
    }
}

impl_to_from_sql_and_serde!(Signature);

pub fn verify_signature(
    message: &[u8],
    signature: &Signature,
    cert: &Certificate,
) -> Result<(), CertError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let public_key = spki.subject_public_key.raw_bytes();
    match &spki.algorithm {
        AlgorithmIdentifier {
            oid: ID_ED_25519,
            parameters: None,
        } => {
            let signature = Ed25519Signature::from_slice(signature)?;
            let public_key = Ed25519VerifyingKey::from_bytes(
                &public_key
                    .try_into()
                    .map_err(|_| CertError::InvalidPublicKey)?,
            )?;
            public_key.verify(message, &signature)?;
        }
        AlgorithmIdentifier {
            oid: ID_EC_PUBLIC_KEY,
            parameters: Some(parameters),
        } if *parameters == SECP_256_R_1.into() => {
            let signature = ecdsa::Signature::from_bytes((&**signature).into())?;
            let public_key = ecdsa::VerifyingKey::from_sec1_bytes(public_key)?;
            public_key.verify(message, &signature)?;
        }
        _ => return Err(CertError::InvalidPublicKey),
    }
    Ok(())
}
