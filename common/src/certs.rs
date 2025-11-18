//! Public key and certificate management.

use std::ops::Deref;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use ed25519_dalek::{
    Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519VerifyingKey,
};
use p256::ecdsa;
use rusqlite::Error as SqlError;
use rusqlite::types::{FromSql, FromSqlError, ToSql, ToSqlOutput, ValueRef};
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
    #[error("DER encoding error: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("Ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),
    #[error("invalid subject public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("can't import a self-signed (root) certificate")]
    SelfSigned,
}

/// Upper half of the SHA-256 of a certificate subject.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyId([u8; 16]);

/// Derive a key ID from a certificate subject/issuer.
impl TryFrom<&Name> for KeyId {
    type Error = CertError;

    fn try_from(name: &Name) -> Result<KeyId, Self::Error> {
        let hash = Sha256::digest(&name.to_der()?);
        Ok(KeyId(hash[..16].try_into().unwrap()))
    }
}

impl Deref for KeyId {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToSql for KeyId {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>, SqlError> {
        Ok(ToSqlOutput::Owned(BASE64.encode(**self).into()))
    }
}

impl FromSql for KeyId {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        let string = <String>::column_result(value)?;
        Ok(KeyId(
            BASE64
                .decode(&string)
                .map_err(FromSqlError::other)?
                .try_into()
                .expect("should decode to 16 bytes"),
        ))
    }
}

pub fn verify_signature(
    message: &[u8],
    signature: &[u8],
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
            let signature = ecdsa::Signature::from_bytes(signature.into())?;
            let public_key = ecdsa::VerifyingKey::from_sec1_bytes(public_key)?;
            public_key.verify(message, &signature)?;
        }
        _ => return Err(CertError::InvalidPublicKey),
    }
    Ok(())
}
