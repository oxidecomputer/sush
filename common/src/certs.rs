//! Key, signature, and X.509 certificate management.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey, Verifier as _,
    VerifyingKey as Ed25519VerifyingKey,
};
use p256::{SecretKey as P256SecretKey, ecdsa};
use rand_core::{OsRng, RngCore as _};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use x509_cert::der::Encode as _;
use x509_cert::der::asn1::{Any, BitString};
use x509_cert::der::oid::db::rfc5912::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, SECP_256_R_1};
use x509_cert::der::oid::db::rfc8410::ID_ED_25519;
use x509_cert::der::pem::{LineEnding, PemLabel as _, encode_string as pem_encode};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned, SubjectPublicKeyInfo};
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate, Version};

/// Self-signed (root) X.509 certificates. Self-signed certificates may
/// not be imported (except in test code), and so must be included here.
pub const ROOT_CERTS: &[&[u8]] = &[
    //include_bytes!("../certs/root.der"),
    include_bytes!("../../../permission-slip/sush.crt"),
];

/// What went wrong handling a key, signature, or certificate.
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
    #[error(transparent)]
    Pem(#[from] pem_rfc7468::Error),
    #[error("can't import a self-signed (root) certificate")]
    SelfSigned,
    #[error("error while signing: {0}")]
    Signer(String),
}

/// Upper half of the SHA-256 of a certificate subject,
/// encoded with base64 for storage and transport.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd)]
pub struct KeyId(#[schemars(with = "String")] [u8; 16]);

impl KeyId {
    pub fn as_slice(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64.encode(self.0))
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

impl TryFrom<&Certificate> for KeyId {
    type Error = CertError;

    fn try_from(cert: &Certificate) -> Result<KeyId, Self::Error> {
        Self::try_from(&cert.tbs_certificate.subject)
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

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64.encode(&self.0))
    }
}

impl FromStr for Signature {
    type Err = CertError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(BASE64.decode(s)?))
    }
}

impl_to_from_sql_and_serde!(Signature);

impl Signature {
    pub fn verify(&self, message: &[u8], cert: &Certificate) -> Result<(), CertError> {
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let public_key_bytes = spki.subject_public_key.raw_bytes();
        match &spki.algorithm {
            AlgorithmIdentifier {
                oid: ID_ED_25519,
                parameters: None,
            } => {
                let signature = Ed25519Signature::from_slice(&self.0)?;
                let public_key = Ed25519VerifyingKey::from_bytes(
                    &public_key_bytes
                        .try_into()
                        .map_err(|_| CertError::InvalidPublicKey)?,
                )?;
                public_key.verify(message, &signature)?;
            }
            AlgorithmIdentifier {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(parameters),
            } if *parameters == SECP_256_R_1.into() => {
                let signature = ecdsa::Signature::from_bytes(self.0.as_slice().into())?;
                let public_key = ecdsa::VerifyingKey::from_sec1_bytes(public_key_bytes)?;
                public_key.verify(message, &signature)?;
            }
            _ => return Err(CertError::InvalidPublicKey),
        }
        Ok(())
    }
}

/// Produce a signature.
#[allow(async_fn_in_trait)]
pub trait Signer {
    type Error: std::fmt::Display;

    async fn key_id(&self) -> Result<KeyId, Self::Error>;
    async fn signature_algorithm(&self) -> Result<AlgorithmIdentifierOwned, Self::Error>;
    async fn sign<T: ToBeSigned>(&self, thing: T) -> Result<Signed<T>, Self::Error>;
}

/// Some data or a hash to be signed with a particular key.
pub trait ToBeSigned {
    fn to_be_signed(&self, key_id: &KeyId) -> Vec<u8>;
}

impl<T: AsRef<[u8]>> ToBeSigned for T {
    /// Trivial transformation for raw bytes.
    fn to_be_signed(&self, _key_id: &KeyId) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

/// A signed envelope around some data.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct Signed<T> {
    payload: T,
    key_id: KeyId,
    signature: Signature,
}

impl<T> Signed<T> {
    pub fn new(payload: T, key_id: KeyId, signature: Signature) -> Self {
        Self {
            payload,
            key_id,
            signature,
        }
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl<T> Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl<T: ToBeSigned> Signed<T> {
    pub fn verify(self, cert: &Certificate) -> Result<Verified<T>, CertError> {
        let tbs = self.to_be_signed(&self.key_id);
        self.signature.verify(&tbs, cert)?;
        Ok(Verified {
            signed: self,
            verified_by: KeyId::try_from(cert)?,
        })
    }
}

/// An envelope whose signature has been verified.
#[derive(Clone, Debug)]
pub struct Verified<T> {
    signed: Signed<T>,
    verified_by: KeyId,
}

impl<T> Verified<T> {
    pub fn verified_by(&self) -> KeyId {
        self.verified_by
    }
}

impl<T> Deref for Verified<T> {
    type Target = Signed<T>;

    fn deref(&self) -> &Self::Target {
        &self.signed
    }
}

/// Supported signing key types.
#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    /// EdDSA signatures over djb's Curve25519.
    Ed25519,

    /// ECDSA signatures over the NIST P-256 curve.
    P256,
}

/// A in-memory-only signing (a.k.a. private, secret) key.
enum SigningKey {
    Ed25519(Ed25519SigningKey),
    P256(P256SecretKey),
}

impl SigningKey {
    /// Generate a random signing key.
    fn new(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => Self::Ed25519(Ed25519SigningKey::generate(&mut OsRng)),
            KeyType::P256 => Self::P256(P256SecretKey::random(&mut OsRng)),
        }
    }

    fn sign(&self, message: &[u8]) -> Signature {
        match self {
            Self::Ed25519(key) => Signature::new(key.sign(message).to_vec()),
            Self::P256(key) => {
                let sig: ecdsa::Signature = ecdsa::SigningKey::from(key).sign(message);
                Signature::new(sig.to_vec())
            }
        }
    }

    fn algorithm_id(&self) -> AlgorithmIdentifierOwned {
        match self {
            Self::Ed25519(_) => AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            },
            Self::P256(_) => AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some((&SECP_256_R_1).into()),
            },
        }
    }

    fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
        match self {
            Self::Ed25519(_) => self.algorithm_id(),
            Self::P256(_) => AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
        }
    }

    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.verifying_key().as_bytes().to_vec(),
            Self::P256(key) => key.public_key().to_sec1_bytes().to_vec(),
        }
    }

    fn spki(&self) -> SubjectPublicKeyInfo<Any, BitString> {
        SubjectPublicKeyInfo {
            algorithm: self.algorithm_id(),
            subject_public_key: BitString::from_bytes(&self.public_key()).unwrap(),
        }
    }
}

/// An in-memory-only signing key with certification.
pub struct EphemeralKey {
    key: SigningKey,
    key_id: KeyId,
    cert: Certificate,
}

impl EphemeralKey {
    /// **For tests only:** Ephemeral root key with self-signed cert.
    pub fn new_root(
        key_type: KeyType,
        subject: Name,
        validity: Validity,
    ) -> Result<Self, CertError> {
        let key = SigningKey::new(key_type);
        let cert = Self::self_signed_cert(&key, subject, validity)?;
        let subject = cert.tbs_certificate.subject.to_owned();
        let key_id = KeyId::try_from(&subject)?;
        let signature = Signature::new(cert.signature.raw_bytes().to_vec());
        signature.verify(&cert.tbs_certificate.to_der()?, &cert)?;
        Ok(Self { key, key_id, cert })
    }

    /// Ephemeral key with cert signed by a parent.
    pub async fn new_child<S: Signer>(
        key_type: KeyType,
        subject: Name,
        issuer: Name,
        validity: Validity,
        signer: &S,
    ) -> Result<Self, CertError> {
        let key = SigningKey::new(key_type);
        let key_id = KeyId::try_from(&subject)?;
        let tbs_certificate = Self::tbs_certificate(
            &key,
            Self::generate_serial_number()?,
            subject.to_owned(),
            issuer.to_owned(),
            validity,
        );
        let cert = Self::sign_cert(tbs_certificate, signer)
            .await
            .map_err(|e| CertError::Signer(e.to_string()))?;
        Ok(Self { key, key_id, cert })
    }

    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub fn subject(&self) -> Name {
        self.cert.tbs_certificate.subject.clone()
    }

    fn generate_serial_number() -> Result<SerialNumber, CertError> {
        let mut buf = [0; 16];
        OsRng.fill_bytes(&mut buf);
        Ok(SerialNumber::new(&buf)?)
    }

    fn tbs_certificate(
        key: &SigningKey,
        serial_number: SerialNumber,
        subject: Name,
        issuer: Name,
        validity: Validity,
    ) -> TbsCertificate {
        TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: key.signature_algorithm(),
            issuer,
            validity,
            subject,
            subject_public_key_info: key.spki(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        }
    }

    fn self_signed_cert(
        key: &SigningKey,
        subject: Name,
        validity: Validity,
    ) -> Result<Certificate, CertError> {
        let tbs_certificate = Self::tbs_certificate(
            key,
            Self::generate_serial_number()?,
            subject.clone(),
            subject,
            validity,
        );
        let signature = key.sign(&tbs_certificate.to_der()?);
        Ok(Certificate {
            tbs_certificate,
            signature_algorithm: key.signature_algorithm(),
            signature: BitString::from_bytes(signature.as_slice())?,
        })
    }

    async fn sign_cert<S: Signer>(
        tbs_certificate: TbsCertificate,
        signer: &S,
    ) -> Result<Certificate, CertError> {
        let tbs = tbs_certificate.to_der()?;
        let signature_algorithm = signer
            .signature_algorithm()
            .await
            .map_err(|e| CertError::Signer(e.to_string()))?;
        let signature = signer
            .sign(&tbs)
            .await
            .map_err(|e| CertError::Signer(e.to_string()))?
            .signature;
        Ok(Certificate {
            tbs_certificate,
            signature_algorithm,
            signature: BitString::from_bytes(signature.as_slice())?,
        })
    }
}

impl Signer for EphemeralKey {
    type Error = CertError;

    async fn key_id(&self) -> Result<KeyId, Self::Error> {
        Ok(self.key_id)
    }

    async fn sign<T: ToBeSigned>(&self, what: T) -> Result<Signed<T>, Self::Error> {
        let key_id = self.key_id().await?;
        let signature = self.key.sign(&what.to_be_signed(&key_id));
        Ok(Signed::new(what, key_id, signature))
    }

    async fn signature_algorithm(&self) -> Result<AlgorithmIdentifierOwned, Self::Error> {
        Ok(self.key.signature_algorithm())
    }
}

/// Encode a vector of certs as PEM and join them on newline for transport.
pub fn pem_cert_chain(certs: Vec<Certificate>) -> Result<String, CertError> {
    Ok(certs
        .into_iter()
        .map(|cert| cert.to_der())
        .collect::<Result<Vec<Vec<u8>>, _>>()?
        .into_iter()
        .map(|cert| pem_encode(Certificate::PEM_LABEL, LineEnding::LF, &cert))
        .collect::<Result<Vec<String>, _>>()?
        .join("\n"))
}
