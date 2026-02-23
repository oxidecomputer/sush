//! Key, signature, and X.509 certificate management.

use std::convert::Infallible;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use crypto_bigint::{ArrayEncoding as _, Random as _, U128, U256};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey, Verifier as _,
    VerifyingKey as Ed25519VerifyingKey,
};
use p256::{SecretKey as P256SecretKey, ecdsa};
use rand_core::OsRng;
use rusqlite::Error as SqlError;
use rusqlite::types::{FromSql, FromSqlError, ToSql, ToSqlOutput, ValueRef};
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
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfo};
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate, Version};

use crate::codephrases::{InvalidCodephrase, WORD_SEPARATOR, codephrase, decode_phrase, id_phrase};

/// What went wrong handling a key, signature, or certificate.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("DER encoding error: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("Ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),
    #[error(transparent)]
    InvalidCodephrase(#[from] InvalidCodephrase),
    #[error("invalid key ID")]
    InvalidKeyId,
    #[error("invalid subject public key")]
    InvalidPublicKey,
    #[error("invalid public key algorithm")]
    InvalidPublicKeyAlgorithm,
    #[error("invalid signature")]
    InvalidSignature,
    #[error(transparent)]
    Pem(#[from] pem_rfc7468::Error),
    #[error("can't import a self-signed (root) certificate")]
    SelfSigned,
    #[error("error while signing: {0}")]
    Signer(String),
}

impl CertError {
    fn signer(error: impl std::fmt::Display) -> Self {
        Self::Signer(error.to_string())
    }
}

/// SHA-256 of a certificate subject, encoded as a pseudo-random
/// code phrase for storage and transport.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct KeyId(String);

impl Deref for KeyId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for KeyId {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl From<&Self> for KeyId {
    fn from(other: &Self) -> Self {
        other.to_owned()
    }
}

impl TryFrom<&Name> for KeyId {
    type Error = CertError;

    fn try_from(name: &Name) -> Result<KeyId, Self::Error> {
        let hash = Sha256::digest(&name.to_der()?);
        let phrase = id_phrase(U256::from_be_slice(hash.as_slice()));
        Ok(KeyId(phrase.join(WORD_SEPARATOR)))
    }
}

impl TryFrom<&Certificate> for KeyId {
    type Error = CertError;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        Self::try_from(&cert.tbs_certificate.subject)
    }
}

impl FromSql for KeyId {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        Ok(Self(value.as_str()?.to_string()))
    }
}

impl ToSql for KeyId {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>, SqlError> {
        Ok(ToSqlOutput::from(self.0.clone()))
    }
}

/// Code phrase encoded signature.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EncodedSignature {
    r: String,
    s: String,
}

impl EncodedSignature {
    fn decode(
        &self,
        signature_algorithm: &AlgorithmIdentifierOwned,
    ) -> Result<Signature, CertError> {
        // Currently assumes all (r, s) values are 256 bits.
        // If we introduce longer signature variants later,
        // this code will need to change slightly.
        let Self { r, s } = self;
        let r = decode_phrase(r)?.to_be_byte_array();
        let s = decode_phrase(s)?.to_be_byte_array();
        match signature_algorithm {
            AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            } => Ok(Signature::EcdsaSha256(ecdsa::Signature::from_scalars(
                r, s,
            )?)),
            AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            } => Ok(Signature::Ed25519(Ed25519Signature::from_components(
                r.into(),
                s.into(),
            ))),
            _ => Err(CertError::InvalidPublicKeyAlgorithm),
        }
    }
}

// Use JSON to encode signature (r, s) values. Keeps the database
// consistent with the wire protocol, but we might regret it later.

impl FromSql for EncodedSignature {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        serde_json::from_str(value.as_str()?).map_err(FromSqlError::other)
    }
}

impl ToSql for EncodedSignature {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>, SqlError> {
        Ok(ToSqlOutput::from(
            serde_json::to_string(self).map_err(FromSqlError::other)?,
        ))
    }
}

/// Decoded digital signature.
#[derive(Debug)]
pub enum Signature {
    EcdsaSha256(ecdsa::Signature),
    Ed25519(Ed25519Signature),
}

impl Signature {
    pub fn to_bit_string(&self) -> Result<BitString, CertError> {
        match self {
            Self::EcdsaSha256(signature) => Ok(BitString::from_bytes(
                signature.to_der().to_bytes().as_ref(),
            )?),
            Self::Ed25519(signature) => Ok(BitString::from_bytes(signature.to_bytes().as_slice())?),
        }
    }

    pub fn encode(&self) -> EncodedSignature {
        let codephrase = |x: U256| codephrase(x).join(WORD_SEPARATOR);
        match self {
            Self::EcdsaSha256(signature) => EncodedSignature {
                r: codephrase(U256::from_be_byte_array(signature.r().to_bytes())),
                s: codephrase(U256::from_be_byte_array(signature.s().to_bytes())),
            },
            Self::Ed25519(signature) => EncodedSignature {
                r: codephrase(U256::from_be_slice(signature.r_bytes())),
                s: codephrase(U256::from_be_slice(signature.s_bytes())),
            },
        }
    }

    pub fn verify(
        &self,
        message: &[u8],
        spki: &SubjectPublicKeyInfo<Any, BitString>,
    ) -> Result<(), CertError> {
        let public_key_bytes = spki.subject_public_key.raw_bytes();
        match self {
            Self::EcdsaSha256(signature) => {
                let public_key = ecdsa::VerifyingKey::from_sec1_bytes(public_key_bytes)?;
                public_key.verify(message, signature)?;
            }
            Self::Ed25519(signature) => {
                let public_key = Ed25519VerifyingKey::from_bytes(
                    &public_key_bytes
                        .try_into()
                        .map_err(|_| CertError::InvalidPublicKey)?,
                )?;
                public_key.verify(message, signature)?;
            }
        }
        Ok(())
    }
}

/// Extract the signature on a certificate.
impl TryFrom<&Certificate> for Signature {
    type Error = CertError;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        if cert.signature_algorithm != cert.tbs_certificate.signature {
            return Err(Self::Error::InvalidSignature);
        }

        let signature = cert.signature.raw_bytes();
        match cert.signature_algorithm {
            AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            } => Ok(Self::EcdsaSha256(ecdsa::Signature::from_der(signature)?)),
            AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            } => Ok(Self::Ed25519(Ed25519Signature::from_slice(signature)?)),
            _ => Err(Self::Error::InvalidSignature),
        }
    }
}

/// Produce a verifiable signature.
#[allow(async_fn_in_trait)]
pub trait Signer {
    type Error: std::fmt::Display;

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
    signature: EncodedSignature,
}

impl<T> Signed<T> {
    pub fn new(payload: T, key_id: KeyId, signature: EncodedSignature) -> Self {
        Self {
            payload,
            key_id,
            signature,
        }
    }

    pub fn into_payload(self) -> T {
        self.payload
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn signature(&self) -> &EncodedSignature {
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
    /// Verify that the signature on a payload was produced by the private key
    /// corresponding to the subject of `cert`.
    pub fn verify(self, cert: &Certificate) -> Result<Verified<T>, CertError> {
        let spki = &cert.tbs_certificate.subject_public_key_info;
        self.signature
            .decode(&Self::signature_algorithm_from_spki(&spki.algorithm)?)?
            .verify(&self.to_be_signed(&self.key_id), spki)?;
        Ok(Verified {
            signed: self,
            verified_by: KeyId::try_from(cert)?,
        })
    }

    /// Derive a signature algorithm from the subject public key algorithm.
    /// This mapping must be fixed and one-to-one.
    pub fn signature_algorithm_from_spki(
        algorithm_id: &AlgorithmIdentifierOwned,
    ) -> Result<AlgorithmIdentifierOwned, CertError> {
        match algorithm_id {
            AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            } => Ok(algorithm_id.to_owned()),
            AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(parameters),
            } if *parameters == (&SECP_256_R_1).into() => Ok(AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            }),
            _ => Err(CertError::InvalidPublicKeyAlgorithm),
        }
    }
}

/// An envelope whose signature has been verified.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct Verified<T> {
    signed: Signed<T>,
    verified_by: KeyId,
}

impl<T> Verified<T> {
    pub fn into_signed(self) -> Signed<T> {
        self.signed
    }

    pub fn verified_by(&self) -> &KeyId {
        &self.verified_by
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

    /// Sign a message with this key.
    fn sign(&self, message: &[u8]) -> Signature {
        match self {
            Self::Ed25519(key) => Signature::Ed25519(key.sign(message)),
            Self::P256(key) => Signature::EcdsaSha256(ecdsa::SigningKey::from(key).sign(message)),
        }
    }

    /// Identify the algorithm used for signatures with this key,
    /// i.e., what goes in the X.509 `signatureAlgorithm` and
    /// `TBSCertificate.signature` fields (which must match).
    fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
        match self {
            Self::Ed25519(_) => self.algorithm_id(),
            Self::P256(_) => AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
        }
    }

    /// Identify the algorithm used for the key itself, i.e., what
    /// goes in the X.509 `SubjectPublicKeyInfo.algorithm` field.
    /// For ECDSA keys this includes the curve ID as a parameter.
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

    /// Retrieve the public key associated with this signing key.
    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.verifying_key().as_bytes().to_vec(),
            Self::P256(key) => key.public_key().to_sec1_bytes().to_vec(),
        }
    }

    /// Build an X.509 `SubjectPublicKeyInfo` structure for this key.
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
        let signature = Signature::try_from(&cert)?;
        signature.verify(
            &cert.tbs_certificate.to_der()?,
            &cert.tbs_certificate.subject_public_key_info,
        )?;
        Ok(Self { key, key_id, cert })
    }

    /// Ephemeral key with cert signed by a parent.
    pub async fn new_child(
        key_type: KeyType,
        subject: Name,
        issuer: Name,
        validity: Validity,
        signer: &impl Signer,
        signature_algorithm: AlgorithmIdentifierOwned,
    ) -> Result<Self, CertError> {
        let key = SigningKey::new(key_type);
        let key_id = KeyId::try_from(&subject)?;
        let tbs_certificate = Self::tbs_certificate(
            &key,
            Self::generate_serial_number()?,
            signature_algorithm,
            subject.to_owned(),
            issuer.to_owned(),
            validity,
        );
        let cert = Self::sign_cert(tbs_certificate, signer)
            .await
            .map_err(|e| CertError::Signer(e.to_string()))?;
        Ok(Self { key, key_id, cert })
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
        self.key.signature_algorithm()
    }

    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub fn subject(&self) -> Name {
        self.cert.tbs_certificate.subject.clone()
    }

    fn generate_serial_number() -> Result<SerialNumber, CertError> {
        Ok(SerialNumber::new(
            &U128::random(&mut OsRng).to_be_byte_array(),
        )?)
    }

    fn tbs_certificate(
        key: &SigningKey,
        serial_number: SerialNumber,
        signature: AlgorithmIdentifierOwned,
        subject: Name,
        issuer: Name,
        validity: Validity,
    ) -> TbsCertificate {
        TbsCertificate {
            version: Version::V3,
            serial_number,
            signature,
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
        let signature_algorithm = key.signature_algorithm();
        let tbs_certificate = Self::tbs_certificate(
            key,
            Self::generate_serial_number()?,
            signature_algorithm.clone(),
            subject.clone(),
            subject,
            validity,
        );
        let signature = key.sign(&tbs_certificate.to_der()?).to_bit_string()?;
        Ok(Certificate {
            tbs_certificate,
            signature_algorithm,
            signature,
        })
    }

    async fn sign_cert(
        tbs_certificate: TbsCertificate,
        signer: &impl Signer,
    ) -> Result<Certificate, CertError> {
        let tbs = tbs_certificate.to_der()?;
        let signature_algorithm = tbs_certificate.signature.to_owned();
        let signature = signer
            .sign(&tbs)
            .await
            .map_err(CertError::signer)?
            .signature
            .decode(&signature_algorithm)?
            .to_bit_string()?;
        Ok(Certificate {
            tbs_certificate,
            signature_algorithm,
            signature,
        })
    }
}

impl Signer for EphemeralKey {
    type Error = CertError;

    async fn sign<T: ToBeSigned>(&self, what: T) -> Result<Signed<T>, Self::Error> {
        let key_id = self.key_id.clone();
        let signature = self.key.sign(&what.to_be_signed(&key_id));
        Ok(Signed::new(what, key_id, signature.encode()))
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
