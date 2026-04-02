//! Key, signature, and certificate management.

// Handle raw SSH public keys, algorithms, and signatures.
#![allow(clippy::disallowed_types)]

use std::fmt;
use std::ops::Deref;

use bytes::{Buf as _, BufMut as _, BytesMut};
use crypto_bigint::{ArrayEncoding as _, Random as _, U128, U256};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use kms_agent_lib::protocol::{ProtocolError, SshBufReader as _, SshBufWriter as _};
use p256::{SecretKey as P256SecretKey, ecdsa};
use rand_core::OsRng;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{Error as SqlError, Result as SqlResult};
use schemars::schema::Schema;
use schemars::{JsonSchema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use signature::Verifier;
use ssh_key::{
    Algorithm as SshAlgorithm, EcdsaCurve, Error as SshKeyError, Signature as SshSignature,
};
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

/// SHA-256 of a certificate subject or an identity public key,
/// encoded as a pseudorandom code phrase for storage & transport.
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

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&Self> for KeyId {
    fn from(other: &Self) -> Self {
        other.to_owned()
    }
}

impl TryFrom<&Name> for KeyId {
    type Error = KeyError;

    fn try_from(name: &Name) -> Result<KeyId, Self::Error> {
        let hash = Sha256::digest(&name.to_der()?);
        let phrase = id_phrase(U256::from_be_slice(hash.as_slice()));
        Ok(KeyId(phrase.join(WORD_SEPARATOR)))
    }
}

impl TryFrom<&Certificate> for KeyId {
    type Error = KeyError;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        Self::try_from(&cert.tbs_certificate.subject)
    }
}

#[allow(clippy::disallowed_types)]
impl TryFrom<&ssh_key::PublicKey> for KeyId {
    type Error = KeyError;

    fn try_from(public_key: &ssh_key::PublicKey) -> Result<Self, Self::Error> {
        let hash = Sha256::digest(public_key.to_bytes()?);
        let phrase = id_phrase(U256::from_be_slice(hash.as_slice()));
        Ok(KeyId(phrase.join(WORD_SEPARATOR)))
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

/// A (de)serializable wrapper around [`ssh_key::PublicKey`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SshPublicKey(ssh_key::PublicKey);

impl SshPublicKey {
    pub fn key_id(&self) -> Result<KeyId, KeyError> {
        KeyId::try_from(&self.0)
    }

    pub fn is_acceptable_algorithm(&self) -> bool {
        use EcdsaCurve::*;
        use SshAlgorithm::*;
        matches!(
            self.algorithm(),
            Ecdsa { curve: NistP256 } | Ed25519 | SkEcdsaSha2NistP256 | SkEd25519
        )
    }

    pub fn is_sk_algorithm(&self) -> bool {
        use SshAlgorithm::*;
        matches!(self.algorithm(), SkEcdsaSha2NistP256 | SkEd25519)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), KeyError> {
        signature.verify_with_ssh_public_key(message, self)
    }

    pub fn into_inner(self) -> ssh_key::PublicKey {
        self.0
    }
}

impl From<ssh_key::PublicKey> for SshPublicKey {
    fn from(key: ssh_key::PublicKey) -> Self {
        Self(key)
    }
}

impl Deref for SshPublicKey {
    type Target = ssh_key::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromSql for SshPublicKey {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Ok(Self(
            ssh_key::PublicKey::from_openssh(value.as_str()?).map_err(FromSqlError::other)?,
        ))
    }
}

impl ToSql for SshPublicKey {
    fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(
            self.0.to_openssh().map_err(FromSqlError::other)?,
        ))
    }
}

impl JsonSchema for SshPublicKey {
    fn schema_name() -> String {
        <String as JsonSchema>::schema_name()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        <String as JsonSchema>::json_schema(generator)
    }

    fn is_referenceable() -> bool {
        <String as JsonSchema>::is_referenceable()
    }
}

/// Code phrase encoded signature.
///
/// The decoded phrases `r` and `s` together comprise a signature
/// _(r, s)_ over a 256 bit elliptic curve.
///
/// The `flags` and `counter` parameters are for the [`SK-*` family of SSH
/// public keys](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD).
/// They should be set to 0 for other key types.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct EncodedSignature {
    pub r: String,
    pub s: String,

    #[serde(default, skip_serializing_if = "is_zero_flags")]
    pub flags: u8,
    #[serde(default, skip_serializing_if = "is_zero_counter")]
    pub counter: u32,
}

fn is_zero_flags(flags: &u8) -> bool {
    *flags == 0
}

fn is_zero_counter(counter: &u32) -> bool {
    *counter == 0
}

impl EncodedSignature {
    fn decode_with_cert(
        &self,
        signature_algorithm: &AlgorithmIdentifierOwned,
    ) -> Result<Signature, KeyError> {
        // Currently assumes all (r, s) values are 256 bits.
        // If we introduce longer signature variants later,
        // this code will need to change slightly.
        let Self {
            r,
            s,
            flags: _,
            counter: _,
        } = self;
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
            _ => Err(KeyError::InvalidPublicKeyAlgorithm),
        }
    }

    fn decode_with_ssh_public_key(&self, algorithm: SshAlgorithm) -> Result<Signature, KeyError> {
        use EcdsaCurve::*;
        use SshAlgorithm::*;
        let Self {
            r,
            s,
            flags,
            counter,
        } = self;
        let r = decode_phrase(r)?.to_be_byte_array();
        let s = decode_phrase(s)?.to_be_byte_array();
        match algorithm {
            Ecdsa { curve: NistP256 } => Ok(Signature::EcdsaSha256(
                ecdsa::Signature::from_scalars(r, s)?,
            )),
            Ed25519 => Ok(Signature::Ed25519(Ed25519Signature::from_components(
                r.into(),
                s.into(),
            ))),
            SkEcdsaSha2NistP256 => {
                let mut bytes = BytesMut::new();
                bytes.put_mpint(r)?;
                bytes.put_mpint(s)?;
                bytes.put_u8(*flags);
                bytes.put_u32(*counter);
                Ok(Signature::SkEcdsaSha256(SshSignature::new(
                    algorithm,
                    bytes.freeze(),
                )?))
            }
            SkEd25519 => {
                let mut bytes = BytesMut::new();
                bytes.extend(r);
                bytes.extend(s);
                bytes.put_u8(*flags);
                bytes.put_u32(*counter);
                Ok(Signature::SkEd25519(SshSignature::new(
                    algorithm,
                    bytes.freeze(),
                )?))
            }
            _ => Err(KeyError::InvalidPublicKeyAlgorithm),
        }
    }
}

// Use JSON to encode signatures values for storage. Keeps the database
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
    SkEcdsaSha256(SshSignature),
    SkEd25519(SshSignature),
}

impl Signature {
    pub fn to_bit_string(&self) -> Result<BitString, KeyError> {
        match self {
            Self::EcdsaSha256(signature) => Ok(BitString::from_bytes(
                signature.to_der().to_bytes().as_ref(),
            )?),
            Self::Ed25519(signature) => Ok(BitString::from_bytes(signature.to_bytes().as_slice())?),
            Self::SkEcdsaSha256(_) | Self::SkEd25519(_) => Err(KeyError::InvalidSignatureAlgorithm),
        }
    }

    pub fn encode(&self) -> Result<EncodedSignature, KeyError> {
        let codephrase = |x: U256| codephrase(x).join(WORD_SEPARATOR);
        match self {
            Self::EcdsaSha256(signature) => Ok(EncodedSignature {
                r: codephrase(U256::from_be_byte_array(signature.r().to_bytes())),
                s: codephrase(U256::from_be_byte_array(signature.s().to_bytes())),
                flags: 0,
                counter: 0,
            }),
            Self::Ed25519(signature) => Ok(EncodedSignature {
                r: codephrase(U256::from_be_slice(signature.r_bytes())),
                s: codephrase(U256::from_be_slice(signature.s_bytes())),
                flags: 0,
                counter: 0,
            }),
            Self::SkEcdsaSha256(signature) => {
                let (signature, flags, counter) = sk_split(signature.as_bytes())?;
                let mut signature = BytesMut::from(signature);
                let r = signature.try_get_mpint()?;
                let s = signature.try_get_mpint()?;
                let e = || KeyError::InvalidSignatureEncoding;
                Ok(EncodedSignature {
                    r: codephrase(U256::from_be_slice(r.as_positive_bytes().ok_or_else(e)?)),
                    s: codephrase(U256::from_be_slice(s.as_positive_bytes().ok_or_else(e)?)),
                    flags,
                    counter,
                })
            }
            Self::SkEd25519(signature) => {
                let (signature, flags, counter) = sk_split(signature.as_bytes())?;
                let signature = Ed25519Signature::from_slice(signature)?;
                Ok(EncodedSignature {
                    r: codephrase(U256::from_be_slice(signature.r_bytes())),
                    s: codephrase(U256::from_be_slice(signature.s_bytes())),
                    flags,
                    counter,
                })
            }
        }
    }

    pub fn verify_with_spki(
        &self,
        message: &[u8],
        spki: &SubjectPublicKeyInfo<Any, BitString>,
    ) -> Result<(), KeyError> {
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
                        .map_err(|_| KeyError::InvalidPublicKey)?,
                )?;
                public_key.verify(message, signature)?;
            }
            Self::SkEcdsaSha256(_) | Self::SkEd25519(_) => {
                return Err(KeyError::InvalidSignatureAlgorithm);
            }
        }
        Ok(())
    }

    pub fn verify_with_ssh_public_key(
        &self,
        message: &[u8],
        public_key: &SshPublicKey,
    ) -> Result<(), KeyError> {
        match self {
            Self::EcdsaSha256(signature) => {
                Verifier::verify(&public_key.0, message, &signature.try_into()?)?;
            }
            Self::Ed25519(signature) => {
                let signature = SshSignature::new(SshAlgorithm::Ed25519, signature.to_bytes())?;
                Verifier::verify(&public_key.0, message, &signature)?;
            }
            Self::SkEcdsaSha256(signature) | Self::SkEd25519(signature) => {
                Verifier::verify(&public_key.0, message, signature)?;
            }
        }
        Ok(())
    }
}

/// Decode an `SK-*` signature into `(signature, flags, counter)`.
/// See <https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD>
fn sk_split(raw_signature: &[u8]) -> Result<(&[u8], u8, u32), KeyError> {
    const TRAILER_LEN: usize = 1 + 4;
    let n = raw_signature.len();
    if n < TRAILER_LEN {
        return Err(KeyError::SignatureTooShort);
    }
    let (signature, mut trailer) = raw_signature.split_at(n - TRAILER_LEN);
    let flags = trailer.get_u8();
    let counter = trailer.get_u32();
    assert!(trailer.is_empty(), "leftover trailer bytes");
    Ok((signature, flags, counter))
}

/// Extract the signature on a certificate.
impl TryFrom<&Certificate> for Signature {
    type Error = KeyError;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        if cert.signature_algorithm != cert.tbs_certificate.signature {
            return Err(Self::Error::InvalidSignatureAlgorithm);
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
            _ => Err(Self::Error::InvalidSignatureAlgorithm),
        }
    }
}

/// Translate from an SSH signature.
impl TryFrom<SshSignature> for Signature {
    type Error = KeyError;

    fn try_from(signature: SshSignature) -> Result<Self, Self::Error> {
        use EcdsaCurve::*;
        use SshAlgorithm::*;
        match signature.algorithm() {
            Ecdsa { curve: NistP256 } => Ok(Self::EcdsaSha256(signature.try_into()?)),
            Ed25519 => Ok(Self::Ed25519(signature.try_into()?)),
            SkEcdsaSha2NistP256 => Ok(Self::SkEcdsaSha256(signature.to_owned())),
            SkEd25519 => Ok(Self::SkEd25519(signature.to_owned())),
            _ => Err(Self::Error::InvalidSignatureAlgorithm),
        }
    }
}

/// Produce a verifiable signature.
#[allow(async_fn_in_trait)]
pub trait Signer {
    type Error: std::fmt::Display;

    async fn sign<T: ToBeSigned>(&mut self, thing: T) -> Result<Signed<T>, Self::Error>;
}

/// Some data or a hash to be signed.
pub trait ToBeSigned {
    fn to_be_signed(&self) -> Vec<u8>;
}

impl<T: AsRef<[u8]>> ToBeSigned for T {
    /// Trivial transformation for raw bytes.
    fn to_be_signed(&self) -> Vec<u8> {
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
    /// corresponding to the given SSH public key.
    pub fn verify_with_ssh_public_key(
        self,
        public_key: &SshPublicKey,
    ) -> Result<Verified<T>, KeyError> {
        self.signature
            .decode_with_ssh_public_key(public_key.algorithm())?
            .verify_with_ssh_public_key(&self.to_be_signed(), public_key)?;
        Ok(Verified {
            signed: self,
            verified_by: public_key.key_id()?,
        })
    }

    /// Verify that the signature on a payload was produced by the private key
    /// corresponding to the subject of `cert`.
    pub fn verify_with_cert(self, cert: &Certificate) -> Result<Verified<T>, KeyError> {
        let spki = &cert.tbs_certificate.subject_public_key_info;
        self.signature
            .decode_with_cert(&Self::signature_algorithm_from_spki(&spki.algorithm)?)?
            .verify_with_spki(&self.to_be_signed(), spki)?;
        Ok(Verified {
            signed: self,
            verified_by: KeyId::try_from(cert)?,
        })
    }

    /// Derive a signature algorithm from an SSH public key algorithm.
    /// This mapping must be one-to-one.
    pub fn signature_algorithm_from_ssh_public_key(
        public_key: &SshPublicKey,
    ) -> Result<AlgorithmIdentifierOwned, KeyError> {
        use EcdsaCurve::*;
        use SshAlgorithm::*;
        match public_key.algorithm() {
            Ecdsa { curve: NistP256 } | SkEcdsaSha2NistP256 => Ok(AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            }),
            Ed25519 | SkEd25519 => Ok(AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            }),
            _ => Err(KeyError::InvalidPublicKeyAlgorithm),
        }
    }

    /// Derive a signature algorithm from the subject public key algorithm.
    /// This mapping must be one-to-one.
    pub fn signature_algorithm_from_spki(
        algorithm_id: &AlgorithmIdentifierOwned,
    ) -> Result<AlgorithmIdentifierOwned, KeyError> {
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
            _ => Err(KeyError::InvalidPublicKeyAlgorithm),
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

    pub fn into_payload(self) -> T {
        self.into_signed().into_payload()
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
    ) -> Result<Self, KeyError> {
        let key = SigningKey::new(key_type);
        let cert = Self::self_signed_cert(&key, subject, validity)?;
        let subject = cert.tbs_certificate.subject.to_owned();
        let key_id = KeyId::try_from(&subject)?;
        let signature = Signature::try_from(&cert)?;
        signature.verify_with_spki(
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
        signer: &mut impl Signer,
        signature_algorithm: AlgorithmIdentifierOwned,
    ) -> Result<Self, KeyError> {
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
            .map_err(|e| KeyError::Signer(e.to_string()))?;
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

    fn generate_serial_number() -> Result<SerialNumber, KeyError> {
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
    ) -> Result<Certificate, KeyError> {
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
        signer: &mut impl Signer,
    ) -> Result<Certificate, KeyError> {
        let tbs = tbs_certificate.to_der()?;
        let signature_algorithm = tbs_certificate.signature.to_owned();
        let signature = signer
            .sign(&tbs)
            .await
            .map_err(KeyError::signer)?
            .signature
            .decode_with_cert(&signature_algorithm)?
            .to_bit_string()?;
        Ok(Certificate {
            tbs_certificate,
            signature_algorithm,
            signature,
        })
    }

    pub fn ssh_public_key(&self) -> SshPublicKey {
        use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey};
        match &self.key {
            SigningKey::Ed25519(key) => {
                SshPublicKey(Ed25519PublicKey::from(key.verifying_key()).into())
            }
            SigningKey::P256(key) => SshPublicKey(
                EcdsaPublicKey::from(ecdsa::VerifyingKey::from(key.public_key())).into(),
            ),
        }
    }
}

impl Signer for EphemeralKey {
    type Error = KeyError;

    async fn sign<T: ToBeSigned>(&mut self, what: T) -> Result<Signed<T>, Self::Error> {
        let signature = self.key.sign(&what.to_be_signed());
        Ok(Signed::new(what, self.key_id.clone(), signature.encode()?))
    }
}

/// Encode a vector of certs as PEM and join them on newline for transport.
pub fn pem_cert_chain(certs: Vec<Certificate>) -> Result<String, KeyError> {
    Ok(certs
        .into_iter()
        .map(|cert| cert.to_der())
        .collect::<Result<Vec<Vec<u8>>, _>>()?
        .into_iter()
        .map(|cert| pem_encode(Certificate::PEM_LABEL, LineEnding::LF, &cert))
        .collect::<Result<Vec<String>, _>>()?
        .join("\n"))
}

/// What went wrong handling a key, signature, or certificate.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("DER encoding error: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error(transparent)]
    InvalidCodephrase(#[from] InvalidCodephrase),
    #[error("Invalid key ID")]
    InvalidKeyId,
    #[error("Invalid subject public key")]
    InvalidPublicKey,
    #[error("Invalid public key algorithm")]
    InvalidPublicKeyAlgorithm,
    #[error("Invalid signature algorithm")]
    InvalidSignatureAlgorithm,
    #[error("Invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error(transparent)]
    Pem(#[from] pem_rfc7468::Error),
    #[error("SSH agent protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Will not import a self-signed (root) certificate")]
    SelfSigned,
    #[error("Signature error: {0}")]
    Signature(#[from] signature::Error),
    #[error("Invalid signature: too short")]
    SignatureTooShort,
    #[error("Signing error: {0}")]
    Signer(String),
    #[error("SSH key error: {0}")]
    SshKey(#[from] SshKeyError),
}

impl KeyError {
    fn signer(error: impl std::fmt::Display) -> Self {
        Self::Signer(error.to_string())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::time::Duration;

    use crate::authn::Nonce;

    use super::*;

    #[test]
    fn test_sk_split() {
        assert!(matches!(
            sk_split(b"").unwrap_err(),
            KeyError::SignatureTooShort
        ));
        assert!(matches!(
            sk_split(b"abcd").unwrap_err(),
            KeyError::SignatureTooShort
        ));
        assert!(matches!(
            sk_split(b"abcde").unwrap(),
            (&[], 0x61, 0x62_63_64_65)
        ));
        assert!(matches!(
            sk_split(b"sigabcde").unwrap(),
            (&[0x73, 0x69, 0x67], 0x61, 0x62_63_64_65)
        ));
    }

    #[tokio::test]
    async fn signing() {
        let mut key = EphemeralKey::new_root(
            KeyType::P256,
            String::from("CN=Ephemeral Test Signing Key,O=Oxide Computer Company,C=US")
                .parse()
                .unwrap(),
            Validity::from_now(Duration::from_secs(60)).unwrap(),
        )
        .unwrap();
        let mut signatures = HashSet::new();
        for _ in 0..100 {
            let nonce = Nonce::generate();
            let signed = key.sign(nonce.as_bytes()).await.unwrap();
            assert_eq!(signed.key_id(), key.key_id());
            assert_eq!(*signed.payload(), nonce.as_bytes());
            let signature = signed.signature();
            assert!(signatures.insert(signature.clone()), "duplicate signature");
            let signature_string = serde_json::to_string(&signature).unwrap();
            assert!(signature_string.starts_with("{\"r\":\""));
            assert!(signature_string.contains("\"s\":\""));
            assert!(signature_string.ends_with("\"}"));
            assert_eq!(
                serde_json::from_str::<EncodedSignature>(&signature_string).unwrap(),
                *signature
            );
            let verified = signed.verify_with_cert(key.cert()).unwrap();
            assert_eq!(verified.verified_by(), key.key_id());
            assert_eq!(verified.into_payload(), nonce.as_bytes());
        }
    }
}
