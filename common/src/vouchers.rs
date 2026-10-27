// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A *voucher* is an RoT signature over an ephemeral key,
//! embedded in that key's self-signed certificate; see
//! RFD&nbsp;620 §4.6.2.1.

use x509_cert::der::Encode as _;
use x509_cert::der::asn1::{Any, BitString};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::spki::SubjectPublicKeyInfo;

use crate::hash::Hasher;
use crate::keys::KeyError;

#[cfg(feature = "verify-vouchers")]
pub use verify::verify_voucher;

/// A signature in a trenchcoat. Allocated in OANA.
pub const VOUCHER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57551.3.1");

/// What a vouched key is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoucherRole {
    /// A proxy TLS key, for securing client connections.
    Proxy,

    /// A sush server key, for signing login receipts.
    Server,
}

impl VoucherRole {
    /// Domain separation for [`voucher_digest`]. Each role has its own
    /// tag, so a voucher for one role's key never verifies for another.
    /// The tags are ASCII, so a preimage never collides with a DER
    /// certificate, which begins `0x30`.
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Proxy => b"sush-proxy-voucher-v0:",
            Self::Server => b"sush-server-voucher-v0:",
        }
    }
}

/// Compute the SHA-3 digest the RoT signs to make a voucher for a key.
/// We must use only its public key info, because it is to be embedded
/// in a self-signed certificate.
pub fn voucher_digest(
    role: VoucherRole,
    spki: &SubjectPublicKeyInfo<Any, BitString>,
) -> Result<[u8; 32], KeyError> {
    let mut hasher = Hasher::new();
    hasher.update(role.tag());
    hasher.update(&spki.to_der()?);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(feature = "verify-vouchers")]
mod verify {
    use attest_data::{DICE_TCB_INFO, DiceTcbInfo};
    use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
    use x509_cert::Certificate;
    use x509_cert::der::Decode as _;
    use x509_cert::ext::pkix::BasicConstraints;

    use super::{VOUCHER_OID, VoucherRole, voucher_digest};
    use crate::keys::KeyError;

    /// Verify that `cert` carries a valid voucher for `role` from `platform`.
    /// Vouchers are encoded as a [`VOUCHER_OID`] extension with a signature
    /// over [`voucher_digest`]. The caller must verify `platform` itself
    /// against the platform roots.
    pub fn verify_voucher(
        role: VoucherRole,
        cert: &Certificate,
        platform: &Certificate,
    ) -> Result<(), KeyError> {
        verify_vouching_cert(platform)?;
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
                return Err(KeyError::UnknownCriticalExtension(extension.extn_id));
            }
        }
        let voucher = voucher.ok_or(KeyError::MissingVoucher)?;
        let digest = voucher_digest(role, &cert.tbs_certificate.subject_public_key_info)?;
        let signature = Ed25519Signature::from_slice(voucher)?;
        spki_ed25519_key(platform)?.verify_strict(&digest, &signature)?;
        Ok(())
    }

    /// Verify that a platform identity cert may vouch for a key. Any cert
    /// that chains to a platform root is a platform identity cert,
    /// including the CAs above the Trust Quorum cert, but only the RoT may
    /// sign a voucher. We check that the vouching cert is *not* a CA but
    /// *does* contain a plausible DICE TCB info constraint.
    fn verify_vouching_cert(platform: &Certificate) -> Result<(), KeyError> {
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
            _ => Err(KeyError::NotVouchingCert),
        }
    }

    /// The Ed25519 key in a certificate's SPKI.
    fn spki_ed25519_key(cert: &Certificate) -> Result<Ed25519VerifyingKey, KeyError> {
        let key: [u8; 32] = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .try_into()
            .map_err(|_| KeyError::InvalidPublicKey)?;
        Ok(Ed25519VerifyingKey::from_bytes(&key)?)
    }

    #[cfg(test)]
    mod test {
        use super::*;

        /// The DICE TCB info extension from hubris's trust-quorum-dhe
        /// cert template (lib/dice/src/trust_quorum_dhe_cert_tmpl.rs)
        /// decodes as the type the voucher check requires.
        #[test]
        fn voucher_check_reads_hubris_tcb_info() {
            let mut extn_value = vec![
                0x30, 0x31, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                0x04, 0x02, 0x08, 0x04, 0x20,
            ];
            extn_value.extend([0; 32]);
            let tcb_info = DiceTcbInfo::from_der(&extn_value).unwrap();
            assert_eq!(tcb_info.fwids.unwrap().len(), 1);
        }
    }
}

#[cfg(test)]
mod test {
    use x509_cert::der::oid::db::rfc8410::ID_ED_25519;
    use x509_cert::spki::AlgorithmIdentifierOwned;

    use super::*;

    /// The voucher digest is a convention shared with the
    /// signatures on deployed proxy certificates. If this
    /// fails, STOP: existing vouchers would no longer verify.
    #[test]
    fn pin_voucher_digest() {
        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&[0x42; 32]).unwrap(),
        };
        assert_eq!(
            voucher_digest(VoucherRole::Proxy, &spki).unwrap(),
            [
                0x3c, 0x39, 0xf5, 0x94, 0x94, 0xa7, 0x6c, 0xe4, 0x37, 0x01, 0x97, 0xa3, 0xfc, 0xbd,
                0xf1, 0x28, 0x52, 0x3f, 0x87, 0x0b, 0x07, 0xf2, 0x44, 0x99, 0xcf, 0xf0, 0xdb, 0x14,
                0x97, 0x03, 0xa6, 0xeb,
            ],
        );
        assert_ne!(
            voucher_digest(VoucherRole::Server, &spki).unwrap(),
            voucher_digest(VoucherRole::Proxy, &spki).unwrap(),
        );
    }
}
