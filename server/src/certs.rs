// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! X.509 certificates for job signature validation.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use chrono::{DateTime, Utc};
use lru::LruCache;
use slog::{Logger, error, info};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};

use sush_common::keys::{KeyError, KeyId, Signature};

use crate::messages::v0::CertRequest;

/// Maximum certificate chain length.
const MAX_CERT_CHAIN_LEN: usize = 10;

/// Maximum number of job request signing certificates.
/// The ideal number of certs is 1, so this need not be large.
const MAX_CERTS: usize = 100;

/// Maximum number of revocations held for certificates not yet seen.
const MAX_TOMBSTONES: NonZeroUsize = NonZeroUsize::new(100).unwrap();

/// Certificate validation state. Transitions are monotone, so state only
/// moves upward in this lattice:
///
/// ```text
///              Revoked
///             ▲   ▲   ▲
///            /    |    \
///        Valid    |    Invalid
///            ▲    |    ▲
///             \   |   /
///              Unknown ──┐
///                  ▲     │ (issuer not yet seen)
///                  └─────┘
/// ```
///
/// Allowed transitions are `Unknown → Valid` on successful validation;
/// `Unknown → Unknown` while no valid issuer verifies the certificate;
/// `Unknown → Invalid` on a bad encoding or signature; and any state
/// `→ Revoked`, from which no state ever returns. Trust anchors are
/// born `Valid`.
#[derive(Debug)]
enum CertState {
    Unknown(Box<Certificate>),
    Valid(Box<Certificate>, Option<KeyId>),
    Invalid(KeyError),
    Revoked(KeyId, DateTime<Utc>),
}

impl CertState {
    fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    fn is_anchor(&self) -> bool {
        matches!(self, Self::Valid(_, None))
    }

    fn cert(&self) -> Option<&Certificate> {
        match self {
            Self::Unknown(cert) | Self::Valid(cert, _) => Some(cert),
            Self::Invalid(_) | Self::Revoked(..) => None,
        }
    }

    fn map_valid<R>(&self, f: impl FnOnce(&Certificate) -> &R) -> Option<&R> {
        if let Self::Valid(cert, _) = self {
            Some(f(cert))
        } else {
            None
        }
    }

    fn validate(self, certs: &BTreeMap<KeyId, CertState>) -> Self {
        if let Self::Unknown(cert) = self {
            macro_rules! with_err {
                ($expr:expr) => {
                    match $expr {
                        Ok(res) => res,
                        Err(err) => return Self::Invalid(err.into()),
                    }
                };
            }

            // Verify the certificate signature.
            // TODO: check expiry, basicConstraints, keyUsage.
            let signature = with_err!(Signature::try_from(cert.as_ref()));
            let tbs = with_err!(cert.tbs_certificate.to_der());
            let issuer = &cert.tbs_certificate.issuer;
            for (key_id, candidate) in certs {
                if let Some(parent) = candidate.map_valid(|cert| cert)
                    && parent.tbs_certificate.subject == *issuer
                    && let spki = &parent.tbs_certificate.subject_public_key_info
                    && signature.verify_with_spki(&tbs, spki).is_ok()
                {
                    return Self::Valid(cert, Some(key_id.clone()));
                }
            }
            Self::Unknown(cert)
        } else {
            self
        }
    }
}

#[derive(Debug)]
pub struct Certificates {
    /// Known certificates and their validation states.
    certs: BTreeMap<KeyId, CertState>,

    /// Revocations of certificates we have never seen. Stored
    /// apart from `certs` so revocation spam evicts only itself.
    tombstones: LruCache<KeyId, DateTime<Utc>>,
}

impl Certificates {
    /// Fails if any anchor is malformed or a self-signed anchor's
    /// signature does not verify.
    pub fn new(anchors: &[Certificate]) -> Result<Self, KeyError> {
        Ok(Self {
            certs: anchors
                .iter()
                .map(|cert| {
                    let subject = &cert.tbs_certificate.subject;
                    let issuer = &cert.tbs_certificate.issuer;
                    if subject == issuer {
                        // Verify root anchor self-signatures.
                        let tbs = cert.tbs_certificate.to_der()?;
                        let spki = &cert.tbs_certificate.subject_public_key_info;
                        let signature = Signature::try_from(cert)?;
                        signature.verify_with_spki(&tbs, spki)?;
                    } else {
                        // Trust intermediate anchors by fiat.
                    }
                    Ok((
                        KeyId::try_from(cert)?,
                        CertState::Valid(Box::new(cert.clone()), None),
                    ))
                })
                .collect::<Result<BTreeMap<KeyId, CertState>, KeyError>>()?,
            tombstones: LruCache::new(MAX_TOMBSTONES),
        })
    }

    pub fn is_anchor(&self, key_id: &KeyId) -> bool {
        self.certs.get(key_id).is_some_and(CertState::is_anchor)
    }

    pub fn revoked(&self, key_id: &KeyId) -> Option<DateTime<Utc>> {
        match self.certs.get(key_id) {
            Some(CertState::Revoked(_, when)) => Some(*when),
            _ => self.tombstones.peek(key_id).cloned(),
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Handle a certificate request.
    pub fn apply(&mut self, log: &Logger, request: &CertRequest) {
        match request {
            CertRequest::Import(der) => {
                match Certificate::from_der(der)
                    .map_err(KeyError::from)
                    .and_then(|cert| self.import(cert))
                {
                    Ok(key_id) => {
                        info!(log, "imported certificate"; "key_id" => %key_id);
                        self.validate();
                    }
                    Err(error) => {
                        error!(log, "ignoring invalid certificate"; "error" => %error);
                    }
                }
            }
            CertRequest::Revoke(key_id, when) => {
                if let Some(state) = self.certs.get_mut(key_id) {
                    if state.is_anchor() {
                        error!(log, "refusing to revoke trust anchor"; "key_id" => %key_id);
                    } else {
                        *state = CertState::Revoked(key_id.clone(), *when);
                        info!(log, "revoked known certificate"; "key_id" => %key_id);
                    }
                } else {
                    self.tombstones.put(key_id.clone(), *when);
                    info!(log, "revoked unknown certificate"; "key_id" => %key_id);
                }
            }
        }
    }

    /// Re-importing a certificate is a no-op; importing a self-signed,
    /// conflicting, or revoked cert is an error.
    pub fn check_import(&self, cert: &Certificate) -> Result<KeyId, KeyError> {
        if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
            return Err(KeyError::SelfSigned);
        }
        let key_id = KeyId::try_from(cert)?;
        if let Some(when) = self.revoked(&key_id) {
            return Err(KeyError::Revoked(key_id, when));
        }
        if let Some(existing) = self.certs.get(&key_id)
            && existing.cert() != Some(cert)
        {
            return Err(KeyError::CertConflict(key_id));
        }
        if self.len() >= MAX_CERTS {
            return Err(KeyError::TooManyCerts(MAX_CERTS));
        }
        Ok(key_id)
    }

    /// Import a certificate.
    fn import(&mut self, cert: Certificate) -> Result<KeyId, KeyError> {
        match self.check_import(&cert) {
            Err(KeyError::Revoked(key_id, when)) => {
                // A tombstone becomes a durable revocation once its certificate appears,
                // space permitting.
                if self.certs.len() < MAX_CERTS && self.tombstones.pop(&key_id).is_some() {
                    self.certs
                        .insert(key_id.clone(), CertState::Revoked(key_id.clone(), when));
                }
                Err(KeyError::Revoked(key_id, when))
            }
            Err(error) => Err(error),
            Ok(key_id) => {
                if !self.certs.contains_key(&key_id) {
                    self.certs
                        .insert(key_id.clone(), CertState::Unknown(Box::new(cert)));
                }
                Ok(key_id)
            }
        }
    }

    /// Return the cert chain for the given key in root-to-leaf order.
    /// Will never return an empty chain.
    pub fn chain(&self, key_id: &KeyId) -> Result<Vec<Certificate>, KeyError> {
        let mut chain = Vec::new();
        let mut key_id = key_id.to_owned();
        loop {
            if chain.len() >= MAX_CERT_CHAIN_LEN {
                return Err(KeyError::CertChainTooLong);
            }
            let (cert, parent) = match self.certs.get(&key_id) {
                None | Some(CertState::Unknown(_)) => return Err(KeyError::MissingCert(key_id)),
                Some(CertState::Valid(cert, parent)) => (*cert.clone(), parent.clone()),
                Some(CertState::Invalid(error)) => {
                    return Err(KeyError::InvalidCert(error.to_string()));
                }
                Some(CertState::Revoked(key_id, when)) => {
                    return Err(KeyError::Revoked(key_id.clone(), *when));
                }
            };
            chain.push(cert);
            match parent {
                None => break,
                Some(parent) => key_id = parent,
            }
        }
        assert!(!chain.is_empty());
        chain.reverse();
        Ok(chain)
    }

    /// Move as many certificates as possible from `Unknown → `Valid`.
    /// This allows us to eventually validate chains whose elements
    /// may arrive out of order.
    fn validate(&mut self) {
        loop {
            let mut progressed = false;
            let pending = self
                .certs
                .iter()
                .filter(|(_, s)| s.is_unknown())
                .map(|(k, _)| k.clone())
                .collect::<Vec<KeyId>>();
            for key_id in pending {
                let state = self.certs.remove(&key_id).unwrap();
                let validated = state.validate(&self.certs);
                progressed |= !validated.is_unknown();
                self.certs.insert(key_id, validated);
            }
            if !progressed {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use slog::{Discard, o};
    use x509_cert::der::asn1::BitString;
    use x509_cert::time::Validity;

    use sush_common::keys::{EphemeralKey, KeyType};

    use super::*;

    fn log() -> Logger {
        Logger::root(Discard, o!())
    }

    fn validity() -> Validity {
        Validity::from_now(Duration::from_secs(60)).unwrap()
    }

    fn root(name: &str) -> EphemeralKey {
        let subject = format!("CN={name},O=Oxide Computer Company,C=US");
        EphemeralKey::new_root(KeyType::P256, subject.parse().unwrap(), validity()).unwrap()
    }

    async fn child(parent: &mut EphemeralKey, name: &str) -> EphemeralKey {
        let subject = format!("CN={name},O=Oxide Computer Company,C=US");
        let issuer = parent.subject();
        let algorithm = parent.signature_algorithm();
        EphemeralKey::new_child(
            KeyType::Ed25519,
            subject.parse().unwrap(),
            issuer,
            validity(),
            parent,
            algorithm,
        )
        .await
        .unwrap()
    }

    fn corrupt(cert: &Certificate) -> Certificate {
        let mut bytes = cert.signature.raw_bytes().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        Certificate {
            signature: BitString::from_bytes(&bytes).unwrap(),
            ..cert.clone()
        }
    }

    fn import(certs: &mut Certificates, cert: &Certificate) {
        certs.apply(&log(), &CertRequest::Import(cert.to_der().unwrap()));
    }

    fn revoke(certs: &mut Certificates, key_id: &KeyId) {
        certs.apply(&log(), &CertRequest::Revoke(key_id.clone(), Utc::now()));
    }

    #[tokio::test]
    async fn anchors_are_trusted_by_fiat() {
        let mut offline = root("Offline Root");
        let intermediate = child(&mut offline, "Intermediate").await;
        let anchor = root("Root Anchor");
        let certs =
            Certificates::new(&[anchor.cert().clone(), intermediate.cert().clone()]).unwrap();
        for key in [anchor.key_id(), intermediate.key_id()] {
            assert!(certs.is_anchor(key));
        }
        assert_eq!(
            certs.chain(anchor.key_id()).unwrap(),
            vec![anchor.cert().clone()]
        );
        assert_eq!(
            certs.chain(intermediate.key_id()).unwrap(),
            vec![intermediate.cert().clone()]
        );
    }

    #[test]
    fn bad_anchor_refused_at_construction() {
        let anchor = root("Bad Root");
        assert!(Certificates::new(&[corrupt(anchor.cert())]).is_err());
    }

    #[tokio::test]
    async fn imports_chain_to_an_anchor() {
        let mut anchor = root("Root");
        let mut mid = child(&mut anchor, "Mid").await;
        let leaf = child(&mut mid, "Leaf").await;
        let mut certs = Certificates::new(&[anchor.cert().clone()]).unwrap();
        import(&mut certs, mid.cert());
        import(&mut certs, leaf.cert());
        assert_eq!(
            certs.chain(leaf.key_id()).unwrap(),
            vec![
                anchor.cert().clone(),
                mid.cert().clone(),
                leaf.cert().clone()
            ]
        );
        assert!(!certs.is_anchor(mid.key_id()));
        assert!(!certs.is_anchor(leaf.key_id()));
    }

    #[tokio::test]
    async fn validation_is_order_independent() {
        let mut anchor = root("Root");
        let mut mid = child(&mut anchor, "Mid").await;
        let leaf = child(&mut mid, "Leaf").await;
        let mut certs = Certificates::new(&[anchor.cert().clone()]).unwrap();
        import(&mut certs, leaf.cert());
        assert!(matches!(
            certs.chain(leaf.key_id()),
            Err(KeyError::MissingCert(_))
        ));
        import(&mut certs, mid.cert());
        assert_eq!(certs.chain(leaf.key_id()).unwrap().len(), 3);
    }

    #[tokio::test]
    async fn hostile_imports_refused() {
        let mut anchor = root("Root");
        let leaf = child(&mut anchor, "Leaf").await;
        let mut certs = Certificates::new(&[anchor.cert().clone()]).unwrap();
        let interloper = root("Interloper");
        assert!(matches!(
            certs.import(interloper.cert().clone()),
            Err(KeyError::SelfSigned)
        ));
        import(&mut certs, leaf.cert());
        certs.import(leaf.cert().clone()).unwrap();
        assert!(matches!(
            certs.import(corrupt(leaf.cert())),
            Err(KeyError::CertConflict(_))
        ));
        assert_eq!(certs.chain(leaf.key_id()).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn revocation_wins_and_anchors_survive() {
        let mut anchor = root("Root");
        let leaf = child(&mut anchor, "Leaf").await;
        let mut certs = Certificates::new(&[anchor.cert().clone()]).unwrap();
        import(&mut certs, leaf.cert());
        assert!(certs.chain(leaf.key_id()).is_ok());
        revoke(&mut certs, leaf.key_id());
        assert!(certs.revoked(leaf.key_id()).is_some());
        assert!(matches!(
            certs.chain(leaf.key_id()),
            Err(KeyError::Revoked(..))
        ));
        assert!(matches!(
            certs.import(leaf.cert().clone()),
            Err(KeyError::Revoked(..))
        ));
        revoke(&mut certs, anchor.key_id());
        assert!(certs.is_anchor(anchor.key_id()));
        assert!(certs.chain(anchor.key_id()).is_ok());
    }

    #[tokio::test]
    async fn tombstone_converts_on_import() {
        let mut anchor = root("Root");
        let leaf = child(&mut anchor, "Leaf").await;
        let mut certs = Certificates::new(&[anchor.cert().clone()]).unwrap();
        revoke(&mut certs, leaf.key_id());
        assert!(certs.revoked(leaf.key_id()).is_some());
        assert!(matches!(
            certs.chain(leaf.key_id()),
            Err(KeyError::MissingCert(_))
        ));
        assert!(matches!(
            certs.import(leaf.cert().clone()),
            Err(KeyError::Revoked(..))
        ));
        assert!(matches!(
            certs.chain(leaf.key_id()),
            Err(KeyError::Revoked(..))
        ));
    }
}
