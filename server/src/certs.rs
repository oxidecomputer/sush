// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! X.509 certificates for job signature validation.

use std::collections::BTreeMap;

use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_common::jobs::{SignedJob, VerifiedJob};
use sush_common::keys::{KeyError, KeyId, Signature};

/// Trust anchors for signed job request signatures.
/// Anchors may be roots or intermediates; intermediates
/// record the key ID of their issuers.
#[derive(Debug)]
pub struct Certificates {
    anchors: BTreeMap<KeyId, (Certificate, Option<KeyId>)>,
}

impl Certificates {
    /// `anchors` must be in root-to-leaf order. Fails if any anchor
    /// is malformed, a root's signature does not verify itself, or
    /// an intermediate's signature is not verified by a preceding
    /// anchor.
    pub fn new(anchors: &[Certificate]) -> Result<Self, KeyError> {
        let mut trusted: BTreeMap<KeyId, (Certificate, Option<KeyId>)> = BTreeMap::new();
        for cert in anchors {
            let key_id = KeyId::try_from(cert)?;
            let tbs = cert.tbs_certificate.to_der()?;
            let signature = Signature::try_from(cert)?;
            let parent_id = if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
                signature.verify_with_spki(&tbs, &cert.tbs_certificate.subject_public_key_info)?;
                None
            } else {
                let (parent_id, (parent, _)) = trusted
                    .iter()
                    .find(|(_, (parent, _))| {
                        parent.tbs_certificate.subject == cert.tbs_certificate.issuer
                    })
                    .ok_or_else(|| KeyError::UnanchoredCert(key_id.clone()))?;
                signature
                    .verify_with_spki(&tbs, &parent.tbs_certificate.subject_public_key_info)?;
                Some(parent_id.clone())
            };
            trusted.insert(key_id, (cert.clone(), parent_id));
        }
        Ok(Self { anchors: trusted })
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Return the cert chain for the given key in root-to-leaf order.
    pub fn chain(&self, key_id: &KeyId) -> Result<Vec<Certificate>, KeyError> {
        let mut chain = Vec::new();
        let mut next = Some(key_id.to_owned());
        while let Some(key_id) = next {
            let (cert, parent) = self
                .anchors
                .get(&key_id)
                .ok_or(KeyError::MissingCert(key_id))?;
            chain.push(cert.clone());
            next = parent.clone();
        }
        chain.reverse();
        Ok(chain)
    }

    /// Verify a job signature against its signing certificate.
    pub fn verify(&self, job: &SignedJob) -> Result<VerifiedJob, KeyError> {
        let (cert, _) = self
            .anchors
            .get(job.key_id())
            .ok_or_else(|| KeyError::MissingCert(job.key_id().to_owned()))?;
        job.clone().verify_with_cert(cert)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use x509_cert::time::Validity;

    use sush_common::keys::{EphemeralKey, KeyType};

    use super::*;

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

    #[test]
    fn anchors_verify_at_construction() {
        let root = root("anchor");
        let certs = Certificates::new(&[root.cert().clone()]).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs.chain(root.key_id()).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn intermediate_anchors_chain_to_their_roots() {
        let mut root = root("anchor");
        let intermediate = child(&mut root, "intermediate").await;
        let certs = Certificates::new(&[root.cert().clone(), intermediate.cert().clone()]).unwrap();
        assert_eq!(
            certs.chain(intermediate.key_id()).unwrap(),
            vec![root.cert().clone(), intermediate.cert().clone()]
        );
    }

    #[tokio::test]
    async fn leaf_to_root_order_is_refused() {
        let mut root = root("anchor");
        let intermediate = child(&mut root, "intermediate").await;
        assert!(matches!(
            Certificates::new(&[intermediate.cert().clone(), root.cert().clone()]),
            Err(KeyError::UnanchoredCert(_))
        ));
    }

    #[tokio::test]
    async fn orphan_intermediate_is_refused() {
        let mut absent = root("absent");
        let orphan = child(&mut absent, "orphan").await;
        assert!(matches!(
            Certificates::new(&[root("anchor").cert().clone(), orphan.cert().clone()]),
            Err(KeyError::UnanchoredCert(_))
        ));
    }

    #[tokio::test]
    async fn forged_intermediate_is_refused() {
        let anchor = root("anchor");
        let mut outsider = root("anchor"); // same subject, different key
        let forged = child(&mut outsider, "forged").await;
        assert!(Certificates::new(&[anchor.cert().clone(), forged.cert().clone()]).is_err());
    }

    #[test]
    fn unknown_key_has_no_chain() {
        let certs = Certificates::new(&[root("anchor").cert().clone()]).unwrap();
        let other = root("other");
        assert!(matches!(
            certs.chain(other.key_id()),
            Err(KeyError::MissingCert(_))
        ));
    }
}
