// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SSH key based identities for login and request attribution.

use std::num::NonZeroUsize;

use chrono::Utc;
use lru::LruCache;
use slog::{Logger, error, info};

use sush_common::authn::{Identity, Nonce, RequestVerifier, SignedLogin};
use sush_common::keys::{KeyError, KeyId, SshPublicKey};

use crate::messages::v0::IdentityRequest;

/// Maximum number of registered identities.
const MAX_REGISTERED_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// A rack-wide record of a verified login.
#[derive(Clone, Debug)]
pub struct RegisteredIdentity {
    pub identity: Identity,
    pub verifier: RequestVerifier,
}

#[derive(Debug)]
pub struct Identities {
    /// Verified logins, rack-wide.
    identities: LruCache<(KeyId, Nonce), RegisteredIdentity>,
}

impl Identities {
    pub fn new() -> Self {
        Self {
            identities: LruCache::new(MAX_REGISTERED_IDENTITIES),
        }
    }

    pub fn registered_identity(&self, key: &(KeyId, Nonce)) -> Option<&RegisteredIdentity> {
        self.identities.peek(key)
    }

    pub fn apply(&mut self, log: &Logger, request: &IdentityRequest) {
        match request {
            IdentityRequest::Login(openssh, signed) => {
                match SshPublicKey::from_openssh(openssh)
                    .and_then(|public_key| verify_login(&public_key, signed))
                {
                    Ok(registered) => {
                        let identity = &registered.identity;
                        info!(log, "registered identity"; "key_id" => %identity.key_id);
                        let key = (identity.key_id.clone(), identity.nonce.clone());
                        self.identities.put(key, registered);
                    }
                    Err(error) => {
                        error!(log, "ignoring invalid login"; "error" => %error);
                    }
                }
            }
        }
    }
}

impl Default for Identities {
    fn default() -> Self {
        Self::new()
    }
}

/// Locally verify gossiped login evidence.
fn verify_login(
    public_key: &SshPublicKey,
    signed: &SignedLogin,
) -> Result<RegisteredIdentity, KeyError> {
    let verified = signed.clone().verify_with_ssh_public_key(public_key)?;
    let verifier = verified.epk().clone();
    let identity = Identity::new(public_key.clone(), verified, Utc::now())?;
    Ok(RegisteredIdentity { identity, verifier })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use slog::{Discard, o};
    use x509_cert::time::Validity;

    use sush_common::authn::{Challenge, ChallengeResponse, RequestKey};
    use sush_common::keys::{EphemeralKey, KeyType, Signer as _};

    use super::*;

    fn log() -> Logger {
        Logger::root(Discard, o!())
    }

    fn key(name: &str) -> EphemeralKey {
        let subject = format!("CN={name},O=Oxide Computer Company,C=US");
        let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
        EphemeralKey::new_root(KeyType::P256, subject.parse().unwrap(), validity).unwrap()
    }

    fn key_id(key: &EphemeralKey) -> KeyId {
        key.ssh_public_key().key_id().unwrap()
    }

    async fn login(key: &mut EphemeralKey) -> (Nonce, IdentityRequest) {
        let nonce = Nonce::random();
        let challenge = Challenge::new(nonce.clone());
        let response = ChallengeResponse::new(challenge, RequestKey::new().verifier());
        let signed = key.sign(response).await.unwrap();
        let openssh = key.ssh_public_key().to_openssh().unwrap();
        (nonce, IdentityRequest::Login(openssh, signed))
    }

    #[tokio::test]
    async fn login_registers_identity() {
        let mut key = key("Operator");
        let mut identities = Identities::new();
        let (nonce, request) = login(&mut key).await;
        identities.apply(&log(), &request);
        assert!(
            identities
                .registered_identity(&(key_id(&key), nonce))
                .is_some()
        );
    }

    #[tokio::test]
    async fn hostile_logins_ignored() {
        let mut signer = key("Signer");
        let bystander = key("Bystander");
        let mut identities = Identities::new();
        let (nonce, request) = login(&mut signer).await;
        let IdentityRequest::Login(_, signed) = &request;
        let forged = IdentityRequest::Login(
            bystander.ssh_public_key().to_openssh().unwrap(),
            signed.clone(),
        );
        identities.apply(&log(), &forged);
        identities.apply(
            &log(),
            &IdentityRequest::Login("junk".into(), signed.clone()),
        );
        for key in [key_id(&signer), key_id(&bystander)] {
            assert!(
                identities
                    .registered_identity(&(key, nonce.clone()))
                    .is_none()
            );
        }
    }
}
