// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Verify client identities. Servers don't check claimed identities;
//! they trust that we (the proxy) have performed this verification.
//! This trust is warranted by the fact that *anything* on the underlay
//! or bootstrap network is currently trusted, and in the future will
//! be authenticated via sprockets-backed mTLS.

use std::num::NonZeroUsize;
use std::time::Instant;

use chrono::Utc;
use lru::LruCache;
use slog::{Logger, debug, warn};
use thiserror::Error;
use tokio::sync::Mutex;

use sush_common::authn::{
    Authn, AuthnError, BoundCredentials, BoundRequest, Credentials, IDENTITY_IDLE_TTL,
    IDENTITY_MAX_TTL, Identity, NONCE_TTL, Nonce, RequestVerifier, SeqWindow,
};
use sush_common::keys::{KeyError, KeyId, SshPublicKey};

/// Maximum number of cached identities.
const MAX_CACHED_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// Maximum number of outstanding authentication nonces. Every failed
/// request mints one, so garbage traffic evicts real challenges. This
/// is sized so a flood must sustain hundreds of requests per second
/// for the whole nonce TTL to lock a user out.
const MAX_OUTSTANDING_NONCES: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// An authenticated identity and the state that authorizes its
/// requests: the ephemeral verifier, the spent sequence numbers, and
/// its lifetime, kept on the monotonic clock because the wall clock
/// may step by decades when NTP first syncs.
#[derive(Debug)]
struct CachedIdentity {
    identity: Identity,
    verifier: RequestVerifier,
    window: SeqWindow,
    authenticated: Instant,
    last_used: Instant,
}

impl CachedIdentity {
    fn is_still_valid(&self) -> bool {
        self.authenticated.elapsed() < IDENTITY_MAX_TTL
            && self.last_used.elapsed() < IDENTITY_IDLE_TTL
    }
}

/// A fresh challenge nonce in response to a denied request.
#[derive(Debug)]
pub struct Unauthorized(pub Nonce);

/// Why a login or a request was refused.
#[derive(Debug, Error)]
enum LoginError {
    #[error("missing authorization")]
    MissingAuthorization,
    #[error(transparent)]
    Authn(#[from] AuthnError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("bound credentials presented at login")]
    BoundAtLogin,
    #[error("initial credentials are only valid at login")]
    InitialOutsideLogin,
    #[error("nonce not found")]
    NonceNotFound,
    #[error("nonce expired")]
    NonceExpired,
    #[error("key ID does not match the public key")]
    KeyIdMismatch,
    #[error("not logged in")]
    NotLoggedIn,
    #[error("unknown identity")]
    UnknownIdentity,
    #[error("identity expired")]
    IdentityExpired,
    #[error("sequence number already spent")]
    SeqSpent,
}

/// Outstanding challenge nonces and logged-in identities.
/// NB: All tables must have a fixed maximum size!
#[derive(Debug)]
pub struct Logins {
    log: Logger,
    nonces: Mutex<LruCache<Nonce, Instant>>,
    identities: Mutex<LruCache<(KeyId, Nonce), CachedIdentity>>,
}

impl Logins {
    pub fn new(log: Logger) -> Self {
        Self {
            log,
            nonces: Mutex::new(LruCache::new(MAX_OUTSTANDING_NONCES)),
            identities: Mutex::new(LruCache::new(MAX_CACHED_IDENTITIES)),
        }
    }

    /// Authenticate initial credentials for `public_key`, and cache the
    /// identity they prove.
    pub async fn login(
        &self,
        authz: Option<&str>,
        public_key: SshPublicKey,
    ) -> Result<Identity, Unauthorized> {
        let result = self.verify_login(authz, public_key).await;
        self.refuse_failure(result).await
    }

    /// Authorize a bound request against a cached identity. `request`
    /// is the method and target exactly as received.
    pub async fn authorize(
        &self,
        authz: Option<&str>,
        request: (&str, &str),
    ) -> Result<Identity, Unauthorized> {
        let result = self.verify_request(authz, request).await;
        self.refuse_failure(result).await
    }

    /// Log why authentication failed, and answer with a fresh challenge.
    /// Every failure must come through here, so that the client can
    /// log in again.
    async fn refuse_failure<T>(&self, result: Result<T, LoginError>) -> Result<T, Unauthorized> {
        let error = match result {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        warn!(self.log, "authentication failed"; "error" => %error);
        let nonce = Nonce::random();
        self.nonces.lock().await.put(nonce.clone(), Instant::now());
        Err(Unauthorized(nonce))
    }

    async fn verify_login(
        &self,
        authz: Option<&str>,
        public_key: SshPublicKey,
    ) -> Result<Identity, LoginError> {
        let authz = authz.ok_or(LoginError::MissingAuthorization)?;
        let Authn::Initial(credentials) = authz.parse()? else {
            return Err(LoginError::BoundAtLogin);
        };
        let Credentials { key_id, nonce, .. } = *credentials.clone();

        // Claim the nonce.
        let minted = self
            .nonces
            .lock()
            .await
            .pop(&nonce)
            .ok_or(LoginError::NonceNotFound)?;
        if minted.elapsed() >= NONCE_TTL {
            return Err(LoginError::NonceExpired);
        }

        // Verify the supplied credentials.
        if public_key.key_id().ok() != Some(key_id.clone()) {
            return Err(LoginError::KeyIdMismatch);
        }
        let response = credentials.clone().into_challenge_response();
        let verified = response.verify_with_ssh_public_key(&public_key)?;
        let identity = Identity::new(public_key, verified, Utc::now())?;

        // Authenticated! Cache the identity and its request verifier.
        debug!(self.log, "authenticated credentials for identity"; "key_id" => %key_id);
        self.identities.lock().await.put(
            (key_id, nonce),
            CachedIdentity {
                identity: identity.clone(),
                verifier: credentials.epk,
                window: SeqWindow::default(),
                authenticated: Instant::now(),
                last_used: Instant::now(),
            },
        );
        Ok(identity)
    }

    async fn verify_request(
        &self,
        authz: Option<&str>,
        request: (&str, &str),
    ) -> Result<Identity, LoginError> {
        let authz = authz.ok_or(LoginError::MissingAuthorization)?;
        let Authn::Bound(BoundCredentials { key_id, signature }) = authz.parse()? else {
            return Err(LoginError::InitialOutsideLogin);
        };
        let proof = signature.ok_or(LoginError::NotLoggedIn)?;
        let mut identities = self.identities.lock().await;
        let cache_key = (key_id.clone(), proof.nonce.clone());
        let cached = identities
            .get_mut(&cache_key)
            .ok_or(LoginError::UnknownIdentity)?;
        if !cached.is_still_valid() {
            identities.pop(&cache_key);
            return Err(LoginError::IdentityExpired);
        }
        let (method, target) = request;
        let received = BoundRequest::new(method, target, proof.seq);
        cached.verifier.verify(&received, &key_id, &proof)?;
        if !cached.window.spend(proof.seq) {
            return Err(LoginError::SeqSpent);
        }
        cached.last_used = Instant::now();
        debug!(self.log, "bound request authorized"; "key_id" => %key_id);
        Ok(cached.identity.clone())
    }

    /// The identities whose logins have not expired.
    pub async fn identities(&self) -> Vec<Identity> {
        self.identities
            .lock()
            .await
            .iter()
            .filter(|(_, cached)| cached.is_still_valid())
            .map(|(_, cached)| cached.identity.to_owned())
            .collect()
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use slog::o;
    use x509_cert::time::Validity;

    use sush_common::authn::{Challenge, ChallengeResponse, RequestKey};
    use sush_common::keys::{EphemeralKey, KeyType, Signer as _};

    use super::*;

    #[tokio::test]
    async fn logins() {
        let logins = Logins::new(Logger::root(slog::Discard, o!()));
        let subject = "CN=Login Test Key,O=Oxide Computer Company,C=US";
        let mut root = EphemeralKey::new_root(
            KeyType::P256,
            subject.parse().unwrap(),
            Validity::from_now(Duration::from_secs(60)).unwrap(),
        )
        .unwrap();
        let Unauthorized(nonce) = logins
            .authorize(None, ("GET", "/sessions"))
            .await
            .unwrap_err();

        // Construct credentials.
        let challenge = Challenge::new(nonce.clone());
        let request_key = RequestKey::new();
        let response = ChallengeResponse::new(challenge, request_key.verifier());
        let signed = root.sign(response).await.unwrap();
        let verified = signed.verify_with_cert(root.cert()).unwrap();
        let mut credentials = Credentials::new(verified);
        let public_key = root.ssh_public_key();
        let key_id = public_key.key_id().unwrap();
        credentials.key_id = key_id.clone(); // override cert key ID
        let initial = credentials.to_string();
        let bind = |method, target, seq| {
            let request = BoundRequest::new(method, target, seq);
            request_key
                .bind(key_id.clone(), credentials.nonce.clone(), &request)
                .to_string()
        };

        // Claiming a key is not a login.
        let claimed = BoundCredentials::claim(key_id.clone()).to_string();
        assert!(
            logins
                .authorize(Some(&claimed), ("GET", "/sessions"))
                .await
                .is_err()
        );

        // Register our identity. Initial credentials work only to log in.
        assert!(
            logins
                .authorize(Some(&initial), ("GET", "/sessions"))
                .await
                .is_err()
        );
        let identity = logins
            .login(Some(&initial), public_key.clone())
            .await
            .unwrap();
        let Identity {
            key_id: iam_key_id,
            public_key: iam_public_key,
            nonce: iam_nonce,
            time_authenticated: iam_authenticated,
        } = identity;
        assert_eq!(iam_key_id, key_id);
        assert_eq!(iam_public_key, public_key);
        assert_eq!(iam_nonce, credentials.nonce);
        assert!(iam_authenticated <= Utc::now());

        // A bound request authorizes; replaying its header does not, nor
        // does presenting it against a different request line.
        let header = bind("GET", "/sessions", 1);
        let sessions = ("GET", "/sessions");
        let authorized = logins.authorize(Some(&header), sessions).await.unwrap();
        assert_eq!(authorized.key_id, key_id);
        assert!(logins.authorize(Some(&header), sessions).await.is_err());
        let header = bind("GET", "/sessions", 2);
        assert!(
            logins
                .authorize(Some(&header), ("GET", "/jobs"))
                .await
                .is_err()
        );

        // Bound credentials cannot log in.
        let header = bind("POST", "/iam", 3);
        assert!(
            logins
                .login(Some(&header), public_key.clone())
                .await
                .is_err()
        );

        // Replayed initial credentials are rejected: the nonce is spent.
        assert!(logins.login(Some(&initial), public_key).await.is_err());
    }
}
