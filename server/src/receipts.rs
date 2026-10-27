// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Issue and verify login receipts.

use std::fmt;

use dice_mfg_msgs::{PlatformId, PlatformIdPkiPathError};
use rustls::pki_types::CertificateDer;
use sled_hardware_types::BaseboardId;
use slog::{Discard, Logger, error, o};
use sprockets_tls::keys::RotCertVerifier;
use thiserror::Error;
use tokio::sync::Mutex;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_common::authn::{Credentials, LoginReceipt};
use sush_common::keys::{EphemeralKey, KeyError};

use crate::link::baseboard;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("Unparseable platform ID `{0}`")]
    Baseboard(String),
    #[error("Platform chain does not verify: {0}")]
    Chain(#[from] rustls::Error),
    #[error("This server does not accept login receipts")]
    Disabled,
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    PlatformId(#[from] PlatformIdPkiPathError),
}

/// What a server needs to issue and verify login receipts.
pub struct Receipts {
    log: Logger,

    /// This server's vouched key and its platform chain. Without one,
    /// the server issues no receipts.
    issuer: Option<Mutex<(EphemeralKey, Vec<Certificate>)>>,

    /// Verifies issuers' platform chains against the platform roots.
    /// Without one, the server accepts no receipts.
    verifier: Option<RotCertVerifier>,
}

impl fmt::Debug for Receipts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receipts")
            .field("issues", &self.issuer.is_some())
            .field("verifies", &self.verifier.is_some())
            .finish()
    }
}

impl Receipts {
    /// Neither issue nor accept receipts.
    pub fn none() -> Self {
        Self {
            log: Logger::root(Discard, o!()),
            issuer: None,
            verifier: None,
        }
    }

    /// Accept receipts whose platform chains verify against `roots`.
    /// Given an issuer, also issue receipts signed with its key.
    pub fn new(
        log: &Logger,
        roots: Vec<Certificate>,
        issuer: Option<(EphemeralKey, Vec<Certificate>)>,
    ) -> Self {
        Self {
            log: log.clone(),
            issuer: issuer.map(Mutex::new),
            verifier: Some(RotCertVerifier {
                roots,
                log: log.clone(),
            }),
        }
    }

    /// Sign a receipt for `credentials`, which the caller has verified.
    /// Return nothing if this server has no issuer or signing fails.
    pub async fn issue(&self, credentials: &Credentials) -> Option<LoginReceipt> {
        let mut issuer = self.issuer.as_ref()?.lock().await;
        let (key, platform) = &mut *issuer;
        match LoginReceipt::new(key, platform, credentials).await {
            Ok(receipt) => Some(receipt),
            Err(error) => {
                error!(self.log, "login receipt signing failed"; "error" => %error);
                None
            }
        }
    }

    /// Verify that `receipt` signs `credentials` and that its platform
    /// chain verifies against the platform roots. Return the baseboard
    /// of the issuing sled.
    pub fn verify(
        &self,
        receipt: &LoginReceipt,
        credentials: &Credentials,
    ) -> Result<BaseboardId, ReceiptError> {
        let verifier = self.verifier.as_ref().ok_or(ReceiptError::Disabled)?;
        let platform = receipt.verify(credentials)?;
        let der = platform
            .iter()
            .map(|cert| Ok(CertificateDer::from(cert.to_der()?)))
            .collect::<Result<Vec<_>, KeyError>>()?;
        let [leaf, intermediates @ ..] = der.as_slice() else {
            return Err(KeyError::ChainTooShort.into());
        };
        verifier.verify_cert(leaf, intermediates)?;
        let platform_id = PlatformId::try_from(&platform)?;
        baseboard(&self.log, platform_id.as_str())
            .ok_or_else(|| ReceiptError::Baseboard(platform_id.as_str().to_owned()))
    }
}
