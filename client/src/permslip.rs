// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Use Permission Slip to sign Support Shell job requests.

use http::HeaderValue;
use permslip_client_lib::login::TokenProvider;
use permslip_client_lib::types::{CreateSushSessionBody, CreatedSushSession, Error as ApiError};
use permslip_client_lib::{Client, ClientRequestBuilder, Error as ClientError};
use sled_hardware_types::BaseboardId;
use thiserror::Error;

use sush_common::codephrases::InvalidCodephrase;
use sush_common::jobs::{JobStartRequest, SessionSushNonce, SignedJob};
use sush_common::keys::KeyError;
use sush_common::targets::InvalidTarget;

pub struct PermslipSigner {
    client: Client,
    key_name: String,
}

/// Get a bearer token by the sshauth challenge, signed with the agent
/// key named by `fingerprint`.
pub async fn fresh_token(
    url: &str,
    agent_sock: String,
    fingerprint: String,
) -> Result<String, PermslipError> {
    let tokens = TokenProvider::SshAuth {
        fingerprint: Some(fingerprint),
        server_url: url.to_owned(),
        agent_sock,
    };
    let token = tokens.token().await.map_err(PermslipError::token)?;
    let value = token.into_header_value().map_err(PermslipError::token)?;
    value
        .to_str()
        .map(str::to_owned)
        .map_err(PermslipError::token)
}

impl PermslipSigner {
    /// A signer authenticated with `token`.
    pub fn new<N: AsRef<str>>(key_name: N, url: &str, token: &str) -> Result<Self, PermslipError> {
        let mut token = HeaderValue::from_str(token).map_err(PermslipError::token)?;
        token.set_sensitive(true);
        let builder = ClientRequestBuilder::new().token(token);
        Ok(Self {
            client: Client::new_with_client(
                url,
                builder
                    .build()
                    .map_err(|err| PermslipError::Client(err.to_string()))?,
            ),
            key_name: key_name.as_ref().to_owned(),
        })
    }

    pub async fn create_session(
        &self,
        baseboard: &BaseboardId,
        sush_nonce: SessionSushNonce,
    ) -> Result<CreatedSushSession, PermslipError> {
        Ok(self
            .client
            .create_sush_session()
            .body(CreateSushSessionBody {
                cpn: baseboard.part_number.clone(),
                serial_number: baseboard.serial_number.clone(),
                key_name: self.key_name.clone(),
                sush_nonce,
            })
            .send()
            .await?
            .into_inner())
    }

    pub async fn sign_job_request(
        &self,
        request: JobStartRequest,
    ) -> Result<SignedJob, PermslipError> {
        Ok(self
            .client
            .sign_sush_job()
            .body(request)
            .send()
            .await?
            .into_inner())
    }
}

#[derive(Debug, Error)]
pub enum PermslipError {
    #[error("{0}")]
    Client(String),
    #[error(transparent)]
    Der(#[from] x509_cert::der::Error),
    #[error("Ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),
    #[error("invalid PEM certificate")]
    InvalidPem,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid codephrase")]
    InvalidCodephrase(#[from] InvalidCodephrase),
    #[error("invalid target")]
    InvalidTarget(#[from] InvalidTarget),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error(transparent)]
    Pem(#[from] pem_rfc7468::Error),
    #[error("authentication token: {0}")]
    Token(String),
}

impl PermslipError {
    fn token<E: ToString>(error: E) -> Self {
        Self::Token(error.to_string())
    }
}

impl From<ClientError<ApiError>> for PermslipError {
    fn from(error: ClientError<ApiError>) -> Self {
        use ClientError::*;
        match error {
            InvalidRequest(e) => PermslipError::Client(format!("Invalid request: {e}")),
            CommunicationError(e) => PermslipError::Client(format!("Communication error: {e}")),
            InvalidUpgrade(e) => PermslipError::Client(e.to_string()),
            ErrorResponse(e) => PermslipError::Client(e.message.to_owned()),
            ResponseBodyError(e) => PermslipError::Client(e.to_string()),
            InvalidResponsePayload(_b, e) => PermslipError::Client(e.to_string()),
            UnexpectedResponse(e) if e.status().is_redirection() => {
                if let Some(l) = e.headers().get("location") {
                    PermslipError::Client(format!(
                        "Got {} to {}",
                        e.status(),
                        l.to_str().unwrap_or("?")
                    ))
                } else {
                    PermslipError::Client(format!("Got {}", e.status()))
                }
            }
            UnexpectedResponse(e) => PermslipError::Client(format!("Unexpected response: {e:?}")),
            Custom(e) => PermslipError::Client(e.to_string()),
        }
    }
}
