// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Use Permission Slip to sign Support Shell job requests.

use permslip_client_lib::login::{TokenProvider, forget_session};
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
    url: String,
    auth: PermslipAuth,
}

/// How to authenticate to the signing service.
#[derive(Clone)]
pub enum PermslipAuth {
    /// A Google session, for humans: a cached session when one is
    /// live, a device-flow login otherwise.
    Google,

    /// The sshauth challenge, signed by the agent key `fingerprint`
    /// names, for machines like manufacturing stations.
    Ssh {
        agent_sock: String,
        fingerprint: Option<String>,
    },
}

async fn authenticated_client(url: &str, auth: &PermslipAuth) -> Result<Client, PermslipError> {
    let tokens = match auth {
        PermslipAuth::Google => TokenProvider::GoogleSession {
            server_url: url.to_owned(),
        },
        PermslipAuth::Ssh {
            agent_sock,
            fingerprint,
        } => TokenProvider::SshAuth {
            fingerprint: fingerprint.clone(),
            server_url: url.to_owned(),
            agent_sock: agent_sock.clone(),
        },
    };
    let token = tokens.token().await.map_err(PermslipError::token_flow)?;
    let builder =
        ClientRequestBuilder::new().token(token.into_header_value().map_err(PermslipError::token)?);
    Ok(Client::new_with_client(
        url,
        builder
            .build()
            .map_err(|err| PermslipError::Client(err.to_string()))?,
    ))
}

impl PermslipSigner {
    /// A signer for `key_name`, authenticated by `auth`.
    pub async fn connect<N: AsRef<str>>(
        key_name: N,
        url: &str,
        auth: PermslipAuth,
    ) -> Result<Self, PermslipError> {
        Ok(Self {
            client: authenticated_client(url, &auth).await?,
            key_name: key_name.as_ref().to_owned(),
            url: url.to_owned(),
            auth,
        })
    }

    /// Authenticate afresh, for when the server refuses the session
    /// before its local expiry.
    async fn renew(&mut self) -> Result<(), PermslipError> {
        if let PermslipAuth::Google = self.auth {
            forget_session(&self.url).map_err(PermslipError::token)?;
        }
        self.client = authenticated_client(&self.url, &self.auth).await?;
        Ok(())
    }

    pub async fn create_session(
        &mut self,
        baseboard: &BaseboardId,
        sush_nonce: SessionSushNonce,
    ) -> Result<CreatedSushSession, PermslipError> {
        match self.try_create_session(baseboard, sush_nonce).await {
            Err(PermslipError::Unauthorized(_)) => {
                self.renew().await?;
                self.try_create_session(baseboard, sush_nonce).await
            }
            result => result,
        }
    }

    async fn try_create_session(
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
        &mut self,
        request: JobStartRequest,
    ) -> Result<SignedJob, PermslipError> {
        match self.try_sign_job_request(request.clone()).await {
            Err(PermslipError::Unauthorized(_)) => {
                self.renew().await?;
                self.try_sign_job_request(request).await
            }
            result => result,
        }
    }

    async fn try_sign_job_request(
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
    #[error("the signing service refused the session: {0}")]
    Unauthorized(String),
}

impl PermslipError {
    fn token<E: ToString>(error: E) -> Self {
        Self::Token(error.to_string())
    }

    /// Recover the API error from the permslip token flow.
    fn token_flow(error: anyhow::Error) -> Self {
        match error.downcast::<ClientError<ApiError>>() {
            Ok(client) => client.into(),
            Err(error) => Self::token(error),
        }
    }
}

impl From<ClientError<ApiError>> for PermslipError {
    fn from(error: ClientError<ApiError>) -> Self {
        use ClientError::*;
        match error {
            InvalidRequest(e) => PermslipError::Client(format!("Invalid request: {e}")),
            CommunicationError(e) => PermslipError::Client(format!("Communication error: {e}")),
            InvalidUpgrade(e) => PermslipError::Client(e.to_string()),
            ErrorResponse(e) if e.status() == http::StatusCode::UNAUTHORIZED => {
                PermslipError::Unauthorized(e.message.to_owned())
            }
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
