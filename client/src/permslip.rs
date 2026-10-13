// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Use Permission Slip to sign Support Shell job requests.

use std::time::Duration;

use permslip_client_lib::credential_store::store_credential;
use permslip_client_lib::login::{BearerToken, TokenProvider};
use permslip_client_lib::types::{
    CreateGoogleSessionParams, CreateGoogleSessionResponse, CreateSushSessionBody,
    CreatedSushSession, Error as ApiError,
};
use permslip_client_lib::{Client, ClientRequestBuilder, Error as ClientError};
use sled_hardware_types::BaseboardId;
use thiserror::Error;
use tokio::time::sleep;

use sush_common::codephrases::InvalidCodephrase;
use sush_common::jobs::{JobStartRequest, SessionSushNonce, SignedJob};
use sush_common::keys::KeyError;
use sush_common::targets::InvalidTarget;

use crate::context::CommandContext;

pub struct PermslipSigner<C> {
    client: Client,
    key_name: String,
    url: String,
    authn: PermslipAuthn,
    ctx: C,
}

/// How to authenticate to the signing service.
#[derive(Clone)]
pub enum PermslipAuthn {
    /// A Google session, for humans.
    Google,

    /// An sshauth challenge, for machines like manufacturing stations.
    Ssh {
        agent_sock: String,
        fingerprint: Option<String>,
    },
}

/// Authenticate to the signing service via Google and save the session
/// credential where `permslip login` does.
async fn google_authn<C: CommandContext>(
    ctx: &mut C,
    url: &str,
) -> Result<BearerToken, PermslipError> {
    let anonymous = Client::new(url);
    let redirect = anonymous
        .get_google_auth_redirect()
        .send()
        .await?
        .into_inner();
    ctx.please_authn(&redirect.redirect_url);
    loop {
        let response = anonymous
            .create_google_session()
            .body(CreateGoogleSessionParams {
                exchange_code: redirect.exchange_code.clone(),
            })
            .send()
            .await?
            .into_inner();
        match response {
            CreateGoogleSessionResponse::Created { expires_at, token } => {
                store_credential(url, &token, expires_at)
                    .await
                    .map_err(PermslipError::token)?;
                return saved_token(url).await;
            }
            CreateGoogleSessionResponse::WaitingForOauth {
                retry_in_milliseconds,
            } => sleep(Duration::from_millis(retry_in_milliseconds)).await,
        }
    }
}

/// The credential saved for `url`, if it has not expired.
async fn saved_token(url: &str) -> Result<BearerToken, PermslipError> {
    TokenProvider::SavedCredentials
        .token(url)
        .await
        .map_err(PermslipError::token_flow)
}

/// A client for `url` authenticated by `authn`.
async fn authn_client<C: CommandContext>(
    ctx: &mut C,
    url: &str,
    authn: &PermslipAuthn,
    fresh: bool,
) -> Result<Client, PermslipError> {
    let token = match authn {
        PermslipAuthn::Google => match saved_token(url).await {
            Ok(token) if !fresh => token,
            _ => google_authn(ctx, url).await?,
        },
        PermslipAuthn::Ssh {
            agent_sock,
            fingerprint,
        } => TokenProvider::SshAuth {
            fingerprint: fingerprint.clone(),
            agent_sock: agent_sock.clone(),
        }
        .token(url)
        .await
        .map_err(PermslipError::token_flow)?,
    };
    let builder =
        ClientRequestBuilder::new().token(token.into_header_value().map_err(PermslipError::token)?);
    Ok(Client::new_with_client(
        url,
        builder
            .build()
            .map_err(|err| PermslipError::Client(err.to_string()))?,
    ))
}

impl<C: CommandContext> PermslipSigner<C> {
    /// A signer for `key_name`, authenticated to `url` by `authn`.
    pub async fn connect<N: AsRef<str>>(
        mut ctx: C,
        key_name: N,
        url: &str,
        authn: PermslipAuthn,
    ) -> Result<Self, PermslipError> {
        Ok(Self {
            client: authn_client(&mut ctx, url, &authn, false).await?,
            key_name: key_name.as_ref().to_owned(),
            url: url.to_owned(),
            authn,
            ctx,
        })
    }

    /// Authenticate afresh.
    async fn renew(&mut self) -> Result<(), PermslipError> {
        self.client = authn_client(&mut self.ctx, &self.url, &self.authn, true).await?;
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
