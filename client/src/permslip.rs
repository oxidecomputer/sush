//! Use Permission Slip to sign Support Shell job requests.

use permission_slip_common::params::{BlobStampParams, SignParams, StampParams};
use permission_slip_common::{ArtifactKind, HashAlgorithm};
use permslip_client_lib::login::{IdentityProvider, TokenProvider};
use permslip_client_lib::types::Error as ApiError;
use permslip_client_lib::{Client, ClientRequestBuilder, Error as ClientError};
use serde_json::{json, to_string as json_to_string};
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::der::Decode as _;
use x509_cert::der::pem::{PemLabel as _, decode_vec as decode_pem};
use x509_cert::spki::AlgorithmIdentifierOwned;

use sush_common::certs::{CertError, KeyId, Signature, Signed, Signer, ToBeSigned};

/// The default Permission Slip (aka Online Signing Service) server.
pub const DEFAULT_PERMSLIP_URL: &str = "https://signer-us-west.corp.oxide.computer";

pub struct PermslipSigner {
    client: Client,
    key_name: String,
    cert: Certificate,
}

impl PermslipSigner {
    pub async fn new<N: AsRef<str>>(key_name: N, url: &str) -> Result<Self, PermslipError> {
        let tokens = TokenProvider::IdP(IdentityProvider::Google);
        let mut builder = ClientRequestBuilder::new();
        let token = tokens.token().await.map_err(PermslipError::token)?;
        builder = builder.token(token.into_header_value().map_err(PermslipError::token)?);
        let client = Client::new_with_client(url, builder.build()?);
        let key_name = key_name.as_ref().to_owned();
        let cert = Self::get_cert(&client, &key_name).await?;
        Ok(Self {
            client,
            key_name,
            cert,
        })
    }

    async fn get_cert(client: &Client, key_name: &str) -> Result<Certificate, PermslipError> {
        let pem = client
            .get_cert()
            .key_name(key_name)
            .send()
            .await?
            .into_inner();
        if !pem.starts_with("-----BEGIN ") {
            return Err(PermslipError::InvalidPem);
        }
        let (label, der) = decode_pem(pem.as_bytes())?;
        if label != Certificate::PEM_LABEL {
            return Err(PermslipError::InvalidPem);
        }
        Ok(Certificate::from_der(&der)?)
    }
}

impl Signer for PermslipSigner {
    type Error = PermslipError;

    async fn key_id(&self) -> Result<KeyId, Self::Error> {
        Ok(KeyId::try_from(&self.cert)?)
    }

    async fn signature_algorithm(&self) -> Result<AlgorithmIdentifierOwned, Self::Error> {
        Ok(self
            .cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .clone())
    }

    async fn sign<T: ToBeSigned>(&self, thing: T) -> Result<Signed<T>, Self::Error> {
        let key_id = self.key_id().await?;
        let message = thing.to_be_signed(&key_id);
        let params = StampParams::Blob(BlobStampParams {
            sign: SignParams {
                artifact_kind: ArtifactKind::Blob,
                hash_algorithm: HashAlgorithm::Default,
                key_name: self.key_name.to_string(),
                origin_hash: blake3::hash(&message).to_string(),
                version: None,
                version_head: None,
                version_prev: None,
            },
        });
        let signature = self
            .client
            .sign()
            .params(json_to_string(&json!(params))?)
            .body(message)
            .send()
            .await?
            .into_inner();
        Ok(Signed::new(thing, key_id, Signature::new(signature)))
    }
}

#[derive(Debug, Error)]
pub enum PermslipError {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error("permslip: {0}")]
    Client(String),
    #[error(transparent)]
    Der(#[from] x509_cert::der::Error),
    #[error("invalid PEM certificate")]
    InvalidPem,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Pem(#[from] pem_rfc7468::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error("permslip authentication token: {0}")]
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
