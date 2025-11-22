//! Use Permission Slip to sign Support Shell job requests.

use anyhow::{Error, Result, bail};
use permission_slip_common::params::{BlobStampParams, SignParams, StampParams};
use permission_slip_common::{ArtifactKind, HashAlgorithm};
use permslip_client_lib::login::{IdentityProvider, TokenProvider};
use permslip_client_lib::{Client, ClientRequestBuilder};
use serde_json::{json, to_string as json_to_string};
use x509_cert::Certificate;
use x509_cert::der::Decode as _;
use x509_cert::der::pem::{PemLabel, decode_vec as decode_pem};
use x509_cert::spki::AlgorithmIdentifierOwned;

use sush_common::certs::{KeyId, Signature, Signed, Signer, ToBeSigned};

pub struct PermslipSigner {
    client: Client,
    key_name: String,
    cert: Certificate,
}

impl PermslipSigner {
    pub async fn new<N: AsRef<str>>(key_name: N, url: &str) -> Result<Self> {
        let tokens = TokenProvider::IdP(IdentityProvider::Google);
        let mut builder = ClientRequestBuilder::new();
        builder = builder.token(tokens.token().await?.into_header_value()?);
        let client = Client::new_with_client(url, builder.build()?);
        let key_name = key_name.as_ref().to_owned();
        let cert = Self::get_cert(&client, &key_name).await?;
        Ok(Self {
            client,
            key_name,
            cert,
        })
    }

    async fn get_cert(client: &Client, key_name: &str) -> Result<Certificate> {
        let pem = client
            .get_cert()
            .key_name(key_name)
            .send()
            .await?
            .into_inner();
        if !pem.starts_with("-----BEGIN ") {
            bail!("invalid PEM");
        }
        let (label, der) = decode_pem(pem.as_bytes())?;
        if label != Certificate::PEM_LABEL {
            bail!("invalid PEM certificate");
        }
        Ok(Certificate::from_der(&der)?)
    }
}

impl Signer for PermslipSigner {
    type Error = Error;

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
