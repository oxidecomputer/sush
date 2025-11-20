//! Signed job requests.

use std::ops::Deref;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;
use x509_cert::Certificate;

use crate::certs::{CertError, KeyId, Signature, verify_signature};

#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd)]
pub struct JobId(Uuid);

impl JobId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for JobId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for JobId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::from_str(s)?))
    }
}

impl_to_from_sql_and_serde!(JobId);

/// The response to a job reservation request.
#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct JobsReserved {
    /// Fresh, globally unique job IDs.
    pub job_ids: Vec<JobId>,

    /// The server's idea of the time at which the job IDs were reserved.
    pub time_reserved: DateTime<Utc>,
}

/// Internal representation of a job to be signed.
struct UnsignedJob {
    job_id: JobId,
    key_id: KeyId,
    command: String,
}

impl UnsignedJob {
    /// Generate a SHA-256 hash over the fields of `self`.
    fn to_be_signed(&self) -> Vec<u8> {
        // Prefix the fields with the number of fields, and each field's
        // data with its length. Update the constant as fields are added
        // to `UnsignedJob` and hashed below.
        const FIELDS_HASHED: u64 = 3;
        let mut fields_hashed = 0;
        let mut hasher = Sha256::default();
        hasher.update("sush-job");
        hasher.update(FIELDS_HASHED.to_be_bytes());
        let mut hash = |data: &[u8]| {
            hasher.update((data.len() as u64).to_be_bytes());
            hasher.update(data);
            fields_hashed += 1;
        };
        hash(self.job_id.as_bytes());
        hash(self.key_id.as_slice());
        hash(self.command.as_bytes());
        assert_eq!(fields_hashed, FIELDS_HASHED);
        hasher.finalize().to_vec()
    }
}

pub trait JobSigner {
    type Error: std::error::Error;

    fn key_id(&self) -> KeyId;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("unable to sign job request: {0}")]
    Generic(String),
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct SignedJob {
    pub job_id: JobId,
    pub key_id: KeyId,
    pub command: String,
    pub signature: Signature,
}

impl SignedJob {
    pub fn new<S, C>(job_id: JobId, signer: &S, command: C) -> Result<Self, SigningError>
    where
        S: JobSigner,
        C: AsRef<str>,
    {
        let key_id = signer.key_id();
        let command = command.as_ref().to_string();
        let unsigned = UnsignedJob {
            job_id,
            key_id,
            command: command.clone(),
        };
        Ok(Self {
            job_id,
            key_id,
            command,
            signature: Signature::new(
                signer
                    .sign(&unsigned.to_be_signed())
                    .map_err(|e| SigningError::Generic(e.to_string()))?,
            ),
        })
    }

    pub fn verify(self, cert: &Certificate) -> Result<VerifiedJob, CertError> {
        verify_signature(&self.to_unsigned().to_be_signed(), &self.signature, cert)?;
        Ok(VerifiedJob(self))
    }

    fn to_unsigned(&self) -> UnsignedJob {
        UnsignedJob {
            job_id: self.job_id,
            key_id: self.key_id,
            command: self.command.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedJob(SignedJob);

impl Deref for VerifiedJob {
    type Target = SignedJob;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub enum JobStatus {
    NotFound,
    Reserved {
        job_id: JobId,
        time_reserved: DateTime<Utc>,
    },
    Started {
        job: SignedJob,
        time_reserved: DateTime<Utc>,
        time_started: DateTime<Utc>,
    },
    Ended {
        job: SignedJob,
        time_reserved: DateTime<Utc>,
        time_started: DateTime<Utc>,
        time_ended: DateTime<Utc>,
        status: Option<i32>,
        stdout_len: i32,
        stderr_len: i32,
    },
}
