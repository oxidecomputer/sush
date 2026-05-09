//! Command context tracking.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use clap::ValueEnum;

use sush_common::authn::{Credentials, Identity};
use sush_common::jobs::{JobId, JobOutputStream, JobStatus, SessionId, SignedJob};
use sush_common::keys::{KeyId, SshPublicKey};

use crate::commands::{CommandError, GlobalArgs};

/// What kind of output to emit.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Behavior in response to command execution, e.g., printing output,
/// maintaining (ephemeral) state.
pub trait CommandContext: Send + Sync {
    // Context management
    fn get_output_format(&self) -> OutputFormat;
    fn set_output_format(&mut self, output: OutputFormat);
    fn set_globals(&mut self, _args: &mut GlobalArgs, _values: GlobalArgs) {}
    fn pre_parse_hook(&mut self, _command: &str) {}
    fn more(&self) -> bool;

    // Session management
    fn get_credentials(&self) -> Option<(Credentials, SshPublicKey)>;
    fn set_credentials(&mut self, credentials: Option<(Credentials, SshPublicKey)>);
    fn session_id(&self) -> Option<&SessionId>;
    fn next_job_id(&self) -> Result<JobId, CommandError>;
    fn session_started(&mut self, session_id: &SessionId) -> Result<(), CommandError>;
    fn session_stopped(&mut self, session_id: &SessionId) -> Result<(), CommandError>;

    // Job signing certificates
    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<(), CommandError>;
    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError>;

    // Job management
    fn job_started(&mut self, job: &SignedJob) -> Result<(), CommandError>;
    fn job_stopped(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_error(&mut self, error: CommandError) -> Result<(), CommandError>;
    fn job_output(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        output: &[u8],
        binary: bool,
    ) -> Result<(), CommandError>;
    fn job_output_started(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total_length: u64,
    ) -> Result<(), CommandError>;
    fn job_output_update(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        bytes: u64,
    ) -> Result<(), CommandError>;
    fn job_output_finished(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        stage: Option<&str>,
    ) -> Result<(), CommandError>;
    fn job_polling_started(&mut self, id: &JobId, duration: Duration) -> Result<(), CommandError>;
    fn job_polling_update(&mut self, id: &JobId, status: &JobStatus) -> Result<(), CommandError>;
    fn job_polling_finished(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_session_connected(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_session_disconnected(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_signing_started(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_signing_update(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_signing_finished(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_signed(&mut self, job: &SignedJob, show: bool) -> Result<(), CommandError>;
    fn job_status(&mut self, id: &JobId, status: &JobStatus) -> Result<(), CommandError>;
    fn read_signed_job(&mut self) -> Result<SignedJob, CommandError>;

    // SSH agent and identity
    fn iam(&mut self, identity: &Identity) -> Result<(), CommandError>;
    fn identities(&mut self, identities: &[SshPublicKey]) -> Result<(), CommandError>;
    fn please_touch(&mut self, identity: &SshPublicKey) -> Result<(), CommandError>;
    fn really_revoke(&mut self, key_id: KeyId) -> Result<KeyId, CommandError>;
    fn identity_revoked(&mut self, key_id: KeyId) -> Result<(), CommandError>;
}
