// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command context tracking.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use clap::ValueEnum;
use x509_cert::Certificate;

use sush_common::authn::{Credentials, Identity};
use sush_common::jobs::{JobId, JobOutputStream, JobStatusMap, Session, SessionId, SignedJob};
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
pub trait CommandContext: Clone + Send + Sync {
    // Context management
    fn get_output_format(&self) -> OutputFormat;
    fn set_output_format(&mut self, output: OutputFormat);
    fn get_globals(&self) -> GlobalArgs;
    fn set_globals(&mut self, _args: GlobalArgs) {}
    fn pre_parse_hook(&mut self, _command: &str) {}

    // Session management
    fn get_credentials(&self) -> Option<Credentials>;
    fn set_credentials(&mut self, credentials: Option<Credentials>);
    fn session_id(&self) -> Option<SessionId>;
    fn next_job_id(&self) -> Result<JobId, CommandError>;
    fn session_started(&mut self, session: Session) -> Result<(), CommandError>;
    fn session_stopped(&mut self, session_id: &SessionId) -> Result<(), CommandError>;

    // Job signing certificates
    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<Certificate, CommandError>;
    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError>;

    // Job management
    fn job_started(&mut self, job: &SignedJob);
    fn job_stopped(&mut self, id: &JobId);
    fn job_error(&mut self, error: CommandError) -> CommandError;
    fn job_output(&mut self, id: &JobId, stream: JobOutputStream, output: &[u8], binary: bool);
    fn job_output_started(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total_length: u64,
    );
    fn job_output_update(&mut self, id: &JobId, stream: JobOutputStream, bytes: u64);
    fn job_output_finished(&mut self, id: &JobId, stream: JobOutputStream, stage: Option<&str>);
    fn job_polling_started(&mut self, id: &JobId, duration: Duration);
    fn job_polling_update(&mut self, id: &JobId);
    fn job_polling_finished(&mut self, id: &JobId);
    fn job_attached(&mut self, id: &JobId);
    fn job_detached(&mut self, id: &JobId);
    fn job_signing_started(&mut self, id: &JobId);
    fn job_signing_update(&mut self, id: &JobId);
    fn job_signing_finished(&mut self, id: &JobId);
    fn job_signed(&mut self, job: &SignedJob, show: bool);
    fn job_status(&mut self, id: &JobId, status: &JobStatusMap);
    fn read_signed_job(&mut self) -> Result<SignedJob, CommandError>;

    // SSH agent and identity
    fn iam(&mut self, identity: &Identity) -> Result<(), CommandError>;
    fn identities(&mut self, identities: &[SshPublicKey]) -> Result<(), CommandError>;
    fn please_touch(&mut self, identity: &SshPublicKey) -> Result<(), CommandError>;
    fn really_revoke(&mut self, key_id: KeyId) -> Result<KeyId, CommandError>;
    fn identity_revoked(&mut self, key_id: KeyId) -> Result<(), CommandError>;
}
