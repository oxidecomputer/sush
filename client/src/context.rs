// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command context tracking.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::ValueEnum;
use sled_hardware_types::BaseboardId;
use x509_cert::Certificate;

use sush_common::authn::{BoundRequest, Credentials, Identity, RequestKey};
use sush_common::jobs::{
    Access, JobId, JobOutputStream, JobStatusMap, Session, SessionId, SessionSignerNonce, SignedJob,
};
use sush_common::keys::{KeyId, SshPublicKey};
use sush_common::targets::{SledId, SledVersion};
use sush_common::version::VersionInfo;

use crate::AuthzSigner;
use crate::commands::{CommandError, GlobalArgs};
use crate::types::SessionStartNonce;

/// Authorization state: the credentials that authenticated us, and the
/// ephemeral key that binds each request we make.
#[derive(Clone, Debug)]
pub struct Authz {
    pub credentials: Credentials,
    key: RequestKey,
    seq: Arc<AtomicU64>,
}

impl Authz {
    pub fn new(credentials: Credentials, key: RequestKey) -> Self {
        Self {
            credentials,
            key,
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    /// The `Authorization` header binding one request.
    pub fn header(&self, method: &str, target: &str) -> String {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let request = BoundRequest::new(method, target, seq);
        self.key
            .bind(
                self.credentials.key_id.clone(),
                self.credentials.nonce.clone(),
                &request,
            )
            .to_string()
    }
}

/// What kind of output to emit.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// How much of a job's per-sled status to show.
#[derive(Clone, Copy, Debug, Default)]
pub enum StatusDisplayStyle {
    #[default]
    Short,
    Full,
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

    // Build provenance
    fn versions(
        &mut self,
        client: &VersionInfo,
        server: Option<&VersionInfo>,
        sleds: &[SledVersion],
    );

    // Session management
    fn authz_signer(&self) -> AuthzSigner;
    fn get_credentials(&self) -> Option<Authz> {
        self.authz_signer().get()
    }
    fn set_credentials(&mut self, credentials: Option<Authz>) {
        self.authz_signer().set(credentials)
    }
    fn session_id(&self) -> Option<SessionId>;
    fn next_job_id(&self) -> Result<JobId, CommandError>;
    fn session_start_params(
        &self,
        baseboard_id: BaseboardId,
        nonce: SessionStartNonce,
    ) -> Result<(), CommandError>;
    fn session_created(&mut self, session: Session, signer_nonce: SessionSignerNonce);
    fn session_started(&mut self, session: Session, force: bool) -> Result<(), CommandError>;
    fn session_stopped(&mut self, session_id: &SessionId) -> Result<(), CommandError>;
    fn attach_allowed(&mut self, key_id: &KeyId, access: Access);
    fn attach_denied(&mut self, key_id: &KeyId);

    // Job signing certificates
    fn cert_chain(
        &mut self,
        key_id: KeyId,
        certs: &str,
        roots: &[Certificate],
    ) -> Result<Certificate, CommandError>;
    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError>;

    // Job management
    fn really_target(&mut self, sled: &SledId) -> Result<(), CommandError>;
    fn job_started(&mut self, job: &SignedJob);
    fn job_stopped(&mut self, id: &JobId);
    fn job_skipped(&mut self, id: &JobId) -> bool;
    fn job_error(&mut self, error: CommandError) -> CommandError;
    fn job_output(&mut self, id: &JobId, stream: JobOutputStream, output: &[u8], binary: bool);
    fn job_output_target(&mut self, target: &BaseboardId);
    fn job_output_started(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total_length: u64,
    );
    fn job_output_update(&mut self, id: &JobId, stream: JobOutputStream, bytes: u64);
    fn job_output_finished(&mut self, id: &JobId, stream: JobOutputStream, stage: Option<&str>);
    fn job_watch_started(&mut self, id: &JobId);
    fn job_watch_update(&mut self, status: &JobStatusMap);
    fn job_watch_stalled(&mut self, id: &JobId);
    fn job_watch_finished(&mut self, id: &JobId);
    fn job_attached(&mut self, id: &JobId);
    fn job_detached(&mut self, id: &JobId);
    fn job_signing_started(&mut self, id: &JobId);
    fn job_signing_update(&mut self, id: &JobId);
    fn job_signing_finished(&mut self, id: &JobId);
    fn job_signed(&mut self, job: &SignedJob, show: bool);
    fn job_status(&mut self, id: &JobId, status: &JobStatusMap, style: StatusDisplayStyle);
    fn read_signed_job(&mut self) -> Result<SignedJob, CommandError>;

    // SSH agent and identity
    fn iam(&mut self, identity: &Identity) -> Result<(), CommandError>;
    fn identities(&mut self, identities: &[SshPublicKey]) -> Result<(), CommandError>;
    fn please_touch(&mut self, identity: &SshPublicKey) -> Result<(), CommandError>;
    fn really_revoke(&mut self, what: &str, key_id: KeyId) -> Result<KeyId, CommandError>;
    fn revoked(&mut self, what: &str, key_id: KeyId) -> Result<(), CommandError>;
}
