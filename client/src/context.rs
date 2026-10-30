// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command context tracking.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::ValueEnum;
use sled_hardware_types::BaseboardId;
use x509_cert::Certificate;

use sush_common::authn::{BoundRequest, Credentials, Identity, RequestKey};
use sush_common::jobs::{
    Access, JobId, JobOutputStream, JobStartRequest, JobStatusMap, Session, SessionClientNonce,
    SessionId, SessionSeq, SessionSignerNonce, SessionSushNonce, SignedJob,
};
use sush_common::keys::{KeyId, SshPublicKey};
use sush_common::targets::{SledId, SledVersion};
use sush_common::version::VersionInfo;

use crate::AuthzSigner;
use crate::commands::{ClientHandle, CommandError, GlobalArgs};
use crate::config::SuppliedOptions;

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

    /// Sign one request with the login's ephemeral key, yielding its
    /// `Authorization` header.
    pub fn sign(&self, method: &str, target: &str) -> String {
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

/// What kind of output to emit on standard output. Standard input
/// and standard error may be used with all formats for interactive
/// communication with a human user (if there is one).
#[derive(Clone, Copy, Debug, Default, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// UTF-8 encoded text
    #[default]
    Text,

    /// One JSON object per line
    Json,
}

/// How much of a job's per-sled status to show.
#[derive(Clone, Copy, Debug, Default)]
pub enum StatusDisplayStyle {
    Short,
    #[default]
    Medium,
    Full,
}

/// What to show when a job starts.
#[derive(Clone, Copy, Debug)]
pub enum StartedDisplay {
    /// Display nothing; the job was signed offline.
    None,

    /// Display a note to stderr only.
    Note,

    /// Display a note to stderr, and the job ID to stdout.
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
    fn set_options(&mut self, _options: SuppliedOptions) -> Result<(), CommandError> {
        Err(CommandError::ReplOnly("set"))
    }
    fn unset_options(&mut self, _long_names: &[String]) -> Result<(), CommandError> {
        Err(CommandError::ReplOnly("unset"))
    }
    fn last_job_id(&self) -> Option<JobId> {
        None
    }

    // Errors
    fn command_error(&mut self, error: &CommandError);

    // Build provenance
    fn versions(
        &mut self,
        client: &VersionInfo,
        server: Option<&VersionInfo>,
        sleds: &[SledVersion],
    );

    // Session management
    fn authz_signer(&self) -> AuthzSigner;
    #[expect(async_fn_in_trait, reason = "commands run as non-`Send` futures")]
    async fn client_handle(
        &mut self,
        args: &GlobalArgs,
    ) -> Result<Option<Arc<ClientHandle>>, CommandError> {
        let handle = ClientHandle::from_args(args, self.authz_signer()).await?;
        Ok(handle.map(Arc::new))
    }
    fn get_credentials(&self) -> Option<Authz> {
        self.authz_signer().get()
    }
    fn set_credentials(&mut self, credentials: Option<Authz>) {
        self.authz_signer().set(credentials)
    }
    fn pending_client_nonce(&self) -> Option<SessionClientNonce> {
        None
    }
    fn save_client_nonce(&self, _client_nonce: SessionClientNonce) {}
    fn session_id(&self) -> Option<SessionId>;
    fn next_job_id(&self) -> Result<JobId, CommandError>;
    fn session_start_params(
        &self,
        baseboard_id: BaseboardId,
        client_nonce: SessionClientNonce,
        sush_nonce: SessionSushNonce,
    );
    fn job_start_params(&self, request: &JobStartRequest);
    fn session_created(
        &mut self,
        session: Session,
        signer_nonce: SessionSignerNonce,
        seq: SessionSeq,
    );
    fn session_started(&mut self, session: Session, force: bool);
    fn session_joined(&mut self, session: Session, force: bool);
    fn session_stopped(&mut self, session_id: &SessionId);
    fn attach_allowed(&mut self, key_id: &KeyId, access: Access);
    fn attach_denied(&mut self, key_id: &KeyId);

    // Job signing certificates
    fn cert_chain(
        &mut self,
        key_id: KeyId,
        certs: &str,
        roots: &[Certificate],
    ) -> Result<Certificate, CommandError>;

    // Job management
    fn really_target(&mut self, sled: &SledId) -> Result<(), CommandError>;
    fn job_started(
        &mut self,
        job: &SignedJob,
        sleds: Option<&BTreeSet<BaseboardId>>,
        display: StartedDisplay,
    );
    fn job_stopped(&mut self, id: &JobId);
    fn job_skipped(&mut self, id: &JobId) -> bool;
    fn job_output(
        &mut self,
        id: &JobId,
        target: &BaseboardId,
        stream: JobOutputStream,
        output: &[u8],
        binary: bool,
    );
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
    fn job_signing_finished(&mut self, id: &JobId, signed: bool);
    fn job_signed(&mut self, job: &SignedJob, show: bool);
    fn job_status(&mut self, id: &JobId, status: &JobStatusMap, style: StatusDisplayStyle);
    fn read_signed_job(&mut self) -> Result<SignedJob, CommandError>;

    // SSH agent and identity
    fn iam(&mut self, identity: &Identity) -> Result<(), CommandError>;
    fn identities(&mut self, identities: &[SshPublicKey]) -> Result<(), CommandError>;
    fn please_touch(&mut self, identity: &SshPublicKey) -> Result<(), CommandError>;
    #[cfg(feature = "permslip")]
    fn please_authn(&mut self, url: &str);
}
