//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _, stdin};
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use async_recursion::async_recursion;
use blake3::{Hasher, hash};
use bytesize::ByteSize;
use clap::{Parser, Subcommand};
use futures::stream;
use futures::{FutureExt as _, StreamExt as _};
use http::header::WWW_AUTHENTICATE;
use http::status::StatusCode;
use memmap2::Mmap;
use reqwest::Upgraded;
use rustix::termios::tcgetwinsize;
use thiserror::Error;
use tokio::signal::ctrl_c;
use tokio::time::{MissedTickBehavior, interval};
use tokio::{pin, select};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::error::Error as WebSocketError;
use tokio_tungstenite::tungstenite::protocol::Role;

use sush_common::authn::{AuthnError, Challenge, ChallengeResponse, Credentials};
use sush_common::interactive::InteractiveSessionError;
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
use sush_common::jobs::{
    JobId, JobLimits, JobOutputHash, JobStartRequest, JobStatus, SessionId, SignedJob,
};
use sush_common::keys::{KeyError, KeyId, Signer as _};

use crate::ByteStream;
use crate::context::{CommandContext, OutputFormat};
use crate::identity::{IdentityError, SshAgentConnection};
use crate::interactive::interactive_session;
use crate::permslip::PermslipError;
use crate::permslip::{DEFAULT_PERMSLIP_URL, PermslipSigner};
use crate::repl::Repl;
use crate::types::Error as ApiError;
use crate::{Client, Error as ClientError};

// Names of environment variables for argument defaults
// (to prevent mispellings).
pub const PERMSLIP_URL: &str = "PERMSLIP_URL";
pub const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";
pub const SUSH_JOB_ID: &str = "SUSH_JOB_ID";
pub const SUSH_KEY_ID: &str = "SUSH_KEY_ID";
pub const SUSH_MAX_CPU: &str = "SUSH_MAX_CPU";
pub const SUSH_MAX_MEM: &str = "SUSH_MAX_MEM";
pub const SUSH_MAX_FSIZE: &str = "SUSH_MAX_FSIZE";
pub const SUSH_PERMSLIP_KEY: &str = "SUSH_PERMSLIP_KEY";
pub const SUSH_OUTPUT_FORMAT: &str = "SUSH_OUTPUT_FORMAT";
pub const SUSH_URL: &str = "SUSH_URL";

/// Default chunk size for parallel downloads of large output.
const DEFAULT_CHUNK_SIZE: ByteSize = ByteSize::mib(32);

/// Default number of elements in a page of results.
const DEFAULT_PAGE_LIMIT: NonZeroU32 = NonZeroU32::new(100).unwrap();

/// Default number of simultaneous downloads for large output.
const PARALLEL_CHUNKS: NonZeroU8 = NonZeroU8::new(8).unwrap();

/// Process limits for job execution.
#[derive(Clone, Debug, Parser)]
pub struct LimitArgs {
    /// Maximum CPU use in seconds.
    #[arg(long, env = SUSH_MAX_CPU)]
    pub max_cpu: Option<u64>,

    /// Maximum size of address space in bytes.
    #[arg(long, env = SUSH_MAX_MEM)]
    pub max_mem: Option<u64>,

    /// Maximum file size in bytes.
    #[arg(long, env = SUSH_MAX_FSIZE)]
    pub max_fsize: Option<u64>,
}

impl LimitArgs {
    pub fn as_limits(&self) -> JobLimits {
        let Self {
            max_cpu,
            max_mem,
            max_fsize,
        } = self;
        let defaults = JobLimits::default();
        JobLimits {
            max_cpu: max_cpu.unwrap_or(defaults.max_cpu),
            max_mem: max_mem.unwrap_or(defaults.max_mem),
            max_fsize: max_fsize.unwrap_or(defaults.max_fsize),
        }
    }
}

/// Optional global arguments, i.e., ones that apply to every command.
#[derive(Clone, Debug, Parser)]
pub struct GlobalArgs {
    /// Output format
    #[arg(long,
          env = SUSH_OUTPUT_FORMAT,
          default_value = "text",
          default_value_if("json", "true", "json"),
          default_value_if("text", "true", "text"),
          name = "FORMAT",
          value_enum)]
    #[clap(global = true)]
    pub output: Option<OutputFormat>,

    /// Shortcut for `--output=json`
    #[arg(short, long, default_value_t = false, conflicts_with = "text")]
    #[clap(global = true)]
    pub json: bool,

    /// Shortcut for `--output=text`
    #[arg(short, long, default_value_t = false, conflicts_with = "json")]
    #[clap(global = true)]
    pub text: bool,

    /// Support Shell HTTP API address for online mode
    #[arg(short, long, env = SUSH_URL)]
    #[clap(global = true)]
    pub url: Option<String>,

    /// Offline mode, i.e., job signing only
    #[arg(long, default_value_t = false, conflicts_with = "url")]
    #[clap(global = true)]
    pub offline: bool,

    /// Path to the SSH authentication agent Unix-domain socket.
    #[arg(long, env = SSH_AUTH_SOCK)]
    pub ssh_auth_sock: Option<String>,

    /// Authenticate as this SSH identity (try `iam -l` for a list).
    #[arg(short, long, env = SUSH_KEY_ID)]
    pub ssh_key_id: Option<KeyId>,
}

#[derive(Debug, Parser)]
#[clap(name = "Oxide Support Shell")]
#[clap(author = "Oxide Computer Company")]
#[clap(about, version)]
pub struct ClientArgs {
    #[clap(flatten)]
    globals: GlobalArgs,

    #[clap(subcommand)]
    command: ClientCommand,
}

impl ClientArgs {
    pub async fn execute(&mut self, ctx: &mut impl CommandContext) -> Result<(), CommandError> {
        self.command.clone().execute(ctx, &mut self.globals).await
    }
}

/// Arguments for `job-stdout` and `job-stderr`.
#[derive(Clone, Debug, Parser)]
pub struct JobOutput {
    /// The job whose output should be fetched.
    #[clap(env = SUSH_JOB_ID)]
    job_id: JobId,

    /// Job output is binary, not UTF-8 encoded text.
    #[arg(short, long, default_value_t = false, conflicts_with = "file")]
    binary: bool,

    /// File that output should be written to.
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Overwrite output file if it exists.
    #[arg(long, requires = "file")]
    force: bool,

    /// Chunk size for parallel downloads of large output.
    #[arg(short, long, default_value_t = DEFAULT_CHUNK_SIZE, requires = "file")]
    chunk_size: ByteSize,

    /// Number of simultaneous downloads for large output [max: 255].
    #[arg(short, long, default_value_t = PARALLEL_CHUNKS, requires = "file")]
    parallel: NonZeroU8,

    /// Size to which output should be truncated *on the server*.
    ///
    /// WARNING: Destructive and irreversible! Subsequent downloads of this
    /// output will show a hash mismatch to warn that this has taken place.
    #[arg(long, conflicts_with = "file")]
    truncate: Option<ByteSize>,
}

/// Support Shell job management command
#[derive(Clone, Debug, Subcommand)]
pub enum ClientCommand {
    /// Job-signing certificate management.
    Cert {
        #[clap(subcommand)]
        command: CertCommand,
    },

    /// Identity and access management.
    #[clap(alias = "whoami")]
    Iam {
        #[clap(subcommand)]
        command: Option<IdentityCommand>,

        /// Shortcut for `iam available`
        #[arg(short = 'l')]
        available: bool,

        /// Shortcut for `iam revoke <KEY_ID>`
        #[arg(short = 'r', name = "KEY_ID", conflicts_with = "available")]
        revoke: Option<KeyId>,
    },

    /// Session management.
    Session {
        #[clap(subcommand)]
        command: Option<SessionCommand>,
    },

    /// Job management.
    Job {
        #[clap(subcommand)]
        command: JobCommand,
    },

    /// Arguments for subsequent interactive commands.
    Set {
        #[clap(flatten)]
        args: GlobalArgs,
    },

    /// Start an interactive REPL.
    #[clap(alias = "repl")]
    Shell,

    /// Leave the interactive REPL.
    #[clap(alias = "exit")]
    Quit,
}

#[derive(Clone, Debug, Subcommand)]
pub enum CertCommand {
    /// Import a certificate, verify its signature, and return a key ID for it.
    Import { path: PathBuf },

    /// Get the certificate chain that validates a key, in root-to-leaf order.
    Chain { key_id: KeyId },
}

#[derive(Clone, Debug, Default, Subcommand)]
pub enum IdentityCommand {
    /// List available local SSH agent identities.
    /// Does not communicate with the server.
    Available,

    /// List SSH identities registered with the server.
    List {
        /// The number of identities per page of results.
        #[arg(short, long, default_value_t = DEFAULT_PAGE_LIMIT)]
        limit: NonZeroU32,
    },

    /// Log in to the server as an SSH identity.
    #[default]
    Login,

    /// Revoke an SSH identity.
    Revoke {
        /// The identity to be revoked.
        #[clap(name = "KEY_ID")]
        revoke: KeyId,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum SessionCommand {
    /// Start a new support session.
    Start { session_id: Option<SessionId> },

    /// Stop a support session.
    Stop {
        /// The session to stop.
        session_id: Option<SessionId>,
    },
}

impl Default for SessionCommand {
    fn default() -> Self {
        Self::Start { session_id: None }
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum JobCommand {
    /// Sign and start a job.
    Start {
        #[clap(flatten)]
        start_args: JobStartArgs,
    },

    /// Stop a (running) job.
    #[clap(alias = "abort")]
    Stop {
        /// The job to abort.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Get the status of a started job.
    Status {
        /// The job whose status should be fetched.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Get the standard output of a job.
    #[clap(alias = "output")]
    Stdout {
        #[clap(flatten)]
        output: JobOutput,
    },

    /// Get the standard error of a job.
    #[clap(alias = "error")]
    Stderr {
        #[clap(flatten)]
        output: JobOutput,
    },

    /// Connect to a running interactive job.
    Session {
        /// The job to connect to.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Show status of previously started jobs.
    History {
        /// How many history entries to fetch in total, or 0 for all.
        #[arg(short, long, default_value_t = 0)]
        limit: usize,
    },
}

#[derive(Clone, Debug, Parser)]
pub struct JobStartArgs {
    #[clap(flatten)]
    limits: LimitArgs,

    /// The command for the job to run. Passed as an argument to
    /// `bash -c`, so may be an arbitrary bash(1) command or pipeline.
    /// Be sure to quote spaces and characters special to your shell!
    command: Option<String>,

    /// Job ID within the session.
    job_id: Option<JobId>,

    /// Job output is binary, not UTF-8 encoded text.
    #[arg(short, long, default_value_t = false, requires = "wait")]
    binary: bool,

    /// Run the job with a pseudoterminal and allow interactive sessions.
    #[arg(short, long, env = SUSH_KEY_ID, name = "KEY_ID")]
    interactive: bool,

    /// Use `permslip` to sign job requests with this key name.
    #[arg(short, long, env = SUSH_PERMSLIP_KEY, name = "KEY_NAME")]
    permslip: Option<String>,

    /// The `permslip` server to contact for signing.
    #[arg(long, env = PERMSLIP_URL, default_value = DEFAULT_PERMSLIP_URL)]
    permslip_url: String,

    /// Terminal type for interactive jobs.
    #[arg(long, env = "TERM")]
    term: Option<String>,

    /// Wait for the job to end and display its output.
    #[arg(short, long, default_value_if("interactive", "true", "true"))]
    wait: bool,
}

impl ClientCommand {
    #[async_recursion]
    pub async fn execute(
        self,
        ctx: &mut impl CommandContext,
        args: &mut GlobalArgs,
    ) -> Result<(), CommandError> {
        if let Some(output) = args.output {
            ctx.set_output_format(output);
        }

        let client = args.url.as_ref().map(|url| Client::new(url));
        match (self, client) {
            (ClientCommand::Cert { command }, Some(client)) => {
                cert(ctx, &client, &args.ssh_auth_sock, &args.ssh_key_id, command).await
            }

            (
                ClientCommand::Iam {
                    command,
                    available,
                    revoke,
                },
                Some(client),
            ) => {
                iam(
                    ctx,
                    &client,
                    &args.ssh_auth_sock,
                    &args.ssh_key_id,
                    command.unwrap_or_else(|| {
                        if available {
                            IdentityCommand::Available
                        } else if let Some(revoke) = revoke {
                            IdentityCommand::Revoke { revoke }
                        } else {
                            IdentityCommand::default()
                        }
                    }),
                )
                .await
            }

            (ClientCommand::Session { command }, client) => {
                session(
                    ctx,
                    &client,
                    &args.ssh_auth_sock,
                    &args.ssh_key_id,
                    command.unwrap_or_default(),
                )
                .await
            }

            (ClientCommand::Job { command }, client) => {
                job(ctx, &client, &args.ssh_auth_sock, &args.ssh_key_id, command).await
            }

            (ClientCommand::Set { args: values }, _) => {
                ctx.set_globals(args, values);
                Ok(())
            }

            (ClientCommand::Shell, client) => {
                Repl::default().run(args, client).await?;
                Ok(())
            }

            (ClientCommand::Quit, _) => Err(CommandError::Quit),

            (_, None) => Err(CommandError::Offline),
        }
    }
}

macro_rules! with_authz {
    ($ctx:ident, $client:ident, $ssh_auth_sock:expr, $ssh_key_id:expr, $authz:ident => $req:expr) => {
        loop {
            let $authz = $ctx
                .get_identity()
                .map(|i| i.to_owned().into_credentials().to_string())
                .unwrap_or_default();

            match $req.await {
                Err(ClientError::ErrorResponse(err))
                    if err.status() == StatusCode::UNAUTHORIZED =>
                {
                    let mut ssh_agent = if let Some(ssh_auth_sock) = $ssh_auth_sock {
                        SshAgentConnection::connect(ssh_auth_sock).await?
                    } else {
                        return Err(CommandError::MissingSshAuthSock);
                    };
                    let public_key = ssh_agent.identity($ssh_key_id).await?;
                    let challenge = err
                        .headers()
                        .get(WWW_AUTHENTICATE)
                        .ok_or(CommandError::InvalidAuthorization)?
                        .to_str()
                        .map_err(|_| CommandError::InvalidAuthorization)?
                        .parse::<Challenge>()?;
                    let response = ChallengeResponse::new(challenge);
                    $ctx.please_touch(&public_key)?;
                    let signed = select! {
                        s = ssh_agent.sign(response) => s?,
                        _ = ctrl_c() => return Err(CommandError::Canceled),
                    };
                    let verified = signed.verify_with_ssh_public_key(&public_key)?;
                    let credentials = Credentials::new(verified);
                    let identity = $client
                        .iam()
                        .authorization(credentials.to_string())
                        .body(public_key.to_string())
                        .send()
                        .await?
                        .into_inner();
                    $ctx.set_identity(Some(identity));
                }
                res => break res,
            }
        }
    };
}

async fn iam(
    ctx: &mut impl CommandContext,
    client: &Client,
    ssh_auth_sock: &Option<String>,
    ssh_key_id: &Option<KeyId>,
    command: IdentityCommand,
) -> Result<(), CommandError> {
    match command {
        IdentityCommand::Available => {
            let mut ssh_agent = if let Some(ssh_auth_sock) = ssh_auth_sock {
                SshAgentConnection::connect(ssh_auth_sock).await?
            } else {
                return Err(CommandError::MissingSshAuthSock);
            };
            let mut keys = Vec::new();
            for key in ssh_agent.list_identities().await? {
                if let Some(key_id) = ssh_key_id
                    && key.key_id()? != *key_id
                {
                    continue;
                }
                keys.push(key);
            }
            ctx.identities(&keys)
        }

        IdentityCommand::List { limit } => {
            let mut page = with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client
                    .identities()
                    .limit(limit)
                    .authorization(&authz)
                    .send()
            )?
            .into_inner();
            loop {
                for identity in &page.items {
                    ctx.iam(identity)?;
                }
                if let Some(next_page) = page.next_page
                    && ctx.more()
                {
                    page = with_authz!(
                        ctx,
                        client,
                        ssh_auth_sock,
                        ssh_key_id.as_ref(),
                        authz => client
                            .identities()
                            .authorization(&authz)
                            .limit(limit)
                            .page_token(&next_page)
                            .send()
                    )?
                    .into_inner();
                } else {
                    break Ok(());
                }
            }
        }

        IdentityCommand::Login => {
            ctx.set_identity(None);
            let identity = with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client.iam().authorization(&authz).body(None).send()
            )?
            .into_inner();
            ctx.iam(&identity)
        }

        IdentityCommand::Revoke { revoke } => {
            let revoke = ctx.really_revoke(revoke)?;
            with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client
                    .revoke_identity()
                    .authorization(&authz)
                    .key_id(&revoke)
                    .send()
            )?;
            ctx.identity_revoked(revoke)
        }
    }
}

async fn cert(
    ctx: &mut impl CommandContext,
    client: &Client,
    ssh_auth_sock: &Option<String>,
    ssh_key_id: &Option<KeyId>,
    command: CertCommand,
) -> Result<(), CommandError> {
    match command {
        CertCommand::Import { path } => {
            let io_error = |error| CommandError::io(&path, error);
            let mut file = File::open(&path).map_err(io_error)?;
            let mut cert = Vec::new();
            file.read_to_end(&mut cert).map_err(io_error)?;
            let key_id = with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client
                    .import_cert()
                    .authorization(authz)
                    .body(cert.clone())
                    .send()
            )?
            .into_inner();
            ctx.cert_imported(&path, key_id)
        }

        CertCommand::Chain { key_id } => {
            let certs = with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client
                    .cert_chain()
                    .authorization(authz)
                    .key_id(&key_id)
                    .send()
            )?
            .into_inner();
            ctx.cert_chain(key_id, &certs)
        }
    }
}

async fn session(
    ctx: &mut impl CommandContext,
    client: &Option<Client>,
    ssh_auth_sock: &Option<String>,
    ssh_key_id: &Option<KeyId>,
    command: SessionCommand,
) -> Result<(), CommandError> {
    match (command, client) {
        (SessionCommand::Start { session_id: None }, Some(client)) => {
            let session_id = with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client
                    .session_start()
                    .authorization(&authz)
                    .send()
            )?
            .into_inner();
            ctx.session_started(&session_id)?;
            Ok(())
        }

        (
            SessionCommand::Start {
                session_id: Some(session_id),
            },
            _,
        ) => {
            ctx.session_started(&session_id)?;
            Ok(())
        }

        (SessionCommand::Stop { session_id }, Some(client)) => {
            let ctx_session_id = ctx.session_id().cloned();
            let Some(session_id) = session_id.as_ref().or(ctx_session_id.as_ref()) else {
                return Err(CommandError::MissingSession);
            };
            with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client
                    .session_stop()
                    .session_id(session_id.clone())
                    .authorization(&authz)
                    .send()
            )?;
            ctx.session_stopped(session_id)?;
            Ok(())
        }

        (_, None) => Err(CommandError::Offline),
    }
}

async fn job(
    ctx: &mut impl CommandContext,
    client: &Option<Client>,
    ssh_auth_sock: &Option<String>,
    ssh_key_id: &Option<KeyId>,
    command: JobCommand,
) -> Result<(), CommandError> {
    match (command, client) {
        (JobCommand::Start { start_args }, Some(client))
            if start_args.command.is_none() && start_args.permslip.is_none() =>
        {
            let job = ctx.read_signed_job()?;
            job_start(ctx, client, ssh_auth_sock, ssh_key_id, job, start_args).await?;
            Ok(())
        }

        (
            JobCommand::Start {
                start_args: JobStartArgs { command: None, .. },
                ..
            },
            Some(_),
        ) => Err(CommandError::MissingCommand),

        (
            JobCommand::Start {
                start_args: JobStartArgs { permslip: None, .. },
                ..
            },
            Some(_),
        ) => Err(CommandError::MissingKeyName),

        (
            JobCommand::Start {
                start_args:
                    ref start_args @ JobStartArgs {
                        command: Some(ref command),
                        permslip: Some(ref key_name),
                        ref job_id,
                        ref permslip_url,
                        ref interactive,
                        ..
                    },
            },
            client,
        ) => {
            let job_id = if let Some(job_id) = job_id {
                job_id.to_owned()
            } else {
                ctx.next_job_id()?
            };
            let mut signer = PermslipSigner::new(key_name, permslip_url).await?;
            let mut interval = interval(Duration::from_millis(100));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let sign = signer.sign(JobStartRequest::new(
                job_id.to_owned(),
                command,
                *interactive,
            ));
            pin!(sign);
            ctx.job_signing_started(&job_id)?;
            let job = loop {
                select! {
                    job = &mut sign => {
                        ctx.job_signing_finished(&job_id)?;
                        break job?;
                    }
                    _ = interval.tick() => ctx.job_signing_update(&job_id)?,
                    _ = ctrl_c() => return ctx.job_signing_finished(&job_id),
                }
            };
            if let Some(client) = client {
                ctx.job_signed(&job, false)?;
                job_start(
                    ctx,
                    client,
                    ssh_auth_sock,
                    ssh_key_id,
                    job,
                    start_args.to_owned(),
                )
                .await
            } else {
                ctx.job_signed(&job, true)
            }
        }

        (JobCommand::Stop { job_id }, Some(client)) => {
            with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client
                    .job_stop()
                    .job_id(&job_id)
                    .authorization(&authz)
                    .send()
            )?;
            ctx.job_stopped(&job_id)
        }

        (JobCommand::Status { job_id }, Some(client)) => {
            let status = with_authz!(
                ctx,
                client,
                ssh_auth_sock,
                ssh_key_id.as_ref(),
                authz => client
                    .job_status()
                    .job_id(&job_id)
                    .authorization(&authz)
                    .send()
            )?
            .into_inner();
            ctx.job_status(&job_id, &status)
        }

        (JobCommand::Stdout { output }, Some(client)) => {
            job_output(ctx, client, ssh_auth_sock, ssh_key_id, Stdout, output).await
        }

        (JobCommand::Stderr { output }, Some(client)) => {
            job_output(ctx, client, ssh_auth_sock, ssh_key_id, Stderr, output).await
        }

        (JobCommand::Session { job_id }, Some(client)) => {
            job_start_interactive_session(ctx, client, ssh_auth_sock, ssh_key_id, &job_id).await
        }

        (JobCommand::History { limit: _ }, Some(_client)) => {
            todo!("paginated job history")
        }

        (_, None) => Err(CommandError::Offline),
    }
}

async fn job_start(
    ctx: &mut impl CommandContext,
    client: &Client,
    ssh_auth_sock: &Option<String>,
    ssh_key_id: &Option<KeyId>,
    job: SignedJob,
    start_args: JobStartArgs,
) -> Result<(), CommandError> {
    let Some(identity) = ctx.get_identity() else {
        // It's ok to bail here because if we haven't got an identity in
        // the context, we also won't have a session; `job start` is only
        // useful from the REPL.
        return Err(CommandError::InvalidAuthorization);
    };
    let authz = identity.into_credentials().to_string();
    let job_id = job.job_id().to_owned();
    let interactive = job.interactive();
    let JobStartArgs {
        limits,
        binary,
        term,
        wait,
        ..
    } = start_args;
    let JobLimits {
        max_cpu,
        max_mem,
        max_fsize,
    } = limits.as_limits();
    let mut start = client
        .job_start()
        .authorization(&authz)
        .job_id(&job_id)
        .max_cpu(max_cpu)
        .max_mem(max_mem)
        .max_fsize(max_fsize)
        .wait(wait && !interactive)
        .body(job.clone());
    if let Some(term) = term {
        start = start.term(term);
        if let Ok(winsize) = tcgetwinsize(stdin()) {
            start = start.rows(winsize.ws_row);
            start = start.cols(winsize.ws_col);
        }
    }
    let start = start.send();
    pin!(start);

    let status = if interactive {
        start.as_mut().await?;
        ctx.job_started(&job)?;
        job_start_interactive_session(ctx, client, ssh_auth_sock, ssh_key_id, &job_id).await?;
        client
            .job_status()
            .authorization(&authz)
            .job_id(&job_id)
            .send()
            .await?
            .into_inner()
    } else {
        let mut interval = interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ctx.job_polling_started(&job_id, interval.period())?;
        loop {
            select! {
                status = &mut start => {
                    ctx.job_polling_finished(&job_id)?;
                    let status = status?.into_inner();
                    ctx.job_started(&job)?;
                    break status;
                }
                _ = interval.tick() => {
                    let status = client
                        .job_status()
                        .authorization(&authz)
                        .job_id(&job_id)
                        .send()
                        .await?
                        .into_inner();
                    ctx.job_polling_update(&job_id, &status)?;
                }
                _ = ctrl_c() => {
                    client
                        .job_stop()
                        .authorization(&authz)
                        .job_id(&job_id)
                        .send()
                        .await?;
                    ctx.job_polling_finished(&job_id)?;
                    ctx.job_stopped(&job_id)?;
                    break client
                        .job_status()
                        .authorization(&authz)
                        .job_id(&job_id)
                        .send()
                        .await?
                        .into_inner();
                }
            }
        }
    };
    ctx.job_status(&job_id, &status)?;
    if wait {
        for stream in [Stdout, Stderr] {
            match client
                .job_output()
                .authorization(&authz)
                .job_id(&job_id)
                .stream(stream)
                .send()
                .await
            {
                Ok(byte_stream) => {
                    let output = byte_stream_to_vec(byte_stream.into_inner()).await?;
                    ctx.job_output(&job_id, stream, &output, binary)?;
                }
                Err(error) => ctx.job_error(error.into())?,
            }
        }
    }
    Ok(())
}

/// Stream some bytes into a vector.
async fn byte_stream_to_vec(mut stream: ByteStream) -> Result<Vec<u8>, CommandError> {
    let mut output = Vec::new();
    while let Some(bytes) = stream.next().await {
        output.extend(bytes?);
    }
    Ok(output)
}

/// Inclusive byte range for requesting job output.
#[derive(Debug)]
struct Range {
    start: u64,
    end: u64,
}

impl Range {
    fn bytes(&self) -> String {
        format!("bytes={}-{}", self.start, self.end)
    }

    fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

/// Some bytes for a range of job output.
struct Chunk(Range, ByteStream);

/// A promise of some bytes for a range of output.
type FutureChunk<'a> = dyn Future<Output = Result<Chunk, CommandError>> + Send + 'a;

/// Download or truncate job output.
async fn job_output(
    ctx: &mut impl CommandContext,
    client: &Client,
    ssh_auth_sock: &Option<String>,
    ssh_key_id: &Option<KeyId>,
    stream: JobOutputStream,
    JobOutput {
        job_id,
        binary,
        file,
        force,
        chunk_size,
        parallel,
        truncate,
    }: JobOutput,
) -> Result<(), CommandError> {
    // Maybe truncate instead of fetching output.
    if let Some(n) = truncate.map(|n| n.as_u64()) {
        with_authz!(
            ctx,
            client,
            ssh_auth_sock,
            ssh_key_id.as_ref(),
            authz => client
                .job_output_delete()
                .authorization(&authz)
                .job_id(&job_id)
                .stream(stream)
                .range(format!("bytes={n}-"))
                .send()
        )?;
        return Ok(());
    }

    // Fetch job status for output length and hash.
    let JobStatus::Ended {
        stdout_len,
        stderr_len,
        stdout_hash,
        stderr_hash,
        ..
    } = with_authz!(
        ctx,
        client,
        ssh_auth_sock,
        ssh_key_id.as_ref(),
        authz => client
            .job_status()
            .authorization(authz)
            .job_id(&job_id)
            .send()
    )?
    .into_inner()
    else {
        // TODO: emulate `tail -f` for running jobs
        return Err(CommandError::JobStillRunning(job_id.to_owned()));
    };
    let len = match stream {
        Stdout => stdout_len,
        Stderr => stderr_len,
    };
    let expected_hash = match stream {
        Stdout => stdout_hash,
        Stderr => stderr_hash,
    };

    macro_rules! check_hash {
        ($hash:expr, $stage:expr) => {{
            let expected = expected_hash;
            let received = $hash.into();
            if received == expected {
                ctx.job_output_finished(&job_id, stream, $stage)
            } else {
                let _ = ctx.job_output_finished(&job_id, stream, None);
                Err(CommandError::OutputHashMismatch { expected, received })
            }
        }};
    }

    if let Some(path) = file {
        // Save the output to a file, downloading in chunks.
        let Some(chunk_size) = NonZeroU64::new(chunk_size.as_u64()) else {
            return Err(CommandError::ChunkSizeZero);
        };

        // Open the output file.
        let io_error = |error| CommandError::io(&path, error);
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut file = options.open(&path).map_err(io_error)?;

        // Download and write the output in parallel (unordered) chunks.
        ctx.job_output_started(&job_id, stream, "Downloading", len)?;
        let Some(identity) = ctx.get_identity() else {
            return Err(CommandError::InvalidAuthorization);
        };
        let authz = identity.into_credentials().to_string();
        let chunks = job_output_chunks(client, &authz, &job_id, stream, len, chunk_size);
        let par = parallel.get() as usize;
        let mut chunks_par = stream::iter(chunks).buffer_unordered(par);
        while let Some(chunk) = chunks_par.next().await {
            let Chunk(range, bytes) = chunk?;
            ctx.job_output_update(&job_id, stream, range.len())?;
            byte_stream_to_file(&mut file, &path, bytes, range).await?;
        }
        file.flush().map_err(io_error)?;
        ctx.job_output_finished(&job_id, stream, Some("✅ Downloaded"))?;

        // Verify the output hash. Note that even if this verification fails,
        // we will leave the file as written. This provides a way of fetching
        // truncated outputs (with an error).
        let output = unsafe { Mmap::map(&file) }.map_err(io_error)?;
        if len < chunk_size.get() {
            check_hash!(hash(&output), None)
        } else {
            // Multi-threaded BLAKE3 is very, very fast, but still takes
            // perceptible time on multi-GB outputs. So if there's more
            // than one chunk, hash in chunks with a progress bar.
            ctx.job_output_started(&job_id, stream, "Verifying", len)?;
            let mut hasher = Hasher::new();
            for chunk in output.chunks(chunk_size.get() as usize) {
                hasher.update_rayon(chunk);
                ctx.job_output_update(&job_id, stream, chunk.len() as u64)?;
            }
            check_hash!(hasher.finalize(), Some("✅ Verified"))
        }
    } else {
        // Download and print the output all at once. If hash verification
        // fails here, do not print any output.
        let byte_stream = with_authz!(
            ctx,
            client,
            ssh_auth_sock,
            ssh_key_id.as_ref(),
            authz => client
                .job_output()
                .authorization(authz)
                .job_id(&job_id)
                .stream(stream)
                .send()
        )?
        .into_inner();
        let bytes = byte_stream_to_vec(byte_stream).await?;
        check_hash!(hash(&bytes), None)?;
        ctx.job_output(&job_id, stream, &bytes, binary)
    }
}

/// Prepare a vector of futures that fetch chunks of output.
fn job_output_chunks<'a>(
    client: &'a Client,
    authz: &'a str,
    job_id: &'a JobId,
    stream: JobOutputStream,
    len: u64,
    chunk_size: NonZeroU64,
) -> Vec<Pin<Box<FutureChunk<'a>>>> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < len {
        let end = (start + chunk_size.get() - 1).min(len - 1);
        let range = Range { start, end };
        chunks.push(
            async move {
                let bytes = range.bytes();
                let stream = client
                    .job_output()
                    .authorization(authz)
                    .job_id(job_id)
                    .stream(stream)
                    .range(&bytes)
                    .send()
                    .await?
                    .into_inner();
                Ok(Chunk(range, stream))
            }
            .boxed(),
        );
        start = end + 1;
    }
    chunks
}

/// Stream a range of bytes into an open file.
async fn byte_stream_to_file(
    file: &mut File,
    path: &Path,
    mut bytes: ByteStream,
    range: Range,
) -> Result<u64, CommandError> {
    let io_error = |error| CommandError::io(path, error);
    let Range { start, end: _ } = range;
    file.seek(SeekFrom::Start(start)).map_err(io_error)?;

    let mut n = 0;
    while let Some(bytes) = bytes.next().await {
        let bytes = bytes?;
        n += bytes.len() as u64;
        file.write_all(&bytes).map_err(io_error)?;
    }

    if n == range.len() {
        Ok(n)
    } else {
        Err(CommandError::LengthMismatch {
            expected: range.len(),
            received: n,
        })
    }
}

/// Connect via WebSockets to a running interactive job,
/// providing authentication via an SSH agent.
async fn job_start_interactive_session(
    ctx: &mut impl CommandContext,
    client: &Client,
    ssh_auth_sock: &Option<String>,
    ssh_key_id: &Option<KeyId>,
    job_id: &JobId,
) -> Result<(), CommandError> {
    match with_authz!(
        ctx,
        client,
        ssh_auth_sock,
        ssh_key_id.as_ref(),
        authz => client
            .job_start_interactive_session()
            .authorization(&authz)
            .job_id(job_id)
            .send()
    ) {
        Err(error) => ctx.job_error(error.into()),
        Ok(socket) => {
            ctx.job_session_connected(job_id)?;
            let socket = socket.into_inner();
            let stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
            if let Err(error) = interactive_session(stream).await {
                return ctx.job_error(CommandError::from(error));
            }
            ctx.job_session_disconnected(job_id)
        }
    }
}

/// What went wrong parsing, preparing, or executing a client command.
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("❌ Authentication error")]
    Authn(#[from] AuthnError),
    #[error("❌ Canceled")]
    Canceled,
    #[error("❌ Chunk size must be positive")]
    ChunkSizeZero,
    #[error("❓ {0}")]
    Clap(#[from] clap::Error),
    #[error("❌ {0}")]
    Client(String),
    #[error("❌ {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("❌ {0}")]
    DurationOutOfRange(#[from] chrono::OutOfRangeError),
    #[error("❌ Empty certificate chain")]
    EmptyCertChain,
    #[error("❌ Identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error(
        "❌ Identity mismatch,  tried to start an interactive job\n   \
            for `{interactive}`\n    \
             as `{key_id}`"
    )]
    IdentityMismatch { interactive: KeyId, key_id: KeyId },
    #[error("❌ I/O error accessing `{path}`: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("❌ Unauthorized, try `iam`")]
    InvalidAuthorization,
    #[error("❌ Leaf certificate does not match key `{0}`")]
    InvalidLeafCert(KeyId),
    #[error("❌ Unable to read reserved job IDs")]
    InvalidReservedJobs,
    #[error("❌ Root certificate is not self-signed")]
    InvalidRootCert,
    #[error("❌ Job `{0}` is still running")]
    JobStillRunning(JobId),
    #[error("❌ JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("❌ Key error: {0}")]
    Key(#[from] KeyError),
    #[error("❌ Length mismatch: expected {expected} bytes, received {received}")]
    LengthMismatch { expected: u64, received: u64 },
    #[error("❌ Missing job command, try `--help`")]
    MissingCommand,
    #[error("❌ Missing signing key name, try `--permslip`")]
    MissingKeyName,
    #[error("❌ Missing session, try `session start`")]
    MissingSession,
    #[error("❌ Missing SSH agent socket, try `--ssh-auth-sock`")]
    MissingSshAuthSock,
    #[error("❌ Command not supported in offline mode, try `--url`")]
    Offline,
    #[error(
        "❌ Hash mismatch, output may be truncated or corrupted\n   \
            Expected: {expected}\n   \
            Received: {received}"
    )]
    OutputHashMismatch {
        expected: JobOutputHash,
        received: JobOutputHash,
    },
    #[error("❌ permslip error: {0}")]
    Permslip(#[from] PermslipError),
    #[error("👋 Goodbye!")]
    Quit,
    #[error("❌ {0}")]
    Readline(#[from] rustyline::error::ReadlineError),
    #[error(transparent)]
    Recursive(#[from] Box<Self>),
    #[error("❌ Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("❌ Interactive session error: {0}")]
    Session(#[from] InteractiveSessionError),
    #[error("❌ SSH signature error on key ID `{0}`")]
    Signature(KeyId),
    #[error("❌ SSH key error: {0}")]
    SshKey(#[from] kms_agent_lib::ssh_key::Error),
    #[error("❌ Too much output to display on terminal, try `--file`")]
    TooMuchOutput,
    #[error("❌ Can't start interactive session: {0}")]
    Upgrade(String),
    #[error("❌ UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("❌ WebSocket error: {0}")]
    WebSocket(#[from] WebSocketError),
}

impl CommandError {
    /// Report I/O errors with the corresponding path or stream name.
    pub fn io(path: impl AsRef<Path>, error: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_owned(),
            error,
        }
    }
}

impl From<ClientError<ApiError>> for CommandError {
    fn from(error: ClientError<ApiError>) -> Self {
        use ClientError::*;
        match error {
            InvalidRequest(e) => CommandError::Client(format!("Invalid request: {e}")),
            CommunicationError(e) => CommandError::Client(format!("Communication error: {e}")),
            InvalidUpgrade(e) => CommandError::Client(e.to_string()),
            ErrorResponse(e) => CommandError::Client(e.message.to_owned()),
            ResponseBodyError(e) => CommandError::Client(e.to_string()),
            InvalidResponsePayload(_b, e) => CommandError::Client(e.to_string()),
            UnexpectedResponse(e) if e.status().is_redirection() => {
                if let Some(l) = e.headers().get("location") {
                    CommandError::Client(format!(
                        "Got {} to {}",
                        e.status(),
                        l.to_str().unwrap_or("?")
                    ))
                } else {
                    CommandError::Client(format!("Got {}", e.status()))
                }
            }
            UnexpectedResponse(e) => CommandError::Client(format!("Unexpected response: {e:?}")),
            Custom(e) => CommandError::Client(e.to_string()),
        }
    }
}

impl From<ClientError<ByteStream>> for CommandError {
    fn from(error: ClientError<ByteStream>) -> Self {
        match error.status() {
            Some(StatusCode::PAYLOAD_TOO_LARGE) => Self::TooMuchOutput,
            Some(status) => Self::Client(status.to_string()),
            None => Self::Client(error.to_string()),
        }
    }
}

impl From<ClientError<Upgraded>> for CommandError {
    fn from(error: ClientError<Upgraded>) -> Self {
        match error.status() {
            Some(status) => Self::Client(status.to_string()),
            None => Self::Client(error.to_string()),
        }
    }
}
