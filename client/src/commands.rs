//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _, stdin};
use std::num::{NonZeroU8, NonZeroU64};
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
use progenitor_client::ResponseValue;
use reqwest::Upgraded;
use rustix::termios::tcgetwinsize;
use sled_hardware_types::BaseboardId;
use thiserror::Error;
use tokio::signal::ctrl_c;
use tokio::time::{MissedTickBehavior, interval};
use tokio::{pin, select};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::error::Error as WebSocketError;
use tokio_tungstenite::tungstenite::protocol::Role;

use sush_api::JobWait;
use sush_common::authn::{AuthnError, Challenge, ChallengeResponse, Credentials, Identity};
use sush_common::interactive::InteractiveJobError;
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
use sush_common::jobs::{
    JobId, JobLimits, JobOutputHash, JobOutputState, JobStartRequest, JobStatus, Session,
    SessionId, SignedJob, job_status_try_from_json_map,
};
use sush_common::keys::{KeyError, KeyId, Signer as _};

use crate::ByteStream;
use crate::context::{CommandContext, OutputFormat};
use crate::identity::{IdentityError, SshAgentConnection};
use crate::interactive::interactive_job;
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

/// Default number of simultaneous downloads for large output.
const PARALLEL_CHUNKS: NonZeroU8 = NonZeroU8::new(8).unwrap();

// Spinner update intervals.
const JOB_START_UPDATE_INTERVAL: Duration = Duration::from_millis(250);
const SIGNING_UPDATE_INTERVAL: Duration = Duration::from_millis(100);

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
#[derive(Clone, Debug, Default, Parser)]
pub struct GlobalArgs {
    /// Output format
    #[arg(long,
          env = SUSH_OUTPUT_FORMAT,
          default_value = "text",
          default_value_if("json", "true", "json"),
          default_value_if("text", "true", "text"),
          value_name = "FORMAT",
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
    #[clap(global = true)]
    pub ssh_auth_sock: Option<String>,

    /// Authenticate as this SSH identity (try `iam -l` for a list).
    #[arg(short, long, env = SUSH_KEY_ID)]
    #[clap(global = true)]
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
        ctx.set_globals(self.globals.clone());
        self.command.clone().execute(ctx).await
    }
}

/// [`ClientArgs`] must satisfy Clap's internal consistency asserts
/// (unique shorts per subcommand, valid references).
#[test]
fn client_args() {
    use clap::CommandFactory as _;
    ClientArgs::command().debug_assert();
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
    List,

    /// Log in to the server as an SSH identity.
    #[default]
    Login,
}

#[derive(Clone, Debug, Subcommand)]
pub enum SessionCommand {
    /// Attach to a current support session.
    Attach { session_id: Option<SessionId> },

    /// Start a new support session.
    Start {
        /// The session to start.
        session_id: Option<SessionId>,
    },

    /// Stop a support session.
    Stop {
        /// The session to stop.
        session_id: Option<SessionId>,
    },
}

impl Default for SessionCommand {
    fn default() -> Self {
        Self::Attach { session_id: None }
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
        /// The baseboard ID of the sled from which output should be fetched.
        #[arg(short = 'T', long, default_value = "*")]
        target: String,

        #[clap(flatten)]
        output: JobOutput,
    },

    /// Get the standard error of a job.
    #[clap(alias = "error")]
    Stderr {
        /// The baseboard ID of the sled from which output should be fetched.
        #[arg(short = 'T', long, default_value = "*")]
        target: String,

        #[clap(flatten)]
        output: JobOutput,
    },

    /// Attach to an interactive job.
    Attach {
        /// The interactive job to attach to.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,

        /// The baseboard ID of the sled to attach to.
        #[arg(short = 'T', long, default_value = "*")]
        target: String,
    },

    /// Show status of previously started jobs.
    History {
        /// How many jobs' status to show.
        #[arg(short, long, default_value_t = 100)]
        limit: u32,

        /// Where in the list of jobs to start.
        #[arg(short, long, default_value_t = 0)]
        offset: u32,
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

    /// Run the job with a pseudoterminal and allow attaching to it.
    #[arg(short, long)]
    interactive: bool,

    /// Use `permslip` to sign job requests with this key name.
    #[arg(short, long, env = SUSH_PERMSLIP_KEY, value_name = "KEY_NAME")]
    permslip: Option<String>,

    /// The `permslip` server to contact for signing.
    #[arg(long, env = PERMSLIP_URL, default_value = DEFAULT_PERMSLIP_URL)]
    permslip_url: String,

    /// Terminal type for interactive jobs.
    #[arg(long, env = "TERM")]
    term: Option<String>,

    /// Wait for job start/stop and then attach/show output.
    #[arg(short, long, default_value_if("interactive", "true", "true"))]
    wait: bool,
}

impl ClientCommand {
    #[async_recursion(?Send)]
    pub async fn execute(self, ctx: &mut impl CommandContext) -> Result<(), CommandError> {
        let args = ctx.get_globals().to_owned();
        if let Some(output) = args.output {
            ctx.set_output_format(output);
        }

        let client = args.url.as_ref().map(|url| Client::new(url));
        match (self, client) {
            (ClientCommand::Cert { command }, Some(client)) => cert(ctx, &client, command).await,

            (ClientCommand::Iam { command, available }, Some(client)) => {
                iam(
                    ctx,
                    &client,
                    &args.ssh_auth_sock,
                    &args.ssh_key_id,
                    command.unwrap_or_else(|| {
                        if available {
                            IdentityCommand::Available
                        } else {
                            IdentityCommand::default()
                        }
                    }),
                )
                .await
            }

            (ClientCommand::Session { command }, client) => {
                session(ctx, &client, command.unwrap_or_default()).await
            }

            (ClientCommand::Job { command }, client) => job(ctx, &client, command).await,

            (ClientCommand::Set { args }, _) => {
                ctx.set_globals(args);
                Ok(())
            }

            (ClientCommand::Shell, client) => {
                Repl::default().run(args.clone(), client).await?;
                Ok(())
            }

            (ClientCommand::Quit, _) => Err(CommandError::Quit),

            (_, None) => Err(CommandError::Offline),
        }
    }
}

async fn authenticate<E>(
    ctx: &mut impl CommandContext,
    client: &Client,
    response: ResponseValue<E>,
) -> Result<(Identity, Credentials), CommandError> {
    let mut ssh_agent = if let Some(ssh_auth_sock) = &ctx.get_globals().ssh_auth_sock {
        SshAgentConnection::connect(ssh_auth_sock).await?
    } else {
        return Err(CommandError::MissingSshAuthSock);
    };
    let public_key = ssh_agent
        .identity(ctx.get_globals().ssh_key_id.as_ref())
        .await?;
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .ok_or(CommandError::InvalidAuthorization)?
        .to_str()
        .map_err(|_| CommandError::InvalidAuthorization)?
        .parse::<Challenge>()?;
    let response = ChallengeResponse::new(challenge);
    ctx.please_touch(&public_key)?;
    let signed = select! {
        s = ssh_agent.sign(response) => s?,
        _ = ctrl_c() => return Err(CommandError::Canceled),
    };
    let verified = signed.verify_with_ssh_public_key(&public_key)?;
    let credentials = Credentials::new(verified);
    let identity = client
        .iam()
        .authorization(credentials.to_string())
        .body(public_key.to_string())
        .send()
        .await?
        .into_inner();
    Ok((identity, credentials))
}

/// Retry a request with transparent authorization.
async fn with_authz<T, E, Req>(
    ctx: &mut impl CommandContext,
    client: &Client,
    mut make_request: Req,
) -> Result<T, CommandError>
where
    Req: AsyncFnMut(&str) -> Result<T, ClientError<E>>,
    CommandError: From<ClientError<E>>,
{
    let authz = ctx
        .get_credentials()
        .map(|creds| creds.to_string())
        .unwrap_or_default();
    match make_request(&authz).await {
        Err(ClientError::ErrorResponse(err)) if err.status() == StatusCode::UNAUTHORIZED => {
            let (_identity, credentials) = authenticate(ctx, client, err).await?;
            let authz = credentials.to_string();
            ctx.set_credentials(Some(credentials));
            Ok(make_request(&authz).await?)
        }
        Err(err) => Err(err.into()),
        Ok(res) => Ok(res),
    }
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

        IdentityCommand::List => {
            let identities = with_authz(ctx, client, async |authz| {
                client.identities().authorization(authz).send().await
            })
            .await?
            .into_inner();
            for identity in identities {
                ctx.iam(&identity)?;
            }
            Ok(())
        }

        IdentityCommand::Login => {
            let identity = with_authz(ctx, client, async |authz| {
                client.iam().authorization(authz).body(None).send().await
            })
            .await?
            .into_inner();
            ctx.iam(&identity)
        }
    }
}

async fn cert(
    ctx: &mut impl CommandContext,
    client: &Client,
    command: CertCommand,
) -> Result<(), CommandError> {
    match command {
        CertCommand::Import { path } => {
            let io_error = |error| CommandError::io(&path, error);
            let mut file = File::open(&path).map_err(io_error)?;
            let mut cert = Vec::new();
            file.read_to_end(&mut cert).map_err(io_error)?;
            let key_id = with_authz(ctx, client, async |authz| {
                client
                    .import_cert()
                    .authorization(authz)
                    .body(cert.clone())
                    .send()
                    .await
            })
            .await?
            .into_inner();
            ctx.cert_imported(&path, key_id)
        }

        CertCommand::Chain { key_id } => {
            let certs = with_authz(ctx, client, async |authz| {
                client
                    .cert_chain()
                    .key_id(&key_id)
                    .authorization(authz)
                    .send()
                    .await
            })
            .await?
            .into_inner();
            ctx.cert_chain(key_id, &certs)?;
            Ok(())
        }
    }
}

async fn session(
    ctx: &mut impl CommandContext,
    client: &Option<Client>,
    command: SessionCommand,
) -> Result<(), CommandError> {
    match (command, client) {
        (SessionCommand::Attach { session_id }, Some(client)) => {
            let session = with_authz(ctx, client, async |authz| {
                client.session().authorization(authz).send().await
            })
            .await?
            .into_inner();
            if let Some(session_id) = session_id
                && *session.session_id() != session_id
            {
                return Err(CommandError::MissingSession);
            }
            ctx.session_started(session)?;
            Ok(())
        }

        (
            SessionCommand::Attach {
                session_id: Some(session_id),
            },
            None,
        ) => {
            ctx.session_started(Session::new(session_id))?;
            Ok(())
        }

        (SessionCommand::Start { session_id }, Some(client)) => {
            let session = if let Some(session_id) = session_id {
                Session::new(session_id)
            } else {
                Session::new(SessionId::new())
            };
            with_authz(ctx, client, async |authz| {
                client
                    .session_start()
                    .session_id(session.session_id())
                    .authorization(authz)
                    .send()
                    .await
            })
            .await?
            .into_inner();
            ctx.session_started(session)?;
            Ok(())
        }

        (SessionCommand::Stop { session_id }, Some(client)) => {
            let ctx_session_id = ctx.session_id();
            let Some(session_id) = session_id.as_ref().or(ctx_session_id.as_ref()) else {
                return Err(CommandError::MissingSession);
            };
            with_authz(ctx, client, async |authz| {
                client
                    .session_stop()
                    .session_id(session_id.clone())
                    .authorization(authz)
                    .send()
                    .await
            })
            .await?;
            ctx.session_stopped(session_id)?;
            Ok(())
        }

        (_, None) => Err(CommandError::Offline),
    }
}

async fn job(
    ctx: &mut impl CommandContext,
    client: &Option<Client>,
    command: JobCommand,
) -> Result<(), CommandError> {
    match (command, client) {
        (JobCommand::Start { start_args }, Some(client))
            if start_args.command.is_none() && start_args.permslip.is_none() =>
        {
            let job = ctx.read_signed_job()?;
            job_start(ctx, client, job, start_args).await?;
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
                // Ensure we have a session for the job.
                if ctx.session_id().is_none()
                    && let Some(client) = client
                {
                    let session = match with_authz(ctx, client, async |authz| {
                        client.session().authorization(authz).send().await
                    })
                    .await
                    {
                        Ok(resp) => resp.into_inner(),
                        Err(CommandError::NotFound) => {
                            let session = Session::new(SessionId::new());
                            with_authz(ctx, client, async |authz| {
                                client
                                    .session_start()
                                    .session_id(session.session_id())
                                    .authorization(authz)
                                    .send()
                                    .await
                            })
                            .await?;
                            session
                        }
                        Err(err) => return Err(err),
                    };
                    ctx.session_started(session)?;
                }
                ctx.next_job_id()?
            };

            let mut signer = PermslipSigner::new(key_name, permslip_url).await?;
            let mut interval = interval(SIGNING_UPDATE_INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let sign = signer.sign(JobStartRequest::new(
                job_id.to_owned(),
                command,
                *interactive,
            ));
            pin!(sign);
            ctx.job_signing_started(&job_id);
            let job = loop {
                select! {
                    job = &mut sign => {
                        ctx.job_signing_finished(&job_id);
                        break job?;
                    }
                    _ = interval.tick() => ctx.job_signing_update(&job_id),
                    _ = ctrl_c() => {
                        ctx.job_signing_finished(&job_id);
                        return Err(CommandError::Canceled);
                    }
                }
            };
            if let Some(client) = client {
                ctx.job_signed(&job, false);
                job_start(ctx, client, job, start_args.to_owned()).await
            } else {
                ctx.job_signed(&job, true);
                ctx.job_started(&job);
                Ok(())
            }
        }

        (JobCommand::Stop { job_id }, Some(client)) => job_stop(ctx, client, &job_id).await,

        (JobCommand::Status { job_id }, Some(client)) => job_status(ctx, client, &job_id).await,

        (JobCommand::Stdout { target, output }, Some(client)) => {
            let target = resolve_target(ctx, client, &target).await?;
            job_output(ctx, client, &target, Stdout, output).await
        }

        (JobCommand::Stderr { target, output }, Some(client)) => {
            let target = resolve_target(ctx, client, &target).await?;
            job_output(ctx, client, &target, Stderr, output).await
        }

        (JobCommand::Attach { job_id, target }, Some(client)) => {
            let target = resolve_target(ctx, client, &target).await?;
            job_attach(ctx, client, &job_id, &target).await?;
            Ok(())
        }

        (JobCommand::History { limit, offset }, Some(client)) => {
            let history = with_authz(ctx, client, async |authz| {
                client
                    .job_history()
                    .limit(limit)
                    .offset(offset)
                    .authorization(authz)
                    .send()
                    .await
            })
            .await?
            .into_inner();
            for job in history {
                let status = job_status_try_from_json_map(job)
                    .map_err(CommandError::BaseboardIdParseError)?;
                if let Some(s) = status.values().next() {
                    ctx.job_status(s.job_id(), &status);
                }
            }
            Ok(())
        }

        (_, None) => Err(CommandError::Offline),
    }
}

async fn job_start(
    ctx: &mut impl CommandContext,
    client: &Client,
    job: SignedJob,
    start_args: JobStartArgs,
) -> Result<(), CommandError> {
    // Eventually, the target will be embedded in the signed job request.
    // But for now, just get it from the server.
    let target = resolve_target(ctx, client, "*").await?;

    // Set up the job request and parameters.
    let job_id = job.job_id().to_owned();
    let JobStartArgs {
        binary,
        limits,
        term,
        wait,
        ..
    } = start_args;
    let interactive = job.payload().interactive;
    let wait = if interactive {
        JobWait::Start
    } else if wait {
        JobWait::Stop
    } else {
        JobWait::None
    };
    let JobLimits {
        max_cpu,
        max_mem,
        max_fsize,
    } = limits.as_limits();
    let mut start_ctx = ctx.clone();
    let start = with_authz(&mut start_ctx, client, async |authz| {
        let mut start = client
            .job_start()
            .job_id(job.job_id())
            .max_cpu(max_cpu)
            .max_mem(max_mem)
            .max_fsize(max_fsize)
            .wait(wait)
            .authorization(authz)
            .body(job.clone());
        if let Some(term) = term.as_ref() {
            start = start.term(term);
        }
        if let Ok(winsize) = tcgetwinsize(stdin()) {
            start = start.rows(winsize.ws_row);
            start = start.cols(winsize.ws_col);
        }
        start.send().await
    });
    pin!(start);

    // Start the job.
    if interactive {
        start.await?;
        ctx.job_started(&job);
        match job_attach(ctx, client, &job_id, &target).await {
            Ok(()) | Err(CommandError::NotFound) => job_status(ctx, client, &job_id).await?,
            Err(error) => return Err(error),
        }
    } else if wait.is_some() {
        let mut interval = interval(JOB_START_UPDATE_INTERVAL);
        let mut stopped = false;
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ctx.job_polling_started(&job_id, interval.period());
        loop {
            select! {
                // Wait for the start request to finish.
                start_result = &mut start => {
                    if !stopped {
                        ctx.job_polling_finished(&job_id);
                    }
                    start_result?;
                    ctx.job_started(&job);
                    break;
                }

                // Periodically update the spinner.
                _ = interval.tick() => {
                    ctx.job_polling_update(&job_id);
                }

                // Stop the job on interrupt, but don't break out of
                // the select loop; we must wait for the start future
                // to resolve.
                _ = ctrl_c(), if !stopped => {
                    ctx.job_polling_finished(&job_id);
                    ctx.job_error(CommandError::Canceled);
                    job_stop(ctx, client, &job_id).await?;
                    stopped = true;
                }
            }
        }

        // Show the job status and output.
        job_status(ctx, client, &job_id).await?;
        for stream in [Stdout, Stderr] {
            match with_authz(ctx, client, async |authz| {
                client
                    .job_output()
                    .job_id(&job_id)
                    .target(target.to_string())
                    .stream(stream)
                    .authorization(authz)
                    .send()
                    .await
            })
            .await
            {
                Ok(byte_stream) => {
                    let output = byte_stream_to_vec(byte_stream.into_inner()).await?;
                    ctx.job_output(&job_id, stream, &output, binary);
                }
                Err(error) => return Err(ctx.job_error(error)),
            }
        }
    } else {
        start.await?;
        ctx.job_started(&job);
    }
    Ok(())
}

async fn job_stop(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
) -> Result<(), CommandError> {
    with_authz(ctx, client, async |authz| {
        client
            .job_stop()
            .job_id(job_id)
            .wait(JobWait::Stop)
            .authorization(authz)
            .send()
            .await
    })
    .await?;
    ctx.job_stopped(job_id);
    Ok(())
}

async fn job_status(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
) -> Result<(), CommandError> {
    let status = with_authz(ctx, client, async |authz| {
        client
            .job_status()
            .job_id(job_id)
            .authorization(authz)
            .send()
            .await
    })
    .await?
    .into_inner();
    ctx.job_status(
        job_id,
        &job_status_try_from_json_map(status).map_err(CommandError::BaseboardIdParseError)?,
    );
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
    target: &BaseboardId,
    stream: JobOutputStream,
    JobOutput {
        job_id,
        binary,
        file,
        force,
        chunk_size,
        parallel,
    }: JobOutput,
) -> Result<(), CommandError> {
    // Fetch job status for output length and hash.
    let status = job_status_try_from_json_map(
        with_authz(ctx, client, async |authz| {
            client
                .job_status()
                .job_id(&job_id)
                .authorization(authz)
                .send()
                .await
        })
        .await?
        .into_inner(),
    )
    .map_err(CommandError::BaseboardIdParseError)?;

    let JobOutputState {
        stdout_len,
        stderr_len,
        stdout_hash,
        stderr_hash,
    } = match status.get(target) {
        None => return Err(CommandError::NotFound),
        Some(JobStatus::Started { job_id, .. }) => {
            return Err(CommandError::JobStillRunning(job_id.to_owned()));
        }
        Some(JobStatus::Stopped { output, .. }) => output,
        Some(JobStatus::Error { error, .. }) => {
            return Err(CommandError::Process(error.to_owned()));
        }
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
            let expected = expected_hash.to_owned();
            let received = $hash.into();
            if received == expected {
                ctx.job_output_finished(&job_id, stream, $stage);
                Ok(())
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
        ctx.job_output_started(&job_id, stream, "Downloading", *len);
        let chunks = job_output_chunks(ctx, client, &job_id, target, stream, *len, chunk_size);
        let par = parallel.get() as usize;
        let mut chunks_par = stream::iter(chunks).buffer_unordered(par);
        while let Some(chunk) = chunks_par.next().await {
            let Chunk(range, bytes) = chunk?;
            ctx.job_output_update(&job_id, stream, range.len());
            byte_stream_to_file(&mut file, &path, bytes, range).await?;
        }
        file.flush().map_err(io_error)?;
        ctx.job_output_finished(&job_id, stream, Some("✅ Downloaded"));

        // Verify the output hash. Note that even if this verification fails,
        // we will leave the file as written. This provides a way of fetching
        // truncated outputs (with an error).
        let output = unsafe { Mmap::map(&file) }.map_err(io_error)?;
        if *len < chunk_size.get() {
            check_hash!(hash(&output), None)
        } else {
            // Multi-threaded BLAKE3 is very, very fast, but still takes
            // perceptible time on multi-GB outputs. So if there's more
            // than one chunk, hash in chunks with a progress bar.
            ctx.job_output_started(&job_id, stream, "Verifying", *len);
            let mut hasher = Hasher::new();
            for chunk in output.chunks(chunk_size.get() as usize) {
                hasher.update_rayon(chunk);
                ctx.job_output_update(&job_id, stream, chunk.len() as u64);
            }
            check_hash!(hasher.finalize(), Some("✅ Verified"))
        }
    } else {
        // Download and print the output all at once. If hash verification
        // fails here, do not print any output.
        let byte_stream = with_authz(ctx, client, {
            async |authz| {
                client
                    .job_output()
                    .job_id(&job_id)
                    .target(target.to_string())
                    .stream(stream)
                    .authorization(authz)
                    .send()
                    .await
            }
        })
        .await?
        .into_inner();
        let bytes = byte_stream_to_vec(byte_stream).await?;
        check_hash!(hash(&bytes), None)?;
        ctx.job_output(&job_id, stream, &bytes, binary);
        Ok(())
    }
}

/// Prepare a vector of futures that fetch chunks of output.
fn job_output_chunks<'a>(
    ctx: &mut impl CommandContext,
    client: &'a Client,
    job_id: &'a JobId,
    target: &'a BaseboardId,
    stream: JobOutputStream,
    len: u64,
    chunk_size: NonZeroU64,
) -> Vec<Pin<Box<FutureChunk<'a>>>> {
    let mut chunks = Vec::new();
    let mut start = 0;
    // TODO: transparent authn for long downloads
    let authz = ctx
        .get_credentials()
        .map(|creds| creds.to_string())
        .unwrap_or_default();
    while start < len {
        let end = (start + chunk_size.get() - 1).min(len - 1);
        let range = Range { start, end };
        chunks.push({
            let authz = authz.clone();
            async move {
                let bytes = range.bytes();
                let stream = client
                    .job_output()
                    .job_id(job_id)
                    .target(target.to_string())
                    .stream(stream)
                    .range(&bytes)
                    .authorization(&authz)
                    .send()
                    .await?
                    .into_inner();
                Ok(Chunk(range, stream))
            }
            .boxed()
        });
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

/// Connect via WebSockets to a running interactive job.
async fn job_attach(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
    target: &BaseboardId,
) -> Result<(), CommandError> {
    match with_authz(ctx, client, async |authz| {
        client
            .job_attach()
            .job_id(job_id)
            .target(target.to_string())
            .authorization(authz)
            .send()
            .await
    })
    .await
    {
        Err(error) => Err(ctx.job_error(error)),
        Ok(socket) => {
            ctx.job_attached(job_id);
            let socket = socket.into_inner();
            let stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
            if let Err(error) = interactive_job(stream).await {
                return Err(ctx.job_error(error.into()));
            }
            ctx.job_detached(job_id);
            Ok(())
        }
    }
}

async fn resolve_target(
    ctx: &mut impl CommandContext,
    client: &Client,
    target: &str,
) -> Result<BaseboardId, CommandError> {
    // Eventually, "*" will mean "all sleds", but for now
    // we take it as "the current sled".
    Ok(if target == "*" {
        with_authz(ctx, client, async |authz| {
            client.target().authorization(authz).send().await
        })
        .await?
        .into_inner()
    } else {
        target
            .parse()
            .map_err(CommandError::BaseboardIdParseError)?
    })
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
    #[error("❌ Interactive job error: {0}")]
    Interactive(#[from] InteractiveJobError),
    #[error("❌ I/O error accessing `{path}`: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("❌ Unauthorized, try `iam`")]
    InvalidAuthorization,
    #[error("❌ Leaf certificate does not match key `{0}`")]
    InvalidLeafCert(KeyId),
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
    #[error("❌ Missing job target, try `--target`")]
    MissingTarget,
    #[error("❌ Resource not found")]
    NotFound,
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
    #[error("❌ Job process error: {0}")]
    Process(#[from] sush_common::jobs::ProcessError),
    #[error("👋 Goodbye!")]
    Quit,
    #[error("❌ {0}")]
    Readline(#[from] rustyline::error::ReadlineError),
    #[error(transparent)]
    Recursive(#[from] Box<Self>),
    #[error("❌ Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("❌ SSH signature error on key ID `{0}`")]
    Signature(KeyId),
    #[error("❌ Can't parse target baseboard ID: {0}")]
    BaseboardIdParseError(sled_hardware_types::BaseboardIdParseError),
    #[error("❌ SSH key error: {0}")]
    SshKey(#[from] kms_agent_lib::ssh_key::Error),
    #[error("❌ Timed out waiting for job")]
    TimedOut,
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
            ErrorResponse(e) if e.status() == StatusCode::NOT_FOUND => CommandError::NotFound,
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
