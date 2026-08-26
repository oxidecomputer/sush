// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::fs::{File, OpenOptions, read};
#[cfg(feature = "permslip")]
use std::io::ErrorKind;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _, stdin};
use std::num::{NonZeroU8, NonZeroU64};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
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
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{MissedTickBehavior, interval, sleep};
use tokio::{pin, select};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::error::Error as WebSocketError;
use tokio_tungstenite::tungstenite::protocol::Role;
use x509_cert::Certificate;
use x509_cert::der::DecodePem as _;

use sush_api::JobWait;
use sush_common::authn::{
    AuthnError, Challenge, ChallengeResponse, Credentials, Identity, RequestKey,
};
use sush_common::interactive::{InteractiveJobError, InteractiveJobMessage};
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
#[cfg(feature = "permslip")]
use sush_common::jobs::JobStartRequest;
use sush_common::jobs::{
    Access, JobId, JobLimits, JobOutputHash, JobOutputState, JobStatus, JobStatusMap, Session,
    SessionId, SessionSignerNonce, SignedJob, Streaming, job_status_try_from_json_map,
};
use sush_common::keys::{KeyError, KeyId, Signer as _};
use sush_common::targets::{SledId, Target};
use sush_common::version::VersionInfo;

use crate::ByteStream;
use crate::context::{Authz, CommandContext, OutputFormat, StatusDisplayStyle};
use crate::identity::{IdentityError, SshAgentConnection};
use crate::interactive::interactive_job;
#[cfg(feature = "permslip")]
use crate::permslip::{PermslipError, PermslipSigner};
use crate::repl::Repl;
use crate::tls;
use crate::types::{Error as ApiError, SessionStartBody};
use crate::{Client, Error as ClientError};

// Names of environment variables for argument defaults
// (to prevent mispellings).
#[cfg(feature = "permslip")]
pub const PERMSLIP_URL: &str = "PERMSLIP_URL";
pub const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";
pub const SUSH_JOB_ID: &str = "SUSH_JOB_ID";
pub const SUSH_KEY_ID: &str = "SUSH_KEY_ID";
pub const SUSH_MAX_CPU: &str = "SUSH_MAX_CPU";
pub const SUSH_MAX_MEM: &str = "SUSH_MAX_MEM";
pub const SUSH_MAX_FSIZE: &str = "SUSH_MAX_FSIZE";
#[cfg(feature = "permslip")]
pub const SUSH_PERMSLIP_KEY: &str = "SUSH_PERMSLIP_KEY";
pub const SUSH_OUTPUT_FORMAT: &str = "SUSH_OUTPUT_FORMAT";
pub const SUSH_PROXY_ROOT: &str = "SUSH_PROXY_ROOT";
pub const SUSH_URL: &str = "SUSH_URL";

/// Default chunk size for parallel downloads of large output.
const DEFAULT_CHUNK_SIZE: ByteSize = ByteSize::mib(32);

/// Default number of simultaneous downloads for large output.
const PARALLEL_CHUNKS: NonZeroU8 = NonZeroU8::new(8).unwrap();

/// Most simultaneous downloads allowed (see [`parallel_chunks`]).
const MAX_PARALLEL_CHUNKS: NonZeroU8 = NonZeroU8::new(64).unwrap();

// Job polling and spinner update intervals.
const JOB_STOP_RETRY_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(feature = "permslip")]
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

    /// PEM roots that a proxy's TLS certificate must chain to,
    /// replacing the baked-in platform identity roots.
    #[arg(long = "proxy-root", env = SUSH_PROXY_ROOT, value_name = "PEM")]
    #[clap(global = true)]
    pub proxy_roots: Vec<PathBuf>,

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
#[clap(about, version = sush_common::version::LONG_VERSION)]
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

/// A rack-wide target can't combine with `--binary` or `--file`.
#[tokio::test]
async fn output_needs_target() {
    use crate::cli::Cli;

    let client =
        Client::new_with_client("http://[::1]:1", reqwest::Client::new(), Default::default());
    let output = JobOutput::try_parse_from([
        "job-stdout",
        "--binary",
        "sea-say-sting-palm-tunnel-festival-pull-bid",
    ])
    .unwrap();
    let err = job_output(
        &mut Cli::default(),
        &client,
        &"*".parse::<TargetArg>().unwrap(),
        Stdout,
        output,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, CommandError::OutputNeedsTarget));
}

/// The watch settles only after the sled set is stable and every sled
/// is terminal for consecutive polls.
#[test]
fn watch_settling() {
    use chrono::Utc;

    fn sled(serial: &str) -> BaseboardId {
        BaseboardId {
            part_number: "913-0000019".to_owned(),
            serial_number: serial.to_owned(),
        }
    }
    let job_id: JobId = "sea-say-sting-palm-tunnel-festival-pull-bid"
        .parse()
        .unwrap();
    let terminal = JobStatus::Cancelled {
        job_id,
        time_cancelled: Utc::now(),
        actor: KeyId::random(),
    };
    let running = JobStatus::Started {
        job_id,
        time_started: Utc::now(),
    };

    let all = Target::All;
    let mut settling = Settling::default();
    let mut status = JobStatusMap::new();
    assert!(!settling.done(&all, None, &status), "empty never settles");

    status.insert(sled("A"), terminal.clone());
    assert!(!settling.done(&all, None, &status), "new sled resets");
    assert!(!settling.done(&all, None, &status), "first quiet poll");
    assert!(
        !settling.done(&all, None, &status),
        "quiet but too young for gossip"
    );
    assert!(settling.done(&all, None, &status), "old enough, quiet");

    let mut settling = Settling::default();
    status.insert(sled("B"), running.clone());
    assert!(!settling.done(&all, None, &status), "running sled holds");
    status.insert(sled("B"), terminal.clone());
    assert!(
        !settling.done(&all, Some(2), &status),
        "the rack count must hold"
    );
    assert!(
        settling.done(&all, Some(2), &status),
        "the rack count held twice"
    );

    let named: Target = format!("{},{}", sled("A"), sled("B")).parse().unwrap();
    let mut settling = Settling::default();
    assert!(
        settling.done(&named, None, &status),
        "named sleds settle on the first terminal poll"
    );
    let duplicates: Target = format!("{},{}", sled("A"), sled("A")).parse().unwrap();
    let mut settling = Settling::default();
    assert!(
        settling.done(&duplicates, None, &status),
        "duplicate baseboards collapse"
    );
    status.insert(sled("B"), running);
    assert!(
        !settling.done(&named, None, &status),
        "a running named sled holds"
    );
    status.insert(sled("B"), terminal);
    let missing: Target = format!("{},{}", sled("A"), sled("C")).parse().unwrap();
    let mut settling = Settling::default();
    assert!(
        !settling.done(&missing, None, &status),
        "a missing named sled holds"
    );
}

/// Anything the target grammar accepts stays a target.
#[test]
fn target_arg() {
    assert!(matches!("*".parse(), Ok(TargetArg::Target(_))));
    assert!(matches!("14".parse(), Ok(TargetArg::Target(_))));
    assert!(matches!(
        "913-0000019:BRM42220030".parse(),
        Ok(TargetArg::Target(_))
    ));
    assert!(matches!(
        "brm42220030".parse(),
        Ok(TargetArg::Abbreviated(sleds))
            if matches!(sleds.as_slice(), [SledArg::Serial(s)] if s == "brm42220030")
    ));
    assert!(matches!(
        "14,brm42220030".parse(),
        Ok(TargetArg::Abbreviated(sleds))
            if matches!(sleds.as_slice(), [SledArg::Sled(SledId::Cubby(14)), SledArg::Serial(_)])
    ));
    assert!(matches!(
        "913-0000019:BRM42220036,brm42220030".parse(),
        Ok(TargetArg::Abbreviated(sleds))
            if matches!(sleds.as_slice(), [SledArg::Sled(SledId::Baseboard(_)), SledArg::Serial(_)])
    ));
    assert!("n!ot,a:target".parse::<TargetArg>().is_err());
    assert!("*,brm42220030".parse::<TargetArg>().is_err());
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

    /// Number of simultaneous downloads for large output [max: 64].
    #[arg(short, long,
          default_value_t = PARALLEL_CHUNKS,
          requires = "file",
          value_parser = parallel_chunks)]
    parallel: NonZeroU8,
}

/// Parse and bound `--parallel`. The ceiling keeps a download's
/// in-flight spread comfortably inside the server's sequence window
/// (see [`sush_common::authn::SEQ_WINDOW`]).
fn parallel_chunks(s: &str) -> Result<NonZeroU8, String> {
    let n: NonZeroU8 = s
        .parse()
        .map_err(|_| String::from("expected a count from 1 to 64"))?;
    if n > MAX_PARALLEL_CHUNKS {
        return Err(format!(
            "at most {MAX_PARALLEL_CHUNKS} simultaneous downloads"
        ));
    }
    Ok(n)
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

    /// Report client and sled build versions.
    Version,

    /// Leave the interactive REPL.
    #[clap(alias = "exit")]
    Quit,
}

#[derive(Clone, Debug, Subcommand)]
pub enum CertCommand {
    /// Import a PEM encoded X.509 certificate and return its key ID.
    Import { path: PathBuf },

    /// Get the certificate chain that validates a key, in root-to-leaf order.
    Chain {
        key_id: KeyId,

        /// Trusted root certificates (PEM) to verify the chain against.
        /// Without any, only the chain's internal consistency is checked.
        #[arg(long = "root-cert")]
        root_certs: Vec<PathBuf>,
    },

    /// Permanently revoke a certificate across the rack.
    Revoke { key_id: KeyId },
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

    /// Revoke an SSH identity and refuse its future logins.
    Revoke { key_id: KeyId },
}

#[derive(Clone, Debug, Subcommand)]
pub enum SessionCommand {
    /// Grant a key attach access to this session's interactive jobs.
    Allow {
        /// The key to grant access to (try `iam` for your own).
        key_id: KeyId,

        /// Grant read-write access instead of read-only.
        #[arg(short, long)]
        write: bool,
    },

    /// Attach to a current support session.
    Attach { session_id: Option<SessionId> },

    /// Withdraw a key's attach access.
    Deny {
        /// The key to withdraw access from.
        key_id: KeyId,
    },

    /// Get the parameters to send to the signer server to start a session.
    StartParams,

    /// Start a new support session.
    Start {
        /// The session to start.
        #[arg(requires = "nonce")]
        session_id: Option<SessionId>,

        /// The signer nonce for the session.
        nonce: Option<SessionSignerNonce>,

        /// Use `permslip` to sign sessions and jobs with this key name.
        #[cfg(feature = "permslip")]
        #[arg(short, long, env = SUSH_PERMSLIP_KEY, value_name = "KEY_NAME")]
        permslip: Option<String>,

        /// The `permslip` server to contact for signing.
        #[cfg(feature = "permslip")]
        #[arg(long, env = PERMSLIP_URL, requires = "permslip", value_name = "URL")]
        permslip_url: Option<String>,

        /// Wait for the session to become active.
        #[arg(short, long)]
        wait: bool,
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

    /// Decline a job, burning its ID and advancing the session.
    Skip {
        /// The job to skip.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Get the status of a started job.
    Status {
        /// The job whose status should be fetched.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,

        /// Show full per-sled status instead of one line per sled.
        #[arg(short, long)]
        full: bool,

        /// Watch the status until the job settles on every sled.
        #[arg(short, long)]
        wait: bool,
    },

    /// Get the standard output of a job.
    #[clap(alias = "output")]
    Stdout {
        /// The sled from which output should be fetched.
        #[arg(short = 'T', long, default_value = "*")]
        target: TargetArg,

        #[clap(flatten)]
        output: JobOutput,
    },

    /// Get the standard error of a job.
    #[clap(alias = "error")]
    Stderr {
        /// The sled from which output should be fetched.
        #[arg(short = 'T', long, default_value = "*")]
        target: TargetArg,

        #[clap(flatten)]
        output: JobOutput,
    },

    /// Attach to an interactive job.
    Attach {
        /// The interactive job to attach to.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,

        /// The sled to attach to.
        #[arg(short = 'T', long, default_value = "*")]
        target: TargetArg,
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

    /// Job output is binary, not UTF-8 encoded text.
    #[arg(short, long, default_value_t = false, requires = "wait")]
    binary: bool,

    /// Run the job with a pseudoterminal and allow attaching to it.
    #[arg(short, long)]
    interactive: bool,

    /// Stream the job's output to an attached client instead of recording it.
    #[arg(short = 'S', long, conflicts_with = "interactive")]
    streaming: bool,

    /// File that streamed output should be written to.
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Overwrite the output file if it exists.
    #[arg(long, requires = "file")]
    force: bool,

    /// Where the job runs: every sled (`*`), or a comma-separated list
    /// of cubby numbers, baseboard IDs, or bare serial numbers.
    #[arg(short = 'T', long, default_value = "*")]
    target: TargetArg,

    /// Use `permslip` to sign job requests with this key name.
    #[cfg(feature = "permslip")]
    #[arg(short, long, env = SUSH_PERMSLIP_KEY, value_name = "KEY_NAME")]
    permslip: Option<String>,

    /// The `permslip` server to contact for signing.
    #[cfg(feature = "permslip")]
    #[arg(long, env = PERMSLIP_URL, requires = "permslip", value_name = "URL")]
    permslip_url: Option<String>,

    /// Terminal type for interactive jobs.
    #[arg(long, env = "TERM")]
    term: Option<String>,

    /// Wait for job start/stop and then attach/show output.
    #[arg(short, long, default_value_if("interactive", "true", "true"))]
    wait: bool,
}

impl JobStartArgs {
    /// The signing key name in a build that can sign.
    fn key_name(&self) -> Option<&str> {
        #[cfg(feature = "permslip")]
        return self.permslip.as_deref();
        #[cfg(not(feature = "permslip"))]
        None
    }
}

impl ClientCommand {
    /// Interactive jobs forward SIGINT to the job, watches use it to
    /// stop the job or end the watch, and the REPL turns it into a
    /// fresh prompt.
    fn handles_sigint(&self) -> bool {
        matches!(
            self,
            Self::Shell
                | Self::Job {
                    command: JobCommand::Start { .. } | JobCommand::Attach { .. },
                }
        )
    }

    /// Run the command, letting an interrupt cancel it unless the
    /// command handles SIGINT itself.
    #[async_recursion(?Send)]
    pub async fn execute(self, ctx: &mut impl CommandContext) -> Result<(), CommandError> {
        if self.handles_sigint() {
            return self.run(ctx).await;
        }
        select! {
            result = self.run(ctx) => result,
            _ = ctrl_c() => Err(CommandError::Canceled),
        }
    }

    async fn run(self, ctx: &mut impl CommandContext) -> Result<(), CommandError> {
        let args = ctx.get_globals().to_owned();
        if let Some(output) = args.output {
            ctx.set_output_format(output);
        }

        let client = match args.url.as_ref() {
            Some(url) => {
                let roots = if args.proxy_roots.is_empty() {
                    tls::platform_roots()?
                } else {
                    let mut roots = Vec::new();
                    for path in &args.proxy_roots {
                        let pem = read(path).map_err(|err| CommandError::io(path, err))?;
                        roots.push(Certificate::from_pem(&pem)?);
                    }
                    roots
                };
                {
                    let (url, resolve) = tls::descope_url(url)?;
                    Some(Client::new_with_client(
                        &url,
                        tls::client(roots, resolve)?,
                        ctx.authz_signer(),
                    ))
                }
            }
            None => None,
        };
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

            (ClientCommand::Version, client) => {
                let (server, sleds) = match client {
                    Some(client) => (
                        Some(client.version().send().await?.into_inner()),
                        client
                            .versions()
                            .send()
                            .await
                            .map(|sleds| sleds.into_inner())
                            .unwrap_or_default(),
                    ),
                    None => (None, Vec::new()),
                };
                ctx.versions(&VersionInfo::current(), server.as_ref(), &sleds);
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
    via: Option<&BaseboardId>,
    response: ResponseValue<E>,
) -> Result<(Identity, Authz), CommandError> {
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
    let key = RequestKey::new();
    let response = ChallengeResponse::new(challenge, key.verifier());
    ctx.please_touch(&public_key)?;
    let signed = select! {
        s = ssh_agent.sign(response) => s?,
        _ = ctrl_c() => return Err(CommandError::Canceled),
    };
    let verified = signed.verify_with_ssh_public_key(&public_key)?;
    let credentials = Credentials::new(verified);
    let mut request = client
        .iam()
        .authorization(credentials.to_string())
        .body(public_key.to_string());
    if let Some(via) = via {
        request = request.via(via.to_string());
    }
    let identity = request.send().await?.into_inner();
    Ok((identity, Authz::new(credentials, key)))
}

/// Make a request as someone who is logged in, logging in if needed.
/// The client's pre-send hook signs each attempt.
async fn with_login<T, E, Req>(
    ctx: &mut impl CommandContext,
    client: &Client,
    make_request: Req,
) -> Result<T, CommandError>
where
    Req: AsyncFnMut() -> Result<T, ClientError<E>>,
    CommandError: From<ClientError<E>>,
{
    with_login_via(ctx, client, None, make_request).await
}

/// Like [`with_login`], for requests a proxy routes to a particular
/// sled. Identities live on one sled, so the login must go where the
/// request it retries went.
async fn with_login_via<T, E, Req>(
    ctx: &mut impl CommandContext,
    client: &Client,
    via: Option<&BaseboardId>,
    mut make_request: Req,
) -> Result<T, CommandError>
where
    Req: AsyncFnMut() -> Result<T, ClientError<E>>,
    CommandError: From<ClientError<E>>,
{
    match make_request().await {
        Err(ClientError::ErrorResponse(err)) if err.status() == StatusCode::UNAUTHORIZED => {
            let (_identity, authz) = authenticate(ctx, client, via, err).await?;
            ctx.set_credentials(Some(authz));
            Ok(make_request().await?)
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
            let identities = with_login(ctx, client, async || client.identities().send().await)
                .await?
                .into_inner();
            for identity in identities {
                ctx.iam(&identity)?;
            }
            Ok(())
        }

        IdentityCommand::Login => {
            let identity = with_login(ctx, client, async || client.iam().body(None).send().await)
                .await?
                .into_inner();
            ctx.iam(&identity)
        }

        IdentityCommand::Revoke { key_id } => {
            let key_id = ctx.really_revoke("SSH identity", key_id)?;
            with_login(ctx, client, async || {
                client.iam_revoke().key_id(&key_id).wait(true).send().await
            })
            .await?;
            ctx.revoked("SSH identity", key_id)
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
            let key_id = with_login(ctx, client, async || {
                client.cert_import().body(cert.clone()).send().await
            })
            .await?
            .into_inner();
            ctx.cert_imported(&path, key_id)
        }

        CertCommand::Chain { key_id, root_certs } => {
            let mut roots = Vec::new();
            for path in &root_certs {
                let pem = read(path).map_err(|err| CommandError::io(path, err))?;
                roots.push(Certificate::from_pem(&pem)?);
            }
            let certs = with_login(ctx, client, async || {
                client.cert_chain().key_id(&key_id).send().await
            })
            .await?
            .into_inner();
            ctx.cert_chain(key_id, &certs, &roots)?;
            Ok(())
        }

        CertCommand::Revoke { key_id } => {
            let key_id = ctx.really_revoke("certificate", key_id)?;
            with_login(ctx, client, async || {
                client.cert_revoke().key_id(&key_id).wait(true).send().await
            })
            .await?;
            ctx.revoked("certificate", key_id)
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
            let session = with_login(ctx, client, async || client.session().send().await)
                .await?
                .into_inner();
            if let Some(session_id) = session_id
                && session.session_id() != session_id
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

        (SessionCommand::StartParams, Some(client)) => {
            let (baseboard_id, nonce) = with_login(ctx, client, async || {
                Ok((
                    client.target().send().await?.into_inner(),
                    client.session_start_nonce().send().await?.into_inner(),
                ))
            })
            .await?;
            ctx.session_start_params(baseboard_id, nonce)?;
            Ok(())
        }

        #[cfg(feature = "permslip")]
        (
            SessionCommand::Start {
                session_id,
                nonce,
                permslip,
                permslip_url,
                wait,
            },
            Some(client),
        ) => {
            let (session_id, nonce) =
                if let (Some(session_id), Some(nonce)) = (session_id, nonce) {
                    (session_id, nonce)
                } else {
                    use sush_common::codephrases::InvalidCodephrase;

                    let Some(permslip_url) = permslip_url else {
                        return Err(CommandError::MissingPermslipUrl);
                    };
                    let Some(permslip_key) = permslip else {
                        return Err(CommandError::MissingKeyName);
                    };
                    let signer = PermslipSigner::new(permslip_key, &permslip_url).await?;

                    let (baseboard_id, nonce) = with_login(ctx, client, async || {
                        Ok((
                            client.target().send().await?.into_inner(),
                            client.session_start_nonce().send().await?.into_inner(),
                        ))
                    })
                    .await?;

                    let created = signer.create_session(&baseboard_id, nonce.nonce).await?;

                    (
                        created.session_id.to_string().parse().map_err(
                            |e: InvalidCodephrase| {
                                CommandError::UnsupportedPermslipResponse(e.to_string())
                            },
                        )?,
                        created.signer_nonce.to_string().parse().map_err(
                            |e: InvalidCodephrase| {
                                CommandError::UnsupportedPermslipResponse(e.to_string())
                            },
                        )?,
                    )
                };
            session_start(ctx, client, session_id, nonce, wait).await
        }

        #[cfg(not(feature = "permslip"))]
        (
            SessionCommand::Start {
                session_id,
                nonce,
                wait,
            },
            Some(client),
        ) => {
            let (session_id, nonce) = if let (Some(session_id), Some(nonce)) = (session_id, nonce) {
                (session_id, nonce)
            } else {
                return Err(CommandError::SigningUnavailable);
            };
            session_start(ctx, client, session_id, nonce, wait).await
        }

        (SessionCommand::Allow { key_id, write }, Some(client)) => {
            let Some(session_id) = ctx.session_id() else {
                return Err(CommandError::MissingSession);
            };
            let access = if write {
                Access::ReadWrite
            } else {
                Access::ReadOnly
            };
            with_login(ctx, client, async || {
                client
                    .session_allow_attach()
                    .session_id(session_id)
                    .key_id(key_id.clone())
                    .access(access)
                    .send()
                    .await
            })
            .await?;
            ctx.attach_allowed(&key_id, access);
            Ok(())
        }

        (SessionCommand::Deny { key_id }, Some(client)) => {
            let Some(session_id) = ctx.session_id() else {
                return Err(CommandError::MissingSession);
            };
            with_login(ctx, client, async || {
                client
                    .session_deny_attach()
                    .session_id(session_id)
                    .key_id(key_id.clone())
                    .send()
                    .await
            })
            .await?;
            ctx.attach_denied(&key_id);
            Ok(())
        }

        (SessionCommand::Stop { session_id }, Some(client)) => {
            let ctx_session_id = ctx.session_id();
            let Some(session_id) = session_id.as_ref().or(ctx_session_id.as_ref()) else {
                return Err(CommandError::MissingSession);
            };
            with_login(ctx, client, async || {
                client.session_stop().session_id(*session_id).send().await
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
            if start_args.command.is_none() && start_args.key_name().is_none() =>
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

        #[cfg(feature = "permslip")]
        (
            JobCommand::Start {
                start_args: JobStartArgs { permslip: None, .. },
                ..
            },
            Some(_),
        ) => Err(CommandError::MissingKeyName),

        #[cfg(not(feature = "permslip"))]
        (JobCommand::Start { .. }, Some(_)) => Err(CommandError::SigningUnavailable),

        #[cfg(feature = "permslip")]
        (
            JobCommand::Start {
                start_args:
                    ref start_args @ JobStartArgs {
                        command: Some(ref command),
                        permslip: Some(ref key_name),
                        ref permslip_url,
                        ref interactive,
                        ref streaming,
                        ref target,
                        ..
                    },
            },
            client,
        ) => {
            let Some(session_id) = ctx.session_id() else {
                return Err(CommandError::MissingSession);
            };
            let Some(permslip_url) = permslip_url else {
                return Err(CommandError::MissingPermslipUrl);
            };
            let job_id = ctx.next_job_id()?;
            let target = match target {
                TargetArg::Target(target) => target.clone(),
                abbreviated => {
                    let Some(client) = client.as_ref() else {
                        return Err(CommandError::Offline);
                    };
                    resolve_target_arg(client, abbreviated).await?
                }
            };
            // Sign an interactive or streaming job for the sled its
            // attachment will land on.
            let target = if (*interactive || *streaming) && target.single_baseboard().is_none() {
                let Some(client) = client.as_ref() else {
                    return Err(CommandError::InteractiveTarget);
                };
                Target::from(resolve_target(client, &target).await?)
            } else {
                target
            };
            // Catch output file problems before the signing ceremony.
            if *streaming {
                let Some(path) = &start_args.file else {
                    return Err(CommandError::StreamingNeedsFile);
                };
                if !start_args.force && path.exists() {
                    return Err(CommandError::io(path, ErrorKind::AlreadyExists.into()));
                }
            }
            if let Some(client) = client.as_ref() {
                preflight_target(ctx, client, &target).await?;
            }
            let streaming = if *streaming {
                Streaming::Output
            } else {
                Streaming::None
            };
            let signer = PermslipSigner::new(key_name, permslip_url).await?;
            let mut interval = interval(SIGNING_UPDATE_INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let sign = signer.sign_job_request(JobStartRequest::new(
                job_id.to_owned(),
                session_id,
                command,
                *interactive,
                streaming,
                target,
            ));
            pin!(sign);
            ctx.job_signing_started(&job_id);
            let mut sigint = signal(SignalKind::interrupt())?;
            let job = loop {
                select! {
                    job = &mut sign => {
                        ctx.job_signing_finished(&job_id);
                        break job?;
                    }
                    _ = interval.tick() => ctx.job_signing_update(&job_id),
                    _ = sigint.recv() => {
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

        (JobCommand::Stop { job_id }, Some(client)) => {
            job_stop(ctx, client, &job_id, None).await?;
            ctx.job_stopped(&job_id);
            Ok(())
        }

        // Offline skips advance only the local session, keeping the
        // signer's chain in step with a rack that skipped.
        (JobCommand::Skip { job_id }, client) => {
            let Some(session_id) = ctx.session_id() else {
                return Err(CommandError::MissingSession);
            };
            if let Some(client) = client {
                with_login(ctx, client, async || {
                    client
                        .session_skip_job()
                        .session_id(session_id)
                        .job_id(job_id)
                        .send()
                        .await
                })
                .await?;
            }
            if ctx.job_skipped(&job_id) {
                Ok(())
            } else {
                Err(CommandError::NotNextJob(job_id))
            }
        }

        (JobCommand::Status { job_id, full, wait }, Some(client)) => {
            let style = if full {
                StatusDisplayStyle::Full
            } else {
                StatusDisplayStyle::Short
            };
            if wait {
                let status = job_watch(ctx, client, &job_id, &Target::All).await?;
                ctx.job_status(&job_id, &status, style);
                Ok(())
            } else {
                job_status(ctx, client, &job_id, style).await
            }
        }

        (JobCommand::Stdout { target, output }, Some(client)) => {
            job_output(ctx, client, &target, Stdout, output).await
        }

        (JobCommand::Stderr { target, output }, Some(client)) => {
            job_output(ctx, client, &target, Stderr, output).await
        }

        (JobCommand::Attach { job_id, target }, Some(client)) => {
            let target = match &target {
                TargetArg::Abbreviated(sleds) => match sleds.as_slice() {
                    [SledArg::Serial(serial)] => {
                        resolve_serial(ctx, client, &job_id, serial).await?
                    }
                    _ => {
                        let target = resolve_target_arg(client, &target).await?;
                        resolve_target(client, &target).await?
                    }
                },
                TargetArg::Target(target) => resolve_target(client, target).await?,
            };
            job_attach(ctx, client, &job_id, &target).await?;
            Ok(())
        }

        (JobCommand::History { limit, offset }, Some(client)) => {
            let history = with_login(ctx, client, async || {
                client
                    .job_history()
                    .limit(limit)
                    .offset(offset)
                    .send()
                    .await
            })
            .await?
            .into_inner();
            for job in history {
                let status = job_status_try_from_json_map(job)
                    .map_err(CommandError::BaseboardIdParseError)?;
                if let Some(s) = status.values().next() {
                    ctx.job_status(s.job_id(), &status, StatusDisplayStyle::Short);
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
    // Resolve the signed request's target to one sled to watch and
    // fetch output from.
    let target = resolve_target(client, job.payload().target()).await?;

    // Set up the job request and parameters.
    let job_id = job.job_id().to_owned();
    let JobStartArgs {
        binary,
        limits,
        term,
        wait,
        file,
        force,
        ..
    } = start_args;
    let interactive = job.payload().interactive;
    let streaming = matches!(job.payload().streaming, Streaming::Output);
    let wait = if interactive || streaming {
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
    let start = with_login_via(&mut start_ctx, client, Some(&target), async || {
        let mut start = client
            .job_start()
            .job_id(job.job_id())
            .target(target.to_string())
            .max_cpu(max_cpu)
            .max_mem(max_mem)
            .max_fsize(max_fsize)
            .wait(wait)
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
            Ok(()) | Err(CommandError::NotFound(_)) => {
                job_status(ctx, client, &job_id, StatusDisplayStyle::Short).await?
            }
            Err(error) => return Err(error),
        }
    } else if streaming {
        let Some(path) = file else {
            return Err(CommandError::StreamingNeedsFile);
        };
        let mut options = OpenOptions::new();
        options.write(true);
        if force {
            options.create(true);
        } else {
            options.create_new(true);
        }
        let file = options
            .open(&path)
            .map_err(|error| CommandError::io(&path, error))?;
        start.await?;
        ctx.job_started(&job);
        let hasher = job_stream(ctx, client, &job_id, &target, &path, file).await?;
        let status = job_watch(ctx, client, &job_id, &target.clone().into()).await?;
        ctx.job_status(&job_id, &status, StatusDisplayStyle::Short);
        let Some(JobStatus::Stopped {
            result: Ok(0),
            output:
                JobOutputState {
                    stdout_len,
                    stdout_hash,
                    ..
                },
            ..
        }) = status.get(&target)
        else {
            return Err(CommandError::StreamUnverified(job_id));
        };
        if *stdout_len != hasher.count() {
            return Err(CommandError::LengthMismatch {
                expected: *stdout_len,
                received: hasher.count(),
            });
        }
        let received = JobOutputHash::from(hasher.finalize());
        if received != *stdout_hash {
            return Err(CommandError::OutputHashMismatch {
                expected: stdout_hash.to_owned(),
                received,
            });
        }
    } else if wait.is_some() {
        // Watch the whole rack while the start request runs, and keep
        // watching until the job settles everywhere.
        ctx.job_watch_started(&job_id);
        let job_target = job.payload().target().clone();
        let mut ticker = interval(WATCH_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last = JobStatusMap::new();
        let mut settling = Settling::default();
        let mut started = false;
        let mut stalled = false;
        let mut stopped = false;
        let mut sigint = signal(SignalKind::interrupt())?;
        let status = loop {
            select! {
                // Wait for the start request to finish.
                start_result = &mut start, if !started => {
                    match start_result {
                        Ok(_) | Err(CommandError::TimedOut) => ctx.job_started(&job),
                        Err(error) => {
                            ctx.job_watch_finished(&job_id);
                            return Err(error);
                        }
                    }
                    started = true;
                    ticker.reset_immediately();
                }

                _ = ticker.tick() => {
                    last = match job_status_map(ctx, client, &job_id, job_target.single_baseboard()).await {
                        Ok(status) => status,
                        // The job may not be visible anywhere yet.
                        Err(CommandError::NotFound(_)) => JobStatusMap::new(),
                        Err(error) => {
                            ctx.job_watch_finished(&job_id);
                            return Err(error);
                        }
                    };
                    ctx.job_watch_update(&last);
                    let rack = rack_sleds(client, &job_target).await;
                    if settling.done(&job_target, rack, &last) && started {
                        break last;
                    }
                    if !stalled && last.is_empty() && settling.polls >= WATCH_STALL_POLLS {
                        ctx.job_watch_stalled(&job_id);
                        stalled = true;
                    }
                }

                // While the job runs, an interrupt stops it but keeps
                // watching: the start future must still resolve, and the
                // stops are worth seeing. There is a race with the start,
                // so retry the stop a few times if needed. Once the job
                // has stopped, or after a first interrupt, an interrupt
                // just ends the watch.
                _ = sigint.recv() => {
                    if started || stopped {
                        break last;
                    }
                    for _ in 0..3 {
                        match job_stop(ctx, client, &job_id, job_target.single_baseboard()).await {
                            Ok(_) => {
                                ctx.job_stopped(&job_id);
                                stopped = true;
                                break;
                            }
                            Err(CommandError::NotFound(_)) => {
                                sleep(JOB_STOP_RETRY_INTERVAL).await;
                            }
                            Err(error) => {
                                ctx.job_watch_finished(&job_id);
                                return Err(error);
                            }
                        }
                    }
                }
            }
        };
        ctx.job_watch_finished(&job_id);
        ctx.job_status(&job_id, &status, StatusDisplayStyle::Short);
        if !status
            .values()
            .any(|s| matches!(s, JobStatus::Stopped { .. }))
        {
            return Err(if status.values().all(JobStatus::is_terminal) {
                CommandError::JobDidNotRun(job_id)
            } else {
                CommandError::JobStillRunning(job_id)
            });
        }
        // Show the output of every sled the job ran on.
        let multiple = status.len() > 1;
        for baseboard in status.keys() {
            if multiple {
                ctx.job_output_target(baseboard);
            }
            for stream in [Stdout, Stderr] {
                match with_login_via(ctx, client, Some(baseboard), async || {
                    client
                        .job_output()
                        .job_id(job_id)
                        .target(baseboard.to_string())
                        .stream(stream)
                        .send()
                        .await
                })
                .await
                {
                    Ok(byte_stream) => {
                        let output = byte_stream_to_vec(byte_stream.into_inner()).await?;
                        ctx.job_output(&job_id, stream, &output, binary);
                    }
                    Err(error) if multiple => {
                        let _ = ctx.job_error(error);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    } else {
        start.await?;
        ctx.job_started(&job);
    }
    Ok(())
}

async fn session_start(
    ctx: &mut impl CommandContext,
    client: &Client,
    session_id: SessionId,
    signer_nonce: SessionSignerNonce,
    wait: bool,
) -> Result<(), CommandError> {
    let session = Session::new(session_id);
    with_login(ctx, client, async || {
        client
            .session_start()
            .session_id(session.session_id())
            .wait(wait)
            .body(SessionStartBody { signer_nonce })
            .send()
            .await
    })
    .await?
    .into_inner();
    ctx.session_started(session)
}

async fn job_stop(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
    via: Option<&BaseboardId>,
) -> Result<(), CommandError> {
    with_login_via(ctx, client, via, async || {
        let mut request = client.job_stop().job_id(job_id).wait(JobWait::Stop);
        if let Some(via) = via {
            request = request.via(via.to_string());
        }
        request.send().await
    })
    .await?;
    Ok(())
}

async fn job_status(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
    style: StatusDisplayStyle,
) -> Result<(), CommandError> {
    let status = job_status_map(ctx, client, job_id, None).await?;
    ctx.job_status(job_id, &status, style);
    Ok(())
}

/// Fetch a job's rack-wide status map. Routing `via` a single-sled
/// target gets its authoritative status and keeps the login on the
/// sled that already knows it.
async fn job_status_map(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
    via: Option<&BaseboardId>,
) -> Result<JobStatusMap, CommandError> {
    let status = with_login_via(ctx, client, via, async || {
        let mut request = client.job_status().job_id(job_id);
        if let Some(via) = via {
            request = request.via(via.to_string());
        }
        request.send().await
    })
    .await?
    .into_inner();
    job_status_try_from_json_map(status).map_err(CommandError::BaseboardIdParseError)
}

/// How often a watched job's status is refreshed.
const WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// Watch a job's status across the rack, one live line per sled, until
/// it settles or the user interrupts. Returns the last status map.
async fn job_watch(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
    target: &Target,
) -> Result<JobStatusMap, CommandError> {
    ctx.job_watch_started(job_id);
    let mut settling = Settling::default();
    let mut sigint = signal(SignalKind::interrupt())?;
    let status = loop {
        let status = match job_status_map(ctx, client, job_id, target.single_baseboard()).await {
            Ok(status) => status,
            Err(error) => {
                ctx.job_watch_finished(job_id);
                return Err(error);
            }
        };
        ctx.job_watch_update(&status);
        let rack = rack_sleds(client, target).await;
        if settling.done(target, rack, &status) {
            break status;
        }
        select! {
            _ = sleep(WATCH_INTERVAL) => {}
            _ = sigint.recv() => break status,
        }
    };
    ctx.job_watch_finished(job_id);
    Ok(status)
}

/// The fewest polls a watch may run: gossip needs a few seconds to
/// fan a job out across the rack, so a map that looks settled early
/// is likely still missing sleds.
const WATCH_MIN_POLLS: usize = 5;

/// How many polls a watch may go without any sled reporting a status
/// before warning that the job may never run.
const WATCH_STALL_POLLS: usize = 15;

/// Rolling settlement state for a watched job.
#[derive(Default)]
struct Settling {
    polls: usize,
    sleds: usize,
    quiet: usize,
    met: usize,
}

impl Settling {
    /// A watched job has settled once every sled it runs on reports a
    /// terminal status. A target naming only baseboards is settled as
    /// soon as they all report. Against the rack inventory, the count
    /// must match on consecutive polls. Either way, the watch is done
    /// once it is old enough for gossip to have named every sled and
    /// the set of sleds has been stable for a couple of polls.
    fn done(&mut self, target: &Target, rack: Option<usize>, status: &JobStatusMap) -> bool {
        self.polls += 1;
        let terminal = !status.is_empty() && status.values().all(JobStatus::is_terminal);
        if terminal && status.len() == self.sleds {
            self.quiet += 1;
        } else {
            self.quiet = 0;
        }
        self.sleds = status.len();
        if rack.is_some_and(|sleds| terminal && status.len() == sleds) {
            self.met += 1;
        } else {
            self.met = 0;
        }
        if let Some(named) = target.named_baseboards()
            && named
                .into_iter()
                .all(|sled| status.get(sled).is_some_and(JobStatus::is_terminal))
        {
            return true;
        }
        self.met >= 2 || (self.polls >= WATCH_MIN_POLLS && self.quiet >= 2)
    }
}

/// The number of sleds in the rack's own inventory, where available.
/// Skips the fetch for targets whose sleds are named.
async fn rack_sleds(client: &Client, target: &Target) -> Option<usize> {
    if target.named_baseboards().is_some() {
        return None;
    }
    let sleds = client.versions().send().await.ok()?.into_inner().len();
    (sleds > 0).then_some(sleds)
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

/// Download job output.
async fn job_output(
    ctx: &mut impl CommandContext,
    client: &Client,
    target: &TargetArg,
    stream: JobOutputStream,
    args: JobOutput,
) -> Result<(), CommandError> {
    let target = match target {
        TargetArg::Target(target) => target.clone(),
        TargetArg::Abbreviated(sleds) => {
            if let [SledArg::Serial(serial)] = sleds.as_slice() {
                let baseboard = resolve_serial(ctx, client, &args.job_id, serial).await?;
                return job_output_from(ctx, client, &baseboard, stream, args).await;
            }
            resolve_target_arg(client, target).await?
        }
    };
    if !target.is_all() {
        let baseboard = resolve_target(client, &target).await?;
        return job_output_from(ctx, client, &baseboard, stream, args).await;
    }
    if args.binary || args.file.is_some() {
        return Err(CommandError::OutputNeedsTarget);
    }

    // Fetch output from every sled with a recorded status.
    let status = job_status_map(ctx, client, &args.job_id, None).await?;
    if status.is_empty() {
        return Err(CommandError::NotFound(format!(
            "Job `{}` not found",
            args.job_id
        )));
    }
    for baseboard in status.keys() {
        ctx.job_output_target(baseboard);
        if let Err(error) = job_output_from(ctx, client, baseboard, stream, args.clone()).await {
            let _ = ctx.job_error(error);
        }
    }
    Ok(())
}

async fn job_output_from(
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
    let status = job_status_map(ctx, client, &job_id, Some(target)).await?;

    let JobOutputState {
        stdout_len,
        stderr_len,
        stdout_hash,
        stderr_hash,
    } = match status.get(target) {
        None => {
            return Err(CommandError::NotFound(format!(
                "Job `{job_id}` not found on sled `{target}`"
            )));
        }
        Some(JobStatus::Cancelled { .. }) => {
            return Err(CommandError::JobCancelled(job_id.to_owned()));
        }
        Some(JobStatus::Queued { job_id, .. }) => {
            return Err(CommandError::JobNotYetRunning(job_id.to_owned()));
        }
        Some(JobStatus::Error { error, .. }) => {
            return Err(CommandError::Process(error.to_owned()));
        }
        Some(JobStatus::Started { job_id, .. }) => {
            return Err(CommandError::JobStillRunning(job_id.to_owned()));
        }
        Some(JobStatus::Stopped { output, .. }) => output,
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
        let chunks = job_output_chunks(client, &job_id, target, stream, *len, chunk_size);
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
        let byte_stream = with_login_via(ctx, client, Some(target), {
            async || {
                client
                    .job_output()
                    .job_id(job_id)
                    .target(target.to_string())
                    .stream(stream)
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
    client: &'a Client,
    job_id: &'a JobId,
    target: &'a BaseboardId,
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
                    .job_id(job_id)
                    .target(target.to_string())
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

/// Connect via WebSockets to a running interactive job.
async fn job_attach(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
    target: &BaseboardId,
) -> Result<(), CommandError> {
    match with_login_via(ctx, client, Some(target), async || {
        client
            .job_attach()
            .job_id(job_id)
            .target(target.to_string())
            .send()
            .await
    })
    .await
    {
        Err(error) => Err(error),
        Ok(socket) => {
            ctx.job_attached(job_id);
            let socket = socket.into_inner();
            let stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
            if let Err(error) = interactive_job(stream).await {
                return Err(error.into());
            }
            ctx.job_detached(job_id);
            Ok(())
        }
    }
}

/// Receive a streaming job's output into an open file, returning the
/// hasher fed by the received bytes.
async fn job_stream(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
    target: &BaseboardId,
    path: &Path,
    mut file: File,
) -> Result<Hasher, CommandError> {
    let io_error = |error| CommandError::io(path, error);
    let socket = with_login_via(ctx, client, Some(target), async || {
        client
            .job_attach()
            .job_id(job_id)
            .target(target.to_string())
            .send()
            .await
    })
    .await?
    .into_inner();
    let mut stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
    file.set_len(0).map_err(io_error)?;
    let mut hasher = Hasher::new();
    let mut sigint = signal(SignalKind::interrupt())?;
    ctx.job_output_started(job_id, Stdout, "Streaming", 0);
    let result = loop {
        select! {
            message = stream.next() => {
                let Some(message) = message else { break Ok(()) };
                let message = match message.map_err(InteractiveJobError::from) {
                    Ok(message) => message,
                    Err(error) => break Err(error.into()),
                };
                match InteractiveJobMessage::try_from(message) {
                    Ok(InteractiveJobMessage::Data(bytes)) => {
                        hasher.update(&bytes);
                        if let Err(error) = file.write_all(&bytes).map_err(io_error) {
                            break Err(error);
                        }
                        ctx.job_output_update(job_id, Stdout, bytes.len() as u64);
                    }
                    Ok(InteractiveJobMessage::Close) => break Ok(()),
                    Ok(InteractiveJobMessage::Control(_) | InteractiveJobMessage::Ignore) => (),
                    Err(error) => break Err(error.into()),
                }
            }
            _ = sigint.recv() => break Err(CommandError::Canceled),
        }
    };
    match result {
        Ok(()) => {
            file.flush().map_err(io_error)?;
            ctx.job_output_finished(job_id, Stdout, Some("✅ Streamed"));
            let _ = stream.close(None).await;
            Ok(hasher)
        }
        Err(error) => {
            ctx.job_output_finished(job_id, Stdout, Some("❌ Received"));
            Err(error)
        }
    }
}

/// Resolve a target to the baseboard of one sled it names. A single
/// baseboard resolves locally. Anything else asks `/target`, routed
/// by the expression, so a proxy resolves cubbies and `*` means the
/// handling sled.
async fn resolve_target(client: &Client, target: &Target) -> Result<BaseboardId, CommandError> {
    if let Target::Sleds(sleds) = target
        && let [SledId::Baseboard(baseboard)] = sleds.as_slice()
    {
        return Ok(baseboard.clone());
    }
    let mut request = client.target();
    if !target.is_all() {
        request = request.via(target.to_string());
    }
    Ok(request.send().await?.into_inner())
}

/// A target expression, with sleds optionally abbreviated to bare
/// serial numbers.
#[derive(Clone, Debug)]
pub enum TargetArg {
    Target(Target),
    Abbreviated(Vec<SledArg>),
}

/// One sled named in a target argument.
#[derive(Clone, Debug)]
pub enum SledArg {
    Sled(SledId),
    Serial(String),
}

impl FromStr for TargetArg {
    type Err = <Target as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let error = match s.parse() {
            Ok(target) => return Ok(Self::Target(target)),
            Err(error) => error,
        };
        let mut sleds = Vec::new();
        for piece in s.split(',') {
            let piece = piece.trim();
            match piece.parse::<Target>() {
                Ok(Target::Sleds(sled)) if sled.len() == 1 => {
                    sleds.push(SledArg::Sled(sled.into_iter().next().expect("one sled")));
                }
                _ if !piece.is_empty() && piece.chars().all(|c| c.is_ascii_alphanumeric()) => {
                    sleds.push(SledArg::Serial(piece.to_owned()));
                }
                _ => return Err(error),
            }
        }
        Ok(Self::Abbreviated(sleds))
    }
}

/// Confirm before signing a job for a sled that doesn't appear in inventory.
#[cfg(feature = "permslip")]
async fn preflight_target(
    ctx: &mut impl CommandContext,
    client: &Client,
    target: &Target,
) -> Result<(), CommandError> {
    let Target::Sleds(sleds) = target else {
        return Ok(());
    };
    let Ok(inventory) = client.versions().send().await else {
        return Ok(());
    };
    let inventory = inventory.into_inner();
    for sled in sleds {
        let known = match sled {
            SledId::Baseboard(baseboard) => inventory.iter().any(|s| &s.baseboard == baseboard),
            SledId::Cubby(cubby) => inventory.iter().any(|s| s.cubby == Some(*cubby)),
        };
        if !known {
            ctx.really_target(sled)?;
        }
    }
    Ok(())
}

/// Resolve a target argument to a target, matching bare serial
/// numbers against the rack's sled inventory.
async fn resolve_target_arg(client: &Client, target: &TargetArg) -> Result<Target, CommandError> {
    match target {
        TargetArg::Target(target) => Ok(target.clone()),
        TargetArg::Abbreviated(sleds) => {
            let inventory = client.versions().send().await?.into_inner();
            sleds
                .iter()
                .map(|sled| match sled {
                    SledArg::Sled(sled) => Ok(sled.clone()),
                    SledArg::Serial(serial) => {
                        let mut matches = inventory
                            .iter()
                            .map(|sled| &sled.baseboard)
                            .filter(|b| b.serial_number.eq_ignore_ascii_case(serial));
                        match (matches.next(), matches.next()) {
                            (Some(baseboard), None) => Ok(SledId::Baseboard(baseboard.clone())),
                            (None, _) => Err(CommandError::UnknownRackSerial(serial.to_owned())),
                            (Some(_), Some(_)) => {
                                Err(CommandError::AmbiguousSerial(serial.to_owned()))
                            }
                        }
                    }
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Target::Sleds)
        }
    }
}

/// Resolve a bare serial number against the sleds that have a status
/// for a job.
async fn resolve_serial(
    ctx: &mut impl CommandContext,
    client: &Client,
    job_id: &JobId,
    serial: &str,
) -> Result<BaseboardId, CommandError> {
    let status = job_status_map(ctx, client, job_id, None).await?;
    let mut matches = status
        .keys()
        .filter(|b| b.serial_number.eq_ignore_ascii_case(serial));
    match (matches.next(), matches.next()) {
        (Some(baseboard), None) => Ok(baseboard.clone()),
        (None, _) => Err(CommandError::UnknownSerial {
            serial: serial.to_owned(),
            job_id: job_id.to_owned(),
        }),
        (Some(_), Some(_)) => Err(CommandError::AmbiguousSerial(serial.to_owned())),
    }
}

/// What went wrong parsing, preparing, or executing a client command.
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("❌ Serial `{0}` matches more than one sled, use a full baseboard ID")]
    AmbiguousSerial(String),
    #[error("❌ Authentication error")]
    Authn(#[from] AuthnError),
    #[error("❌ Canceled")]
    Canceled,
    #[error("❌ Certificate for `{0}` is outside its validity window")]
    CertExpired(String),
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
    #[error("❌ Interactive jobs must target exactly one sled")]
    InteractiveTarget,
    #[error("❌ Local I/O error accessing `{path}`: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("❌ Signal handling error: {0}")]
    Signal(#[from] std::io::Error),
    #[error("❌ Unauthorized, try `iam`")]
    InvalidAuthorization,
    #[error("❌ Leaf certificate does not match key `{0}`")]
    InvalidLeafCert(KeyId),
    #[error("❌ Root certificate is not self-signed")]
    InvalidRootCert,
    #[error("❌ Job `{0}` was cancelled before it started")]
    JobCancelled(JobId),
    #[error("❌ Job `{0}` did not run")]
    JobDidNotRun(JobId),
    #[error("❌ Job `{0}` is not yet running")]
    JobNotYetRunning(JobId),
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
    #[cfg(feature = "permslip")]
    #[error("❌ Missing signing key name, try `--permslip`")]
    MissingKeyName,
    #[cfg(feature = "permslip")]
    #[error("❌ Missing permslip URL, try `--permslip-url` or setting `PERMSLIP_URL`")]
    MissingPermslipUrl,
    #[error("❌ Missing session, try `session start`")]
    MissingSession,
    #[error("❌ Missing SSH agent socket, try `--ssh-auth-sock`")]
    MissingSshAuthSock,
    #[error("❌ {0}")]
    NotFound(String),
    #[error("❌ Job `{0}` is not the session's next job")]
    NotNextJob(JobId),
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
    #[error("❌ `--binary` and `--file` need a specific `--target`")]
    OutputNeedsTarget,
    #[cfg(feature = "permslip")]
    #[error("❌ permslip error: {0}")]
    Permslip(#[from] PermslipError),
    #[error("❌ Job process error: {0}")]
    Process(#[from] sush_common::jobs::ProcessError),
    #[error("❌ Proxy TLS error: {0}")]
    ProxyTls(#[from] tls::ProxyTlsError),
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
    #[cfg(not(feature = "permslip"))]
    #[error("❌ Signing unavailable: built without the `permslip` feature")]
    SigningUnavailable,
    #[error("❌ Streaming jobs need `--file`")]
    StreamingNeedsFile,
    #[error("❌ Job `{0}` did not exit cleanly, streamed output is unverified")]
    StreamUnverified(JobId),
    #[error("❌ Can't parse target baseboard ID: {0}")]
    BaseboardIdParseError(sled_hardware_types::BaseboardIdParseError),
    #[error("❌ SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),
    #[error("❌ Timed out waiting for job")]
    TimedOut,
    #[error("❌ Too much output to display on terminal, try `--file`")]
    TooMuchOutput,
    #[error("❌ No sled with serial `{serial}` has a status for job `{job_id}`")]
    UnknownSerial { serial: String, job_id: JobId },
    #[error("❌ Serial `{0}` matches no sled in the rack inventory")]
    UnknownRackSerial(String),
    #[error("❌ Chain root does not match any supplied root certificate")]
    UntrustedRoot,
    #[error("❌ Can't start interactive session: {0}")]
    Upgrade(String),
    #[error("❌ UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("❌ WebSocket error: {0}")]
    WebSocket(#[from] WebSocketError),
    #[cfg(feature = "permslip")]
    #[error("❌ Unsupported permslip response: {0}")]
    UnsupportedPermslipResponse(String),
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
            CommunicationError(e) if e.is_timeout() => CommandError::TimedOut,
            CommunicationError(e) => CommandError::Client(format!("Communication error: {e}")),
            InvalidUpgrade(e) => CommandError::Client(e.to_string()),
            ErrorResponse(e) if e.status() == StatusCode::NOT_FOUND => {
                CommandError::NotFound(e.message.to_owned())
            }
            ErrorResponse(e) if e.status() == StatusCode::REQUEST_TIMEOUT => CommandError::TimedOut,
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
            Some(StatusCode::NOT_FOUND) => Self::NotFound(String::from("Job output not found")),
            Some(status) => Self::Client(status.to_string()),
            None => Self::Client(error.to_string()),
        }
    }
}

impl From<ClientError<Upgraded>> for CommandError {
    fn from(error: ClientError<Upgraded>) -> Self {
        match error.status() {
            Some(StatusCode::NOT_FOUND) => {
                Self::NotFound(String::from("Interactive job not found"))
            }
            Some(status) => Self::Client(status.to_string()),
            None => Self::Client(error.to_string()),
        }
    }
}
