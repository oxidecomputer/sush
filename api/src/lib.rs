//! Oxide Support Shell API

use std::collections::BTreeMap;
use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use dropshot::{
    Body, ClientErrorStatusCode, Header, HttpError, HttpResponseOk, HttpResponseUpdatedNoContent,
    Path as PathParams, Query as QueryParams, RequestContext, TypedBody, WebsocketEndpointResult,
    WebsocketUpgrade, api_description,
};
use http_range_header::{SyntacticallyCorrectRange as Range, parse_range_header};
use hyper::Response;
use schemars::JsonSchema;
use serde::de::{Deserializer, Error as DeserializeError, IntoDeserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sled_hardware_types::BaseboardId;

use sush_common::authn::Identity;
use sush_common::jobs::{
    JobId, JobLimits, JobOutputStream, JobStatus, JsonJobStatusMap, Session, SessionId, SignedJob,
};
use sush_common::keys::{KeyId, SshPublicKey};

/// Oxide Support Shell API
#[api_description]
pub trait SushApi {
    type Context;

    // Certificate management.

    /// Import a certificate, verify its signature, and return a key ID for it.
    #[endpoint { method = PUT, path = "/certs" }]
    async fn import_cert(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: TypedBody<Vec<u8>>,
    ) -> Result<HttpResponseOk<KeyId>, HttpError>;

    /// Get the certificate chain that validates a key.
    ///
    /// Certificates are in root-to-leaf order, PEM encoded and newline separated.
    #[endpoint { method = GET, path = "/certs/{key_id}" }]
    async fn cert_chain(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<KeyIdParam>,
    ) -> Result<HttpResponseOk<String>, HttpError>;

    // Identity management.

    /// Prove and register identity.
    #[endpoint { method = POST, path = "/iam" }]
    async fn iam(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        body: TypedBody<Option<SshPublicKey>>,
    ) -> Result<HttpResponseOk<Identity>, HttpError>;

    /// List cached identities.
    ///
    /// May include duplicate identities with different nonces.
    #[endpoint { method = GET, path = "/iam" }]
    async fn identities(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<Vec<Identity>>, HttpError>;

    // Session management.

    /// Get the current session from this server's point of view.
    #[endpoint { method = GET, path = "/sessions" }]
    async fn session(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<Session>, HttpError>;

    /// Start a new support session.
    ///
    /// There may only be one session active on the rack at a time.
    /// If a session is already running when this request is made,
    /// the new session supersedes the old one, but the old session's
    /// jobs are not stopped.
    #[endpoint { method = POST, path = "/sessions/{session_id}/start" }]
    async fn session_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionIdParam>,
        query: QueryParams<SessionStartParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// End a support session.
    #[endpoint { method = POST, path = "/sessions/{session_id}/stop" }]
    async fn session_stop(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionIdParam>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Burn a job ID in the current session.
    #[endpoint { method = POST, path = "/sessions/{session_id}/skip/{job_id}" }]
    async fn session_skip_job(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionAndJobIds>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // Job management.

    /// Start an authorized job.
    #[endpoint { method = POST, path = "/jobs/{job_id}/start" }]
    async fn job_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        query: QueryParams<JobStartParams>,
        body: TypedBody<SignedJob>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Stop a (running) job.
    #[endpoint { method = POST, path = "/jobs/{job_id}/stop" }]
    async fn job_stop(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        query: QueryParams<JobStopParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Get the status of a job across the rack.
    #[endpoint { method = GET, path = "/jobs/{job_id}/status" }]
    async fn job_status(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
    ) -> Result<HttpResponseOk<JsonJobStatusMap>, HttpError>;

    /// Get (a subset of) the standard output or standard error of a job.
    #[endpoint { method = GET, path = "/jobs/{job_id}/output/{target}/{stream}" }]
    async fn job_output(
        ctx: RequestContext<Self::Context>,
        headers: Header<AuthorizedRangeRequest>,
        params: PathParams<JobOutputParams>,
    ) -> Result<Response<Body>, HttpError>;

    /// Attach to an interactive job.
    // This should use `channel { protocol = WEBSOCKETS, .. }`, but that
    // does not currently let us return (unauthorized) errors before the
    // connection upgrade.
    #[endpoint { method = GET, path = "/jobs/{job_id}/attach/{target}" }]
    async fn job_attach(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobAttachParams>,
        upgrade: WebsocketUpgrade,
    ) -> WebsocketEndpointResult;

    /// List previous jobs sorted by start time, most recent first.
    #[endpoint { method = GET, path = "/jobs" }]
    async fn job_history(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        query: QueryParams<JobHistoryParams>,
    ) -> Result<HttpResponseOk<Vec<JsonJobStatusMap>>, HttpError>;

    /// Get the baseboard ID of the sled handling this request.
    #[endpoint { method = GET, path = "/target" }]
    async fn target(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<BaseboardId>, HttpError>;
}

#[derive(Deserialize, JsonSchema)]
pub struct KeyIdParam {
    pub key_id: KeyId,
}

#[derive(Deserialize, JsonSchema)]
pub struct SessionIdParam {
    pub session_id: SessionId,
}

#[derive(Deserialize, JsonSchema)]
pub struct SessionAndJobIds {
    pub session_id: SessionId,
    pub job_id: JobId,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, BorshSerialize, BorshDeserialize)]
#[serde(default)]
pub struct SessionStartParams {
    /// Wait for the session to become active.
    pub wait: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct JobIdParam {
    pub job_id: JobId,
}

#[derive(Deserialize, JsonSchema)]
pub struct JobAttachParams {
    /// Which job to attach to.
    pub job_id: JobId,

    /// To be used by Nexus for routing.
    pub target: String,
}

/// Job parameters _not_ specified in the signed job request.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, BorshSerialize, BorshDeserialize)]
#[serde(default)]
pub struct JobStartParams {
    #[serde(flatten, deserialize_with = "deserialize_job_limits")]
    pub limits: JobLimits,

    /// Terminal type for interactive jobs.
    pub term: Option<String>,

    /// Terminal window height for interactive jobs.
    pub rows: Option<u16>,

    /// Terminal window width for interactive jobs.
    pub cols: Option<u16>,

    /// Wait for the job to start or stop.
    pub wait: JobWait,
}

/// Whether and until what state is reached to wait for a job start/stop request.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    JsonSchema,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum JobWait {
    #[default]
    None,
    Start,
    Stop,
}

impl JobWait {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    pub fn matches_status(&self, status: &JobStatus) -> bool {
        use JobStatus::*;
        match self {
            Self::None => true,
            Self::Start => !matches!(status, Queued { .. }),
            Self::Stop => matches!(status, Cancelled { .. } | Error { .. } | Stopped { .. }),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, BorshSerialize, BorshDeserialize)]
#[serde(default)]
pub struct JobStopParams {
    /// Wait for the job process to end.
    pub wait: JobWait,
}

/// Simple pagination for history list.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct JobHistoryParams {
    /// limit=0 means all jobs
    pub limit: u32,
    pub offset: u32,
}

/// This deserialization method is a work-around for a bug in Serde; see
/// [sush#3](https://github.com/oxidecomputer/sush/pull/3#discussion_r2613036692) and
/// [serde#1183](https://github.com/serde-rs/serde/issues/1183#issuecomment-668315831).
/// Luckily limits are homogeneous, so it's pretty simple.
fn deserialize_job_limits<'de, D>(de: D) -> Result<JobLimits, D::Error>
where
    D: Deserializer<'de>,
{
    struct LimitsVisitor;

    impl<'de> Visitor<'de> for LimitsVisitor {
        type Value = JobLimits;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a homogeneous map of process limits")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut limits = BTreeMap::<String, u64>::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                limits.insert(key, value.parse().map_err(DeserializeError::custom)?);
            }
            <JobLimits as Deserialize>::deserialize(limits.into_deserializer())
        }
    }

    de.deserialize_map(LimitsVisitor)
}

#[derive(Deserialize, JsonSchema)]
pub struct JobOutputParams {
    pub job_id: JobId,
    pub target: String,
    pub stream: JobOutputStream,
}

/// Authorized `Range` request headers.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AuthorizedRangeRequest {
    /// Authorization to access the range.
    ///
    /// See: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Authorization>
    pub authorization: Option<String>,

    /// A request to access a portion of the resource, such as `bytes=0-499`
    ///
    /// See: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Range>
    range: Option<String>,
}

impl AuthorizedRangeRequest {
    /// Extract a single range from the `Range` request header.
    /// This is just to avoid the complexity of encoding multiple
    /// ranges as output, not an inherent limitation.
    pub fn range(&self) -> Result<Option<Range>, HttpError> {
        let Some(header) = self.range.as_ref() else {
            return Ok(None);
        };
        let mut parsed = parse_range_header(header).map_err(|e| {
            HttpError::for_client_error(
                None,
                ClientErrorStatusCode::RANGE_NOT_SATISFIABLE,
                e.to_string(),
            )
        })?;
        let range = if parsed.ranges.len() == 1 {
            parsed.ranges.pop().unwrap()
        } else {
            return Err(HttpError::for_client_error(
                None,
                ClientErrorStatusCode::RANGE_NOT_SATISFIABLE,
                String::from("one range at a time, please"),
            ));
        };
        Ok(Some(range))
    }
}

/// HTTP "Authorization" header.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct Authorization {
    /// Authorization to access some resource, such as a signature.
    ///
    /// See: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Authorization>
    pub authorization: Option<String>,
}
