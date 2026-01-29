//! Oxide Support Shell API

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use dropshot::{
    Body, ClientErrorStatusCode, EmptyScanParams, Header, HttpError, HttpResponseOk,
    PaginationParams, Path as PathParams, Query as QueryParams, RequestContext, ResultsPage,
    TypedBody, WebsocketEndpointResult, WebsocketUpgrade, api_description,
};
use http_range_header::{SyntacticallyCorrectRange as Range, parse_range_header};
use hyper::Response;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::{Deserializer, Error as DeserializeError, IntoDeserializer, MapAccess, Visitor};

use sush_common::certs::KeyId;
use sush_common::jobs::{JobId, JobLimits, JobOutputStream, JobStatus, JobsReserved, SignedJob};

/// Oxide Support Shell API
#[api_description]
pub trait SushApi {
    type Context;

    // Certificate requests.

    /// Import a certificate, verify its signature, and return a key ID for it.
    #[endpoint { method = PUT, path = "/certs" }]
    async fn import_cert(
        ctx: RequestContext<Self::Context>,
        params: TypedBody<Vec<u8>>,
    ) -> Result<HttpResponseOk<KeyId>, HttpError>;

    /// Get the certificate chain that validates a key.
    ///
    /// Certificates are in root-to-leaf order,
    /// PEM encoded and newline separated.
    #[endpoint { method = GET, path = "/certs/{key_id}" }]
    async fn cert_chain(
        ctx: RequestContext<Self::Context>,
        params: PathParams<CertChainParams>,
    ) -> Result<HttpResponseOk<String>, HttpError>;

    // Job reservation requests.

    /// Reserve some job slots with fresh, globally unique IDs.
    #[endpoint { method = POST, path = "/reserved" }]
    async fn reserve_jobs(
        ctx: RequestContext<Self::Context>,
        params: TypedBody<u8>,
    ) -> Result<HttpResponseOk<JobsReserved>, HttpError>;

    /// Map of job ID → time reserved for unused job slots.
    #[endpoint { method = GET, path = "/reserved" }]
    async fn get_reserved(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BTreeMap<JobId, DateTime<Utc>>>, HttpError>;

    /// Revoke a set of reserved but unused job slots.
    ///
    /// Has no effect on jobs already started or finished, so it is safe to
    /// call this with a list of IDs where some have been used. If called with
    /// an empty list, revokes all reserved but unused jobs. Returns the list
    /// of jobs actually revoked.
    #[endpoint { method = DELETE, path = "/reserved" }]
    async fn revoke_reserved(
        ctx: RequestContext<Self::Context>,
        params: TypedBody<Vec<JobId>>,
    ) -> Result<HttpResponseOk<Vec<JobId>>, HttpError>;

    // Job management requests.

    /// Start an authorized job.
    #[endpoint { method = POST, path = "/jobs/{job_id}/start" }]
    async fn job_start(
        ctx: RequestContext<Self::Context>,
        params: PathParams<JobIdParam>,
        query: QueryParams<JobStartParams>,
        body: TypedBody<SignedJob>,
    ) -> Result<HttpResponseOk<JobStatus>, HttpError>;

    /// Get the status of a started job.
    #[endpoint { method = GET, path = "/jobs/{job_id}/status" }]
    async fn job_status(
        ctx: RequestContext<Self::Context>,
        params: PathParams<JobIdParam>,
    ) -> Result<HttpResponseOk<JobStatus>, HttpError>;

    /// Start a new interactive job session.
    // This should use `channel { protocol = WEBSOCKETS, .. }`, but that
    // does not currently let us return errors before the connection upgrade.
    #[endpoint { method = GET, path = "/jobs/{job_id}/session" }]
    async fn job_session(
        ctx: RequestContext<Self::Context>,
        params: PathParams<JobIdParam>,
        upgrade: WebsocketUpgrade,
    ) -> WebsocketEndpointResult;

    /// Abort a started job.
    #[endpoint { method = GET, path = "/jobs/{job_id}/abort" }]
    async fn job_abort(
        ctx: RequestContext<Self::Context>,
        params: PathParams<JobIdParam>,
    ) -> Result<HttpResponseOk<()>, HttpError>;

    /// Get (a subset of) the standard output or standard error of a job.
    #[endpoint { method = GET, path = "/jobs/{job_id}/output/{stream}" }]
    async fn job_output(
        ctx: RequestContext<Self::Context>,
        headers: Header<RangeRequest>,
        params: PathParams<JobOutputParams>,
    ) -> Result<Response<Body>, HttpError>;

    /// Truncate the standard output or standard error of a job.
    /// Returns its new length.
    #[endpoint { method = DELETE, path = "/jobs/{job_id}/output/{stream}" }]
    async fn job_output_delete(
        ctx: RequestContext<Self::Context>,
        headers: Header<RangeRequest>,
        params: PathParams<JobOutputParams>,
    ) -> Result<HttpResponseOk<u64>, HttpError>;

    /// List previous jobs (paginated).
    #[endpoint { method = GET, path = "/history" }]
    async fn history(
        ctx: RequestContext<Self::Context>,
        params: QueryParams<PaginationParams<EmptyScanParams, JobId>>,
    ) -> Result<HttpResponseOk<ResultsPage<JobStatus>>, HttpError>;
}

#[derive(Deserialize, JsonSchema)]
pub struct CertChainParams {
    pub key_id: KeyId,
}

#[derive(Deserialize, JsonSchema)]
pub struct JobIdParam {
    pub job_id: JobId,
}

#[derive(Deserialize, JsonSchema)]
pub struct JobStartParams {
    #[serde(flatten, deserialize_with = "deserialize_job_limits")]
    pub limits: JobLimits,

    /// Keep the request open until the job ends.
    pub wait: bool,
}

/// This deserialization method is a work-around for a bug in Serde; see
/// <https://github.com/oxidecomputer/sush/pull/3#discussion_r2613036692>,
/// <https://github.com/serde-rs/serde/issues/1183#issuecomment-668315831>.
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
            JobLimits::deserialize(limits.into_deserializer())
        }
    }

    de.deserialize_map(LimitsVisitor)
}

#[derive(Deserialize, JsonSchema)]
pub struct JobOutputParams {
    pub job_id: JobId,
    pub stream: JobOutputStream,
}

/// `Range` request header.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RangeRequest {
    /// A request to access a portion of the resource, such as `bytes=0-499`
    ///
    /// See: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Range>
    range: Option<String>,
}

impl RangeRequest {
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
