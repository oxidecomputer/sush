//! HTTP API for the Oxide Support Shell server.
//!
//! A paper-thin wrapper around [`JobManager`].

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU32;

use chrono::{DateTime, Utc};
use dropshot::{
    ApiDescription, Body, ClientErrorStatusCode, EmptyScanParams, Header, HttpError,
    HttpResponseOk, PaginationParams, Path as PathParams, Query as QueryParams, RequestContext,
    ResultsPage, TypedBody, WhichPage, endpoint,
};
use http_range_header::{SyntacticallyCorrectRange as Range, parse_range_header};
use hyper::Response;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::{Deserializer, Error as DeserializeError, IntoDeserializer, MapAccess, Visitor};

use sush_common::certs::{KeyId, pem_cert_chain};
use sush_common::jobs::{JobId, JobLimits, JobOutputStream, JobStatus, JobsReserved, SignedJob};

use crate::manager::{JobError, JobManager};

type Context = RequestContext<JobManager>;

pub fn api() -> ApiDescription<JobManager> {
    let mut api = ApiDescription::new();
    api.register(import_cert).unwrap();
    api.register(cert_chain).unwrap();
    api.register(reserve_jobs).unwrap();
    api.register(get_reserved).unwrap();
    api.register(revoke_reserved).unwrap();
    api.register(job_start).unwrap();
    api.register(job_status).unwrap();
    api.register(job_output).unwrap();
    api.register(job_output_delete).unwrap();
    api.register(job_abort).unwrap();
    api.register(history).unwrap();
    api
}

// Certificate requests.

/// Import a certificate, verify its signature, and return a key ID for it.
#[endpoint { method = PUT, path = "/certs" }]
async fn import_cert(
    ctx: Context,
    params: TypedBody<Vec<u8>>,
) -> Result<HttpResponseOk<KeyId>, HttpError> {
    let cert = params.into_inner();
    let key_id = ctx.context().import_cert_bytes(&cert).await?;
    Ok(HttpResponseOk(key_id))
}

#[derive(Deserialize, JsonSchema)]
struct CertChainParams {
    key_id: KeyId,
}

/// Get the certificate chain that validates a key.
///
/// Certificates are in root-to-leaf order,
/// PEM encoded and newline separated.
#[endpoint { method = GET, path = "/certs/{key_id}" }]
async fn cert_chain(
    ctx: Context,
    params: PathParams<CertChainParams>,
) -> Result<HttpResponseOk<String>, HttpError> {
    let CertChainParams { key_id } = params.into_inner();
    let certs = ctx.context().cert_chain(key_id).await?;
    let chain = pem_cert_chain(certs).map_err(JobError::Cert)?;
    Ok(HttpResponseOk(chain))
}

// Job reservation requests.

/// Reserve some job slots with fresh, globally unique IDs.
#[endpoint { method = POST, path = "/reserved" }]
async fn reserve_jobs(
    ctx: Context,
    params: TypedBody<u8>,
) -> Result<HttpResponseOk<JobsReserved>, HttpError> {
    let number = params.into_inner();
    let response = ctx.context().reserve_jobs(number).await?;
    Ok(HttpResponseOk(response))
}

/// Map of job ID → time reserved for unused job slots.
#[endpoint { method = GET, path = "/reserved" }]
async fn get_reserved(
    ctx: Context,
) -> Result<HttpResponseOk<BTreeMap<JobId, DateTime<Utc>>>, HttpError> {
    let response = ctx.context().get_reserved().await?;
    Ok(HttpResponseOk(response))
}

/// Revoke a set of reserved but unused job slots.
///
/// Has no effect on jobs already started or finished, so it is safe to
/// call this with a list of IDs where some have been used. If called with
/// an empty list, revokes all reserved but unused jobs. Returns the list
/// of jobs actually revoked.
#[endpoint { method = DELETE, path = "/reserved" }]
async fn revoke_reserved(
    ctx: Context,
    params: TypedBody<Vec<JobId>>,
) -> Result<HttpResponseOk<Vec<JobId>>, HttpError> {
    let job_ids = params.into_inner();
    let revoked = ctx.context().revoke_reserved(job_ids).await?;
    Ok(HttpResponseOk(revoked))
}

// Job management requests.

#[derive(Deserialize, JsonSchema)]
struct JobIdParam {
    job_id: JobId,
}

#[derive(Deserialize, JsonSchema)]
struct JobStartParams {
    #[serde(flatten, deserialize_with = "deserialize_job_limits")]
    limits: JobLimits,

    /// Keep the request open until the job ends.
    wait: bool,
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

#[endpoint { method = POST, path = "/jobs/{job_id}/start" }]
async fn job_start(
    ctx: Context,
    params: PathParams<JobIdParam>,
    query: QueryParams<JobStartParams>,
    body: TypedBody<SignedJob>,
) -> Result<HttpResponseOk<JobStatus>, HttpError> {
    let mgr = ctx.context();
    let JobIdParam { job_id } = params.into_inner();
    let JobStartParams { limits, wait } = query.into_inner();
    let job = body.into_inner();
    if *job.job_id() != job_id {
        return Err(HttpError::for_client_error(
            None,
            ClientErrorStatusCode::BAD_REQUEST,
            String::from("query parameter job ID does not match body"),
        ));
    }
    let done = mgr.job_start(job, limits).await?;
    if wait {
        done.await
            .map_err(|_| {
                HttpError::for_internal_error(String::from("can't wait for job, sender dropped"))
            })?
            .map_err(JobError::from)?;
    }
    Ok(HttpResponseOk(ctx.context().job_status(&job_id).await?))
}

/// Get the status of a started job.
#[endpoint { method = GET, path = "/jobs/{job_id}/status" }]
async fn job_status(
    ctx: Context,
    params: PathParams<JobIdParam>,
) -> Result<HttpResponseOk<JobStatus>, HttpError> {
    let JobIdParam { job_id } = params.into_inner();
    let status = ctx.context().job_status(&job_id).await?;
    Ok(HttpResponseOk(status))
}

/// `Range` request header.
#[derive(Debug, Deserialize, JsonSchema)]
struct RangeRequest {
    /// A request to access a portion of the resource, such as `bytes=0-499`
    ///
    /// See: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Range>
    range: Option<String>,
}

impl RangeRequest {
    /// Extract a single range from the `Range` request header.
    /// This is just to avoid the complexity of encoding multiple
    /// ranges as output, not an inherent limitation.
    fn range(&self) -> Result<Option<Range>, HttpError> {
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

#[derive(Deserialize, JsonSchema)]
struct JobOutputParams {
    job_id: JobId,
    stream: JobOutputStream,
}

/// Get (a subset of) the standard output or standard error of a job.
#[endpoint { method = GET, path = "/jobs/{job_id}/output/{stream}" }]
async fn job_output(
    ctx: Context,
    headers: Header<RangeRequest>,
    params: PathParams<JobOutputParams>,
) -> Result<Response<Body>, HttpError> {
    let range = headers.into_inner().range()?;
    let JobOutputParams { job_id, stream } = params.into_inner();
    let stdout = ctx.context().job_output(&job_id, stream, range).await?;
    Ok(Response::new(stdout.into()))
}

/// Truncate the standard output or standard error of a job.
/// Returns its new length.
#[endpoint { method = DELETE, path = "/jobs/{job_id}/output/{stream}" }]
async fn job_output_delete(
    ctx: Context,
    headers: Header<RangeRequest>,
    params: PathParams<JobOutputParams>,
) -> Result<HttpResponseOk<u64>, HttpError> {
    let range = headers.into_inner().range()?;
    let JobOutputParams { job_id, stream } = params.into_inner();
    let n = ctx
        .context()
        .job_output_delete(&job_id, stream, range)
        .await?;
    Ok(HttpResponseOk(n))
}

/// Abort a started job.
#[endpoint { method = GET, path = "/jobs/{job_id}/abort" }]
async fn job_abort(
    ctx: Context,
    params: PathParams<JobIdParam>,
) -> Result<HttpResponseOk<()>, HttpError> {
    let JobIdParam { job_id } = params.into_inner();
    ctx.context().job_abort(&job_id).await?;
    Ok(HttpResponseOk(()))
}

/// List previous jobs (paginated).
#[endpoint { method = GET, path = "/history" }]
async fn history(
    ctx: Context,
    params: QueryParams<PaginationParams<EmptyScanParams, JobId>>,
) -> Result<HttpResponseOk<ResultsPage<JobStatus>>, HttpError> {
    let pag_params = params.into_inner();
    let Some(limit) = NonZeroU32::new(ctx.page_limit(&pag_params)?.get()) else {
        return Err(HttpError::for_client_error(
            None,
            ClientErrorStatusCode::BAD_REQUEST,
            String::from("page limit must be non-zero"),
        ));
    };

    let mgr = ctx.context();
    let list = match pag_params.page {
        WhichPage::First(..) => mgr.job_history(None, limit).await?,
        WhichPage::Next(job_id) => mgr.job_history(Some(job_id), limit).await?,
    };

    Ok(HttpResponseOk(ResultsPage::new(
        list,
        &EmptyScanParams {},
        |job: &JobStatus, _| job.job_id().to_owned(),
    )?))
}
