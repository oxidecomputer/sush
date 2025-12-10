//! HTTP API for the Oxide Support Shell server.
//!
//! A paper-thin wrapper around [`JobManager`].

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use dropshot::{
    ApiDescription, ClientErrorStatusCode, HttpError, HttpResponseOk, Path as PathParams,
    Query as QueryParams, RequestContext, TypedBody, endpoint,
};
use schemars::JsonSchema;
use serde::Deserialize;

use sush_common::certs::{KeyId, pem_cert_chain};
use sush_common::jobs::{JobId, JobStatus, JobsReserved, SignedJob};

use crate::manager::{JobError, JobLimits, JobManager};

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
    api.register(job_stdout).unwrap();
    api.register(job_stderr).unwrap();
    api.register(job_abort).unwrap();
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
    wait: bool,
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
    let JobStartParams { wait } = query.into_inner();
    let job = body.into_inner();
    if job.job_id() != job_id {
        return Err(HttpError::for_client_error(
            None,
            ClientErrorStatusCode::BAD_REQUEST,
            String::from("query parameter job ID does not match body's"),
        ));
    }
    let status = mgr.job_start(job, JobLimits::default()).await?;
    if wait {
        Ok(HttpResponseOk(status.await.map_err(|_| {
            HttpError::for_internal_error(String::from("can't wait for job, sender dropped"))
        })??))
    } else {
        Ok(HttpResponseOk(ctx.context().job_status(job_id).await?))
    }
}

/// Get the status of a started job.
#[endpoint { method = GET, path = "/jobs/{job_id}/status" }]
async fn job_status(
    ctx: Context,
    params: PathParams<JobIdParam>,
) -> Result<HttpResponseOk<JobStatus>, HttpError> {
    let JobIdParam { job_id } = params.into_inner();
    let status = ctx.context().job_status(job_id).await?;
    Ok(HttpResponseOk(status))
}

/// Get the standard output of a job.
#[endpoint { method = GET, path = "/jobs/{job_id}/stdout" }]
async fn job_stdout(
    ctx: Context,
    params: PathParams<JobIdParam>,
) -> Result<HttpResponseOk<Vec<u8>>, HttpError> {
    // TODO: Range requests.
    let JobIdParam { job_id } = params.into_inner();
    let stdout = ctx.context().job_stdout(job_id, None).await?;
    Ok(HttpResponseOk(stdout))
}

/// Get the standard output of a job.
#[endpoint { method = GET, path = "/jobs/{job_id}/stderr" }]
async fn job_stderr(
    ctx: Context,
    params: PathParams<JobIdParam>,
) -> Result<HttpResponseOk<Vec<u8>>, HttpError> {
    // TODO: Range requests.
    let JobIdParam { job_id } = params.into_inner();
    let stderr = ctx.context().job_stderr(job_id, None).await?;
    Ok(HttpResponseOk(stderr))
}

/// Abort a started job.
#[endpoint { method = GET, path = "/jobs/{job_id}/abort" }]
async fn job_abort(
    ctx: Context,
    params: PathParams<JobIdParam>,
) -> Result<HttpResponseOk<()>, HttpError> {
    let JobIdParam { job_id } = params.into_inner();
    ctx.context().job_abort(job_id).await?;
    Ok(HttpResponseOk(()))
}
