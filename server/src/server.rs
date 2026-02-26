//! API server for the Oxide Support Shell.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use chrono::{DateTime, Utc};
use dropshot::{
    Body, ClientErrorStatusCode, EmptyScanParams, Header, HttpError, HttpResponseDeleted,
    HttpResponseOk, PaginationParams, Path as PathParams, Query as QueryParams, RequestContext,
    ResultsPage, TypedBody, WebsocketEndpointResult, WebsocketUpgrade, WhichPage,
};
use hyper::Response;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, DecodePem as _};

use sush_api::{
    Authorization, JobIdParam, JobOutputParams, JobStartParams, KeyIdParam, RangeRequest, SushApi,
};
use sush_common::authn::Identity;
use sush_common::jobs::{JobId, JobStatus, JobsReserved, SignedJob};
use sush_common::keys::{KeyId, SshPublicKey, pem_cert_chain};

use crate::error::JobError;
use crate::manager::JobManager;

pub struct ApiServer;

impl SushApi for ApiServer {
    type Context = JobManager;

    async fn import_cert(
        ctx: RequestContext<Self::Context>,
        params: TypedBody<Vec<u8>>,
    ) -> Result<HttpResponseOk<KeyId>, HttpError> {
        let bytes = params.into_inner();
        let cert = Certificate::from_pem(&bytes)
            .or_else(|_| Certificate::from_der(&bytes))
            .map_err(JobError::Der)?;
        let key_id = ctx.context().import_cert(&cert).await?;
        Ok(HttpResponseOk(key_id))
    }

    async fn cert_chain(
        ctx: RequestContext<Self::Context>,
        params: PathParams<KeyIdParam>,
    ) -> Result<HttpResponseOk<String>, HttpError> {
        let KeyIdParam { key_id } = params.into_inner();
        let certs = ctx.context().cert_chain(key_id).await?;
        let chain = pem_cert_chain(certs).map_err(JobError::Key)?;
        Ok(HttpResponseOk(chain))
    }

    async fn reserve_jobs(
        ctx: RequestContext<Self::Context>,
        params: TypedBody<u8>,
    ) -> Result<HttpResponseOk<JobsReserved>, HttpError> {
        let number = params.into_inner();
        let response = ctx.context().reserve_jobs(number).await?;
        Ok(HttpResponseOk(response))
    }

    async fn get_reserved(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BTreeMap<JobId, DateTime<Utc>>>, HttpError> {
        let response = ctx.context().get_reserved().await?;
        Ok(HttpResponseOk(response))
    }

    async fn revoke_reserved(
        ctx: RequestContext<Self::Context>,
        params: TypedBody<Vec<JobId>>,
    ) -> Result<HttpResponseOk<Vec<JobId>>, HttpError> {
        let job_ids = params.into_inner();
        let revoked = ctx.context().revoke_reserved(job_ids).await?;
        Ok(HttpResponseOk(revoked))
    }

    async fn job_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        query: QueryParams<JobStartParams>,
        body: TypedBody<SignedJob>,
    ) -> Result<HttpResponseOk<JobStatus>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = if authorization.is_some() {
            Some(mgr.iam(authorization, None).await?)
        } else {
            None
        };
        let JobIdParam { job_id } = params.into_inner();
        let params = query.into_inner();
        let job = body.into_inner();
        if *job.job_id() != job_id {
            return Err(HttpError::for_client_error(
                None,
                ClientErrorStatusCode::BAD_REQUEST,
                String::from("Query parameter job ID does not match body"),
            ));
        }
        if let Some(Ok(end)) = mgr.job_start(job, params, authn).await? {
            Ok(HttpResponseOk(end.into()))
        } else {
            Ok(HttpResponseOk(mgr.job_status(&job_id).await?))
        }
    }

    async fn job_status(
        ctx: RequestContext<Self::Context>,
        params: PathParams<JobIdParam>,
    ) -> Result<HttpResponseOk<JobStatus>, HttpError> {
        let JobIdParam { job_id } = params.into_inner();
        let status = ctx.context().job_status(&job_id).await?;
        Ok(HttpResponseOk(status))
    }

    async fn job_session(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        upgrade: WebsocketUpgrade,
    ) -> WebsocketEndpointResult {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobIdParam { job_id } = params.into_inner();
        let session = mgr.job_session(&job_id, &authn).await?;
        upgrade.handle(async move |conn| {
            let socket = conn.into_inner();
            let stream = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
            session.try_send(stream).map_err(|_| {
                HttpError::for_client_error(
                    None,
                    ClientErrorStatusCode::NOT_FOUND,
                    String::from("Interactive session unavailable"),
                )
            })?;
            Ok(())
        })
    }

    async fn job_abort(
        ctx: RequestContext<Self::Context>,
        params: PathParams<JobIdParam>,
    ) -> Result<HttpResponseOk<()>, HttpError> {
        let JobIdParam { job_id } = params.into_inner();
        ctx.context().job_abort(&job_id).await?;
        Ok(HttpResponseOk(()))
    }

    async fn job_output(
        ctx: RequestContext<Self::Context>,
        headers: Header<RangeRequest>,
        params: PathParams<JobOutputParams>,
    ) -> Result<Response<Body>, HttpError> {
        let range = headers.into_inner().range()?;
        let JobOutputParams { job_id, stream } = params.into_inner();
        let stdout = ctx.context().job_output(&job_id, stream, range).await?;
        Ok(Response::new(stdout.into()))
    }

    async fn job_output_delete(
        ctx: RequestContext<Self::Context>,
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

    async fn history(
        ctx: RequestContext<Self::Context>,
        params: QueryParams<PaginationParams<EmptyScanParams, JobId>>,
    ) -> Result<HttpResponseOk<ResultsPage<JobStatus>>, HttpError> {
        let pag_params = params.into_inner();
        let Some(limit) = NonZeroU32::new(ctx.page_limit(&pag_params)?.get()) else {
            return Err(HttpError::for_client_error(
                None,
                ClientErrorStatusCode::BAD_REQUEST,
                String::from("Page limit must be non-zero"),
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

    async fn iam(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        body: TypedBody<Option<SshPublicKey>>,
    ) -> Result<HttpResponseOk<Identity>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let public_key = body.into_inner();
        let identity = mgr.iam(authorization, public_key).await?;
        Ok(HttpResponseOk(identity))
    }

    async fn identities(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: QueryParams<PaginationParams<EmptyScanParams, KeyId>>,
    ) -> Result<HttpResponseOk<ResultsPage<Identity>>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let pag_params = params.into_inner();
        let Some(limit) = NonZeroU32::new(ctx.page_limit(&pag_params)?.get()) else {
            return Err(HttpError::for_client_error(
                None,
                ClientErrorStatusCode::BAD_REQUEST,
                String::from("Page limit must be non-zero"),
            ));
        };
        let list = match pag_params.page {
            WhichPage::First(..) => mgr.identities(None, limit, &authn).await?,
            WhichPage::Next(key_id) => mgr.identities(Some(key_id), limit, &authn).await?,
        };
        Ok(HttpResponseOk(ResultsPage::new(
            list,
            &EmptyScanParams {},
            |identity: &Identity, _| identity.key_id.to_owned(),
        )?))
    }

    async fn revoke_identity(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<KeyIdParam>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let KeyIdParam { key_id } = params.into_inner();
        mgr.revoke_identity(key_id, &authn).await?;
        Ok(HttpResponseDeleted())
    }
}
