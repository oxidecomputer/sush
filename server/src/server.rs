//! API server for the Oxide Support Shell.

use dropshot::{
    Body, ClientErrorStatusCode, Header, HttpError, HttpResponseOk, HttpResponseUpdatedNoContent,
    Path as PathParams, Query as QueryParams, RequestContext, TypedBody, WebsocketEndpointResult,
    WebsocketUpgrade,
};
use hyper::Response;
use sled_hardware_types::BaseboardId;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, DecodePem as _};

use sush_api::{
    Authorization, AuthorizedRangeRequest, JobAttachParams, JobHistoryParams, JobIdParam,
    JobOutputParams, JobStartParams, JobStopParams, KeyIdParam, SessionAndJobIds, SessionIdParam,
    SessionStartParams, SushApi,
};
use sush_common::authn::Identity;
use sush_common::jobs::{JsonJobStatusMap, Session, SignedJob, job_status_to_json_map};
use sush_common::keys::{KeyId, SshPublicKey, pem_cert_chain};

use crate::error::JobError;
use crate::manager::JobManager;

pub struct ApiServer;

impl SushApi for ApiServer {
    type Context = JobManager;

    // Certificate management.

    async fn import_cert(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: TypedBody<Vec<u8>>,
    ) -> Result<HttpResponseOk<KeyId>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let bytes = params.into_inner();
        let cert = Certificate::from_pem(&bytes)
            .or_else(|_| Certificate::from_der(&bytes))
            .map_err(JobError::Der)?;
        let key_id = mgr.import_cert(&authn, cert).await?;
        Ok(HttpResponseOk(key_id))
    }

    async fn cert_chain(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<KeyIdParam>,
    ) -> Result<HttpResponseOk<String>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let KeyIdParam { key_id } = params.into_inner();
        let certs = mgr.cert_chain(&authn, &key_id).await?;
        let chain = pem_cert_chain(certs).map_err(JobError::Key)?;
        Ok(HttpResponseOk(chain))
    }

    // Identity management.

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
    ) -> Result<HttpResponseOk<Vec<Identity>>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        Ok(HttpResponseOk(mgr.identities(&authn).await?))
    }

    // Session management.

    async fn session(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<Session>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        if let Some(session) = mgr.session(&authn) {
            Ok(HttpResponseOk(session))
        } else {
            Err(JobError::NoSession.into())
        }
    }

    async fn session_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionIdParam>,
        query: QueryParams<SessionStartParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let SessionIdParam { session_id } = params.into_inner();
        mgr.session_start(&authn, session_id.clone(), query.into_inner())
            .await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn session_stop(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionIdParam>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let SessionIdParam { session_id } = params.into_inner();
        mgr.session_stop(&authn, session_id).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn session_skip_job(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionAndJobIds>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let SessionAndJobIds { session_id, job_id } = params.into_inner();
        mgr.session_skip_job(&authn, session_id, job_id).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    // Job management.

    async fn job_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        query: QueryParams<JobStartParams>,
        body: TypedBody<SignedJob>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobIdParam { job_id } = params.into_inner();
        let job = body.into_inner();
        if *job.job_id() != job_id {
            return Err(HttpError::for_client_error(
                None,
                ClientErrorStatusCode::BAD_REQUEST,
                String::from("Query parameter job ID does not match body"),
            ));
        }
        mgr.job_start(&authn, job, query.into_inner()).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn job_stop(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        query: QueryParams<JobStopParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobIdParam { job_id } = params.into_inner();
        mgr.job_stop(&authn, &job_id, query.into_inner()).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn job_status(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
    ) -> Result<HttpResponseOk<JsonJobStatusMap>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobIdParam { job_id } = params.into_inner();
        Ok(HttpResponseOk(job_status_to_json_map(
            mgr.job_status(&authn, &job_id).await?,
        )))
    }

    async fn job_output(
        ctx: RequestContext<Self::Context>,
        headers: Header<AuthorizedRangeRequest>,
        params: PathParams<JobOutputParams>,
    ) -> Result<Response<Body>, HttpError> {
        let mgr = ctx.context();
        let headers = headers.into_inner();
        let range = headers.range()?;
        let authn = mgr.iam(headers.authorization, None).await?;
        let JobOutputParams {
            job_id,
            stream,
            target,
        } = params.into_inner();
        let target = if target == "*" {
            mgr.own_baseboard().clone()
        } else {
            target.parse().map_err(|_| {
                HttpError::for_client_error(
                    None,
                    ClientErrorStatusCode::BAD_REQUEST,
                    String::from("Unable to parse target as baseboard ID"),
                )
            })?
        };
        let stdout = mgr
            .job_output(&authn, &job_id, &target, stream, range)
            .await?;
        Ok(Response::new(stdout.into()))
    }

    async fn job_attach(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobAttachParams>,
        upgrade: WebsocketUpgrade,
    ) -> WebsocketEndpointResult {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobAttachParams { job_id, target } = params.into_inner();
        let target = if target == "*" {
            mgr.own_baseboard().clone()
        } else {
            target.parse().map_err(|_| {
                HttpError::for_client_error(
                    None,
                    ClientErrorStatusCode::BAD_REQUEST,
                    String::from("Unable to parse target as baseboard ID"),
                )
            })?
        };
        let attachment = mgr.job_attachment(&authn, &job_id, &target).await?;
        upgrade.handle(async move |conn| {
            let socket = conn.into_inner();
            let stream = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
            attachment.try_send(stream).map_err(|_| {
                HttpError::for_internal_error(String::from("Unable to attach to interactive job"))
            })?;
            Ok(())
        })
    }

    async fn job_history(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        query: QueryParams<JobHistoryParams>,
    ) -> Result<HttpResponseOk<Vec<JsonJobStatusMap>>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobHistoryParams { limit, offset } = query.into_inner();
        Ok(HttpResponseOk(
            mgr.job_history(&authn, limit, offset)
                .await?
                .into_iter()
                .map(job_status_to_json_map)
                .collect(),
        ))
    }

    async fn target(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<BaseboardId>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let _authn = mgr.iam(authorization, None).await?;
        Ok(HttpResponseOk(mgr.own_baseboard().to_owned()))
    }
}
