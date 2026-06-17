//! API server for the Oxide Support Shell.

use dropshot::{
    Body, ClientErrorStatusCode, Header, HttpError, HttpResponseOk, Path as PathParams,
    Query as QueryParams, RequestContext, TypedBody, WebsocketEndpointResult, WebsocketUpgrade,
};
use hyper::Response;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, DecodePem as _};

use sush_api::{
    Authorization, AuthorizedRangeRequest, JobHistoryParams, JobIdParam, JobOutputParams,
    JobStartParams, KeyIdParam, SessionIdParam, SushApi,
};
use sush_common::authn::Identity;
use sush_common::jobs::{JobStatus, Session, SignedJob};
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
        if let Some(session) = mgr.session(&authn).await? {
            Ok(HttpResponseOk(session))
        } else {
            Err(JobError::NoSession.into())
        }
    }

    async fn session_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<Session>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let session = mgr.session_start(&authn).await?;
        Ok(HttpResponseOk(session))
    }

    async fn session_stop(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionIdParam>,
    ) -> Result<HttpResponseOk<()>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let SessionIdParam { session_id } = params.into_inner();
        mgr.session_stop(&authn, &session_id).await?;
        Ok(HttpResponseOk(()))
    }

    // Job management.

    async fn job_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        query: QueryParams<JobStartParams>,
        body: TypedBody<SignedJob>,
    ) -> Result<HttpResponseOk<JobStatus>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
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
        match mgr.job_start(&authn, job, params).await? {
            None => Ok(HttpResponseOk(mgr.job_status(&authn, &job_id).await?)),
            Some(Ok(end)) => Ok(HttpResponseOk(mgr.job_end_status(&authn, end).await?)),
            Some(Err(err)) => Err(JobError::from(err).into()),
        }
    }

    async fn job_stop(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
    ) -> Result<HttpResponseOk<()>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobIdParam { job_id } = params.into_inner();
        mgr.job_stop(&authn, &job_id).await?;
        Ok(HttpResponseOk(()))
    }

    async fn job_status(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
    ) -> Result<HttpResponseOk<JobStatus>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobIdParam { job_id } = params.into_inner();
        Ok(HttpResponseOk(mgr.job_status(&authn, &job_id).await?))
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
        let JobOutputParams { job_id, stream } = params.into_inner();
        let stdout = mgr.job_output(&authn, &job_id, stream, range).await?;
        Ok(Response::new(stdout.into()))
    }

    async fn job_output_delete(
        ctx: RequestContext<Self::Context>,
        headers: Header<AuthorizedRangeRequest>,
        params: PathParams<JobOutputParams>,
    ) -> Result<HttpResponseOk<u64>, HttpError> {
        let mgr = ctx.context();
        let headers = headers.into_inner();
        let range = headers.range()?;
        let authn = mgr.iam(headers.authorization, None).await?;
        let JobOutputParams { job_id, stream } = params.into_inner();
        let n = mgr
            .job_output_delete(&authn, &job_id, stream, range)
            .await?;
        Ok(HttpResponseOk(n))
    }

    async fn job_start_interactive_session(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        upgrade: WebsocketUpgrade,
    ) -> WebsocketEndpointResult {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobIdParam { job_id } = params.into_inner();
        let session = mgr.job_start_interactive_session(&authn, &job_id).await?;
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

    async fn job_history(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        query: QueryParams<JobHistoryParams>,
    ) -> Result<HttpResponseOk<Vec<JobStatus>>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr.iam(authorization, None).await?;
        let JobHistoryParams { limit, offset } = query.into_inner();
        Ok(HttpResponseOk(
            mgr.job_history(&authn, limit, offset).await?,
        ))
    }
}
