// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! API server for the Oxide Support Shell.

use std::sync::Arc;

use dropshot::{
    Body, CONTENT_TYPE_OCTET_STREAM, ClientErrorStatusCode, Header, HttpError, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path as PathParams, Query as QueryParams, RequestContext,
    TypedBody, WebsocketEndpointResult, WebsocketUpgrade,
};
use futures::TryStreamExt as _;
use http::StatusCode;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http_body_util::StreamBody;
use hyper::Response;
use hyper::body::Frame;
use sled_hardware_types::BaseboardId;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use x509_cert::Certificate;
use x509_cert::der::DecodePem as _;

use sush_api::{
    AccessParam, Authorization, AuthorizedRangeRequest, JobHistoryParams, JobIdParam,
    JobOutputParams, JobStartParams, JobStopParams, JobTargetParams, KeyIdParam, RoutingParam,
    SessionAndJobIds, SessionAndKeyIds, SessionIdParam, SessionStartBody, SessionStartNonce,
    SushApi, WaitParam,
};
use sush_common::authn::Identity;
use sush_common::jobs::{JsonJobStatusMap, Session, SignedJob, job_status_to_json_map};
use sush_common::keys::{KeyId, SshPublicKey, pem_cert_chain};
use sush_common::targets::SledVersion;
use sush_common::version::VersionInfo;

use crate::error::JobError;
use crate::manager::JobManager;

/// Cap on WebSocket messages.
const MAX_WS_MESSAGE_SIZE: usize = 0x10_0000;

pub struct ApiServer;

/// The request line as [`JobManager::iam`] wants it: the method and
/// the target exactly as received.
fn request_line(request: &dropshot::RequestInfo) -> (&str, &str) {
    (
        request.method().as_str(),
        request.uri().path_and_query().map_or("", |pq| pq.as_str()),
    )
}

impl SushApi for ApiServer {
    type Context = Arc<JobManager>;

    // Certificate management.

    async fn cert_import(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        query: QueryParams<WaitParam>,
        params: TypedBody<String>,
    ) -> Result<HttpResponseOk<KeyId>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let WaitParam { wait } = query.into_inner();
        let bytes = params.into_inner();
        let cert = Certificate::from_pem(&bytes).map_err(JobError::DecodeCert)?;
        let key_id = KeyId::try_from(&cert).map_err(JobError::Key)?;
        mgr.cert_import(&authn, cert, wait).await?;
        Ok(HttpResponseOk(key_id))
    }

    async fn cert_chain(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<KeyIdParam>,
    ) -> Result<HttpResponseOk<String>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let KeyIdParam { key_id } = params.into_inner();
        let certs = mgr.cert_chain(&authn, &key_id)?;
        let chain = pem_cert_chain(certs).map_err(JobError::Key)?;
        Ok(HttpResponseOk(chain))
    }

    async fn cert_revoke(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<KeyIdParam>,
        query: QueryParams<WaitParam>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let KeyIdParam { key_id } = params.into_inner();
        let WaitParam { wait } = query.into_inner();
        mgr.cert_revoke(&authn, key_id, wait).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    // Identity management.

    async fn iam(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        _query: QueryParams<RoutingParam>,
        body: TypedBody<Option<SshPublicKey>>,
    ) -> Result<HttpResponseOk<Identity>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let public_key = body.into_inner();
        let identity = mgr
            .iam(authorization, public_key, request_line(&ctx.request))
            .await?;
        Ok(HttpResponseOk(identity))
    }

    async fn identities(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<Vec<Identity>>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        Ok(HttpResponseOk(mgr.identities(&authn).await?))
    }

    async fn iam_revoke(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<KeyIdParam>,
        query: QueryParams<WaitParam>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let KeyIdParam { key_id } = params.into_inner();
        let WaitParam { wait } = query.into_inner();
        mgr.iam_revoke(&authn, key_id, wait).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    // Session management.

    async fn session(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<Session>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        if let Some(session) = mgr.session(&authn) {
            Ok(HttpResponseOk(session))
        } else {
            Err(JobError::NoSession.into())
        }
    }

    async fn session_start_nonce(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
    ) -> Result<HttpResponseOk<SessionStartNonce>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let _authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        Ok(HttpResponseOk(SessionStartNonce {
            nonce: mgr.regenerate_session_sush_nonce(),
        }))
    }

    async fn session_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionIdParam>,
        query: QueryParams<WaitParam>,
        body: TypedBody<SessionStartBody>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let WaitParam { wait } = query.into_inner();
        let SessionIdParam { session_id } = params.into_inner();
        let SessionStartBody { signer_nonce } = body.into_inner();
        mgr.session_start(&authn, session_id, signer_nonce, wait)
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
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
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
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let SessionAndJobIds { session_id, job_id } = params.into_inner();
        mgr.session_skip_job(&authn, session_id, job_id).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn session_allow_attach(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionAndKeyIds>,
        query: QueryParams<AccessParam>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let SessionAndKeyIds { session_id, key_id } = params.into_inner();
        let AccessParam { access } = query.into_inner();
        mgr.session_allow_attach(&authn, session_id, key_id, access)
            .await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn session_deny_attach(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<SessionAndKeyIds>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let SessionAndKeyIds { session_id, key_id } = params.into_inner();
        mgr.session_deny_attach(&authn, session_id, key_id).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    // Job management.

    async fn job_start(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobTargetParams>,
        query: QueryParams<JobStartParams>,
        body: TypedBody<SignedJob>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let JobTargetParams { job_id, target: _ } = params.into_inner();
        let job = body.into_inner();
        if *job.job_id() != job_id {
            return Err(HttpError::for_client_error(
                None,
                ClientErrorStatusCode::BAD_REQUEST,
                String::from("Path parameter job ID does not match body"),
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
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let JobIdParam { job_id } = params.into_inner();
        mgr.job_stop(&authn, &job_id, query.into_inner()).await?;
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn job_status(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobIdParam>,
        _query: QueryParams<RoutingParam>,
    ) -> Result<HttpResponseOk<JsonJobStatusMap>, HttpError> {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let JobIdParam { job_id } = params.into_inner();
        Ok(HttpResponseOk(job_status_to_json_map(
            mgr.job_status(&authn, &job_id).await?,
        )))
    }

    async fn job_output(
        ctx: RequestContext<Self::Context>,
        headers: Header<AuthorizedRangeRequest>,
        params: PathParams<JobOutputParams>,
        _query: QueryParams<RoutingParam>,
    ) -> Result<Response<Body>, HttpError> {
        let mgr = ctx.context();
        let headers = headers.into_inner();
        let range = headers.range()?;
        let authn = mgr
            .iam(headers.authorization, None, request_line(&ctx.request))
            .await?;
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

        let stream = mgr
            .job_output(&authn, &job_id, &target, stream, range)
            .await?;
        let length = stream.length();
        let body = Body::wrap(StreamBody::new(stream.map_ok(Frame::data)));
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, CONTENT_TYPE_OCTET_STREAM)
            .header(CONTENT_LENGTH, length)
            .body(body)?)
    }

    async fn job_attach(
        ctx: RequestContext<Self::Context>,
        headers: Header<Authorization>,
        params: PathParams<JobTargetParams>,
        _query: QueryParams<RoutingParam>,
        upgrade: WebsocketUpgrade,
    ) -> WebsocketEndpointResult {
        let mgr = ctx.context();
        let Authorization { authorization } = headers.into_inner();
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
        let JobTargetParams { job_id, target } = params.into_inner();
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
        let (attachment, access) = mgr.job_attachment(&authn, &job_id, &target).await?;
        upgrade.handle(async move |conn| {
            let socket = conn.into_inner();
            let config = WebSocketConfig::default()
                .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
                .max_frame_size(Some(MAX_WS_MESSAGE_SIZE));
            let stream = WebSocketStream::from_raw_socket(socket, Role::Server, Some(config)).await;
            attachment.try_send((stream, access)).map_err(|_| {
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
        let authn = mgr
            .iam(authorization, None, request_line(&ctx.request))
            .await?;
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
        _query: QueryParams<RoutingParam>,
    ) -> Result<HttpResponseOk<BaseboardId>, HttpError> {
        Ok(HttpResponseOk(ctx.context().own_baseboard().to_owned()))
    }

    async fn versions(
        ctx: RequestContext<Self::Context>,
        _query: QueryParams<RoutingParam>,
    ) -> Result<HttpResponseOk<Vec<SledVersion>>, HttpError> {
        Ok(HttpResponseOk(ctx.context().versions()))
    }

    async fn version(
        _ctx: RequestContext<Self::Context>,
        _query: QueryParams<RoutingParam>,
    ) -> Result<HttpResponseOk<VersionInfo>, HttpError> {
        Ok(HttpResponseOk(VersionInfo::current()))
    }
}
