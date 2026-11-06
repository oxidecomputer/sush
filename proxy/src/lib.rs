// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Proxy server for the Oxide Support Shell API.
//!
//! Terminates client connections, verifies request credentials,
//! and routes requests to servers. The proxy answers `/version`
//! and `/iam` itself; other requests are forwarded untouched.
//!
//! A request that specifies a target goes to the first sled the
//! target resolves to. Anything else goes to the server on the
//! sled hosting the proxy, the proxy's *home* sled.
//!
//! Clients authenticate the proxy by its RoT-vouched certificate;
//! see [`platform_tls`].

pub mod login;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{Method, StatusCode};
use http_body_util::{BodyExt as _, Either, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1 as client_conn;
use hyper::server::conn::http1 as server_conn;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::TLS13;
use serde::Serialize;
use serde_json::json;
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, error, info, o, warn};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio::{select, spawn, try_join};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use sush_common::authn::Challenge;
use sush_common::keys::SshPublicKey;
use sush_common::targets::{Cubbies, SledId, Target};
use sush_common::version::VersionInfo;

use crate::login::{Logins, Unauthorized};

/// Server addresses by baseboard.
pub type Sleds = BTreeMap<BaseboardId, SocketAddr>;

/// How long to wait for a sled to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on a login's body, which holds only an SSH public key.
const MAX_IAM_BODY_BYTES: usize = 0x1_0000;

/// Discovery endpoints that don't require a login.
const UNAUTHENTICATED: &[(Method, &str)] = &[
    (Method::GET, "/target"),
    (Method::GET, "/version"),
    (Method::GET, "/versions"),
];

/// The sush servers the proxy may route to. The sled and cubby maps are
/// discovered independently (by DDM and MGS, resp.), so each arrives on
/// its own channel.
#[derive(Clone, Debug)]
pub struct Targets {
    /// Server addresses by baseboard.
    pub sleds: watch::Receiver<Sleds>,
    /// Baseboards by cubby number, as much of it as is known.
    pub cubbies: watch::Receiver<Cubbies>,
}

impl Targets {
    /// Return a fresh sled map sender, cubby map sender, and receiver
    /// for both maps.
    pub fn channel() -> (watch::Sender<Sleds>, watch::Sender<Cubbies>, Targets) {
        let (sleds_tx, sleds) = watch::channel(Sleds::new());
        let (cubbies_tx, cubbies) = watch::channel(Cubbies::new());
        (sleds_tx, cubbies_tx, Targets { sleds, cubbies })
    }

    /// The address of the first sled `target` resolves to. For
    /// routing, a list means the first of these that is reachable.
    fn resolve(&self, target: &Target) -> Option<SocketAddr> {
        let Target::Sleds(ids) = target else {
            return None;
        };
        let sleds = self.sleds.borrow();
        let cubbies = self.cubbies.borrow();
        ids.iter()
            .filter_map(|sled| match sled {
                SledId::Baseboard(baseboard) => Some(baseboard),
                SledId::Cubby(cubby) => cubbies.get(cubby),
            })
            .find_map(|baseboard| sleds.get(baseboard))
            .copied()
    }
}

/// Backend responses pass through. Proxy errors carry their own body.
type ProxyBody = Either<Incoming, Full<Bytes>>;

#[derive(Debug, Error)]
pub enum ProxyTlsError {
    #[error("reading `{path}` failed: {error}")]
    Pem {
        path: Utf8PathBuf,
        #[source]
        error: rustls::pki_types::pem::Error,
    },
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
}

/// Build a standard TLS 1.3 configuration for the proxy. The chain
/// consists of the proxy's self-signed, RoT-vouched certificate,
/// followed by the usual platform identity chain; see RFD 620 §4.6.2.1.
/// Because the voucher is a critical constraint unknown to
/// `with_single_cert`, we cannot take the usual path, and instead
/// hand rustls the key and chain directly.
pub fn platform_tls(
    priv_key: &Utf8Path,
    cert_chain: &Utf8Path,
) -> Result<ServerConfig, ProxyTlsError> {
    let pem = |path: &Utf8Path, error| ProxyTlsError::Pem {
        path: path.to_owned(),
        error,
    };
    let certs = CertificateDer::pem_file_iter(cert_chain)
        .map_err(|e| pem(cert_chain, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pem(cert_chain, e))?;
    let key = PrivateKeyDer::from_pem_file(priv_key).map_err(|e| pem(priv_key, e))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let key = provider.key_provider.load_private_key(key)?;
    let certified = Arc::new(CertifiedKey::new(certs, key));
    Ok(ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(VouchedCert(certified))))
}

/// Serve the one vouched certificate to every client.
#[derive(Debug)]
struct VouchedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for VouchedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

pub struct ProxyServer {
    local_addr: SocketAddr,
    shutdown: CancellationToken,
}

impl ProxyServer {
    /// Start listening at `local_addr`, routing to `targets`.
    /// Unrouted requests prefer `home`, the sled hosting the proxy.
    pub async fn start(
        log: &Logger,
        local_addr: SocketAddr,
        tls: Option<ServerConfig>,
        targets: Targets,
        home: Option<BaseboardId>,
        shutdown: CancellationToken,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(local_addr).await?;
        let local_addr = listener.local_addr()?;
        let acceptor = tls.map(|config| TlsAcceptor::from(Arc::new(config)));
        let logins = Logins::new(log.new(o!("component" => "logins")));
        let router = Arc::new(Router {
            targets,
            home,
            logins,
        });
        spawn(listen(
            log.new(o!("component" => "proxy")),
            listener,
            acceptor,
            router,
            shutdown.clone(),
        ));
        info!(log, "started proxy server"; "local_addr" => local_addr);
        Ok(Self {
            local_addr,
            shutdown,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(&mut self) {
        self.shutdown.cancel();
    }
}

/// Check each request's login, and pick a sled for it.
struct Router {
    targets: Targets,
    home: Option<BaseboardId>,
    logins: Logins,
}

impl Router {
    fn route<B>(&self, request: &Request<B>) -> Result<SocketAddr, Box<Response<ProxyBody>>> {
        match named_target(request) {
            Some(Ok(target)) => self.targets.resolve(&target).ok_or_else(|| {
                Box::new(error_response(
                    StatusCode::BAD_GATEWAY,
                    format!("No reachable sled matches `{target}`"),
                ))
            }),
            Some(Err(bad)) => Err(Box::new(error_response(
                StatusCode::BAD_REQUEST,
                format!("Invalid target `{bad}`"),
            ))),
            None => {
                let sleds = self.targets.sleds.borrow();
                match self.home.as_ref() {
                    Some(home) => sleds.get(home).copied().ok_or_else(|| {
                        Box::new(error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            format!("The proxy's own sled `{home}` is not reachable"),
                        ))
                    }),
                    None => match sleds.iter().next() {
                        Some((_, addr)) => Ok(*addr),
                        None => Err(Box::new(error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "No sleds are reachable",
                        ))),
                    },
                }
            }
        }
    }
}

/// The target a request names, if any. A `*` path segment names no
/// particular sled, so the `via` query parameter may still route.
fn named_target<B>(request: &Request<B>) -> Option<Result<Target, String>> {
    let uri = request.uri();
    let segments: Vec<&str> = uri.path().trim_start_matches('/').split('/').collect();
    let named = match segments.as_slice() {
        ["jobs", _, "attach" | "output" | "start", target, ..] if *target != "*" => Some(*target),
        _ => uri.query().and_then(|query| {
            query.split('&').find_map(|param| {
                param
                    .split_once('=')
                    .filter(|(key, _)| *key == "via")
                    .map(|(_, value)| value)
            })
        }),
    }?;
    let decoded = match percent_decode_str(named).decode_utf8() {
        Ok(decoded) => decoded,
        Err(_) => return Some(Err(named.to_string())),
    };
    match decoded.parse() {
        Ok(Target::All) => None,
        Ok(target) => Some(Ok(target)),
        Err(_) => Some(Err(decoded.into_owned())),
    }
}

/// The proxy answers `/version` for itself, so proxy and sled builds
/// stay distinguishable when a rack updates gradually. A `via` still
/// routes the request to a sled.
fn own_version<B>(log: &Logger, request: &Request<B>) -> Option<Response<ProxyBody>> {
    if request.method() != Method::GET
        || request.uri().path() != "/version"
        || named_target(request).is_some()
    {
        return None;
    }
    let response = serde_json::to_vec(&VersionInfo::current())
        .ok()
        .and_then(|body| {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(Either::Right(Full::new(body.into())))
                .ok()
        });
    if response.is_none() {
        warn!(log, "unable to answer /version; forwarding to a sled");
    }
    response
}

/// What to do with a request once its login is checked.
enum Checked {
    /// Forward it to a sled.
    Forward(Request<Incoming>),
    /// Answer it here.
    Answer(Response<ProxyBody>),
}

/// Verify the identity claimed by a request before forwarding.
async fn check_login(logins: &Logins, request: Request<Incoming>) -> Checked {
    // Special-case unauthenticated endpoints (see `test::unauthenticated_endpoints`).
    if UNAUTHENTICATED
        .iter()
        .any(|(method, path)| request.method() == method && request.uri().path() == *path)
    {
        return Checked::Forward(request);
    }

    let (head, body) = request.into_parts();
    let mut authz_headers = head.headers.get_all(AUTHORIZATION).iter();
    let authz = authz_headers.next().and_then(|value| value.to_str().ok());
    if authz_headers.next().is_some() {
        return Checked::Answer(error_response(
            StatusCode::BAD_REQUEST,
            "Requests may have only one `Authorization` header",
        ));
    }
    let method = head.method.as_str();
    let target = head.uri.path_and_query().map_or("", |pq| pq.as_str());
    match (&head.method, head.uri.path()) {
        (&Method::POST, "/iam") => {
            let public_key = match login_key(body).await {
                Ok(public_key) => public_key,
                Err(err) => {
                    return Checked::Answer(error_response(
                        StatusCode::BAD_REQUEST,
                        err.to_string(),
                    ));
                }
            };
            let result = match public_key {
                Some(public_key) => logins.login(authz, public_key).await,
                None => logins.authorize(authz, (method, target)).await,
            };
            Checked::Answer(match result {
                Ok(identity) => json_response(&identity),
                Err(err) => login_refused(err),
            })
        }
        (&Method::GET, "/iam") => {
            Checked::Answer(match logins.authorize(authz, (method, target)).await {
                Ok(_) => json_response(&logins.identities().await),
                Err(err) => login_refused(err),
            })
        }
        _ => match logins.authorize(authz, (method, target)).await {
            Ok(_) => Checked::Forward(Request::from_parts(head, body)),
            Err(err) => Checked::Answer(login_refused(err)),
        },
    }
}

/// Read the public key from the body of a request to `iam`.
async fn login_key(body: Incoming) -> Result<Option<SshPublicKey>, LoginKeyError> {
    let body = Limited::new(body, MAX_IAM_BODY_BYTES);
    let body = body.collect().await.map_err(LoginKeyError::Unreadable)?;
    Ok(serde_json::from_slice(&body.to_bytes())?)
}

#[derive(Debug, Error)]
enum LoginKeyError {
    #[error("Unable to read login request body: {0}")]
    Unreadable(Box<dyn std::error::Error + Send + Sync>),
    #[error("Invalid public key: {0}")]
    InvalidKey(#[from] serde_json::Error),
}

/// Answer a refused login with a fresh challenge.
fn login_refused(Unauthorized(nonce): Unauthorized) -> Response<ProxyBody> {
    let mut response = error_response(
        StatusCode::UNAUTHORIZED,
        "Authentication required, try `iam`",
    );
    let challenge = Challenge::new(nonce).to_string();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        challenge
            .parse()
            .expect("challenge should be a valid header"),
    );
    response
}

fn json_response(value: &impl Serialize) -> Response<ProxyBody> {
    match serde_json::to_vec(value) {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Either::Right(Full::new(body.into())))
            .expect("JSON response should build"),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn listen(
    log: Logger,
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    router: Arc<Router>,
    shutdown: CancellationToken,
) {
    loop {
        select! {
            result = listener.accept() => {
                match result {
                    Ok((client, client_addr)) => {
                        let log = log.new(o!("client_addr" => client_addr));
                        let router = router.clone();
                        match acceptor.clone() {
                            Some(acceptor) => spawn(async move {
                                match acceptor.accept(client).await {
                                    Ok(client) => serve(log, client, router).await,
                                    Err(err) => {
                                        debug!(log, "TLS handshake failed"; "error" => %err);
                                    }
                                }
                            }),
                            None => spawn(serve(log, client, router)),
                        };
                    }
                    Err(err) => {
                        error!(log, "accept failed"; "error" => %err);
                        continue;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!(log, "shutting down");
                return;
            }
        }
    }
}

/// Serve one client connection, forwarding each request to the sled
/// the router picks for it.
async fn serve<S>(log: Logger, client: S, router: Arc<Router>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(|request| {
        let log = log.clone();
        let router = router.clone();
        async move {
            if let Some(response) = own_version(&log, &request) {
                return Ok::<_, Infallible>(response);
            }
            let request = match check_login(&router.logins, request).await {
                Checked::Forward(request) => request,
                Checked::Answer(response) => return Ok(response),
            };
            Ok(match router.route(&request) {
                Ok(addr) => forward(log, addr, request).await,
                Err(response) => {
                    warn!(
                        log, "request not routable";
                        "uri" => %request.uri(), "status" => %response.status()
                    );
                    *response
                }
            })
        }
    });
    if let Err(err) = server_conn::Builder::new()
        .serve_connection(TokioIo::new(client), service)
        .with_upgrades()
        .await
    {
        debug!(log, "client connection ended"; "error" => %err);
    }
}

/// Forward one request to the sled at `addr` and relay the response.
async fn forward(log: Logger, addr: SocketAddr, request: Request<Incoming>) -> Response<ProxyBody> {
    match try_forward(log, addr, request).await {
        Ok(response) => response.map(Either::Left),
        Err(err) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("Unable to reach sled at `{addr}`: {err}"),
        ),
    }
}

/// A `101 Switching Protocols` response upgrades both connections and
/// bridges them.
async fn try_forward(
    log: Logger,
    addr: SocketAddr,
    mut request: Request<Incoming>,
) -> Result<Response<Incoming>, Box<dyn std::error::Error + Send + Sync>> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("no answer within {}s", CONNECT_TIMEOUT.as_secs()))??;
    let (mut sender, conn) = client_conn::handshake(TokioIo::new(stream)).await?;
    spawn({
        let log = log.clone();
        async move {
            if let Err(err) = conn.with_upgrades().await {
                debug!(log, "sled connection ended"; "error" => %err);
            }
        }
    });

    debug!(
        log, "forwarding";
        "method" => %request.method(), "target" => %request.uri(), "addr" => addr,
    );
    let client_upgrade = hyper::upgrade::on(&mut request);
    let mut response = sender.send_request(request).await?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let sled_upgrade = hyper::upgrade::on(&mut response);
        spawn(bridge(log, client_upgrade, sled_upgrade));
    }
    Ok(response)
}

/// Splice the two upgraded connections together.
async fn bridge(log: Logger, client: OnUpgrade, sled: OnUpgrade) {
    match try_join!(client, sled) {
        Ok((client, sled)) => {
            if let Err(err) =
                copy_bidirectional(&mut TokioIo::new(client), &mut TokioIo::new(sled)).await
            {
                debug!(log, "bridged connection ended"; "error" => %err);
            }
        }
        Err(err) => warn!(log, "upgrade failed"; "error" => %err),
    }
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response<ProxyBody> {
    let body = json!({ "request_id": "", "message": message.into() });
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Either::Right(Full::new(body.to_string().into())))
        .expect("error response should build")
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use sush_api::sush_api_mod::stub_api_description;
    use sush_common::{OPENAPI_TITLE, OPENAPI_VERSION};

    use super::*;

    /// The proxy lets through without a login exactly the endpoints
    /// whose API signatures take no `Authorization` header.
    #[test]
    fn unauthenticated_endpoints() {
        let api = stub_api_description().unwrap();
        let openapi = api
            .openapi(OPENAPI_TITLE, OPENAPI_VERSION.parse().unwrap())
            .json()
            .unwrap();
        let mut unauthenticated = BTreeSet::new();
        for (path, item) in openapi["paths"].as_object().unwrap() {
            for (method, operation) in item.as_object().unwrap() {
                let authorized = operation["parameters"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|param| param["in"] == "header" && param["name"] == "authorization");
                if !authorized {
                    unauthenticated.insert((method.to_uppercase(), path.clone()));
                }
            }
        }
        let expected: BTreeSet<_> = UNAUTHENTICATED
            .iter()
            .map(|(method, path)| (method.to_string(), path.to_string()))
            .collect();
        assert_eq!(unauthenticated, expected);
    }

    fn request(path_and_query: &str) -> Request<()> {
        Request::builder().uri(path_and_query).body(()).unwrap()
    }

    fn target(s: &str) -> Target {
        s.parse().unwrap()
    }

    /// Check that proxy errors carry the fields clients require.
    #[tokio::test]
    async fn error_body() {
        use http_body_util::BodyExt as _;

        let response = error_response(StatusCode::BAD_GATEWAY, "no route");
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "no route");
        assert_eq!(body["request_id"], "");
    }

    /// Unrouted requests go to the home sled, or fail while the
    /// targets don't know it. Without a home, any sled will do.
    #[test]
    fn home_preference() {
        let sled = |serial: &str| BaseboardId {
            part_number: "913".to_string(),
            serial_number: serial.to_string(),
        };
        let addr = |port| SocketAddr::from(([127, 0, 0, 1], port));
        let (tx, _cubbies_tx, targets) = Targets::channel();
        tx.send_modify(|sleds| {
            sleds.insert(sled("away"), addr(1));
            sleds.insert(sled("home"), addr(2));
        });
        let logins = || Logins::new(Logger::root(slog::Discard, o!()));
        let router = Router {
            targets: targets.clone(),
            home: Some(sled("home")),
            logins: logins(),
        };
        let get = request("/versions");
        assert_eq!(router.route(&get).unwrap(), addr(2));
        tx.send_modify(|sleds| {
            sleds.remove(&sled("home"));
        });
        assert_eq!(
            router.route(&get).unwrap_err().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        tx.send_modify(|sleds| {
            sleds.insert(sled("home"), addr(2));
        });
        assert_eq!(router.route(&get).unwrap(), addr(2));
        let homeless = Router {
            targets,
            home: None,
            logins: logins(),
        };
        assert_eq!(homeless.route(&get).unwrap(), addr(1));
    }

    /// The proxy answers `GET /version` itself unless `via` routes it.
    /// A `*` target means the handling server, which is the proxy.
    #[test]
    fn version_interception() {
        let log = Logger::root(slog::Discard, o!());
        assert!(own_version(&log, &request("/version")).is_some());
        assert!(own_version(&log, &request("/version?via=*")).is_some());
        assert!(own_version(&log, &request("/version?via=14")).is_none());
        assert!(own_version(&log, &request("/version?via=")).is_none());
        assert!(own_version(&log, &request("/versions")).is_none());
        let post = Request::builder()
            .method(Method::POST)
            .uri("/version")
            .body(())
            .unwrap();
        assert!(own_version(&log, &post).is_none());
    }

    #[test]
    fn named_targets() {
        assert_eq!(
            named_target(&request("/jobs/some-job/output/test%20part:0000/stdout")),
            Some(Ok(target("test part:0000"))),
        );
        assert_eq!(
            named_target(&request("/jobs/some-job/start/test%20part:0000")),
            Some(Ok(target("test part:0000"))),
        );
        assert_eq!(named_target(&request("/jobs/some-job/start/*")), None);
        assert_eq!(
            named_target(&request("/jobs/some-job/attach/test%20part:0000")),
            Some(Ok(target("test part:0000"))),
        );
        assert_eq!(
            named_target(&request("/iam?via=test%20part:0000")),
            Some(Ok(target("test part:0000"))),
        );
        assert_eq!(
            named_target(&request("/jobs/some-job/output/*/stdout?via=14,16")),
            Some(Ok(target("14,16"))),
        );
        assert_eq!(named_target(&request("/jobs/some-job/attach/*")), None);
        assert_eq!(named_target(&request("/iam?via=*")), None);
        assert_eq!(
            named_target(&request("/jobs/some-job/output/nonsense/stdout")),
            Some(Err(String::from("nonsense"))),
        );
        assert_eq!(named_target(&request("/jobs/some-job/status")), None);
        assert_eq!(named_target(&request("/iam")), None);
        assert_eq!(named_target(&request("/sessions?wait=true")), None);
    }

    #[test]
    fn resolution() {
        let brm31: BaseboardId = "913-0000019:BRM42220031".parse().unwrap();
        let brm40: BaseboardId = "913-0000019:BRM42220040".parse().unwrap();
        let addr31: SocketAddr = "[::1]:31000".parse().unwrap();
        let addr40: SocketAddr = "[::1]:40000".parse().unwrap();
        let (sleds_tx, cubbies_tx, targets) = Targets::channel();
        sleds_tx.send_replace(BTreeMap::from([
            (brm31.clone(), addr31),
            (brm40.clone(), addr40),
        ]));
        cubbies_tx.send_replace(Cubbies::from([(14, brm31), (16, brm40)]));

        assert_eq!(
            targets.resolve(&target("913-0000019:BRM42220031")),
            Some(addr31),
        );
        assert_eq!(targets.resolve(&target("16")), Some(addr40));
        // The first routable element wins.
        assert_eq!(targets.resolve(&target("3,16,14")), Some(addr40));
        assert_eq!(targets.resolve(&target("3")), None);
        assert_eq!(targets.resolve(&Target::All), None);
        let (_sleds_tx, _cubbies_tx, empty) = Targets::channel();
        assert_eq!(empty.resolve(&target("14")), None);
    }
}
