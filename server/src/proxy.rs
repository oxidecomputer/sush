// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Proxy server for the Oxide Support Shell API.
//!
//! Terminates client connections and routes each request to a sled.
//! A request that names a target goes to the first sled the target
//! resolves to. Anything else goes to a sticky default, because
//! identities are cached on the sled that authenticated them.
//! Requests are forwarded untouched: bound request signatures cover
//! the exact request line, so the proxy may never rewrite one.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http::StatusCode;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1 as client_conn;
use hyper::server::conn::http1 as server_conn;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use rustls::ServerConfig;
use rustls::version::TLS13;
use sled_hardware_types::BaseboardId;
use slog::{Logger, debug, error, info, o, warn};
use sprockets_tls::keys::{CertResolver, ResolveSetting};
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::{select, spawn, try_join};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use sush_common::targets::{Cubbies, SledId, Target};

/// The sush servers the proxy may route to.
#[derive(Clone, Debug, Default)]
pub struct Targets {
    /// Server addresses by baseboard.
    pub sleds: BTreeMap<BaseboardId, SocketAddr>,
    /// Baseboards by cubby number, as much of it as is known.
    pub cubbies: Cubbies,
}

impl Targets {
    /// The address of the first sled `target` resolves to. For
    /// routing, a list means the first of these that is reachable.
    fn resolve(&self, target: &Target) -> Option<SocketAddr> {
        let Target::Sleds(sleds) = target else {
            return None;
        };
        sleds
            .iter()
            .filter_map(|sled| match sled {
                SledId::Baseboard(baseboard) => Some(baseboard),
                SledId::Cubby(cubby) => self.cubbies.get(cubby),
            })
            .find_map(|baseboard| self.sleds.get(baseboard))
            .copied()
    }
}

/// Backend responses pass through. Proxy errors carry their own body.
type ProxyBody = Either<Incoming, Full<Bytes>>;

/// The proxy's TLS identity is the sled's platform identity.
pub fn platform_tls(log: &Logger, resolve: ResolveSetting) -> Result<ServerConfig, rustls::Error> {
    let log = log.new(o!("component" => "proxy-cert-resolver"));
    let resolver = Arc::new(CertResolver::new(log, resolve));
    Ok(
        ServerConfig::builder_with_provider(Arc::new(sprockets_tls::crypto_provider()))
            .with_protocol_versions(&[&TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    )
}

pub struct ProxyServer {
    local_addr: SocketAddr,
    shutdown: CancellationToken,
}

impl ProxyServer {
    /// Start listening at `local_addr`, routing to `targets`.
    pub async fn start(
        log: &Logger,
        local_addr: SocketAddr,
        tls: Option<ServerConfig>,
        targets: watch::Receiver<Targets>,
        shutdown: CancellationToken,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(local_addr).await?;
        let local_addr = listener.local_addr()?;
        let acceptor = tls.map(|config| TlsAcceptor::from(Arc::new(config)));
        let router = Arc::new(Router {
            targets,
            default: Mutex::new(None),
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

/// Pick a sled for each request.
struct Router {
    targets: watch::Receiver<Targets>,
    default: Mutex<Option<BaseboardId>>,
}

impl Router {
    fn route(&self, request: &Request<Incoming>) -> Result<SocketAddr, Box<Response<ProxyBody>>> {
        let targets = self.targets.borrow();
        match named_target(request) {
            Some(Ok(target)) => targets.resolve(&target).ok_or_else(|| {
                Box::new(error_response(
                    StatusCode::BAD_GATEWAY,
                    format!("no route to target `{target}`"),
                ))
            }),
            Some(Err(bad)) => Err(Box::new(error_response(
                StatusCode::BAD_REQUEST,
                format!("unable to parse target `{bad}`"),
            ))),
            None => {
                let mut default = self.default.lock().unwrap();
                if let Some(baseboard) = default.as_ref()
                    && let Some(addr) = targets.sleds.get(baseboard)
                {
                    return Ok(*addr);
                }
                match targets.sleds.iter().next() {
                    Some((baseboard, addr)) => {
                        *default = Some(baseboard.clone());
                        Ok(*addr)
                    }
                    None => Err(Box::new(error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "no sleds known to the proxy",
                    ))),
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
        ["jobs", _, "output" | "attach", target, ..] if *target != "*" => Some(*target),
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
            Ok::<_, Infallible>(match router.route(&request) {
                Ok(addr) => forward(log, addr, request).await,
                Err(response) => *response,
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
            format!("unable to reach sled at `{addr}`: {err}"),
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
    let stream = TcpStream::connect(addr).await?;
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

fn error_response(status: StatusCode, message: impl Into<Bytes>) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(Either::Right(Full::new(message.into())))
        .expect("error response should build")
}

#[cfg(test)]
mod test {
    use super::*;

    fn request(path_and_query: &str) -> Request<()> {
        Request::builder().uri(path_and_query).body(()).unwrap()
    }

    fn target(s: &str) -> Target {
        s.parse().unwrap()
    }

    #[test]
    fn named_targets() {
        assert_eq!(
            named_target(&request("/jobs/some-job/output/test%20part:0000/stdout")),
            Some(Ok(target("test part:0000"))),
        );
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
        let targets = Targets {
            sleds: BTreeMap::from([(brm31.clone(), addr31), (brm40.clone(), addr40)]),
            cubbies: Cubbies::from([(14, brm31), (16, brm40)]),
        };

        assert_eq!(
            targets.resolve(&target("913-0000019:BRM42220031")),
            Some(addr31),
        );
        assert_eq!(targets.resolve(&target("16")), Some(addr40));
        // The first routable element wins.
        assert_eq!(targets.resolve(&target("3,16,14")), Some(addr40));
        assert_eq!(targets.resolve(&target("3")), None);
        assert_eq!(targets.resolve(&Target::All), None);
        assert_eq!(Targets::default().resolve(&target("14")), None);
    }
}
