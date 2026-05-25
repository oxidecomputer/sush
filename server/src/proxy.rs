//! Proxy server for the Oxide Support Shell API.
//!
//! Loosely adapted from the Wicketd/Nexus proxy.

use std::io;
use std::net::SocketAddr;

use slog::{Logger, error, info, o};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::{select, spawn};

pub struct ProxyServer {
    local_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ProxyServer {
    /// Start listening at `local_addr`. Does not connect to `remote_addr`
    /// until a client connection is accepted.
    pub async fn start(
        log: &Logger,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(local_addr).await?;
        let local_addr = listener.local_addr()?;
        let (tx_shutdown, rx_shutdown) = oneshot::channel();
        spawn(listen(
            log.new(o!("component" => "proxy")),
            listener,
            remote_addr,
            rx_shutdown,
        ));
        info!(log, "started proxy server");
        Ok(Self {
            local_addr,
            shutdown: Some(tx_shutdown),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            _ = shutdown.send(());
        }
    }
}

async fn listen(
    log: Logger,
    listener: TcpListener,
    remote_addr: SocketAddr,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        select! {
            result = listener.accept() => {
                match result {
                    Ok((client, client_addr)) => {
                        accept(&log, client, client_addr, remote_addr).await;
                    }
                    Err(err) => {
                        error!(log, "accept failed"; "error" => %err);
                        return;
                    }
                }
            }
            _ = &mut shutdown => {
                info!(log, "shutting down");
                return;
            }
        }
    }
}

async fn accept(
    log: &Logger,
    mut client: TcpStream,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) {
    let mut server = match TcpStream::connect(server_addr).await {
        Ok(stream) => {
            info!(
                log, "connection established";
                "server_addr" => %server_addr,
                "client_addr" => %client_addr,
            );
            stream
        }
        Err(err) => {
            error!(
                log, "failed to connect to server";
                "server_addr" => %server_addr,
                "error" => %err,
            );
            return;
        }
    };

    match copy_bidirectional(&mut client, &mut server).await {
        Ok((client_to_server, server_to_client)) => {
            info!(
                log, "connection closed";
                "bytes_sent_to_server" => client_to_server,
                "bytes_sent_to_client" => server_to_client,
            );
        }
        Err(err) => {
            error!(log, "error relaying to server"; "error" => %err);
        }
    }
}
