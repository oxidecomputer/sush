//! Multiplex WebSocket I/O across a dynamic set of clients.
//!
//! We delegate all the hard parts: buffered sending to [`broadcast`]
//! streams, fair receiving to [`StreamMap`], and lock management to
//! [`StreamExt::split`].

use std::collections::BTreeMap;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use futures::stream::{FuturesUnordered, SplitStream};
use futures::{SinkExt as _, Stream, StreamExt};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::{select, spawn};
use tokio_stream::{StreamMap, StreamNotifyClose};
use tokio_tungstenite::tungstenite::error::Error as WebSocketError;
use tokio_tungstenite::tungstenite::protocol::Message as WebSocketMessage;
use tokio_util::sync::CancellationToken;

use crate::interactive::SocketStream;

/// Maximum number of messages a client is allowed to lag by
/// before it is disconnected.
pub const MUX_CLIENT_CHANNEL_CAPACITY: usize = 100;

/// Client identifiers are opaque and ephemeral. We use monotonically
/// increasing integers because they're simple and cheap.
pub type ClientId = usize;

/// Multiplex I/O across a set of WebSocket connections.
pub struct WebSocketMux {
    next_client_id: ClientId,
    recv: StreamMap<ClientId, StreamNotifyClose<SplitStream<SocketStream>>>,
    send: broadcast::Sender<WebSocketMessage>,
    stop: BTreeMap<ClientId, CancellationToken>,
    done: FuturesUnordered<JoinHandle<ClientId>>,
}

impl WebSocketMux {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            next_client_id: 0,
            recv: StreamMap::new(),
            send: broadcast::channel(MUX_CLIENT_CHANNEL_CAPACITY).0,
            stop: BTreeMap::new(),
            done: FuturesUnordered::new(),
        }
    }

    pub fn add(&mut self, stream: SocketStream, stop: CancellationToken) -> ClientId {
        let client_id = self.next_client_id;
        self.next_client_id += 1;
        let (mut to, from) = stream.split();
        self.recv.insert(client_id, StreamNotifyClose::new(from));
        self.stop.insert(client_id, stop.clone());
        let mut rx = self.send.subscribe();
        let handle = spawn(async move {
            loop {
                select! {
                    recvd = rx.recv() => {
                        let Ok(message) = recvd else { break };
                        if to.send(message).await.is_err() {
                            break
                        }
                    }
                    _ = stop.cancelled() => {
                        break;
                    }
                }
            }
            let _ = to.close().await;
            stop.cancel();
            client_id
        });
        self.done.push(handle);
        client_id
    }

    pub fn remove(&mut self, client_id: &ClientId) {
        self.recv.remove(client_id);
        if let Some(stop) = self.stop.remove(client_id) {
            stop.cancel();
        }
    }

    pub fn send(
        &self,
        message: WebSocketMessage,
    ) -> Result<usize, broadcast::error::SendError<WebSocketMessage>> {
        self.send.send(message)
    }

    pub fn is_empty(&self) -> bool {
        self.recv.is_empty()
    }
}

impl Stream for WebSocketMux {
    type Item = (ClientId, Result<WebSocketMessage, WebSocketError>);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Reap dead clients.
        while let Poll::Ready(Some(result)) = Pin::new(&mut this.done).poll_next(cx) {
            if let Ok(id) = result {
                this.recv.remove(&id);
                this.stop.remove(&id);
            }
        }

        // Poll clients, cancelling dead ones.
        loop {
            match ready!(Pin::new(&mut this.recv).poll_next(cx)) {
                Some((id, None)) => {
                    if let Some(stop) = this.stop.remove(&id) {
                        stop.cancel();
                    }
                }
                Some((id, Some(item))) => return Poll::Ready(Some((id, item))),
                None => return Poll::Ready(None),
            }
        }
    }
}
