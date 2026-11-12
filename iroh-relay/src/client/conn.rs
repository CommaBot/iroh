//! Manages client-side connections to the relay server.
//!
//! based on tailscale/derp/derp_client.go

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use iroh_base::SecretKey;
use n0_error::{AnyError, anyerr, ensure, stack_error};
use n0_future::{Sink, Stream};
use tracing::trace;

use super::KeyCache;
#[cfg(not(wasm_browser))]
use crate::client::streams::{MaybeTlsStream, ProxyStream};
use crate::{
    MAX_PACKET_SIZE,
    http::ProtocolVersion,
    protos::{
        handshake,
        relay::{ClientToRelayMsg, Error as ProtoError, RelayToClientMsg},
        streams::WsBytesFramed,
    },
};

/// Error for sending messages to the relay server.
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum SendError {
    /// Error returned from the underlying WebSocket stream while sending.
    ///
    /// The concrete error type is `tokio_websockets::Error` on native targets and
    /// `ws_stream_wasm::WsErr` on `wasm_browser` targets. Use [`AnyError::downcast_ref`] to
    /// recover it. Note that the concrete downcast type is not covered by any semver
    /// guarantees and may change between releases.
    #[error("Stream error")]
    StreamError { source: AnyError },
    #[error("Exceeds max packet size ({MAX_PACKET_SIZE}): {size}")]
    ExceedsMaxPacketSize { size: usize },
    #[error("Attempted to send empty packet")]
    EmptyPacket {},
}

/// Errors when receiving messages from the relay server.
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum RecvError {
    #[error(transparent)]
    Protocol { source: ProtoError },
    /// Error returned from the underlying WebSocket stream while receiving.
    ///
    /// The concrete error type is `tokio_websockets::Error` on native targets and
    /// `ws_stream_wasm::WsErr` on `wasm_browser` targets. Use [`AnyError::downcast_ref`] to
    /// recover it. Note that the concrete downcast type is not covered by any semver
    /// guarantees and may change between releases.
    #[error("Stream error")]
    StreamError { source: AnyError },
}

/// A connection to a relay server.
///
/// This holds a connection to a relay server.  It is:
///
/// - A [`Stream`] for [`RelayToClientMsg`] to receive from the server.
/// - A [`Sink`] for [`ClientToRelayMsg`] to send to the server.
#[derive(derive_more::Debug)]
pub(crate) struct Conn {
    #[cfg(not(wasm_browser))]
    #[debug("tokio_websockets::WebSocketStream")]
    pub(crate) conn: WsBytesFramed<MaybeTlsStream<ProxyStream>>,
    #[cfg(wasm_browser)]
    #[debug("ws_stream_wasm::WsStream")]
    pub(crate) conn: WsBytesFramed,
    pub(crate) key_cache: KeyCache,
    pub(crate) protocol_version: ProtocolVersion,
    /// ember: the browser's WebSocket, asked how much it has yet to send (`bufferedAmount`): a browser buffers all that
    /// is sent on a WebSocket, so what waits to be written must wait before it, where it ages out (client/tcp.rs).
    #[cfg(wasm_browser)]
    #[debug("ws_stream_wasm::WsMeta")]
    pub(crate) meta: ws_stream_wasm::WsMeta,
    /// ember: when to ask `meta` again while it holds too much: the browser tells nothing as it sends.
    #[cfg(wasm_browser)]
    #[debug(skip)]
    pub(crate) recheck: Option<Pin<Box<n0_future::time::Sleep>>>,
}

/// ember: the most a browser's relay WebSocket holds that it has not sent yet (client/tcp.rs UNSENT_MAX), and how often
/// it is asked again while it holds more.
#[cfg(wasm_browser)]
const UNSENT_MAX: u32 = 16 * 1024;
#[cfg(wasm_browser)]
const UNSENT_RECHECK: std::time::Duration = std::time::Duration::from_millis(10);

impl Conn {
    /// Constructs a new websocket connection, including the initial server handshake.
    pub(crate) async fn new(
        #[cfg(not(wasm_browser))] io: tokio_websockets::WebSocketStream<
            MaybeTlsStream<ProxyStream>,
        >,
        #[cfg(wasm_browser)] io: ws_stream_wasm::WsStream,
        #[cfg(wasm_browser)] meta: ws_stream_wasm::WsMeta,
        key_cache: KeyCache,
        secret_key: &SecretKey,
        protocol_version: ProtocolVersion,
    ) -> Result<Self, handshake::Error> {
        let mut conn = WsBytesFramed { io };

        // exchange information with the server
        trace!("server_handshake: started");
        handshake::clientside(&mut conn, secret_key).await?;
        trace!("server_handshake: done");

        Ok(Self {
            conn,
            key_cache,
            protocol_version,
            #[cfg(wasm_browser)]
            meta,
            #[cfg(wasm_browser)]
            recheck: None,
        })
    }

    #[cfg(all(test, feature = "server"))]
    pub(crate) fn test(io: tokio::io::DuplexStream, protocol_version: ProtocolVersion) -> Self {
        use crate::protos::relay::MAX_FRAME_SIZE;
        Self {
            conn: WsBytesFramed {
                io: tokio_websockets::ClientBuilder::new()
                    .limits(
                        tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)),
                    )
                    .take_over(MaybeTlsStream::Test(io)),
            },
            key_cache: KeyCache::test(),
            protocol_version,
        }
    }
}

impl Stream for Conn {
    type Item = Result<RelayToClientMsg, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.conn).poll_next(cx)) {
            Some(Ok(msg)) => {
                let message =
                    RelayToClientMsg::from_bytes(msg, &self.key_cache, self.protocol_version);
                Poll::Ready(Some(message.map_err(Into::into)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(anyerr!(e).into()))),
            None => Poll::Ready(None),
        }
    }
}

impl Sink<ClientToRelayMsg> for Conn {
    type Error = SendError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        #[cfg(wasm_browser)]
        loop {
            if self.meta.buffered_amount() <= UNSENT_MAX {
                self.recheck = None;
                break;
            }
            let recheck = self
                .recheck
                .get_or_insert_with(|| Box::pin(n0_future::time::sleep(UNSENT_RECHECK)));
            ready!(recheck.as_mut().poll(cx));
            self.recheck = None;
        }
        Pin::new(&mut self.conn).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, frame: ClientToRelayMsg) -> Result<(), Self::Error> {
        let size = frame.encoded_len();
        ensure!(
            size <= MAX_PACKET_SIZE,
            SendError::ExceedsMaxPacketSize { size }
        );
        if let ClientToRelayMsg::Datagrams { datagrams, .. } = &frame {
            ensure!(!datagrams.contents.is_empty(), SendError::EmptyPacket);
        }

        Pin::new(&mut self.conn)
            .start_send(frame.to_bytes().freeze())
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_close(cx).map_err(Into::into)
    }
}
