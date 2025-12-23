use futures_util::SinkExt;
use once_cell::sync::Lazy;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::outbound::quinn_tuic::handler::TuicCounter;
use crate::outbound::quinn_tuic::protocol::dissociate::Dissociate;
use crate::outbound::quinn_tuic::to_io_error;
use crate::outbound::quinn_tuic::udp_api::UdpApi;

static GLOBAL_COUNTER: Lazy<Arc<Mutex<u16>>> = Lazy::new(|| Arc::new(Mutex::new(1u16)));
fn increment() {
    let mut num = GLOBAL_COUNTER.lock().unwrap();
    *num += 1;
}
pub(crate) struct TuicUdpStream {
    counter: TuicCounter,
    assoc_id: u16,
    api: Arc<UdpApi>,
    send_tx: tokio_util::sync::PollSender<bytes::Bytes>,
    recv_rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
}

impl TuicUdpStream {
    pub async fn new(
        counter: TuicCounter,
        api: Arc<UdpApi>,
        address: Arc<NetLocation>,
    ) -> TuicUdpStream {
        let assoc_id = GLOBAL_COUNTER.lock().unwrap().clone();
        increment();
        let (send_tx, send_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(32);
        api.clone()
            .new_udp_session(send_rx, recv_tx, assoc_id, address)
            .await;
        Self {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
            counter,
            assoc_id,
            api,
        }
    }
}

impl AsyncRead for TuicUdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = ready!(self.recv_rx.poll_recv(cx));
        match result {
            None => Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe))),
            Some(bytes) => {
                let to_copy = std::cmp::min(buf.remaining(), bytes.len());
                buf.put_slice(&bytes[..to_copy]);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for TuicUdpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        ready!(
            self.send_tx
                .poll_ready_unpin(cx)
                .map_err(|v| to_io_error(format!("{v:?}")))
        )?;
        let mut bytes = bytes::BytesMut::new();
        bytes.extend_from_slice(buf);
        self.send_tx
            .start_send_unpin(bytes.freeze())
            .map_err(|v| to_io_error(format!("{v:?}")))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|v| to_io_error(format!("{v:?}")))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|v| to_io_error(format!("{v:?}")))
    }
}

impl Drop for TuicUdpStream {
    fn drop(&mut self) {
        let api = self.api.clone();
        let dissociate = Dissociate::new(self.assoc_id);
        tokio::spawn(async move {
            let _ = api.dissociate(dissociate).await;
        });
    }
}

impl AsyncXrayTcpStream for TuicUdpStream {}
