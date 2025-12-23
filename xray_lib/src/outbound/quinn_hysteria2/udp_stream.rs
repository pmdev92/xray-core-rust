use crate::core::io::AsyncXrayTcpStream;
use crate::outbound::quinn_hysteria2::handler::Hysteria2Counter;
use crate::outbound::quinn_hysteria2::to_io_error;
use crate::outbound::quinn_hysteria2::udp_api::UdpApi;
use futures_util::SinkExt;
use once_cell::sync::Lazy;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

static GLOBAL_COUNTER: Lazy<Arc<Mutex<u32>>> = Lazy::new(|| Arc::new(Mutex::new(1u32)));

pub(crate) struct Hysteria2UdpStream {
    counter: Hysteria2Counter,
    send_tx: tokio_util::sync::PollSender<bytes::Bytes>,
    recv_rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
}
fn increment() {
    let mut num = GLOBAL_COUNTER.lock().unwrap();
    *num += 1;
}
impl Hysteria2UdpStream {
    pub async fn new(
        counter: Hysteria2Counter,
        api: Arc<UdpApi>,
        address: String,
    ) -> Hysteria2UdpStream {
        let session_id = GLOBAL_COUNTER.lock().unwrap().clone();
        increment();
        let (send_tx, send_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(32);
        api.new_udp_session(send_rx, recv_tx, session_id, address)
            .await;
        Self {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
            counter,
        }
    }
}

impl AsyncRead for Hysteria2UdpStream {
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

impl AsyncWrite for Hysteria2UdpStream {
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

        return Poll::Ready(Ok(buf.len()));
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

impl AsyncXrayTcpStream for Hysteria2UdpStream {}
