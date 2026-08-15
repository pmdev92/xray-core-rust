use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use futures::ready;
use quinn::RecvStream;
use quinn::SendStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::vec::vec_allocate;
use crate::core::io::AsyncXrayTcpStream;
use crate::outbound::quinn_hysteria2::handler::Hysteria2Counter;

pub(crate) struct Hysteria2TcpStream {
    pub(crate) counter: Hysteria2Counter,
    pub(crate) address: String,
    pub(crate) send_stream: SendStream,
    pub(crate) receive_stream: RecvStream,
    pub(crate) read_buffer: BytesMut,
    pub(crate) read_closed: bool,
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buffer.is_empty() {
                let n = buf.remaining().min(self.read_buffer.len());
                let tcp_data = self.read_buffer.split_to(n);
                buf.put_slice(&tcp_data);
                return Poll::Ready(Ok(()));
            }
            let mut buffer = vec_allocate(buf.remaining());
            let mut buffer = ReadBuf::new(&mut buffer);
            let result = ready!(Pin::new(&mut self.receive_stream).poll_read(cx, &mut buffer));
            match result {
                Ok(_) => {
                    if buffer.filled().len() == 0 {
                        log::trace!("hy2 tcp read: EOF addr={}", self.address);
                        if self.read_closed {
                            return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
                        }
                        self.read_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    log::trace!(
                        "hy2 tcp read: {} bytes addr={}",
                        buffer.filled().len(),
                        self.address
                    );
                    self.read_buffer.extend_from_slice(buffer.filled());
                    continue;
                }
                Err(err) => {
                    log::trace!("hy2 tcp read: error={} addr={}", err, self.address);
                    let message = format!("{{quinn_hysteria2 read message: {}}}", err);
                    return Poll::Ready(Err(Error::new(err.kind(), message)));
                }
            }
        }
    }
}

impl AsyncWrite for Hysteria2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match ready!(Pin::new(&mut self.send_stream).poll_write(cx, buf)) {
            Ok(n) => {
                log::trace!("hy2 tcp write: {} bytes addr={}", n, self.address);
                Poll::Ready(Ok(n))
            }
            Err(err) => {
                let message = format!("{{quinn_hysteria2 write message: {}}}", err);
                Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, message)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().send_stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().send_stream).poll_shutdown(cx)
    }
}

impl AsyncXrayTcpStream for Hysteria2TcpStream {}
