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
    pub(crate) write_buffer: BytesMut,
    pub(crate) read_closed: bool,
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let mut tcp_data = self.read_buffer.split();
            buf.put_slice(&tcp_data[..]);
            return Poll::Ready(Ok(()));
        }
        //read data from transport
        let mut buffer_vev = vec_allocate(buf.capacity());
        let mut buffer = ReadBuf::new(&mut buffer_vev);
        let result = ready!(Pin::new(&mut self.receive_stream).poll_read(cx, &mut buffer));

        match result {
            Ok(_) => {
                if (buffer.filled().len() == 0) {
                    if self.read_closed {
                        return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
                    }
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                self.read_buffer.extend_from_slice(buffer.filled());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => {
                let message = format!("{{quinn_hysteria2 read message: {}}}", err);
                let error = Error::new(err.kind(), message);
                Poll::Ready(Err(error))
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
        if !self.write_buffer.is_empty() {
            let mut data = self.write_buffer.split();
            let result = ready!(Pin::new(&mut self.send_stream).poll_write(cx, &data[..]));
            return match result {
                Ok(size) => {
                    return Poll::Ready(Ok(size));
                }
                Err(err) => {
                    let message = format!("{{quinn_hysteria2 write message: {}}}", err);
                    Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, message)))
                }
            };
        }
        self.write_buffer.put_slice(buf);
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().send_stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().send_stream).poll_shutdown(cx)
    }
}

impl AsyncXrayTcpStream for Hysteria2TcpStream {}
