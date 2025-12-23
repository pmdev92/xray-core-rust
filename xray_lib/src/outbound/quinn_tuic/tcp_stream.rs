use quinn::RecvStream;
use quinn::SendStream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::core::io::AsyncXrayTcpStream;
use crate::outbound::quinn_tuic::handler::TuicCounter;

pub(crate) struct TuicTcpStream {
    pub(crate) counter: TuicCounter,
    pub(crate) send_stream: SendStream,
    pub(crate) receive_stream: RecvStream,
}

impl AsyncRead for TuicTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = AsyncRead::poll_read(Pin::new(&mut self.get_mut().receive_stream), cx, buf);
        return result;
    }
}
impl AsyncWrite for TuicTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send_stream), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send_stream), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send_stream), cx)
    }
}

impl AsyncXrayTcpStream for TuicTcpStream {}
