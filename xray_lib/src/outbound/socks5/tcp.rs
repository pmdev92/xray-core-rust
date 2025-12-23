use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::core::io::AsyncXrayTcpStream;
use crate::core::transport::XrayTransport;

pub(crate) struct Socks5TcpStream {
    stream: Box<dyn XrayTransport>,
}
impl Socks5TcpStream {
    pub fn new(stream: Box<dyn XrayTransport>) -> Socks5TcpStream {
        Self { stream }
    }
}
impl AsyncRead for Socks5TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        return Pin::new(&mut self.stream).poll_read(cx, buf);
    }
}

impl AsyncWrite for Socks5TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        return Pin::new(&mut self.stream).poll_write(cx, buf);
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.stream).poll_flush(cx);
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.stream).poll_shutdown(cx);
    }
}

impl AsyncXrayTcpStream for Socks5TcpStream {}
