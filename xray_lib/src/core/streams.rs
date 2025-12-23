use crate::common::net_location::NetLocation;
use bytes::Bytes;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tls_parser::nom::complete::bool;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

pub(crate) struct XrayTcpStream {
    tcp_stream: TcpStream,
}
impl XrayTcpStream {
    pub(crate) async fn new(
        net_location: Arc<NetLocation>,
        context: Arc<crate::core::context::Context>,
    ) -> Result<Self, io::Error> {
        let socket_addr = net_location.to_socket_addr(context.clone()).await?;
        let tcp_stream = context.connect_tokio_tcp(socket_addr).await?;
        return Ok(XrayTcpStream { tcp_stream });
    }
}
impl AsyncRead for XrayTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        return Pin::new(&mut self.tcp_stream).poll_read(cx, buf);
    }
}

impl AsyncWrite for XrayTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        return Pin::new(&mut self.tcp_stream).poll_write(cx, buf);
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.tcp_stream).poll_flush(cx);
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.tcp_stream).poll_shutdown(cx);
    }
}

impl AsyncXrayTcpStream for XrayTcpStream {}

pub(crate) struct XrayUdpStream {
    pub(crate) instant: Instant,
    pub(crate) socket_addr: SocketAddr,
    pub(crate) udp_socket: UdpSocket,
    flushed: bool,
    data: Option<Bytes>,
}

impl XrayUdpStream {
    pub async fn new(
        net_location: Arc<NetLocation>,
        context: Arc<crate::core::context::Context>,
    ) -> Result<Self, io::Error> {
        let socket_addr = net_location.to_socket_addr(context.clone()).await?;
        let local_addr: SocketAddr = if socket_addr.is_ipv6() {
            SocketAddr::from_str("[::]:0").map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        } else {
            SocketAddr::from_str("0.0.0.0:0")
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        };
        let udp_socket = context.bind_tokio_udp(local_addr).await?;
        let _ = udp_socket.connect(socket_addr.clone()).await?;
        let dialer_stream = XrayUdpStream {
            instant: Instant::now(),
            socket_addr,
            udp_socket,
            flushed: true,
            data: None,
        };
        return Ok(dialer_stream);
    }
}

use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use futures::{Sink, Stream};

impl Stream for XrayUdpStream {
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut udp_socket, ..
        } = *self;
        let mut mem = vec![0u8; 8 * 1024];
        let mut buf = ReadBuf::new(&mut mem);
        match ready!(udp_socket.poll_recv_from(cx, &mut buf)) {
            Ok(_src) => {
                let data = buf.filled().to_vec();
                Poll::Ready(Some(Bytes::from(data)))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}

impl Sink<Bytes> for XrayUdpStream {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match <Self as Sink<Bytes>>::poll_flush(self, cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.data = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut udp_socket,
            data: ref mut pkt,
            ref mut socket_addr,
            ..
        } = *self;

        if pkt.is_some() {
            let bytes = pkt.as_ref().unwrap();
            let _dst = socket_addr.clone();
            let n = ready!(udp_socket.poll_send(cx, bytes))?;
            let wrote_all = n == bytes.len();
            self.data = None;
            self.flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(io::Error::other(
                    "failed to send all data, only sent {n} bytes",
                ))
            };
            Poll::Ready(res)
        } else {
            Poll::Ready(Err(io::Error::other("no packet to send")))
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(<Self as Sink<Bytes>>::poll_flush(self, cx))?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncXrayUdpStream for XrayUdpStream {}
