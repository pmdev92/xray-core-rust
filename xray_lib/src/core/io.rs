use bytes::Bytes;
use futures_util::{Sink, Stream};
use std::any::Any;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncXrayTcpStream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any {}

impl AsyncXrayTcpStream for tokio::net::TcpStream {}

pub trait AsyncXrayUdpStream:
    Stream<Item = Bytes> + Sink<Bytes, Error = io::Error> + Unpin + Send
{
}
