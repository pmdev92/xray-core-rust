use crate::common::buffer_manager::BufferHandle;
use crate::common::constants::MAX_UDP_BUFFER_CAPACITY;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use bytes::Bytes;
use futures::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;

pub async fn get_udp_open_port(ip: &str) -> Option<u16> {
    {
        let local_addr = format!("{}:0", ip);
        let result = UdpSocket::bind(local_addr).await;
        return match result {
            Ok(socket) => {
                let result = socket.local_addr();
                drop(socket);
                match result {
                    Ok(local_address) => Some(local_address.port()),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        };
    }
}

pub struct TcpDatagramWrapper {
    buffer_manager: Box<dyn BufferHandle>,
    stream: Box<dyn AsyncXrayTcpStream>,
    tx: Option<Bytes>,
    written: usize,
}

impl TcpDatagramWrapper {
    pub async fn new(
        context: Arc<crate::Context>,
        stream: Box<dyn AsyncXrayTcpStream>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let mut buffer_manager = context
            .get_buffer_manager()
            .get_buffer(MAX_UDP_BUFFER_CAPACITY)
            .await?;

        let s = TcpDatagramWrapper {
            buffer_manager,
            stream,
            tx: None,
            written: 0,
        };
        Ok(Box::new(s))
    }
}

impl Stream for TcpDatagramWrapper {
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let buf_slice = this.buffer_manager.data();
        let stream = &mut this.stream;
        let mut rb = ReadBuf::new(buf_slice);
        match Pin::new(stream).poll_read(cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    Poll::Ready(None)
                } else {
                    let out = Bytes::copy_from_slice(rb.filled());
                    Poll::Ready(Some(out))
                }
            }
            Poll::Ready(Err(_e)) => Poll::Ready(None),
        }
    }
}

impl Sink<Bytes> for TcpDatagramWrapper {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.tx.is_none() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::ErrorKind::WouldBlock.into()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        if self.tx.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.tx = Some(item);
        self.written = 0;
        Ok(())
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        while let Some(buf) = self.tx.take() {
            let total = buf.len();
            while self.written < total {
                let to_send = buf.slice(self.written..);
                match Pin::new(&mut self.stream).poll_write(cx, &to_send) {
                    Poll::Pending => {
                        self.tx = Some(buf);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(0)) => {
                        self.written = 0;
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Ready(Ok(n)) => {
                        self.written += n;
                    }
                    Poll::Ready(Err(e)) => {
                        self.written = 0;
                        return Poll::Ready(Err(e));
                    }
                }
            }
            self.written = 0;
        }
        match Pin::new(&mut self.stream).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        match Pin::new(&mut self.stream).poll_shutdown(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncXrayUdpStream for TcpDatagramWrapper {}

pub struct UdpConnection {
    sender: mpsc::Sender<Bytes>,
    last_used: Arc<Mutex<Instant>>,
}

impl UdpConnection {
    pub fn new(sender: mpsc::Sender<Bytes>, last_used: Arc<Mutex<Instant>>) -> Self {
        Self { sender, last_used }
    }

    pub fn get_last_used(&self) -> Arc<Mutex<Instant>> {
        return self.last_used.clone();
    }
    pub fn get_sender_as_mut(&self) -> &mpsc::Sender<Bytes> {
        return &self.sender;
    }
}
