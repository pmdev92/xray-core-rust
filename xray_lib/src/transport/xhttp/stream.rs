use crate::core::io::AsyncXrayTcpStream;
use crate::core::transport::XrayTransport;
use crate::transport::xhttp::xmux::XmuxClientOpenUsage;
use bytes::{Bytes, BytesMut};
use std::future::Future;
use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{Receiver, Sender};

pub(crate) struct XHttpStream {
    download_open_usage_counter: XmuxClientOpenUsage,
    upload: Sender<Vec<u8>>,
    download: Receiver<Result<Bytes, Error>>,
    read_buffer: BytesMut,
    future_write: Option<Pin<Box<dyn Future<Output = ()> + Send + Sync>>>,
}

impl XHttpStream {
    pub fn new(
        download_open_usage_counter: XmuxClientOpenUsage,
        download: Receiver<Result<Bytes, Error>>,
        upload: Sender<Vec<u8>>,
    ) -> Self {
        Self {
            download_open_usage_counter,
            upload,
            download,
            read_buffer: Default::default(),
            future_write: None,
        }
    }
}

impl AsyncRead for XHttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let n = buf.remaining().min(self.read_buffer.len());
            let data = self.read_buffer.split_to(n);
            buf.put_slice(data.as_ref());
            return Poll::Ready(Ok(()));
        }
        let result = std::task::ready!(Pin::new(&mut self.download).poll_recv(cx))
            .ok_or(Error::new(ErrorKind::Other, "stream closed"))?;
        match result {
            Ok(data) => {
                self.read_buffer.extend_from_slice(&data);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl AsyncWrite for XHttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        if self.future_write.is_none() {
            let future = self.upload.clone();
            let buffer = buf.to_vec();
            let handle = Box::pin(async move { let _ = future.send(buffer).await; });
            self.future_write = Some(handle);
        }
        let future = self.future_write.as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Other, "future write not set"))?;
        let _ = std::task::ready!(Pin::new(future).poll(cx));
        self.future_write = None;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.future_write.is_none() {
            let future = self.upload.clone();
            let handle = Box::pin(async move { let _ = future.send(vec![]).await; });
            self.future_write = Some(handle);
        }
        let future = self.future_write.as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Other, "future write not set"))?;
        let _ = std::task::ready!(Pin::new(future).poll(cx));
        self.future_write = None;
        Poll::Ready(Ok(()))
    }
}

impl AsyncXrayTcpStream for XHttpStream {}
impl XrayTransport for XHttpStream {}
