use crate::common::vec::vec_allocate;
use crate::core::io::AsyncXrayTcpStream;
use bytes::{BufMut, BytesMut};
use std::future::Future;
use std::io;
use std::io::ErrorKind::{BrokenPipe, InvalidData};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub struct ChunkStreamUp {
    connection: Arc<ChunkStreamUpInner<Box<dyn AsyncXrayTcpStream + Send + Sync + Unpin>>>,
    read_buffer: BytesMut,
    future_read: Option<Pin<Box<dyn Future<Output = Result<Vec<u8>, io::Error>> + Send + Sync>>>,
    future_write: Option<Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>>,
}

impl ChunkStreamUp {
    pub fn new(connection: Box<TcpStream>) -> ChunkStreamUp {
        Self {
            connection: Arc::new(ChunkStreamUpInner {
                connection: Mutex::new(connection),
                is_read_closed: AtomicBool::new(false),
                is_write_closed: AtomicBool::new(false),
            }),
            read_buffer: BytesMut::new(),
            future_read: None,
            future_write: None,
        }
    }
}

impl AsyncRead for ChunkStreamUp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            if buf.capacity() > self.read_buffer.len() {
                let data = self.read_buffer.split();
                buf.put_slice(data.as_ref())
            } else {
                let data = self.read_buffer.split_to(buf.capacity());
                buf.put_slice(data.as_ref())
            }
            return Poll::Ready(Ok(()));
        }

        if self.future_read.is_none() {
            let future = self.connection.clone();
            let handle = Box::pin(async move { future.read().await });
            self.future_read = Some(handle);
        }
        let future = self
            .future_read
            .as_mut()
            .ok_or_else(|| io::Error::new(InvalidData, "future read not set"))?;
        let result = std::task::ready!(Pin::new(future).poll(cx));
        self.future_read = None;
        let data = result?;
        self.read_buffer.extend_from_slice(&data);
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for ChunkStreamUp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.future_write.is_none() {
            let future = self.connection.clone();
            let vec = buf.to_vec();
            let handle = Box::pin(async move { future.write(vec).await });
            self.future_write = Some(handle);
        }
        let future = self
            .future_write
            .as_mut()
            .ok_or_else(|| io::Error::new(InvalidData, "future write not set"))?;
        let result = std::task::ready!(Pin::new(future).poll(cx));
        self.future_write = None;
        let _ = result?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if self.future_write.is_none() {
            let future = self.connection.clone();
            let handle = Box::pin(async move { future.flush().await });
            self.future_write = Some(handle);
        }
        let future = self
            .future_write
            .as_mut()
            .ok_or_else(|| io::Error::new(InvalidData, "future write not set"))?;
        let result = std::task::ready!(Pin::new(future).poll(cx));
        self.future_write = None;
        Poll::Ready(result)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if self.future_write.is_none() {
            let future = self.connection.clone();
            let handle = Box::pin(async move { future.shutdown().await });
            self.future_write = Some(handle);
        }
        let future = self
            .future_write
            .as_mut()
            .ok_or_else(|| io::Error::new(InvalidData, "future write not set"))?;
        let result = std::task::ready!(Pin::new(future).poll(cx));
        self.future_write = None;
        Poll::Ready(result)
    }
}

struct ChunkStreamUpInner<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> {
    connection: Mutex<T>,
    is_read_closed: AtomicBool,
    is_write_closed: AtomicBool,
}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> ChunkStreamUpInner<T> {
    pub(crate) async fn read(&self) -> Result<Vec<u8>, io::Error> {
        if self.is_read_closed.load(Ordering::Acquire) {
            return Err(io::Error::new(BrokenPipe, "x-http read is closed"));
        }

        let new_line = "\r\n";
        let mut chunk_size_hex = "".to_string();
        loop {
            let byte = self.connection.lock().await.read_u8().await?;
            chunk_size_hex.push(byte as char);
            if chunk_size_hex.ends_with(new_line) {
                break;
            }
        }
        chunk_size_hex = chunk_size_hex.replace(new_line, "");
        let chunk_size = usize::from_str_radix(chunk_size_hex.as_str(), 16);
        let chunk_size = match chunk_size {
            Ok(chunk_size) => chunk_size,
            Err(_) => {
                return Err(io::Error::new(
                    InvalidData,
                    "x-http chunk size is not valid",
                ));
            }
        };
        if chunk_size == 0 {
            self.is_read_closed.store(true, Ordering::Release);
        }

        let mut buffer: Vec<u8> = vec_allocate(chunk_size);

        self.connection
            .lock()
            .await
            .read_exact(buffer.as_mut_slice())
            .await?;

        let mut buffer_end: Vec<u8> = vec_allocate(2);

        self.connection
            .lock()
            .await
            .read_exact(buffer_end.as_mut_slice())
            .await?;
        let buffer_end_exact = [13u8, 10];

        let is_ok = buffer_end.ends_with(&buffer_end_exact);
        if !is_ok {
            return Err(io::Error::new(InvalidData, "x-http chunk is not valid"));
        }
        Ok(buffer[0..chunk_size].to_vec())
    }

    pub(crate) async fn write(&self, buf: Vec<u8>) -> Result<(), io::Error> {
        if self.is_write_closed.load(Ordering::Acquire) {
            return Err(io::Error::new(BrokenPipe, "x-http write is closed"));
        }

        let start = format!("{:x}\r\n", buf.len());
        let end = "\r\n";
        let len = start.len() + buf.len() + end.len();
        let mut all = BytesMut::with_capacity(len);
        all.put_slice(start.as_bytes());
        all.put_slice(buf.as_slice());
        all.put_slice(end.as_bytes());
        self.connection
            .lock()
            .await
            .write_all(all.freeze().as_ref())
            .await?;
        Ok(())
    }
    pub(crate) async fn flush(&self) -> Result<(), io::Error> {
        if self.is_write_closed.load(Ordering::Acquire) {
            return Err(io::Error::new(BrokenPipe, "x-http write is closed"));
        }

        self.connection.lock().await.flush().await?;
        Ok(())
    }
    pub(crate) async fn shutdown(&self) -> Result<(), io::Error> {
        if self.is_write_closed.load(Ordering::Acquire) {
            return Err(io::Error::new(BrokenPipe, "x-http write is closed"));
        }
        self.is_write_closed.store(true, Ordering::Release);
        self.write(Vec::new()).await?;
        self.connection.lock().await.shutdown().await?;
        Ok(())
    }
}
