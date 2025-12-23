use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::XraySecurity;
use bytes::{Buf, BytesMut};
use futures::ready;
use log::error;
use quinn::rustls::ClientConfig;
use std::io::{BufRead, Error, ErrorKind, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::{io, result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConnection;

pub struct NewTlsSecurityStream {
    stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    session: ClientConnection,
    is_handshake_completed: bool,
    is_early_data: bool,
    early_data_len: usize,
    flushed: bool,
    read_waker: Option<Waker>,
}

impl NewTlsSecurityStream {
    pub fn new(
        server_name: String,
        config: Arc<ClientConfig>,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
        is_early_data: bool,
        early_data_len: usize,
    ) -> Result<Self, io::Error> {
        let domain = ServerName::try_from((server_name).to_string())
            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()))?;
        let session = ClientConnection::new(config, domain)
            .map_err(|e| Error::other(format!("Unable to create tls session: {}", e)))?;

        let tls = Self {
            stream,
            session,
            is_handshake_completed: false,
            is_early_data,
            early_data_len,
            flushed: true,
            read_waker: None,
        };
        Ok(tls)
    }
    pub(crate) fn conn_read(&mut self, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let mut reader = SyncAdapter {
            stream: &mut self.stream,
            cx,
        };
        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => {
                if n == 0 {
                    return Poll::Ready(Err(Error::from(ErrorKind::UnexpectedEof)));
                }
                n
            }
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        };
        log::debug!("Tls read {} bytes encrypted data", n);
        let state = self
            .session
            .process_new_packets()
            .map_err(|e| Error::other(format!("-----: {}", e)))
            .unwrap();
        log::debug!(
            "Tls has {} bytes plaintext to read, {} bytes plaintext to write",
            state.plaintext_bytes_to_read(),
            state.tls_bytes_to_write()
        );
        if state.plaintext_bytes_to_read() == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    pub(crate) fn conn_write(&mut self, cx: &mut Context) -> Poll<Result<usize, io::Error>> {
        let mut writer = SyncAdapter {
            stream: &mut self.stream,
            cx,
        };

        match self.session.write_tls(&mut writer) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    pub(crate) fn handshake(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut io = SyncAdapter {
            stream: &mut self.stream,
            cx,
        };

        if self.is_early_data {
            if let Some(mut early_data) = self.session.early_data() {
                if data.len() > self.early_data_len {
                    let _ = early_data.write_all(&data[..self.early_data_len]);
                } else {
                    let _ = early_data.write_all(data);
                }
            }
        }

        match self.session.complete_io(&mut io) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
            _ => {}
        }

        let mut data_len = 0usize;
        if self.is_early_data {
            let accepted = self.session.is_early_data_accepted();
            if accepted {
                data_len = data.len();
            }
        }
        Poll::Ready(Ok(data_len))
    }
}

impl AsyncRead for NewTlsSecurityStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.is_handshake_completed {
            this.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if this.session.wants_read() {
            let result = this.conn_read(cx);
            match result {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
        let result = this.session.reader().into_first_chunk();
        match result {
            Ok(chunk) => {
                if chunk.len() == 0 {
                    return Poll::Ready(Err(Error::from(ErrorKind::UnexpectedEof)));
                }
                let mut len = buf.remaining();
                if len > chunk.len() {
                    len = chunk.len();
                }
                buf.put_slice(&chunk[..len]);
                this.session.reader().consume(len);
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWrite for NewTlsSecurityStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        let count = if !this.is_handshake_completed {
            let count = match this.handshake(cx, buf) {
                Poll::Ready(Ok(count)) => count,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.is_handshake_completed = true;
            if let Some(waker) = this.read_waker.take() {
                waker.wake_by_ref();
            }
            if buf.len() == count {
                return Ok(buf.len()).into();
            }
            count
        } else {
            0
        };
        if this.flushed {
            if let Err(e) = this.session.writer().write_all(&buf[count..]) {
                return Poll::Ready(Err(e));
            }
            this.flushed = false;
        }
        while this.session.wants_write() {
            match this.conn_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.flushed = true;
        Ok(buf.len()).into()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        while this.session.wants_write() {
            ready!(this.conn_write(cx)).unwrap();
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncXrayTcpStream for NewTlsSecurityStream {}

impl XraySecurity for NewTlsSecurityStream {}

struct SyncAdapter<'a, 'b> {
    pub stream: &'a mut Box<dyn AsyncXrayTcpStream + Send + Sync>,
    pub cx: &'a mut Context<'b>,
}

impl Read for SyncAdapter<'_, '_> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let mut buffer = ReadBuf::new(buf);
        let result = match Pin::new(&mut self.stream).poll_read(self.cx, &mut buffer) {
            Poll::Ready(Ok(())) => Ok(buffer.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        };
        return result;
    }
}

impl SyncAdapter<'_, '_> {
    #[inline]
    fn poll_with<U>(
        &mut self,
        f: impl FnOnce(
            Pin<&mut Box<dyn AsyncXrayTcpStream + Send + Sync>>,
            &mut Context<'_>,
        ) -> Poll<Result<U, io::Error>>,
    ) -> Result<U, io::Error> {
        match f(Pin::new(self.stream), self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }
}

impl Write for SyncAdapter<'_, '_> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.poll_with(|io, cx| io.poll_write(cx, buf))
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.poll_with(|io, cx| io.poll_flush(cx))
    }
}
