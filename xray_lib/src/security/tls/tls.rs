use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::XraySecurity;
use bytes::{Buf, BytesMut};
use std::io;
use std::io::{ErrorKind, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

pub(crate) struct TlsSecurityStream {
    server_name: String,
    connector: Option<TlsConnector>,
    stream: Option<Box<dyn AsyncXrayTcpStream + Send + Sync>>,
    connection: Option<TlsStream<Box<dyn AsyncXrayTcpStream + Send + Sync>>>,
    write_buffer: BytesMut,
    read_buffer: BytesMut,
    read_waker: Option<core::task::Waker>,
    is_early_data: bool,
    early_data_len: usize,
    handshake_fut: Option<
        Pin<
            Box<
                dyn Future<
                        Output = io::Result<(
                            usize,
                            TlsStream<Box<dyn AsyncXrayTcpStream + Send + Sync>>,
                        )>,
                    > + Send
                    + Sync,
            >,
        >,
    >,
}

impl TlsSecurityStream {
    pub fn new(
        server_name: String,
        config: Arc<ClientConfig>,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
        is_early_data: bool,
        early_data_len: usize,
    ) -> Self {
        let connector = TlsConnector::from(config);
        TlsSecurityStream {
            server_name,
            stream: Some(stream),
            connector: Some(connector),
            connection: None,
            write_buffer: BytesMut::new(),
            handshake_fut: None,
            read_waker: None,
            is_early_data,
            read_buffer: BytesMut::new(),
            early_data_len,
        }
    }

    async fn do_handshake(
        tls_connector: TlsConnector,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
        server_name: String,
        data: Vec<u8>,
    ) -> Result<(usize, TlsStream<Box<dyn AsyncXrayTcpStream + Send + Sync>>), io::Error> {
        let domain = ServerName::try_from(server_name)
            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()))?;
        let tls = tls_connector
            .connect_with(domain, stream, |conn| {
                if let Some(mut early_data) = conn.early_data() {
                    let _ = early_data.write_all(&data);
                }
            })
            .await?;
        let mut data_len = 0usize;
        let accepted = tls.get_ref().1.is_early_data_accepted();
        if accepted {
            data_len = data.len();
        }
        Ok((data_len, tls))
    }
}
impl AsyncRead for TlsSecurityStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            let data = self.read_buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            return Poll::Ready(Ok(()));
        }

        if let Some(conn) = self.connection.as_mut() {
            let result = ready!(Pin::new(conn).poll_read(cx, buf));
            return match result {
                Ok(_) => {
                    let len = buf.filled().len();
                    if len == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::BrokenPipe,
                            "read zero bytes",
                        )));
                    }

                    self.read_buffer.extend_from_slice(buf.filled());
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(err)),
            };
        }
        self.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TlsSecurityStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if this.write_buffer.is_empty() {
            this.write_buffer.extend_from_slice(buf);
        }
        loop {
            if this.connection.is_none() {
                if this.handshake_fut.is_none() {
                    let connector = this.connector.take().ok_or_else(|| {
                        io::Error::new(ErrorKind::NotConnected, "TLS connector is not available")
                    })?;
                    let stream = this.stream.take().ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::NotConnected,
                            "Underlying stream is not available",
                        )
                    })?;
                    let server_name = this.server_name.clone();
                    let early_data = if this.is_early_data {
                        let early_data = if this.write_buffer.len() > this.early_data_len {
                            this.write_buffer.as_ref()[..this.early_data_len].to_vec()
                        } else {
                            this.write_buffer.as_ref().to_vec()
                        };
                        early_data
                    } else {
                        vec![]
                    };

                    let fut = async move {
                        Self::do_handshake(connector, stream, server_name, early_data).await
                    };
                    this.handshake_fut = Some(Box::pin(fut));
                }

                match this.handshake_fut.as_mut().unwrap().as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        this.handshake_fut = None;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok((accepted_len, tls))) => {
                        this.handshake_fut = None;
                        this.connection = Some(tls);
                        if accepted_len < buf.len() {
                            this.write_buffer.advance(accepted_len);
                        }
                        if let Some(w) = this.read_waker.take() {
                            w.wake();
                        }
                    }
                };
            }
            if this.write_buffer.is_empty() {
                this.write_buffer.clear();
                return Poll::Ready(Ok(buf.len()));
            }

            let conn = this.connection.as_mut().expect("connection must be Some");
            let result = ready!(Pin::new(conn).poll_write(cx, this.write_buffer.as_ref()));
            match result {
                Ok(len) => {
                    this.write_buffer.advance(len);
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.connection.as_mut() {
            None => Poll::Ready(Ok(())),
            Some(conn) => Pin::new(conn).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.connection.as_mut() {
            None => Poll::Ready(Ok(())),
            Some(connection) => Pin::new(connection).poll_shutdown(cx),
        }
    }
}

impl AsyncXrayTcpStream for TlsSecurityStream {}

impl XraySecurity for TlsSecurityStream {}
