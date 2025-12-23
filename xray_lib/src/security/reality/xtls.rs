use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::XraySecurity;
use futures::ready;
use log::error;
use once_cell::sync::Lazy;
use reality_tokio_rustls::rustls::pki_types::ServerName;
use reality_tokio_rustls::rustls::{ClientConfig, ClientConnection};
use std::future::poll_fn;
use std::io;
use std::io::{BufRead, Error, ErrorKind, Read, Result, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct RealityXtlsSecurityStream {
    stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    session: ClientConnection,
    read_state: ReadState,
    is_handshake_completed: bool,
    is_early_data: bool,
    early_data_len: usize,
    flushed: bool,
    read_waker: Option<Waker>,
}
impl RealityXtlsSecurityStream {
    pub fn new(
        server_name: String,
        config: Arc<ClientConfig>,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
        is_early_data: bool,
        early_data_len: usize,
    ) -> std::result::Result<Self, io::Error> {
        let domain = ServerName::try_from(server_name)
            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()))?;
        let session = ClientConnection::new(config, domain)
            .map_err(|e| Error::other(format!("Unable to create tls session: {}", e)))?;

        let xtls = Self {
            stream,
            session,
            read_state: ReadState::ReadHead([0u8; 5], 0),
            is_handshake_completed: false,
            is_early_data,
            early_data_len,
            flushed: true,
            read_waker: None,
        };
        Ok(xtls)
    }
    pub fn get_raw_stream(&mut self) -> &mut Box<dyn AsyncXrayTcpStream + Send + Sync> {
        return &mut self.stream;
    }
    pub(crate) fn conn_read(
        &mut self,
        cx: &mut Context,
    ) -> Poll<std::result::Result<(), io::Error>> {
        let mut reader = XtlsSyncAdapter {
            stream: &mut self.stream,
            cx,
            xtls_mode: true && !self.session.is_handshaking(),
            read_state: &mut self.read_state,
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
            .map_err(|e| Error::other(format!("-----: {}", e)))?;
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

    pub(crate) fn conn_write(
        &mut self,
        cx: &mut Context,
    ) -> Poll<std::result::Result<usize, io::Error>> {
        let mut writer = XtlsSyncAdapter {
            stream: &mut self.stream,
            cx,
            xtls_mode: false,
            read_state: &mut self.read_state,
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
    ) -> Poll<std::result::Result<usize, io::Error>> {
        let mut io = XtlsSyncAdapter {
            stream: &mut self.stream,
            cx,
            xtls_mode: false,
            read_state: &mut self.read_state,
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

impl AsyncRead for RealityXtlsSecurityStream {
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
            match this.conn_read(cx) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
        match this.session.reader().into_first_chunk() {
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
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for RealityXtlsSecurityStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, io::Error>> {
        let this = self.get_mut();
        let count = if !this.is_handshake_completed {
            let count = match this.handshake(cx, buf) {
                Poll::Ready(Ok(count)) => count,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.is_handshake_completed = true;
            if let Some(waker) = this.read_waker.take() {
                waker.wake();
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
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        let this = self.get_mut();

        while this.session.wants_write() {
            ready!(this.conn_write(cx))?;
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncXrayTcpStream for RealityXtlsSecurityStream {}

impl XraySecurity for RealityXtlsSecurityStream {}

enum ReadState {
    ReadHead([u8; 5], usize),
    ReadBody(Vec<u8>, usize),
    RemainingBody(Vec<u8>, usize),
}
struct XtlsSyncAdapter<'a, 'b> {
    pub stream: &'a mut Box<dyn AsyncXrayTcpStream + Send + Sync>,
    pub cx: &'a mut Context<'b>,
    pub xtls_mode: bool,
    pub read_state: &'a mut ReadState,
}

impl Read for XtlsSyncAdapter<'_, '_> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut buffer = ReadBuf::new(buf);
        if !self.xtls_mode {
            let result = match Pin::new(&mut self.stream).poll_read(self.cx, &mut buffer) {
                Poll::Ready(Ok(())) => Ok(buffer.filled().len()),
                Poll::Ready(Err(err)) => Err(err),
                Poll::Pending => Err(ErrorKind::WouldBlock.into()),
            };
            return result;
        }
        // as xtls would switch to send raw tcp data after first tls application data package
        // make sure to only read one complete tls package each time
        // otherwise it may read later tcp package which does not need tls decryption
        loop {
            match &mut self.read_state {
                ReadState::ReadHead(tls13_header, read_len) => {
                    let mut tls13_header_read_buf = ReadBuf::new(&mut tls13_header[*read_len..]);
                    match Pin::new(&mut self.stream).poll_read(self.cx, &mut tls13_header_read_buf)
                    {
                        Poll::Ready(Ok(())) => {
                            *read_len += tls13_header_read_buf.filled().len();
                            if *read_len < tls13_header.len() {
                                continue;
                            }
                            if tls13_header[..3] != [0x17, 0x03, 0x03] {
                                log::error!("Tls read Unknown head type {:?}", tls13_header);
                                return Err(io::Error::other(
                                    "Xtls Unknown tls application header",
                                ));
                            }
                            let content_length =
                                u16::from_be_bytes([tls13_header[3], tls13_header[4]]);
                            let content = vec![0u8; content_length as usize];
                            *self.read_state = ReadState::ReadBody(content, 0);
                        }
                        Poll::Ready(Err(err)) => return Err(err),
                        Poll::Pending => return Err(ErrorKind::WouldBlock.into()),
                    }
                }
                ReadState::ReadBody(tls13_content, read_len) => {
                    let mut tls13_content_read_buf = ReadBuf::new(&mut tls13_content[*read_len..]);
                    match Pin::new(&mut self.stream).poll_read(self.cx, &mut tls13_content_read_buf)
                    {
                        Poll::Ready(Ok(())) => {
                            *read_len += tls13_content_read_buf.filled().len();
                            if *read_len < tls13_content.len() {
                                continue;
                            }
                            let len = (tls13_content.len() as u16).to_be_bytes();
                            buffer.put_slice(&[0x17, 0x03, 0x03]);
                            buffer.put_slice(&len);

                            // as rustls read_tls buffer size is const 4096
                            // https://github.com/rustls/rustls/blob/3ccfcece31d727f57e9ad3806e4652e146ac3eed/rustls/src/msgs/deframer/buffers.rs#L220
                            // slice the array to fit in
                            // 5 bytes for the header
                            *self.read_state =
                                ReadState::RemainingBody(tls13_content.split_off(0), 4096 - 5);
                        }
                        Poll::Ready(Err(err)) => return Err(err),
                        Poll::Pending => return Err(ErrorKind::WouldBlock.into()),
                    }
                }
                ReadState::RemainingBody(tls13_content, remaining_size) => {
                    let tls13_content_len = tls13_content.len();
                    let read_state = if tls13_content_len > *remaining_size {
                        let tls13_content_left = tls13_content.split_off(*remaining_size);
                        ReadState::RemainingBody(tls13_content_left, 4096)
                    } else {
                        ReadState::ReadHead([0u8; 5], 0)
                    };
                    buffer.put_slice(tls13_content);
                    *self.read_state = read_state;
                    return Ok(buffer.filled().len());
                }
            }
        }
    }
}

impl XtlsSyncAdapter<'_, '_> {
    #[inline]
    fn poll_with<U>(
        &mut self,
        f: impl FnOnce(
            Pin<&mut Box<dyn AsyncXrayTcpStream + Send + Sync>>,
            &mut Context<'_>,
        ) -> Poll<std::result::Result<U, io::Error>>,
    ) -> std::result::Result<U, io::Error> {
        match f(Pin::new(self.stream), self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }
}
impl Write for XtlsSyncAdapter<'_, '_> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, io::Error> {
        self.poll_with(|io, cx| io.poll_write(cx, buf))
    }

    fn flush(&mut self) -> std::result::Result<(), io::Error> {
        self.poll_with(|io, cx| io.poll_flush(cx))
    }
}
