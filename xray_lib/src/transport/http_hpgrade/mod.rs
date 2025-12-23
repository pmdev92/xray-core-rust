use std::any::Any;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::Security;
use crate::core::stream::StreamSettings;
use crate::core::transport::{Transport, XrayTransport};
use crate::stream::get_stream;
use crate::transport::http_hpgrade::config::HttpUpgradeConfig;
use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use tls_parser::nom::AsBytes;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};

pub mod config;

pub struct HttpUpgradeTransport {
    security: Option<Box<dyn Security>>,
    host: Option<String>,
    path: Option<String>,
    stream_settings: Option<StreamSettings>,
}

impl HttpUpgradeTransport {
    pub fn new(
        stream_settings: Option<StreamSettings>,
        http_upgrade_config: Option<HttpUpgradeConfig>,
        security: Option<Box<dyn Security>>,
    ) -> Self {
        match http_upgrade_config {
            None => Self {
                stream_settings,
                security,
                host: None,
                path: None,
            },
            Some(http_upgrade_config) => Self {
                stream_settings,
                security,
                host: http_upgrade_config.host.clone(),
                path: http_upgrade_config.path.clone(),
            },
        }
    }
}

impl HttpUpgradeTransport {
    fn make_request(&self, address: String, host: Option<String>, path: String) -> String {
        let mut header_string = "".to_string();
        if let Some(host) = host {
            header_string.push_str(format!("Host: {}\r\n", host).as_str());
        } else {
            header_string.push_str(format!("Host: {}\r\n", address).as_str());
        }

        header_string.push_str(format!("Connection: {}\r\n", "Upgrade").as_str());
        header_string.push_str(format!("Upgrade: {}\r\n", "websocket").as_str());
        let request = format!("{} {} HTTP/{}\r\n{}\r\n", "GET", path, "1.1", header_string);
        request
    }
    fn get_request(&self, address: String) -> String {
        let path = self.path.clone().unwrap_or("/".to_string());
        let host = self.host.clone();
        return self.make_request(address, host, path);
    }
}

#[async_trait]
impl Transport for HttpUpgradeTransport {
    async fn dial(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn XrayTransport>, io::Error> {
        let connection = get_stream(
            context,
            detour,
            self.stream_settings.clone(),
            server_net_location.clone(),
        )
        .await?;

        let mut connection = match &self.security {
            None => connection,
            Some(security) => {
                let mut connection: Box<dyn AsyncXrayTcpStream + Send + Sync> =
                    security.dial(connection).await?;
                connection
            }
        };
        let request = self.get_request(server_net_location.clone().address.to_string());

        connection.write_all(request.as_bytes()).await?;
        connection.flush().await?;

        let mut reader = BufReader::new(connection);
        let mut lines = reader.lines();

        let status_line = lines.next_line().await?.unwrap_or_default();
        let mut parts = status_line.split_whitespace();
        let _http_version = parts.next();
        let status_code = parts.next().unwrap_or("500").parse::<u16>().unwrap_or(500);
        if (status_code != 101) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "http_upgrade unexpected response status code: {}",
                    status_code
                ),
            ));
        }
        let mut headers = http::HeaderMap::new();
        while let Some(line) = lines.next_line().await? {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(": ") {
                if let Ok(header_name) = HeaderName::from_str(key) {
                    if let Ok(header_value) = HeaderValue::from_str(value) {
                        headers.insert(header_name, header_value);
                    }
                }
            }
        }

        let connection = headers
            .get("Connection")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let upgrade = headers
            .get("Upgrade")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if (!"upgrade".eq_ignore_ascii_case(connection)
            || !"websocket".eq_ignore_ascii_case(upgrade))
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "http_upgrade unexpected headers `connection: {} upgrade: {}`",
                    connection, upgrade
                ),
            ));
        }

        let tcp_transport = HttpUpgradeStream {
            connection: lines.into_inner().into_inner(),
        };
        Ok(Box::new(tcp_transport))
    }
}

pub struct HttpUpgradeStream<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Any> {
    connection: T,
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Any> HttpUpgradeStream<T> {}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Any> AsyncRead for HttpUpgradeStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = ready!(Pin::new(&mut self.connection).poll_read(cx, buf));
        return match result {
            Ok(_) => {
                if buf.filled().len() == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "connection closed",
                    )));
                }
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        };
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Any> AsyncWrite for HttpUpgradeStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let result = ready!(Pin::new(&mut self.connection).poll_write(cx, buf));

        match result {
            Ok(size) => Poll::Ready(Ok(size)),
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.connection).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.connection).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Any> AsyncXrayTcpStream
    for HttpUpgradeStream<T>
{
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Any + Any> XrayTransport
    for HttpUpgradeStream<T>
{
}
