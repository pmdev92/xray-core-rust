use crate::common::constants::MAX_TCP_BUFFER_CAPACITY;
use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::Security;
use crate::core::stream::StreamSettings;
use crate::core::transport::{Transport, XrayTransport};
use crate::transport::xhttp::config::XHttpConfig;
use crate::transport::xhttp::http_unify::open_http_unify;
use crate::transport::xhttp::protocol::{
    DownloadSettings, HttpVersion, Mode, UploadSettings, XhttpSettings, decide_http_version,
    decide_mode, is_secure_link,
};
use crate::transport::xhttp::stream::XHttpStream;
use crate::transport::xhttp::xmux::XmuxClientOpenUsage;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use log::warn;
use reqwest::Body;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

mod chunk_stream;
pub mod config;
pub(crate) mod http_unify;
pub(crate) mod huffman_table;
pub(crate) mod meta;
pub(crate) mod padding;
pub(crate) mod protocol;
pub(crate) mod stream;
pub(crate) mod xmux;

pub struct XHttpTransport {
    inner: Arc<XHttpTransportInner>,
}

impl XHttpTransport {
    pub fn new(
        stream_settings: Option<StreamSettings>,
        x_http_config: Option<XHttpConfig>,
        security: Option<Box<dyn Security>>,
    ) -> Self {
        let upload_security = Arc::new(security);

        let inner = match x_http_config {
            None => {
                let xhttp_settings = Arc::new(XhttpSettings::parse(
                    None,
                    decide_http_version(None, None),
                    is_secure_link(None),
                ));
                let upload_mux = xmux::XmuxManager::new(&xhttp_settings.x_mux_settings);
                XHttpTransportInner {
                    mode: decide_mode(None),
                    upload_settings: UploadSettings {
                        security: upload_security.clone(),
                        mux_manager: upload_mux.clone(),
                        xhttp_settings: xhttp_settings.clone(),
                    },
                    download_settings: DownloadSettings {
                        address: None,
                        port: None,
                        security: upload_security.clone(),
                        mux_manager: upload_mux,
                        xhttp_settings,
                    },
                }
            }
            Some(x_http_config) => {
                let mut upload_security_type = None;
                let mut upload_tls_config = None;
                if let Some(ref ss) = stream_settings {
                    upload_security_type = Some(ss.security.clone());
                    upload_tls_config = ss.tls_settings.clone();
                }

                let upload_xhttp_settings = XhttpSettings::parse(
                    Some(x_http_config.clone()),
                    HttpVersion::V2,
                    is_secure_link(upload_security_type),
                );
                let upload_mux = xmux::XmuxManager::new(&upload_xhttp_settings.x_mux_settings);
                let upload_settings = UploadSettings {
                    security: upload_security,
                    mux_manager: upload_mux,
                    xhttp_settings: Arc::new(upload_xhttp_settings),
                };
                let download_settings =
                    DownloadSettings::parse(x_http_config.extra.clone(), &upload_settings);
                XHttpTransportInner {
                    mode: decide_mode(x_http_config.mode),
                    upload_settings,
                    download_settings,
                }
            }
        };

        XHttpTransport {
            inner: Arc::new(inner),
        }
    }
}

#[async_trait]
impl Transport for XHttpTransport {
    async fn dial(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn XrayTransport>, Error> {
        let session_id = match self.inner.mode {
            Mode::PacketUp | Mode::StreamUp => Uuid::new_v4().to_string(),
            Mode::StreamOne => "".to_string(),
        };

        let (download_open_usage, download_link, upload_link) = match self.inner.mode {
            Mode::PacketUp => {
                let dl = self
                    .inner
                    .open_stream_down(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        &session_id,
                    )
                    .await?;
                let ul = self
                    .inner
                    .open_post_packet(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        &session_id,
                    )
                    .await?;
                (dl.0, dl.1, ul)
            }
            Mode::StreamUp => {
                let dl = self
                    .inner
                    .open_stream_down(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        &session_id,
                    )
                    .await?;
                let ul = self
                    .inner
                    .open_stream_up(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        &session_id,
                    )
                    .await?;
                (dl.0, dl.1, ul)
            }
            Mode::StreamOne => {
                self.inner
                    .open_stream_one(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        &session_id,
                    )
                    .await?
            }
        };

        Ok(Box::new(XHttpStream::new(
            download_open_usage,
            download_link,
            upload_link,
        )))
    }
}

struct XHttpTransportInner {
    mode: Mode,
    upload_settings: UploadSettings,
    download_settings: DownloadSettings,
}

impl XHttpTransportInner {
    async fn get_upload_sender(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<xmux::XmuxConnection, Error> {
        let mut manager = self.upload_settings.mux_manager.lock().await;
        let version = self.upload_settings.xhttp_settings.http_version.clone();
        let security = self.upload_settings.security.clone();
        manager
            .get_or_create(|| {
                open_http_unify(context, detour, server_net_location, version, security)
            })
            .await
    }

    async fn get_download_sender(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<xmux::XmuxConnection, Error> {
        let mut manager = self.download_settings.mux_manager.lock().await;
        let version = self.download_settings.xhttp_settings.http_version.clone();
        let security = self.download_settings.security.clone();
        manager
            .get_or_create(|| {
                open_http_unify(context, detour, server_net_location, version, security)
            })
            .await
    }

    async fn open_stream_down(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        session_id: &str,
    ) -> Result<(XmuxClientOpenUsage, Receiver<Result<Bytes, Error>>), Error> {
        use crate::common::address::Address;
        let mut server_net_location = server_net_location;
        if let (Some(dl_address), Some(dl_port)) = (
            &self.download_settings.address,
            &self.download_settings.port,
        ) {
            let address = Address::from(dl_address.as_str())?;
            server_net_location = Arc::new(NetLocation::new(address, *dl_port));
        }

        let mut mux_connection = self
            .get_download_sender(context, detour, server_net_location)
            .await?;

        let dl = &self.download_settings.xhttp_settings;
        let url = dl.get_url_builder();
        let builder = meta::build_request(
            session_id,
            "GET",
            url,
            &dl.headers,
            &dl.padding,
            &dl.session_placement,
            &dl.session_key,
            false,
            false,
        );
        let req = builder
            .body(Body::from(Bytes::new()))
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

        let response = mux_connection
            .sender
            .send_request_unify(req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

        if response.status != 200 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("x-http unexpected status {}", response.status),
            ));
        }

        Ok((mux_connection.open_usage_counter, response.rx))
    }

    async fn open_stream_up(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        session_id: &str,
    ) -> Result<Sender<Vec<u8>>, Error> {
        let mut mux_connection = self
            .get_upload_sender(context, detour, server_net_location)
            .await?;

        let ul = &self.upload_settings.xhttp_settings;
        let url = ul.get_url_builder();
        let builder = meta::build_request(
            session_id,
            ul.uplink_http_method.as_str(),
            url,
            &ul.headers,
            &ul.padding,
            &ul.session_placement,
            &ul.session_key,
            ul.no_grpc_header.unwrap_or(false),
            true,
        );
        let (mut tx_hyper, rx_hyper) = mpsc::channel::<Result<Bytes, Error>>(10);
        use http_body_util::BodyStream;
        use tokio_stream::wrappers::ReceiverStream;
        let stream = Body::wrap_stream(ReceiverStream::new(rx_hyper));
        let body = BodyStream::new(stream);
        let req = builder
            .body(Body::wrap(body))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10);
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                let res = tx_hyper.send(Ok(Bytes::from(chunk))).await;
                if res.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            let open_usage = mux_connection.open_usage_counter;
            let response = mux_connection.sender.send_request_unify(req).await;
            let mut response = match response {
                Ok(r) => r,
                Err(_) => {
                    return;
                }
            };
            while let Some(_) = response.rx.recv().await {}
            drop(open_usage);
        });

        Ok(tx)
    }

    async fn open_stream_one(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        session_id: &str,
    ) -> Result<
        (
            XmuxClientOpenUsage,
            Receiver<Result<Bytes, Error>>,
            Sender<Vec<u8>>,
        ),
        Error,
    > {
        let mut mux_connection = self
            .get_upload_sender(context, detour, server_net_location)
            .await?;

        let ul = &self.upload_settings.xhttp_settings;
        let url = ul.get_url_builder();
        let builder = meta::build_request(
            session_id,
            ul.uplink_http_method.as_str(),
            url,
            &ul.headers,
            &ul.padding,
            &ul.session_placement,
            &ul.session_key,
            ul.no_grpc_header.unwrap_or(false),
            true,
        );
        let (mut tx_hyper, rx_hyper) = mpsc::channel::<Result<Bytes, Error>>(10);
        use http_body_util::BodyStream;
        let stream = Body::wrap_stream(ReceiverStream::new(rx_hyper));
        let body = BodyStream::new(stream);
        let req = builder
            .body(Body::wrap(body))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let mut response = mux_connection
            .sender
            .send_request_unify(req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        if response.status != 200 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("x-http unexpected status {}", response.status),
            ));
        }

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10);
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                let res = tx_hyper.send(Ok(Bytes::from(chunk))).await;
                if res.is_err() {
                    break;
                }
            }
        });

        Ok((mux_connection.open_usage_counter, response.rx, tx))
    }

    async fn post_packet(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        session_id: String,
        seq_str: String,
        data: Bytes,
    ) -> Result<(), Error> {
        let mut conn = self
            .get_upload_sender(context, detour, server_net_location)
            .await?;

        let ul = &self.upload_settings.xhttp_settings;
        let url = ul.get_url_builder();
        let mut builder = meta::build_packet_request(
            &session_id,
            ul.uplink_http_method.as_str(),
            url,
            &ul.headers,
            &ul.padding,
            &ul.session_placement,
            &ul.session_key,
            &seq_str,
            &ul.seq_placement,
            &ul.seq_key,
        );

        match ul.uplink_data_placement.as_str() {
            "header" => {
                builder = builder.header("Content-Length", 0);
                builder = meta::apply_data_to_headers(
                    builder,
                    &data,
                    &ul.uplink_data_key,
                    ul.uplink_chunk_size_min,
                    ul.uplink_chunk_size_max,
                );
                let req = builder
                    .body(Body::from(Bytes::new()))
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                let response = conn
                    .sender
                    .send_request_unify(req)
                    .await
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                if response.status != 200 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("x-http unexpected status {}", response.status),
                    ));
                }
            }
            "cookie" => {
                builder = builder.header("Content-Length", 0);
                builder = meta::apply_data_to_cookies(
                    builder,
                    &data,
                    &ul.uplink_data_key,
                    ul.uplink_chunk_size_min,
                    ul.uplink_chunk_size_max,
                );
                let req = builder
                    .body(Body::from(Bytes::new()))
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                let response = conn
                    .sender
                    .send_request_unify(req)
                    .await
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                if response.status != 200 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("x-http unexpected status {}", response.status),
                    ));
                }
            }
            _ => {
                builder = builder.header("Content-Length", data.len());
                let req = builder
                    .body(Body::from(data))
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                let response = conn
                    .sender
                    .send_request_unify(req)
                    .await
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                if response.status != 200 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("x-http unexpected status {}", response.status),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn open_post_packet(
        self: &Arc<Self>,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        session_id: &str,
    ) -> Result<Sender<Vec<u8>>, Error> {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10);

        let max_packet_size = self
            .upload_settings
            .xhttp_settings
            .packet_up_max_each_post_bytes
            .unwrap_or(1_000_000)
            - MAX_TCP_BUFFER_CAPACITY;

        let interval_ms = self
            .upload_settings
            .xhttp_settings
            .packet_up_interval_ms
            .unwrap_or(30);

        let buffer = Arc::new(Mutex::new(BytesMut::new()));
        let notify_data = Arc::new(Notify::new());
        let notify_space = Arc::new(Notify::new());
        let is_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        {
            let buffer = buffer.clone();
            let notify_data = notify_data.clone();
            let notify_space = notify_space.clone();
            let is_closed = is_closed.clone();
            tokio::spawn(async move {
                while let Some(data) = rx.recv().await {
                    if is_closed.load(Ordering::Acquire) {
                        return;
                    }
                    if data.is_empty() {
                        break;
                    }
                    loop {
                        let mut buf = buffer.lock().await;
                        if is_closed.load(Ordering::Acquire) {
                            return;
                        }
                        if buf.len() + data.len() <= max_packet_size {
                            buf.extend_from_slice(&data);
                            notify_data.notify_waiters();
                            break;
                        }
                        drop(buf);
                        if is_closed.load(Ordering::Acquire) {
                            return;
                        }
                        notify_space.notified().await;
                    }
                }
                is_closed.store(true, Ordering::Release);
                notify_data.notify_waiters();
                notify_space.notify_waiters();
            });
        }

        {
            let self_clone = self.clone();
            let context = context.clone();
            let server_net_location = server_net_location.clone();
            let buffer = buffer.clone();
            let notify_data = notify_data.clone();
            let notify_space = notify_space.clone();
            let is_closed = is_closed.clone();
            let session_id = session_id.to_string();
            let detour = detour.clone();
            tokio::spawn(async move {
                let mut seq = 0usize;
                let mut last_write = 0i64;
                loop {
                    if is_closed.load(Ordering::Acquire) {
                        break;
                    }
                    {
                        let buf = buffer.lock().await;
                        if buf.is_empty() {
                            drop(buf);
                            notify_data.notified().await;
                            continue;
                        }
                    }
                    let now = Utc::now().timestamp_micros();
                    let min_gap = interval_ms as i64 * 1000;
                    let diff = (last_write + min_gap) - now;
                    if diff > 0 {
                        sleep(Duration::from_micros(diff as u64)).await;
                    }
                    let packet = {
                        let mut buf = buffer.lock().await;
                        if buf.is_empty() {
                            continue;
                        }
                        let out = if buf.len() > max_packet_size {
                            buf.split_to(max_packet_size).freeze()
                        } else {
                            buf.split().freeze()
                        };
                        drop(buf);
                        notify_space.notify_waiters();
                        out
                    };
                    last_write = Utc::now().timestamp_micros();
                    let seq_str = seq.to_string();
                    seq += 1;
                    let res = self_clone
                        .post_packet(
                            context.clone(),
                            detour.clone(),
                            server_net_location.clone(),
                            session_id.clone(),
                            seq_str,
                            packet,
                        )
                        .await;
                    if res.is_err() {
                        is_closed.store(true, Ordering::Release);
                        notify_data.notify_waiters();
                        notify_space.notify_waiters();
                    }
                }
            });
        }

        Ok(tx)
    }
}
