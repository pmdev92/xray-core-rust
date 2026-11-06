use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::dns::config::{DnsProtocol, DnsServer};
use async_trait::async_trait;
use blake3::IncrementCounter::No;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::net::client::Client;
use hickory_resolver::net::h2::{HttpsClientStream, connect};
use hickory_resolver::net::h3::H3ClientStream;
use hickory_resolver::net::quic::QuicClientStream;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::runtime::iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd};
use hickory_resolver::net::tcp::{TcpClientStream, TcpStream};
use hickory_resolver::net::tls::tls_client_connect;
use hickory_resolver::net::udp::{UdpClientStream, UdpStream};
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::net::{BufDnsStreamHandle, runtime};
use log::{debug, error};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::future::Future;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::{TcpSocket, UdpSocket};
use tokio_rustls::TlsConnector;

pub struct DnsClient;

impl DnsClient {
    pub async fn query(
        context: Arc<Context>,
        server: &DnsServer,
        message: &Message,
    ) -> io::Result<Message> {
        let mut packet = Vec::new();
        let mut encoder = hickory_proto::serialize::binary::BinEncoder::new(&mut packet);

        message
            .emit(&mut encoder)
            .map_err(|e| io::Error::other(format!("Failed to encode query: {}", e)))?;

        let response = match &server.protocol {
            DnsProtocol::Udp => Self::query_udp(context, server, &packet).await,
            DnsProtocol::Tcp => Self::query_tcp(context, server, &packet).await,
            DnsProtocol::Tls => Self::query_tls(context, server, &packet).await,
            DnsProtocol::Https(path) => {
                Self::query_https(context, server, path.clone(), &packet).await
            }
            DnsProtocol::Quic => Self::query_quic(context, server, &packet).await,
            DnsProtocol::H3(path) => Self::query_h3(context, server, path.clone(), &packet).await,
        }?;

        Message::from_bytes(&response)
            .map_err(|e| io::Error::other(format!("Failed to decode query response: {}", e)))
    }

    async fn exchange(
        mut client: Client<TokioRuntimeProvider>,
        bg: impl Future<Output = ()> + Send + 'static,
        query_packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        tokio::spawn(bg);

        let message = Message::from_vec(query_packet)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let response = client
            .send(message.into())
            .first_answer()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        response
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    fn tls_config() -> ClientConfig {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    }

    async fn query_tcp(
        context: Arc<Context>,
        server: &DnsServer,
        query_packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        let addr = server
            .net_location()?
            .to_socket_addr(context.clone())
            .await?;

        let net_location = Arc::new(NetLocation::from_socket_address(addr));

        debug!("DNS TCP query to {}:{}", server.address, server.port);
        let socket = context
            .dial_tcp(server.outbound.clone(), net_location.clone())
            .await?;
        let socket = AsyncIoTokioAsStd(socket);

        let (sender, outbound_messages) = BufDnsStreamHandle::new(addr);
        let stream = TcpStream::from_stream_with_receiver(socket, addr, outbound_messages);

        let client_stream = TcpClientStream::from_stream(stream);

        let (client, bg) = Client::<TokioRuntimeProvider>::new(client_stream, sender);

        Self::exchange(client, bg, query_packet).await
    }

    async fn query_tls(
        context: Arc<Context>,
        server: &DnsServer,
        query_packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        let addr = server
            .net_location()?
            .to_socket_addr(context.clone())
            .await?;

        let net_location = Arc::new(NetLocation::from_socket_address(addr));

        debug!("DNS TLS query to {}:{}", server.address, server.port);

        let socket = context
            .dial_tcp(server.outbound.clone(), net_location)
            .await?;

        let config = Arc::new(Self::tls_config());

        let server_name = ServerName::try_from(server.address.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let connector = TlsConnector::from(config);

        let tls_stream = connector
            .connect(server_name, socket)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let socket = AsyncIoTokioAsStd(tls_stream);

        let (sender, outbound_messages) = BufDnsStreamHandle::new(addr);

        let stream = TcpStream::from_stream_with_receiver(socket, addr, outbound_messages);

        let client_stream = TcpClientStream::from_stream(stream);

        let (client, bg) = Client::<TokioRuntimeProvider>::new(client_stream, sender);

        Self::exchange(client, bg, query_packet).await
    }

    async fn query_https(
        context: Arc<Context>,
        server: &DnsServer,
        path: String,
        query_packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        let addr = server
            .net_location()?
            .to_socket_addr(context.clone())
            .await?;
        let net_location = Arc::new(NetLocation::from_socket_address(addr));
        debug!("DNS HTTPS query to {}:{}", server.address, server.port);
        let tcp_context = context.clone();
        let outbound = server.outbound.clone();

        let tcp = async move {
            let socket = tcp_context.dial_tcp(outbound, net_location).await?;
            Ok::<_, io::Error>(AsyncIoTokioAsStd(socket))
        };

        let sender = connect(
            tcp,
            Arc::new(Self::tls_config()),
            addr,
            Arc::from(server.address.clone()),
            Arc::from(path),
            None,
        )
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

        let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(sender);

        Self::exchange(client, bg, query_packet).await
    }

    async fn query_udp(
        context: Arc<Context>,
        server: &DnsServer,
        query_packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        let addr = server
            .net_location()?
            .to_socket_addr(context.clone())
            .await?;

        debug!("DNS UDP query to {}:{}", server.address, server.port);
        let addr = if server.outbound.is_some() {
            let net_location = Arc::new(NetLocation::from_socket_address(addr));
            context
                .dial_udp_proxy(server.outbound.clone(), net_location.clone())
                .await?
        } else {
            addr
        };

        let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::new()).build();

        let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);

        Self::exchange(client, bg, query_packet).await
    }

    async fn query_quic(
        context: Arc<Context>,
        server: &DnsServer,
        query_packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        let addr = server
            .net_location()?
            .to_socket_addr(context.clone())
            .await?;

        debug!("DNS QUIC query to {}:{}", server.address, server.port);
        let addr = if server.outbound.is_some() {
            let net_location = Arc::new(NetLocation::from_socket_address(addr));
            context
                .dial_udp_proxy(server.outbound.clone(), net_location.clone())
                .await?
        } else {
            addr
        };

        let sender = QuicClientStream::builder()
            .crypto_config(Self::tls_config())
            .build(addr, Arc::from(server.address.clone()))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(sender);

        Self::exchange(client, bg, query_packet).await
    }

    async fn query_h3(
        context: Arc<Context>,
        server: &DnsServer,
        path: String,
        query_packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        let addr = server
            .net_location()?
            .to_socket_addr(context.clone())
            .await?;

        debug!("DNS H3 query to {}:{}", server.address, server.port);
        let addr = if server.outbound.is_some() {
            let net_location = Arc::new(NetLocation::from_socket_address(addr));
            context
                .dial_udp_proxy(server.outbound.clone(), net_location.clone())
                .await?
        } else {
            addr
        };

        let sender = H3ClientStream::builder()
            .crypto_config(Self::tls_config())
            .build(addr, Arc::from(server.address.clone()), Arc::from(path))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(sender);

        Self::exchange(client, bg, query_packet).await
    }
}
