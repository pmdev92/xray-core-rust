use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::common::net_location::NetLocation;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;

#[derive(Debug)]
pub struct DirectOutbound {}

impl DirectOutbound {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    async fn dial_tcp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let stream = context.dial_tcp(detour, net_location).await?;
        return Ok(stream);
    }

    async fn dial_udp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let stream = context.dial_udp(detour, net_location).await?;
        return Ok(stream);
    }
}
