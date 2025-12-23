use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use async_trait::async_trait;

use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;

#[derive(Debug)]
pub struct BlockOutbound {}

impl BlockOutbound {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Outbound for BlockOutbound {
    async fn dial_tcp(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("block tcp outbound to {}", net_location),
        ));
    }

    async fn dial_udp(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("block udp outbound to {}", net_location),
        ));
    }
}
