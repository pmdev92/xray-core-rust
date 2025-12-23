use std::fmt::Debug;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::stream::StreamSettings;

#[async_trait]
pub trait Outbound: Send + Sync {
    async fn dial_tcp(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error>;
    async fn dial_udp(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutboundConfig {
    pub protocol: String,
    pub detour: Option<String>,
    pub tag: Option<String>,
    pub settings: Option<Box<RawValue>>,
    pub stream_settings: Option<StreamSettings>,
}
