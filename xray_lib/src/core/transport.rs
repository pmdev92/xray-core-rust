use std::any::Any;
use std::io::Error;
use std::sync::Arc;

use async_trait::async_trait;

use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::io::AsyncXrayTcpStream;

#[async_trait]
pub trait Transport: Send + Sync + Any {
    async fn dial(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn XrayTransport>, Error>;
}

pub trait XrayTransport: AsyncXrayTcpStream + Send + Sync {}
