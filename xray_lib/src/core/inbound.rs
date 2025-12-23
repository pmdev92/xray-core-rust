use std::io::Error;
use std::sync::Arc;

use crate::core::context::Context;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

// pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + Any {}
//
// impl AsyncStream for TcpStream {}

#[async_trait]
pub trait InboundTcp: Send + Sync {
    async fn start(self: Box<Self>, context: Arc<Context>) -> Result<(), Error>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InboundConfig {
    pub settings: Option<Box<RawValue>>,
    pub protocol: String,
    pub tag: Option<String>,
}
