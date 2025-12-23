use async_trait::async_trait;
use std::any::Any;
use std::io::Error;

use crate::core::io::AsyncXrayTcpStream;

#[async_trait]
pub trait Security: Send + Sync + Any {
    async fn dial(
        &self,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    ) -> Result<Box<dyn XraySecurity>, Error>;

    fn get_domain(&self) -> Option<String>;

    async fn add_alpn(&self, alpn_string: String);
}

pub trait XraySecurity: AsyncXrayTcpStream + Send + Sync {}
