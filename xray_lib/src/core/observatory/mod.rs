use crate::core::context::Context;
use crate::core::observatory::stats::ObserveStats;
use async_trait::async_trait;
use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;

pub mod brust;
pub mod config;
pub mod normal;
pub mod ping_client;
pub mod stats;

#[async_trait]
pub trait Observable: Send + Sync {
    async fn start(&self, context: Arc<Context>) -> Result<(), Error>;
    async fn get_stats(&self) -> Option<HashMap<String, ObserveStats>>;
    fn request_check(&self);
}
