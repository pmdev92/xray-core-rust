mod config;
mod load;
mod ping;
mod random;
mod round_robin;

use crate::core::context::Context;
use crate::core::observatory::stats::ObserveStats;
use crate::core::router::balancer::config::StrategyLeastLoadConfig;
use crate::core::router::balancer::load::LeastLoadBalancerStrategy;
use crate::core::router::balancer::ping::LeastPingBalancerStrategy;
use crate::core::router::balancer::random::RandomBalancerStrategy;
use crate::core::router::balancer::round_robin::RoundRobinBalancerStrategy;
use crate::core::router::config::BalancerConfig;
use async_trait::async_trait;
use rand::Rng;
use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

pub struct Balancer {
    fallback_outbound_tag: String,
    observatory_tag: Option<String>,
    outbound_selector: Vec<String>,
    strategy: Box<dyn BalancerStrategy>,
}

impl Balancer {
    pub fn new(balancer: &BalancerConfig) -> Self {
        let b: Box<dyn BalancerStrategy> =
            match balancer.strategy.method.as_str().to_lowercase().as_str() {
                "least_load" => {
                    let mut settings = StrategyLeastLoadConfig::default();
                    if let Some(setting) = &balancer.strategy.settings {
                        let result: io::Result<StrategyLeastLoadConfig> =
                            serde_json::from_str(setting.get()).map_err(|err| {
                                io::Error::new(ErrorKind::InvalidData, err.to_string())
                            });
                        if let Ok(s) = result {
                            settings = s;
                        }
                    }
                    Box::new(LeastLoadBalancerStrategy::new(settings))
                }
                "least_ping" => Box::new(LeastPingBalancerStrategy::new()),
                "round_robin" => Box::new(RoundRobinBalancerStrategy::new()),
                "random" | _ => Box::new(RandomBalancerStrategy::new()),
            };
        Self {
            fallback_outbound_tag: balancer.fallback_outbound_tag.clone(),
            observatory_tag: balancer.observatory_tag.clone(),
            outbound_selector: balancer.outbound_selector.clone(),
            strategy: b,
        }
    }

    pub async fn balance_outbound_tag(&self, context: Arc<Context>) -> (String, String) {
        let candidates = context.select_outbounds(&self.outbound_selector).await;
        let stats = context.get_stats(self.observatory_tag.clone()).await;
        let picked = self.strategy.pick(candidates, stats).await;
        if let Some(picked) = picked {
            return (picked, self.strategy.get_strategy_name());
        }
        (self.fallback_outbound_tag.clone(), "fallback".to_string())
    }
}

#[async_trait]
pub trait BalancerStrategy: Send + Sync {
    async fn pick(
        &self,
        candidates: Vec<String>,
        stats: Option<HashMap<String, ObserveStats>>,
    ) -> Option<String>;
    fn get_strategy_name(&self) -> String;
}
