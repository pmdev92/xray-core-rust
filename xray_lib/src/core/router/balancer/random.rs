use crate::core::observatory::stats::ObserveStats;
use crate::core::router::balancer::BalancerStrategy;
use async_trait::async_trait;
use rand::Rng;
use std::collections::HashMap;

pub struct RandomBalancerStrategy {}

impl RandomBalancerStrategy {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl BalancerStrategy for RandomBalancerStrategy {
    async fn pick(
        &self,
        mut candidates: Vec<String>,
        stats: Option<HashMap<String, ObserveStats>>,
    ) -> Option<String> {
        if let Some(stats) = stats {
            candidates.retain(|candidate| match stats.get(candidate) {
                None => true,

                Some(item) => item.alive,
            });
        }
        if candidates.len() > 0 {
            let idx = rand::thread_rng().gen_range(0..candidates.len());
            let item = candidates.get(idx);
            if let Some(item) = item {
                return Some(item.clone().clone());
            }
        }
        None
    }

    fn get_strategy_name(&self) -> String {
        "random".to_string()
    }
}
