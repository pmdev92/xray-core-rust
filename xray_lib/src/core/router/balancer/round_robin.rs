use crate::core::observatory::stats::ObserveStats;
use crate::core::router::balancer::BalancerStrategy;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct RoundRobinBalancerStrategy {
    index: AtomicUsize,
}

impl RoundRobinBalancerStrategy {
    pub fn new() -> Self {
        Self {
            index: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl BalancerStrategy for RoundRobinBalancerStrategy {
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
        let n = candidates.len();
        if n == 0 {
            return None;
        }
        let index = self.index.load(Ordering::Relaxed) % n;
        self.index.store((index + 1) % n, Ordering::Relaxed);
        Some(candidates[index].clone())
    }
    fn get_strategy_name(&self) -> String {
        "round robin".to_string()
    }
}
