use crate::core::observatory::stats::ObserveStats;
use crate::core::router::balancer::BalancerStrategy;
use async_trait::async_trait;
use std::collections::HashMap;

pub struct LeastPingBalancerStrategy {}

impl LeastPingBalancerStrategy {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl BalancerStrategy for LeastPingBalancerStrategy {
    async fn pick(
        &self,
        mut candidates: Vec<String>,
        stats: Option<HashMap<String, ObserveStats>>,
    ) -> Option<String> {
        let stats = stats?;

        let mut best_candidate: Option<String> = None;

        let mut best_ping = None;

        for candidate in candidates {
            let stat = match stats.get(&candidate) {
                Some(stat) => stat,
                None => continue,
            };
            if !stat.alive {
                continue;
            }
            let ping = match stat.delay {
                Some(ping) => ping,
                None => continue,
            };

            if let Some(current__best_ping) = best_ping {
                if ping < current__best_ping {
                    best_ping = Some(ping);
                    best_candidate = Some(candidate);
                }
            } else {
                best_ping = Some(ping);
                best_candidate = Some(candidate);
            }
        }
        best_candidate
    }
    fn get_strategy_name(&self) -> String {
        "least ping".to_string()
    }
}
