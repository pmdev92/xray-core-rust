use crate::core::observatory::stats::ObserveStats;
use crate::core::router::balancer::BalancerStrategy;
use crate::core::router::balancer::config::{StrategyLeastLoadConfig, StrategyWeight};

use crate::common::duration::parse_duration;
use async_trait::async_trait;
use rand::Rng;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::Duration;

pub struct LeastLoadBalancerStrategy {
    costs: WeightManager,
    baselines: Vec<Duration>,
    expected: usize,
    max_rtt: Option<Duration>,
    tolerance: f64,
}

impl LeastLoadBalancerStrategy {
    pub fn new(config: StrategyLeastLoadConfig) -> Self {
        Self {
            costs: WeightManager::new(config.costs.unwrap_or_default()),

            baselines: config
                .baselines
                .unwrap_or_default()
                .into_iter()
                .filter_map(|value| parse_duration(value.as_str()).ok())
                .collect(),

            expected: config.expected.unwrap_or(0),

            max_rtt: config
                .max_rtt
                .as_deref()
                .and_then(|value| parse_duration(value).ok()),
            tolerance: config.tolerance.unwrap_or(0f64),
        }
    }

    fn get_nodes(
        &self,
        candidates: Vec<String>,
        stats: Option<HashMap<String, ObserveStats>>,
    ) -> Vec<LeastLoadNode> {
        let stats = match stats {
            Some(stats) => stats,
            None => return Vec::new(),
        };

        let mut nodes = Vec::new();

        for candidate in candidates {
            let stat = match stats.get(&candidate) {
                Some(stat) => stat,
                None => continue,
            };

            if !self.should_select_node(stat) {
                continue;
            }

            let delay = match stat.delay {
                Some(delay) => delay,
                None => continue,
            };

            let mut node = LeastLoadNode {
                tag: candidate.clone(),
                count_all: 1,
                count_fail: 1,
                rtt_average: delay,
                rtt_deviation: delay,

                rtt_deviation_cost: self.costs.apply(&candidate, delay),
            };

            if let Some(health) = &stat.health {
                node.rtt_average = health.average;
                node.rtt_deviation = health.deviation;
                node.rtt_deviation_cost = self.costs.apply(&candidate, health.deviation);
                node.count_all = health.all;
                node.count_fail = health.fail;
            }

            nodes.push(node);
        }

        self.least_load_sort(&mut nodes);

        nodes
    }

    fn should_select_node(&self, stat: &ObserveStats) -> bool {
        if !stat.alive {
            return false;
        }

        if let Some(d) = self.max_rtt.clone() {
            let delay = match stat.delay {
                Some(delay) => delay,
                None => return false,
            };

            if delay >= d {
                return false;
            }
        }

        if let Some(health) = &stat.health {
            if health.all > 0 && self.tolerance > 0.0 {
                let failure_rate = health.fail as f64 / health.all as f64;

                if failure_rate > self.tolerance {
                    return false;
                }
            }
        }

        true
    }

    fn least_load_sort(&self, nodes: &mut [LeastLoadNode]) {
        nodes.sort_by(|left, right| {
            let ordering = left.rtt_deviation_cost.cmp(&right.rtt_deviation_cost);

            if ordering != Ordering::Equal {
                return ordering;
            }

            let ordering = left.rtt_average.cmp(&right.rtt_average);

            if ordering != Ordering::Equal {
                return ordering;
            }

            let ordering = left.count_fail.cmp(&right.count_fail);

            if ordering != Ordering::Equal {
                return ordering;
            }

            let ordering = right.count_all.cmp(&left.count_all);

            if ordering != Ordering::Equal {
                return ordering;
            }

            left.tag.cmp(&right.tag)
        });
    }

    fn select_least_load(&self, nodes: Vec<LeastLoadNode>) -> Vec<LeastLoadNode> {
        if nodes.is_empty() {
            return Vec::new();
        }

        let available_count = nodes.len();

        let mut expected = self.expected;

        if expected > available_count {
            return nodes;
        }

        if expected == 0 {
            expected = 1;
        }

        if self.baselines.is_empty() {
            return nodes.into_iter().take(expected).collect();
        }

        let mut count = 0;

        for baseline in &self.baselines {
            for i in count..available_count {
                if nodes[i].rtt_deviation_cost >= *baseline {
                    break;
                }
                count = i + 1;
            }

            if count >= expected {
                break;
            }
        }
        if self.expected > 0 && count < expected {
            count = expected;
        }

        nodes.into_iter().take(count).collect()
    }
}

#[async_trait]
impl BalancerStrategy for LeastLoadBalancerStrategy {
    async fn pick(
        &self,
        candidates: Vec<String>,
        stats: Option<HashMap<String, ObserveStats>>,
    ) -> Option<String> {
        let nodes = self.get_nodes(candidates, stats);
        let selected = self.select_least_load(nodes);
        if selected.is_empty() {
            return None;
        }
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..selected.len());
        Some(selected[index].tag.clone())
    }

    fn get_strategy_name(&self) -> String {
        "least load".to_string()
    }
}

// ============================================================
// LeastLoadNode
// ============================================================

#[derive(Debug)]
struct LeastLoadNode {
    tag: String,

    count_all: usize,
    count_fail: usize,

    rtt_average: Duration,
    rtt_deviation: Duration,

    rtt_deviation_cost: Duration,
}

// ============================================================
// WeightManager
// ============================================================

struct WeightManager {
    costs: Vec<StrategyWeightMatcher>,
}

struct StrategyWeightMatcher {
    regexp: bool,
    matcher: String,
    value: f64,
    regex: Option<Regex>,
}

impl WeightManager {
    fn new(costs: Vec<StrategyWeight>) -> Self {
        let costs = costs
            .into_iter()
            .map(|cost| {
                let regex = if cost.regexp {
                    Regex::new(&cost.r#match).ok()
                } else {
                    None
                };

                StrategyWeightMatcher {
                    regexp: cost.regexp,
                    matcher: cost.r#match,
                    value: cost.value,
                    regex,
                }
            })
            .collect();

        Self { costs }
    }

    fn apply(&self, tag: &str, value: Duration) -> Duration {
        let cost = self.get_cost(tag);
        let value = value.as_secs_f64() * cost.sqrt();
        Duration::from_secs_f64(value)
    }

    fn get_cost(&self, tag: &str) -> f64 {
        for cost in &self.costs {
            let matched = if cost.regexp {
                match &cost.regex {
                    Some(regex) => regex.is_match(tag),
                    None => false,
                }
            } else {
                tag == cost.matcher
            };

            if matched {
                return cost.value;
            }
        }
        1.0
    }
}
