use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ObserveStats {
    pub alive: bool,
    pub delay: Option<Duration>,
    pub last_try_time: Instant,
    pub last_alive_time: Instant,
    pub last_error_reason: Option<String>,
    pub health: Option<ObserveStatsHealth>,
}

#[derive(Debug, Default)]
pub struct ObserveStatsHealth {
    pub all: usize,
    pub fail: usize,
    pub deviation: Duration,
    pub average: Duration,
    pub max: Duration,
    pub min: Duration,
}
