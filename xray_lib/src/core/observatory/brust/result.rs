use crate::core::observatory::stats::{ObserveStats, ObserveStatsHealth};
use std::time::Duration;
use std::time::Instant;

pub(super) struct HealthPingRTTS {
    cap: usize,
    validity: Duration,
    rtts: Vec<PingRTT>,
}

struct PingRTT {
    time: Instant,
    ping: Option<Duration>,
}

impl PingRTT {
    fn new(ping: Option<Duration>) -> Self {
        Self {
            time: Instant::now(),
            ping,
        }
    }
}

impl HealthPingRTTS {
    pub fn new(cap: usize, validity: Duration) -> Self {
        Self {
            cap,
            validity,
            rtts: Vec::with_capacity(cap),
        }
    }

    pub fn put(&mut self, ping: Option<Duration>) {
        push_bounded(&mut self.rtts, PingRTT::new(ping), self.cap);
    }

    pub fn get_statistics(&self) -> ObserveStatsHealth {
        let mut stats = ObserveStatsHealth::default();

        let mut sum = Duration::ZERO;
        let mut cnt = 0usize;

        let mut valid_rtts = Vec::new();

        let mut min: Option<Duration> = None;
        let mut max: Option<Duration> = None;

        for rtt in &self.rtts {
            // RTT is expired.
            if rtt.time.elapsed() > self.validity {
                continue;
            }

            // None means ping failed.
            let ping = match rtt.ping {
                Some(ping) => ping,
                None => {
                    stats.fail += 1;
                    continue;
                }
            };

            // Ignore zero RTT.
            if ping.is_zero() {
                continue;
            }

            cnt += 1;
            sum += ping;
            valid_rtts.push(ping);

            min = Some(min.map_or(ping, |value| value.min(ping)));
            max = Some(max.map_or(ping, |value| value.max(ping)));
        }

        stats.all = cnt + stats.fail;

        if cnt == 0 {
            return stats;
        }

        stats.average = sum / cnt as u32;

        stats.min = min.unwrap_or(Duration::ZERO);
        stats.max = max.unwrap_or(Duration::ZERO);

        let average = stats.average;

        let variance = valid_rtts
            .iter()
            .map(|rtt| {
                let diff = rtt.abs_diff(average);
                let nanos = diff.as_nanos() as f64;
                nanos * nanos
            })
            .sum::<f64>()
            / cnt as f64;

        stats.deviation = Duration::from_nanos(variance.sqrt() as u64);

        stats
    }
}
impl Into<ObserveStats> for &HealthPingRTTS {
    fn into(self) -> ObserveStats {
        let health = self.get_statistics();
        let time = Instant::now();
        let last_try_time = self.rtts.last().map(|rtt| rtt.time).unwrap_or(time.clone());

        let last_alive_time = self
            .rtts
            .iter()
            .rev()
            .find(|rtt| rtt.ping.is_some())
            .map(|rtt| rtt.time)
            .unwrap_or(time.clone());

        ObserveStats {
            alive: health.all != health.fail,

            delay: Some(health.average),
            last_try_time,

            last_alive_time,

            last_error_reason: None,

            health: Some(health),
        }
    }
}

fn push_bounded<T>(vec: &mut Vec<T>, value: T, capacity: usize) {
    if capacity == 0 {
        return;
    }

    if vec.len() >= capacity {
        vec.remove(0);
    }

    vec.push(value);
}
