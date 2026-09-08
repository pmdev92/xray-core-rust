pub mod config;
mod result;

use crate::common::duration::parse_duration;
use crate::core::context::Context;
use crate::core::observatory::Observable;
use crate::core::observatory::brust::config::BrustObservationConfig;
use crate::core::observatory::brust::result::HealthPingRTTS;
use crate::core::observatory::ping_client::PingClient;
use crate::core::observatory::stats::ObserveStats;

use async_trait::async_trait;
use log::{error, info};
use rand::Rng;
use s2n_codec::zerocopy::IntoBytes;
use std::collections::{HashMap, HashSet};
use std::io::Error;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration, sleep};

pub struct BrustObservation {
    selector: Vec<String>,
    destination: String,
    connectivity: Option<String>,

    interval: Duration,
    timeout: Duration,
    sampling_count: usize,
    request_check_all: bool,

    results: RwLock<HashMap<String, HealthPingRTTS>>,

    check_trigger: Notify,

    request_check_task_all: Mutex<Option<JoinHandle<()>>>,
    request_check_task_interval: Mutex<Option<JoinHandle<()>>>,
}

impl BrustObservation {
    pub fn new(config: BrustObservationConfig, selector: Vec<String>) -> Result<Self, Error> {
        let destination = config
            .destination
            .unwrap_or("https://connectivitycheck.gstatic.com/generate_204".to_string());

        let interval = config.interval.as_deref().unwrap_or("10m");

        let interval = parse_duration(interval)?;

        let sampling_count = config.sampling_count.unwrap_or(1).max(1);

        let timeout = config.timeout.as_deref().unwrap_or("5s");

        let timeout = parse_duration(timeout)?;

        Ok(Self {
            selector,
            destination,
            connectivity: config.connectivity.clone(),

            interval,
            timeout,
            sampling_count,

            request_check_all: config.request_check_all.unwrap_or(false),
            results: Default::default(),

            check_trigger: Notify::new(),

            request_check_task_all: Mutex::new(None),
            request_check_task_interval: Mutex::new(None),
        })
    }

    async fn do_check(
        self: &Arc<Self>,
        context: Arc<Context>,
        tags: Vec<String>,
        duration: Duration,
        rounds: usize,
    ) {
        info!(
            "brust observation: check tags: {:?} duration {:?} rounds {}",
            tags, duration, rounds
        );

        if tags.is_empty() || rounds == 0 {
            return;
        }

        let mut tasks = JoinSet::new();

        for tag in tags {
            for _ in 0..rounds {
                let delay = if duration > Duration::ZERO {
                    rand::thread_rng().gen_range(Duration::ZERO..duration)
                } else {
                    Duration::ZERO
                };

                info!(
                    "brust observation: check tag {} delay {}m {}s",
                    tag,
                    delay.as_secs() / 60,
                    delay.as_secs() % 60
                );

                let timeout = self.timeout;
                let destination = self.destination.clone();
                let tag_clone = tag.clone();
                let context_clone = context.clone();
                let self_clone = self.clone();

                tasks.spawn(async move {
                    sleep(delay).await;

                    let ping_client = match PingClient::new_tagged(
                        context_clone.clone(),
                        tag_clone.clone(),
                        destination.clone(),
                        Some(timeout),
                    ) {
                        Ok(client) => client,

                        Err(error) => {
                            error!(
                                "brust observation: create ping client error {} with {} : {}",
                                destination, tag_clone, error
                            );

                            return;
                        }
                    };

                    match ping_client.measure_delay().await {
                        Ok(result) => {
                            info!(
                                "brust observation: ok ping {} with {} : {:?}",
                                destination, tag_clone, result
                            );

                            self_clone.put_result(tag_clone, Some(result)).await;
                        }

                        Err(error) => {
                            if !self_clone.check_connectivity(context_clone.clone()).await {
                                info!("brust observation: network is down");

                                return;
                            }

                            info!(
                                "brust observation: error ping {} with {} : {}",
                                destination, tag_clone, error
                            );

                            self_clone.put_result(tag_clone, None).await;
                        }
                    }
                });
            }
        }

        while tasks.join_next().await.is_some() {}
    }

    async fn start_request_check(self: &Arc<Self>, context: Arc<Context>) {
        let candidates = context.select_outbounds(&self.selector).await;

        self.cleanup(candidates.clone()).await;

        let mut current = self.request_check_task_all.lock().await;

        if let Some(handle) = current.take() {
            handle.abort();
        }

        let this = self.clone();

        let handle = tokio::spawn(async move {
            this.do_check(context, candidates, Duration::ZERO, 1).await;
        });

        *current = Some(handle);
    }

    async fn check_connectivity(self: &Arc<Self>, context: Arc<Context>) -> bool {
        let connectivity = match &self.connectivity {
            Some(connectivity) => connectivity.clone(),
            None => return true,
        };

        let ping = PingClient::new_direct(context, connectivity, Some(self.timeout));

        ping.is_ok()
    }

    async fn put_result(self: &Arc<Self>, tag: String, ping: Option<Duration>) {
        let mut results = self.results.write().await;

        let item = results.entry(tag).or_insert_with(|| {
            let validity = self.interval * self.sampling_count as u32 * 2;

            HealthPingRTTS::new(self.sampling_count, validity)
        });

        item.put(ping);
    }

    async fn cleanup(self: &Arc<Self>, tags: Vec<String>) {
        let tags: HashSet<String> = tags.into_iter().collect();

        let mut results = self.results.write().await;

        results.retain(|tag, _| tags.contains(tag));
    }

    pub async fn start_run(self: &Arc<Self>, context: Arc<Context>) {
        let interval = self.interval * self.sampling_count as u32;

        let s_clone = self.clone();
        let context_clone = context.clone();

        tokio::spawn(async move {
            loop {
                s_clone.start_request_check(context_clone.clone()).await;
                s_clone.check_trigger.notified().await;
            }
        });

        loop {
            let candidates = context.select_outbounds(&self.selector).await;

            self.cleanup(candidates.clone()).await;

            let mut current = self.request_check_task_interval.lock().await;

            let self_clone = self.clone();
            let context_clone = context.clone();
            {
                if let Some(handle) = current.take() {
                    handle.abort();
                }
                let handle = tokio::spawn(async move {
                    self_clone
                        .do_check(
                            context_clone,
                            candidates,
                            interval,
                            self_clone.sampling_count,
                        )
                        .await;
                });
                *current = Some(handle);
            }
            let one = self.check_trigger.notified();
            let two = sleep(interval);
            if self.request_check_all {
                tokio::select! {
                    _ = one => {},
                    _ = two => {},
                }
            } else {
                two.await;
            }
        }
    }
}

// ================================================================
// OBSERVABLE
// ================================================================

#[async_trait]
impl Observable for Arc<BrustObservation> {
    async fn start(&self, context: Arc<Context>) -> Result<(), Error> {
        self.start_run(context).await;

        Ok(())
    }

    async fn get_stats(&self) -> Option<HashMap<String, ObserveStats>> {
        let mut ret: HashMap<String, ObserveStats> = HashMap::new();

        let results = self.results.read().await;

        for (tag, result) in results.iter() {
            ret.insert(tag.clone(), result.into());
        }

        Some(ret)
    }

    fn request_check(&self) {
        self.check_trigger.notify_waiters();
    }
}
