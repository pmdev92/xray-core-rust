use crate::common::duration::parse_duration;
use crate::core::context::Context;
use crate::core::observatory::Observable;
use crate::core::observatory::normal::config::NormalObservationConfig;
use crate::core::observatory::ping_client::PingClient;
use crate::core::observatory::stats::ObserveStats;
use async_trait::async_trait;
use log::{info, trace};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::io::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;

pub mod config;

pub struct NormalObservation {
    selector: Vec<String>,
    destination: String,
    interval: Duration,
    enable_concurrency: bool,
    results: RwLock<HashMap<String, PingResult>>,
    check_trigger: Notify,
    request_check_task: Mutex<Option<JoinHandle<()>>>,
}
impl NormalObservation {
    pub fn new(config: NormalObservationConfig, selector: Vec<String>) -> Result<Self, Error> {
        let destination = config
            .destination
            .unwrap_or("https://api.v2fly.org/checkConnection.svgz".to_string());
        let interval = config.interval.as_deref().unwrap_or("10s");
        let interval = parse_duration(interval)?;
        let enable_concurrency = config.enable_concurrency.unwrap_or(false);

        Ok(Self {
            selector,
            destination,
            interval,
            enable_concurrency,
            results: Default::default(),
            check_trigger: Notify::new(),
            request_check_task: Mutex::new(None),
        })
    }
    async fn do_check(
        self: &Arc<Self>,
        context: Arc<Context>,
        tags: Vec<String>,
        enable_concurrency: bool,
    ) {
        info!(
            "normal Observation: check tags: {:?} enable_concurrency {}",
            tags, enable_concurrency
        );
        if enable_concurrency {
            let mut current = self.request_check_task.lock().await;
            if let Some(handle) = current.take() {
                handle.abort();
            }
            let s1 = self.clone();
            let c1 = context.clone();
            let handle = tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                for tag in tags {
                    let s = s1.clone();
                    let c = c1.clone();
                    tasks.spawn(async move {
                        s.check(c, tag).await;
                    });
                }
                while tasks.join_next().await.is_some() {}
            });
            *current = Some(handle);
        } else {
            let mut tags = tags.iter().peekable();
            while let Some(tag) = tags.next() {
                self.check(context.clone(), tag.clone()).await;
                if tags.peek().is_some() {
                    self.wait().await;
                }
            }
        }
    }

    async fn put_result(
        self: &Arc<Self>,
        tag: String,
        ping: Option<Duration>,
        error: Option<String>,
    ) {
        let mut results = self.results.write().await;
        let item = results.entry(tag).or_insert_with(|| PingResult::new());
        let time = Instant::now();
        item.last_try_time = time.clone();
        item.alive = ping.is_some();
        if let Some(ping) = ping {
            item.delay = Some(ping);
            item.last_error_reason = None;
            item.last_alive_time = time.clone();
        }
        if let Some(error) = error {
            item.delay = None;
            item.last_error_reason = Some(error);
        }
    }
    async fn cleanup(self: &Arc<Self>, tags: Vec<String>) {
        let tags: HashSet<String> = tags.into_iter().collect();
        let mut results = self.results.write().await;
        results.retain(|tag, _| tags.contains(tag));
    }

    async fn check(self: &Arc<Self>, context: Arc<Context>, tag: String) {
        info!("normal observation: check tag {}", tag);
        let ping_client = PingClient::new_tagged(
            context,
            tag.clone(),
            self.destination.clone(),
            Some(Duration::from_secs(5)),
        );
        let error = match ping_client {
            Err(error) => error,
            Ok(ping_client) => {
                let result = ping_client.measure_delay().await;
                match result {
                    Ok(result) => {
                        info!(
                            "normal observation: ok ping {} with {} : {:?}",
                            self.destination, tag, result
                        );
                        self.put_result(tag, Some(result), None).await;
                        return;
                    }
                    Err(error) => error,
                }
            }
        };
        info!(
            "normal observation: error ping {} with {} : {}",
            self.destination.clone(),
            tag,
            error
        );
        self.put_result(tag, None, Some(error.to_string())).await;
    }

    pub async fn start_run(self: &Arc<Self>, context: Arc<Context>) {
        loop {
            let context_clone = context.clone();
            let candidates = context_clone.select_outbounds(&self.selector).await;
            self.cleanup(candidates.clone()).await;
            self.do_check(context_clone, candidates, self.enable_concurrency.clone())
                .await;
            self.wait().await;
        }
    }

    async fn wait(&self) {
        tokio::select! {
            _ = sleep(self.interval) => {}
            _ = self.check_trigger.notified() => {}
        }
    }
}
#[async_trait]
impl Observable for Arc<NormalObservation> {
    async fn start(&self, context: Arc<Context>) -> Result<(), Error> {
        self.start_run(context).await;
        Ok(())
    }

    async fn get_stats(&self) -> Option<HashMap<String, ObserveStats>> {
        let mut ret: HashMap<String, ObserveStats> = HashMap::new();
        let mut results = self.results.read().await;
        for result in results.iter() {
            ret.insert(result.0.clone(), result.1.into());
        }
        Some(ret)
    }

    fn request_check(&self) {
        self.check_trigger.notify_one();
    }
}

#[derive(Debug)]
pub(super) struct PingResult {
    alive: bool,
    delay: Option<Duration>,
    last_try_time: Instant,
    last_alive_time: Instant,
    last_error_reason: Option<String>,
}

impl PingResult {
    pub fn new() -> Self {
        Self {
            alive: false,
            delay: Default::default(),
            last_try_time: Instant::now(),
            last_alive_time: Instant::now(),
            last_error_reason: None,
        }
    }
}

impl Into<ObserveStats> for &PingResult {
    fn into(self) -> ObserveStats {
        ObserveStats {
            alive: self.alive,
            delay: self.delay,
            last_try_time: self.last_try_time,
            last_alive_time: self.last_alive_time,
            last_error_reason: self.last_error_reason.clone(),
            health: None,
        }
    }
}
