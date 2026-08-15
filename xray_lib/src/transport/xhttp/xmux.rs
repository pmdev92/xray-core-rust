use crate::common::serde::uint_range::UIntRange;
use crate::transport::xhttp::config::XmuxConfig;
use crate::transport::xhttp::http_unify::HttpUnify;
use lazy_static::lazy_static;
use rand::Rng;
use std::io::Error;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

lazy_static! {
    static ref DEFAULT_MAX_CONCURRENCY: UIntRange = UIntRange::new(16, Some(32));
    static ref DEFAULT_H_MAX_REQUEST_TIMES: UIntRange = UIntRange::new(600, Some(900));
    static ref DEFAULT_H_MAX_REUSABLE_SECS: UIntRange = UIntRange::new(1800, Some(3000));
}

pub(crate) struct XmuxClientOpenUsage {
    counter: Arc<AtomicU32>,
}

impl XmuxClientOpenUsage {
    pub fn new(counter: Arc<AtomicU32>) -> Self {
        XmuxClientOpenUsage { counter }
    }
}

impl Drop for XmuxClientOpenUsage {
    fn drop(&mut self) {
        if self.counter.load(Ordering::Relaxed) > 0 {
            self.counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

pub struct XmuxClient {
    pub conn: Box<dyn HttpUnify>,
    pub usage: AtomicI32,
    pub open_usage: Arc<AtomicU32>,
    pub left_usage: Option<AtomicI32>,
    pub left_requests: AtomicI32,
    pub unreusable_at: Option<Instant>,
}

impl XmuxClient {
    pub fn is_usable(&self) -> bool {
        if self.conn.is_closed_unify() { return false; }
        if let Some(left_usage) = self.left_usage.as_ref() {
            if left_usage.load(Ordering::Relaxed) <= 0 { return false; }
        }
        if self.left_requests.load(Ordering::Relaxed) <= 0 { return false; }
        if let Some(at) = self.unreusable_at {
            if Instant::now() > at { return false; }
        }
        true
    }
}

#[derive(Clone)]
pub struct XmuxSettings {
    pub max_concurrency: i32,
    pub max_connections: i32,
    pub c_max_reuse_times: i32,
    pub h_max_request_times: i32,
    pub h_max_reusable_secs: i32,
}

impl XmuxSettings {
    pub fn from_config(c: &XmuxConfig) -> Self {
        Self {
            max_concurrency: c.max_concurrency.as_ref()
                .map(|r| r.random() as i32)
                .unwrap_or(DEFAULT_MAX_CONCURRENCY.random() as i32),
            max_connections: c.max_connections.as_ref()
                .map(|r| r.random() as i32)
                .unwrap_or(0),
            c_max_reuse_times: c.c_max_reuse_times.as_ref()
                .map(|r| r.random() as i32)
                .unwrap_or(-1),
            h_max_request_times: c.h_max_request_times.as_ref()
                .map(|r| r.random() as i32)
                .unwrap_or(DEFAULT_H_MAX_REUSABLE_SECS.random() as i32),
            h_max_reusable_secs: c.h_max_reusable_secs.as_ref()
                .map(|r| r.random() as i32)
                .unwrap_or(DEFAULT_H_MAX_REUSABLE_SECS.random() as i32),
        }
    }
}

impl Default for XmuxSettings {
    fn default() -> Self {
        Self {
            max_concurrency: DEFAULT_MAX_CONCURRENCY.random() as i32,
            max_connections: 0,
            c_max_reuse_times: -1,
            h_max_request_times: DEFAULT_H_MAX_REQUEST_TIMES.random() as i32,
            h_max_reusable_secs: DEFAULT_H_MAX_REUSABLE_SECS.random() as i32,
        }
    }
}

pub struct XmuxConnection {
    pub open_usage_counter: XmuxClientOpenUsage,
    pub sender: Box<dyn HttpUnify>,
}

pub struct XmuxManager {
    clients: Vec<Arc<XmuxClient>>,
    config: XmuxSettings,
}

impl XmuxManager {
    pub fn new(config: &XmuxSettings) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            clients: Vec::new(),
            config: config.clone(),
        }))
    }

    pub async fn get_or_create<F, Fut>(&mut self, create_conn: F) -> Result<XmuxConnection, Error>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Box<dyn HttpUnify>, Error>>,
    {
        let client = if let Some(client) = self.get_available_client() {
            client
        } else {
            let conn = create_conn().await?;
            if !conn.can_clone() {
                return Ok(XmuxConnection {
                    open_usage_counter: XmuxClientOpenUsage::new(Arc::new(AtomicU32::new(1))),
                    sender: conn,
                });
            }
            self.register_connection(conn)
        };

        client.usage.fetch_add(1, Ordering::Relaxed);
        client.open_usage.fetch_add(1, Ordering::Relaxed);
        client.left_requests.fetch_sub(1, Ordering::Relaxed);
        if let Some(left_usage) = client.left_usage.as_ref() {
            let current = left_usage.load(Ordering::Relaxed);
            if current > 0 {
                left_usage.fetch_sub(1, Ordering::Relaxed);
            }
        }

        Ok(XmuxConnection {
            open_usage_counter: XmuxClientOpenUsage::new(client.open_usage.clone()),
            sender: client.conn.clone_unify()?,
        })
    }

    fn register_connection(&mut self, conn: Box<dyn HttpUnify>) -> Arc<XmuxClient> {
        let left_usage = if self.config.c_max_reuse_times > 0 {
            Some(AtomicI32::new(self.config.c_max_reuse_times - 1))
        } else {
            None
        };
        let left_requests = if self.config.h_max_request_times > 0 {
            self.config.h_max_request_times
        } else {
            DEFAULT_H_MAX_REQUEST_TIMES.random() as i32
        };
        let unreusable_at = if self.config.h_max_reusable_secs > 0 {
            Some(Instant::now() + Duration::from_secs(self.config.h_max_reusable_secs as u64))
        } else {
            None
        };
        let client = Arc::new(XmuxClient {
            conn,
            usage: AtomicI32::new(0),
            open_usage: Arc::new(AtomicU32::new(0)),
            left_usage,
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
        });
        self.clients.push(client.clone());
        client
    }

    fn get_available_client(&mut self) -> Option<Arc<XmuxClient>> {
        self.clients.retain(|c| c.is_usable());
        if self.clients.is_empty() { return None; }
        if self.config.max_connections > 0
            && (self.clients.len() as i32) < self.config.max_connections
        {
            return None;
        }
        let available: Vec<&Arc<XmuxClient>> = if self.config.max_concurrency > 0 {
            self.clients.iter()
                .filter(|c| c.open_usage.load(Ordering::Relaxed) < self.config.max_concurrency as u32)
                .collect()
        } else {
            self.clients.iter().collect()
        };
        if available.is_empty() { return None; }
        let idx = rand::thread_rng().gen_range(0..available.len());
        Some(available[idx].clone())
    }
}
