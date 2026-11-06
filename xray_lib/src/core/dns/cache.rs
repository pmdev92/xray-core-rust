use hickory_proto::rr::RecordType;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub data: Vec<String>,
    pub ttl: u32,
    pub created_at: u64,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now - self.created_at) > self.ttl as u64
    }
}

pub struct DnsCache {
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: u32,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(ttl: u32, max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            max_entries,
        }
    }

    pub async fn get(&self, key: &str) -> Option<Vec<String>> {
        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(key) {
            if !entry.is_expired() {
                return Some(entry.data.clone());
            }
        }
        None
    }

    pub async fn set(&self, key: String, data: Vec<String>) {
        let mut entries = self.entries.write().await;

        if entries.len() >= self.max_entries {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(
            key,
            CacheEntry {
                data,
                ttl: self.ttl,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        );
    }

    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }

    pub async fn cleanup_expired(&self) {
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| !entry.is_expired());
    }
}
