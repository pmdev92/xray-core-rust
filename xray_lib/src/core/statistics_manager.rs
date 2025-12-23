use std::sync::{atomic::AtomicU64, Arc, Mutex};
use tokio::time::Instant;

pub struct StatisticsManager {
    instant: Mutex<Instant>,
    upload_total: AtomicU64,
    duration_upload: AtomicU64,
    download_total: AtomicU64,
    duration_download: AtomicU64,
}

#[derive(Debug)]
pub struct StatisticsResult {
    pub total_upload: u64,
    pub total_download: u64,
    pub duration_upload: u64,
    pub duration_download: u64,
    pub duration: u64,
}

impl StatisticsManager {
    pub fn new() -> Arc<Self> {
        let manager = Arc::new(Self {
            instant: Mutex::new(Instant::now()),
            upload_total: AtomicU64::new(0),
            duration_upload: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            duration_download: AtomicU64::new(0),
        });
        manager
    }

    pub fn get_statistics(&self) -> Option<StatisticsResult> {
        let total_upload = self.upload_total.load(std::sync::atomic::Ordering::Relaxed);
        let total_download = self
            .download_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let duration_upload = self
            .duration_upload
            .load(std::sync::atomic::Ordering::Relaxed);
        let duration_download = self
            .duration_download
            .load(std::sync::atomic::Ordering::Relaxed);

        self.duration_upload
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.duration_download
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let mutex = self.instant.lock();
        let mut duration = 0;

        match mutex {
            Ok(mut mutex) => {
                duration = mutex.elapsed().as_millis() as u64;
                *mutex = Instant::now();
            }
            Err(_) => return None,
        }
        Some(StatisticsResult {
            total_upload,
            total_download,
            duration_upload,
            duration_download,
            duration,
        })
    }
    pub fn push_uploaded(&self, n: usize) {
        self.upload_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.duration_upload
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn push_downloaded(&self, n: usize) {
        self.download_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.duration_download
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }
}
