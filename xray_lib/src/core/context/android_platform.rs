#[cfg(target_os = "android")]
pub trait AndroidContext: Send + Sync {
    fn protect_fd(&self, id: u64);
}
