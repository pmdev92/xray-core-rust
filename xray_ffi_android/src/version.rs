pub fn xray_version(callback: Box<dyn Version>) {
    let version = xray_lib::version::VERSION;
    callback.version(version.to_string());
}

pub trait Version: Send + Sync {
    fn version(&self, message: String);
}
