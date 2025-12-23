mod logger;

use crate::logger::AndroidLogger;
use jni::JavaVM;
use std::thread;

uniffi::include_scaffolding!("xray");

static VM: once_cell::sync::OnceCell<JavaVM> = once_cell::sync::OnceCell::new();

pub fn start_xray_logger(is_all_packages: bool, logger: Box<dyn AndroidLogger>) {
    logger::start_xray_logger(is_all_packages, logger)
}

pub fn start_xray_core(id: u32, config: String, protector: Box<dyn ProtectFd>) {
    let android_platform = AndroidPlatform { protector };
    thread::spawn(move || {
        xray_lib::start(id, config, Some(Box::new(android_platform)));
    });
}

pub fn shutdown_xray_core(id: u32) {
    let _ = xray_lib::shutdown(id);
}

pub trait ProtectFd: Send + Sync {
    fn protect(&self, id: u64) -> bool;
}

struct AndroidPlatform {
    protector: Box<dyn ProtectFd>,
}

impl xray_lib::ContextPlatform for AndroidPlatform {
    fn android_protect_fd(&self, id: u64) {
        let jvm = VM.get();
        match jvm {
            None => {}
            Some(jvm) => {
                let env = jvm.attach_current_thread();
                match env {
                    Ok(_) => {
                        self.protector.protect(id);
                    }
                    Err(_) => {}
                }
            }
        }
    }

    fn can_accept(&self) -> bool {
        true
    }
}
