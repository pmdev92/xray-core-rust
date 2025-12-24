mod logger;

use crate::logger::AndroidLogger;
use jni::JavaVM;
use std::thread;

uniffi::include_scaffolding!("xray");


static VM: once_cell::sync::OnceCell<JavaVM> = once_cell::sync::OnceCell::new();

#[unsafe(export_name = "Java_com_xray_core_rust_InitCore_initXrayRustCore")]
pub extern "system" fn init_xray_rust_core(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    _app: jni::objects::JObject,
) {
    let jvm = VM.get();
    match jvm {
        None => {
            let vm = env.get_java_vm().unwrap();
            _ = VM.set(vm);
        }
        Some(_) => {
        }
    }
}


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
            None => {
                self.protector.protect(id);
            }
            Some(jvm) => {
                let env = jvm.attach_current_thread();

                match env {
                    Ok(_) => {
                        self.protector.protect(id);
                    }
                    Err(_) => {
                    }
                }
            }
        }
    }

    fn can_accept(&self) -> bool {
        true
    }
}
