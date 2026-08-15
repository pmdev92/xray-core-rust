use jni::JavaVM;
use std::{env, thread};

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
        Some(_) => {}
    }
}

pub fn init_asset_path(path: String) {
    env::set_var("XRAY_ASSET_LOCATION", path)
}
pub fn start_xray_core(id: u32, config: String, protector: Box<dyn ProtectFd>) {
    let android_context = AndroidContext { protector };
    thread::spawn(move || {
        xray_lib::start(id, config, Box::new(android_context));
    });
}

pub fn shutdown_xray_core(id: u32) {
    let _ = xray_lib::shutdown(id);
}

pub trait ProtectFd: Send + Sync {
    fn protect(&self, id: u64) -> bool;
}
struct AndroidContext {
    protector: Box<dyn ProtectFd>,
}

impl xray_lib::AndroidContext for AndroidContext {
    fn protect_fd(&self, id: u64) {
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
                    Err(_) => {}
                }
            }
        }
    }
}
