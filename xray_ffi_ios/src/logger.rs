use std::{
    os::raw::{c_char, c_void},
    sync::Mutex,
};

pub(crate) static LOG_CALLBACK: Mutex<Option<LogCallback>> = Mutex::new(None);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn start_xray_logger(
    is_all_packages: bool,
    callback: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    ctx: *mut c_void,
) {
    *LOG_CALLBACK.lock().unwrap() = Some(LogCallback(callback, ctx));
    let dumper = Logger {
        is_all_packages,
        packages: vec!["xray_lib".to_string()],
    };
    log::set_max_level(log::LevelFilter::Warn);
    if let Err(err) = log::set_boxed_logger(Box::new(dumper)) {
        log::debug!("set logger error: {err}");
    }
}

#[derive(Clone)]
pub struct LogCallback(
    Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    *mut c_void,
);

impl LogCallback {
    unsafe fn call(self, info: *const c_char) {
        if let Some(cb) = self.0 {
            unsafe { cb(info, self.1) };
        }
    }
}
unsafe impl Send for LogCallback {}
unsafe impl Sync for LogCallback {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Logger {
    is_all_packages: bool,
    packages: Vec<String>,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if self.is_all_packages {
            return metadata.level() <= log::Level::Trace;
        }
        let package = metadata.target();
        for enable_package in &self.packages {
            if package.starts_with(enable_package.as_str()) {
                return metadata.level() <= log::Level::Trace;
            }
        }
        false
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            self.do_dump_log(record);
        }
    }

    fn flush(&self) {}
}

impl Logger {
    fn do_dump_log(&self, record: &log::Record) {
        let timestamp: chrono::DateTime<chrono::Local> = chrono::Local::now();
        let msg = format!(
            "XRAY [{} {:<5} {}] - {}",
            timestamp.format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.module_path().unwrap_or(""),
            record.args()
        );
        let c_msg = std::ffi::CString::new(msg).unwrap();
        let ptr = c_msg.as_ptr();
        if let Some(cb) = LOG_CALLBACK.lock().unwrap().clone() {
            unsafe {
                cb.call(ptr);
            }
        }
    }
}
