use std::sync::{Arc, Mutex};

pub(crate) static LOG_CALLBACK: Mutex<Option<LogCallback>> = Mutex::new(None);

pub fn start_xray_logger(is_all_packages: bool, logger: Box<dyn AndroidLogger>) {
    *LOG_CALLBACK.lock().unwrap() = Some(LogCallback {
        logger: Arc::new(logger),
    });
    let dumper = Logger {
        is_all_packages,
        packages: vec!["xray_bin".to_string(), "xray_lib".to_string()],
    };
    if let Err(err) = log::set_boxed_logger(Box::new(dumper)) {
        log::debug!("set logger error: {err}");
    }
}

pub trait AndroidLogger: Send + Sync {
    fn log(&self, message: String);
}

#[derive(Clone)]
pub struct LogCallback {
    logger: Arc<Box<dyn AndroidLogger>>,
}

impl LogCallback {
    fn call(self, message: String) {
        self.logger.log(message);
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
        if let Some(cb) = LOG_CALLBACK.lock().unwrap().clone() {
            cb.call(msg);
        }
    }
}
