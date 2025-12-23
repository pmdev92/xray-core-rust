use crate::logger::console::ConsoleLogger;

mod console;
mod crash;

pub enum LoggerType {
    SIMPLE,
    VERBOSE,
}

pub fn init(logger_type: LoggerType) {
    let logger = match logger_type {
        LoggerType::VERBOSE => ConsoleLogger::new_all(),
        LoggerType::SIMPLE => {
            ConsoleLogger::new_with(vec!["xray_bin".to_string(), "xray_lib".to_string()])
        }
    };
    if let Err(err) = log::set_boxed_logger(Box::new(logger)) {
        println!("set logger error: {err}");
    } else {
        crash::init();
    }
}
