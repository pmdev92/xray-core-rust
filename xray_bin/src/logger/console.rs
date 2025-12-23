use chrono::Local;
use colored::Colorize;
use log::{Level, Metadata, Record};

pub struct ConsoleLogger {
    is_all_packages: bool,
    packages: Vec<String>,
}

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if self.is_all_packages {
            return true;
        }
        let package = metadata.target();
        for enable_package in &self.packages {
            if package.starts_with(enable_package.as_str()) {
                return true;
            }
        }
        false
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let tag = record.metadata().target();
            let date = Local::now();
            let time = date.format("%Y-%m-%d %H:%M:%S");
            let mut level = record.level().to_string();
            if level.len() < 5 {
                let spaces = " ".to_string().repeat(5 - level.len());
                level = level + &spaces;
            }
            let log = format!("[{}] [{}] [{}] {} ", time, level, tag, record.args());
            match record.level() {
                Level::Error => {
                    println!("{}", log.bright_red());
                }
                Level::Warn => {
                    println!("{}", log.bright_yellow());
                }
                Level::Info => {
                    println!("{}", log.bright_blue());
                }
                Level::Debug => {
                    println!("{}", log.bright_cyan());
                }
                Level::Trace => {
                    println!("{}", log.bright_white());
                }
            }
        }
    }
    fn flush(&self) {}
}

impl ConsoleLogger {
    pub fn new_all() -> Self {
        Self {
            is_all_packages: true,
            packages: vec![],
        }
    }
    pub fn new_with(packages: Vec<String>) -> Self {
        Self {
            is_all_packages: false,
            packages,
        }
    }
}
