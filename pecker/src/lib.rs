use std::sync::Arc;

use log::Level;
use serde::Serialize;

use self::loggers::get_loggers;

mod loggers;

static LOG_FACTORY: loggers::LoggerFactory = loggers::LoggerFactory {};

#[derive(Clone, Eq, Debug, Serialize)]
pub struct LoggerConfig {
    pub log_dir: String,
    pub name: String,
    pub level: String,
    pub file: String,
    pub policy: TriggeringPolicy,
}

impl PartialEq for LoggerConfig {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl std::hash::Hash for LoggerConfig {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl LoggerConfig {}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub enum TriggeringPolicy {
    Hour,
    Day,
}

impl From<String> for TriggeringPolicy {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "hour" => TriggeringPolicy::Hour,
            _ => TriggeringPolicy::Day,
        }
    }
}

#[derive(Default)]
pub struct Pecker {}

impl log::Log for Pecker {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let log_str = format!("{}", record.args());
        match record.level() {
            Level::Error => {
                if let Some(logger) = get_loggers().get("error") {
                    logger.flush(log_str, record.level(), record.target());
                }
            }
            _ => {
                if let Some(logger) = get_loggers().get(record.target()) {
                    logger.flush(log_str, record.level(), record.target());
                }
            }
        }
    }

    fn flush(&self) {}
}
impl Pecker {
    ///
    ///
    ///
    pub fn init(self, log_dir: &str) {
        let mut log_path = std::path::Path::new(log_dir);
        if !log_path.exists() {
            log_path = std::path::Path::new("logs");
            if !log_path.exists() {
                let _ = std::fs::create_dir_all(log_path);
            }
        }

        if !log_path.exists() {
            println!("log dir {:?} is not exist.", log_path);
        }

        let log_dir = log_path.to_path_buf().as_path().display().to_string();
        let configs = vec![
            LoggerConfig {
                log_dir: log_dir.clone(),
                name: "default".to_string(),
                level: "info".to_string(),
                file: "default.log".to_string(),
                policy: TriggeringPolicy::Hour,
            },
            LoggerConfig {
                log_dir: log_dir.clone(),
                name: "crawler".to_string(),
                level: "info".to_string(),
                file: "crawler.log".to_string(),
                policy: TriggeringPolicy::Hour,
            },
            LoggerConfig {
                log_dir: log_dir.clone(),
                name: "dht".to_string(),
                level: "info".to_string(),
                file: "dht.log".to_string(),
                policy: TriggeringPolicy::Hour,
            },
            LoggerConfig {
                log_dir: log_dir.clone(),
                name: "error".to_string(),
                level: "error".to_string(),
                file: "error.log".to_string(),
                policy: TriggeringPolicy::Hour,
            },
        ];
        let configs = Arc::new(configs);
        LOG_FACTORY.setup_loggers(configs);

        log::set_max_level(log::LevelFilter::Trace);
        let _ = log::set_boxed_logger(Box::new(self));
    }
}

pub fn get_logger_configs() -> Vec<LoggerConfig> {
    (**loggers::get_logger_config()).clone()
}

pub fn set_level(name: &str, level: &str) {
    LOG_FACTORY.set_level(name, level)
}