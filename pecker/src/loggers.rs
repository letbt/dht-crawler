use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};

use chrono::{Datelike, Timelike};
use lazy_static::lazy_static;
use parking_lot::Mutex;

use super::{Level, LoggerConfig, TriggeringPolicy};

pub(crate) struct DateBasedState {
    current_file_path: PathBuf,
    current_file_modified_time: Option<SystemTime>,
    file_stream: Option<BufWriter<fs::File>>,
}

impl DateBasedState {
    ///
    ///
    ///
    fn new(current_file_path: PathBuf, file_stream: Option<fs::File>) -> Self {
        let mut current_file_modified_time = None;
        if let Ok(metadata) = fs::metadata(&current_file_path) {
            if let Ok(modified) = metadata.modified() {
                current_file_modified_time = Some(modified);
            }
        }

        DateBasedState {
            current_file_path,
            current_file_modified_time,
            file_stream: file_stream.map(BufWriter::new),
        }
    }

    ///
    ///
    ///
    fn replace_file(&mut self, new_file: Option<fs::File>) {
        if let Some(mut old) = self.file_stream.take() {
            let _ = old.flush();
        }
        self.file_stream = new_file.map(BufWriter::new);
    }
}

#[derive(Clone)]
pub(crate) struct Logger {
    config: LoggerConfig,
    state: Arc<Mutex<DateBasedState>>,
    level: Level,
}

lazy_static! {
    static ref LOGGERS: arc_swap::ArcSwap<BTreeMap<String, Logger>> =
        arc_swap::ArcSwap::from(Arc::new(BTreeMap::new()));
    static ref LOG_CONFIGS: arc_swap::ArcSwap<Vec<LoggerConfig>> =
        arc_swap::ArcSwap::from(Arc::new(vec![]));
}

///
///
///
pub(crate) fn get_loggers() -> arc_swap::Guard<Arc<BTreeMap<String, Logger>>> {
    LOGGERS.load()
}

///
///
///
pub(crate) fn get_logger_config() -> arc_swap::Guard<Arc<Vec<LoggerConfig>>> {
    LOG_CONFIGS.load()
}

impl Logger {
    ///
    ///
    ///
    fn new(config: LoggerConfig) -> Self {
        let current_file_path = compute_file_path(&config.file, &config);
        let file_stream = open_log_file(&current_file_path).ok();
        let level = config.level.clone();
        Logger {
            config,
            state: Arc::new(Mutex::new(DateBasedState::new(
                current_file_path,
                file_stream,
            ))),
            level: Level::from_str(&level).unwrap_or(Level::Info),
        }
    }

    ///
    ///
    ///
    fn renew_check(&self, state: &DateBasedState) -> bool {
        if let Some(modified) = state.current_file_modified_time {
            let modified = chrono::DateTime::<chrono::Local>::from(modified);
            let now = chrono::Local::now();
            let pattern = match self.config.policy {
                TriggeringPolicy::Hour => {
                    if modified.hour() == now.hour() {
                        return false;
                    }
                    let dt = now.checked_sub_signed(chrono::Duration::hours(1)).unwrap();
                    dt.format(".%Y-%m-%d_%H").to_string()
                }
                TriggeringPolicy::Day => {
                    if modified.day0() == now.day0() {
                        return false;
                    }
                    let dt = now.checked_sub_signed(chrono::Duration::hours(1)).unwrap();
                    dt.format(".%Y-%m-%d").to_string()
                }
            };

            let old_file_name = self.config.file.clone() + pattern.as_str();
            let old_file_path = compute_file_path(&old_file_name, &self.config);

            let mut renew = false;
            if state.current_file_path.exists() && !old_file_path.exists() {
                let _ = fs::rename(state.current_file_path.clone(), old_file_path);
                renew = true;

                if let Ok(dir) = fs::read_dir(&self.config.log_dir) {
                    let path = compute_file_path(&self.config.file, &self.config);
                    let mut files = vec![];

                    for file in dir.flatten() {
                        let p = file.path();
                        if p.to_string_lossy().starts_with(&*path.to_string_lossy()) {
                            files.push(file);
                        }
                    }

                    files.sort_by(|a, b| {
                        let mut order = std::cmp::Ordering::Less;
                        if let Ok(m_a) = a.metadata() {
                            if let Ok(m_b) = b.metadata() {
                                let _ = m_a.modified().map(|m_a| {
                                    let _ = m_b.modified().map(|m_b| {
                                        order = m_a.cmp(&m_b);
                                    });
                                });
                            }
                        }
                        order
                    });

                    if files.len() > 7 {
                        let j = files.len() - 7;
                        for item in files.iter().take(j) {
                            let _ = fs::remove_file(item.path());
                        }
                    }
                }
            }
            renew
        } else {
            true
        }
    }

    pub(crate) fn flush(&self, log_str: String, level: Level, target: &str) {
        if level > self.level {
            return;
        }

        let mut state = self.state.lock();
        if state.file_stream.is_none() || self.renew_check(&*state) {
            let current_file_path = &state.current_file_path;
            let r = open_log_file(current_file_path);
            match r {
                Ok(file) => {
                    if let Ok(metadata) = file.metadata() {
                        if let Ok(modified) = metadata.modified() {
                            state.current_file_modified_time = Some(modified);
                        }
                    }
                    state.replace_file(Some(file));
                }
                Err(_) => {
                    state.replace_file(None);
                    return;
                }
            }
        }

        let writer = state.file_stream.as_mut().unwrap();
        let _ = writeln!(
            writer,
            "{}|{:<5}|,{},{}",
            chrono::Local::now().format("[%Y-%m-%d %H:%M:%S%.3f]"),
            level.as_str(),
            target,
            log_str
        );
        let _ = writer.flush();
    }
}

pub(crate) struct LoggerFactory {}

impl LoggerFactory {
    ///
    ///
    ///
    pub fn setup_loggers(&self, configs: Arc<Vec<LoggerConfig>>) {
        let mut loggers = BTreeMap::new();
        for config in &*configs {
            let logger = Logger::new(config.clone());
            loggers.insert(config.name.clone(), logger);
        }
        LOG_CONFIGS.store(configs);
        LOGGERS.store(Arc::new(loggers));
    }

    ///
    ///
    ///
    pub fn set_level(&self, name: &str, level: &str) {
        let mut configs = Vec::new();
        let old_configs = &**get_logger_config();
        configs.extend(old_configs.clone());

        if let Some(logger) = get_loggers().get(name) {
            let mut loggers = BTreeMap::new();
            let old_loggers = &**get_loggers();
            loggers.extend(old_loggers.clone());
            let mut logger = logger.clone();
            logger.config.level = level.to_string();
            logger.level = Level::from_str(level).unwrap_or(Level::Info);
            loggers.insert(name.to_string(), logger);

            for config in &mut configs {
                if name.eq(&config.name) {
                    config.level = level.to_string();
                    break;
                }
            }

            LOG_CONFIGS.store(Arc::new(configs));
            LOGGERS.store(Arc::new(loggers));
        }
    }
}

///
///
///
fn compute_file_path(file: &str, config: &LoggerConfig) -> PathBuf {
    let mut path = OsString::from(&config.log_dir);
    path.push(std::path::MAIN_SEPARATOR.to_string());
    path.push(file);
    path.into()
}

///
///
///
fn open_log_file(path: &Path) -> io::Result<fs::File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(path)
}
