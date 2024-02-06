#[macro_use]
mod bencode;

use std::{env, fs, path, process::Command, sync::Arc, thread::sleep, time::Duration};

use crawler::Config;
use log::error;
use pecker::Pecker;

mod blacklist;
mod crawler;
mod dht;
mod error;
mod limit;
mod meta;
mod node;
mod torrent;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut config_path = "/etc/crawler/crawler.toml".to_string();
    let mut log_path = "/var/log/crawler/".to_string();
    let mut s = String::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].eq("-c") && i + 1 < args.len() - 1 {
            config_path = args[i + 1].clone();
        } else if args[i].eq("-l") && i + 1 < args.len() - 1 {
            log_path = args[i + 1].clone();
        } else if args[i].eq("-s") && i + 1 < args.len() - 1 {
            s = args[i + 1].clone();
        }
        i += 1;
    }

    if s.as_str() == "quit" {
        let _ = Command::new("sh")
            .arg("-c")
            .arg("killall dht-crawler")
            .output()
            .expect("failed to execute process");
        sleep(Duration::from_secs(5));
        return;
    }

    let mut config_path = path::Path::new(config_path.as_str());
    if !config_path.exists() {
        config_path = path::Path::new("conf/crawler.toml");
    }

    if !config_path.exists() {
        panic!("config file {:?} is not exist.", config_path);
    }

    // 1、init logger
    Pecker::default().init(log_path.as_str());

    // 2、load local config file
    let content = fs::read_to_string(config_path).unwrap();
    let config: Config = toml::from_str(&content).unwrap();
    let config = Arc::new(config);

    // dht bootstrap nodes
    let bootstrap_nodes: Vec<String> = [
        "router.bittorrent.com:6881".to_string(),
        "dht.transmissionbt.com:6881".to_string(),
        "router.utorrent.com:6881".to_string(),
    ]
    .to_vec();

    if let Err(e) = crawler::run(config, bootstrap_nodes) {
        error!("run crawler error. {:?}", e);
    }
}
