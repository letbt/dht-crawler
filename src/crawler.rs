use std::{net::SocketAddr, sync::Arc, time::Duration};

use bloomfilter::Bloom;
use log::{error, info};
use serde::{Deserialize, Serialize};
use tokio::{
    net::UdpSocket,
    sync::{mpsc::Receiver, Mutex},
};
use ureq::Agent;

use crate::{
    blacklist::BlackList, dht::{Dht, Message}, limit::LimitRate, meta::MetaWire, node::NodeId, torrent
};

#[tokio::main]
pub async fn run(
    config: Arc<Config>,
    bootstrap_nodes: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut parsed_nodes = vec![];
    let mut nodes = vec![];
    nodes.extend_from_slice(&bootstrap_nodes);
    nodes.extend_from_slice(&config.bootstrap_nodes);

    for host in nodes {
        let addrs = tokio::net::lookup_host(host).await?;
        for address in addrs {
            parsed_nodes.push(address);
        }
    }

    for node in &parsed_nodes {
        info!(target:"default","bootstrap node: {:?}", node);
    }

    let local_id = NodeId::get_current_id()?;

    let port = config.port.map_or(6881, |p| p);
    let addr = ":::".to_string() + port.to_string().as_str();

    info!(target:"default", "Crawler is running, current node id: {}, listen on: {}", local_id, &addr);

    let socket = Arc::new(UdpSocket::bind(addr.as_str()).await?);

    let crawler = Crawler::new(config, local_id, socket, parsed_nodes);
    
    crawler.run().await
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    blacklist: Option<usize>,
    port: Option<u16>,
    url: String,
    bootstrap_nodes: Vec<String>,
    limit: Option<usize>,
}

impl Config {
    pub fn get_limit(&self) -> usize {
        self.limit.map_or(10, |l| l)
    }
}

struct Crawler {
    config: Arc<Config>,
    dht: Arc<Dht>,
    receiver: Arc<Mutex<Receiver<Message>>>,
}

impl Crawler {
    fn new(
        config: Arc<Config>,
        local_id: NodeId,
        socket: Arc<UdpSocket>,
        bootstrap_nodes: Vec<SocketAddr>,
    ) -> Self {
        let limit = Arc::new(LimitRate::new(config.get_limit()));
        let (sender, receiver) = tokio::sync::mpsc::channel(4096);
        Crawler {
            config,
            dht: Arc::new(Dht::new(
                limit,
                local_id,
                bootstrap_nodes,
                socket,
                Arc::new(sender),
            )),
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    ///
    ///
    ///
    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let dht = self.dht.clone();
        tokio::spawn(async move {
            dht.auto_join().await;
        });

        let dht = self.dht.clone();
        tokio::spawn(async move {
            let _r = dht.process_response().await;
        });

        let mut blacklist = BlackList::new(self.config.blacklist.map_or(1024, |b| b));
        let mut bloom = Bloom::<Vec<u8>>::new_for_fp_rate(10000000, 0.0001);

        let agent: Agent = ureq::AgentBuilder::new()
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .build();

        loop {
            if let Some(message) = self.receiver.lock().await.recv().await {
                let peer = message.get_peer().clone();
                if blacklist.contains(&peer).await {
                    continue;
                }

                if bloom.check(message.get_info_hash()) {
                    continue;
                }

                let info_hash = message.get_info_hash().clone();
                let mut meta = MetaWire::new(message, 15);
                let r = meta.fetch().await;
                if let Ok(data) = r {
                    let r = torrent::from_bytes(&info_hash, &data);
                    if let Ok(torrent) = r {
                        info!(target: "crawler", "{:#?}", serde_json::to_string(&torrent));

                        if self.config.url.is_empty() {
                            continue;
                        }

                        let r = agent.post(&self.config.url).send_json(torrent);
                        if r.is_err() {
                            error!("post data error: {}, {:?}",hex::encode(&info_hash), r.err());
                        } else {
                            bloom.set(&info_hash);
                        }
                    } else {
                        error!("parse torrent file error. {:?}", r.err());
                    }
                } else {
                    error!("feath meta {:?} error. {:?}", hex::encode(&info_hash), r.err());
                    blacklist.insert(peer).await;
                }
            }
        }
    }
}
