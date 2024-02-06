use lru::LruCache;
use sha1::{Digest, Sha1};
use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use crate::{
    bencode::{self, Value},
    error::{Error, Result},
    limit::LimitRate,
    node::{self, Node, NodeId},
};

use log::{error, info};
use tokio::{
    net::UdpSocket,
    sync::{mpsc::Sender, Mutex},
};

///
/// See more : https://www.bittorrent.org/beps/bep_0005.html
///

// announcement message.
#[derive(Debug, Clone)]
pub struct Message {
    peer: SocketAddr,
    info_hash: Vec<u8>,
}

impl Message {
    pub fn new(peer: SocketAddr, info_hash: Vec<u8>) -> Self {
        Self { peer, info_hash }
    }

    pub fn get_peer(&self) -> &SocketAddr {
        &self.peer
    }

    pub fn get_info_hash(&self) -> &Vec<u8> {
        &self.info_hash
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.info_hash))
    }
}

trait DhtMessageBuilder: Display + Sync + Send {
    fn build(&self) -> Result<Vec<u8>>;
}

struct DhtMessageParser {
    pending: Arc<Mutex<LruCache<Vec<u8>, DhtMessageSend>>>,
    secret: Arc<Vec<u8>>,
}

///
/// ```
///  {"t":"449c", "y":"q", "q":"find_node", "a": {"id":"f386d6dd38a44e7f9ea5d01e6a4ec9bdc287d70a", "target":"474ec751b176cdaf3bd00da348b34b91927ea51c"}}
/// ```
///
struct FindNodeRequest {
    t: Vec<u8>,
    id: NodeId,
    target: NodeId,
}

impl FindNodeRequest {
    pub fn new(id: NodeId, target: NodeId) -> Self {
        Self {
            t: node::get_transaction_id(),
            id,
            target,
        }
    }
}

impl DhtMessageBuilder for FindNodeRequest {
    ///
    ///
    ///
    fn build(&self) -> Result<Vec<u8>> {
        let a = map!(
            b"id".to_vec() => Value::from(&self.id.0[..]),
            b"target".to_vec() => Value::from(&self.target.0[..])
        );
        let m = map!(
            b"t".to_vec() => Value::from(&self.t[..]),
            b"y".to_vec() => Value::from(b"q".as_ref()),
            b"q".to_vec() => Value::from(b"find_node".as_ref()),
            b"a".to_vec() => Value::from(a)
        );
        bencode::to_bytes(&Value::from(m)).map_err(crate::error::Error::from)
    }
}
impl Display for FindNodeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{\"t\":\"{}\", \"y\":\"q\", \"q\":\"find_node\", \"a\": {{\"id\":\"{}\", \"target\":\"{}\"}}}}",hex::encode(&self.t), hex::encode(&self.id.0),  hex::encode(&self.target.0))
    }
}

struct FindNodeResponse {
    t: Vec<u8>,
    id: NodeId,
    nodes: Vec<Node>,
}

impl Display for FindNodeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        for node in &self.nodes {
            s = s + &node.address.to_string();
            s += ";";
        }

        write!(f, "{{\"t\":\"{}\", \"y\":\"r\", \"r\":\"find_node\", \"a\": {{\"id\":\"{}\", \"nodes\":\"{}\"}}}}",hex::encode(&self.t), hex::encode(&self.id.0), s)
    }
}

struct GetPeersRequest {
    t: Vec<u8>,
    id: NodeId,
    info_hash: Vec<u8>,
}

impl Display for GetPeersRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{\"t\":\"{}\", \"y\":\"q\", \"q\":\"get_peers\", \"a\": {{\"id\":\"{}\", \"info_hash\":\"{}\"}}}}",hex::encode(&self.t), hex::encode(&self.id.0),  hex::encode(&self.info_hash))
    }
}

///
/// {"t":"17b9", "y":"r", "r": {"id":"867db7723c10b518518784906d285ba536c1546a", "token":"26d4cefcec4210b3bfaa86b2926a2be83ce81e9b"}}
///
struct GetPeersResponse {
    t: Vec<u8>,
    id: NodeId,
    token: Vec<u8>,
}

impl DhtMessageBuilder for GetPeersResponse {
    ///
    ///
    ///
    fn build(&self) -> Result<Vec<u8>> {
        let r = map!(
            b"id".to_vec() => Value::from(&self.id.0[..]),
            b"token".to_vec() => Value::from(&self.token[..])
        );
        let m = map!(
            b"t".to_vec() => Value::from(&self.t[..]),
            b"y".to_vec() => Value::from(b"r".as_ref()),
            b"r".to_vec() => Value::from(r)
        );
        bencode::to_bytes(&Value::from(m)).map_err(crate::error::Error::from)
    }
}

impl Display for GetPeersResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\"t\":\"{}\", \"y\":\"r\", \"r\": {{\"id\":\"{}\", \"token\":\"{}\"}}}}",
            hex::encode(&self.t),
            hex::encode(&self.id.0),
            hex::encode(&self.token)
        )
    }
}

impl GetPeersResponse {
    pub fn new(t: Vec<u8>, id: NodeId, token: Vec<u8>) -> Self {
        Self { t, id, token }
    }
}

struct AnnouncePeerRequest {
    info_hash: Vec<u8>,
    address: SocketAddr,
}

impl Display for AnnouncePeerRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "info_hash:{}, addr:{:?}",
            hex::encode(&self.info_hash),
            &self.address
        )
    }
}

struct DhtError {
    code: i64,
    message: String,
}

impl Display for DhtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\"code\":\"{}\", \"message\":\"{}\"}}",
            self.code, &self.message
        )
    }
}

enum DhtMessageRead {
    GetPeers(GetPeersRequest),
    AnnouncePeer(AnnouncePeerRequest),
    FindNode(FindNodeResponse),
    Error(DhtError),
    NotSupported(String),
}

enum DhtMessageSend {
    FindNode,
}

impl DhtMessageParser {
    ///
    ///
    ///
    pub async fn parse(&self, data: &[u8], from: &SocketAddr) -> Result<DhtMessageRead> {
        // unpack bencode.
        let c = bencode::from_bytes(&data)?;
        let m = c
            .dict()?
            .get(b"y".as_ref())
            .ok_or(Error::DictNotFound("y".to_string()))?;

        match m.string()? {
            "q" => self.on_query(&c, &from),
            "r" => self.on_reply(&c).await,
            "e" => Ok(DhtMessageRead::Error(self.on_error(&c)?)),
            _ => Err(Error::Other("skip other request packet".to_string())),
        }
    }

    fn on_query(&self, v: &Value, addr: &SocketAddr) -> Result<DhtMessageRead> {
        // do check. is exist of the "t" field?
        v.dict()?
            .get(b"t".as_ref())
            .ok_or(Error::Other("query not found 't' field".to_string()))?;

        let q = v
            .dict()?
            .get(b"q".as_ref())
            .ok_or(Error::Other("query not found 'q' field".to_string()))?
            .string()?;

        match q {
            "get_peers" => self.on_get_peers(v),
            "announce_peer" => self.on_announce_peer(v, addr),
            _ => Ok(DhtMessageRead::NotSupported(q.to_string())),
        }
    }

    async fn on_reply(&self, v: &Value) -> Result<DhtMessageRead> {
        // transaction id
        let t = v
            .dict()?
            .get(b"t".as_ref())
            .ok_or(Error::DictNotFound("t".to_string()))?
            .bytes()?;

        if let Some((_id, send)) = self.pending.lock().await.pop_entry(t) {
            match send {
                DhtMessageSend::FindNode => {
                    let r = v
                        .dict()?
                        .get(b"r".as_ref())
                        .ok_or(Error::DictNotFound("r".to_string()))?;

                    let id = r
                        .dict()?
                        .get(b"id".as_ref())
                        .ok_or(Error::DictNotFound("id".to_string()))?
                        .bytes()?;

                    let nodes = r.dict()?.get(b"nodes".as_ref()).map_or(None, |item| {
                        item.bytes().map_or(None, |item| Some(item.to_vec()))
                    });

                    let nodes6 = r.dict()?.get(b"nodes6".as_ref()).map_or(None, |item| {
                        item.bytes().map_or(None, |item| Some(item.to_vec()))
                    });

                    let mut node_list = vec![];
                    if let Some(nodes) = nodes {
                        if nodes.len() % 26 == 0 {
                            nodes.chunks(26).for_each(|node| {
                                let node_id = NodeId(node.to_vec());
                                let addr =
                                    Ipv4Addr::from(*(&<[u8; 4]>::try_from(&node[20..24]).unwrap()));

                                let node_addr = SocketAddr::new(
                                    IpAddr::V4(addr),
                                    u16::from_be_bytes(node[24..26].try_into().unwrap()),
                                );
                                let node = Node::new(node_id, node_addr);
                                node_list.push(node);
                            });
                        } else {
                            error!("{}", nodes.len());
                        }
                    }

                    if let Some(nodes) = nodes6 {
                        if nodes.len() % 38 == 0 {
                            nodes.chunks(38).for_each(|node| {
                                let node_id = NodeId(node.to_vec());
                                let addr = Ipv6Addr::from(
                                    *(&<[u8; 16]>::try_from(&node[20..36]).unwrap()),
                                );

                                let node_addr = SocketAddr::new(
                                    IpAddr::V6(addr),
                                    u16::from_be_bytes(node[36..38].try_into().unwrap()),
                                );
                                let node = Node::new(node_id, node_addr);
                                node_list.push(node);
                            });
                        } else {
                            error!("{}", nodes.len());
                        }
                    }

                    return Ok(DhtMessageRead::FindNode(FindNodeResponse {
                        t: t.to_vec(),
                        id: NodeId::from(&id.to_vec()),
                        nodes: node_list,
                    }));
                }
            }
        }

        Err(Error::Other("not supported".to_string()))
    }

    fn on_error(&self, v: &Value) -> Result<DhtError> {
        let e = v
            .dict()?
            .get(b"e".as_ref())
            .ok_or(Error::DictNotFound("e".to_string()))?;

        let a = e.list()?;
        if a.len() != 2 {
            return Err(Error::Other("invalid dht error list field".to_string()));
        }

        // decode error describe.
        let code = a[0].integer()?;
        let desc = a[1].string()?;

        Ok(DhtError {
            code,
            message: desc.to_string(),
        })
    }

    fn on_get_peers(&self, v: &Value) -> Result<DhtMessageRead> {
        let tid = v
            .dict()?
            .get(b"t".as_ref())
            .ok_or(Error::DictNotFound("t".to_string()))?
            .bytes()?;

        let a = v
            .dict()?
            .get(b"a".as_ref())
            .ok_or(Error::DictNotFound("a".to_string()))?;

        let id = a
            .dict()?
            .get(b"id".as_ref())
            .ok_or(Error::DictNotFound("id".to_string()))?
            .bytes()?;

        let info_hash = a
            .dict()?
            .get(b"info_hash".as_ref())
            .ok_or(Error::DictNotFound("info_hash".to_string()))?
            .bytes()?;

        Ok(DhtMessageRead::GetPeers(GetPeersRequest {
            t: tid.to_vec(),
            id: NodeId::from(&id.to_vec()),
            info_hash: info_hash.to_vec(),
        }))
    }

    fn on_announce_peer(&self, v: &Value, addr: &SocketAddr) -> Result<DhtMessageRead> {
        let a = v
            .dict()?
            .get(b"a".as_ref())
            .ok_or(Error::DictNotFound("a".to_string()))?;

        let token = a
            .dict()?
            .get(b"token".as_ref())
            .ok_or(Error::DictNotFound("token".to_string()))?
            .bytes()?;

        if !self.is_valid_token(token, addr) {
            return Err(Error::Other("announce peers invalid token".to_string()));
        }

        let hash = a
            .dict()?
            .get(b"info_hash".as_ref())
            .ok_or(Error::DictNotFound("info_hash".to_string()))?
            .bytes()?;

        let mut port = addr.port();
        if let Some(Value::Integer(0)) = a.dict()?.get(b"implied_port".as_ref()) {
            port = a
                .dict()?
                .get(b"port".as_ref())
                .ok_or(Error::DictNotFound("port".to_string()))?
                .integer()? as u16;
        }

        Ok(DhtMessageRead::AnnouncePeer(AnnouncePeerRequest {
            address: SocketAddr::new(addr.ip(), port),
            info_hash: hash.to_vec(),
        }))
    }

    fn is_valid_token(&self, token: &[u8], addr: &SocketAddr) -> bool {
        token == make_token(&self.secret, addr).as_slice()
    }
}
///
/// See more: http://bittorrent.org/beps/bep_0005.html
///
///
pub struct Dht {
    local_id: NodeId,
    bootstrap_nodes: Vec<SocketAddr>,
    socket: Arc<UdpSocket>,
    sender: Arc<Sender<Message>>,
    limit: Arc<LimitRate>,
    pending: Arc<Mutex<LruCache<Vec<u8>, DhtMessageSend>>>,
    parser: DhtMessageParser,
    secret: Arc<Vec<u8>>,
}

impl Dht {
    pub fn new(
        limit: Arc<LimitRate>,
        local_id: NodeId,
        bootstrap_nodes: Vec<SocketAddr>,
        socket: Arc<UdpSocket>,
        sender: Arc<Sender<Message>>,
    ) -> Self {
        let pending = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(1024).unwrap())));
        let secret = Arc::new(NodeId::random_id().0);
        Self {
            local_id,
            bootstrap_nodes,
            socket,
            sender,
            limit,
            pending: pending.clone(),
            parser: DhtMessageParser {
                pending,
                secret: secret.clone(),
            },
            secret,
        }
    }

    ///
    ///
    ///
    pub async fn auto_join(&self) {
        loop {
            for node in &self.bootstrap_nodes {
                // do find_node
                self.find_node(&NodeId::random_id(), node).await;
            }

            tokio::time::sleep(Duration::from_millis(10000)).await;
        }
    }

    ///
    ///
    ///
    pub async fn process_response(&self) -> Result<()> {
        let mut buf = [0; 65535];
        loop {
            if let Ok((size, address)) = self.socket.recv_from(&mut buf).await {
                let data = &buf[..size];

                let msg = self.parser.parse(data, &address).await;
                if let Ok(msg) = msg {
                    match msg {
                        DhtMessageRead::GetPeers(g) => {
                            info!(target:"dht", "read msg: get_peers, {}", g);
                            let id = NodeId::get_neighbor(&g.id, &self.local_id);
                            let message = GetPeersResponse::new(
                                g.t.clone(),
                                id,
                                make_token(&self.secret, &address),
                            );
                            let r = send_message(&self.socket, &message, &address).await;
                            if r.is_err() {
                                error!("send message error: {:?}", r.err());
                            }
                        }
                        DhtMessageRead::AnnouncePeer(a) => {
                            info!(target:"dht", "read msg: announce_peer, {}", a);
                            let _ = self.sender.send(Message::new(a.address, a.info_hash)).await;
                        }
                        DhtMessageRead::FindNode(f) => {
                            info!(target:"dht", "read msg: find_node, {}", f);
                            for node in f.nodes {
                                self.find_node(&node.id, &node.address).await;
                            }
                        }
                        DhtMessageRead::Error(e) => {
                            error!("{:?}: {}", address, e);
                        }
                        DhtMessageRead::NotSupported(_) => {}
                    }
                } else {
                    error!("{:?}: {:?}", address, msg.err());
                }
            } else {
                error!("read message error.");
            }
        }
    }

    ///
    /// `id` current request node id.
    ///
    /// find_node Query = {"t":"aa", "y":"q", "q":"find_node", "a": {"id":"abcdefghij0123456789", "target":"mnopqrstuvwxyz123456"}}
    /// bencoded = d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe
    /// Response = {"t":"aa", "y":"r", "r": {"id":"0123456789abcdefghij", "nodes": "def456..."}}
    /// bencoded = d1:rd2:id20:0123456789abcdefghij5:nodes9:def456...e1:t2:aa1:y1:re
    ///
    async fn find_node(&self, target: &NodeId, address: &SocketAddr) {
        if !self.limit.allow() {
            return;
        }
        let id = NodeId::get_neighbor(target, &self.local_id);
        let request = FindNodeRequest::new(id, NodeId::random_id());
        self.pending
            .lock()
            .await
            .push(request.t.clone(), DhtMessageSend::FindNode);

        let _ = send_message(&self.socket, &request, address).await;
    }
}

async fn send_message(
    socket: &UdpSocket,
    message: &dyn DhtMessageBuilder,
    addr: &SocketAddr,
) -> Result<()> {
    info!(target:"dht", "send msg: {:?}, {}", addr, message);

    let msg = message.build()?;

    socket
        .send_to(&msg, addr)
        .await
        .map_err(|e| Error::Send(e.to_string()))?;
    Ok(())
}

fn make_token(secret: &Vec<u8>, addr: &SocketAddr) -> Vec<u8> {
    let mut m = Sha1::new();
    m.update(addr.to_string().as_bytes());
    m.update(secret);

    m.finalize().to_vec()
}
