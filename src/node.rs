use std::{
    cmp::Ordering,
    fmt::Display,
    io::{self, Error, ErrorKind},
    net::{IpAddr, SocketAddr, UdpSocket},
    ptr::copy,
};

use rand::Rng;
use serde::{Deserialize, Serialize};
pub use util::get_transaction_id;

///
/// See more https://libtorrent.org/dht_sec.html
///
/// In order to avoid the number node IDs controlled to grow linearly by the number of IPs,
/// as well as allowing more than one node ID per external IP, the node ID can be restricted at each class level of the IP.
///
/// Another important property of the restriction put on node IDs is that the distribution of the IDs remain uniform.
/// This is why CRC32C (Castagnoli) was chosen as the hash function.
///
/// The expression to calculate a valid ID prefix (from an IPv4 address) is:
///
/// ```
/// crc32c((ip & 0x030f3fff) | (r << 29))
/// ```
///
/// And for an IPv6 address (ip is the high 64 bits of the address):
///
/// ```
/// crc32c((ip & 0x0103070f1f3f7fff) | (r << 61))
/// ```
/// `r` s a random number in the range [0, 7]. The resulting integer,
/// representing the masked IP address is supposed to be big-endian before hashed. The "|" operator means bit-wise OR.
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub Vec<u8>);

// neighbor id length.
const CLOSENESS: usize = 15;

impl NodeId {
    ///
    ///
    ///
    pub fn random_id() -> Self {
        NodeId::from(&util::get_node_id())
    }

    ///
    ///
    ///
    pub fn get_current_id() -> io::Result<Self> {
        let addr = util::get_local_ip()?;
        let rand = util::get_rand_num();
        Self::get_by_ip(rand, addr)
    }

    pub fn get_neighbor(target: &NodeId, local: &NodeId) -> Self {
        let mut id = vec![0; 20];
        unsafe {
            copy(target.0.as_ptr(), id.as_mut_ptr(), CLOSENESS);
            copy(
                local.0.as_ptr().offset(CLOSENESS as isize),
                id.as_mut_ptr().offset(CLOSENESS as isize),
                20 - CLOSENESS,
            );
        }
        NodeId(id)
    }

    ///
    ///
    ///
    pub fn from(data: &Vec<u8>) -> Self {
        let mut r = [0u8; 20];
        r.copy_from_slice(&data);
        NodeId(r.to_vec())
    }

    fn get_by_ip(rand: u32, addr: IpAddr) -> io::Result<Self> {
        let r = rand & 0x7;
        let crc;

        match addr {
            IpAddr::V4(v4) => {
                let ip = (u32::from_be_bytes(v4.octets()) & 0x030f3fff) | (r << 29);
                crc = crc32c::crc32c(&ip.to_be_bytes());
            }
            IpAddr::V6(v6) => {
                let ip =
                    (u128::from_be_bytes(v6.octets()) & 0x0103070f1f3f7fff) | ((r as u128) << 61);
                crc = crc32c::crc32c(&ip.to_be_bytes());
            }
        }

        let mut node_id = [0u8; 20];
        node_id[0] = ((crc >> 24) & 0xff) as u8;
        node_id[1] = ((crc >> 16) & 0xff) as u8;
        node_id[2] = (((crc >> 8) & 0xf8) | util::get_rand_num() & 0x7) as u8;

        for i in 3..19 {
            node_id[i] = util::get_rand_num() as u8;
        }
        node_id[19] = rand as u8;
        Ok(NodeId(node_id.to_vec()))
    }
}

impl Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl PartialOrd for NodeId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl Ord for NodeId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub id: NodeId,
    pub address: SocketAddr,
}

impl Node {
    pub fn new(id: NodeId, address: SocketAddr) -> Self {
        Self { id, address }
    }
}

mod util {
    use rand::RngCore;

    use super::*;

    //
    const NODE_ID_LENGTH: usize = 20;
    // transaction id length.
    const TID_LENGTH: usize = 2;

    pub fn get_node_id() -> Vec<u8> {
        rand_bytes(NODE_ID_LENGTH)
    }
    ///
    ///
    ///
    pub fn get_transaction_id() -> Vec<u8> {
        rand_bytes(TID_LENGTH)
    }

    ///
    ///
    ///
    pub fn get_local_ip() -> std::io::Result<IpAddr> {
        if let Ok(r) = get_ipv6() {
            return Ok(r.ip());
        }
        if let Ok(r) = get_ipv4() {
            Ok(r.ip())
        } else {
            Err(Error::from(ErrorKind::BrokenPipe))
        }
    }

    ///
    ///
    ///
    pub fn get_rand_num() -> u32 {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..256)
    }

    fn get_ipv6() -> std::io::Result<SocketAddr> {
        let socket = UdpSocket::bind(":::0")?;
        let addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        socket.connect(addr)?;
        let local_addr = socket.local_addr()?;
        Ok(local_addr)
    }

    fn get_ipv4() -> std::io::Result<SocketAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        socket.connect(addr)?;
        let local_addr = socket.local_addr()?;
        Ok(local_addr)
    }

    fn rand_bytes(n: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut ret = vec![0; n];
        rng.fill_bytes(&mut ret);
        ret
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_get_local_ip() {
        let addr = util::get_local_ip();
        assert!(addr.is_ok())
    }

    #[test]
    fn test_get_current() {
        let node = NodeId::get_current_id();
        if let Ok(node) = node {
            println!("{}", node);
        }
    }

    #[test]
    fn test_get_by_ip() {
        let addr: IpAddr = "21.75.31.124".parse().unwrap();
        let node = NodeId::get_by_ip(86, addr);
        if let Ok(node) = node {
            println!("{}", node);
            let s = node.to_string();
            assert!(s.starts_with("5a3ce"));
        }
    }
}
