use std::time::Duration;

use bencode::Value;
use sha1::Digest;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::{
    bencode,
    dht::Message,
    error::{Error, Result},
    node,
};

const EXTENDED: u8 = 20;
const EXTHANDSHAKE: u8 = 0;

const PER_BLOCK: i64 = 16384;
const MAX_METADATA_SIZE: i64 = PER_BLOCK * 1024;

const PROTOCOL_HEADER: &[u8] = &[
    0x13, // Protocol Name Length.
    b'B', b'i', b't', b'T', b'o', b'r', b'r', b'e', b'n', b't', b' ', b'p', b'r', b'o', b't', b'o',
    b'c', b'o', b'l', // Name.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, // Reserved Extension Bytes.
];

///
/// See more: http://bittorrent.org/beps/bep_0009.html
///
/// This extension only transfers the info-dictionary part of the .torrent file.
///
pub struct MetaWire {
    message: Message,
    peer_id: Vec<u8>,
    stream: Option<Mutex<TcpStream>>,
    pieces: Vec<Option<Vec<u8>>>,
    timeout: Duration,
}

impl MetaWire {
    pub fn new(msg: Message, t: u64) -> Self {
        Self {
            message: msg,
            peer_id: node::NodeId::random_id().0,
            stream: None,
            pieces: Vec::new(),
            timeout: Duration::from_secs(t),
        }
    }

    pub async fn fetch(&mut self) -> Result<Vec<u8>> {
        self.connect().await?;
        self.handshake().await?;
        self.on_handshake().await?;
        self.ext_handshake().await?;

        loop {
            let data = self.next().await?;
            if data[0] != EXTENDED {
                continue;
            }

            self.on_extended(data[1], &data[2..]).await?;

            if !self.check_pieces_done() {
                continue;
            }

            let (res, digest) = self.join_pieces();
            if self.message.get_info_hash().eq(&digest) {
                return Ok(res);
            } else {
                return Err(Error::Other("metadata checksum mismatch".to_string()));
            }
        }
    }

    async fn connect(&mut self) -> Result<()> {
        let peer = self.message.get_peer();
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(peer))
            .await
            .map_err(|e| Error::Other(format!("connect {} timeout, {}", peer, e)))?
            .map_err(|e| Error::Other(format!("connect {} fail, {}", peer, e)))?;

        self.stream = Some(Mutex::new(stream));
        Ok(())
    }

    async fn handshake(&self) -> Result<usize> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&PROTOCOL_HEADER);
        buf.extend_from_slice(self.message.get_info_hash());
        buf.extend_from_slice(&self.peer_id);

        let r = self
            .stream
            .as_ref()
            .ok_or(Error::Other("invalid tcp socket".to_string()))?
            .lock()
            .await
            .write(&buf)
            .await
            .map_err(|_e| Error::Other("handshake error".to_string()))?;

        Ok(r)
    }

    async fn on_handshake(&self) -> Result<()> {
        let mut buf = [0; 68];
        self.read_exact(&mut buf).await?;

        // verify Protocol Name
        if buf[..20] != PROTOCOL_HEADER[..20] {
            return Err(Error::Other(
                "remote peer not supporting bittorrent protocol".to_string(),
            ));
        }

        if buf[25] & 0x10 != 0x10 {
            return Err(Error::Other(
                "remote peer not supporting extension protocol".to_string(),
            ));
        }

        if &buf[28..48] != self.message.get_info_hash().as_slice() {
            return Err(Error::Other(
                "invalid bittorrent extension header response".to_string(),
            ));
        }

        Ok(())
    }

    async fn ext_handshake(&self) -> Result<usize> {
        let m = map!(
            b"m".to_vec() => Value::from(
                map!(b"ut_metadata".to_vec() => Value::from(1)))
        );
        let data = bencode::to_bytes(&Value::from(m))?;

        let mut buf = Vec::new();
        buf.extend_from_slice(&[EXTENDED, EXTHANDSHAKE]);
        buf.extend_from_slice(&data);
        Ok(self.write(&buf).await?)
    }

    async fn next(&self) -> Result<Vec<u8>> {
        let mut data = [0; 4];
        self.read_exact(&mut data).await?;

        let n = u32::from_be_bytes(data) as usize;
        let mut res = vec![0; n];
        self.read_exact(&mut res).await?;

        Ok(res)
    }

    async fn on_extended(&mut self, ext: u8, payload: &[u8]) -> Result<()> {
        if ext == 0 {
            self.on_ext_handshake(payload).await?;
        } else {
            let (piece, index) = self.on_piece(payload).await?;
            self.pieces[index] = Some(piece);
        }
        Ok(())
    }

    async fn on_ext_handshake(&mut self, payload: &[u8]) -> Result<()> {
        let m = bencode::from_bytes(payload)?;
        let dict = m.dict()?;

        let metadata_size = dict
            .get(b"metadata_size".as_ref())
            .ok_or(Error::DictNotFound("metadata_size".to_string()))?
            .integer()?;

        if metadata_size > MAX_METADATA_SIZE {
            return Err(Error::Other("metadata size too long".to_string()));
        }

        if metadata_size < 0 {
            return Err(Error::Other("negative metadata size".to_string()));
        }

        let m = dict
            .get(b"m".as_ref())
            .ok_or(Error::DictNotFound("m".to_string()))?
            .dict()?;

        let ut_metadata = m
            .get(b"ut_metadata".as_ref())
            .ok_or(Error::DictNotFound("ut_metadata".to_string()))?
            .integer()?;

        let mut num_pieces = metadata_size / PER_BLOCK;
        if metadata_size % PER_BLOCK != 0 {
            num_pieces += 1;
        }

        self.pieces = vec![None; num_pieces as usize];
        for i in 0..num_pieces {
            self.request_piece(i, ut_metadata).await?;
        }

        Ok(())
    }

    async fn request_piece(&self, index: i64, ut_metadata: i64) -> Result<usize> {
        let m = map!(
            b"msg_type".to_vec() => Value::from(0),
            b"piece".to_vec() => Value::from(index)
        );
        let data = bencode::to_bytes(&Value::from(m))?;

        let mut buf = Vec::new();
        buf.extend_from_slice(&[EXTENDED, ut_metadata as u8]);
        buf.extend_from_slice(&data);

        Ok(self.write(&buf).await?)
    }

    async fn on_piece(&self, payload: &[u8]) -> Result<(Vec<u8>, usize)> {
        let trailer_index = payload
            .windows(2)
            .position(|x| x == b"ee".as_ref())
            .ok_or(Error::Other("piece index not found".to_string()))?
            + 2;

        let m = bencode::from_bytes(&payload[..trailer_index])?;
        let dict = m.dict()?;

        let piece_index = dict
            .get(b"piece".as_ref())
            .ok_or(Error::DictNotFound("piece".to_string()))?
            .integer()?;

        let msg_type = dict
            .get(b"msg_type".as_ref())
            .ok_or(Error::DictNotFound("msg_type".to_string()))?
            .integer()?;

        if msg_type != 1 {
            return Err(Error::Other(
                "piece msg_type != 1, invalid piece".to_string(),
            ));
        }

        Ok((payload[trailer_index..].to_vec(), piece_index as usize))
    }

    async fn write(&self, data: &[u8]) -> Result<usize> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);

        let r = self
            .stream
            .as_ref()
            .ok_or(Error::Other("invalid tcp socket".to_string()))?
            .lock()
            .await
            .write(&buf)
            .await
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(r)
    }

    async fn read_exact(&self, buf: &mut [u8]) -> Result<()> {
        let mut stream = self
            .stream
            .as_ref()
            .ok_or(Error::Other("invalid tcp socket".to_string()))?
            .lock()
            .await;

        let peer = self.message.get_peer();
        let _r = tokio::time::timeout(self.timeout, stream.read_exact(buf))
            .await
            .map_err(|e| Error::Other(format!("{} read {} bytes timeout, {}", peer, buf.len(), e)))?
            .map_err(|e| Error::Other(format!("{} read {} bytes fail, {}", peer, buf.len(), e)))?;

        Ok(())
    }

    fn check_pieces_done(&self) -> bool {
        for p in self.pieces.iter() {
            if p.is_none() {
                return false;
            }
        }
        true
    }

    fn join_pieces(&self) -> (Vec<u8>, Vec<u8>) {
        let mut res = Vec::new();
        let mut m = sha1::Sha1::new();

        self.pieces.iter().for_each(|x| {
            x.as_ref().map(|s| {
                res.extend(s);
                m.update(&s);
            });
        });

        let r = m.finalize();

        (res, r.to_vec())
    }
}
