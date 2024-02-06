use crate::{
    bencode,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};

use std::{fmt::Display, path::PathBuf};

#[derive(Serialize, Deserialize)]
pub struct TorrentFile {
    name: String,
    size: i64,
    md5sum: Option<String>,
}

impl Display for TorrentFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\t{}\n{}", self.name, self.size)
    }
}

#[derive(Serialize, Deserialize)]
pub struct TorrentInfo {
    #[serde(rename = "infoHash")]
    info_hash: String,
    name: String,
    size: i64,
    files: usize,

    #[serde(rename = "fileList")]
    file_list: Vec<TorrentFile>,
}

impl Display for TorrentInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\n{}\n{}{:#?}",
            self.info_hash, self.name, self.size, self.files
        )
    }
}

// extract torrent inter path.
fn extract_path(value: &bencode::Value) -> Result<String> {
    let array = value.list()?;

    let mut paths = Vec::new();
    for s in array {
        paths.push(s.string()?);
    }

    paths
        .iter()
        .fold(PathBuf::new(), |pb, x| pb.join(x))
        .into_os_string()
        .into_string()
        .map_err(|e| Error::Other(format!("extract path fail, {:?}", e)))
}

// parse torrent included files.
fn extract_files(value: &bencode::Value) -> Result<TorrentFile> {
    let name: String;
    let mut length = 0_i64;

    let dict = value.dict()?;
    if let Some(x) = dict.get(b"path.utf-8".as_ref()) {
        name = extract_path(x)?;
    } else if let Some(x) = dict.get(b"path".as_ref()) {
        name = extract_path(x)?;
    } else {
        name = "".to_string();
    }

    if let Some(x) = dict.get(b"length".as_ref()) {
        length = x.integer()?;
    }

    let md5sum = dict
        .get(b"md5sum".as_ref())
        .map_or(None, |a| a.string().map_or(None, |a| Some(a.to_string())));

    Ok(TorrentFile {
        name,
        size: length,
        md5sum,
    })
}

// parse meta into Torrent instance.
pub fn from_bytes(info_hash: &Vec<u8>, meta: &[u8]) -> Result<TorrentInfo> {
    let name: String;
    let mut length = 0_i64;

    let m = bencode::from_bytes(meta)?;
    let dict = m.dict()?;

    if let Some(s) = dict.get(b"name.utf-8".as_ref()) {
        name = s.string()?.to_string();
    } else if let Some(s) = dict.get(b"name".as_ref()) {
        name = s.string()?.to_string();
    } else {
        name = "".to_string();
    }

    if let Some(x) = dict.get(b"length".as_ref()) {
        length = x.integer()?;
    }

    let mut total_length = 0;
    let mut files = Vec::new();
    if let Some(x) = dict.get(b"files".as_ref()) {
        for f in x.list()? {
            let tf = extract_files(f)?;
            total_length += tf.size;
            files.push(tf);
        }
    }

    if length == 0 {
        length = total_length;
    }

    Ok(TorrentInfo {
        info_hash: format!("magnet:?xt=urn:btih:{}", hex::encode(info_hash.clone())),
        name,
        size: length,
        files: {
            if files.len() > 0 {
                files.len()
            } else {
                1
            }
        },
        file_list: files,
    })
}
