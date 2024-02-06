use std::{io, num, str::Utf8Error, string::FromUtf8Error};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {

    #[error("Io error {0}")]
    Io(#[from] io::Error),

    #[error("ParseInt error {0}")]
    ParseInt(#[from] num::ParseIntError),

    #[error("Utf8Error {0}")]
    Utf8(#[from] Utf8Error),
    
    #[error("FromUtf8Error {0}")]
    FromUtf8(#[from] FromUtf8Error),

    #[error("Send message failed: {0:?}")]
    Send(String),

    #[error("bencode dict not found '{0}'")]
    DictNotFound(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
