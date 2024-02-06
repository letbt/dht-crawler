use crate::error::{Error, Result};
use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::str;

#[derive(PartialEq, Clone, Debug)]
pub enum Value {
    ByteString(Vec<u8>),
    Integer(i64),
    List(Vec<Value>),
    Dict(HashMap<Vec<u8>, Value>),
}

impl Value {
    pub fn bytes(&self) -> Result<&[u8]> {
        match self {
            Value::ByteString(x) => Ok(&x),
            _ => Err(Error::Other("value not byte string type".to_string())),
        }
    }

    pub fn string(&self) -> Result<&str> {
        match self {
            Value::ByteString(x) => Ok(unsafe { std::str::from_utf8_unchecked(x) }),
            _ => Err(Error::Other("value not byte string type".to_string())),
        }
    }

    pub fn dict(&self) -> Result<&HashMap<Vec<u8>, Value>> {
        match self {
            Value::Dict(ref m) => Ok(m),
            _ => Err(Error::Other("value not dict type".to_string())),
        }
    }

    pub fn list(&self) -> Result<&Vec<Value>> {
        match self {
            Value::List(ref x) => Ok(x),
            _ => Err(Error::Other("value not list type".to_string())),
        }
    }

    pub fn integer(&self) -> Result<i64> {
        match self {
            Value::Integer(n) => Ok(*n),
            _ => Err(Error::Other("value not integer type".to_string())),
        }
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::ByteString(v)
    }
}

impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Value::ByteString(Vec::from(v))
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::ByteString(v.as_bytes().to_vec())
    }
}

impl From<i8> for Value {
    fn from(n: i8) -> Self {
        Value::Integer(n.into())
    }
}

impl From<i16> for Value {
    fn from(n: i16) -> Self {
        Value::Integer(n.into())
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::Integer(n.into())
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Integer(n)
    }
}

impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::List(v)
    }
}

impl From<&[Value]> for Value {
    fn from(v: &[Value]) -> Self {
        Value::List(v.to_vec())
    }
}

impl From<HashMap<Vec<u8>, Value>> for Value {
    fn from(v: HashMap<Vec<u8>, Value>) -> Self {
        Value::Dict(v)
    }
}

struct Decoder<'a> {
    data: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    // skip one byte.
    fn skip_byte(&mut self) -> Result<()> {
        let mut tmp = [0; 1];
        self.data.read(&mut tmp)?;
        Ok(())
    }

    // Strings are length-prefixed base ten followed by a colon and the string.
    // For example 4:spam corresponds to 'spam'.
    fn read_byte_string(&mut self) -> Result<Value> {
        let mut buf = Vec::new();
        self.data.read_until(b':', &mut buf)?;

        let n = str::from_utf8(&buf[..buf.len() - 1])?.parse::<i64>()?;

        buf.clear();
        buf.resize_with(n as usize, Default::default);

        self.data.read_exact(&mut buf)?;

        Ok(Value::ByteString(buf))
    }

    // Integers are represented by an 'i' followed by the number in base 10
    // followed by an 'e'. For example i3e corresponds to 3 and i-3e corresponds
    // to -3. Integers have no size limitation. i-0e is invalid. All encodings with
    // a leading zero, such as i03e, are invalid, other than i0e, which of course
    // corresponds to 0.
    fn read_integer(&mut self) -> Result<Value> {
        self.skip_byte()?;

        let mut buf = Vec::new();
        self.data.read_until(b'e', &mut buf)?;

        let s = str::from_utf8(&buf[..buf.len() - 1])?;
        if s.starts_with("-0") || (s.len() > 1 && s.starts_with("0")) {
            return Err(Error::Other(format!("invalid integer '{}'", s)));
        }

        Ok(Value::Integer(s.parse::<i64>()?))
    }

    // Lists are encoded as an 'l' followed by their elements (also bencoded)
    // followed by an 'e'. For example l4:spam4:eggse corresponds to ['spam', 'eggs'].
    fn read_list(&mut self) -> Result<Value> {
        self.skip_byte()?;

        let mut res = Vec::new();
        loop {
            let mut p = self.data.iter().peekable();
            match p.peek() {
                Some(b'e') => {
                    self.skip_byte()?;
                    break;
                }
                Some(_) => res.push(self.read_value()?),
                None => {
                    return Err(Error::Other("eof stream".to_string()));
                }
            }
        }
        Ok(Value::List(res))
    }

    // Dictionaries are encoded as a 'd' followed by a list of alternating keys
    // and their corresponding values followed by an 'e'.
    // For example, d3:cow3:moo4:spam4:eggse corresponds to {'cow': 'moo', 'spam': 'eggs'}
    // and d4:spaml1:a1:bee corresponds to {'spam': ['a', 'b']}. Keys must be strings
    // and appear in sorted order (sorted as raw strings, not alphanumerics).
    fn read_dict(&mut self) -> Result<Value> {
        self.skip_byte()?;

        let mut res = HashMap::new();
        loop {
            let mut p = self.data.iter().peekable();
            let ch = p.peek();
            if ch.is_none() || ch == Some(&&b'e') {
                self.skip_byte()?;
                break;
            }

            let key = match self.read_value()? {
                Value::ByteString(inner) => inner,
                _ => unreachable!(),
            };

            let val = self.read_value()?;
            res.insert(key, val);
        }
        Ok(Value::Dict(res))
    }

    fn read_value(&mut self) -> Result<Value> {
        let mut p = self.data.iter().peekable();

        match p.peek() {
            Some(b'i') => self.read_integer(),
            Some(b'l') => self.read_list(),
            Some(b'd') => self.read_dict(),
            Some(_) => self.read_byte_string(),
            None => Err(Error::Other("eof stream".to_string())),
        }
    }
}

struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn write_byte_string(&mut self, v: &[u8]) -> Result<()> {
        self.buf.write(v.len().to_string().as_bytes())?;
        self.buf.write(b":")?;
        self.buf.write(v)?;
        Ok(())
    }

    fn write_integer(&mut self, v: i64) -> Result<()> {
        self.buf.write(b"i")?;
        self.buf.write(v.to_string().as_bytes())?;
        self.buf.write(b"e")?;
        Ok(())
    }

    fn write_list(&mut self, l: &[Value]) -> Result<()> {
        self.buf.write(b"l")?;
        for v in l.iter() {
            self.write_value(&v)?;
        }
        self.buf.write(b"e")?;
        Ok(())
    }

    fn write_dict(&mut self, dict: &HashMap<Vec<u8>, Value>) -> Result<()> {
        self.buf.write(b"d")?;
        for (key, val) in dict.iter() {
            self.write_byte_string(key)?;
            self.write_value(val)?;
        }
        self.buf.write(b"e")?;
        Ok(())
    }

    fn write_value(&mut self, value: &Value) -> Result<()> {
        match value {
            Value::ByteString(ref v) => self.write_byte_string(v),
            Value::Integer(ref v) => self.write_integer(*v),
            Value::List(ref v) => self.write_list(v),
            Value::Dict(ref v) => self.write_dict(v),
        }
    }

    fn buffer(&mut self) -> &[u8] {
        &self.buf
    }
}

///
/// See more: https://en.wikipedia.org/wiki/Bencode
///
pub fn from_bytes(v: &[u8]) -> Result<Value> {
    let mut decoder = Decoder::new(v);
    decoder.read_value()
}

///
/// Value encode convert bytes.
///
pub fn to_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.write_value(value)?;
    Ok(encoder.buffer().to_vec())
}

#[macro_export]
macro_rules! map(
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::HashMap::new();
            $(
                m.insert($key, $value);
            )+
            m
        }
     };
);
