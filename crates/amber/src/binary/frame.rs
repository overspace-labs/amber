use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::diagnostic::{Error, Result, SourceRange};

use super::source::FileSource;

pub const CHUNK: u64 = 1024 * 1024;

const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"PATCH ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"CONNECT ",
    b"TRACE ",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpFrame {
    pub frame_offset: u64,
    pub payload_offset: u64,
    pub frame_length: u32,
    pub payload_length: u32,
    pub kind: FrameKind,
}

impl HttpFrame {
    pub const fn payload(self) -> SourceRange {
        SourceRange::new(self.payload_offset, self.payload_length as u64)
    }
}

pub fn header(payload_length: u32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0..4].copy_from_slice(&(payload_length + 8).to_be_bytes());
    bytes[4..8].copy_from_slice(&payload_length.to_be_bytes());
    bytes
}

pub fn frame_at(source: &FileSource, frame_offset: u64) -> Result<Option<HttpFrame>> {
    let payload_offset = match frame_offset.checked_add(8) {
        Some(value) if value <= source.len() => value,
        _ => return Ok(None),
    };
    let frame_length = source.u32(frame_offset)?;
    let payload_length = source.u32(frame_offset + 4)?;
    let end = payload_offset
        .checked_add(u64::from(payload_length))
        .ok_or(Error::OffsetOverflow)?;
    if payload_length == 0 || frame_length < payload_length || end > source.len() {
        return Ok(None);
    }
    let prefix = source.bytes(payload_offset, u64::from(payload_length).min(8))?;
    let kind = if METHODS.iter().any(|method| prefix.starts_with(method)) {
        FrameKind::Request
    } else if prefix.starts_with(b"HTTP/") {
        FrameKind::Response
    } else {
        return Ok(None);
    };
    Ok(Some(HttpFrame {
        frame_offset,
        payload_offset,
        frame_length,
        payload_length,
        kind,
    }))
}

pub fn digest(source: &FileSource, range: SourceRange) -> Result<String> {
    let mut hasher = Sha256::new();
    stream(source, range, |window| {
        hasher.update(window);
        Ok(())
    })?;
    Ok(hex(&hasher.finalize()))
}

pub fn stream(
    source: &FileSource,
    range: SourceRange,
    mut visit: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut buffer = vec![0u8; usize::try_from(range.length.min(CHUNK)).unwrap_or(0)];
    let mut done = 0u64;
    while done < range.length {
        let amount =
            usize::try_from((range.length - done).min(CHUNK)).map_err(|_| Error::OffsetOverflow)?;
        let window = &mut buffer[..amount];
        source.read_into_at(range.offset + done, window)?;
        visit(window)?;
        done += amount as u64;
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}
