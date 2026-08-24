use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRange {
    pub offset: u64,
    pub length: u64,
}

impl SourceRange {
    pub const fn new(offset: u64, length: u64) -> Self {
        Self { offset, length }
    }

    pub fn checked_end(self) -> Result<u64> {
        self.offset
            .checked_add(self.length)
            .ok_or(Error::OffsetOverflow)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("offset arithmetic overflow")]
    OffsetOverflow,
    #[error("range {range:?} exceeds source length {source_length}")]
    OutOfBounds {
        range: SourceRange,
        source_length: u64,
    },
    #[error("short read at offset {offset}: expected {expected} bytes, got {actual}")]
    ShortRead {
        offset: u64,
        expected: usize,
        actual: usize,
    },
    #[error("invalid UTF-16BE data in range {range:?}")]
    InvalidUtf16 { range: SourceRange },
    #[error("resource limit exceeded for {resource}: requested {requested}, limit {limit}")]
    ResourceLimit {
        resource: &'static str,
        requested: u64,
        limit: u64,
    },
    #[error("destination {0} already exists; pass --force to overwrite")]
    DestinationExists(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported or malformed project: {0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, Error>;
