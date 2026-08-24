use crate::binary::Schema;
use crate::diagnostic::{Error, Result};
use crate::history::layout;

use super::input::Entry;

const CHUNK_CAPACITY: u64 = 200;
const COLLECTIONS: u64 = 2;
const MINIMUM_SLACK: u64 = 64 * 1024;
const GRANULARITY: u64 = 64 * 1024;

fn span(schema: &Schema) -> u64 {
    schema
        .last()
        .map_or(0, |(_, relative)| u64::from(*relative) + 8)
}

fn text_bytes(value: &str) -> u64 {
    8 + 2 * value.encode_utf16().count() as u64
}

fn entry_bytes(entry: &Entry) -> u64 {
    let comment = if entry.comment.is_empty() {
        0
    } else {
        text_bytes(&entry.comment) + span(&layout::COMMENT_CHUNK) + span(&layout::COMMENT_WRAPPER)
    };
    8 + entry.request.len() as u64
        + entry
            .response
            .as_ref()
            .map_or(0, |payload| 8 + payload.len() as u64)
        + text_bytes(&entry.host)
        + span(&layout::HOST_WRAPPER)
        + span(&layout::SERVICE)
        + span(&layout::REQUEST_METADATA)
        + comment
        + span(&layout::ROW)
}

pub fn slack_for(entries: &[Entry]) -> Result<u64> {
    let rows = entries
        .iter()
        .try_fold(0u64, |total, entry| total.checked_add(entry_bytes(entry)))
        .ok_or(Error::OffsetOverflow)?;
    let chunks =
        (entries.len() as u64).div_ceil(CHUNK_CAPACITY) * COLLECTIONS * (8 + CHUNK_CAPACITY * 8);
    rows.checked_add(chunks)
        .and_then(|total| total.checked_next_multiple_of(GRANULARITY))
        .map(|total| total.max(MINIMUM_SLACK))
        .ok_or(Error::OffsetOverflow)
}
