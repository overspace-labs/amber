use crate::binary::Schema;
use crate::diagnostic::{Error, Result};
use crate::history::layout;

use super::fields;
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

// text_bytes_raw is text_bytes for arbitrary message bytes: the frame header
// plus two UTF-16 code units per byte-slice rune, matching write_text_record's
// Go-faithful rune decoding on invalid UTF-8.
fn text_bytes_raw(value: &[u8]) -> u64 {
    8 + 2 * fields::utf16_count(value) as u64
}

fn entry_bytes(entry: &Entry) -> u64 {
    let comment = if entry.comment.is_empty() {
        0
    } else {
        text_bytes(&entry.comment) + span(&layout::COMMENT_CHUNK) + span(&layout::COMMENT_WRAPPER)
    };
    let response = entry
        .response
        .as_ref()
        .map_or(0, |payload| 8 + payload.len() as u64);
    let ip = if entry.ip.is_empty() {
        0
    } else {
        text_bytes_raw(entry.ip.as_bytes()) + span(&layout::TEXT_WRAPPER) // tag 4 target IP
    };
    // A missing <title> writes tag 9 == 0 (no frame), mirroring write_entry's
    // use of write_text_record; the same text feeds the URL/display cache.
    let title_text: Vec<u8> = entry
        .response
        .as_deref()
        .map(fields::extract_title)
        .unwrap_or_default();
    let title = if title_text.is_empty() {
        0
    } else {
        text_bytes_raw(&title_text) + span(&layout::TEXT_WRAPPER) // tag 9 title
    };

    // Display columns derived from the request path/headers, mirroring the
    // computations in write_entry.
    let target = fields::request_target(&entry.request);
    let path = match target.iter().position(|byte| *byte == b'?') {
        Some(query) => &target[..query],
        None => target,
    };
    let path = if path.is_empty() { b"/".as_slice() } else { path };
    let extension_name = fields::url_extension(path);
    let cookie_text: &[u8] = entry
        .response
        .as_deref()
        .map(fields::cookie_value)
        .unwrap_or(&[]);
    let extension = if extension_name.is_empty() {
        0
    } else {
        text_bytes_raw(extension_name) + span(&layout::TEXT_WRAPPER) // tag 3 extension
    };
    let cookies = if cookie_text.is_empty() {
        0
    } else {
        text_bytes_raw(cookie_text) + span(&layout::TEXT_WRAPPER) // tag 10 cookies
    };
    // URL/display cache (RequestMetadata field 1): the path block plus one
    // 26-byte TextWrapper and one 4-byte-header cache frame per non-empty
    // value, matching write_url_cache.
    let mut url_cache = 8 + ((path.len() + 1) & !1) as u64;
    for value in [extension_name, entry.host.as_bytes(), &title_text, cookie_text] {
        if !value.is_empty() {
            url_cache += span(&layout::TEXT_WRAPPER) + 4 + 2 * fields::utf16_count(value) as u64;
        }
    }

    8 + entry.request.len() as u64
        + response
        + text_bytes_raw(fields::request_method(&entry.request))
        + span(&layout::TEXT_WRAPPER) // tag 1 method
        + extension // tag 3 extension
        + ip // tag 4 target IP
        + title // tag 9 title
        + cookies // tag 10 cookies
        + url_cache // RequestMetadata field 1 URL/display cache
        + text_bytes(&entry.host)
        + span(&layout::HOST_WRAPPER) // service host
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
