//! Content search over Proxy history messages, the command-line twin of Burp's
//! "Filter by search term" in Proxy > HTTP history.

use std::io::Read;

use regex::bytes::{Regex, RegexBuilder};
use serde::Serialize;

use crate::binary::FileSource;
use crate::diagnostic::{Error, Result};
use crate::model::history::{HistoryEntry, HttpHeader, Message};

/// Cap on a decoded (decompressed) body, so a hostile or corrupt stream cannot exhaust RAM.
pub const DECODE_LIMIT: u64 = 256 * 1024 * 1024;
/// Cap on matches reported per message part.
pub const MATCH_LIMIT: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Part {
    ReqHeaders,
    ReqBody,
    ResHeaders,
    ResBody,
}

impl Part {
    pub const ALL: [Self; 4] = [
        Self::ReqHeaders,
        Self::ReqBody,
        Self::ResHeaders,
        Self::ResBody,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ReqHeaders => "req-headers",
            Self::ReqBody => "req-body",
            Self::ResHeaders => "res-headers",
            Self::ResBody => "res-body",
        }
    }

    const fn is_request(self) -> bool {
        matches!(self, Self::ReqHeaders | Self::ReqBody)
    }

    const fn is_headers(self) -> bool {
        matches!(self, Self::ReqHeaders | Self::ResHeaders)
    }
}

#[derive(Debug, Clone)]
pub struct SearchOptions {
    /// Parts to look in; empty means all four.
    pub parts: Vec<Part>,
    /// Undo `Transfer-Encoding: chunked` and `Content-Encoding` gzip/deflate/br on bodies
    /// before matching. Burp's own search matches the stored bytes, so this is opt-in.
    pub decode: bool,
    /// Report this capture group instead of the whole match.
    pub group: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Matcher {
    regex: Regex,
}

impl Matcher {
    /// A literal (default) or regular-expression matcher over raw bytes.
    pub fn new(pattern: &str, regex: bool, case_sensitive: bool) -> Result<Self> {
        let source = if regex {
            pattern.to_owned()
        } else {
            regex::escape(pattern)
        };
        let regex = RegexBuilder::new(&source)
            .case_insensitive(!case_sensitive)
            .size_limit(64 * 1024 * 1024)
            .build()
            .map_err(|error| Error::Malformed(format!("invalid search pattern: {error}")))?;
        Ok(Self { regex })
    }

    pub const fn regex(&self) -> &Regex {
        &self.regex
    }
}

/// Matches found in one part of one message. `text` is the haystack that was searched
/// (decoded when decoding was asked for and applied), `ranges` index into it.
#[derive(Debug, Clone)]
pub struct PartMatches {
    pub part: Part,
    pub text: Vec<u8>,
    pub ranges: Vec<(usize, usize)>,
    pub decoded: bool,
    /// More than `MATCH_LIMIT` matches; only the first ones are listed.
    pub truncated: bool,
}

/// Result of searching one entry.
#[derive(Debug, Clone, Default)]
pub struct EntryMatches {
    /// Parts with at least one match.
    pub parts: Vec<PartMatches>,
    /// Parts whose decoded body exceeded `DECODE_LIMIT`: only the first `DECODE_LIMIT`
    /// bytes were searched, so "no match" there is not conclusive.
    pub capped: Vec<Part>,
}

impl EntryMatches {
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }
}

/// A decoded body, and whether it was cut at `DECODE_LIMIT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub data: Vec<u8>,
    pub capped: bool,
}

fn header_value<'a>(headers: &'a [HttpHeader], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.trim().eq_ignore_ascii_case(name))
        .map(|header| header.value.trim())
}

/// Removes chunked framing. Output never exceeds `limit`; the flag reports a cut.
fn dechunk(body: &[u8], limit: usize) -> Option<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    loop {
        let line_end = memchr::memmem::find(body.get(cursor..)?, b"\r\n")? + cursor;
        let size_text = std::str::from_utf8(&body[cursor..line_end]).ok()?;
        let size_text = size_text.split(';').next()?.trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        cursor = line_end + 2;
        if size == 0 {
            return Some((out, false));
        }
        let end = cursor.checked_add(size)?;
        if end > body.len() {
            return None;
        }
        let room = limit - out.len();
        if size > room {
            out.extend_from_slice(&body[cursor..cursor + room]);
            return Some((out, true));
        }
        out.extend_from_slice(&body[cursor..end]);
        cursor = end + 2;
        if cursor > body.len() {
            return Some((out, false));
        }
    }
}

/// Reads at most `limit` bytes, and reports whether the stream had more.
fn read_limited(reader: impl Read, limit: usize) -> Option<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    let capped = out.len() > limit;
    out.truncate(limit);
    Some((out, capped))
}

fn inflate(encoding: &str, data: &[u8], limit: usize) -> Option<(Vec<u8>, bool)> {
    match encoding {
        "gzip" | "x-gzip" => read_limited(flate2::read::MultiGzDecoder::new(data), limit),
        "deflate" => read_limited(flate2::read::ZlibDecoder::new(data), limit)
            .or_else(|| read_limited(flate2::read::DeflateDecoder::new(data), limit)),
        "br" => read_limited(brotli_decompressor::Decompressor::new(data, 64 * 1024), limit),
        "identity" => Some((data.to_vec(), false)),
        _ => None,
    }
}

/// Returns the body with transfer and content codings removed (each stage capped at
/// `DECODE_LIMIT`), or `None` when there was nothing to undo or decoding failed (the
/// caller then searches the stored bytes).
pub fn decode_body(headers: &[HttpHeader], body: &[u8]) -> Option<Decoded> {
    decode_body_limited(headers, body, usize::try_from(DECODE_LIMIT).unwrap_or(usize::MAX))
}

fn decode_body_limited(headers: &[HttpHeader], body: &[u8], limit: usize) -> Option<Decoded> {
    let chunked = header_value(headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let encodings: Vec<String> = header_value(headers, "content-encoding")
        .map(|value| {
            value
                .split(',')
                .map(|coding| coding.trim().to_ascii_lowercase())
                .filter(|coding| !coding.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if !chunked && encodings.is_empty() {
        return None;
    }
    let (mut data, mut capped) = if chunked {
        dechunk(body, limit)?
    } else {
        (body.to_vec(), false)
    };
    // Codings are listed in the order they were applied, so undo them in reverse. A
    // stream cut by the cap cannot be decoded further reliably, so stop there.
    for coding in encodings.iter().rev() {
        if capped {
            break;
        }
        let (next, cut) = inflate(coding, &data, limit)?;
        data = next;
        capped = cut;
    }
    Some(Decoded { data, capped })
}

fn find(matcher: &Matcher, text: &[u8], group: Option<usize>) -> (Vec<(usize, usize)>, bool) {
    let mut ranges = Vec::new();
    match group {
        None | Some(0) => {
            for found in matcher.regex.find_iter(text) {
                if ranges.len() == MATCH_LIMIT {
                    return (ranges, true);
                }
                ranges.push((found.start(), found.end()));
            }
        }
        Some(index) => {
            for captures in matcher.regex.captures_iter(text) {
                if ranges.len() == MATCH_LIMIT {
                    return (ranges, true);
                }
                if let Some(found) = captures.get(index) {
                    ranges.push((found.start(), found.end()));
                }
            }
        }
    }
    (ranges, false)
}

/// Byte range of one part of a message within the project file.
fn range(message: &Message, part: Part) -> (u64, u64) {
    if part.is_headers() {
        (
            message.payload_offset,
            message.body_offset - message.payload_offset,
        )
    } else {
        (message.body_offset, message.body_length)
    }
}

/// Searches the requested parts of `entry`. Only the requested parts are read, each one
/// separately, so a header search never loads a large body.
pub fn search_entry(
    source: &FileSource,
    entry: &HistoryEntry,
    matcher: &Matcher,
    options: &SearchOptions,
) -> Result<EntryMatches> {
    let parts: &[Part] = if options.parts.is_empty() {
        &Part::ALL
    } else {
        &options.parts
    };
    let mut result = EntryMatches::default();
    for part in parts {
        let message = if part.is_request() {
            Some(&entry.request)
        } else {
            entry.response.as_ref()
        };
        let Some(message) = message else {
            continue;
        };
        let (offset, length) = range(message, *part);
        let raw = source.bytes(offset, length)?;
        let (text, decoded) = if options.decode && !part.is_headers() {
            match decode_body(&message.headers, &raw) {
                Some(decoded) => {
                    if decoded.capped {
                        result.capped.push(*part);
                    }
                    (decoded.data, true)
                }
                None => (raw, false),
            }
        } else {
            (raw, false)
        };
        let (ranges, truncated) = find(matcher, &text, options.group);
        if !ranges.is_empty() {
            result.parts.push(PartMatches {
                part: *part,
                text,
                ranges,
                decoded,
                truncated,
            });
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> HttpHeader {
        HttpHeader {
            name: name.to_owned(),
            value: value.to_owned(),
            offset: 0,
            length: 0,
        }
    }

    #[test]
    fn literal_is_escaped_and_case_insensitive_by_default() {
        let matcher = Matcher::new("a.b", false, false).unwrap();
        assert!(matcher.regex().is_match(b"xxA.Byy"));
        assert!(!matcher.regex().is_match(b"aXb"));
        let strict = Matcher::new("A.B", false, true).unwrap();
        assert!(!strict.regex().is_match(b"a.b"));
    }

    #[test]
    fn capture_group_ranges() {
        let matcher = Matcher::new(r"token=([a-z0-9]+)", true, false).unwrap();
        let (ranges, truncated) = find(&matcher, b"x token=abc1 y token=zz9", Some(1));
        assert!(!truncated);
        assert_eq!(ranges, vec![(8, 12), (21, 24)]);
    }

    #[test]
    fn decodes_chunked_gzip() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"hello secret world").unwrap();
        let gz = encoder.finish().unwrap();
        let mut chunked = format!("{:x}\r\n", gz.len()).into_bytes();
        chunked.extend_from_slice(&gz);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let headers = [
            header("Transfer-Encoding", "chunked"),
            header("Content-Encoding", "gzip"),
        ];
        assert_eq!(
            decode_body(&headers, &chunked),
            Some(Decoded {
                data: b"hello secret world".to_vec(),
                capped: false
            })
        );
    }

    #[test]
    fn decode_cap_is_reported_not_silent() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&[b'a'; 4096]).unwrap();
        let gz = encoder.finish().unwrap();
        let headers = [header("Content-Encoding", "gzip")];
        let decoded = decode_body_limited(&headers, &gz, 1000).unwrap();
        assert!(decoded.capped);
        assert_eq!(decoded.data.len(), 1000);
        let exact = decode_body_limited(&headers, &gz, 4096).unwrap();
        assert!(!exact.capped);
    }

    #[test]
    fn dechunk_respects_the_cap() {
        let body = b"a\r\n0123456789\r\n5\r\nabcde\r\n0\r\n\r\n";
        assert_eq!(dechunk(body, 100), Some((b"0123456789abcde".to_vec(), false)));
        assert_eq!(dechunk(body, 12), Some((b"0123456789ab".to_vec(), true)));
        assert_eq!(dechunk(b"zz\r\n", 10), None);
    }

    #[test]
    fn plain_body_is_not_decoded() {
        assert!(decode_body(&[header("Content-Type", "text/plain")], b"abc").is_none());
    }
}
