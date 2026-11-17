//! Content search over Proxy history messages, the command-line twin of Burp's
//! "Filter by search term" in Proxy > HTTP history.

use std::io::Read;

use regex::bytes::{Regex, RegexBuilder};
use serde::Serialize;

use crate::binary::FileSource;
use crate::diagnostic::{Error, Result};
use crate::history::decode::message_bytes;
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
    pub truncated: bool,
}

fn header_value<'a>(headers: &'a [HttpHeader], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.trim().eq_ignore_ascii_case(name))
        .map(|header| header.value.trim())
}

fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0usize;
    loop {
        let line_end = memchr::memmem::find(&body[cursor..], b"\r\n")? + cursor;
        let size_text = std::str::from_utf8(&body[cursor..line_end]).ok()?;
        let size_text = size_text.split(';').next()?.trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        cursor = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        let end = cursor.checked_add(size)?;
        if end > body.len() {
            return None;
        }
        out.extend_from_slice(&body[cursor..end]);
        cursor = end + 2;
        if cursor > body.len() {
            return Some(out);
        }
    }
}

fn read_limited(reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(DECODE_LIMIT).read_to_end(&mut out).ok()?;
    Some(out)
}

fn inflate(encoding: &str, data: &[u8]) -> Option<Vec<u8>> {
    match encoding {
        "gzip" | "x-gzip" => read_limited(flate2::read::MultiGzDecoder::new(data)),
        "deflate" => read_limited(flate2::read::ZlibDecoder::new(data))
            .or_else(|| read_limited(flate2::read::DeflateDecoder::new(data))),
        "br" => read_limited(brotli_decompressor::Decompressor::new(data, 64 * 1024)),
        "identity" | "" => Some(data.to_vec()),
        _ => None,
    }
}

/// Returns the body with transfer and content codings removed, or `None` when there was
/// nothing to undo or decoding failed (the caller then searches the stored bytes).
pub fn decode_body(headers: &[HttpHeader], body: &[u8]) -> Option<Vec<u8>> {
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
    let mut data = if chunked {
        dechunk(body).unwrap_or_else(|| body.to_vec())
    } else {
        body.to_vec()
    };
    // Codings are listed in the order they were applied, so undo them in reverse.
    for coding in encodings.iter().rev() {
        data = inflate(coding, &data)?;
    }
    Some(data)
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

fn split(source: &FileSource, message: &Message) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut bytes = message_bytes(source, message)?;
    let head = usize::try_from(message.body_offset - message.payload_offset)
        .map_err(|_| Error::OffsetOverflow)?
        .min(bytes.len());
    let body = bytes.split_off(head);
    Ok((bytes, body))
}

/// Searches the requested parts of `entry`, returning only parts with at least one match.
pub fn search_entry(
    source: &FileSource,
    entry: &HistoryEntry,
    matcher: &Matcher,
    options: &SearchOptions,
) -> Result<Vec<PartMatches>> {
    let parts: &[Part] = if options.parts.is_empty() {
        &Part::ALL
    } else {
        &options.parts
    };
    let mut found = Vec::new();
    let mut request: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut response: Option<(Vec<u8>, Vec<u8>)> = None;

    for part in parts {
        let message = if part.is_request() {
            Some(&entry.request)
        } else {
            entry.response.as_ref()
        };
        let Some(message) = message else {
            continue;
        };
        let cache = if part.is_request() {
            &mut request
        } else {
            &mut response
        };
        if cache.is_none() {
            *cache = Some(split(source, message)?);
        }
        let Some((headers, body)) = cache.as_ref() else {
            continue;
        };
        let (text, decoded) = if part.is_headers() {
            (headers.clone(), false)
        } else if options.decode {
            match decode_body(&message.headers, body) {
                Some(decoded) => (decoded, true),
                None => (body.clone(), false),
            }
        } else {
            (body.clone(), false)
        };
        let (ranges, truncated) = find(matcher, &text, options.group);
        if !ranges.is_empty() {
            found.push(PartMatches {
                part: *part,
                text,
                ranges,
                decoded,
                truncated,
            });
        }
    }
    Ok(found)
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
            decode_body(&headers, &chunked).as_deref(),
            Some(&b"hello secret world"[..])
        );
    }

    #[test]
    fn plain_body_is_not_decoded() {
        assert!(decode_body(&[header("Content-Type", "text/plain")], b"abc").is_none());
    }
}
