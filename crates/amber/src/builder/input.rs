use std::path::Path;

use base64::Engine;
use sha2::{Digest, Sha256};
use url::Url;

use crate::binary::hex;
use crate::builder::fields::equal_fold_ascii;
use crate::diagnostic::{Error, Result};
use crate::model::history::highlight_code;
use crate::model::input::{BlobInput, HistoryInput, HistoryInputEntry, INPUT_VERSION};

pub const MAX_MESSAGE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Entry {
    pub entry_id: Option<u64>,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub tls: bool,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub status: u16,
    pub comment: String,
    pub highlight: Option<String>,
    pub time_epoch_ms: u64,
    pub listener_port: u16,
}

pub fn load(path: &Path) -> Result<Vec<Entry>> {
    let document: HistoryInput = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    if document.schema_version != INPUT_VERSION {
        return Err(Error::Malformed(format!(
            "unsupported input schema_version {}; expected {INPUT_VERSION}",
            document.schema_version
        )));
    }
    let base = path.parent().unwrap_or(Path::new("."));
    document
        .entries
        .iter()
        .enumerate()
        .map(|(ordinal, entry)| prepare(&document, entry, ordinal as u64, base))
        .collect()
}

fn prepare(
    document: &HistoryInput,
    entry: &HistoryInputEntry,
    ordinal: u64,
    base: &Path,
) -> Result<Entry> {
    let url = Url::parse(&entry.url)
        .map_err(|error| Error::Malformed(format!("invalid url {}: {error}", entry.url)))?;
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        other => {
            return Err(Error::Malformed(format!(
                "unsupported url scheme {other}; Proxy history is http or https"
            )));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| Error::Malformed(format!("url {} has no host", entry.url)))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .unwrap_or(if tls { 443 } else { 80 });

    let request = blob(&entry.request, base)?;
    check_request(&request)?;
    // Burp Proxy history stores origin-form HTTP/1.x; normalize the captured
    // text (mitmproxy's HTTP/2 assembly yields absolute-form HTTP/2.0 with no
    // Host header). Well-formed requests are returned byte-for-byte unchanged.
    let request = normalize_request(&request, &host, port, tls);
    let response = entry
        .response
        .as_ref()
        .map(|blob_input| blob(blob_input, base))
        .transpose()?
        .map(|payload| normalize_response(&payload));
    let status = response
        .as_deref()
        .map(status_code)
        .transpose()?
        .unwrap_or(0);
    let defaults = document.resolved_defaults(ordinal, entry);
    let highlight = document.resolved_highlight(entry);
    if let Some(name) = highlight
        && highlight_code(name).is_none()
    {
        return Err(Error::Malformed(format!("unknown highlight colour {name}")));
    }

    Ok(Entry {
        entry_id: entry.entry_id,
        host,
        ip: document.resolved_ip(entry).to_owned(),
        port,
        tls,
        request,
        response,
        status,
        comment: document.resolved_comment(entry).to_owned(),
        highlight: highlight.map(str::to_owned),
        time_epoch_ms: defaults.time_epoch_ms,
        listener_port: defaults.listener_port,
    })
}

fn blob(input: &BlobInput, base: &Path) -> Result<Vec<u8>> {
    match input {
        BlobInput::Base64 { base64 } => base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|error| Error::Malformed(format!("invalid base64 message: {error}"))),
        BlobInput::File {
            path,
            length,
            sha256,
        } => {
            let resolved = base.join(path);
            let size = std::fs::metadata(&resolved)?.len();
            if size > MAX_MESSAGE_BYTES {
                return Err(Error::ResourceLimit {
                    resource: "raw message",
                    requested: size,
                    limit: MAX_MESSAGE_BYTES,
                });
            }
            let bytes = std::fs::read(&resolved)?;
            if length.is_some_and(|expected| expected != bytes.len() as u64) {
                return Err(Error::Malformed(format!(
                    "{path}: declared length does not match {} bytes read",
                    bytes.len()
                )));
            }
            if let Some(expected) = sha256 {
                let actual = hex(&Sha256::digest(&bytes));
                if !actual.eq_ignore_ascii_case(expected) {
                    return Err(Error::Malformed(format!(
                        "{path}: declared sha256 {expected} but content hashes to {actual}"
                    )));
                }
            }
            Ok(bytes)
        }
    }
}

fn line_end(bytes: &[u8]) -> usize {
    memchr::memmem::find(bytes, b"\r\n").unwrap_or(bytes.len())
}

fn check_request(request: &[u8]) -> Result<()> {
    if request.is_empty() {
        return Err(Error::Malformed("raw request is empty".to_owned()));
    }
    let end = memchr::memmem::find(request, b"\r\n")
        .ok_or_else(|| Error::Malformed("raw request has no CRLF request line".to_owned()))?;
    if request[..end].split(|byte| *byte == b' ').count() < 3 {
        return Err(Error::Malformed(
            "raw request line is not `METHOD TARGET VERSION`".to_owned(),
        ));
    }
    Ok(())
}

fn status_code(response: &[u8]) -> Result<u16> {
    let line = &response[..line_end(response)];
    if !line.starts_with(b"HTTP/") {
        return Err(Error::Malformed(
            "raw response does not start with an HTTP status line".to_owned(),
        ));
    }
    line.split(|byte| *byte == b' ')
        .nth(1)
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| Error::Malformed("raw response status code is not a number".to_owned()))
}

// normalizeRequest rewrites a captured request into the origin-form HTTP/1.x
// shape Burp Suite stores in Proxy history. mitmproxy's HTTP/2 text assembly
// yields an absolute-form target, an "HTTP/2.0" version line and no Host
// header; the canonical Burp form is "METHOD /path HTTP/1.1" plus a Host
// header. A request that is already well-formed comes back byte-for-byte
// unchanged, so existing round-trips are unaffected.
fn normalize_request(request: &[u8], host: &str, port: u16, tls: bool) -> Vec<u8> {
    let Some(line_end) = memchr::memmem::find(request, b"\r\n") else {
        return request.to_vec();
    };
    let parts: Vec<&[u8]> = request[..line_end].splitn(3, |byte| *byte == b' ').collect();
    if parts.len() != 3 {
        return request.to_vec();
    }

    let version = parts[2];
    let mut new_version = version.to_vec();
    let mut changed = version != b"HTTP/1.1" && version != b"HTTP/1.0";
    if changed {
        new_version = b"HTTP/1.1".to_vec();
    }
    let target = parts[1];
    let mut new_target = target.to_vec();
    if target.starts_with(b"http://") || target.starts_with(b"https://") {
        if let Ok(text) = std::str::from_utf8(target)
            && let Ok(parsed) = Url::parse(text)
        {
            let mut uri = parsed.path().to_owned();
            if uri.is_empty() {
                uri.push('/');
            }
            if let Some(query) = parsed.query() {
                uri.push('?');
                uri.push_str(query);
            }
            new_target = uri.into_bytes();
            changed = true;
        }
    }

    let (kept, has_host, body, dropped) = scan_headers(request, line_end, true);
    if dropped {
        changed = true;
    }
    if !has_host {
        changed = true;
    }
    if !changed {
        return request.to_vec();
    }

    let mut out = Vec::with_capacity(request.len() + 16);
    out.extend_from_slice(parts[0]);
    out.push(b' ');
    out.extend_from_slice(&new_target);
    out.push(b' ');
    out.extend_from_slice(&new_version);
    out.extend_from_slice(b"\r\n");
    if !has_host {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(authority(host, port, tls).as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for header in kept {
        out.extend_from_slice(header);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

// canonical_version maps an HTTP version token to the form Burp Suite stores.
// HTTP/1.x tokens pass through unchanged; a spurious minor version on HTTP/2 or
// HTTP/3 ("HTTP/2.0") collapses to the major-only token, and anything
// unrecognized falls back to HTTP/1.1. The second return reports whether the
// token was rewritten.
fn canonical_version(version: &[u8]) -> (Vec<u8>, bool) {
    if version == b"HTTP/1.1" || version == b"HTTP/1.0" {
        return (version.to_vec(), false);
    }
    if version.starts_with(b"HTTP/2") {
        return (b"HTTP/2".to_vec(), version != b"HTTP/2");
    }
    if version.starts_with(b"HTTP/3") {
        return (b"HTTP/3".to_vec(), version != b"HTTP/3");
    }
    (b"HTTP/1.1".to_vec(), true)
}

// normalize_response canonicalizes a response status line and drops any HTTP/2
// pseudo-headers, mirroring normalize_request. Real Burp Suite keeps the major
// version marker for HTTP/2 responses, so "HTTP/2.0" becomes "HTTP/2" (and
// "HTTP/3.0" becomes "HTTP/3"); HTTP/1.x lines and already-canonical responses
// come back unchanged.
fn normalize_response(response: &[u8]) -> Vec<u8> {
    let Some(line_end) = memchr::memmem::find(response, b"\r\n") else {
        return response.to_vec();
    };
    let line = &response[..line_end];
    if !line.starts_with(b"HTTP/") {
        return response.to_vec();
    }
    let parts: Vec<&[u8]> = line.splitn(3, |byte| *byte == b' ').collect();
    if parts.len() < 2 {
        return response.to_vec();
    }
    let (new_version, mut changed) = canonical_version(parts[0]);
    let (kept, _, body, dropped) = scan_headers(response, line_end, false);
    if dropped {
        changed = true;
    }
    if !changed {
        return response.to_vec();
    }

    let mut out = Vec::with_capacity(response.len() + 16);
    out.extend_from_slice(&new_version);
    out.push(b' ');
    out.extend_from_slice(parts[1]);
    if let Some(rest) = parts.get(2) {
        out.push(b' ');
        out.extend_from_slice(rest);
    }
    out.extend_from_slice(b"\r\n");
    for header in kept {
        out.extend_from_slice(header);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

// scan_headers walks the header block that starts at line_end+2, collecting
// every header line (HTTP/2 pseudo-headers starting with ':' are dropped) and
// the message body. When want_host is set it reports whether a Host header was
// seen.
fn scan_headers<'a>(
    message: &'a [u8],
    line_end: usize,
    want_host: bool,
) -> (Vec<&'a [u8]>, bool, &'a [u8], bool) {
    let mut kept = Vec::new();
    let mut has_host = false;
    let mut dropped = false;
    let mut scan = line_end + 2;
    let body = loop {
        if scan >= message.len() {
            break &message[scan..];
        }
        let Some(rel) = memchr::memmem::find(&message[scan..], b"\r\n") else {
            break &message[scan..];
        };
        let line_end = scan + rel;
        if line_end == scan {
            break &message[scan + 2..];
        }
        let header = &message[scan..line_end];
        if header[0] == b':' {
            dropped = true;
            scan = line_end + 2;
            continue;
        }
        if want_host && !has_host {
            if let Some(colon) = header.iter().position(|byte| *byte == b':') {
                if colon > 0 && equal_fold_ascii(&header[..colon], b"host") {
                    has_host = true;
                }
            }
        }
        kept.push(header);
        scan = line_end + 2;
    };
    (kept, has_host, body, dropped)
}

// authority renders the Host header value, omitting the default port for the
// scheme.
fn authority(host: &str, port: u16, tls: bool) -> String {
    if (tls && port == 443) || (!tls && port == 80) {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}
