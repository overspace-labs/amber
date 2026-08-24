use std::path::Path;

use base64::Engine;
use sha2::{Digest, Sha256};
use url::Url;

use crate::binary::hex;
use crate::diagnostic::{Error, Result};
use crate::model::history::highlight_code;
use crate::model::input::{BlobInput, HistoryInput, HistoryInputEntry, INPUT_VERSION};

pub const MAX_MESSAGE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Entry {
    pub entry_id: Option<u64>,
    pub host: String,
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

    let request = blob(&entry.request, base)?;
    check_request(&request)?;
    let response = entry
        .response
        .as_ref()
        .map(|blob_input| blob(blob_input, base))
        .transpose()?;
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
        port: url
            .port_or_known_default()
            .unwrap_or(if tls { 443 } else { 80 }),
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
