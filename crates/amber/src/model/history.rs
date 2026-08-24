use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::binary::{FieldSlice, TextFrame, hex};

pub const DOCUMENT_TYPE: &str = "burp_proxy_http_history";
pub const ORDERING: &str = "entry_id_ascending";
pub const SCAN_MODE: &str = "exact_proxy_row_schema";

pub const HIGHLIGHTS: [(u64, &str); 9] = [
    (1, "red"),
    (2, "orange"),
    (3, "yellow"),
    (4, "green"),
    (5, "cyan"),
    (6, "blue"),
    (7, "pink"),
    (8, "magenta"),
    (9, "gray"),
];

pub fn highlight_name(code: u64) -> Option<String> {
    (code != 0).then(|| {
        HIGHLIGHTS
            .iter()
            .find(|(value, _)| *value == code)
            .map_or_else(|| format!("unknown:{code}"), |(_, name)| (*name).to_owned())
    })
}

pub fn highlight_code(name: &str) -> Option<u64> {
    HIGHLIGHTS
        .iter()
        .find(|(_, colour)| colour.eq_ignore_ascii_case(name))
        .map(|(code, _)| *code)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawField {
    pub offset: u64,
    pub width: u8,
    pub unsigned: u64,
    pub hex: String,
}

impl From<FieldSlice> for RawField {
    fn from(slice: FieldSlice) -> Self {
        let bytes = slice.unsigned.to_be_bytes();
        Self {
            offset: slice.offset,
            width: slice.width,
            unsigned: slice.unsigned,
            hex: hex(&bytes[8 - usize::from(slice.width)..]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostText {
    #[serde(flatten)]
    pub text: TextFrame,
    pub wrapper_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortValue {
    pub value: u64,
    pub offset: u64,
    pub width: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsValue {
    pub value: bool,
    pub offset: u64,
    pub width: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub host: HostText,
    pub port: PortValue,
    pub tls: TlsValue,
    pub service_offset: u64,
    pub request_metadata_offset: u64,
}

impl Service {
    pub const fn scheme(&self) -> &'static str {
        if self.tls.value { "https" } else { "http" }
    }

    pub fn authority(&self) -> String {
        let default = if self.tls.value { 443 } else { 80 };
        if self.port.value == default {
            self.host.text.value.clone()
        } else {
            format!("{}:{}", self.host.text.value, self.port.value)
        }
    }

    pub fn url(&self, target: &str) -> String {
        if target.starts_with("http://") || target.starts_with("https://") {
            return target.to_owned();
        }
        format!("{}://{}{target}", self.scheme(), self.authority())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub frame_offset: u64,
    pub payload_offset: u64,
    pub length: u64,
    pub sha256: String,
    pub headers: Vec<HttpHeader>,
    pub body_offset: u64,
    pub body_length: u64,
    pub body_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub http_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub blob: Option<String>,
}

impl Message {
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| header.value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentChunk {
    #[serde(flatten)]
    pub text: TextFrame,
    pub object_offset: u64,
    pub length_field_offset: u64,
    pub next_field_offset: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    pub value: String,
    pub wrapper_offset: Option<u64>,
    pub chunks: Vec<CommentChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Highlight {
    pub value: Option<String>,
    pub code: u64,
    pub offset: u64,
    pub width: u8,
}

impl From<FieldSlice> for Highlight {
    fn from(slice: FieldSlice) -> Self {
        Self {
            value: highlight_name(slice.unsigned),
            code: slice.unsigned,
            offset: slice.offset,
            width: slice.width,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    pub value_1: RawField,
    pub value_2: RawField,
    pub secondary_time_epoch_ms: RawField,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validation {
    pub service_decoded: bool,
    pub status_matches: bool,
    pub response_length_matches: bool,
    pub listener_port_valid: bool,
    pub entry_id_valid: bool,
}

impl Validation {
    pub const fn is_complete(self) -> bool {
        self.service_decoded
            && self.status_matches
            && self.response_length_matches
            && self.listener_port_valid
            && self.entry_id_valid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub ordinal: u64,
    pub entry_id: u64,
    pub row_offset: u64,
    pub tool_source: String,
    pub service: Option<Service>,
    pub request: Message,
    pub response: Option<Message>,
    pub status_code: RawField,
    pub burp_mime_code: RawField,
    pub response_length: RawField,
    pub time_epoch_ms: RawField,
    pub listener_port: RawField,
    pub highlight: Highlight,
    pub comment: Comment,
    pub timing: Timing,
    pub raw_fields: BTreeMap<String, RawField>,
    pub validation: Validation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub header_hex: String,
    pub header_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub proxy_history_entry_count: u64,
    pub proxy_history_complete: bool,
    pub scan_mode: String,
}
