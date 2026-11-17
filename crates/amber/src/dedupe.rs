//! Duplicate detection for Proxy history entries.
//!
//! A key is a SHA-256 over the parts of an exchange that make it "the same call". Every
//! mode keys on the request body and (except `Endpoint`) the response body by their stored
//! digests, so no message is read again here.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::model::history::{HistoryEntry, HttpHeader, Message};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DedupeMode {
    /// Keep everything.
    None,
    /// Same method, URL, request body, caller identity (`Authorization` + session cookies),
    /// status and response body. Static assets ignore the identity part.
    #[default]
    Session,
    /// Same method, URL, request body, status and response body, whoever sent it.
    Any,
    /// Same method, URL and request body; the response is ignored.
    Endpoint,
}

pub type DedupeKey = [u8; 32];

const STATIC_EXTENSIONS: &[&str] = &[
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp",
    "woff", "woff2", "ttf", "otf", "eot",
];

const STATIC_MIME_FRAGMENTS: &[&str] = &[
    "javascript",
    "ecmascript",
    "text/css",
    "image/",
    "font/",
    "application/font",
    "application/x-font",
    "woff",
];

/// Cookie names (exact, lower-case) that carry analytics or bot-management state rather
/// than a session. They change on nearly every request and would defeat deduplication.
const VOLATILE_COOKIES: &[&str] = &[
    "rt", "mbox", "at_check", "muid", "ai_session", "ai_user", "ak_bmsc", "_abck", "bm_sv",
    "bm_sz", "bm_mi", "_fbp", "_gid", "_gat", "optanonconsent", "optanonalertboxclosed",
];

/// Cookie name prefixes (lower-case) treated the same way.
const VOLATILE_COOKIE_PREFIXES: &[&str] = &[
    "_ga", "_gcl_", "_uet", "_clck", "_clsk", "_hj", "s_", "amcv_", "amcvs_", "utag_", "notice_",
    "bm_", "_dd_s", "_pk_",
];

fn header_values<'a>(headers: &'a [HttpHeader], name: &'a str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |header| header.name.trim().eq_ignore_ascii_case(name))
        .map(|header| header.value.trim())
}

fn volatile_cookie(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    VOLATILE_COOKIES.contains(&name.as_str())
        || VOLATILE_COOKIE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// The OCI request-signing scheme (`Signature ... keyId="..."`) signs the date, so the
/// header differs on every call; the key id is the stable caller identity.
fn authorization_identity(value: &str) -> String {
    let lowered = value.to_ascii_lowercase();
    if lowered.starts_with("signature ") {
        if let Some(start) = lowered.find("keyid=\"") {
            let rest = &value[start + 7..];
            if let Some(end) = rest.find('"') {
                return format!("signature-key:{}", &rest[..end]);
            }
        }
    }
    value.to_owned()
}

/// Caller identity: normalised `Authorization` values plus the non-volatile cookies,
/// sorted so header order and cookie order do not matter.
pub fn identity(request: &Message) -> String {
    let mut parts: Vec<String> = header_values(&request.headers, "authorization")
        .map(authorization_identity)
        .collect();
    let mut cookies: Vec<&str> = header_values(&request.headers, "cookie")
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| !volatile_cookie(pair.split('=').next().unwrap_or_default().trim()))
        .collect();
    cookies.sort_unstable();
    parts.push(cookies.join("; "));
    parts.join("\n")
}

/// True when the exchange is a static asset (script, style, image, font, source map),
/// judged by the response `Content-Type` or else the URL path extension.
pub fn is_static(entry: &HistoryEntry) -> bool {
    if let Some(content_type) = entry.response.as_ref().and_then(Message::content_type) {
        let content_type = content_type.to_ascii_lowercase();
        if STATIC_MIME_FRAGMENTS
            .iter()
            .any(|fragment| content_type.contains(fragment))
        {
            return true;
        }
    }
    let target = entry.request.target.as_deref().unwrap_or_default();
    let path = target.split(['?', '#']).next().unwrap_or_default();
    let segment = path.rsplit('/').next().unwrap_or_default();
    segment.rsplit_once('.').is_some_and(|(_, extension)| {
        STATIC_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
    })
}

fn field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Computes the key for `entry` under `mode`, or `None` for `DedupeMode::None`.
pub fn key(entry: &HistoryEntry, mode: DedupeMode) -> Option<DedupeKey> {
    if mode == DedupeMode::None {
        return None;
    }
    let mut hasher = Sha256::new();
    field(
        &mut hasher,
        entry.request.method.as_deref().unwrap_or_default().as_bytes(),
    );
    let url = entry
        .request
        .url
        .as_deref()
        .or(entry.request.target.as_deref())
        .unwrap_or_default();
    field(&mut hasher, url.as_bytes());
    field(&mut hasher, entry.request.body_sha256.as_bytes());
    if mode == DedupeMode::Session && !is_static(entry) {
        field(&mut hasher, identity(&entry.request).as_bytes());
    }
    if mode != DedupeMode::Endpoint {
        match entry.response.as_ref() {
            Some(response) => {
                field(&mut hasher, &entry.status_code.unsigned.to_be_bytes());
                field(&mut hasher, response.body_sha256.as_bytes());
            }
            None => field(&mut hasher, b"<no response>"),
        }
    }
    Some(hasher.finalize().into())
}

/// Remembers the first entry seen for each key.
#[derive(Debug, Default)]
pub struct Deduper {
    mode: DedupeMode,
    seen: HashMap<DedupeKey, u64>,
}

impl Deduper {
    pub fn new(mode: DedupeMode) -> Self {
        Self {
            mode,
            seen: HashMap::new(),
        }
    }

    /// Returns the entry id of an earlier identical exchange, or records this entry as the
    /// first of its kind and returns `None`.
    pub fn check(&mut self, entry: &HistoryEntry) -> Option<u64> {
        let key = key(entry, self.mode)?;
        if let Some(first) = self.seen.get(&key) {
            return Some(*first);
        }
        self.seen.insert(key, entry.entry_id);
        None
    }
}
