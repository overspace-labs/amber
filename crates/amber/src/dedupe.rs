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

/// Media types (type/subtype, parameters stripped) treated as static assets.
fn static_media_type(media: &str) -> bool {
    media.starts_with("image/")
        || media.starts_with("font/")
        || media.starts_with("application/font")
        || media.starts_with("application/x-font")
        || matches!(
            media,
            "text/css"
                | "text/javascript"
                | "application/javascript"
                | "application/x-javascript"
                | "application/ecmascript"
                | "text/ecmascript"
                | "application/vnd.ms-fontobject"
                | "application/json+sourcemap"
        )
}

/// Analytics, consent and bot-management cookies (exact names, lower-case). They change
/// on nearly every request and would defeat deduplication. The list is deliberately
/// literal: a broad prefix such as `s_` or `_ga` would also swallow real session cookies
/// (`s_session`, `_gateway_session`).
const VOLATILE_COOKIES: &[&str] = &[
    // Google Analytics / Ads
    "_ga", "_gid", "_gat", "_gcl_au", "_gcl_aw", "_gcl_dc",
    // Adobe Analytics / Target
    "s_cc", "s_sq", "s_vi", "s_fid", "s_nr", "s_ppv", "s_ips", "s_tp", "s_plt", "s_pltp",
    "s_ecid", "mbox", "at_check",
    // Akamai bot manager / mPulse
    "ak_bmsc", "_abck", "bm_sv", "bm_sz", "bm_mi", "bm_so", "bm_ss", "bm_s", "bm_lso", "rt",
    // Consent managers
    "optanonconsent", "optanonalertboxclosed", "notice_behavior", "notice_gdpr_prefs",
    "notice_preferences", "notice_poptime", "cmapi_cookie_privacy", "cmapi_gtm_bl",
    "trustarc_consent",
    // Microsoft / Bing / Clarity / App Insights
    "muid", "_uetsid", "_uetvid", "_clck", "_clsk", "ai_session", "ai_user",
    // Others
    "_fbp", "_hjid", "_dd_s", "utag_main",
];

/// Cookie name shapes that are analytics by construction: a fixed prefix followed by a
/// generated id (`_ga_<container>`, `AMCV_<org>@AdobeOrg`, `_pk_id.<site>.<hash>`).
fn volatile_cookie_shape(name: &str) -> bool {
    (name.starts_with("_ga_") && name.len() > 4)
        || ((name.starts_with("amcv_") || name.starts_with("amcvs_")) && name.ends_with("@adobeorg"))
        || name.starts_with("_pk_id.")
        || name.starts_with("_pk_ses.")
        || name.starts_with("_hjsessionuser_")
        || name.starts_with("_hjsession_")
}

fn header_values<'a>(headers: &'a [HttpHeader], name: &'a str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |header| header.name.trim().eq_ignore_ascii_case(name))
        .map(|header| header.value.trim())
}

fn volatile_cookie(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    VOLATILE_COOKIES.contains(&name.as_str()) || volatile_cookie_shape(&name)
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
    let mut cookies: Vec<(&str, &str)> = header_values(&request.headers, "cookie")
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .map(|pair| (pair.split('=').next().unwrap_or_default().trim(), pair))
        .filter(|(name, _)| !volatile_cookie(name))
        .collect();
    // Order by name only, and stably: `a=1; a=2` and `a=2; a=1` stay different callers,
    // because servers usually honour the first occurrence of a repeated name.
    cookies.sort_by_key(|(name, _)| *name);
    let cookies: Vec<&str> = cookies.into_iter().map(|(_, pair)| pair).collect();
    parts.push(cookies.join("; "));
    parts.join("\n")
}

/// True when the exchange is a static asset (script, style, image, font, source map),
/// judged by the response `Content-Type` or else the URL path extension.
pub fn is_static(entry: &HistoryEntry) -> bool {
    if let Some(content_type) = entry.response.as_ref().and_then(Message::content_type) {
        let media = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if static_media_type(&media) {
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
    // When the request line or header block was not parsed (malformed, or headers over
    // the decoder's 1 MiB parse limit), method/URL/identity are unknown: key on the whole
    // raw request so only byte-identical requests can collide.
    let parsed = entry.request.method.is_some() && !entry.request.headers.is_empty();
    if !parsed {
        field(&mut hasher, b"<unparsed request>");
        field(&mut hasher, entry.request.sha256.as_bytes());
    }
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
                if response.status_code.is_none() {
                    // Unparsed status line: the header/body split is unreliable.
                    field(&mut hasher, response.sha256.as_bytes());
                }
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

    /// Looks `entry` up without recording it: the id of an earlier recorded identical
    /// exchange (if any) and the entry's key (`None` when deduplication is off).
    pub fn find(&self, entry: &HistoryEntry) -> (Option<u64>, Option<DedupeKey>) {
        let Some(key) = key(entry, self.mode) else {
            return (None, None);
        };
        (self.seen.get(&key).copied(), Some(key))
    }

    /// Records `entry_id` as the first of its kind for `key`, unless one is recorded.
    pub fn record(&mut self, key: DedupeKey, entry_id: u64) {
        self.seen.entry(key).or_insert(entry_id);
    }

    /// Returns the entry id of an earlier identical exchange, or records this entry as the
    /// first of its kind and returns `None`.
    pub fn check(&mut self, entry: &HistoryEntry) -> Option<u64> {
        let (first, key) = self.find(entry);
        if first.is_none() {
            if let Some(key) = key {
                self.record(key, entry.entry_id);
            }
        }
        first
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(headers: &[(&str, &str)]) -> Message {
        Message {
            frame_offset: 0,
            payload_offset: 0,
            length: 0,
            sha256: "req".to_owned(),
            headers: headers
                .iter()
                .map(|(name, value)| HttpHeader {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                    offset: 0,
                    length: 0,
                })
                .collect(),
            body_offset: 0,
            body_length: 0,
            body_sha256: String::new(),
            method: Some("GET".to_owned()),
            target: Some("/".to_owned()),
            http_version: Some("HTTP/1.1".to_owned()),
            status_code: None,
            reason: None,
            url: None,
            blob: None,
        }
    }

    #[test]
    fn analytics_cookies_are_ignored_but_lookalike_session_cookies_are_not() {
        let a = identity(&request(&[("Cookie", "_ga=1; _ga_ABC123=2; s_cc=true; sid=X")]));
        let b = identity(&request(&[("Cookie", "_ga=9; _ga_ABC123=8; s_cc=false; sid=X")]));
        assert_eq!(a, b);
        for name in ["_gateway_session", "s_session", "notice_session", "bm_auth"] {
            let one = identity(&request(&[("Cookie", &format!("{name}=A"))]));
            let two = identity(&request(&[("Cookie", &format!("{name}=B"))]));
            assert_ne!(one, two, "{name} must count as identity");
        }
    }

    #[test]
    fn cookie_order_is_ignored_except_between_repeats_of_a_name() {
        let a = identity(&request(&[("Cookie", "b=2; a=1")]));
        let b = identity(&request(&[("Cookie", "a=1; b=2")]));
        assert_eq!(a, b);
        let first = identity(&request(&[("Cookie", "session=A; session=B")]));
        let second = identity(&request(&[("Cookie", "session=B; session=A")]));
        assert_ne!(first, second);
    }

    #[test]
    fn oci_signature_identity_is_the_key_id() {
        let one = identity(&request(&[(
            "Authorization",
            r#"Signature version="1",keyId="ocid1.tenancy/user/fp",signature="aaa""#,
        )]));
        let two = identity(&request(&[(
            "authorization",
            r#"Signature version="1",keyId="ocid1.tenancy/user/fp",signature="bbb""#,
        )]));
        assert_eq!(one, two);
        let bearer_a = identity(&request(&[("Authorization", "Bearer a")]));
        let bearer_b = identity(&request(&[("Authorization", "Bearer b")]));
        assert_ne!(bearer_a, bearer_b);
    }

    #[test]
    fn media_type_parameters_do_not_make_a_response_static() {
        assert!(static_media_type("image/png"));
        assert!(static_media_type("application/javascript"));
        assert!(!static_media_type("application/json"));
        let parsed = "application/json; profile=\"https://example.com/image/profile\""
            .split(';')
            .next()
            .unwrap();
        assert!(!static_media_type(parsed));
    }
}
