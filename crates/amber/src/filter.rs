use crate::binary::Fields;
use crate::diagnostic::{Error, Result};
use crate::history::layout::tag;
use crate::model::history::{HistoryEntry, Message};

pub const NO_HIGHLIGHT: &str = "none";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryFilter {
    pub host: Option<String>,
    pub url_contains: Option<String>,
    pub method: Option<String>,
    pub status: Vec<u64>,
    pub since_epoch_ms: Option<u64>,
    pub until_epoch_ms: Option<u64>,
    pub mime_contains: Option<String>,
    pub tool: Option<String>,
    pub comment_contains: Option<String>,
    pub highlight: Option<String>,
    pub entry_id: Option<u64>,
}

fn contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    haystack.len() >= needle.len()
        && (0..=haystack.len() - needle.len())
            .any(|start| haystack[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

fn equals(actual: Option<&str>, wanted: &str) -> bool {
    actual.is_some_and(|value| value.eq_ignore_ascii_case(wanted))
}

impl HistoryFilter {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if let (Some(since), Some(until)) = (self.since_epoch_ms, self.until_epoch_ms)
            && since > until
        {
            return Err(Error::Malformed(format!(
                "time filter is empty: since {since} is after until {until}"
            )));
        }
        if self
            .method
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(Error::Malformed(
                "method filter must not be blank".to_owned(),
            ));
        }
        Ok(())
    }

    fn accepts_scalars(&self, entry_id: u64, status: u64, time: u64, highlight: u64) -> bool {
        self.entry_id.is_none_or(|wanted| wanted == entry_id)
            && (self.status.is_empty() || self.status.contains(&status))
            && self.since_epoch_ms.is_none_or(|since| time >= since)
            && self.until_epoch_ms.is_none_or(|until| time <= until)
            && self
                .highlight
                .as_ref()
                .is_none_or(|wanted| !wanted.eq_ignore_ascii_case(NO_HIGHLIGHT) || highlight == 0)
    }

    pub fn accepts_row(&self, fields: &Fields) -> bool {
        if !fields.contains_key(&tag::ENTRY_ID) {
            return true;
        }
        let value = |tag: u8| fields.get(&tag).map_or(0, |field| field.unsigned);
        self.accepts_scalars(
            value(tag::ENTRY_ID),
            value(tag::STATUS_CODE),
            value(tag::TIME_EPOCH_MS),
            value(tag::HIGHLIGHT),
        )
    }

    pub fn accepts(&self, entry: &HistoryEntry) -> bool {
        if !self.accepts_scalars(
            entry.entry_id,
            entry.status_code.unsigned,
            entry.time_epoch_ms.unsigned,
            entry.highlight.code,
        ) {
            return false;
        }
        if let Some(host) = &self.host
            && !equals(
                entry
                    .service
                    .as_ref()
                    .map(|service| service.host.text.value.as_str()),
                host,
            )
        {
            return false;
        }
        if let Some(needle) = &self.url_contains
            && !contains(entry.request.url.as_deref().unwrap_or_default(), needle)
        {
            return false;
        }
        if let Some(method) = &self.method
            && !equals(entry.request.method.as_deref(), method)
        {
            return false;
        }
        if let Some(needle) = &self.mime_contains
            && !entry
                .response
                .as_ref()
                .and_then(Message::content_type)
                .is_some_and(|value| contains(value, needle))
        {
            return false;
        }
        if let Some(tool) = &self.tool
            && !entry.tool_source.eq_ignore_ascii_case(tool)
        {
            return false;
        }
        if let Some(needle) = &self.comment_contains
            && !contains(&entry.comment.value, needle)
        {
            return false;
        }
        if let Some(wanted) = &self.highlight {
            let actual = entry.highlight.value.as_deref();
            let matches = if wanted.eq_ignore_ascii_case(NO_HIGHLIGHT) {
                actual.is_none()
            } else {
                equals(actual, wanted)
            };
            if !matches {
                return false;
            }
        }
        true
    }
}
