use serde::{Deserialize, Serialize};

pub const INPUT_VERSION: u32 = 1;

pub const DEFAULT_TIME_EPOCH_MS: u64 = 946_684_800_000;
pub const DEFAULT_LISTENER_PORT: u16 = 8080;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryInput {
    pub schema_version: u32,
    #[serde(default)]
    pub defaults: InputDefaults,
    pub entries: Vec<HistoryInputEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputDefaults {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub time_epoch_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub listener_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub highlight: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryInputEntry {
    pub url: String,
    pub request: BlobInput,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub response: Option<BlobInput>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entry_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub time_epoch_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub listener_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub highlight: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlobInput {
    File {
        path: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        length: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        sha256: Option<String>,
    },
    Base64 {
        base64: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedDefaults {
    pub time_epoch_ms: u64,
    pub listener_port: u16,
}

impl HistoryInput {
    pub fn resolved_defaults(&self, ordinal: u64, entry: &HistoryInputEntry) -> ResolvedDefaults {
        ResolvedDefaults {
            time_epoch_ms: entry
                .time_epoch_ms
                .or(self.defaults.time_epoch_ms)
                .unwrap_or(DEFAULT_TIME_EPOCH_MS + ordinal),
            listener_port: entry
                .listener_port
                .or(self.defaults.listener_port)
                .unwrap_or(DEFAULT_LISTENER_PORT),
        }
    }

    pub fn resolved_comment<'a>(&'a self, entry: &'a HistoryInputEntry) -> &'a str {
        entry
            .comment
            .as_deref()
            .or(self.defaults.comment.as_deref())
            .unwrap_or("")
    }

    pub fn resolved_highlight<'a>(&'a self, entry: &'a HistoryInputEntry) -> Option<&'a str> {
        entry
            .highlight
            .as_deref()
            .or(self.defaults.highlight.as_deref())
            .filter(|value| !value.is_empty())
    }
}
