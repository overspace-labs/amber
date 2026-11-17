mod hosts;
mod inspect;
mod search;
mod trim;
mod write;

use std::path::PathBuf;

use amber::{Error, HistoryFilter, HostScope, Project};
use clap::Args;

pub use hosts::HostsCommand;
pub use inspect::{ExportCommand, ListCommand, ShowCommand};
pub use search::SearchCommand;
pub use trim::TrimCommand;
pub use write::{AppendCommand, CreateCommand};

pub fn is_broken_pipe(error: &Error) -> bool {
    let kind = match error {
        Error::Io(io) => Some(io.kind()),
        Error::Json(json) => json.io_error_kind(),
        _ => None,
    };
    kind == Some(std::io::ErrorKind::BrokenPipe)
}

pub fn warn_unknown_header(project: &Project) {
    if !project.header_match() {
        eprintln!(
            "warning: project header is not the supported Burp grammar; results may be empty"
        );
    }
}

pub fn exit_code(error: &Error) -> u8 {
    match error {
        Error::Io(_) => 2,
        Error::Json(_)
        | Error::Malformed(_)
        | Error::OutOfBounds { .. }
        | Error::ShortRead { .. }
        | Error::InvalidUtf16 { .. } => 3,
        Error::ResourceLimit { .. } => 4,
        Error::DestinationExists(_) => 5,
        Error::OffsetOverflow => 70,
    }
}

#[derive(Debug, Clone, Args)]
pub struct FilterArgs {
    /// Exact host match, case-insensitive.
    #[arg(short = 'H', long)]
    pub host: Option<String>,
    /// Case-insensitive substring of the absolute URL.
    #[arg(short, long)]
    pub url: Option<String>,
    /// Exact request method, case-insensitive.
    #[arg(short = 'X', long)]
    pub method: Option<String>,
    /// Keep entries whose stored status is any of these values.
    #[arg(short, long, value_name = "CODE")]
    pub status: Vec<u64>,
    /// Lower bound on the stored request time, in epoch milliseconds.
    #[arg(short = 'S', long, value_name = "EPOCH_MS")]
    pub since: Option<u64>,
    /// Upper bound on the stored request time, in epoch milliseconds.
    #[arg(short = 'U', long, value_name = "EPOCH_MS")]
    pub until: Option<u64>,
    /// Case-insensitive substring of the response Content-Type header.
    #[arg(short, long)]
    pub mime: Option<String>,
    /// Exact tool source, case-insensitive.
    #[arg(short, long)]
    pub tool: Option<String>,
    /// Case-insensitive substring of the entry comment.
    #[arg(short, long)]
    pub comment: Option<String>,
    /// Highlight colour, or `none` for unhighlighted entries.
    #[arg(short = 'l', long)]
    pub highlight: Option<String>,
    /// In-scope host pattern: `example.com` matches it and every subdomain, `*` globs,
    /// a leading `!` excludes. Repeatable; combined with --scope-file.
    #[arg(long, value_name = "PATTERN")]
    pub scope_host: Vec<String>,
    /// File of host patterns, one per line (`#` comments, `!` excludes).
    #[arg(long, value_name = "FILE")]
    pub scope_file: Option<PathBuf>,
}

impl FilterArgs {
    pub fn build(&self) -> amber::Result<HistoryFilter> {
        let mut scope = match &self.scope_file {
            Some(path) => Some(HostScope::from_file(path)?),
            None => None,
        };
        if !self.scope_host.is_empty() {
            let patterns = self.scope_host.iter().map(String::as_str);
            match scope.as_mut() {
                Some(existing) => existing.extend(patterns)?,
                None => scope = Some(HostScope::parse(patterns)?),
            }
        }
        Ok(HistoryFilter {
            host: self.host.clone(),
            url_contains: self.url.clone(),
            method: self.method.clone(),
            status: self.status.clone(),
            since_epoch_ms: self.since,
            until_epoch_ms: self.until,
            mime_contains: self.mime.clone(),
            tool: self.tool.clone(),
            comment_contains: self.comment.clone(),
            highlight: self.highlight.clone(),
            entry_id: None,
            scope,
        })
    }
}

#[derive(Debug, Clone, Args)]
pub struct Destination {
    /// Path to write; existing files are kept unless `--force` is given.
    #[arg(short, long)]
    pub output: PathBuf,
    /// Overwrite `--output` if it already exists.
    #[arg(short, long)]
    pub force: bool,
}

/// Duplicate rule, shared by `hosts`, `search` and `trim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DedupeArg {
    /// Keep everything.
    None,
    /// Same method, URL, request body, caller identity, status and response body.
    Session,
    /// Like `session` but ignoring who sent it.
    Any,
    /// Same method, URL and request body; response ignored.
    Endpoint,
}

impl From<DedupeArg> for amber::DedupeMode {
    fn from(value: DedupeArg) -> Self {
        match value {
            DedupeArg::None => Self::None,
            DedupeArg::Session => Self::Session,
            DedupeArg::Any => Self::Any,
            DedupeArg::Endpoint => Self::Endpoint,
        }
    }
}

#[allow(clippy::cast_precision_loss)]
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Renders bytes for a one-line terminal display: lossy UTF-8 with CR, LF and tab escaped.
pub fn printable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| match character {
            '\r' => "\\r".to_owned(),
            '\n' => "\\n".to_owned(),
            '\t' => "\\t".to_owned(),
            other if other.is_control() => format!("\\x{:02x}", u32::from(other)),
            other => other.to_string(),
        })
        .collect()
}
