mod inspect;
mod write;

use std::path::PathBuf;

use amber::{Error, HistoryFilter, Project};
use clap::Args;

pub use inspect::{ExportCommand, ListCommand, ShowCommand};
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
}

impl FilterArgs {
    pub fn build(&self) -> HistoryFilter {
        HistoryFilter {
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
        }
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
