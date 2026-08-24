use std::path::PathBuf;

use amber::model::input::{
    BlobInput, DEFAULT_LISTENER_PORT, DEFAULT_TIME_EPOCH_MS, HistoryInput, HistoryInputEntry,
    INPUT_VERSION, InputDefaults,
};
use amber::{Error, Result, WriteOptions, WriteSummary, append, create, load};
use clap::Args;

use super::Destination;

#[derive(Debug, Args)]
pub struct CreateCommand {
    /// JSON document with URL plus raw request and optional raw response per entry.
    #[arg(required_unless_present = "example")]
    pub input: Option<PathBuf>,
    /// Path to write; existing files are kept unless `--force` is given.
    #[arg(short, long, required_unless_present = "example")]
    pub output: Option<PathBuf>,
    /// Overwrite `--output` if it already exists.
    #[arg(short, long)]
    pub force: bool,
    /// Project name Burp will show; defaults to the name in the embedded model.
    #[arg(short, long)]
    pub name: Option<String>,
    /// Print a starter input document to stdout and exit.
    #[arg(short, long, conflicts_with_all = ["input", "output", "force", "name"])]
    pub example: bool,
}

impl CreateCommand {
    pub fn run(&self) -> Result<()> {
        if self.example {
            println!("{}", serde_json::to_string_pretty(&example())?);
            return Ok(());
        }
        let (Some(input), Some(output)) = (&self.input, &self.output) else {
            return Err(Error::Malformed(
                "create needs <INPUT> and --output".to_owned(),
            ));
        };
        report(&create(
            output,
            &load(input)?,
            &WriteOptions {
                force: self.force,
                name: self.name.clone(),
            },
        )?);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct AppendCommand {
    /// Existing Burp project to read; it is never modified.
    pub project: PathBuf,
    /// JSON document with the entries to append.
    pub input: PathBuf,
    #[command(flatten)]
    pub destination: Destination,
}

impl AppendCommand {
    pub fn run(&self) -> Result<()> {
        report(&append(
            &self.project,
            &self.destination.output,
            &load(&self.input)?,
            &self.destination.options(),
        )?);
        Ok(())
    }
}

fn example() -> HistoryInput {
    HistoryInput {
        schema_version: INPUT_VERSION,
        defaults: InputDefaults {
            time_epoch_ms: Some(DEFAULT_TIME_EPOCH_MS),
            listener_port: Some(DEFAULT_LISTENER_PORT),
            comment: None,
            highlight: None,
        },
        entries: vec![
            HistoryInputEntry {
                url: "https://example.com/login".to_owned(),
                request: BlobInput::File {
                    path: "login.request.bin".to_owned(),
                    length: None,
                    sha256: None,
                },
                response: Some(BlobInput::File {
                    path: "login.response.bin".to_owned(),
                    length: None,
                    sha256: None,
                }),
                entry_id: None,
                time_epoch_ms: None,
                listener_port: None,
                comment: None,
                highlight: None,
            },
            HistoryInputEntry {
                url: "http://127.0.0.1:8080/health".to_owned(),
                request: BlobInput::Base64 {
                    base64: "R0VUIC9oZWFsdGggSFRUUC8xLjENCkhvc3Q6IDEyNy4wLjAuMTo4MDgwDQoNCg=="
                        .to_owned(),
                },
                response: None,
                entry_id: None,
                time_epoch_ms: None,
                listener_port: None,
                comment: Some("request-only entry".to_owned()),
                highlight: Some("orange".to_owned()),
            },
        ],
    }
}

impl Destination {
    pub fn options(&self) -> WriteOptions {
        WriteOptions {
            force: self.force,
            name: None,
        }
    }
}

fn report(summary: &WriteSummary) {
    eprintln!(
        "wrote {} ({} existing + {} appended = {} entries, {} bytes, mark {})",
        summary.destination.display(),
        summary.existing_entries,
        summary.appended_entries,
        summary.total_entries,
        summary.bytes_written,
        summary.allocation_mark
    );
}
