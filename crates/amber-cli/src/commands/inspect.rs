use std::io::{BufWriter, Write};
use std::path::PathBuf;

use amber::{ExportOptions, HistoryEntry, Project, Result, export};
use clap::{Args, ValueEnum};
use serde_json::json;

use super::{Destination, FilterArgs, warn_unknown_header};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Table,
    Jsonl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EntryFormat {
    Human,
    Json,
}

#[derive(Debug, Args)]
pub struct ExportCommand {
    pub project: PathBuf,
    #[command(flatten)]
    pub destination: Destination,
    /// Write only the manifest and skip raw message sidecars.
    #[arg(short, long)]
    pub no_blobs: bool,
    /// Print a progress summary to stderr.
    #[arg(short, long)]
    pub progress: bool,
    #[command(flatten)]
    pub filters: FilterArgs,
}

impl ExportCommand {
    pub fn run(&self) -> Result<()> {
        let summary = export(
            &self.project,
            &self.destination.output,
            &ExportOptions {
                write_blobs: !self.no_blobs,
                force: self.destination.force,
                filter: self.filters.build(),
            },
        )?;
        if self.progress {
            eprintln!(
                "exported {} entries ({} blobs, {} bytes) to {}",
                summary.entry_count,
                summary.blob_count,
                summary.blob_bytes,
                summary.history_path.display()
            );
        }
        if !summary.header_match {
            eprintln!("warning: project header is not the supported Burp grammar");
        }
        if !summary.complete {
            eprintln!("warning: extraction is incomplete; see entry validation flags");
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct ListCommand {
    pub project: PathBuf,
    #[arg(short = 'F', long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    #[command(flatten)]
    pub filters: FilterArgs,
}

impl ListCommand {
    pub fn run(&self) -> Result<()> {
        let filter = self.filters.build();
        filter.validate()?;
        let project = Project::open(&self.project)?;
        warn_unknown_header(&project);

        let stdout = std::io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        if self.format == Format::Table {
            writeln!(
                writer,
                "{:>6}  {:>6}  {:>7}  {:>10}  URL",
                "ORD", "ID", "STATUS", "LENGTH"
            )?;
        }

        let summary = project.for_each(&filter, |entry| match self.format {
            Format::Table => Ok(writeln!(
                writer,
                "{:>6}  {:>6}  {:>7}  {:>10}  {}",
                entry.ordinal,
                entry.entry_id,
                entry.status_code.unsigned,
                entry.response.as_ref().map_or(0, |message| message.length),
                entry.request.url.as_deref().unwrap_or_default()
            )?),
            Format::Jsonl => {
                serde_json::to_writer(&mut writer, &summarize(&entry))?;
                Ok(writer.write_all(b"\n")?)
            }
        })?;
        writer.flush()?;

        if summary.emitted < summary.total {
            eprintln!("matched {} of {} entries", summary.emitted, summary.total);
        }
        Ok(())
    }
}

fn summarize(entry: &HistoryEntry) -> serde_json::Value {
    json!({
        "ordinal": entry.ordinal,
        "entry_id": entry.entry_id,
        "method": entry.request.method,
        "url": entry.request.url,
        "host": entry.service.as_ref().map(|service| service.host.text.value.clone()),
        "port": entry.service.as_ref().map(|service| service.port.value),
        "tls": entry.service.as_ref().map(|service| service.tls.value),
        "status_code": entry.status_code.unsigned,
        "request_length": entry.request.length,
        "response_length": entry.response.as_ref().map(|message| message.length),
        "time_epoch_ms": entry.time_epoch_ms.unsigned,
        "comment": entry.comment.value,
        "highlight": entry.highlight.value,
    })
}

#[derive(Debug, Args)]
pub struct ShowCommand {
    pub project: PathBuf,
    /// Stable entry ID as stored in the Proxy row.
    pub entry_id: u64,
    #[arg(short = 'F', long, value_enum, default_value_t = EntryFormat::Human)]
    pub format: EntryFormat,
}

impl ShowCommand {
    pub fn run(&self) -> Result<()> {
        let project = Project::open(&self.project)?;
        warn_unknown_header(&project);
        let entry = project.entry(self.entry_id)?;
        match self.format {
            EntryFormat::Json => println!("{}", serde_json::to_string_pretty(&entry)?),
            EntryFormat::Human => print_human(&entry),
        }
        Ok(())
    }
}

fn print_human(entry: &HistoryEntry) {
    let field = |name: &str, value: String| println!("{name:<14}{value}");
    field("entry_id", entry.entry_id.to_string());
    field("ordinal", entry.ordinal.to_string());
    field("row_offset", entry.row_offset.to_string());
    field("tool", entry.tool_source.clone());
    if let Some(service) = &entry.service {
        field(
            "service",
            format!(
                "{}://{} (host {} port {} tls {})",
                service.scheme(),
                service.authority(),
                service.host.text.value,
                service.port.value,
                service.tls.value
            ),
        );
    }
    field("url", entry.request.url.clone().unwrap_or_default());
    field(
        "request",
        format!(
            "{} bytes at {} sha256 {}",
            entry.request.length, entry.request.payload_offset, entry.request.sha256
        ),
    );
    field(
        "response",
        entry.response.as_ref().map_or_else(
            || "<none>".to_owned(),
            |response| {
                format!(
                    "{} bytes at {} sha256 {}",
                    response.length, response.payload_offset, response.sha256
                )
            },
        ),
    );
    field("status", entry.status_code.unsigned.to_string());
    field("mime_code", entry.burp_mime_code.unsigned.to_string());
    field("time_epoch_ms", entry.time_epoch_ms.unsigned.to_string());
    field("listener_port", entry.listener_port.unsigned.to_string());
    field(
        "highlight",
        entry
            .highlight
            .value
            .clone()
            .unwrap_or_else(|| "<none>".to_owned()),
    );
    field("comment", entry.comment.value.clone());
    field(
        "validation",
        format!(
            "complete={} (service={} status={} length={} listener={} id={})",
            entry.validation.is_complete(),
            entry.validation.service_decoded,
            entry.validation.status_matches,
            entry.validation.response_length_matches,
            entry.validation.listener_port_valid,
            entry.validation.entry_id_valid
        ),
    );
}
