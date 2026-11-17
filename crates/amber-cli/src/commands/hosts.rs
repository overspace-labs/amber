use std::collections::BTreeMap;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use amber::{Deduper, Project, Result};
use clap::Args;
use serde_json::json;

use super::inspect::Format;
use super::{DedupeArg, FilterArgs, human_bytes, warn_unknown_header};

#[derive(Debug, Args)]
pub struct HostsCommand {
    pub project: PathBuf,
    /// Duplicate rule used for the DUPS column.
    #[arg(short, long, value_enum, default_value_t = DedupeArg::Session)]
    pub dedupe: DedupeArg,
    #[arg(short = 'F', long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    #[command(flatten)]
    pub filters: FilterArgs,
}

#[derive(Debug, Default)]
struct Tally {
    entries: u64,
    duplicates: u64,
    duplicate_bytes: u64,
    request_bytes: u64,
    response_bytes: u64,
}

impl HostsCommand {
    pub fn run(&self) -> Result<()> {
        let filter = self.filters.build()?;
        filter.validate()?;
        let project = Project::open_fast(&self.project)?;
        warn_unknown_header(&project);

        let mut deduper = Deduper::new(self.dedupe.into());
        let mut hosts: BTreeMap<String, Tally> = BTreeMap::new();
        let summary = project.for_each(&filter, |entry| {
            let host = entry.service.as_ref().map_or_else(
                || "<unknown>".to_owned(),
                |service| service.host.text.value.to_ascii_lowercase(),
            );
            let request = entry.request.length;
            let response = entry.response.as_ref().map_or(0, |message| message.length);
            let tally = hosts.entry(host).or_default();
            tally.entries += 1;
            tally.request_bytes += request;
            tally.response_bytes += response;
            if deduper.check(&entry).is_some() {
                tally.duplicates += 1;
                tally.duplicate_bytes += request + response;
            }
            Ok(())
        })?;

        let mut rows: Vec<(String, Tally)> = hosts.into_iter().collect();
        rows.sort_by(|a, b| {
            (b.1.request_bytes + b.1.response_bytes)
                .cmp(&(a.1.request_bytes + a.1.response_bytes))
                .then_with(|| a.0.cmp(&b.0))
        });

        let mut out = BufWriter::new(std::io::stdout().lock());
        match self.format {
            Format::Table => {
                writeln!(
                    out,
                    "{:>8}  {:>8}  {:>11}  {:>11}  {:>11}  HOST",
                    "ENTRIES", "DUPS", "REQUESTS", "RESPONSES", "DUP BYTES"
                )?;
                for (host, tally) in &rows {
                    writeln!(
                        out,
                        "{:>8}  {:>8}  {:>11}  {:>11}  {:>11}  {host}",
                        tally.entries,
                        tally.duplicates,
                        human_bytes(tally.request_bytes),
                        human_bytes(tally.response_bytes),
                        human_bytes(tally.duplicate_bytes),
                    )?;
                }
                let entries: u64 = rows.iter().map(|(_, tally)| tally.entries).sum();
                let duplicates: u64 = rows.iter().map(|(_, tally)| tally.duplicates).sum();
                let bytes: u64 = rows
                    .iter()
                    .map(|(_, tally)| tally.request_bytes + tally.response_bytes)
                    .sum();
                let duplicate_bytes: u64 =
                    rows.iter().map(|(_, tally)| tally.duplicate_bytes).sum();
                writeln!(
                    out,
                    "{entries} entries ({duplicates} duplicates) across {} hosts; {} of messages, {} of it duplicates; project file {}",
                    rows.len(),
                    human_bytes(bytes),
                    human_bytes(duplicate_bytes),
                    human_bytes(project.source().len()),
                )?;
            }
            Format::Jsonl => {
                for (host, tally) in &rows {
                    serde_json::to_writer(
                        &mut out,
                        &json!({
                            "host": host,
                            "entries": tally.entries,
                            "duplicates": tally.duplicates,
                            "duplicate_bytes": tally.duplicate_bytes,
                            "request_bytes": tally.request_bytes,
                            "response_bytes": tally.response_bytes,
                        }),
                    )?;
                    out.write_all(b"\n")?;
                }
            }
        }
        out.flush()?;
        if !summary.complete {
            eprintln!("warning: some rows did not decode or failed validation");
        }
        Ok(())
    }
}
