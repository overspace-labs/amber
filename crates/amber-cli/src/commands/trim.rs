use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use amber::{Error, Result, TrimOptions, TrimSummary, trim};
use clap::Args;
use serde_json::json;

use super::{DedupeArg, FilterArgs, human_bytes};

#[derive(Debug, Args)]
pub struct TrimCommand {
    /// Source Burp project; it is opened read-only and never modified.
    pub project: PathBuf,
    /// New project to write (required unless --dry-run).
    #[arg(short, long, required_unless_present = "dry_run")]
    pub output: Option<PathBuf>,
    /// Overwrite --output / --manifest / --summary if they exist.
    #[arg(short, long)]
    pub force: bool,
    /// Project name Burp shows; defaults to the output file stem.
    #[arg(short, long)]
    pub name: Option<String>,
    /// Duplicate rule. Annotated entries (comment or highlight) are always kept.
    #[arg(short, long, value_enum, default_value_t = DedupeArg::Session)]
    pub dedupe: DedupeArg,
    /// Decide and report only; write no project.
    #[arg(long)]
    pub dry_run: bool,
    /// After writing, re-read the new project and compare every kept message's sha256.
    #[arg(long)]
    pub verify: bool,
    /// Write one JSON line per source entry with the decision taken for it.
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,
    /// Write the run summary (totals and per-host tallies) as JSON.
    #[arg(long, value_name = "FILE")]
    pub summary: Option<PathBuf>,
    /// Number of dropped hosts listed in the report.
    #[arg(long, default_value_t = 25)]
    pub top: usize,
    #[command(flatten)]
    pub filters: FilterArgs,
}

fn create(path: &PathBuf, force: bool) -> Result<BufWriter<File>> {
    if path.exists() && !force {
        return Err(Error::DestinationExists(path.display().to_string()));
    }
    Ok(BufWriter::new(File::create(path)?))
}

fn report(summary: &TrimSummary, top: usize, dry_run: bool) {
    let total = summary.kept + summary.filtered + summary.duplicates + summary.unwritable;
    eprintln!(
        "{}source rows {} | kept {} | out of scope/filter {} | duplicates {} | unwritable {} | undecodable {}",
        if dry_run { "[dry run] " } else { "" },
        summary.source_rows,
        summary.kept,
        summary.filtered,
        summary.duplicates,
        summary.unwritable,
        summary.undecodable
    );
    if total + summary.undecodable != summary.source_rows {
        eprintln!("warning: decisions do not add up to the source row count");
    }
    eprintln!(
        "messages kept {} / dropped {} (source file {}){}",
        human_bytes(summary.kept_message_bytes),
        human_bytes(summary.dropped_message_bytes),
        human_bytes(summary.source_file_bytes),
        if summary.output_file_bytes > 0 {
            format!("; new project file {}", human_bytes(summary.output_file_bytes))
        } else {
            String::new()
        }
    );
    if summary.kept_annotated_duplicates > 0 {
        eprintln!(
            "kept {} duplicates because they carry a comment or highlight",
            summary.kept_annotated_duplicates
        );
    }
    if summary.kept_incomplete > 0 {
        eprintln!(
            "note: {} kept entries already failed amber's validation flags in the source",
            summary.kept_incomplete
        );
    }
    if summary.dropped_highlights > 0 {
        eprintln!(
            "note: {} unknown highlight colours were dropped",
            summary.dropped_highlights
        );
    }
    let mut kept: Vec<_> = summary
        .hosts
        .iter()
        .filter(|(_, tally)| tally.kept > 0)
        .collect();
    kept.sort_by(|a, b| b.1.kept_bytes.cmp(&a.1.kept_bytes));
    eprintln!("\nKEPT HOSTS ({}):", kept.len());
    eprintln!("{:>8}  {:>8}  {:>11}  {:>11}  HOST", "KEPT", "DUPS", "KEPT BYTES", "DROPPED");
    for (host, tally) in kept {
        eprintln!(
            "{:>8}  {:>8}  {:>11}  {:>11}  {host}",
            tally.kept,
            tally.duplicates,
            human_bytes(tally.kept_bytes),
            human_bytes(tally.dropped_bytes)
        );
    }
    let mut dropped: Vec<_> = summary
        .hosts
        .iter()
        .filter(|(_, tally)| tally.kept == 0)
        .collect();
    dropped.sort_by(|a, b| b.1.dropped_bytes.cmp(&a.1.dropped_bytes));
    eprintln!(
        "\nDROPPED HOSTS ({}, top {} by size):",
        dropped.len(),
        top.min(dropped.len())
    );
    for (host, tally) in dropped.iter().take(top) {
        eprintln!(
            "{:>8}  {:>11}  {host}",
            tally.filtered + tally.duplicates + tally.unwritable,
            human_bytes(tally.dropped_bytes)
        );
    }
    if let Some(verified) = summary.verified {
        eprintln!("\nverified {verified} kept entries: request/response sha256 identical to source");
    }
}

impl TrimCommand {
    pub fn run(&self) -> Result<()> {
        let filter = self.filters.build()?;
        let mut manifest = match &self.manifest {
            Some(path) => Some(create(path, self.force)?),
            None => None,
        };
        let output = self.output.clone().unwrap_or_default();
        let name = self.name.clone().or_else(|| {
            output
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        });
        let options = TrimOptions {
            force: self.force,
            name,
            dedupe: self.dedupe.into(),
            dry_run: self.dry_run,
            verify: self.verify,
        };

        let summary = trim(&self.project, &output, &filter, &options, |entry, decision| {
            if let Some(writer) = manifest.as_mut() {
                let mut line = json!({
                    "entry_id": entry.entry_id,
                    "decision": decision,
                    "method": entry.request.method,
                    "url": entry.request.url,
                    "status": entry.status_code.unsigned,
                    "bytes": entry.request.length
                        + entry.response.as_ref().map_or(0, |message| message.length),
                });
                if let Some(object) = line.as_object_mut() {
                    if let Some(serde_json::Value::Object(fields)) = object.remove("decision") {
                        object.extend(fields);
                    }
                }
                serde_json::to_writer(&mut *writer, &line)?;
                writer.write_all(b"\n")?;
            }
            Ok(())
        })?;
        if let Some(mut writer) = manifest {
            writer.flush()?;
        }
        if let Some(path) = &self.summary {
            let mut writer = create(path, self.force)?;
            serde_json::to_writer_pretty(&mut writer, &summary)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
        report(&summary, self.top, self.dry_run);
        if let Some(path) = &summary.destination {
            eprintln!("\nwrote {}", path.display());
        }
        Ok(())
    }
}
