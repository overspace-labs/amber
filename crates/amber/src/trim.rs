//! Streaming trim: copy the Proxy history entries that pass a filter (and are not
//! duplicates) from an existing project into a brand-new project.
//!
//! Messages are copied verbatim, one entry at a time, so memory stays bounded by the
//! largest single message whatever the size of the source project. The new project is
//! built from the embedded empty model, so it carries Proxy history only.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::binary::FileSource;
use crate::builder::{Entry, History, Writer, empty, skeleton, write_entry};
use crate::dedupe::{DedupeMode, Deduper};
use crate::diagnostic::{Error, Result};
use crate::filter::HistoryFilter;
use crate::history::Project;
use crate::history::decode::message_bytes;
use crate::model::history::{HistoryEntry, highlight_code};
use crate::write::{guard, staging_path};

#[derive(Debug, Clone, Default)]
pub struct TrimOptions {
    pub force: bool,
    /// Project name Burp shows for the new project.
    pub name: Option<String>,
    pub dedupe: DedupeMode,
    /// Decide and report only; write nothing.
    pub dry_run: bool,
    /// Re-read the written project and compare every kept message digest with the source.
    pub verify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Kept,
    /// Rejected by the filter (out of scope, wrong method, ...).
    Filtered,
    /// Same exchange as an earlier kept entry.
    Duplicate { of: u64 },
    /// Passed the filter but cannot be rebuilt (no decodable service, bad port).
    Unwritable { reason: String },
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HostTally {
    pub kept: u64,
    pub filtered: u64,
    pub duplicates: u64,
    pub unwritable: u64,
    pub kept_bytes: u64,
    pub dropped_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrimSummary {
    /// Proxy rows found in the source.
    pub source_rows: u64,
    /// Rows that could not be decoded into an entry at all (not written, not counted below).
    pub undecodable: u64,
    pub kept: u64,
    pub filtered: u64,
    pub duplicates: u64,
    pub unwritable: u64,
    /// Kept entries that were annotated (comment or highlight) and would otherwise have
    /// been dropped as duplicates.
    pub kept_annotated_duplicates: u64,
    /// Highlight codes this tool does not know, dropped from kept entries.
    pub dropped_highlights: u64,
    /// Kept entries whose source row failed amber's validation flags.
    pub kept_incomplete: u64,
    pub kept_message_bytes: u64,
    pub dropped_message_bytes: u64,
    pub source_file_bytes: u64,
    pub output_file_bytes: u64,
    pub destination: Option<PathBuf>,
    /// Kept entries whose request and response digests matched after re-reading the output.
    pub verified: Option<u64>,
    pub hosts: BTreeMap<String, HostTally>,
}

fn message_length(entry: &HistoryEntry) -> u64 {
    entry.request.length + entry.response.as_ref().map_or(0, |message| message.length)
}

fn annotated(entry: &HistoryEntry) -> bool {
    !entry.comment.value.is_empty() || entry.highlight.code != 0
}

/// Rebuilds a writable entry from a source row, copying both messages byte for byte.
/// Returns `Err(reason)` in the `Ok` slot when the row cannot be represented.
fn copy_entry(
    source: &FileSource,
    entry: &HistoryEntry,
) -> Result<std::result::Result<(Entry, bool), String>> {
    let Some(service) = entry.service.as_ref() else {
        return Ok(Err("no decodable service (host/port)".to_owned()));
    };
    let Ok(port) = u16::try_from(service.port.value) else {
        return Ok(Err(format!("port {} out of range", service.port.value)));
    };
    let Ok(listener_port) = u16::try_from(entry.listener_port.unsigned) else {
        return Ok(Err(format!(
            "listener port {} out of range",
            entry.listener_port.unsigned
        )));
    };
    let Ok(status) = u16::try_from(entry.status_code.unsigned) else {
        return Ok(Err(format!(
            "status {} out of range",
            entry.status_code.unsigned
        )));
    };
    let highlight = entry
        .highlight
        .value
        .clone()
        .filter(|name| highlight_code(name).is_some());
    let dropped_highlight = entry.highlight.code != 0 && highlight.is_none();
    let request = message_bytes(source, &entry.request)?;
    let response = entry
        .response
        .as_ref()
        .map(|message| message_bytes(source, message))
        .transpose()?;
    Ok(Ok((
        Entry {
            entry_id: Some(entry.entry_id),
            host: service.host.text.value.clone(),
            ip: entry.ip.clone().unwrap_or_default(),
            port,
            tls: service.tls.value,
            request,
            response,
            status,
            comment: entry.comment.value.clone(),
            highlight,
            time_epoch_ms: entry.time_epoch_ms.unsigned,
            listener_port,
        },
        dropped_highlight,
    )))
}

type Digests = (String, Option<String>);

fn digests(entry: &HistoryEntry) -> Digests {
    (
        entry.request.sha256.clone(),
        entry
            .response
            .as_ref()
            .map(|message| message.sha256.clone()),
    )
}

struct Sink<'a> {
    source: &'a FileSource,
    writer: Writer<'a>,
    history: History,
}

#[allow(clippy::too_many_lines)]
fn run(
    project: &Project,
    filter: &HistoryFilter,
    options: &TrimOptions,
    mut sink: Option<Sink<'_>>,
    on_decision: &mut dyn FnMut(&HistoryEntry, &Decision) -> Result<()>,
) -> Result<(TrimSummary, HashMap<u64, Digests>)> {
    let mut summary = TrimSummary {
        source_rows: project.len() as u64,
        source_file_bytes: project.source().len(),
        ..TrimSummary::default()
    };
    let mut kept_digests = HashMap::new();
    let mut deduper = Deduper::new(options.dedupe);
    let mut visited = 0u64;

    project.for_each(&HistoryFilter::default(), |entry| {
        visited += 1;
        let host = entry.service.as_ref().map_or_else(
            || "<unknown>".to_owned(),
            |service| service.host.text.value.to_ascii_lowercase(),
        );
        let length = message_length(&entry);

        let mut decision = if !filter.accepts(&entry) {
            Decision::Filtered
        } else if let Some(first) = deduper.check(&entry) {
            if annotated(&entry) {
                summary.kept_annotated_duplicates += 1;
                Decision::Kept
            } else {
                Decision::Duplicate { of: first }
            }
        } else {
            Decision::Kept
        };

        if decision == Decision::Kept {
            if let Some(sink) = sink.as_mut() {
                match copy_entry(project.source(), &entry)? {
                    Ok((copy, dropped_highlight)) => {
                        let row = write_entry(&mut sink.writer, &copy, entry.entry_id)?;
                        sink.history.record(&mut sink.writer, sink.source, row)?;
                        if dropped_highlight {
                            summary.dropped_highlights += 1;
                        }
                    }
                    Err(reason) => decision = Decision::Unwritable { reason },
                }
            } else if entry.service.is_none() {
                decision = Decision::Unwritable {
                    reason: "no decodable service (host/port)".to_owned(),
                };
            }
        }

        let tally = summary.hosts.entry(host).or_default();
        match &decision {
            Decision::Kept => {
                summary.kept += 1;
                summary.kept_message_bytes += length;
                tally.kept += 1;
                tally.kept_bytes += length;
                if !entry.validation.is_complete() {
                    summary.kept_incomplete += 1;
                }
                if options.verify {
                    kept_digests.insert(entry.entry_id, digests(&entry));
                }
            }
            Decision::Filtered => {
                summary.filtered += 1;
                summary.dropped_message_bytes += length;
                tally.filtered += 1;
                tally.dropped_bytes += length;
            }
            Decision::Duplicate { .. } => {
                summary.duplicates += 1;
                summary.dropped_message_bytes += length;
                tally.duplicates += 1;
                tally.dropped_bytes += length;
            }
            Decision::Unwritable { .. } => {
                summary.unwritable += 1;
                summary.dropped_message_bytes += length;
                tally.unwritable += 1;
                tally.dropped_bytes += length;
            }
        }
        on_decision(&entry, &decision)
    })?;
    summary.undecodable = summary.source_rows - visited;

    if let Some(sink) = sink {
        sink.writer.commit()?;
    }
    Ok((summary, kept_digests))
}

fn verify(destination: &Path, expected: &HashMap<u64, Digests>) -> Result<u64> {
    let project = Project::open_fast(destination)?;
    let mut matched = 0u64;
    let mut problems = Vec::new();
    project.for_each(&HistoryFilter::default(), |entry| {
        match expected.get(&entry.entry_id) {
            Some(wanted) if *wanted == digests(&entry) => matched += 1,
            Some(_) => problems.push(format!("entry {} digest mismatch", entry.entry_id)),
            None => problems.push(format!("entry {} was not expected", entry.entry_id)),
        }
        Ok(())
    })?;
    if matched != expected.len() as u64 {
        problems.push(format!(
            "{} of {} kept entries verified",
            matched,
            expected.len()
        ));
    }
    if problems.is_empty() {
        Ok(matched)
    } else {
        problems.truncate(20);
        Err(Error::Malformed(format!(
            "verification failed: {}",
            problems.join("; ")
        )))
    }
}

/// Trims `source` into `destination`. `on_decision` sees every decoded entry with the
/// decision taken for it, in entry-id order (use it to write a manifest).
pub fn trim(
    source: &Path,
    destination: &Path,
    filter: &HistoryFilter,
    options: &TrimOptions,
    mut on_decision: impl FnMut(&HistoryEntry, &Decision) -> Result<()>,
) -> Result<TrimSummary> {
    filter.validate()?;
    let project = Project::open_fast(source)?;
    if !project.header_match() {
        return Err(Error::Malformed(
            "source project header is not the supported Burp grammar".to_owned(),
        ));
    }

    if options.dry_run {
        let (summary, _) = run(&project, filter, options, None, &mut on_decision)?;
        return Ok(summary);
    }

    guard(
        destination,
        &crate::write::WriteOptions {
            force: options.force,
            name: None,
        },
    )?;
    if destination.exists() && fs::canonicalize(source)? == fs::canonicalize(destination)? {
        return Err(Error::Malformed(
            "source and destination resolve to the same file".to_owned(),
        ));
    }

    let staged = staging_path(destination);
    let result = (|| {
        let blueprint = empty::Blueprint {
            slack: skeleton::slack_for(&[])?,
            name: options.name.as_deref(),
            ..empty::Blueprint::default()
        };
        fs::write(&staged, empty::image(&blueprint)?)?;
        let output = FileSource::open_read_write(&staged)?;
        let sink = Sink {
            source: &output,
            writer: Writer::open(&output)?,
            history: History::open(&output)?,
        };
        let (summary, kept) = run(&project, filter, options, Some(sink), &mut on_decision)?;
        output.sync()?;
        drop(output);

        let written = Project::open_fast(&staged)?;
        if written.len() as u64 != summary.kept {
            return Err(Error::Malformed(format!(
                "staged project decodes {} entries but {} were kept",
                written.len(),
                summary.kept
            )));
        }
        // Every row must decode, ids must be unique, and no row may be less complete than
        // its source (a source row that already failed a validation flag is copied as is).
        written.require_unique_ids()?;
        let mut incomplete = 0u64;
        let stream = written.for_each(&HistoryFilter::default(), |entry| {
            if !entry.validation.is_complete() {
                incomplete += 1;
            }
            Ok(())
        })?;
        if stream.emitted != stream.total || incomplete != summary.kept_incomplete {
            return Err(Error::Malformed(format!(
                "staged project decoded {} of {} rows with {} incomplete (source had {})",
                stream.emitted, stream.total, incomplete, summary.kept_incomplete
            )));
        }
        Ok((summary, kept))
    })();

    match result {
        Ok((mut summary, kept)) => {
            fs::rename(&staged, destination)?;
            summary.destination = Some(destination.to_path_buf());
            summary.output_file_bytes = fs::metadata(destination)?.len();
            if options.verify {
                summary.verified = Some(verify(destination, &kept)?);
            }
            Ok(summary)
        }
        Err(error) => {
            let _ = fs::remove_file(&staged);
            Err(error)
        }
    }
}
