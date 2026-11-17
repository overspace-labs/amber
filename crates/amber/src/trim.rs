//! Streaming trim: copy the Proxy history entries that pass a filter (and are not
//! duplicates) from an existing project into a brand-new project.
//!
//! Messages are copied verbatim, one entry at a time, so memory for message bytes stays
//! bounded by the largest single message whatever the size of the source project. Per-entry
//! bookkeeping (row index, dedupe keys, verify digests) is a few dozen bytes per entry.
//! The new project is built from the embedded empty model, so it carries Proxy history only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::binary::FileSource;
use crate::builder::{Entry, History, Writer, empty, skeleton, write_entry};
use crate::dedupe::{DedupeMode, Deduper};
use crate::diagnostic::{Error, Result};
use crate::filter::HistoryFilter;
use crate::history::Project;
use crate::history::decode::message_bytes;
use crate::history::layout::tag;
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
    /// Re-read the staged project and compare every kept message digest with the source
    /// before it replaces the destination.
    pub verify: bool,
    /// Treat annotated entries (comment or highlight) like any other; by default they are
    /// always kept, even when they duplicate an earlier entry.
    pub dedupe_annotated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Kept,
    /// Rejected by the filter (out of scope, wrong method, ...).
    Filtered,
    /// Same exchange as an earlier kept entry.
    Duplicate { of: u64 },
    /// Passed the filter but cannot be rebuilt (no decodable service, out-of-range field).
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
    /// Kept entries whose source row carried a server-IP record this tool could not read;
    /// they are written without an IP.
    pub kept_ip_unreadable: u64,
    /// Kept entries whose source row already failed amber's validation flags.
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

/// Row fields that fit what the writer can encode, checked without reading any message.
struct Representable {
    port: u16,
    listener_port: u16,
    status: u16,
}

fn representable(entry: &HistoryEntry) -> std::result::Result<Representable, String> {
    let service = entry
        .service
        .as_ref()
        .ok_or_else(|| "no decodable service (host/port)".to_owned())?;
    let port = u16::try_from(service.port.value)
        .map_err(|_| format!("port {} out of range", service.port.value))?;
    let listener_port = u16::try_from(entry.listener_port.unsigned)
        .map_err(|_| format!("listener port {} out of range", entry.listener_port.unsigned))?;
    let status = u16::try_from(entry.status_code.unsigned)
        .map_err(|_| format!("status {} out of range", entry.status_code.unsigned))?;
    if let Some(name) = entry.highlight.value.as_deref() {
        if highlight_code(name).is_none() {
            return Err(format!("highlight code {} cannot be re-encoded", entry.highlight.code));
        }
    }
    Ok(Representable {
        port,
        listener_port,
        status,
    })
}

/// Rebuilds a writable entry from a source row, copying both messages byte for byte.
fn copy_entry(source: &FileSource, entry: &HistoryEntry, fields: &Representable) -> Result<Entry> {
    let service = entry
        .service
        .as_ref()
        .ok_or_else(|| Error::Malformed(format!("entry {} has no service", entry.entry_id)))?;
    let request = message_bytes(source, &entry.request)?;
    let response = entry
        .response
        .as_ref()
        .map(|message| message_bytes(source, message))
        .transpose()?;
    Ok(Entry {
        entry_id: Some(entry.entry_id),
        host: service.host.text.value.clone(),
        ip: entry.ip.clone().unwrap_or_default(),
        port: fields.port,
        tls: service.tls.value,
        request,
        response,
        status: fields.status,
        comment: entry.comment.value.clone(),
        highlight: entry.highlight.value.clone(),
        time_epoch_ms: entry.time_epoch_ms.unsigned,
        listener_port: fields.listener_port,
    })
}

/// One 32-byte digest over both message digests, so verification state stays small.
fn digest(entry: &HistoryEntry) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(entry.request.sha256.as_bytes());
    hasher.update([0]);
    if let Some(response) = entry.response.as_ref() {
        hasher.update(response.sha256.as_bytes());
    }
    hasher.finalize().into()
}

struct Sink<'a> {
    source: &'a FileSource,
    writer: Writer<'a>,
    history: History,
}

/// What `run` hands back besides the summary: what to verify the output against.
struct Ledger {
    digests: HashMap<u64, [u8; 32]>,
    incomplete: HashSet<u64>,
}

#[allow(clippy::too_many_lines)]
fn run(
    project: &Project,
    filter: &HistoryFilter,
    options: &TrimOptions,
    mut sink: Option<Sink<'_>>,
    on_decision: &mut dyn FnMut(&HistoryEntry, &Decision) -> Result<()>,
) -> Result<(TrimSummary, Ledger)> {
    let mut summary = TrimSummary {
        source_rows: project.len() as u64,
        source_file_bytes: project.source().len(),
        ..TrimSummary::default()
    };
    let mut ledger = Ledger {
        digests: HashMap::new(),
        incomplete: HashSet::new(),
    };
    let mut deduper = Deduper::new(options.dedupe);
    let mut visited = 0u64;

    project.for_each(&HistoryFilter::default(), |entry| {
        visited += 1;
        let host = entry.service.as_ref().map_or_else(
            || "<unknown>".to_owned(),
            |service| service.host.text.value.to_ascii_lowercase(),
        );
        let length = message_length(&entry);

        let mut key = None;
        let mut decision = if filter.accepts(&entry) {
            let (first, found_key) = deduper.find(&entry);
            key = found_key;
            match first {
                Some(_) if !options.dedupe_annotated && annotated(&entry) => {
                    summary.kept_annotated_duplicates += 1;
                    Decision::Kept
                }
                Some(first) => Decision::Duplicate { of: first },
                None => Decision::Kept,
            }
        } else {
            Decision::Filtered
        };

        if decision == Decision::Kept {
            // The same representability check runs in dry-run and write mode, and the
            // dedupe key is only recorded once the entry is really kept, so an entry that
            // cannot be written never shadows a later identical one.
            match representable(&entry) {
                Ok(fields) => {
                    if let Some(sink) = sink.as_mut() {
                        let copy = copy_entry(project.source(), &entry, &fields)?;
                        let row = write_entry(&mut sink.writer, &copy, entry.entry_id)?;
                        sink.history.record(&mut sink.writer, sink.source, row)?;
                    }
                    if let Some(key) = key {
                        deduper.record(key, entry.entry_id);
                    }
                }
                Err(reason) => decision = Decision::Unwritable { reason },
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
                    ledger.incomplete.insert(entry.entry_id);
                }
                let ip_record = entry
                    .raw_fields
                    .get(&tag::IP.to_string())
                    .is_some_and(|field| field.unsigned != 0);
                if ip_record && entry.ip.is_none() {
                    summary.kept_ip_unreadable += 1;
                }
                if options.verify {
                    ledger.digests.insert(entry.entry_id, digest(&entry));
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
    Ok((summary, ledger))
}

/// Structural check of the staged project: every row decodes, ids are unique, the count
/// matches, and no entry is less complete than its source row (an entry the writer repairs,
/// for example by recomputing a stale cached length, is fine).
fn validate_staged(staged: &Path, summary: &TrimSummary, ledger: &Ledger) -> Result<()> {
    let written = Project::open_fast(staged)?;
    if written.len() as u64 != summary.kept {
        return Err(Error::Malformed(format!(
            "staged project decodes {} entries but {} were kept",
            written.len(),
            summary.kept
        )));
    }
    written.require_unique_ids()?;
    let mut regressed = Vec::new();
    let stream = written.for_each(&HistoryFilter::default(), |entry| {
        if !entry.validation.is_complete() && !ledger.incomplete.contains(&entry.entry_id) {
            regressed.push(entry.entry_id);
        }
        Ok(())
    })?;
    if stream.emitted != stream.total || !regressed.is_empty() {
        regressed.truncate(20);
        return Err(Error::Malformed(format!(
            "staged project decoded {} of {} rows; entries that lost validity: {regressed:?}",
            stream.emitted, stream.total
        )));
    }
    Ok(())
}

fn verify(staged: &Path, expected: &HashMap<u64, [u8; 32]>) -> Result<u64> {
    let project = Project::open_fast(staged)?;
    let mut matched = 0u64;
    let mut problems = Vec::new();
    project.for_each(&HistoryFilter::default(), |entry| {
        match expected.get(&entry.entry_id) {
            Some(wanted) if *wanted == digest(&entry) => matched += 1,
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
///
/// The source is only ever opened read-only. The output is built in a staging file that
/// this call creates exclusively (it never truncates or follows an existing path), is
/// validated and, with `verify`, digest-checked, and only then renamed onto `destination`.
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
    let blueprint = empty::Blueprint {
        slack: skeleton::slack_for(&[])?,
        name: options.name.as_deref(),
        ..empty::Blueprint::default()
    };
    let image = empty::image(&blueprint)?;
    // `create_new` fails if anything (file or symlink) already has the staging name, so an
    // existing path, including one aliasing the source, is never truncated or removed.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(|error| {
            Error::Malformed(format!(
                "cannot create staging file {}: {error}",
                staged.display()
            ))
        })?;

    let result = (|| {
        file.write_all(&image)?;
        file.sync_all()?;
        drop(file);
        let output = FileSource::open_read_write(&staged)?;
        let sink = Sink {
            source: &output,
            writer: Writer::open(&output)?,
            history: History::open(&output)?,
        };
        let (mut summary, ledger) =
            run(&project, filter, options, Some(sink), &mut on_decision)?;
        output.sync()?;
        drop(output);

        validate_staged(&staged, &summary, &ledger)?;
        if options.verify {
            summary.verified = Some(verify(&staged, &ledger.digests)?);
        }
        Ok(summary)
    })();

    match result {
        Ok(mut summary) => {
            fs::rename(&staged, destination)?;
            summary.destination = Some(destination.to_path_buf());
            summary.output_file_bytes = fs::metadata(destination)?.len();
            Ok(summary)
        }
        Err(error) => {
            // Only the staging file this call created is removed.
            let _ = fs::remove_file(&staged);
            Err(error)
        }
    }
}
