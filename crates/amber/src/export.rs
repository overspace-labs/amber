use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::binary::{FileSource, frame};
use crate::diagnostic::{Error, Result, SourceRange};
use crate::filter::HistoryFilter;
use crate::history::Project;
use crate::model::history::{Coverage, DOCUMENT_TYPE, HistoryEntry, Message, ORDERING, SCAN_MODE};

pub const HISTORY_FILE: &str = "history.json";
pub const BLOB_DIRECTORY: &str = "blobs";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    pub entry_count: u64,
    pub complete: bool,
    pub header_match: bool,
    pub blob_count: u64,
    pub blob_bytes: u64,
    pub history_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub write_blobs: bool,
    pub force: bool,
    pub filter: HistoryFilter,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            write_blobs: true,
            force: false,
            filter: HistoryFilter::default(),
        }
    }
}

pub fn export(project: &Path, output: &Path, options: &ExportOptions) -> Result<ExportSummary> {
    options.filter.validate()?;
    let project = Project::open(project)?;

    let history_path = output.join(HISTORY_FILE);
    let blob_directory = output.join(BLOB_DIRECTORY);
    if !options.force && history_path.exists() {
        return Err(Error::DestinationExists(history_path.display().to_string()));
    }
    fs::create_dir_all(output)?;
    if options.write_blobs {
        fs::create_dir_all(&blob_directory)?;
    }

    let mut writer = BufWriter::new(File::create(&history_path)?);
    let mut emitted = 0u64;
    let mut blob_count = 0u64;
    let mut blob_bytes = 0u64;

    write!(
        writer,
        "{{\"document_type\":\"{DOCUMENT_TYPE}\",\"source\":"
    )?;
    serde_json::to_writer(&mut writer, &project.info())?;
    write!(
        writer,
        ",\"proxy_http_history\":{{\"ordering\":\"{ORDERING}\",\"entries\":["
    )?;

    let stream = project.for_each(&options.filter, |mut entry| {
        if options.write_blobs {
            let (count, bytes) = write_blobs(project.source(), &mut entry, &blob_directory)?;
            blob_count += count;
            blob_bytes += bytes;
        }
        if emitted > 0 {
            writer.write_all(b",")?;
        }
        serde_json::to_writer(&mut writer, &entry)?;
        emitted += 1;
        Ok(())
    })?;

    let coverage = Coverage {
        proxy_history_entry_count: emitted,
        proxy_history_complete: stream.complete,
        scan_mode: SCAN_MODE.to_owned(),
    };
    write!(
        writer,
        "],\"entry_count\":{emitted},\"complete\":{}}},\"coverage\":",
        coverage.proxy_history_complete
    )?;
    serde_json::to_writer(&mut writer, &coverage)?;
    writer.write_all(b"}\n")?;
    writer.flush()?;

    Ok(ExportSummary {
        entry_count: emitted,
        complete: coverage.proxy_history_complete,
        header_match: project.header_match(),
        blob_count,
        blob_bytes,
        history_path,
    })
}

fn write_blobs(
    source: &FileSource,
    entry: &mut HistoryEntry,
    directory: &Path,
) -> Result<(u64, u64)> {
    let mut count = 1;
    let mut bytes = copy_blob(source, &mut entry.request, "request", directory)?;
    if let Some(response) = entry.response.as_mut() {
        bytes += copy_blob(source, response, "response", directory)?;
        count += 1;
    }
    Ok((count, bytes))
}

fn copy_blob(
    source: &FileSource,
    message: &mut Message,
    role: &str,
    directory: &Path,
) -> Result<u64> {
    let name = format!("{}.{role}.bin", message.sha256);
    let path = directory.join(&name);
    message.blob = Some(name);
    if path
        .metadata()
        .is_ok_and(|meta| meta.len() == message.length)
    {
        return Ok(message.length);
    }
    let mut output = BufWriter::new(File::create(&path)?);
    frame::stream(
        source,
        SourceRange::new(message.payload_offset, message.length),
        |window| Ok(output.write_all(window)?),
    )?;
    output.flush()?;
    Ok(message.length)
}
