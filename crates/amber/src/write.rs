use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::builder::{Entry, History, Writer, empty, skeleton, write_entry};
use crate::diagnostic::{Error, Result};
use crate::history::Project;

const COPY_CHUNK: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSummary {
    pub destination: PathBuf,
    pub existing_entries: u64,
    pub appended_entries: u64,
    pub total_entries: u64,
    pub bytes_written: u64,
    pub allocation_mark: u64,
}

#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    pub force: bool,
    pub name: Option<String>,
}

fn guard(destination: &Path, options: &WriteOptions) -> Result<()> {
    if destination.exists() && !options.force {
        return Err(Error::DestinationExists(destination.display().to_string()));
    }
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn build(
    destination: &Path,
    entries: &[Entry],
    options: &WriteOptions,
    seed: impl FnOnce(&Path) -> Result<()>,
) -> Result<WriteSummary> {
    guard(destination, options)?;

    let staged = staging_path(destination);
    let result = (|| {
        seed(&staged)?;
        let summary = apply(&staged, entries)?;
        let project = Project::open(&staged)?;
        if project.len() as u64 != summary.total_entries {
            return Err(Error::Malformed(format!(
                "staged project decodes {} entries but {} were expected",
                project.len(),
                summary.total_entries
            )));
        }
        project.require_complete()?;
        Ok(summary)
    })();

    match result {
        Ok(mut summary) => {
            fs::rename(&staged, destination)?;
            summary.destination = destination.to_path_buf();
            Ok(summary)
        }
        Err(error) => {
            let _ = fs::remove_file(&staged);
            Err(error)
        }
    }
}

pub fn append(
    source: &Path,
    destination: &Path,
    entries: &[Entry],
    options: &WriteOptions,
) -> Result<WriteSummary> {
    guard(destination, options)?;
    if destination.exists() && fs::canonicalize(source)? == fs::canonicalize(destination)? {
        return Err(Error::Malformed(
            "source and destination resolve to the same file".to_owned(),
        ));
    }
    build(destination, entries, options, |staged| copy(source, staged))
}

pub fn create(
    destination: &Path,
    entries: &[Entry],
    options: &WriteOptions,
) -> Result<WriteSummary> {
    let blueprint = empty::Blueprint {
        slack: skeleton::slack_for(entries)?,
        name: options.name.as_deref(),
        ..empty::Blueprint::default()
    };
    build(destination, entries, options, |staged| {
        fs::write(staged, empty::image(&blueprint)?)?;
        Ok(())
    })
}

fn apply(project: &Path, entries: &[Entry]) -> Result<WriteSummary> {
    let source = crate::binary::FileSource::open_read_write(project)?;
    let mut writer = Writer::open(&source)?;
    let mut history = History::open(&source)?;
    let existing = u64::from(history.total());

    for (index, entry) in entries.iter().enumerate() {
        let entry_id = entry.entry_id.unwrap_or(existing + index as u64 + 1);
        let row = write_entry(&mut writer, entry, entry_id)?;
        history.record(&mut writer, &source, row)?;
    }
    writer.commit()?;

    Ok(WriteSummary {
        destination: project.to_path_buf(),
        existing_entries: existing,
        appended_entries: entries.len() as u64,
        total_entries: existing + entries.len() as u64,
        bytes_written: writer.written(),
        allocation_mark: writer.mark(),
    })
}

fn copy(source: &Path, destination: &Path) -> Result<()> {
    let mut input = BufReader::new(fs::File::open(source)?);
    let mut output = BufWriter::new(fs::File::create(destination)?);
    let mut buffer = vec![0u8; COPY_CHUNK];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => output.write_all(&buffer[..read])?,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    output.flush()?;
    output.get_ref().sync_all()?;
    Ok(())
}

fn staging_path(destination: &Path) -> PathBuf {
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".staging-{}", std::process::id()));
    destination.with_file_name(name)
}
