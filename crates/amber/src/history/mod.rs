pub mod decode;
pub mod layout;

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::binary::{FileSource, hex};
use crate::diagnostic::{Error, Result};
use crate::filter::HistoryFilter;
use crate::model::history::{HistoryEntry, SourceInfo};

use layout::tag;

const SCAN_CHUNK: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamSummary {
    pub total: u64,
    pub emitted: u64,
    pub complete: bool,
}

#[derive(Debug)]
pub struct Project {
    path: PathBuf,
    source: FileSource,
    sha256: String,
    header: [u8; 8],
    rows: Vec<(u64, u64)>,
}

impl Project {
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_source(path, FileSource::open(path)?)
    }

    pub fn open_read_write(path: &Path) -> Result<Self> {
        Self::from_source(path, FileSource::open_read_write(path)?)
    }

    fn from_source(path: &Path, source: FileSource) -> Result<Self> {
        let (sha256, offsets) = scan(&source)?;
        let mut header = [0u8; 8];
        if source.len() >= 8 {
            source.read_into_at(0, &mut header)?;
        }
        let mut rows = Vec::with_capacity(offsets.len());
        for offset in offsets {
            let Some(record) = decode::row_at(&source, offset)? else {
                continue;
            };
            rows.push((record.slices(&source)?[&tag::ENTRY_ID].unsigned, offset));
        }
        rows.sort_unstable();
        Ok(Self {
            path: path.to_path_buf(),
            source,
            sha256,
            header,
            rows,
        })
    }

    pub const fn source(&self) -> &FileSource {
        &self.source
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn header_match(&self) -> bool {
        self.header == layout::PROJECT_HEADER
    }

    pub fn info(&self) -> SourceInfo {
        SourceInfo {
            path: self.path.display().to_string(),
            bytes: self.source.len(),
            sha256: self.sha256.clone(),
            header_hex: hex(&self.header),
            header_match: self.header_match(),
        }
    }

    pub fn for_each(
        &self,
        filter: &HistoryFilter,
        mut visit: impl FnMut(HistoryEntry) -> Result<()>,
    ) -> Result<StreamSummary> {
        let mut summary = StreamSummary {
            total: self.rows.len() as u64,
            complete: true,
            ..StreamSummary::default()
        };
        for (ordinal, (_, offset)) in self.rows.iter().enumerate() {
            let Some(record) = decode::row_at(&self.source, *offset)? else {
                summary.complete = false;
                continue;
            };
            let fields = record.slices(&self.source)?;
            if !filter.accepts_row(&fields) {
                continue;
            }
            let Some(entry) = decode::decode_entry(&self.source, &fields, *offset, ordinal as u64)?
            else {
                summary.complete = false;
                continue;
            };
            summary.complete = summary.complete && entry.validation.is_complete();
            if !filter.accepts(&entry) {
                continue;
            }
            summary.emitted += 1;
            visit(entry)?;
        }
        Ok(summary)
    }

    pub fn entry(&self, entry_id: u64) -> Result<HistoryEntry> {
        let filter = HistoryFilter {
            entry_id: Some(entry_id),
            ..HistoryFilter::default()
        };
        let mut found = None;
        self.for_each(&filter, |entry| {
            found = Some(entry);
            Ok(())
        })?;
        found.ok_or_else(|| {
            Error::Malformed(format!(
                "entry {entry_id} is not present in {}",
                self.path.display()
            ))
        })
    }

    pub fn require_complete(&self) -> Result<()> {
        if let Some(pair) = self.rows.windows(2).find(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::Malformed(format!(
                "entry id {} is used by rows at {} and {}",
                pair[0].0, pair[0].1, pair[1].1
            )));
        }
        let summary = self.for_each(&HistoryFilter::default(), |entry| {
            if entry.validation.is_complete() {
                Ok(())
            } else {
                Err(Error::Malformed(format!(
                    "entry {} failed validation: {:?}",
                    entry.entry_id, entry.validation
                )))
            }
        })?;
        if summary.emitted != summary.total {
            return Err(Error::Malformed(format!(
                "decoded {} of {} rows",
                summary.emitted, summary.total
            )));
        }
        Ok(())
    }
}

fn scan(source: &FileSource) -> Result<(String, Vec<u64>)> {
    let needle: &[u8] = &layout::ROW_HEADER;
    let finder = memchr::memmem::Finder::new(needle);
    let carry_length = needle.len() - 1;
    let mut hasher = Sha256::new();
    let mut offsets = Vec::new();
    let mut buffer = vec![0u8; carry_length + SCAN_CHUNK];
    let mut carried = 0usize;
    let mut consumed = 0u64;

    while consumed < source.len() {
        let amount = usize::try_from((source.len() - consumed).min(SCAN_CHUNK as u64))
            .map_err(|_| Error::OffsetOverflow)?;
        source.read_into_at(consumed, &mut buffer[carried..carried + amount])?;
        hasher.update(&buffer[carried..carried + amount]);

        let filled = carried + amount;
        let origin = consumed - carried as u64;
        let mut cursor = 0;
        while let Some(found) = finder.find(&buffer[cursor..filled]) {
            let found = cursor + found;
            let absolute = origin + found as u64;
            if offsets.last() != Some(&absolute) {
                offsets.push(absolute);
            }
            cursor = found + 1;
        }

        let tail = filled.saturating_sub(carry_length);
        buffer.copy_within(tail..filled, 0);
        carried = filled - tail;
        consumed += amount as u64;
    }
    Ok((hex(&hasher.finalize()), offsets))
}
