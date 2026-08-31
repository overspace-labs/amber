pub mod empty;
pub mod encode;
pub mod fields;
pub mod input;
pub mod skeleton;

use crate::binary::{FileSource, frame, schema};
use crate::diagnostic::{Error, Result};
use crate::history::layout::{self, tag};
use crate::model::history::highlight_code;

use encode::{Field, reference_array, standard, text, typed};
pub use input::{Entry, load};

const GROWTH_GRANULARITY: u64 = 64 * 1024;
const GROWTH_CAP: u64 = 64 * 1024 * 1024;
const MAX_SLOTS: u32 = 1 << 20;

#[derive(Debug)]
pub struct Writer<'a> {
    source: &'a FileSource,
    mark: u64,
    written: u64,
}

impl<'a> Writer<'a> {
    pub fn open(source: &'a FileSource) -> Result<Self> {
        let mark = source.u64(layout::ALLOCATION_MARK)?;
        if mark == 0 || mark > source.len() {
            return Err(Error::Malformed(format!(
                "allocation mark {mark} is outside the {}-byte project",
                source.len()
            )));
        }
        Ok(Self {
            source,
            mark,
            written: 0,
        })
    }

    pub const fn mark(&self) -> u64 {
        self.mark
    }

    pub const fn written(&self) -> u64 {
        self.written
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<u64> {
        let offset = self.mark;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        if end > self.source.len() {
            self.source.reserve(grown(self.source.len(), end))?;
        }
        self.source.write_all_at(offset, bytes)?;
        self.mark = end;
        self.written += bytes.len() as u64;
        Ok(offset)
    }

    pub fn commit(&self) -> Result<()> {
        self.source.write_u64(layout::ALLOCATION_MARK, self.mark)?;
        self.source.sync()
    }
}

fn counter(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::OffsetOverflow)
}

fn grown(current: u64, needed: u64) -> u64 {
    let target = needed.max(current.saturating_add(current.min(GROWTH_CAP)));
    target
        .checked_next_multiple_of(GROWTH_GRANULARITY)
        .unwrap_or(target)
}

fn next_free(source: &FileSource, chunk_array: u64, chunk_array_capacity: u32) -> Result<u32> {
    let mut used = 0u32;
    for chunk in 0..chunk_array_capacity {
        let array = source.slot(chunk_array, chunk)?;
        if array == 0 {
            break;
        }
        for index in 0..source.slots(array)? {
            if source.slot(array, index)? == 0 {
                return Ok(used);
            }
            used += 1;
        }
    }
    Ok(used)
}

fn slot_count(value: u64, what: &'static str) -> Result<u32> {
    let slots = counter(value)?;
    if slots == 0 || slots > MAX_SLOTS {
        return Err(Error::ResourceLimit {
            resource: what,
            requested: value,
            limit: u64::from(MAX_SLOTS),
        });
    }
    Ok(slots)
}

#[derive(Debug)]
struct Collection {
    count: u32,
    count_offset: u64,
    chunk_capacity: u32,
    chunk_count_offset: u64,
    chunk_array: u64,
    chunk_array_field: u64,
    chunk_array_capacity: u32,
    used: u32,
}

impl Collection {
    fn open(source: &FileSource, chunking: u64) -> Result<Self> {
        let fields = schema::expect(source, chunking, &layout::CHUNKING, "chunked list")?;
        let table = fields[&2].unsigned;
        let table_fields = schema::expect(source, table, &layout::TABLE, "chunk table")?;
        let chunk_array = table_fields[&1].unsigned;
        let chunk_capacity = slot_count(fields[&1].unsigned, "chunk capacity")?;
        let chunk_array_capacity =
            slot_count(u64::from(source.slots(chunk_array)?), "chunk table slots")?;
        Ok(Self {
            count: counter(fields[&0].unsigned)?,
            count_offset: fields[&0].offset,
            chunk_capacity,
            chunk_count_offset: table_fields[&0].offset,
            chunk_array,
            chunk_array_field: table_fields[&1].offset,
            chunk_array_capacity,
            used: next_free(source, chunk_array, chunk_array_capacity)?,
        })
    }

    fn relocate(
        &mut self,
        writer: &mut Writer<'_>,
        source: &FileSource,
        needed: u32,
    ) -> Result<()> {
        let capacity = needed.max(self.chunk_array_capacity.saturating_mul(2));
        if capacity > MAX_SLOTS {
            return Err(Error::ResourceLimit {
                resource: "history collection chunks",
                requested: u64::from(capacity),
                limit: u64::from(MAX_SLOTS),
            });
        }
        let relocated = writer.write(&reference_array(capacity))?;
        for index in 0..self.chunk_array_capacity {
            source.set_slot(relocated, index, source.slot(self.chunk_array, index)?)?;
        }
        source.write_u64(self.chunk_array_field, relocated)?;
        self.chunk_array = relocated;
        self.chunk_array_capacity = capacity;
        Ok(())
    }

    fn append(&mut self, writer: &mut Writer<'_>, source: &FileSource, value: u64) -> Result<()> {
        let position = self.used;
        let chunk_index = position / self.chunk_capacity;
        if chunk_index >= self.chunk_array_capacity {
            self.relocate(writer, source, chunk_index + 1)?;
        }
        let mut array = source.slot(self.chunk_array, chunk_index)?;
        if array == 0 {
            array = writer.write(&reference_array(self.chunk_capacity))?;
            source.set_slot(self.chunk_array, chunk_index, array)?;
        }
        source.set_slot(array, position % self.chunk_capacity, value)?;
        self.used += 1;
        self.count += 1;
        source.write_u32(self.count_offset, self.count)?;
        source.write_u32(self.chunk_count_offset, chunk_index + 1)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct History {
    total: u32,
    total_offset: u64,
    collections: Vec<Collection>,
}

impl History {
    pub fn open(source: &FileSource) -> Result<Self> {
        let root = schema::compact_at(source, layout::ROOT_OFFSET)?
            .filter(|record| record.type_id() == Some(layout::ROOT_TYPE_ID))
            .ok_or_else(|| {
                Error::Malformed(
                    "no compact root at 0xFC; this Burp project version is unsupported".to_owned(),
                )
            })?
            .slices(source)?;
        let list = root[&layout::ROOT_HISTORY_TAG].unsigned >> 16;
        let fields = schema::expect(source, list, &layout::HISTORY_LIST, "Proxy history list")?;

        Ok(Self {
            total: counter(fields[&4].unsigned)?,
            total_offset: fields[&4].offset,
            collections: [0u8, 1]
                .iter()
                .map(|tag| Collection::open(source, fields[tag].unsigned))
                .collect::<Result<_>>()?,
        })
    }

    pub const fn total(&self) -> u32 {
        self.total
    }

    pub fn record(&mut self, writer: &mut Writer<'_>, source: &FileSource, row: u64) -> Result<()> {
        for collection in &mut self.collections {
            collection.append(writer, source, row)?;
        }
        self.total += 1;
        source.write_u32(self.total_offset, self.total)
    }
}

fn write_frame(writer: &mut Writer<'_>, payload: &[u8]) -> Result<u64> {
    let length = u32::try_from(payload.len()).map_err(|_| Error::OffsetOverflow)?;
    let mut blob = Vec::with_capacity(payload.len() + 8);
    blob.extend_from_slice(&frame::header(length));
    blob.extend_from_slice(payload);
    writer.write(&blob)
}

fn write_comment(writer: &mut Writer<'_>, comment: &str) -> Result<u64> {
    if comment.is_empty() {
        return Ok(0);
    }
    let units = comment.encode_utf16().count() as u64;
    let text_offset = writer.write(&text(comment)?)?;
    let chunk = writer.write(&standard(
        &layout::COMMENT_CHUNK,
        &[
            Field::new(1, text_offset, 8),
            Field::new(2, units, 4),
            Field::new(3, 0, 8),
        ],
    )?)?;
    writer.write(&standard(
        &layout::COMMENT_WRAPPER,
        &[Field::new(1, units, 8), Field::new(2, chunk, 8)],
    )?)
}

fn write_text_record(writer: &mut Writer<'_>, value: &[u8]) -> Result<u64> {
    if value.is_empty() {
        return Ok(0);
    }
    let units = u32::try_from(fields::utf16_count(value)).map_err(|_| Error::OffsetOverflow)?;
    let mut frame = Vec::with_capacity(8 + units as usize * 2);
    frame.extend_from_slice(&(8 + units * 2).to_be_bytes());
    frame.extend_from_slice(&units.to_be_bytes());
    frame.extend_from_slice(&fields::utf16be_bytes(value));
    let frame_offset = writer.write(&frame)?;
    writer.write(&standard(
        &layout::TEXT_WRAPPER,
        &[
            Field::new(0, frame_offset, 8),
            Field::new(1, frame.len() as u64, 8),
        ],
    )?)
}

fn write_url_cache(
    writer: &mut Writer<'_>,
    path: &[u8],
    extension: &[u8],
    host: &str,
    title: &[u8],
    cookies: &[u8],
) -> Result<u64> {
    let even = (path.len() + 1) & !1;
    let path_len = u32::try_from(path.len()).map_err(|_| Error::OffsetOverflow)?;
    let mut blob = Vec::with_capacity(8 + even);
    blob.extend_from_slice(&(8 + path_len).to_be_bytes());
    blob.extend_from_slice(&path_len.to_be_bytes());
    blob.extend_from_slice(path);
    blob.resize(8 + even, 0);
    let offset = writer.write(&blob)?;

    for value in [extension, host.as_bytes(), title, cookies] {
        if value.is_empty() {
            continue;
        }
        let units = u32::try_from(fields::utf16_count(value)).map_err(|_| Error::OffsetOverflow)?;
        let mut wrapper = standard(
            &layout::TEXT_WRAPPER,
            &[Field::new(0, 0, 8), Field::new(1, 8 + u64::from(units) * 2, 8)],
        )?;
        let frame_offset = writer.mark() + wrapper.len() as u64 - 4;
        wrapper[10..18].copy_from_slice(&frame_offset.to_be_bytes());
        let mut item = Vec::with_capacity(wrapper.len() + 4 + units as usize * 2);
        item.extend_from_slice(&wrapper);
        item.extend_from_slice(&units.to_be_bytes());
        item.extend_from_slice(&fields::utf16be_bytes(value));
        writer.write(&item)?;
    }
    Ok(offset)
}

fn write_request_metadata(
    writer: &mut Writer<'_>,
    entry: &Entry,
    path: &[u8],
    url_cache: u64,
) -> Result<u64> {
    let host_text = text(&entry.host)?;
    let host_length = host_text.len() as u64;
    let host_offset = writer.write(&host_text)?;

    let wrapper = writer.write(&standard(
        &layout::HOST_WRAPPER,
        &[Field::new(0, host_offset, 8), Field::new(1, host_length, 8)],
    )?)?;

    let service = writer.write(&standard(
        &layout::SERVICE,
        &[
            Field::new(0, wrapper, 8),
            Field::new(1, u64::from(entry.port), 4),
            Field::new(2, u64::from(entry.tls), 1),
            Field::new(3, layout::SERVICE_TAG3, 1),
            Field::new(4, entry.time_epoch_ms, 8),
            Field::new(5, 0, 8),
            Field::new(6, layout::SERVICE_TAG6, 8),
        ],
    )?)?;

    let cache_total = 8 + path.len() as u64;
    writer.write(&standard(
        &layout::REQUEST_METADATA,
        &[
            Field::new(0, service, 8),
            Field::new(1, url_cache, 8),
            Field::new(2, layout::METADATA_SENTINEL, 4),
            Field::new(3, layout::METADATA_SENTINEL, 4),
            Field::new(4, 0, 8),
            Field::new(5, cache_total, 8),
        ],
    )?)
}

pub fn write_entry(writer: &mut Writer<'_>, entry: &Entry, entry_id: u64) -> Result<u64> {
    let request = write_frame(writer, &entry.request)?;
    let response = match entry.response.as_deref() {
        Some(payload) => write_frame(writer, payload)?,
        None => 0,
    };

    let method = write_text_record(writer, fields::request_method(&entry.request))?;
    let ip = write_text_record(writer, entry.ip.as_bytes())?;
    let title_text: Vec<u8> = entry
        .response
        .as_deref()
        .map(fields::extract_title)
        .unwrap_or_default();
    let title = write_text_record(writer, &title_text)?;

    let target = fields::request_target(&entry.request);
    let path = match target.iter().position(|byte| *byte == b'?') {
        Some(query) => &target[..query],
        None => target,
    };
    let path = if path.is_empty() {
        b"/".as_slice()
    } else {
        path
    };
    let extension_name = fields::url_extension(path);
    let extension = write_text_record(writer, extension_name)?;
    let cookie_name: &[u8] = entry
        .response
        .as_deref()
        .map_or(&[], fields::cookie_value);
    let cookies = write_text_record(writer, cookie_name)?;
    let url_cache = write_url_cache(
        writer,
        path,
        extension_name,
        &entry.host,
        &title_text,
        cookie_name,
    )?;
    let metadata = write_request_metadata(writer, entry, path, url_cache)?;

    let comment = write_comment(writer, &entry.comment)?;
    let highlight = match entry.highlight.as_deref() {
        Some(name) if !name.is_empty() => highlight_code(name)
            .ok_or_else(|| Error::Malformed(format!("unknown highlight colour {name}")))?,
        _ => 0,
    };
    let response_length = entry.response.as_ref().map_or(0, Vec::len) as u64;
    let mime = fields::mime_code(entry.response.as_deref().unwrap_or(&[]));

    let values = [
        (127, layout::ROW_MAGIC),
        (tag::ENTRY_ID, entry_id),
        (tag::METHOD, method),
        (tag::REQUEST_METADATA, metadata),
        (tag::EXTENSION, extension),
        (tag::IP, ip),
        (tag::STATUS_CODE, u64::from(entry.status)),
        (tag::MIME_CODE, mime),
        (tag::RESPONSE_LENGTH, response_length),
        (tag::TITLE, title),
        (tag::COOKIES, cookies),
        (tag::TIME_EPOCH_MS, entry.time_epoch_ms),
        (tag::HIGHLIGHT, highlight),
        (tag::LISTENER_PORT, u64::from(entry.listener_port)),
        (tag::REQUEST_FRAME, request),
        (tag::RESPONSE_FRAME, response),
        (24, layout::ROW_TAG24),
        (25, layout::ROW_TAG25),
        (26, layout::ROW_TAG26),
        (tag::COMMENT_WRAPPER, comment),
        (tag::SECONDARY_TIME, entry.time_epoch_ms),
    ];
    let row_fields: Vec<Field> = layout::ROW_WIDTHS
        .iter()
        .map(|(tag, width)| {
            let value = values
                .iter()
                .find(|(candidate, _)| candidate == tag)
                .map_or(0, |(_, value)| *value);
            Field::new(*tag, value, *width)
        })
        .collect();

    writer.write(&typed(layout::ROW_TYPE_ID, &layout::ROW, &row_fields)?)
}
