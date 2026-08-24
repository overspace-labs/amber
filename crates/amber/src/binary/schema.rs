use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::diagnostic::{Error, Result};

use super::source::FileSource;

pub const MAX_FIELDS: u16 = 32;
pub const MAX_SCHEMA_BYTES: u64 = 0x0001_0000;
pub const LAST_FIELD_WIDTH: u64 = 8;

pub type Schema = [(u8, u16)];
pub type Fields = BTreeMap<u8, FieldSlice>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Envelope {
    Standard,
    Typed { type_id: u16 },
    Compact { type_id: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSlice {
    pub tag: u8,
    pub offset: u64,
    pub width: u8,
    pub unsigned: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRecord {
    pub offset: u64,
    pub envelope: Envelope,
    pub fields: Vec<(u8, u16)>,
}

impl ObjectRecord {
    pub const fn type_id(&self) -> Option<u16> {
        match self.envelope {
            Envelope::Standard => None,
            Envelope::Typed { type_id } => Some(type_id),
            Envelope::Compact { type_id } => Some(type_id as u16),
        }
    }

    pub fn matches(&self, schema: &Schema) -> bool {
        self.fields == schema
    }

    pub fn slices(&self, source: &FileSource) -> Result<Fields> {
        let mut slices = BTreeMap::new();
        for (index, (tag, relative)) in self.fields.iter().enumerate() {
            let offset = self.offset + u64::from(*relative);
            let width = match self.fields.get(index + 1) {
                Some((_, next)) => u64::from(*next - *relative),
                None => LAST_FIELD_WIDTH,
            };
            if width == 0 || width > 8 {
                return Err(Error::Malformed(format!(
                    "field tag {tag} at offset {offset} has unsupported width {width}"
                )));
            }
            let mut unsigned = 0u64;
            for byte in source.bytes(offset, width)? {
                unsigned = (unsigned << 8) | u64::from(byte);
            }
            slices.insert(
                *tag,
                FieldSlice {
                    tag: *tag,
                    offset,
                    width: u8::try_from(width).map_err(|_| Error::OffsetOverflow)?,
                    unsigned,
                },
            );
        }
        Ok(slices)
    }
}

fn descriptors(
    source: &FileSource,
    offset: u64,
    table: u64,
    count: u16,
    header_length: u64,
) -> Result<Option<Vec<(u8, u16)>>> {
    if offset + header_length > source.len() {
        return Ok(None);
    }
    let bytes = source.bytes(table, u64::from(count) * 3)?;
    let mut fields = Vec::with_capacity(count as usize);
    let mut previous = 0u16;
    for index in 0..count as usize {
        let base = index * 3;
        let relative = u16::from_be_bytes([bytes[base + 1], bytes[base + 2]]);
        if index == 0 {
            if u64::from(relative) != header_length {
                return Ok(None);
            }
        } else if relative < previous {
            return Ok(None);
        }
        previous = relative;
        fields.push((bytes[base], relative));
    }
    if u64::from(previous) > MAX_SCHEMA_BYTES {
        return Ok(None);
    }
    Ok(Some(fields))
}

fn record(
    source: &FileSource,
    offset: u64,
    envelope: Envelope,
    table: u64,
    count: u16,
) -> Result<Option<ObjectRecord>> {
    if count == 0 || count > MAX_FIELDS {
        return Ok(None);
    }
    let header_length = 4 + u64::from(count) * 3;
    Ok(
        descriptors(source, offset, table, count, header_length)?.map(|fields| ObjectRecord {
            offset,
            envelope,
            fields,
        }),
    )
}

pub fn standard_at(source: &FileSource, offset: u64) -> Result<Option<ObjectRecord>> {
    if offset.checked_add(4).ok_or(Error::OffsetOverflow)? > source.len() {
        return Ok(None);
    }
    let Ok(count) = u16::try_from(source.u32(offset)?) else {
        return Ok(None);
    };
    record(source, offset, Envelope::Standard, offset + 4, count)
}

pub fn typed_at(source: &FileSource, offset: u64) -> Result<Option<ObjectRecord>> {
    if offset.checked_add(4).ok_or(Error::OffsetOverflow)? > source.len() {
        return Ok(None);
    }
    let type_id = source.u16(offset)?;
    if type_id == 0 {
        return Ok(None);
    }
    let count = source.u16(offset + 2)?;
    record(
        source,
        offset,
        Envelope::Typed { type_id },
        offset + 4,
        count,
    )
}

pub fn compact_at(source: &FileSource, offset: u64) -> Result<Option<ObjectRecord>> {
    if offset.checked_add(2).ok_or(Error::OffsetOverflow)? > source.len() {
        return Ok(None);
    }
    let type_id = source.u8(offset)?;
    if type_id == 0 || type_id > 127 {
        return Ok(None);
    }
    let count = u16::from(source.u8(offset + 1)?);
    record(
        source,
        offset,
        Envelope::Compact { type_id },
        offset + 2,
        count,
    )
}

pub fn expect(source: &FileSource, offset: u64, schema: &Schema, what: &str) -> Result<Fields> {
    standard_at(source, offset)?
        .filter(|record| record.matches(schema))
        .ok_or_else(|| Error::Malformed(format!("no {what} at {offset}")))?
        .slices(source)
}

pub fn typed_header(type_id: u16, schema: &Schema) -> Vec<u8> {
    let count = u16::try_from(schema.len()).unwrap_or(u16::MAX);
    let mut header = Vec::with_capacity(4 + schema.len() * 3);
    header.extend_from_slice(&type_id.to_be_bytes());
    header.extend_from_slice(&count.to_be_bytes());
    for (tag, relative) in schema {
        header.push(*tag);
        header.extend_from_slice(&relative.to_be_bytes());
    }
    header
}
