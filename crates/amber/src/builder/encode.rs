use crate::binary::Schema;
use crate::diagnostic::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub tag: u8,
    pub value: u64,
    pub width: u8,
}

impl Field {
    pub const fn new(tag: u8, value: u64, width: u8) -> Self {
        Self { tag, value, width }
    }
}

fn body(schema: &Schema, fields: &[Field]) -> Result<Vec<u8>> {
    let find = |tag: u8| {
        fields
            .iter()
            .find(|field| field.tag == tag)
            .copied()
            .ok_or_else(|| Error::Malformed(format!("missing value for tag {tag}")))
    };
    let (last_tag, last_relative) = *schema
        .last()
        .ok_or_else(|| Error::Malformed("empty schema".to_owned()))?;
    let span = usize::from(last_relative) + usize::from(find(last_tag)?.width);
    let mut blob = vec![0u8; span];

    for (tag, relative) in schema {
        let field = find(*tag)?;
        let start = usize::from(*relative);
        let width = usize::from(field.width);
        if field.width == 0 || field.width > 8 || start + width > span {
            return Err(Error::Malformed(format!(
                "field tag {tag} does not fit at relative offset {relative}"
            )));
        }
        if field.width < 8 && field.value >= 1u64 << (field.width * 8) {
            return Err(Error::Malformed(format!(
                "field tag {tag} value {} does not fit in {width} bytes",
                field.value
            )));
        }
        blob[start..start + width].copy_from_slice(&field.value.to_be_bytes()[8 - width..]);
    }
    Ok(blob)
}

fn descriptors(blob: &mut [u8], schema: &Schema) {
    for (index, (tag, relative)) in schema.iter().enumerate() {
        let base = 4 + index * 3;
        blob[base] = *tag;
        blob[base + 1..base + 3].copy_from_slice(&relative.to_be_bytes());
    }
}

fn count<T: TryFrom<usize>>(schema: &Schema) -> Result<T> {
    T::try_from(schema.len()).map_err(|_| Error::OffsetOverflow)
}

pub fn standard(schema: &Schema, fields: &[Field]) -> Result<Vec<u8>> {
    let mut blob = body(schema, fields)?;
    blob[0..4].copy_from_slice(&count::<u32>(schema)?.to_be_bytes());
    descriptors(&mut blob, schema);
    Ok(blob)
}

pub fn typed(type_id: u16, schema: &Schema, fields: &[Field]) -> Result<Vec<u8>> {
    let mut blob = body(schema, fields)?;
    blob[0..2].copy_from_slice(&type_id.to_be_bytes());
    blob[2..4].copy_from_slice(&count::<u16>(schema)?.to_be_bytes());
    descriptors(&mut blob, schema);
    Ok(blob)
}

pub fn text(value: &str) -> Result<Vec<u8>> {
    let units: Vec<u16> = value.encode_utf16().collect();
    let length = u32::try_from(units.len()).map_err(|_| Error::OffsetOverflow)?;
    let mut blob = Vec::with_capacity(8 + units.len() * 2);
    blob.extend_from_slice(&(8 + length * 2).to_be_bytes());
    blob.extend_from_slice(&length.to_be_bytes());
    for unit in units {
        blob.extend_from_slice(&unit.to_be_bytes());
    }
    Ok(blob)
}

pub fn reference_array(capacity: u32) -> Vec<u8> {
    let mut blob = Vec::with_capacity(8 + capacity as usize * 8);
    blob.extend_from_slice(&(8 + capacity * 8).to_be_bytes());
    blob.extend_from_slice(&capacity.to_be_bytes());
    blob.resize(8 + capacity as usize * 8, 0);
    blob
}
