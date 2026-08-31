use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::diagnostic::{Error, Result, SourceRange};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextFrame {
    pub value: String,
    pub frame_offset: u64,
    pub data_offset: u64,
    pub frame_length: u32,
    pub capacity: u32,
    pub length: u32,
}

#[derive(Debug)]
pub struct FileSource {
    file: File,
    length: Cell<u64>,
    cursor: Cell<Option<u64>>,
}

impl FileSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_file(File::open(path)?)
    }

    pub fn open_read_write(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_file(OpenOptions::new().read(true).write(true).open(path)?)
    }

    fn from_file(file: File) -> Result<Self> {
        let length = Cell::new(file.metadata()?.len());
        Ok(Self {
            file,
            length,
            cursor: Cell::new(Some(0)),
        })
    }

    pub fn len(&self) -> u64 {
        self.length.get()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn reserve(&self, length: u64) -> Result<()> {
        if length > self.len() {
            self.file.set_len(length)?;
            self.length.set(length);
        }
        Ok(())
    }

    fn check(&self, range: SourceRange) -> Result<()> {
        if range.checked_end()? > self.len() {
            return Err(Error::OutOfBounds {
                range,
                source_length: self.len(),
            });
        }
        Ok(())
    }

    fn seek(&self, offset: u64) -> Result<()> {
        if self.cursor.replace(None) != Some(offset) {
            (&self.file).seek(SeekFrom::Start(offset))?;
        }
        Ok(())
    }

    pub fn read_into_at(&self, offset: u64, mut output: &mut [u8]) -> Result<()> {
        let expected = output.len();
        self.seek(offset)?;
        let mut handle = &self.file;
        while !output.is_empty() {
            match handle.read(output) {
                Ok(0) => {
                    return Err(Error::ShortRead {
                        offset,
                        expected,
                        actual: expected - output.len(),
                    });
                }
                Ok(read) => output = &mut output[read..],
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.cursor.set(offset.checked_add(expected as u64));
        Ok(())
    }

    pub fn write_all_at(&self, offset: u64, mut bytes: &[u8]) -> Result<()> {
        let expected = bytes.len();
        self.check(SourceRange::new(offset, expected as u64))?;
        self.seek(offset)?;
        let mut handle = &self.file;
        while !bytes.is_empty() {
            match handle.write(bytes) {
                Ok(0) => {
                    return Err(Error::ShortRead {
                        offset,
                        expected,
                        actual: expected - bytes.len(),
                    });
                }
                Ok(written) => bytes = &bytes[written..],
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.cursor.set(offset.checked_add(expected as u64));
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }

    pub fn bytes(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        let range = SourceRange::new(offset, length);
        self.check(range)?;
        let mut output = vec![0; usize::try_from(length).map_err(|_| Error::OffsetOverflow)?];
        self.read_into_at(offset, &mut output)?;
        Ok(output)
    }

    pub fn range(&self, range: SourceRange) -> Result<Vec<u8>> {
        self.bytes(range.offset, range.length)
    }

    fn scalar<const N: usize>(&self, offset: u64) -> Result<[u8; N]> {
        self.bytes(offset, N as u64)?
            .try_into()
            .map_err(|_| Error::OffsetOverflow)
    }

    pub fn u8(&self, offset: u64) -> Result<u8> {
        Ok(self.scalar::<1>(offset)?[0])
    }

    pub fn u16(&self, offset: u64) -> Result<u16> {
        Ok(u16::from_be_bytes(self.scalar(offset)?))
    }

    pub fn u32(&self, offset: u64) -> Result<u32> {
        Ok(u32::from_be_bytes(self.scalar(offset)?))
    }

    pub fn u64(&self, offset: u64) -> Result<u64> {
        Ok(u64::from_be_bytes(self.scalar(offset)?))
    }

    pub fn write_u32(&self, offset: u64, value: u32) -> Result<()> {
        self.write_all_at(offset, &value.to_be_bytes())
    }

    pub fn write_u64(&self, offset: u64, value: u64) -> Result<()> {
        self.write_all_at(offset, &value.to_be_bytes())
    }

    pub fn utf16be(&self, offset: u64, code_units: u64) -> Result<String> {
        let length = code_units.checked_mul(2).ok_or(Error::OffsetOverflow)?;
        let range = SourceRange::new(offset, length);
        let units: Vec<u16> = self
            .range(range)?
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).map_err(|_| Error::InvalidUtf16 { range })
    }

    pub fn text_frame(&self, offset: u64, logical: Option<u64>) -> Result<Option<TextFrame>> {
        if offset.checked_add(8).ok_or(Error::OffsetOverflow)? > self.len() {
            return Ok(None);
        }
        let frame_length = self.u32(offset)?;
        let capacity = self.u32(offset + 4)?;
        if u64::from(frame_length) != 8 + u64::from(capacity) * 2
            || offset + u64::from(frame_length) > self.len()
        {
            return Ok(None);
        }
        let length = logical.unwrap_or_else(|| u64::from(capacity));
        if length > u64::from(capacity) {
            return Ok(None);
        }
        let Ok(value) = self.utf16be(offset + 8, length) else {
            return Ok(None);
        };
        Ok(Some(TextFrame {
            value,
            frame_offset: offset,
            data_offset: offset + 8,
            frame_length,
            capacity,
            length: u32::try_from(length).map_err(|_| Error::OffsetOverflow)?,
        }))
    }

    pub fn slots(&self, array: u64) -> Result<u32> {
        self.u32(array + 4)
    }

    pub fn slot(&self, array: u64, index: u32) -> Result<u64> {
        self.u64(array + 8 + u64::from(index) * 8)
    }

    pub fn set_slot(&self, array: u64, index: u32, value: u64) -> Result<()> {
        self.write_u64(array + 8 + u64::from(index) * 8, value)
    }
}
