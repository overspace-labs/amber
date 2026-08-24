use std::collections::BTreeMap;

use crate::binary::{FileSource, FrameKind, HttpFrame, digest, frame_at, schema};
use crate::diagnostic::{Error, Result, SourceRange};
use crate::model::history::{
    Comment, CommentChunk, HistoryEntry, HostText, HttpHeader, Message, PortValue, RawField,
    Service, Timing, TlsValue, Validation,
};

use super::layout::{self, tag};

const HEADER_PARSE_LIMIT: u64 = 1024 * 1024;
const SEPARATOR_CHUNK: u64 = 64 * 1024;
const MAX_COMMENT_CHUNKS: usize = 10_000;

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    (from <= haystack.len())
        .then(|| memchr::memmem::find(&haystack[from..], needle).map(|found| from + found))
        .flatten()
}

fn header_end(source: &FileSource, range: SourceRange) -> Result<u64> {
    let needle = b"\r\n\r\n";
    let mut carry: Vec<u8> = Vec::new();
    let mut consumed = 0u64;
    let mut buffer = vec![0u8; usize::try_from(range.length.min(SEPARATOR_CHUNK)).unwrap_or(0)];

    while consumed < range.length {
        let amount = usize::try_from((range.length - consumed).min(SEPARATOR_CHUNK))
            .map_err(|_| Error::OffsetOverflow)?;
        let window = &mut buffer[..amount];
        source.read_into_at(range.offset + consumed, window)?;
        let mut scan = Vec::with_capacity(carry.len() + amount);
        scan.extend_from_slice(&carry);
        scan.extend_from_slice(window);
        let origin = consumed - carry.len() as u64;
        if let Some(found) = find(&scan, needle, 0) {
            return Ok(origin + found as u64 + needle.len() as u64);
        }
        carry.clear();
        carry.extend_from_slice(&scan[scan.len().saturating_sub(needle.len() - 1)..]);
        consumed += amount as u64;
    }
    Ok(range.length)
}

fn parse_headers(block: &[u8], block_offset: u64) -> Vec<HttpHeader> {
    let Some(first_end) = find(block, b"\r\n", 0) else {
        return Vec::new();
    };
    let mut headers = Vec::new();
    let mut cursor = first_end + 2;
    while cursor + 2 <= block.len() {
        let Some(line_end) = find(block, b"\r\n", cursor) else {
            break;
        };
        if line_end == cursor {
            break;
        }
        let line = &block[cursor..line_end];
        if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            let mut start = colon + 1;
            while start < line.len() && (line[start] == b' ' || line[start] == b'\t') {
                start += 1;
            }
            headers.push(HttpHeader {
                name: latin1(&line[..colon]),
                value: latin1(&line[start..]),
                offset: block_offset + cursor as u64,
                length: line.len() as u64,
            });
        }
        cursor = line_end + 2;
    }
    headers
}

pub fn decode_message(source: &FileSource, frame: HttpFrame) -> Result<Message> {
    let payload = frame.payload();
    let head = header_end(source, payload)?;
    let window = head.min(HEADER_PARSE_LIMIT);
    let block = source.bytes(payload.offset, window)?;
    let body_offset = payload.offset + head;
    let body_length = payload.length - head;

    let mut message = Message {
        frame_offset: frame.frame_offset,
        payload_offset: payload.offset,
        length: payload.length,
        sha256: digest(source, payload)?,
        headers: if head <= HEADER_PARSE_LIMIT {
            parse_headers(&block, payload.offset)
        } else {
            Vec::new()
        },
        body_offset,
        body_length,
        body_sha256: digest(source, SourceRange::new(body_offset, body_length))?,
        method: None,
        target: None,
        http_version: None,
        status_code: None,
        reason: None,
        url: None,
        blob: None,
    };

    if let Some(end) = find(&block, b"\r\n", 0) {
        let line = &block[..end];
        match frame.kind {
            FrameKind::Request => {
                let mut parts = line.splitn(3, |byte| *byte == b' ');
                if let (Some(method), Some(target), Some(version)) =
                    (parts.next(), parts.next(), parts.next())
                {
                    message.method = Some(latin1(method));
                    message.target = Some(latin1(target));
                    message.http_version = Some(latin1(version));
                }
            }
            FrameKind::Response => {
                let mut parts = line.splitn(3, |byte| *byte == b' ');
                let version = parts.next().unwrap_or_default();
                if let Some(status) = parts
                    .next()
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .and_then(|text| text.parse::<u16>().ok())
                {
                    message.http_version = Some(latin1(version));
                    message.status_code = Some(status);
                    message.reason = Some(latin1(parts.next().unwrap_or_default()));
                }
            }
        }
    }
    Ok(message)
}

fn optional(
    source: &FileSource,
    offset: u64,
    expected: &crate::binary::Schema,
) -> Result<Option<crate::binary::Fields>> {
    let Some(record) = schema::standard_at(source, offset)? else {
        return Ok(None);
    };
    if !record.matches(expected) {
        return Ok(None);
    }
    Ok(Some(record.slices(source)?))
}

pub fn decode_service(source: &FileSource, metadata_offset: u64) -> Result<Option<Service>> {
    if metadata_offset == 0 {
        return Ok(None);
    }
    let Some(metadata) = optional(source, metadata_offset, &layout::REQUEST_METADATA)? else {
        return Ok(None);
    };
    let service_offset = metadata[&0].unsigned;
    let Some(service) = optional(source, service_offset, &layout::SERVICE)? else {
        return Ok(None);
    };
    let wrapper_offset = service[&0].unsigned;
    let Some(wrapper) = optional(source, wrapper_offset, &layout::HOST_WRAPPER)? else {
        return Ok(None);
    };
    let Some(host) = source.text_frame(wrapper[&0].unsigned, None)? else {
        return Ok(None);
    };

    Ok(Some(Service {
        host: HostText {
            text: host,
            wrapper_offset,
        },
        port: PortValue {
            value: service[&1].unsigned,
            offset: service[&1].offset,
            width: service[&1].width,
        },
        tls: TlsValue {
            value: service[&2].unsigned != 0,
            offset: service[&2].offset,
            width: service[&2].width,
        },
        service_offset,
        request_metadata_offset: metadata_offset,
    }))
}

pub fn decode_comment(source: &FileSource, wrapper_offset: u64) -> Result<Comment> {
    let mut comment = Comment {
        wrapper_offset: (wrapper_offset != 0).then_some(wrapper_offset),
        ..Comment::default()
    };
    if wrapper_offset == 0 {
        return Ok(comment);
    }
    let Some(wrapper) = optional(source, wrapper_offset, &layout::COMMENT_WRAPPER)? else {
        return Ok(comment);
    };

    let mut current = wrapper[&2].unsigned;
    let mut seen = Vec::new();
    while current != 0 && !seen.contains(&current) && comment.chunks.len() < MAX_COMMENT_CHUNKS {
        seen.push(current);
        let Some(chunk) = optional(source, current, &layout::COMMENT_CHUNK)? else {
            break;
        };
        let Some(text) = source.text_frame(chunk[&1].unsigned, Some(chunk[&2].unsigned))? else {
            break;
        };
        comment.value.push_str(&text.value);
        comment.chunks.push(CommentChunk {
            text,
            object_offset: current,
            length_field_offset: chunk[&2].offset,
            next_field_offset: chunk[&3].offset,
        });
        current = chunk[&3].unsigned;
    }
    Ok(comment)
}

pub fn row_at(source: &FileSource, offset: u64) -> Result<Option<crate::binary::ObjectRecord>> {
    Ok(schema::typed_at(source, offset)?.filter(|record| {
        record.type_id() == Some(layout::ROW_TYPE_ID) && record.matches(&layout::ROW)
    }))
}

pub fn decode_entry(
    source: &FileSource,
    fields: &crate::binary::Fields,
    row_offset: u64,
    ordinal: u64,
) -> Result<Option<HistoryEntry>> {
    let Some(request_frame) = frame_at(source, fields[&tag::REQUEST_FRAME].unsigned)? else {
        return Ok(None);
    };
    if request_frame.kind != FrameKind::Request {
        return Ok(None);
    }
    let response_offset = fields[&tag::RESPONSE_FRAME].unsigned;
    let response_frame = if response_offset == 0 {
        None
    } else {
        match frame_at(source, response_offset)? {
            Some(frame) if frame.kind == FrameKind::Response => Some(frame),
            Some(_) => return Ok(None),
            None => None,
        }
    };

    let service = decode_service(source, fields[&tag::REQUEST_METADATA].unsigned)?;
    let mut request = decode_message(source, request_frame)?;
    let response = match response_frame {
        Some(frame) => Some(decode_message(source, frame)?),
        None => None,
    };
    if let Some(service) = service.as_ref() {
        request.url = Some(service.url(request.target.as_deref().unwrap_or_default()));
    }

    let status = fields[&tag::STATUS_CODE];
    let length = fields[&tag::RESPONSE_LENGTH];
    let listener = fields[&tag::LISTENER_PORT];
    let entry_id = fields[&tag::ENTRY_ID].unsigned;

    Ok(Some(HistoryEntry {
        ordinal,
        entry_id,
        row_offset,
        tool_source: "proxy".to_owned(),
        validation: Validation {
            service_decoded: service.is_some(),
            status_matches: match response.as_ref() {
                None => status.unsigned == 0,
                Some(message) => Some(status.unsigned) == message.status_code.map(u64::from),
            },
            response_length_matches: match response.as_ref() {
                None => length.unsigned == 0,
                Some(message) => length.unsigned == message.length,
            },
            listener_port_valid: (1..=65535).contains(&listener.unsigned),
            entry_id_valid: entry_id > 0,
        },
        service,
        request,
        response,
        status_code: status.into(),
        burp_mime_code: fields[&tag::MIME_CODE].into(),
        response_length: length.into(),
        time_epoch_ms: fields[&tag::TIME_EPOCH_MS].into(),
        listener_port: listener.into(),
        highlight: fields[&tag::HIGHLIGHT].into(),
        comment: decode_comment(source, fields[&tag::COMMENT_WRAPPER].unsigned)?,
        timing: Timing {
            value_1: fields[&tag::TIMING_1].into(),
            value_2: fields[&tag::TIMING_2].into(),
            secondary_time_epoch_ms: fields[&tag::SECONDARY_TIME].into(),
        },
        raw_fields: fields
            .values()
            .map(|slice| (slice.tag.to_string(), RawField::from(*slice)))
            .collect::<BTreeMap<_, _>>(),
    }))
}
