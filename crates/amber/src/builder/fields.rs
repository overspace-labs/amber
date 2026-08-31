use crate::history::layout;

pub(crate) const TITLE_LIMIT: usize = 200;

fn decode_rune_go(bytes: &[u8], i: usize) -> (u32, usize) {
    let b0 = bytes[i];
    if b0 < 0x80 {
        return (u32::from(b0), 1);
    }
    let cont = |j: usize| j < bytes.len() && bytes[j] & 0xC0 == 0x80;
    if b0 < 0xC0 {
        return (0xFFFD, 1);
    }
    if b0 < 0xE0 {
        if !cont(i + 1) {
            return (0xFFFD, 1);
        }
        let r = u32::from(b0 & 0x1F) << 6 | u32::from(bytes[i + 1] & 0x3F);
        if r < 0x80 {
            return (0xFFFD, 1);
        }
        return (r, 2);
    }
    if b0 < 0xF0 {
        if !cont(i + 1) || !cont(i + 2) {
            return (0xFFFD, 1);
        }
        let r = u32::from(b0 & 0x0F) << 12
            | u32::from(bytes[i + 1] & 0x3F) << 6
            | u32::from(bytes[i + 2] & 0x3F);
        if r < 0x800 || (0xD800..=0xDFFF).contains(&r) {
            return (0xFFFD, 1);
        }
        return (r, 3);
    }
    if b0 < 0xF8 {
        if !cont(i + 1) || !cont(i + 2) || !cont(i + 3) {
            return (0xFFFD, 1);
        }
        let r = u32::from(b0 & 0x07) << 18
            | u32::from(bytes[i + 1] & 0x3F) << 12
            | u32::from(bytes[i + 2] & 0x3F) << 6
            | u32::from(bytes[i + 3] & 0x3F);
        if !(0x1_0000..=0x10_FFFF).contains(&r) {
            return (0xFFFD, 1);
        }
        return (r, 4);
    }
    (0xFFFD, 1)
}

fn runes_go(bytes: &[u8]) -> Vec<char> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let (rune, size) = decode_rune_go(bytes, i);
        out.push(char::from_u32(rune).unwrap_or('\u{FFFD}'));
        i += size;
    }
    out
}

pub(crate) fn utf16_count(value: &[u8]) -> usize {
    runes_go(value).iter().map(|c| c.len_utf16()).sum()
}

pub(crate) fn utf16be_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() * 2);
    let mut buf = [0u16; 2];
    for c in runes_go(value) {
        for unit in c.encode_utf16(&mut buf) {
            out.extend_from_slice(&unit.to_be_bytes());
        }
    }
    out
}

fn first_line(bytes: &[u8]) -> &[u8] {
    match memchr::memmem::find(bytes, b"\r\n") {
        Some(end) => &bytes[..end],
        None => bytes,
    }
}

fn split_lines(mut text: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    while let Some(end) = memchr::memmem::find(text, b"\r\n") {
        lines.push(&text[..end]);
        text = &text[end + 2..];
    }
    lines.push(text);
    lines
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

pub(crate) fn equal_fold_ascii(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

pub(crate) fn request_method(request: &[u8]) -> &[u8] {
    let line = first_line(request);
    match line.iter().position(|b| *b == b' ') {
        Some(space) => &line[..space],
        None => line,
    }
}

pub(crate) fn request_target(request: &[u8]) -> &[u8] {
    let line = first_line(request);
    let mut parts = line.splitn(3, |b| *b == b' ');
    let _ = parts.next();
    parts.next().unwrap_or(b"/")
}

pub(crate) fn url_extension(path: &[u8]) -> &[u8] {
    let Some(dot) = path.iter().rposition(|b| *b == b'.') else {
        return b"";
    };
    let tail = &path[dot + 1..];
    if let Some(slash) = tail.iter().position(|b| *b == b'/') {
        if slash != tail.len() - 1 {
            return b"";
        }
    }
    tail
}

pub(crate) fn cookie_value(raw: &[u8]) -> &[u8] {
    let Some(end) = memchr::memmem::find(raw, b"\r\n\r\n") else {
        return b"";
    };
    for line in split_lines(&raw[..end]).into_iter().skip(1) {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        if colon == 0 {
            continue;
        }
        if equal_fold_ascii(trim_ascii_whitespace(&line[..colon]), b"set-cookie") {
            return trim_ascii_whitespace(&line[colon + 1..]);
        }
    }
    b""
}

pub(crate) fn mime_code(response: &[u8]) -> u64 {
    if response.is_empty() {
        return 0;
    }
    let Some(end) = memchr::memmem::find(response, b"\r\n\r\n") else {
        return 0;
    };
    for line in split_lines(&response[..end]).into_iter().skip(1) {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        if colon == 0 {
            continue;
        }
        if !equal_fold_ascii(trim_ascii_whitespace(&line[..colon]), b"content-type") {
            continue;
        }
        let value = trim_ascii_whitespace(&line[colon + 1..]).to_ascii_lowercase();
        if value.windows(4).any(|w| w == b"html") {
            return layout::MIME_HTML;
        }
        if value.starts_with(b"text/plain") {
            return layout::MIME_TEXT;
        }
        if value.starts_with(b"text/css") {
            return layout::MIME_CSS;
        }
        if value.windows(10).any(|w| w == b"javascript") {
            return layout::MIME_SCRIPT;
        }
        if value.windows(3).any(|w| w == b"xml") {
            return layout::MIME_XML;
        }
        if value.windows(4).any(|w| w == b"json") {
            return layout::MIME_JSON;
        }
        return 0;
    }
    0
}

pub(crate) fn extract_title(response: &[u8]) -> Vec<u8> {
    if response.is_empty() {
        return Vec::new();
    }
    let lowered: Vec<u8> = response.iter().map(u8::to_ascii_lowercase).collect();
    let Some(open) = lowered.windows(6).position(|w| w == b"<title") else {
        return Vec::new();
    };
    let after = open + 6;
    if after >= lowered.len() {
        return Vec::new();
    }
    match lowered[after] {
        b'>' | b' ' | b'\t' | b'\r' | b'\n' => {}
        _ => return Vec::new(),
    }
    let Some(rel_gt) = lowered[after..].iter().position(|b| *b == b'>') else {
        return Vec::new();
    };
    let content_start = after + rel_gt + 1;
    let Some(rel_close) = lowered[content_start..]
        .windows(7)
        .position(|w| w == b"</title")
    else {
        return Vec::new();
    };
    let closing_start = content_start + rel_close;
    let closing_after = closing_start + 7;
    if closing_after >= lowered.len() {
        return Vec::new();
    }
    match lowered[closing_after] {
        b'>' | b' ' | b'\t' | b'\r' | b'\n' => {}
        _ => return Vec::new(),
    }
    if !lowered[closing_after..].contains(&b'>') {
        return Vec::new();
    }
    let raw = &response[content_start..closing_start];
    clip_title(&collapse_spaces(&decode_html_text(raw)))
}

fn decode_html_text(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'&' {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        let Some(rel) = raw[i + 1..].iter().position(|b| *b == b';') else {
            out.push(raw[i]);
            i += 1;
            continue;
        };
        let semi = i + 1 + rel;
        if let Some(decoded) = decode_entity(&raw[i + 1..semi]) {
            out.extend_from_slice(&decoded);
            i = semi + 1;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

fn decode_entity(entity: &[u8]) -> Option<Vec<u8>> {
    match entity {
        b"amp" => return Some(b"&".to_vec()),
        b"lt" => return Some(b"<".to_vec()),
        b"gt" => return Some(b">".to_vec()),
        b"quot" => return Some(b"\"".to_vec()),
        b"apos" => return Some(b"'".to_vec()),
        b"nbsp" => return Some(b" ".to_vec()),
        _ => {}
    }
    if entity.len() < 2 || entity[0] != b'#' {
        return None;
    }
    let (base, digits) = match entity[1] {
        b'x' | b'X' => (16, &entity[2..]),
        _ => (10, &entity[1..]),
    };
    if digits.is_empty() {
        return None;
    }
    let value = u32::from_str_radix(std::str::from_utf8(digits).ok()?, base).ok()?;
    let c = char::from_u32(value)?;
    let mut buf = [0u8; 4];
    Some(c.encode_utf8(&mut buf).as_bytes().to_vec())
}

fn collapse_spaces(s: &[u8]) -> Vec<u8> {
    let runes = runes_go(s);
    let mut start = 0;
    while start < runes.len() && runes[start].is_whitespace() {
        start += 1;
    }
    let mut end = runes.len();
    while end > start && runes[end - 1].is_whitespace() {
        end -= 1;
    }
    let mut out = Vec::new();
    let mut prev_space = false;
    for c in &runes[start..end] {
        if c.is_whitespace() {
            if !prev_space {
                out.push(b' ');
            }
            prev_space = true;
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            prev_space = false;
        }
    }
    out
}

pub(crate) fn clip_title(s: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(s);
    let runes: Vec<char> = text.chars().collect();
    let mut units = 0usize;
    for (i, r) in runes.iter().enumerate() {
        let n = r.len_utf16();
        if units + n > TITLE_LIMIT {
            return runes[..i]
                .iter()
                .flat_map(|c| c.to_string().into_bytes())
                .collect();
        }
        units += n;
    }
    text.as_bytes().to_vec()
}
