use std::collections::HashMap;

use serde::Deserialize;

use crate::diagnostic::{Error, Result};

const MODEL: &str = include_str!("empty-project.json");

const CONST: u64 = 0;
const REFERENCE: u64 = 1;
const SHIFTED_REFERENCE: u64 = 2;

#[derive(Debug, Deserialize)]
struct Model {
    head_hex: String,
    root: u64,
    residue_floor: u64,
    #[serde(default)]
    identity_head: Vec<usize>,
    #[serde(default)]
    identity_nodes: Vec<u64>,
    #[serde(default)]
    name: Option<NameBinding>,
    residue: Vec<(u64, String)>,
    nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
struct NameBinding {
    node: u64,
    owner: u64,
    tag: u64,
    scale: u64,
    bias: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Blueprint<'a> {
    pub slack: u64,
    pub keep_model_identity: bool,
    pub name: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct Node {
    o: u64,
    k: String,
    #[serde(default)]
    v: Option<String>,
    #[serde(default)]
    c: Option<u32>,
    #[serde(default)]
    l: Vec<Vec<u64>>,
    #[serde(default)]
    t: Option<u16>,
    #[serde(default)]
    s: Vec<(u8, u16)>,
    #[serde(default)]
    f: Vec<Vec<u64>>,
    #[serde(default)]
    p: Vec<(usize, u8)>,
}

impl Node {
    fn lead(&self) -> u64 {
        match self.k.as_str() {
            "compact_prefixed" => 2,
            "boxed" => 10,
            _ => 0,
        }
    }

    fn span(&self) -> Result<u64> {
        match self.k.as_str() {
            "text" => Ok(8 + 2 * self.text()?.encode_utf16().count() as u64),
            "bytes" => Ok(8 + self.blob()?.len() as u64),
            "array" => Ok(8 + u64::from(self.capacity()?) * 8),
            _ => {
                let (_, last) = *self
                    .s
                    .last()
                    .ok_or_else(|| Error::Malformed("model node has no schema".to_owned()))?;
                Ok(self.lead() + u64::from(last) + 8)
            }
        }
    }

    fn text(&self) -> Result<&str> {
        self.v
            .as_deref()
            .ok_or_else(|| Error::Malformed("model text node has no value".to_owned()))
    }

    fn blob(&self) -> Result<Vec<u8>> {
        unhex(self.text()?)
    }

    fn capacity(&self) -> Result<u32> {
        self.c
            .ok_or_else(|| Error::Malformed("model array node has no capacity".to_owned()))
    }
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    let digits = text.as_bytes();
    if digits.len() % 2 != 0 {
        return Err(Error::Malformed(
            "model hex blob has an odd length".to_owned(),
        ));
    }
    digits
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| Error::Malformed("model hex blob is not ascii".to_owned()))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| Error::Malformed("model hex blob is malformed".to_owned()))
        })
        .collect()
}

struct Canvas {
    bytes: Vec<u8>,
}

impl Canvas {
    fn put(&mut self, offset: u64, blob: &[u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| Error::OffsetOverflow)?;
        let end = start.checked_add(blob.len()).ok_or(Error::OffsetOverflow)?;
        if end > self.bytes.len() {
            return Err(Error::ResourceLimit {
                resource: "empty project image",
                requested: end as u64,
                limit: self.bytes.len() as u64,
            });
        }
        self.bytes[start..end].copy_from_slice(blob);
        Ok(())
    }

    fn put_uint(&mut self, offset: u64, value: u64, width: usize) -> Result<()> {
        if width == 0 || width > 8 {
            return Err(Error::Malformed(format!("model field width {width}")));
        }
        self.put(offset, &value.to_be_bytes()[8 - width..])
    }
}

fn model() -> Result<Model> {
    serde_json::from_str(MODEL).map_err(Error::Json)
}

struct Random {
    bytes: Vec<u8>,
    cursor: usize,
}

impl Random {
    fn new(count: usize) -> Result<Self> {
        let mut bytes = vec![0u8; count];
        getrandom::fill(&mut bytes)
            .map_err(|error| std::io::Error::other(format!("system entropy: {error}")))?;
        Ok(Self { bytes, cursor: 0 })
    }

    fn next(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.cursor)
            .ok_or_else(|| Error::Malformed("ran out of entropy".to_owned()))?;
        self.cursor += 1;
        Ok(byte)
    }

    fn pick(&mut self, alphabet: &[u8]) -> Result<char> {
        let index = usize::from(self.next()?) % alphabet.len();
        Ok(char::from(alphabet[index]))
    }
}

fn mint(value: &str, random: &mut Random) -> Result<String> {
    let hexish = value
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase() || c == '-' || c == '\0');
    let alphabet: &[u8] = if hexish {
        b"0123456789abcdef"
    } else {
        b"0123456789abcdefghijklmnopqrstuvwxyz"
    };
    let mut minted = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_digit() || character.is_ascii_lowercase() {
            minted.push(random.pick(alphabet)?);
        } else {
            minted.push(character);
        }
    }
    Ok(minted)
}

struct Swap {
    from: Vec<u8>,
    to: Vec<u8>,
}

fn utf16be(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

fn clamp(value: &str, units: usize) -> String {
    let mut fitted: String = value.chars().take(units).collect();
    while fitted.encode_utf16().count() < units {
        fitted.push(' ');
    }
    fitted
}

fn rename(model: &mut Model, name: &str) -> Result<Option<Swap>> {
    let Some(binding) = model.name.as_ref() else {
        return Err(Error::Malformed(
            "the embedded model does not locate the project name".to_owned(),
        ));
    };
    let (node, owner, tag) = (binding.node, binding.owner, binding.tag);
    let length = name.encode_utf16().count() as u64 * binding.scale + binding.bias;

    let mut swap = None;
    for entry in &mut model.nodes {
        if entry.o == node {
            let previous = entry.v.take().unwrap_or_default();
            swap = Some(Swap {
                to: utf16be(&clamp(name, previous.encode_utf16().count())),
                from: utf16be(&previous),
            });
            entry.v = Some(name.to_owned());
        }
        if entry.o == owner {
            let field = entry
                .f
                .iter_mut()
                .find(|field| field[0] == tag)
                .ok_or_else(|| Error::Malformed(format!("project name owner has no tag {tag}")))?;
            *field = vec![tag, field[1], field[2], CONST, length];
        }
    }
    Ok(swap)
}

fn freshen(model: &mut Model, swaps: &mut Vec<Swap>) -> Result<Vec<u8>> {
    let wanted: usize = model
        .nodes
        .iter()
        .filter(|node| model.identity_nodes.contains(&node.o))
        .filter_map(|node| node.v.as_ref())
        .map(String::len)
        .sum();
    let mut random = Random::new(wanted + model.identity_head.len() + 16)?;

    let identity = model.identity_nodes.clone();
    for node in &mut model.nodes {
        if !identity.contains(&node.o) {
            continue;
        }
        if let Some(value) = node.v.as_ref() {
            let minted = mint(value, &mut random)?;
            swaps.push(Swap {
                from: utf16be(value),
                to: utf16be(&minted),
            });
            node.v = Some(minted);
        }
    }

    let mut head = unhex(&model.head_hex)?;
    if let [start, end] = model.identity_head[..] {
        for slot in head.get_mut(start..end).into_iter().flatten() {
            *slot = random.next()?;
        }
    }
    Ok(head)
}

fn place(model: &Model) -> Result<(HashMap<u64, u64>, u64)> {
    let mut placement = HashMap::with_capacity(model.nodes.len());
    placement.insert(model.root, model.root);
    let mut cursor = model.residue_floor;
    for node in &model.nodes {
        if node.o == model.root {
            continue;
        }
        placement.insert(node.o, cursor);
        cursor += node.span()?;
    }
    Ok((placement, cursor))
}

fn resolve(placement: &HashMap<u64, u64>, encoded: &[u64], from: usize) -> Result<u64> {
    let mode = *encoded
        .get(from)
        .ok_or_else(|| Error::Malformed("model value has no mode".to_owned()))?;
    let value = *encoded
        .get(from + 1)
        .ok_or_else(|| Error::Malformed("model value has no payload".to_owned()))?;
    match mode {
        CONST => Ok(value),
        REFERENCE | SHIFTED_REFERENCE => {
            let target = *placement
                .get(&value)
                .ok_or_else(|| Error::Malformed(format!("model reference {value} is unknown")))?;
            if mode == REFERENCE {
                Ok(target)
            } else {
                Ok((target << 16) | encoded.get(from + 2).copied().unwrap_or(0))
            }
        }
        other => Err(Error::Malformed(format!("model value mode {other}"))),
    }
}

pub fn identity_image() -> Result<Vec<u8>> {
    let model = model()?;
    let placement = model.nodes.iter().map(|node| (node.o, node.o)).collect();
    let head = unhex(&model.head_hex)?;
    render(
        &model,
        &placement,
        model.residue_floor,
        model.residue_floor,
        &head,
    )
}

pub fn image(blueprint: &Blueprint<'_>) -> Result<Vec<u8>> {
    let mut model = model()?;
    let mut swaps = Vec::new();
    if let Some(name) = blueprint.name {
        swaps.extend(rename(&mut model, name)?);
    }
    let head = if blueprint.keep_model_identity {
        unhex(&model.head_hex)?
    } else {
        freshen(&mut model, &mut swaps)?
    };
    let (placement, cursor) = place(&model)?;
    let size = cursor
        .checked_add(blueprint.slack)
        .ok_or(Error::OffsetOverflow)?;
    let mut image = render(&model, &placement, size, cursor, &head)?;
    for swap in &swaps {
        scrub(&mut image, swap);
    }
    Ok(image)
}

fn scrub(image: &mut [u8], swap: &Swap) {
    if swap.from.is_empty() || swap.from.len() != swap.to.len() {
        return;
    }
    let finder = memchr::memmem::Finder::new(&swap.from);
    let mut cursor = 0;
    while let Some(found) = finder.find(&image[cursor..]) {
        let at = cursor + found;
        image[at..at + swap.to.len()].copy_from_slice(&swap.to);
        cursor = at + swap.to.len();
    }
}

fn render(
    model: &Model,
    placement: &HashMap<u64, u64>,
    size: u64,
    cursor: u64,
    head: &[u8],
) -> Result<Vec<u8>> {
    let size = usize::try_from(size).map_err(|_| Error::OffsetOverflow)?;
    let mut canvas = Canvas {
        bytes: vec![0u8; size],
    };
    canvas.put(0, head)?;
    for (offset, blob) in &model.residue {
        canvas.put(*offset, &unhex(blob)?)?;
    }

    for node in &model.nodes {
        let base = placement[&node.o];
        match node.k.as_str() {
            "text" => {
                let units: Vec<u16> = node.text()?.encode_utf16().collect();
                canvas.put_uint(base, 8 + units.len() as u64 * 2, 4)?;
                canvas.put_uint(base + 4, units.len() as u64, 4)?;
                for (index, unit) in units.iter().enumerate() {
                    canvas.put(base + 8 + index as u64 * 2, &unit.to_be_bytes())?;
                }
            }
            "bytes" => {
                let blob = node.blob()?;
                canvas.put_uint(base, 8 + blob.len() as u64, 4)?;
                canvas.put_uint(base + 4, blob.len() as u64, 4)?;
                canvas.put(base + 8, &blob)?;
            }
            "array" => {
                let capacity = node.capacity()?;
                canvas.put_uint(base, 8 + u64::from(capacity) * 8, 4)?;
                canvas.put_uint(base + 4, u64::from(capacity), 4)?;
                for slot in &node.l {
                    let index = slot[0];
                    canvas.put_uint(base + 8 + index * 8, resolve(placement, slot, 1)?, 8)?;
                }
            }
            _ => {
                let head = base + node.lead();
                let table = match node.k.as_str() {
                    "typed" => {
                        let type_id = node.t.unwrap_or_default();
                        canvas.put(head, &type_id.to_be_bytes())?;
                        canvas.put_uint(head + 2, node.s.len() as u64, 2)?;
                        head + 4
                    }
                    "compact" | "compact_prefixed" => {
                        canvas.put_uint(head, u64::from(node.t.unwrap_or_default()), 1)?;
                        canvas.put_uint(head + 1, node.s.len() as u64, 1)?;
                        head + 2
                    }
                    _ => {
                        canvas.put_uint(head, node.s.len() as u64, 4)?;
                        head + 4
                    }
                };
                for (index, (tag, relative)) in node.s.iter().enumerate() {
                    let at = table + index as u64 * 3;
                    canvas.put_uint(at, u64::from(*tag), 1)?;
                    canvas.put(at + 1, &relative.to_be_bytes())?;
                }
                for field in &node.f {
                    let width = usize::try_from(field[2]).map_err(|_| Error::OffsetOverflow)?;
                    canvas.put_uint(head + field[1], resolve(placement, field, 3)?, width)?;
                }
                for (relative, byte) in &node.p {
                    canvas.put(base + *relative as u64, &[*byte])?;
                }
            }
        }
    }

    canvas.put_uint(56, cursor, 8)?;
    Ok(canvas.bytes)
}
