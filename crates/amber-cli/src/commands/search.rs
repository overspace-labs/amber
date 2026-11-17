use std::io::{BufWriter, Write};
use std::path::PathBuf;

use amber::{Matcher, Part, Project, Result, SearchOptions, search_entry};
use clap::{Args, ValueEnum};
use serde_json::json;

use super::inspect::Format;
use super::{FilterArgs, printable, warn_unknown_header};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PartArg {
    /// Request headers and body.
    Req,
    /// Response headers and body.
    Res,
    ReqHeaders,
    ReqBody,
    ResHeaders,
    ResBody,
}

impl PartArg {
    fn parts(self) -> &'static [Part] {
        match self {
            Self::Req => &[Part::ReqHeaders, Part::ReqBody],
            Self::Res => &[Part::ResHeaders, Part::ResBody],
            Self::ReqHeaders => &[Part::ReqHeaders],
            Self::ReqBody => &[Part::ReqBody],
            Self::ResHeaders => &[Part::ResHeaders],
            Self::ResBody => &[Part::ResBody],
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Args)]
pub struct SearchCommand {
    pub project: PathBuf,
    /// Search term; a literal string unless --regex is given.
    pub term: String,
    /// Treat the term as a regular expression (Rust `regex` syntax).
    #[arg(short, long)]
    pub regex: bool,
    /// Match case exactly (default is case-insensitive, like Burp).
    #[arg(short = 'C', long)]
    pub case_sensitive: bool,
    /// List entries that do NOT match (Burp's "negative search").
    #[arg(short = 'v', long)]
    pub negate: bool,
    /// Where to look, comma-separated; default is everywhere.
    #[arg(short = 'i', long = "in", value_enum, value_delimiter = ',')]
    pub parts: Vec<PartArg>,
    /// Undo chunked transfer coding and gzip/deflate/br content coding before matching.
    #[arg(short, long)]
    pub decode: bool,
    /// Print each match (`ID<TAB>PART<TAB>MATCH`) instead of one line per entry.
    #[arg(short, long)]
    pub only_matching: bool,
    /// Report this regex capture group instead of the whole match (implies the group exists).
    #[arg(short, long, value_name = "N")]
    pub group: Option<usize>,
    /// Under each entry, show every match with this many bytes of context either side.
    #[arg(short = 'x', long, value_name = "BYTES")]
    pub context: Option<usize>,
    /// Stop after this many matching entries.
    #[arg(short = 'n', long, value_parser = clap::value_parser!(u64).range(1..))]
    pub limit: Option<u64>,
    /// Never print matched values: show each as `<first 4 chars>…[N bytes #<sha256 prefix>]`
    /// so equal secrets can be correlated across entries without being revealed. Cannot be
    /// combined with --context (surrounding bytes could expose the value).
    #[arg(short = 'M', long, conflicts_with = "context")]
    pub mask: bool,
    #[arg(short = 'F', long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    #[command(flatten)]
    pub filters: FilterArgs,
}

/// A stable, non-reversible stand-in for a matched value.
fn masked(value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let fingerprint: String = Sha256::digest(value)
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let shown = if value.len() >= 12 {
        printable(&value[..4])
    } else {
        String::new()
    };
    format!("{shown}…[{} bytes #{fingerprint}]", value.len())
}

fn snippet(text: &[u8], start: usize, end: usize, context: usize) -> String {
    let from = start.saturating_sub(context);
    let to = end.saturating_add(context).min(text.len());
    format!(
        "{}{}[{}]{}{}",
        if from > 0 { "…" } else { "" },
        printable(&text[from..start]),
        printable(&text[start..end]),
        printable(&text[end..to]),
        if to < text.len() { "…" } else { "" },
    )
}

impl SearchCommand {
    fn render(&self, value: &[u8]) -> String {
        if self.mask { masked(value) } else { printable(value) }
    }

    #[allow(clippy::too_many_lines)]
    pub fn run(&self) -> Result<()> {
        let filter = self.filters.build()?;
        filter.validate()?;
        let matcher = Matcher::new(&self.term, self.regex, self.case_sensitive)?;
        if let Some(group) = self.group {
            if group >= matcher.regex().captures_len() {
                return Err(amber::Error::Malformed(format!(
                    "pattern has no capture group {group}"
                )));
            }
        }
        let options = SearchOptions {
            parts: self
                .parts
                .iter()
                .flat_map(|part| part.parts().iter().copied())
                .collect(),
            decode: self.decode,
            group: self.group,
        };
        let project = Project::open_fast(&self.project)?;
        warn_unknown_header(&project);

        let mut out = BufWriter::new(std::io::stdout().lock());
        if self.format == Format::Table && !self.only_matching {
            writeln!(out, "{:>6}  {:<7}  {:>6}  {:<28}  URL", "ID", "METHOD", "STATUS", "MATCHES")?;
        }
        let mut hits = 0u64;
        let mut scanned = 0u64;
        let mut capped_entries = 0u64;
        let mut stopped = false;
        let summary = project.for_each_until(&filter, |entry| {
            scanned += 1;
            let result = search_entry(project.source(), &entry, &matcher, &options)?;
            if !result.capped.is_empty() {
                capped_entries += 1;
            }
            // A capped decode with no match is not proof of absence: a negative search
            // still lists it, flagged, rather than silently treating it as clean.
            if result.is_empty() != self.negate {
                return Ok(true);
            }
            hits += 1;
            if self.limit.is_some_and(|limit| hits >= limit) {
                stopped = true;
            }
            let capped_note = if result.capped.is_empty() {
                String::new()
            } else {
                format!(
                    " [decode capped: {}]",
                    result
                        .capped
                        .iter()
                        .map(|part| part.label())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            let found = &result.parts;
            let url = entry.request.url.as_deref().unwrap_or_default();
            let method = entry.request.method.as_deref().unwrap_or_default();
            let status = entry.status_code.unsigned;

            if self.only_matching {
                for part in found {
                    for (start, end) in &part.ranges {
                        match self.format {
                            Format::Table => writeln!(
                                out,
                                "{}\t{}\t{}",
                                entry.entry_id,
                                part.part.label(),
                                self.render(&part.text[*start..*end])
                            )?,
                            Format::Jsonl => {
                                serde_json::to_writer(
                                    &mut out,
                                    &json!({
                                        "entry_id": entry.entry_id,
                                        "part": part.part,
                                        "offset": start,
                                        "match": self.render(&part.text[*start..*end]),
                                    }),
                                )?;
                                out.write_all(b"\n")?;
                            }
                        }
                    }
                }
                return Ok(!stopped);
            }

            match self.format {
                Format::Table => {
                    let labels: Vec<String> = found
                        .iter()
                        .map(|part| {
                            format!(
                                "{}:{}{}",
                                part.part.label(),
                                part.ranges.len(),
                                if part.truncated { "+" } else { "" }
                            )
                        })
                        .collect();
                    writeln!(
                        out,
                        "{:>6}  {:<7}  {:>6}  {:<28}  {url}{capped_note}",
                        entry.entry_id,
                        method,
                        status,
                        if self.negate { "-".to_owned() } else { labels.join(",") },
                    )?;
                    if let Some(context) = self.context {
                        for part in found {
                            for (start, end) in &part.ranges {
                                writeln!(
                                    out,
                                    "        {}@{}{}: {}",
                                    part.part.label(),
                                    start,
                                    if part.decoded { " (decoded)" } else { "" },
                                    snippet(&part.text, *start, *end, context)
                                )?;
                            }
                        }
                    }
                }
                Format::Jsonl => {
                    let context = self.context.unwrap_or(40);
                    let parts_json: Vec<serde_json::Value> = found
                        .iter()
                        .map(|part| {
                            json!({
                                "part": part.part,
                                "count": part.ranges.len(),
                                "truncated": part.truncated,
                                "decoded": part.decoded,
                                "samples": part.ranges.iter().take(20).map(|(start, end)| json!({
                                    "offset": start,
                                    "match": self.render(&part.text[*start..*end]),
                                    "context": (!self.mask).then(|| snippet(&part.text, *start, *end, context)),
                                })).collect::<Vec<_>>(),
                            })
                        })
                        .collect();
                    serde_json::to_writer(
                        &mut out,
                        &json!({
                            "entry_id": entry.entry_id,
                            "method": method,
                            "url": url,
                            "status": status,
                            "time_epoch_ms": entry.time_epoch_ms.unsigned,
                            "comment": entry.comment.value,
                            "matches": parts_json,
                            "decode_capped": result.capped,
                        }),
                    )?;
                    out.write_all(b"\n")?;
                }
            }
            Ok(!stopped)
        })?;
        out.flush()?;
        eprintln!(
            "{hits} matching entries of {scanned} searched ({} in project){}",
            summary.total,
            if stopped { "; stopped at --limit" } else { "" }
        );
        if capped_entries > 0 {
            eprintln!(
                "warning: {capped_entries} entries had a body larger than {} MiB after decoding; only the first part was searched",
                amber::search::DECODE_LIMIT / (1024 * 1024)
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::masked;

    #[test]
    fn mask_hides_value_but_is_stable() {
        let token = b"eyJhbGciOiJSUzI1NiJ9.payload.sig";
        let one = masked(token);
        assert_eq!(one, masked(token));
        assert!(one.starts_with("eyJh…["));
        assert!(!one.contains("payload"));
        assert_ne!(one, masked(b"eyJhbGciOiJSUzI1NiJ9.other.sig"));
        assert!(!masked(b"hunter2").contains("hunt"));
    }
}
