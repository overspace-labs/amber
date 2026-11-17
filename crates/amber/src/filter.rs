use crate::binary::Fields;
use crate::diagnostic::{Error, Result};
use crate::history::layout::tag;
use crate::model::history::{HistoryEntry, Message};

pub const NO_HIGHLIGHT: &str = "none";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryFilter {
    pub host: Option<String>,
    pub url_contains: Option<String>,
    pub method: Option<String>,
    pub status: Vec<u64>,
    pub since_epoch_ms: Option<u64>,
    pub until_epoch_ms: Option<u64>,
    pub mime_contains: Option<String>,
    pub tool: Option<String>,
    pub comment_contains: Option<String>,
    pub highlight: Option<String>,
    pub entry_id: Option<u64>,
    /// Host allow/deny list; `None` accepts every host.
    pub scope: Option<HostScope>,
}

/// One host pattern. A plain pattern matches the host itself and every subdomain of it;
/// a pattern containing `*` is a glob over the whole host name (`*` spans dots), tried
/// against the host and each of its parent domains.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostPattern(String);

impl HostPattern {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        // `*.example.com` is folded into the suffix form `example.com`, so it covers the
        // apex as well as every subdomain, the way Burp's "include subdomains" scope does.
        let raw = match raw.strip_prefix("*.") {
            Some(rest) if !rest.contains('*') => rest,
            _ => raw,
        };
        let value = normalize_host(raw);
        (!value.is_empty()).then_some(Self(value))
    }

    fn matches(&self, host: &str) -> bool {
        if self.0.contains('*') {
            let mut candidate = host;
            loop {
                if glob(self.0.as_bytes(), candidate.as_bytes()) {
                    return true;
                }
                match candidate.find('.') {
                    Some(dot) => candidate = &candidate[dot + 1..],
                    None => return false,
                }
            }
        }
        host == self.0
            || (host.len() > self.0.len()
                && host.ends_with(self.0.as_str())
                && host.as_bytes()[host.len() - self.0.len() - 1] == b'.')
    }
}

fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

/// Lower-cases a host and strips a trailing dot, an IPv6 bracket pair and a `:port`.
pub fn normalize_host(raw: &str) -> String {
    let mut host = raw.trim().to_ascii_lowercase();
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            host = rest[..end].to_owned();
        }
    } else if host.matches(':').count() == 1 {
        if let Some(colon) = host.rfind(':') {
            host.truncate(colon);
        }
    }
    while host.ends_with('.') {
        host.pop();
    }
    host
}

/// Host scope: a host is in scope when it matches at least one include pattern (or there
/// are no include patterns) and no exclude pattern.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostScope {
    include: Vec<HostPattern>,
    exclude: Vec<HostPattern>,
}

impl HostScope {
    /// Builds a scope from pattern lines. Blank lines and `#` comments are ignored, and a
    /// leading `!` turns a line into an exclusion.
    pub fn parse<'a>(lines: impl IntoIterator<Item = &'a str>) -> Result<Self> {
        let mut scope = Self::default();
        for line in lines {
            let line = line.split(" #").next().unwrap_or_default().trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (target, raw) = match line.strip_prefix('!') {
                Some(rest) => (&mut scope.exclude, rest),
                None => (&mut scope.include, line),
            };
            let pattern = HostPattern::parse(raw)
                .ok_or_else(|| Error::Malformed(format!("empty scope pattern in line {line:?}")))?;
            target.push(pattern);
        }
        if scope.include.is_empty() && scope.exclude.is_empty() {
            return Err(Error::Malformed("scope has no patterns".to_owned()));
        }
        Ok(scope)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        Self::parse(std::fs::read_to_string(path)?.lines())
    }

    /// Adds patterns given on the command line to an existing scope.
    pub fn extend<'a>(&mut self, lines: impl IntoIterator<Item = &'a str>) -> Result<()> {
        let extra = Self::parse(lines)?;
        self.include.extend(extra.include);
        self.exclude.extend(extra.exclude);
        Ok(())
    }

    pub fn accepts(&self, host: &str) -> bool {
        let host = normalize_host(host);
        (self.include.is_empty() || self.include.iter().any(|pattern| pattern.matches(&host)))
            && !self.exclude.iter().any(|pattern| pattern.matches(&host))
    }
}

fn contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    haystack.len() >= needle.len()
        && (0..=haystack.len() - needle.len())
            .any(|start| haystack[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

fn equals(actual: Option<&str>, wanted: &str) -> bool {
    actual.is_some_and(|value| value.eq_ignore_ascii_case(wanted))
}

impl HistoryFilter {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if let (Some(since), Some(until)) = (self.since_epoch_ms, self.until_epoch_ms) {
            if since > until {
                return Err(Error::Malformed(format!(
                    "time filter is empty: since {since} is after until {until}"
                )));
            }
        }
        if self
            .method
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(Error::Malformed(
                "method filter must not be blank".to_owned(),
            ));
        }
        Ok(())
    }

    fn accepts_scalars(&self, entry_id: u64, status: u64, time: u64, highlight: u64) -> bool {
        self.entry_id.is_none_or(|wanted| wanted == entry_id)
            && (self.status.is_empty() || self.status.contains(&status))
            && self.since_epoch_ms.is_none_or(|since| time >= since)
            && self.until_epoch_ms.is_none_or(|until| time <= until)
            && self
                .highlight
                .as_ref()
                .is_none_or(|wanted| !wanted.eq_ignore_ascii_case(NO_HIGHLIGHT) || highlight == 0)
    }

    pub fn accepts_row(&self, fields: &Fields) -> bool {
        if !fields.contains_key(&tag::ENTRY_ID) {
            return true;
        }
        let value = |tag: u8| fields.get(&tag).map_or(0, |field| field.unsigned);
        self.accepts_scalars(
            value(tag::ENTRY_ID),
            value(tag::STATUS_CODE),
            value(tag::TIME_EPOCH_MS),
            value(tag::HIGHLIGHT),
        )
    }

    pub fn accepts(&self, entry: &HistoryEntry) -> bool {
        if !self.accepts_scalars(
            entry.entry_id,
            entry.status_code.unsigned,
            entry.time_epoch_ms.unsigned,
            entry.highlight.code,
        ) {
            return false;
        }
        let host_name = entry
            .service
            .as_ref()
            .map(|service| service.host.text.value.as_str());
        if self
            .host
            .as_ref()
            .is_some_and(|host| !equals(host_name, host))
        {
            return false;
        }
        if let Some(scope) = &self.scope {
            if !host_name.is_some_and(|name| scope.accepts(name)) {
                return false;
            }
        }
        if self.url_contains.as_ref().is_some_and(|needle| {
            !contains(entry.request.url.as_deref().unwrap_or_default(), needle)
        }) {
            return false;
        }
        if self
            .method
            .as_ref()
            .is_some_and(|method| !equals(entry.request.method.as_deref(), method))
        {
            return false;
        }
        if self.mime_contains.as_ref().is_some_and(|needle| {
            !entry
                .response
                .as_ref()
                .and_then(Message::content_type)
                .is_some_and(|value| contains(value, needle))
        }) {
            return false;
        }
        if self
            .tool
            .as_ref()
            .is_some_and(|tool| !entry.tool_source.eq_ignore_ascii_case(tool))
        {
            return false;
        }
        if self
            .comment_contains
            .as_ref()
            .is_some_and(|needle| !contains(&entry.comment.value, needle))
        {
            return false;
        }
        if let Some(wanted) = &self.highlight {
            let actual = entry.highlight.value.as_deref();
            let matches = if wanted.eq_ignore_ascii_case(NO_HIGHLIGHT) {
                actual.is_none()
            } else {
                equals(actual, wanted)
            };
            if !matches {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(lines: &str) -> HostScope {
        HostScope::parse(lines.lines()).unwrap()
    }

    #[test]
    fn suffix_matches_apex_and_subdomains_only() {
        let scope = scope("example.com");
        assert!(scope.accepts("example.com"));
        assert!(scope.accepts("a.b.example.com"));
        assert!(scope.accepts("API.Example.COM."));
        assert!(!scope.accepts("notexample.com"));
        assert!(!scope.accepts("example.com.evil.test"));
    }

    #[test]
    fn star_dot_prefix_is_the_suffix_form() {
        let scope = scope("*.example.com");
        assert!(scope.accepts("example.com"));
        assert!(scope.accepts("x.example.com"));
        assert!(!scope.accepts("example.org"));
    }

    #[test]
    fn exclusions_and_globs() {
        let scope = scope(
            "# comment\n\nexample.com\nlogin.example.net  # inline\n!noise*.example.com\n!static.example.com\n",
        );
        assert!(scope.accepts("console.example.com"));
        assert!(scope.accepts("login.example.net"));
        assert!(!scope.accepts("other.example.net"));
        assert!(!scope.accepts("noise-emea.example.com"));
        assert!(!scope.accepts("noise.example.com"));
        assert!(!scope.accepts("a.noise.example.com"));
        assert!(!scope.accepts("static.example.com"));
        assert!(scope.accepts("statics.example.com"));
    }

    #[test]
    fn exclude_only_scope_accepts_everything_else() {
        let scope = scope("!ads.test");
        assert!(scope.accepts("example.com"));
        assert!(!scope.accepts("x.ads.test"));
    }

    #[test]
    fn host_normalisation() {
        assert_eq!(normalize_host("Example.COM:443"), "example.com");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
        assert_eq!(normalize_host("::1"), "::1");
    }

    #[test]
    fn empty_scope_is_rejected() {
        assert!(HostScope::parse(["# nothing", ""]).is_err());
    }
}
