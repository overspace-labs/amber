//! End-to-end: build a small project, trim it, and check decisions and byte fidelity.
//! Uses only reserved example domains; no engagement data.

use std::collections::BTreeMap;
use std::path::PathBuf;

use amber::{
    DedupeMode, Decision, Entry, HistoryFilter, HostScope, Project, TrimOptions, WriteOptions,
    create, trim,
};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("amber-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn entry(id: u64, host: &str, request: &str, response: Option<&str>) -> Entry {
    let status = response.map_or(0, |text| text.split(' ').nth(1).unwrap().parse().unwrap());
    Entry {
        entry_id: Some(id),
        host: host.to_owned(),
        ip: "192.0.2.10".to_owned(),
        port: 443,
        tls: true,
        request: request.as_bytes().to_vec(),
        response: response.map(|text| text.as_bytes().to_vec()),
        status,
        comment: String::new(),
        highlight: None,
        time_epoch_ms: 1_700_000_000_000 + id,
        listener_port: 8080,
    }
}

const API_OK: &str = "HTTP/2 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":1}";
const JS_OK: &str = "HTTP/2 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar a=1;";

fn api(cookie: &str) -> String {
    format!(
        "GET /api/items?x=1 HTTP/2\r\nHost: app.example.com\r\nCookie: _ga=GA1.{cookie}.123; session={cookie}\r\n\r\n"
    )
}

fn js(cookie: &str) -> String {
    format!("GET /static/app.js HTTP/2\r\nHost: app.example.com\r\nCookie: session={cookie}\r\n\r\n")
}

#[test]
fn trim_keeps_scope_drops_duplicates_and_preserves_bytes() {
    let dir = scratch("trim");
    let source = dir.join("source.burp");
    let output = dir.join("trimmed.burp");

    let mut annotated = entry(4, "app.example.com", &api("A"), Some(API_OK));
    annotated.comment = "keep me".to_owned();
    let mut highlighted = entry(9, "app.example.com", &api("A"), Some(API_OK));
    highlighted.highlight = Some("unknown:12".to_owned()); // outside the named palette
    let entries = vec![
        entry(1, "app.example.com", &api("A"), Some(API_OK)),
        entry(2, "app.example.com", &api("A"), Some(API_OK)), // duplicate of 1
        entry(3, "app.example.com", &api("B"), Some(API_OK)), // other session: kept
        annotated,                                            // duplicate but annotated
        entry(5, "app.example.com", &js("A"), Some(JS_OK)),
        entry(6, "app.example.com", &js("B"), Some(JS_OK)), // static: identity ignored
        entry(7, "ads.example.org", "GET /pixel HTTP/1.1\r\nHost: ads.example.org\r\n\r\n", None),
        entry(8, "noise.example.com", "GET / HTTP/1.1\r\nHost: noise.example.com\r\n\r\n", None),
        highlighted, // duplicate but highlighted
        entry(10, "app.example.com", "POST /api/items HTTP/2\r\nHost: app.example.com\r\nCookie: session=A\r\n\r\n{\"n\":1}", Some(API_OK)),
        entry(11, "app.example.com", "POST /api/items HTTP/2\r\nHost: app.example.com\r\nCookie: session=A\r\n\r\n{\"n\":2}", Some(API_OK)), // other body: kept
        entry(12, "app.example.com", &api("A"), Some("HTTP/2 403 Forbidden\r\n\r\n")), // other response: kept
    ];
    create(&source, &entries, &WriteOptions::default()).unwrap();

    let filter = HistoryFilter {
        scope: Some(HostScope::parse(["example.com", "!noise.example.com"]).unwrap()),
        ..HistoryFilter::default()
    };
    let options = TrimOptions {
        dedupe: DedupeMode::Session,
        verify: true,
        name: Some("trimmed".to_owned()),
        ..TrimOptions::default()
    };

    let mut decisions = BTreeMap::new();
    let summary = trim(&source, &output, &filter, &options, |entry, decision| {
        decisions.insert(entry.entry_id, decision.clone());
        Ok(())
    })
    .unwrap();

    assert_eq!(decisions[&1], Decision::Kept);
    assert_eq!(decisions[&2], Decision::Duplicate { of: 1 });
    assert_eq!(decisions[&3], Decision::Kept);
    assert_eq!(decisions[&4], Decision::Kept);
    assert_eq!(decisions[&5], Decision::Kept);
    assert_eq!(decisions[&6], Decision::Duplicate { of: 5 });
    assert_eq!(decisions[&7], Decision::Filtered);
    assert_eq!(decisions[&8], Decision::Filtered);
    assert_eq!(decisions[&9], Decision::Kept);
    assert_eq!(decisions[&10], Decision::Kept);
    assert_eq!(decisions[&11], Decision::Kept);
    assert_eq!(decisions[&12], Decision::Kept);
    assert_eq!(summary.kept, 8);
    assert_eq!(summary.duplicates, 2);
    assert_eq!(summary.filtered, 2);
    assert_eq!(summary.kept_annotated_duplicates, 2);
    assert_eq!(summary.verified, Some(8));

    // The source is untouched and the output holds exactly the kept rows, byte for byte.
    let original = Project::open(&source).unwrap();
    let trimmed = Project::open(&output).unwrap();
    assert_eq!(original.len(), 12);
    assert_eq!(trimmed.len(), 8);
    trimmed.require_complete().unwrap();
    let mut source_rows = BTreeMap::new();
    original
        .for_each(&HistoryFilter::default(), |entry| {
            source_rows.insert(entry.entry_id, entry);
            Ok(())
        })
        .unwrap();
    trimmed
        .for_each(&HistoryFilter::default(), |entry| {
            let before = &source_rows[&entry.entry_id];
            assert_eq!(entry.request.sha256, before.request.sha256);
            assert_eq!(
                entry.response.as_ref().map(|m| &m.sha256),
                before.response.as_ref().map(|m| &m.sha256)
            );
            assert_eq!(entry.comment.value, before.comment.value);
            assert_eq!(entry.highlight.value, before.highlight.value);
            assert_eq!(entry.time_epoch_ms.unsigned, before.time_epoch_ms.unsigned);
            assert_eq!(entry.listener_port.unsigned, before.listener_port.unsigned);
            assert_eq!(entry.ip, before.ip);
            assert_eq!(entry.request.http_version.as_deref(), Some(
                before.request.http_version.as_deref().unwrap()
            ));
            Ok(())
        })
        .unwrap();
    let http2 = amber::history::decode::message_bytes(
        trimmed.source(),
        &trimmed.entry(10).unwrap().request,
    )
    .unwrap();
    assert!(http2.starts_with(b"POST /api/items HTTP/2\r\n"));
    assert_eq!(trimmed.entry(1).unwrap().ip.as_deref(), Some("192.0.2.10"));
    assert_eq!(trimmed.entry(9).unwrap().highlight.code, 12);

    // Refuses to overwrite, and refuses to trim a project onto itself.
    assert!(trim(&source, &output, &filter, &options, |_, _| Ok(())).is_err());
    let forced = TrimOptions { force: true, ..options.clone() };
    assert!(trim(&source, &source, &filter, &forced, |_, _| Ok(())).is_err());
    assert_eq!(Project::open(&source).unwrap().len(), 12);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn dry_run_writes_nothing_and_modes_differ() {
    let dir = scratch("dry");
    let source = dir.join("source.burp");
    let entries = vec![
        entry(1, "app.example.com", &api("A"), Some(API_OK)),
        entry(2, "app.example.com", &api("B"), Some(API_OK)),
        entry(3, "app.example.com", &api("A"), Some("HTTP/2 500 Oops\r\n\r\n")),
    ];
    create(&source, &entries, &WriteOptions::default()).unwrap();
    let output = dir.join("never.burp");
    let count = |mode| {
        let options = TrimOptions { dedupe: mode, dry_run: true, ..TrimOptions::default() };
        trim(&source, &output, &HistoryFilter::default(), &options, |_, _| Ok(()))
            .unwrap()
            .duplicates
    };
    assert_eq!(count(DedupeMode::None), 0);
    assert_eq!(count(DedupeMode::Session), 0);
    assert_eq!(count(DedupeMode::Any), 1);
    assert_eq!(count(DedupeMode::Endpoint), 2);
    assert!(!output.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn existing_staging_path_is_never_truncated() {
    let dir = scratch("staging");
    let source = dir.join("source.burp");
    create(
        &source,
        &[entry(1, "app.example.com", &api("A"), Some(API_OK))],
        &WriteOptions::default(),
    )
    .unwrap();
    let before = std::fs::read(&source).unwrap();
    let output = dir.join("out.burp");
    // Plant the exact staging name this process would use, aliasing the source.
    let staged = dir.join(format!("out.burp.staging-{}", std::process::id()));
    std::os::unix::fs::symlink(&source, &staged).unwrap();

    let result = trim(&source, &output, &HistoryFilter::default(), &TrimOptions::default(), |_, _| Ok(()));
    assert!(result.is_err());
    assert_eq!(std::fs::read(&source).unwrap(), before, "source must be untouched");
    assert!(std::fs::symlink_metadata(&staged).is_ok(), "planted path must not be removed");
    assert!(!output.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}
