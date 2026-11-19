# amber

Read and write Burp Suite Proxy HTTP history, byte for byte.

`amber` opens `.burp` project files directly — no Burp, no extension, no JVM. It decodes the
binary container, walks the Proxy history chain, and reports every value along with the offset
it was read from. It also writes: append entries to a copy of an existing project, or
synthesize a complete, Burp-openable project from nothing but JSON.

## Install

Tagged releases ship prebuilt binaries for Linux (x86_64, aarch64), macOS (x86_64, aarch64,
universal) and Windows (x86_64). To build from source you need Rust 1.85 or newer:

```sh
cargo build --release
./target/release/amber --help
```

## Reading

```sh
amber list project.burp                                  # table of entries
amber list project.burp -F jsonl                          # one JSON object per line
amber list project.burp -H example.com -X POST -s 200 -s 302
amber show project.burp 42                                # one entry, with offsets and hashes
amber export project.burp -o out/ -p                      # manifest + raw messages
```

Both `list` and `export` take the same filters, all optional and combinable:

| flag | matches |
| --- | --- |
| `-H, --host` | exact host, case-insensitive |
| `-u, --url` | substring of the absolute URL |
| `-X, --method` | exact request method |
| `-s, --status` | any of the given status codes, repeatable |
| `-S, --since` / `-U, --until` | request time bounds, epoch milliseconds |
| `-m, --mime` | substring of the response `Content-Type` |
| `-t, --tool` | exact tool source, e.g. `proxy` |
| `-c, --comment` | substring of the entry comment |
| `-l, --highlight` | `red`, `orange`, `yellow`, `green`, `cyan`, `blue`, `pink`, `magenta`, `gray`, or `none` |

`export` writes `out/history.json` plus one `out/blobs/` sidecar per raw message. Pass
`-n, --no-blobs` to skip the sidecars, and `-p, --progress` for a progress summary on stderr.

## Writing

```sh
amber create -e > input.json                              # starter input document
amber create input.json -o new.burp -n 'My Project'       # from scratch, no source project
amber append project.burp input.json -o bigger.burp       # source project is never touched
```

Input documents look like this. `request` and `response` are either `{"path": "..."}` pointing
at a file of raw bytes, or `{"base64": "..."}` inline. A relative `path` is resolved against the
input document's directory. A `path` entry may also carry `length` and `sha256`; when present they
are checked against the file, and the write fails if either differs. Everything except `url` and
`request` is optional, and `defaults` supplies values for entries that omit them.

Per-entry optional fields: `entry_id` (otherwise auto-assigned), `time_epoch_ms`,
`listener_port`, `comment`, `highlight`, and `ip` — the resolved target server IP, written
verbatim as the row's tag-4 text record without any format validation. When omitted, tag 4
is not written (0), matching how Burp stores an entry whose server address was never
resolved. Precedence is entry field > `defaults` > built-in default.

```json
{
  "schema_version": 1,
  "defaults": { "time_epoch_ms": 946684800000, "listener_port": 8080 },
  "entries": [
    {
      "url": "https://example.com/login",
      "request": { "path": "login.request.bin" },
      "response": { "path": "login.response.bin" },
      "ip": "93.184.216.34"
    },
    {
      "url": "http://127.0.0.1:8080/health",
      "request": { "base64": "R0VUIC9oZWFsdGggSFRUUC8xLjENCkhvc3Q6IDEyNy4wLjAuMTo4MDgwDQoNCg==" },
      "comment": "request-only entry",
      "highlight": "orange"
    }
  ]
}
```

Writes go to a staging file next to the destination, which is re-parsed and validated before an
atomic rename, so a failure leaves the destination alone. Existing files are kept unless you
pass `-f, --force`. Generated projects get freshly minted ids so two runs never collide.

## Limits

- The write path is pinned to one Burp project format. Reading is version-tolerant and works on
  projects `create` and `append` will refuse.
- `create` builds on an embedded model of an empty project, so generated projects carry Burp's
  default configuration.

## Burp-tool additions (local fork)

This fork (branch `burp-tool`) builds on Rust 1.85 and adds scope filtering, de-duplication,
content search and a streaming trim. `list`, `show`, `search`, `hosts` and `trim` skip the
whole-file SHA-256 (`export` still records it), so a multi-gigabyte project costs one read.

### Scope filters (every command that takes filters)

| flag | matches |
| --- | --- |
| `--scope-host PATTERN` | `example.com` = the host and all subdomains; `*.example.com` is the same; `*` globs (`noise*.example.com`); a leading `!` excludes. Repeatable. |
| `--scope-file FILE` | one pattern per line, `#` comments, combined with `--scope-host` |

A host is in scope when it matches an include pattern (or there are none) and no exclude.

### Search, like Proxy > HTTP history > "Filter by search term"

```sh
amber search project.burp 'Bearer '                        # entries containing the term (case-insensitive)
amber search project.burp 'idcs-[0-9a-f]{32}' -r -o        # print every match: ID <TAB> part <TAB> match
amber search project.burp 'access_token":"([^"]+)' -r -g 1 -o -i res-body -d   # capture group, decoded bodies
amber search project.burp password -i req-body -X POST --scope-file scope.txt -x 60   # show 60 bytes of context
amber search project.burp csrf -v -i req-headers -X POST   # negative search: POSTs WITHOUT the term
amber show project.burp 1234 --raw response > resp.bin     # the raw message, like Burp's message editor
```

| Burp search option | amber |
| --- | --- |
| Regex | `-r, --regex` |
| Case sensitive | `-C, --case-sensitive` |
| Negative search | `-v, --negate` |
| Search in request / response headers / body | `-i, --in req,res,req-headers,req-body,res-headers,res-body` |
| Show only in-scope items | `--scope-file` / `--scope-host` |
| Filter by MIME / status / method / annotation | `-m`, `-s`, `-X`, `-c`, `-l` |

`-M, --mask` never prints a matched value: each one is shown as `eyJ4…[598 bytes #3d4c2231]`
(prefix, length, sha256 fingerprint), so the same token can be tracked across entries without
being revealed. It cannot be combined with `--context`.

`-g, --group N` reports regex capture group N instead of the whole match, so use it with `-r` and a
pattern that has a `(...)` group.

`-d, --decode` undoes chunked transfer coding and gzip/deflate/br before matching (Burp's search
matches the stored bytes, so it is off by default). `-F jsonl` gives one JSON object per entry
with match samples; `-n` stops after N matching entries.

### Hosts

```sh
amber hosts project.burp                                  # entries, duplicates and bytes per host, largest first
amber hosts project.burp --scope-file scope.txt -F jsonl
```

`-d, --dedupe` sets the rule behind the DUPS column (default `session`, the same modes as `trim`).

### Trim

```sh
amber trim project.burp --scope-file scope.txt --dry-run --manifest plan.jsonl
amber trim project.burp --scope-file scope.txt -o trimmed.burp --manifest trimmed.manifest.jsonl --verify
```

Writes a **new** project holding only the Proxy history entries that pass the filters and are not
duplicates. The source is opened read-only. Requests and responses are copied byte for byte (an
`HTTP/2` request line stays `HTTP/2`), together with the original entry ID, time, listener port,
comment, highlight and server IP. Entries are read and copied one at a time, so message bytes never
pile up in memory. Per-entry bookkeeping (row index, dedupe key, verify digest) is a few dozen bytes
per entry, so it grows with the number of entries, not with message size. `--verify` re-reads the
output and compares every kept message's sha256 with the source. The manifest has one JSON line per
source entry: `kept`, `filtered`, `duplicate` (with `of`, the kept entry it repeats) or `unwritable`
(with `reason`).

`--dedupe` (default `session`). Entries with a comment or highlight are kept even when they repeat
an earlier entry; `--dedupe-annotated` drops those duplicates too. In each group of duplicates the
lowest entry ID is the one kept.

| mode | an entry is a duplicate of an earlier one when these are identical |
| --- | --- |
| `session` | method, URL, request body, caller identity, status, response body |
| `any` | method, URL, request body, status, response body |
| `endpoint` | method, URL, request body |
| `none` | never |

Caller identity is made of two things:
- **The `Authorization` value.** For OCI request signing (`Signature ... keyId=`), only the key id
  counts.
- **The cookies, sorted.** Analytics, consent and bot-management cookies are left out by exact
  name, case-insensitively (for example `_ga`, `s_cc`, `bm_sv`, `_abck`, `optanonconsent`), plus
  two generated shapes: `_ga_<id>` and `amcv_<org>@adobeorg`. Matching is deliberately literal:
  `s_session` and `_gateway_session` still count as identity.

Static assets (script, style, image, font, source map, judged by `Content-Type` or extension)
leave identity out.

The new project contains **Proxy history only**. Repeater, Site map, Scanner issues, Logger,
Organizer and project settings stay in the original. Keep the original as the archive.

Other `trim` options:

| flag | does |
| --- | --- |
| `-n, --name NAME` | project name Burp shows (default: the output file name without its extension) |
| `-f, --force` | overwrite `--output`, `--manifest` or `--summary` if they exist |
| `--dedupe-annotated` | also drop duplicates that carry a comment or highlight |
| `--summary FILE` | write the run totals and per-host tallies as JSON |
| `--top N` | number of dropped hosts listed in the report (default 25) |
