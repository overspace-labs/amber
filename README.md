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
`-n, --no-blobs` to skip the sidecars.

## Writing

```sh
amber create -e > input.json                              # starter input document
amber create input.json -o new.burp -n 'My Project'       # from scratch, no source project
amber append project.burp input.json -o bigger.burp       # source project is never touched
```

Input documents look like this. `request` and `response` are either `{"path": "..."}` pointing
at a file of raw bytes, or `{"base64": "..."}` inline. Everything except `url` and `request`
is optional, and `defaults` supplies values for entries that omit them.

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