//! Provider-owned demo controller (docs/model-demo.md). A tiny dependency-free HTTP server
//! over the `aisig_proto::demo` core. The model/client supplies only a scenario id and one
//! untrusted action proposal; the provider builds all trusted inputs from the synthetic
//! fixture and runs the existing verifier/session/mediator. No real scan/fetch/DB/shell.
//!
//! Routes: `GET /v1/scenarios`, `POST /v1/runs`, `GET /v1/runs/{id}`, `GET /healthz`.
//!
//! Binding: defaults to `127.0.0.1:8787`. Override with `AISIG_DEMO_BIND`. The only intended way
//! to reach it from the local n8n container is as a Compose service on the private network with
//! **no published host port** (the container may bind `0.0.0.0` safely because nothing is
//! published). This server is unauthenticated and must never be exposed on a routable address.
//!
//! Transport bounds (all configurable so they can be tightened in tests): a capped request line
//! and header block, a read timeout so a slow/incomplete request cannot hold a connection open,
//! a maximum body size, and a maximum number of stored runs.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use aisig_proto::demo::{self, DemoError, Proposal, RunRecord};
use serde::Deserialize;

const MAX_BODY: usize = 65_536;
const MAX_REQUEST_LINE: usize = 8_192;
const MAX_HEADER_LINE: usize = 8_192;
const MAX_HEADERS: usize = 100;
const MAX_HEADER_BYTES: usize = 16_384;
const DEFAULT_MAX_RUNS: usize = 1_000;
const DEFAULT_READ_TIMEOUT_MS: u64 = 10_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    scenario_id: String,
    proposal: Proposal,
    #[serde(default)]
    prompt_variant_id: Option<String>,
    #[serde(default)]
    model_metadata: Option<String>,
    /// Untrusted client-side parse classification (audit-only; see `RunRecord::model_parse`).
    #[serde(default)]
    model_parse: Option<String>,
}

struct Config {
    max_runs: usize,
    read_timeout: Option<Duration>,
}

type Store = Mutex<HashMap<String, RunRecord>>;

fn main() {
    let bind = std::env::var("AISIG_DEMO_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let cfg = Config {
        max_runs: env_usize("AISIG_DEMO_MAX_RUNS", DEFAULT_MAX_RUNS),
        read_timeout: match env_u64("AISIG_DEMO_READ_TIMEOUT_MS", DEFAULT_READ_TIMEOUT_MS) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        },
    };
    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    eprintln!(
        "demo controller listening on http://{bind} (synthetic only; no real effects; \
         max_runs={}, read_timeout={:?})",
        cfg.max_runs, cfg.read_timeout
    );
    let store: Store = Mutex::new(HashMap::new());
    let counter = AtomicU64::new(1);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(s, &cfg, &store, &counter) {
                    eprintln!("connection error: {e}");
                }
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A line read that distinguishes a clean EOF, an I/O error (including a read timeout), and a
/// line that exceeds its byte cap.
enum LineRead {
    Line(String),
    Eof,
    TooLong,
    Err,
}

/// Read one CRLF/LF-terminated line, one byte at a time (from a buffered reader), refusing a line
/// longer than `cap` bytes. This bounds both the request line and each header line, and the read
/// timeout on the stream turns a stalled sender into an `Err` rather than an unbounded wait.
fn read_line_capped<R: BufRead>(r: &mut R, cap: usize) -> LineRead {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => {
                return if out.is_empty() {
                    LineRead::Eof
                } else {
                    LineRead::Line(trim_cr(&out))
                }
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    return LineRead::Line(trim_cr(&out));
                }
                out.push(byte[0]);
                if out.len() > cap {
                    return LineRead::TooLong;
                }
            }
            Err(_) => return LineRead::Err,
        }
    }
}

fn trim_cr(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\r')
        .to_owned()
}

fn handle(
    mut stream: TcpStream,
    cfg: &Config,
    store: &Store,
    counter: &AtomicU64,
) -> std::io::Result<()> {
    stream.set_read_timeout(cfg.read_timeout)?;
    let mut reader = BufReader::new(stream.try_clone()?);

    let (status, body) = match read_line_capped(&mut reader, MAX_REQUEST_LINE) {
        LineRead::Eof => return Ok(()),
        LineRead::TooLong => ("414 URI Too Long", err_json("request line too long")),
        LineRead::Err => (
            "408 Request Timeout",
            err_json("timed out reading request line"),
        ),
        LineRead::Line(request_line) => {
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("").to_owned();
            let path = parts.next().unwrap_or("").to_owned();
            match read_headers(&mut reader) {
                Err(resp) => resp,
                Ok(content_length) => route(
                    &method,
                    &path,
                    &mut reader,
                    content_length,
                    cfg,
                    store,
                    counter,
                ),
            }
        }
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    // Half-close the write side so the peer sees end-of-response immediately, then best-effort
    // discard any unread request bytes (e.g. the oversized remainder of a rejected request) so
    // closing the socket does not reset the peer before it reads the response. Bounded by a short
    // drain timeout and a hard byte cap so this never waits on the full request read timeout.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut sink = [0u8; 4096];
    let mut drained = 0usize;
    while drained < 1_048_576 {
        match reader.read(&mut sink) {
            Ok(0) => break,
            Ok(n) => drained += n,
            Err(_) => break,
        }
    }
    Ok(())
}

/// Read the header block, bounding the header count and total bytes, and return the declared
/// Content-Length. On a limit breach or read error, return the response to send instead.
fn read_headers(reader: &mut BufReader<TcpStream>) -> Result<usize, (&'static str, String)> {
    let mut content_length = 0usize;
    let mut count = 0usize;
    let mut bytes = 0usize;
    loop {
        match read_line_capped(reader, MAX_HEADER_LINE) {
            LineRead::Eof => break,
            LineRead::TooLong => {
                return Err((
                    "431 Request Header Fields Too Large",
                    err_json("header line too long"),
                ))
            }
            LineRead::Err => {
                return Err(("408 Request Timeout", err_json("timed out reading headers")))
            }
            LineRead::Line(line) => {
                if line.is_empty() {
                    break;
                }
                count += 1;
                bytes += line.len();
                if count > MAX_HEADERS || bytes > MAX_HEADER_BYTES {
                    return Err((
                        "431 Request Header Fields Too Large",
                        err_json("too many header fields"),
                    ));
                }
                if let Some(v) = line
                    .strip_prefix("Content-Length:")
                    .or_else(|| line.strip_prefix("content-length:"))
                {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }
    }
    Ok(content_length)
}

#[allow(clippy::too_many_arguments)]
fn route(
    method: &str,
    path: &str,
    reader: &mut BufReader<TcpStream>,
    content_length: usize,
    cfg: &Config,
    store: &Store,
    counter: &AtomicU64,
) -> (&'static str, String) {
    match (method, path) {
        ("GET", "/healthz") => ("200 OK", r#"{"status":"ok"}"#.to_owned()),
        ("GET", "/v1/scenarios") => ("200 OK", demo::scenarios_json().to_string()),
        ("POST", "/v1/runs") => {
            if content_length > MAX_BODY {
                return ("413 Payload Too Large", err_json("request body too large"));
            }
            // Refuse before reading the body once the stored-run cap is reached.
            if store.lock().expect("store").len() >= cfg.max_runs {
                return (
                    "429 Too Many Requests",
                    err_json("stored run limit reached"),
                );
            }
            let mut buf = vec![0u8; content_length];
            if let Err(e) = reader.read_exact(&mut buf) {
                let msg = if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    ("408 Request Timeout", "timed out reading request body")
                } else {
                    ("400 Bad Request", "truncated body")
                };
                return (msg.0, err_json(msg.1));
            }
            let req: RunRequest = match serde_json::from_slice(&buf) {
                Ok(r) => r,
                Err(e) => return ("400 Bad Request", err_json(&format!("invalid JSON: {e}"))),
            };
            let run_id = format!("run-{:04}", counter.fetch_add(1, Ordering::SeqCst));
            match demo::run(
                &run_id,
                &req.scenario_id,
                &req.proposal,
                req.prompt_variant_id.as_deref(),
                req.model_metadata.as_deref(),
                req.model_parse.as_deref(),
            ) {
                Ok(record) => {
                    let body = serde_json::to_string(&record).unwrap_or_else(|_| "{}".to_owned());
                    let mut guard = store.lock().expect("store");
                    // Re-check under the lock: never store past the cap.
                    if guard.len() >= cfg.max_runs {
                        return (
                            "429 Too Many Requests",
                            err_json("stored run limit reached"),
                        );
                    }
                    guard.insert(run_id, record);
                    ("200 OK", body)
                }
                Err(DemoError::UnknownScenario) => {
                    ("404 Not Found", err_json("unknown scenario id"))
                }
                Err(DemoError::Oversized(field)) => (
                    "400 Bad Request",
                    err_json(&format!("oversized field: {field}")),
                ),
            }
        }
        ("GET", p) if p.starts_with("/v1/runs/") => {
            let id = &p["/v1/runs/".len()..];
            match store.lock().expect("store").get(id) {
                Some(record) => (
                    "200 OK",
                    serde_json::to_string(record).unwrap_or_else(|_| "{}".to_owned()),
                ),
                None => ("404 Not Found", err_json("unknown run id")),
            }
        }
        _ => ("404 Not Found", err_json("no such route")),
    }
}

fn err_json(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}
