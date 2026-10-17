//! Provider-owned demo controller (docs/model-demo.md). A tiny dependency-free HTTP server
//! over the `aisig_proto::demo` core. The model/client supplies only a scenario id and one
//! untrusted action proposal; the provider builds all trusted inputs from the synthetic
//! fixture and runs the existing verifier/session/mediator. No real scan/fetch/DB/shell.
//!
//! Routes: `GET /v1/scenarios`, `POST /v1/runs`, `GET /v1/runs/{id}`, `GET /healthz`.
//! Bind address defaults to `127.0.0.1:8787`; override with `AISIG_DEMO_BIND` (e.g. to make it
//! reachable from the local n8n container on a single research host — synthetic data only).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aisig_proto::demo::{self, DemoError, Proposal, RunRecord};
use serde::Deserialize;

const MAX_BODY: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    scenario_id: String,
    proposal: Proposal,
    #[serde(default)]
    prompt_variant_id: Option<String>,
    #[serde(default)]
    model_metadata: Option<String>,
}

fn main() {
    let bind = std::env::var("AISIG_DEMO_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    eprintln!("demo controller listening on http://{bind} (synthetic only; no real effects)");
    let store: Mutex<HashMap<String, RunRecord>> = Mutex::new(HashMap::new());
    let counter = AtomicU64::new(1);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(s, &store, &counter) {
                    eprintln!("connection error: {e}");
                }
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

fn handle(
    mut stream: TcpStream,
    store: &Mutex<HashMap<String, RunRecord>>,
    counter: &AtomicU64,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts.next().unwrap_or("").to_owned();

    // Headers: find Content-Length.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let (status, body) = route(&method, &path, &mut reader, content_length, store, counter);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn route(
    method: &str,
    path: &str,
    reader: &mut BufReader<TcpStream>,
    content_length: usize,
    store: &Mutex<HashMap<String, RunRecord>>,
    counter: &AtomicU64,
) -> (&'static str, String) {
    match (method, path) {
        ("GET", "/healthz") => ("200 OK", r#"{"status":"ok"}"#.to_owned()),
        ("GET", "/v1/scenarios") => ("200 OK", demo::scenarios_json().to_string()),
        ("POST", "/v1/runs") => {
            if content_length > MAX_BODY {
                return ("413 Payload Too Large", err_json("request body too large"));
            }
            let mut buf = vec![0u8; content_length];
            if reader.read_exact(&mut buf).is_err() {
                return ("400 Bad Request", err_json("truncated body"));
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
            ) {
                Ok(record) => {
                    let body = serde_json::to_string(&record).unwrap_or_else(|_| "{}".to_owned());
                    store.lock().expect("store").insert(run_id, record);
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
