//! HTTP-level tests for the demo controller binary (`demo_controller`). These spawn the real
//! compiled server on a loopback ephemeral port and speak raw HTTP over TCP — no model, no
//! network beyond loopback. They assert the transport-level bounds (request line, headers, read
//! timeout, stored-run cap) and the core rule that survives every path: an `Allow` records
//! exactly one modeled effect and every other outcome records zero.
//!
//! Reproduction set (added before the hardening): the request-line, header-flood, read-timeout
//! and max-runs tests are expected to FAIL against the un-hardened binary and to pass once the
//! bounds are implemented.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    addr: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local addr").port()
}

fn spawn(extra_env: &[(&str, &str)]) -> Server {
    let addr = format!("127.0.0.1:{}", free_port());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_demo_controller"));
    cmd.env("AISIG_DEMO_BIND", &addr);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("spawn demo_controller");
    let start = Instant::now();
    loop {
        if let Ok(body) = try_request(
            &addr,
            b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            Duration::from_secs(2),
        ) {
            if body.contains("200 OK") {
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(30) {
            panic!("demo_controller did not become ready on {addr}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Server { child, addr }
}

/// Send a raw request and read the whole response until the server closes or the client read
/// times out. A client timeout yields whatever was received (possibly empty).
fn try_request(addr: &str, raw: &[u8], read_timeout: Duration) -> std::io::Result<String> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(read_timeout))?;
    s.write_all(raw)?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => return Err(e),
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn raw(addr: &str, bytes: &[u8]) -> String {
    try_request(addr, bytes, Duration::from_secs(8)).expect("request")
}

fn post(addr: &str, path: &str, body: &str) -> String {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    raw(addr, req.as_bytes())
}

fn get(addr: &str, path: &str) -> String {
    raw(
        addr,
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
}

/// Split an HTTP response into (status line, JSON body value).
fn parse(resp: &str) -> (String, serde_json::Value) {
    let status = resp.lines().next().unwrap_or("").to_owned();
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    let json = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

const REPORTS: &str = "web:https://app.acme.test:443/app/reports";
const ADMIN: &str = "web:https://app.acme.test:443/app/admin";

fn run_body(scenario: &str, op: &str, target: &str) -> String {
    serde_json::json!({
        "scenario_id": scenario,
        "proposal": { "operation": op, "target": target }
    })
    .to_string()
}

#[test]
fn healthz_and_scenarios_ok() {
    let s = spawn(&[]);
    assert!(get(&s.addr, "/healthz").contains("200 OK"));
    let (status, json) = parse(&get(&s.addr, "/v1/scenarios"));
    assert!(status.contains("200 OK"), "status: {status}");
    assert!(json["scenarios"].is_array());
}

#[test]
fn allow_records_exactly_one_effect_over_http() {
    let s = spawn(&[]);
    let (status, json) = parse(&post(
        &s.addr,
        "/v1/runs",
        &run_body("fresh", "web.get", REPORTS),
    ));
    assert!(status.contains("200 OK"), "status: {status}");
    assert_eq!(json["decision"], "Allow");
    assert_eq!(json["effects_delta"], 1);
    // The run is retrievable and still shows the one effect.
    let id = json["run_id"].as_str().expect("run_id");
    let (gstatus, gjson) = parse(&get(&s.addr, &format!("/v1/runs/{id}")));
    assert!(gstatus.contains("200 OK"));
    assert_eq!(gjson["effects_delta"], 1);
}

#[test]
fn excluded_target_denies_with_zero_effect_over_http() {
    let s = spawn(&[]);
    let (status, json) = parse(&post(
        &s.addr,
        "/v1/runs",
        &run_body("fresh", "web.get", ADMIN),
    ));
    assert!(status.contains("200 OK"), "status: {status}");
    assert_eq!(json["decision"], "Deny / scope / DenyTargetExcluded");
    assert_eq!(json["effects_delta"], 0);
}

#[test]
fn extra_trusted_fields_are_rejected() {
    // The client/model must never supply trusted inputs. deny_unknown_fields must reject them,
    // with no run created and therefore no effect.
    let s = spawn(&[]);
    for field in ["session_ref", "bundle", "evidence", "sink", "status"] {
        let body = format!(
            r#"{{"scenario_id":"fresh","proposal":{{"operation":"web.get","target":"{REPORTS}"}},"{field}":"x"}}"#
        );
        let (status, _) = parse(&post(&s.addr, "/v1/runs", &body));
        assert!(
            status.contains("400"),
            "field {field} should be rejected, got {status}"
        );
    }
}

#[test]
fn proposal_with_extra_field_is_rejected() {
    let s = spawn(&[]);
    let body = r#"{"scenario_id":"fresh","proposal":{"operation":"web.get","target":"x","authorized":true}}"#;
    let (status, _) = parse(&post(&s.addr, "/v1/runs", body));
    assert!(status.contains("400"), "got {status}");
}

#[test]
fn malformed_json_is_rejected_without_effect() {
    let s = spawn(&[]);
    let (status, _) = parse(&post(&s.addr, "/v1/runs", "{not json"));
    assert!(status.contains("400"), "got {status}");
}

#[test]
fn unknown_scenario_is_404() {
    let s = spawn(&[]);
    let (status, _) = parse(&post(
        &s.addr,
        "/v1/runs",
        &run_body("nope", "web.get", REPORTS),
    ));
    assert!(status.contains("404"), "got {status}");
}

#[test]
fn oversized_body_is_rejected() {
    let s = spawn(&[]);
    let big = "x".repeat(70_000);
    let body = format!(r#"{{"scenario_id":"fresh","proposal":{{"operation":"{big}"}}}}"#);
    let req = format!(
        "POST /v1/runs HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    // The server rejects an over-limit body before reading it; the client may receive a 413/400
    // response, or the connection may be reset. Both mean "rejected, no run created"; a 200 must
    // never happen.
    let resp = try_request(&s.addr, req.as_bytes(), Duration::from_secs(8)).unwrap_or_default();
    let status = resp.lines().next().unwrap_or("").to_owned();
    assert!(
        !status.contains("200 OK"),
        "oversized body must not be accepted, got {status:?}"
    );
    // The server is still healthy afterwards (it did not crash on the oversized input).
    assert!(get(&s.addr, "/healthz").contains("200 OK"));
}

#[test]
fn oversized_operation_field_is_rejected_without_effect() {
    let s = spawn(&[]);
    let big = "x".repeat(10_000);
    let body = format!(
        r#"{{"scenario_id":"fresh","proposal":{{"operation":"{big}","target":"{REPORTS}"}}}}"#
    );
    let (status, _) = parse(&post(&s.addr, "/v1/runs", &body));
    assert!(status.contains("400"), "got {status}");
}

// ---- hardening reproductions (expected to fail before the bounds are added) ----

#[test]
fn overlong_request_line_is_rejected() {
    let s = spawn(&[]);
    let giant = "a".repeat(20_000);
    let req = format!("GET /{giant} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let resp = raw(&s.addr, req.as_bytes());
    let status = resp.lines().next().unwrap_or("").to_owned();
    assert!(
        status.contains("414") || status.contains("400"),
        "an overlong request line must be rejected, got {status:?}"
    );
}

#[test]
fn header_flood_is_rejected() {
    let s = spawn(&[]);
    let mut req = String::from("GET /healthz HTTP/1.1\r\nHost: x\r\n");
    for i in 0..5000 {
        req.push_str(&format!("X-Pad-{i}: 1\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    let resp = raw(&s.addr, req.as_bytes());
    let status = resp.lines().next().unwrap_or("").to_owned();
    assert!(
        status.contains("431") || status.contains("400"),
        "a header flood must be rejected, got {status:?}"
    );
}

#[test]
fn slow_incomplete_request_times_out() {
    // Server read timeout set low; send a promised body that never arrives. The server must give
    // up and respond/close rather than hang forever.
    let s = spawn(&[("AISIG_DEMO_READ_TIMEOUT_MS", "800")]);
    let mut stream = TcpStream::connect(&s.addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // Content-Length promises 100 bytes; we send only 5 and keep the socket open.
    stream
        .write_all(b"POST /v1/runs HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nhello")
        .unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let start = Instant::now();
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
        if start.elapsed() > Duration::from_secs(5) {
            break;
        }
    }
    assert!(
        start.elapsed() < Duration::from_secs(4) && !buf.is_empty(),
        "server should close/respond quickly after the read timeout; elapsed={:?} bytes={}",
        start.elapsed(),
        buf.len()
    );
}

#[test]
fn dribbling_client_is_cut_off_by_the_absolute_deadline() {
    // The per-read timeout alone is not enough: a client that sends one byte just before each
    // timeout keeps resetting it and would hold the single-threaded server forever. The absolute
    // per-request deadline must end such a connection, and the server must keep serving others.
    let s = spawn(&[
        ("AISIG_DEMO_READ_TIMEOUT_MS", "400"),
        ("AISIG_DEMO_REQUEST_DEADLINE_MS", "1200"),
    ]);
    let stream = TcpStream::connect(&s.addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut wr = stream.try_clone().unwrap();
    // Start a request but never finish the header block.
    wr.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
        .unwrap();
    let start = Instant::now();
    // Dribble one non-terminating byte every 300 ms (< the 400 ms per-read timeout) for longer
    // than the deadline, so each individual read succeeds and resets the per-read timeout.
    let dribbler = std::thread::spawn(move || {
        for _ in 0..20 {
            if wr.write_all(b"A").is_err() || wr.flush().is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    });
    // Read until the server responds (a 408) and closes.
    let mut rd = stream;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match rd.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let elapsed = start.elapsed();
    let _ = dribbler.join();
    assert!(
        elapsed < Duration::from_secs(3),
        "the deadline must end the dribbling connection well before 'indefinitely'; elapsed={elapsed:?}"
    );
    let resp = String::from_utf8_lossy(&buf);
    assert!(
        resp.contains("408"),
        "the server should answer the dribbling client with a 408 at the deadline; got {resp:?}"
    );
    // The single-threaded server is not wedged: it still serves a normal request.
    assert!(get(&s.addr, "/healthz").contains("200 OK"));
}

#[test]
fn stored_run_count_is_bounded() {
    let s = spawn(&[("AISIG_DEMO_MAX_RUNS", "2")]);
    let ok1 = parse(&post(
        &s.addr,
        "/v1/runs",
        &run_body("fresh", "web.get", REPORTS),
    ));
    let ok2 = parse(&post(
        &s.addr,
        "/v1/runs",
        &run_body("fresh", "web.get", REPORTS),
    ));
    assert!(ok1.0.contains("200 OK"), "run 1: {}", ok1.0);
    assert!(ok2.0.contains("200 OK"), "run 2: {}", ok2.0);
    let over = parse(&post(
        &s.addr,
        "/v1/runs",
        &run_body("fresh", "web.get", REPORTS),
    ));
    assert!(
        over.0.contains("429") || over.0.contains("503"),
        "a run past the stored-run cap must be rejected, got {}",
        over.0
    );
}
