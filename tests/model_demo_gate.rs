//! Publish gate for the model-demo artifacts in `results/model_demo/`.
//!
//! This is the blocking check that the repeatable sanitizer (`scripts/sanitize_n8n_export.py`)
//! is meant to satisfy: no committed n8n execution export (or any demo JSON) may carry a token,
//! credential, secret, password, cookie, or authorization field. The test fails with the key
//! *paths* only, never the redacted values.

use std::fs;
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

const DIR: &str = "results/model_demo";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// The Set node's `a4` assignment holds the user prompt in the v1/v2 workflows.
fn user_prompt(workflow_json: &Value) -> Option<String> {
    for node in workflow_json["nodes"].as_array()? {
        if node["type"] == "n8n-nodes-base.set" {
            for a in node["parameters"]["assignments"]["assignments"].as_array()? {
                if a["id"] == "a4" {
                    return a["value"].as_str().map(str::to_owned);
                }
            }
        }
    }
    None
}

/// Mirror of `scripts/sanitize_n8n_export.py`: a key name that denotes a secret. Matched
/// separator-insensitively (lowercase, with '-', '_' and spaces removed) so "api-key", "api_key"
/// and "apikey" match, as do header forms like "Set-Cookie" and "Proxy-Authorization".
fn is_sensitive(key: &str) -> bool {
    let k: String = key
        .to_ascii_lowercase()
        .chars()
        .filter(|c| *c != '-' && *c != '_' && *c != ' ')
        .collect();
    const EXACT: &[&str] = &[
        "resumetoken",
        "token",
        "accesstoken",
        "refreshtoken",
        "sessiontoken",
        "oauthtokendata",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "password",
        "passwd",
        "apikey",
        "xapikey",
        "authorization",
        "proxyauthorization",
        "wwwauthenticate",
        "cookie",
        "setcookie",
        "privatekey",
        "bearer",
    ];
    const SUFFIX: &[&str] = &[
        "token",
        "secret",
        "password",
        "apikey",
        "credential",
        "cookie",
        "authorization",
    ];
    EXACT.contains(&k.as_str()) || SUFFIX.iter().any(|s| k.ends_with(s))
}

fn collect_sensitive(node: &Value, path: &str, hits: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (k, v) in map {
                let p = format!("{path}.{k}");
                if is_sensitive(k) {
                    hits.push(p.clone());
                }
                collect_sensitive(v, &p, hits);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                collect_sensitive(v, &format!("{path}[{i}]"), hits);
            }
        }
        _ => {}
    }
}

#[test]
fn no_committed_demo_export_contains_a_secret_field() {
    let dir = Path::new(DIR);
    assert!(dir.is_dir(), "{DIR} must exist");
    let mut scanned = 0usize;
    let mut all_hits: Vec<String> = Vec::new();
    for entry in fs::read_dir(dir).expect("read results/model_demo") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read json");
        let json: Value = serde_json::from_str(&text).expect("parse json");
        let mut hits = Vec::new();
        collect_sensitive(
            &json,
            path.file_name().unwrap().to_str().unwrap(),
            &mut hits,
        );
        all_hits.extend(hits);
        scanned += 1;
    }
    assert!(scanned > 0, "no demo JSON files were scanned");
    assert!(
        all_hits.is_empty(),
        "publishable demo exports contain secret-like fields (run scripts/sanitize_n8n_export.py); \
         offending key paths (values not shown): {all_hits:?}"
    );
}

#[test]
fn header_key_forms_are_detected() {
    // Common header/credential key spellings, including hyphenated and mixed-case forms.
    for k in [
        "resumeToken",
        "Set-Cookie",
        "set-cookie",
        "Cookie",
        "Proxy-Authorization",
        "Authorization",
        "WWW-Authenticate",
        "api-key",
        "api_key",
        "apiKey",
        "X-Api-Key",
        "accessToken",
        "refresh_token",
        "clientSecret",
        "db_password",
        "Bearer",
    ] {
        assert!(is_sensitive(k), "{k} should be treated as sensitive");
    }
    // Legitimate keys that must NOT be flagged.
    for k in [
        "content-length",
        "model_parse",
        "parse_status",
        "author",
        "operation",
        "target",
        "workflow_revision_sha256",
        "ollama_version",
        "eval_count",
    ] {
        assert!(!is_sensitive(k), "{k} should NOT be flagged");
    }
}

#[test]
fn nested_sensitive_keys_are_found() {
    // A secret buried inside nested objects/arrays (as in an n8n node's HTTP response headers)
    // must be located, and a clean nested structure must report nothing.
    let dirty = serde_json::json!({
        "data": {"resultData": {"runData": {
            "HTTP": [{"json": {"headers": [{"Set-Cookie": "x"}, {"Proxy-Authorization": "y"}]}}]
        }}}
    });
    let mut hits = Vec::new();
    collect_sensitive(&dirty, "root", &mut hits);
    assert_eq!(
        hits.len(),
        2,
        "expected both nested header secrets, got {hits:?}"
    );
    assert!(hits.iter().any(|h| h.ends_with("Set-Cookie")));
    assert!(hits.iter().any(|h| h.ends_with("Proxy-Authorization")));

    let clean =
        serde_json::json!({"a": {"b": [{"operation": "web.get", "model_parse": "no_call"}]}});
    let mut none = Vec::new();
    collect_sensitive(&clean, "root", &mut none);
    assert!(none.is_empty(), "clean structure flagged: {none:?}");
}

#[test]
fn sanitizer_script_is_present() {
    assert!(
        Path::new("scripts/sanitize_n8n_export.py").is_file(),
        "the repeatable sanitizer scripts/sanitize_n8n_export.py must exist"
    );
}

/// Gate the reported v1/v2/control workflow hashes and prompt variants against the committed
/// workflow files, and require the actual Ollama runtime version on each model run. This proves
/// the recorded n8n executions correspond to files in the repository, not to uncommitted ones.
#[test]
fn reported_workflow_hashes_and_prompts_match_committed_files() {
    let runs_json: Value = serde_json::from_str(
        &fs::read_to_string(format!("{DIR}/n8n_runs.json")).expect("n8n_runs"),
    )
    .expect("parse n8n_runs");

    // variant -> top-level workflow_revision_sha256 key
    let top_key = |variant: &str| match variant {
        "v1" => "v1_canonical",
        "v2" => "v2_variant",
        "control-excluded" => "control",
        other => panic!("unexpected variant {other}"),
    };
    let top = &runs_json["workflow_revision_sha256"];

    let runs = runs_json["runs"].as_array().expect("runs array");
    assert!(!runs.is_empty(), "no runs recorded");
    for run in runs {
        let variant = run["variant"].as_str().expect("variant");
        let wf_path = run["workflow_file"]
            .as_str()
            .unwrap_or_else(|| panic!("{variant}: missing workflow_file"));
        let wf_bytes = fs::read(wf_path).unwrap_or_else(|_| panic!("{variant}: {wf_path} missing"));
        let actual = sha256_hex(&wf_bytes);

        let reported = run["workflow_revision_sha256"]
            .as_str()
            .expect("per-run hash");
        assert_eq!(
            actual, reported,
            "{variant}: committed {wf_path} sha256 != reported per-run hash"
        );
        assert_eq!(
            Some(actual.as_str()),
            top[top_key(variant)].as_str(),
            "{variant}: top-level workflow hash does not match the committed file"
        );

        // Prompt-variant gate (v1/v2 carry a model prompt; the control does not).
        if let Some(reported_prompt) = run["prompt_sha256"].as_str() {
            let wf: Value = serde_json::from_slice(&wf_bytes).expect("parse workflow");
            let prompt = user_prompt(&wf)
                .unwrap_or_else(|| panic!("{variant}: no a4 user prompt in {wf_path}"));
            assert_eq!(
                sha256_hex(prompt.as_bytes()),
                reported_prompt,
                "{variant}: committed prompt sha256 != reported prompt_sha256"
            );
        }

        // Record of the actual model runtime version is required for model-driven runs.
        if let Some(model) = run.get("model") {
            let ver = model["ollama_version"].as_str().unwrap_or("");
            assert!(
                !ver.is_empty(),
                "{variant}: model run must record the actual ollama_version"
            );
        }
    }
}
