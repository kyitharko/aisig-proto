//! Publish gate for the model-demo artifacts in `results/model_demo/`.
//!
//! This is the blocking check that the repeatable sanitizer (`scripts/sanitize_n8n_export.py`)
//! is meant to satisfy: no committed n8n execution export (or any demo JSON) may carry a token,
//! credential, secret, password, cookie, or authorization field. The test fails with the key
//! *paths* only, never the redacted values.

use std::fs;
use std::path::Path;

use serde_json::Value;

const DIR: &str = "results/model_demo";

/// Mirror of `scripts/sanitize_n8n_export.py`: a key name that denotes a secret.
fn is_sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
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
        "api_key",
        "authorization",
        "cookie",
        "x-api-key",
        "privatekey",
        "private_key",
    ];
    const SUFFIX: &[&str] = &["token", "secret", "password", "apikey", "credential"];
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
        collect_sensitive(&json, path.file_name().unwrap().to_str().unwrap(), &mut hits);
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
fn sanitizer_script_is_present() {
    assert!(
        Path::new("scripts/sanitize_n8n_export.py").is_file(),
        "the repeatable sanitizer scripts/sanitize_n8n_export.py must exist"
    );
}
