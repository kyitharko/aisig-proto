//! Publish gate for the model-demo artifacts in `results/model_demo/`.
//!
//! This is the blocking check that the repeatable sanitizer (`scripts/sanitize_n8n_export.py`)
//! is meant to satisfy: no committed n8n execution export (or any demo JSON) may carry a token,
//! credential, secret, password, cookie, or authorization field. The test fails with the key
//! *paths* only, never the redacted values.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use aisig_proto::demo::{run, Proposal};
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
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(next).expect("read results/model_demo") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("read json");
            let json: Value = serde_json::from_str(&text).expect("parse json");
            let mut hits = Vec::new();
            collect_sensitive(&json, &path.display().to_string(), &mut hits);
            all_hits.extend(hits);
            scanned += 1;
        }
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

/// Gate the preregistered fixed controls (DC01-DC13) against the real `src/demo.rs` controller.
/// The expectations were committed before the runner; this asserts the controller still produces
/// exactly them, with no parallel decision implementation.
#[test]
fn fixed_controls_match_the_real_controller() {
    let spec: Value = serde_json::from_str(
        &fs::read_to_string(format!("{DIR}/controls_expected.json")).expect("controls_expected"),
    )
    .expect("parse controls_expected");
    let controls = spec["controls"].as_array().expect("controls array");
    assert_eq!(controls.len(), 13, "expected 13 preregistered controls");
    for c in controls {
        let id = c["id"].as_str().unwrap();
        let scenario = c["scenario"].as_str().unwrap();
        let proposal: Proposal = serde_json::from_value(c["proposal"].clone())
            .unwrap_or_else(|e| panic!("{id}: bad proposal: {e}"));
        let r = run(
            id,
            scenario,
            &proposal,
            Some(id),
            Some("fixed control"),
            Some("deterministic_control"),
        )
        .unwrap_or_else(|e| panic!("{id}: run error {e:?}"));
        assert_eq!(
            r.parse_status,
            c["expected_parse_status"].as_str().unwrap(),
            "{id}: parse_status"
        );
        assert_eq!(
            r.decision,
            c["expected_decision"].as_str().unwrap(),
            "{id}: decision"
        );
        assert_eq!(
            r.effects_delta as u64,
            c["expected_delta"].as_u64().unwrap(),
            "{id}: effects_delta"
        );
    }
}

fn variant_file(variant: &str) -> &'static str {
    match variant {
        "v1" => "demo/n8n-workflow.json",
        "v2" => "demo/n8n-workflow-v2.json",
        "v3" => "demo/n8n-workflow-v3.json",
        other => panic!("unexpected variant {other}"),
    }
}

/// Gate the committed fixed-control results: 13 controls, each a 200 that matched its
/// preregistered decision / stage-reason / effect delta.
#[test]
fn committed_control_results_all_matched() {
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(format!("{DIR}/controls_expected.json")).expect("controls_expected"),
    )
    .expect("parse expected");
    let results: Value = serde_json::from_str(
        &fs::read_to_string(format!("{DIR}/controls_results.json")).expect("controls_results"),
    )
    .expect("parse results");
    let exp = expected["controls"].as_array().unwrap();
    let got = results["controls"].as_array().expect("results controls");
    assert_eq!(got.len(), 13, "expected 13 control results");
    assert_eq!(exp.len(), 13);
    for e in exp {
        let id = e["id"].as_str().unwrap();
        let r = got
            .iter()
            .find(|r| r["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("missing control result {id}"));
        assert_eq!(
            r["http_status"], 200,
            "{id}: not a 200 (not an authz decision)"
        );
        assert_eq!(r["pass"], true, "{id}: did not pass");
        assert_eq!(
            r["actual_decision"], e["expected_decision"],
            "{id}: decision"
        );
        assert_eq!(r["actual_delta"], e["expected_delta"], "{id}: delta");
        assert_eq!(
            r["actual_parse_status"], e["expected_parse_status"],
            "{id}: parse_status"
        );
    }
}

/// All problems with a model-matrix JSON value (empty => clean). Pure, so it is unit-testable
/// with synthetic inputs. Mirrors the matrix portion of
/// `scripts/run_prepublication_experiment.py::gate_problems`, plus hash/consistency checks against
/// the committed workflow files.
fn matrix_problems(m: &Value) -> Vec<String> {
    let mut p: Vec<String> = Vec::new();
    let runs = match m["runs"].as_array() {
        Some(r) => r,
        None => {
            p.push("matrix has no runs array".into());
            return p;
        }
    };
    if m["attempted"].as_u64() != Some(30) {
        p.push(format!("attempted != 30 ({:?})", m["attempted"]));
    }
    if runs.len() != 30 {
        p.push(format!("runs.len()={} != 30", runs.len()));
    }

    let id = &m["identity"];
    if !id["model_digest"].as_str().is_some_and(|s| s.len() >= 12) {
        p.push("identity: missing model_digest".into());
    }
    if !id["ollama_version"].as_str().is_some_and(|s| !s.is_empty()) {
        p.push("identity: missing ollama_version".into());
    }
    if !id["n8n_version"].as_str().is_some_and(|s| !s.is_empty()) {
        p.push("identity: missing n8n_version".into());
    }

    // Coverage must be exactly the planned (variant x scenario x repeat) product. This catches an
    // unplanned scenario (30 distinct cells that are not the planned set) and any missing cell.
    let variants = ["v1", "v2", "v3"];
    let scenarios = [
        "fresh",
        "expired_session",
        "revoked_grant",
        "stale_status",
        "unavailable_status",
    ];
    let mut planned = std::collections::HashSet::new();
    for v in variants {
        for s in scenarios {
            for rep in [1u64, 2] {
                planned.insert((v.to_owned(), s.to_owned(), rep));
            }
        }
    }
    let mut cells = std::collections::HashSet::new();
    for r in runs {
        cells.insert((
            r["variant"].as_str().unwrap_or("").to_owned(),
            r["scenario"].as_str().unwrap_or("").to_owned(),
            r["repeat"].as_u64().unwrap_or(0),
        ));
    }
    if cells != planned {
        let unplanned: Vec<_> = cells.difference(&planned).collect();
        let missing: Vec<_> = planned.difference(&cells).collect();
        p.push(format!(
            "coverage != planned 3x5x2 (unplanned={unplanned:?}, missing={missing:?})"
        ));
    }

    let mut wf_sha = HashMap::new();
    let mut prompt_sha = HashMap::new();
    for v in ["v1", "v2", "v3"] {
        if let Ok(bytes) = fs::read(variant_file(v)) {
            wf_sha.insert(v, sha256_hex(&bytes));
            if let Ok(wf) = serde_json::from_slice::<Value>(&bytes) {
                if let Some(pr) = user_prompt(&wf) {
                    prompt_sha.insert(v, sha256_hex(pr.as_bytes()));
                }
            }
        }
    }

    for r in runs {
        let rid = r["run_id"].as_str().unwrap_or("?").to_owned();
        if r["completed"] != Value::Bool(true) {
            p.push(format!("{rid}: not completed"));
            continue;
        }
        for f in [
            "decision",
            "parse_status",
            "effects_delta",
            "proposal",
            "model_raw_message",
        ] {
            if r[f].is_null() {
                p.push(format!("{rid}: missing field {f}"));
            }
        }
        let variant = r["variant"].as_str().unwrap_or("");
        if let Some(exp) = wf_sha.get(variant) {
            if r["committed_variant_sha256"].as_str() != Some(exp.as_str()) {
                p.push(format!("{rid}: committed_variant_sha256 != committed file"));
            }
        }
        if let Some(exp) = prompt_sha.get(variant) {
            if r["prompt_sha256"].as_str() != Some(exp.as_str()) {
                p.push(format!("{rid}: prompt_sha256 != committed variant prompt"));
            }
        }
        if !r["effective_workflow_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64)
        {
            p.push(format!("{rid}: missing effective_workflow_sha256"));
        }
        if !r["workflow_id"].as_str().is_some_and(|s| !s.is_empty()) {
            p.push(format!("{rid}: missing workflow_id"));
        }
        // A nonzero n8n execute returncode is a failure even if the JSON parsed.
        if let Some(rc) = r["execute_returncode"].as_i64() {
            if rc != 0 {
                p.push(format!("{rid}: nonzero n8n execute returncode {rc}"));
            }
        }
        // effective_workflow_fingerprint must be recomputable from retained data.
        if let (Some(cvs), Some(scn)) = (
            r["committed_variant_sha256"].as_str(),
            r["scenario"].as_str(),
        ) {
            let expect_fp = sha256_hex(format!("{cvs}\n{scn}").as_bytes());
            if let Some(fp) = r["effective_workflow_fingerprint"].as_str() {
                if fp != expect_fp {
                    p.push(format!(
                        "{rid}: effective_workflow_fingerprint not recomputable"
                    ));
                }
            }
        }

        let allow = r["decision"] == "Allow";
        let delta1 = r["effects_delta"] == 1;
        if allow != delta1 {
            p.push(format!("{rid}: effect-invariant violation"));
        }
        // effects_delta must equal effects_after - effects_before.
        if let (Some(b), Some(a), Some(d)) = (
            r["effects_before"].as_i64(),
            r["effects_after"].as_i64(),
            r["effects_delta"].as_i64(),
        ) {
            if d != a - b {
                p.push(format!(
                    "{rid}: effects_delta {d} != effects_after {a} - effects_before {b}"
                ));
            }
        }

        let parse = r["parse_status"].as_str().unwrap_or("");
        let proposal = &r["proposal"];
        let calls = r["model_raw_message"]["tool_calls"].as_array();
        if parse == "tool_call" {
            if !proposal["operation"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            {
                p.push(format!("{rid}: tool_call proposal missing operation"));
            }
            if !proposal["target"].as_str().is_some_and(|s| !s.is_empty()) {
                p.push(format!("{rid}: tool_call proposal missing target"));
            }
            match calls.and_then(|c| c.first()) {
                None => p.push(format!(
                    "{rid}: tool_call but raw message has no tool_calls"
                )),
                Some(first) => {
                    if first["function"]["name"] != "propose_action" {
                        p.push(format!("{rid}: raw tool call is not propose_action"));
                    }
                    let args = &first["function"]["arguments"];
                    if args.is_object() {
                        if args["operation"] != proposal["operation"] {
                            p.push(format!("{rid}: op mismatch raw vs proposal"));
                        }
                        if args["target"] != proposal["target"] {
                            p.push(format!("{rid}: target mismatch raw vs proposal"));
                        }
                    }
                }
            }
        } else if parse == "no_call" {
            if !proposal["operation"].is_null() {
                p.push(format!("{rid}: no_call must not carry an operation"));
            }
            if !calls.map(|c| c.is_empty()).unwrap_or(true) {
                p.push(format!("{rid}: no_call but raw message has tool_calls"));
            }
        }
    }
    p
}

fn committed_matrix() -> Value {
    serde_json::from_str(
        &fs::read_to_string(format!("{DIR}/model_matrix.json")).expect("model_matrix"),
    )
    .expect("parse matrix")
}

/// Gate the committed model matrix: full coverage, every cell completed, required fields present,
/// effect invariant, recorded hashes match the committed workflows, raw-message<->proposal
/// consistency, and captured identity present. Additionally require, on the committed authoritative
/// matrix, that every run carries the full provenance (`execute_returncode == 0` and a
/// recomputable `effective_workflow_fingerprint`) and that the provenance note is present.
#[test]
fn committed_model_matrix_is_complete_and_consistent() {
    let m = committed_matrix();
    let problems = matrix_problems(&m);
    assert!(
        problems.is_empty(),
        "committed matrix problems: {problems:?}"
    );
    assert!(
        m["provenance"]["effective_workflow_fingerprint"].is_string(),
        "committed matrix must document the effective-workflow provenance scheme"
    );
    for r in m["runs"].as_array().unwrap() {
        let rid = r["run_id"].as_str().unwrap_or("?");
        assert_eq!(
            r["execute_returncode"].as_i64(),
            Some(0),
            "{rid}: committed run must record execute_returncode == 0"
        );
        let cvs = r["committed_variant_sha256"].as_str().unwrap();
        let scn = r["scenario"].as_str().unwrap();
        let expect_fp = sha256_hex(format!("{cvs}\n{scn}").as_bytes());
        assert_eq!(
            r["effective_workflow_fingerprint"].as_str(),
            Some(expect_fp.as_str()),
            "{rid}: committed run must carry a recomputable effective_workflow_fingerprint"
        );
    }
}

/// Keep the independently executed manual replication separate from run 3, while gating its
/// preregistered controls, full matrix, recorded provenance, and public address redaction.
fn assert_manual_replication(dir: &str) {
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(format!("{DIR}/controls_expected.json")).expect("controls_expected"),
    )
    .expect("parse controls_expected");
    let controls: Value = serde_json::from_str(
        &fs::read_to_string(format!("{dir}/controls_results.json")).expect("manual controls"),
    )
    .expect("parse manual controls");
    assert_eq!(
        controls["controller_url"], "http://100.x.y.z:8787",
        "publication result must redact the private controller address"
    );
    let results = controls["controls"]
        .as_array()
        .expect("manual control results");
    assert_eq!(results.len(), 13);
    for e in expected["controls"].as_array().expect("expected controls") {
        let id = e["id"].as_str().expect("control id");
        let matches: Vec<_> = results
            .iter()
            .filter(|r| r["id"].as_str() == Some(id))
            .collect();
        assert_eq!(matches.len(), 1, "{id}: expected exactly one result");
        let r = matches[0];
        for field in [
            "scenario",
            "proposal",
            "expected_decision",
            "expected_parse_status",
            "expected_delta",
        ] {
            assert_eq!(r[field], e[field], "{id}: preregistered {field} changed");
        }
        assert_eq!(r["http_status"], 200, "{id}: HTTP status");
        assert_eq!(r["pass"], true, "{id}: recorded control failure");
        assert_eq!(
            r["actual_decision"], e["expected_decision"],
            "{id}: decision"
        );
        assert_eq!(
            r["actual_parse_status"], e["expected_parse_status"],
            "{id}: parse"
        );
        assert_eq!(r["actual_delta"], e["expected_delta"], "{id}: effect delta");
    }

    let matrix: Value = serde_json::from_str(
        &fs::read_to_string(format!("{dir}/model_matrix.json")).expect("manual matrix"),
    )
    .expect("parse manual matrix");
    let problems = matrix_problems(&matrix);
    assert!(problems.is_empty(), "manual matrix problems: {problems:?}");
    assert_eq!(matrix["completed"], 30, "manual matrix completed count");
    for r in matrix["runs"].as_array().expect("manual runs") {
        let rid = r["run_id"].as_str().expect("run id");
        assert_eq!(r["execute_returncode"], 0, "{rid}: n8n execution");
        assert_eq!(r["model_parse"], r["parse_status"], "{rid}: parse mismatch");
        let wf = r["committed_variant_sha256"]
            .as_str()
            .expect("workflow hash");
        let scenario = r["scenario"].as_str().expect("scenario");
        let expected_fp = sha256_hex(format!("{wf}\n{scenario}").as_bytes());
        assert_eq!(
            r["effective_workflow_fingerprint"].as_str(),
            Some(expected_fp.as_str()),
            "{rid}: fingerprint"
        );
        if r["model_parse"] == "tool_call" {
            let raw_args = &r["model_raw_message"]["tool_calls"][0]["function"]["arguments"];
            assert_eq!(
                r["proposal"]["claimed_class"], raw_args["claimed_class"],
                "{rid}: audit-only claimed class differs from raw call"
            );
        }
    }
}

#[test]
fn published_manual_replication_matches_its_preregistration() {
    assert_manual_replication(&format!("{DIR}/manual_replication_20261019"));
}

#[test]
fn published_manual_02_matches_its_preregistration_and_source_hashes() {
    let dir = format!("{DIR}/manual_replication_20261022");
    assert_manual_replication(&dir);

    let mut got: Vec<_> = fs::read_dir(&dir)
        .expect("read manual-02 publication directory")
        .map(|entry| {
            entry
                .expect("manual-02 entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    got.sort();
    let mut expected = vec![
        "README.md",
        "publication_manifest.json",
        "controls_results.json",
        "model_matrix.json",
        "visual_report.html",
        "decision_distribution.svg",
    ];
    expected.sort();
    assert_eq!(
        got.iter().map(String::as_str).collect::<Vec<_>>(),
        expected,
        "manual-02 must contain exactly six reviewed files"
    );

    let manifest: Value = serde_json::from_slice(
        &fs::read(format!("{dir}/publication_manifest.json")).expect("publication manifest"),
    )
    .expect("parse publication manifest");
    assert_eq!(manifest["publication_stage"], "publication_copy");
    assert_eq!(manifest["source_run_id"], "full-20261022T105748Z-668695e4");
    assert_eq!(manifest["removed_sensitive_key_count"], 0);

    let controls = fs::read(format!("{dir}/controls_results.json")).expect("manual-02 controls");
    let matrix_bytes = fs::read(format!("{dir}/model_matrix.json")).expect("manual-02 matrix");
    let c_hash = sha256_hex(&controls);
    let m_hash = sha256_hex(&matrix_bytes);
    let note = fs::read_to_string(format!("{dir}/README.md")).expect("manual-02 README");
    let html = fs::read_to_string(format!("{dir}/visual_report.html")).expect("manual-02 HTML");
    for hash in [&c_hash, &m_hash] {
        assert!(
            note.contains(hash.as_str()),
            "manual-02 README input hash mismatch"
        );
        assert!(
            html.contains(hash.as_str()),
            "manual-02 HTML input hash mismatch"
        );
    }

    let matrix: Value = serde_json::from_slice(&matrix_bytes).expect("parse manual-02 matrix");
    let mut counts = [0usize; 4];
    for run in matrix["runs"].as_array().expect("manual-02 runs") {
        let d = run["decision"].as_str().expect("manual-02 decision");
        let class = if d == "Allow" {
            0
        } else if d.starts_with("Deny / ") {
            1
        } else if d.starts_with("Indeterminate / ") {
            2
        } else if d.starts_with("no mediation:") {
            3
        } else {
            panic!("unexpected manual-02 decision")
        };
        counts[class] += 1;
    }
    assert_eq!(counts, [4, 13, 8, 5]);
    assert!(
        note.contains("| **Total** | **4** | **13** | **8** | **5** |"),
        "manual-02 README must report the observed outcome counts"
    );
}

// ---- regression reproductions for the three remaining gate gaps (red before the hardening) ----

#[test]
fn regression_nonzero_execute_with_parseable_json_fails_gate() {
    // A completed run whose n8n execute returned nonzero (even with parseable JSON) must fail.
    let mut m = committed_matrix();
    m["runs"][0]["execute_returncode"] = Value::from(5);
    let problems = matrix_problems(&m);
    assert!(
        problems
            .iter()
            .any(|s| s.contains("execute") && s.contains("nonzero") || s.contains("returncode")),
        "a nonzero execute returncode must be a gate failure; got {problems:?}"
    );
}

#[test]
fn regression_delta_inconsistent_with_before_after_fails_gate() {
    // effects_delta must equal effects_after - effects_before (here Allow/1 passes the existing
    // invariant, but after-before == 2 != 1).
    let mut m = committed_matrix();
    m["runs"][0]["decision"] = Value::from("Allow");
    m["runs"][0]["effects_before"] = Value::from(0);
    m["runs"][0]["effects_after"] = Value::from(2);
    m["runs"][0]["effects_delta"] = Value::from(1);
    let problems = matrix_problems(&m);
    assert!(
        problems
            .iter()
            .any(|s| s.contains("delta") && s.contains("before")),
        "effects_delta inconsistent with before/after must fail the gate; got {problems:?}"
    );
}

#[test]
fn regression_unplanned_scenario_fails_gate() {
    // Rename one cell's scenario to an unplanned value: still 30 distinct cells, but not the
    // planned 3x5x2 product. The distinct-count check alone misses this.
    let mut m = committed_matrix();
    m["runs"][0]["scenario"] = Value::from("bogus_unplanned");
    let problems = matrix_problems(&m);
    assert!(
        problems
            .iter()
            .any(|s| s.contains("planned") || s.contains("unplanned")),
        "an unplanned scenario must fail the gate; got {problems:?}"
    );
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
