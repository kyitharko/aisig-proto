//! Run every labelled case through the chain-aware verifier and the signature-only
//! baseline; write results/case_comparison.{md,json}. Never modifies labels.

use std::fs;

use aisig_proto::experiment::{cases, enforcement_cases, freshness_cases, report, session_cases};

fn main() {
    let labels = cases::load_default().unwrap_or_else(|e| panic!("{e}"));
    let rows = report::run_chain_cases(&labels);
    let queries = report::run_scope_queries(&labels);

    fs::create_dir_all("results").expect("create results/");
    fs::write(
        "results/case_comparison.md",
        report::render_markdown(&rows, &queries),
    )
    .expect("write md");
    let json = serde_json::to_string_pretty(&report::render_json(&rows, &queries)).expect("json");
    fs::write("results/case_comparison.json", json + "\n").expect("write json");

    let s = report::summarize(&rows);
    for (name, t) in [
        ("chain-aware (all)", s.chain_all),
        ("chain-aware (reviewed)", s.chain_reviewed),
        ("signature-only (all)", s.baseline_all),
        ("signature-only (reviewed)", s.baseline_reviewed),
    ] {
        println!(
            "{name:28} cases={:3} false_accept={:3} false_reject={:3} indeterminate={:3} r_vs_i_mismatch={:3} exact={:3}",
            t.cases, t.false_accept, t.false_reject, t.indeterminate, t.class_mismatch, t.exact_match
        );
    }
    let mismatches: Vec<_> = rows.iter().filter(|r| !r.label.matches(&r.chain)).collect();
    for r in &mismatches {
        println!(
            "MISMATCH {} [{}]: expected `{}`, chain-aware returned `{}`",
            r.label.id,
            r.label.label_status,
            r.label.expected_display(),
            r.chain
        );
    }
    let q_bad = queries
        .iter()
        .filter(|q| q.actual != q.label.expected)
        .count();
    println!(
        "scope lookups: {} total, {} mismatches",
        queries.len(),
        q_bad
    );
    println!("wrote results/case_comparison.md and results/case_comparison.json");

    // RQ5 session slice: separate labels, separate output.
    let session_labels =
        cases::load(session_cases::SESSION_CASES_PATH).unwrap_or_else(|e| panic!("{e}"));
    let session_rows = session_cases::run_all(&session_labels);
    fs::write(
        "results/session_cases.md",
        session_cases::render_markdown(&session_rows),
    )
    .expect("write session md");
    let json =
        serde_json::to_string_pretty(&session_cases::render_json(&session_rows)).expect("json");
    fs::write("results/session_cases.json", json + "\n").expect("write session json");
    let ok = session_rows
        .iter()
        .filter(|r| r.actual == r.label.expected)
        .count();
    println!(
        "session slice: {ok}/{} match (all reviewed)",
        session_rows.len()
    );
    for r in session_rows.iter().filter(|r| r.actual != r.label.expected) {
        println!(
            "SESSION MISMATCH {}: expected `{}`, got `{}`",
            r.label.id, r.label.expected, r.actual
        );
    }
    println!("wrote results/session_cases.md and results/session_cases.json");

    // RQ6 enforcement slice: separate labels (all reviewed).
    let enf_labels =
        cases::load(enforcement_cases::ENFORCEMENT_CASES_PATH).unwrap_or_else(|e| panic!("{e}"));
    let enf_rows = enforcement_cases::run_all(&enf_labels);
    fs::write(
        "results/enforcement_cases.md",
        enforcement_cases::render_markdown(&enf_rows),
    )
    .expect("write enforcement md");
    let json =
        serde_json::to_string_pretty(&enforcement_cases::render_json(&enf_rows)).expect("json");
    fs::write("results/enforcement_cases.json", json + "\n").expect("write enforcement json");
    let ok = enf_rows
        .iter()
        .filter(|r| r.actual == r.label.expected)
        .count();
    println!(
        "enforcement slice: {ok}/{} match (all reviewed)",
        enf_rows.len()
    );
    for r in enf_rows.iter().filter(|r| r.actual != r.label.expected) {
        println!(
            "ENFORCEMENT MISMATCH {}: expected `{}`, got `{}`",
            r.label.id, r.label.expected, r.actual
        );
    }
    println!("wrote results/enforcement_cases.md and results/enforcement_cases.json");

    // RQ7 freshness slice: separate labels (all proposed; the oracle for the RQ7 code).
    let fresh_labels =
        cases::load(freshness_cases::FRESHNESS_CASES_PATH).unwrap_or_else(|e| panic!("{e}"));
    let fresh_rows = freshness_cases::run_all(&fresh_labels);
    fs::write(
        "results/freshness_cases.md",
        freshness_cases::render_markdown(&fresh_rows),
    )
    .expect("write freshness md");
    let json =
        serde_json::to_string_pretty(&freshness_cases::render_json(&fresh_rows)).expect("json");
    fs::write("results/freshness_cases.json", json + "\n").expect("write freshness json");
    let ok = fresh_rows
        .iter()
        .filter(|r| r.actual == r.label.expected)
        .count();
    println!(
        "freshness slice: {ok}/{} match (all proposed)",
        fresh_rows.len()
    );
    for r in fresh_rows.iter().filter(|r| r.actual != r.label.expected) {
        println!(
            "FRESHNESS MISMATCH {}: expected `{}`, got `{}`",
            r.label.id, r.label.expected, r.actual
        );
    }
    println!("wrote results/freshness_cases.md and results/freshness_cases.json");
}
