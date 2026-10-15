//! Run every labelled case through the chain-aware verifier and the signature-only
//! baseline; write results/case_comparison.{md,json}. Never modifies labels.

use std::fs;

use aisig_proto::experiment::{cases, report, session_cases};

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
        "session slice: {ok}/{} match (labels reviewed)",
        session_rows.len()
    );
    for r in session_rows.iter().filter(|r| r.actual != r.label.expected) {
        println!(
            "SESSION MISMATCH {}: expected `{}`, got `{}`",
            r.label.id, r.label.expected, r.actual
        );
    }
    println!("wrote results/session_cases.md and results/session_cases.json");
}
