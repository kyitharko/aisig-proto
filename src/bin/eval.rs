//! Run every labelled case through the chain-aware verifier and the signature-only
//! baseline; write results/case_comparison.{md,json}. Never modifies labels.

use std::fs;

use aisig_proto::experiment::{cases, report};

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
        "scope queries: {} total, {} mismatches",
        queries.len(),
        q_bad
    );
    println!("wrote results/case_comparison.md and results/case_comparison.json");
}
