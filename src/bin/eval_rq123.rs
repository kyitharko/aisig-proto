//! Separate RQ1–RQ3 synthetic evaluation. Never edits proposed labels.

use std::fs;

use aisig_proto::experiment::rq123_cases::{labels_cover_mutations, load_default, run_all};

fn main() {
    let labels = load_default().expect("load RQ123 labels");
    assert!(
        labels_cover_mutations(&labels),
        "label/runner coverage mismatch"
    );
    let rows = run_all(&labels);
    let matched = rows.iter().filter(|r| r.match_label).count();
    let reviewed = rows.iter().filter(|r| r.label_status == "reviewed").count();
    let proposed = rows.iter().filter(|r| r.label_status == "proposed").count();
    fs::create_dir_all("results").expect("results directory");
    fs::write(
        "results/rq123_cases.json",
        format!("{}\n", serde_json::to_string_pretty(&rows).unwrap()),
    )
    .expect("RQ123 JSON");
    let mut report = format!(
        "# RQ1–RQ3 synthetic authority slice\n\n\
         **Status:** {reviewed} reviewed labels; {proposed} proposed. RQ1 manual vetting and asset namespace are assumptions.\n\
         Asset hashes bind a declared snapshot; no live asset-control proof or tool effect.\n\n\
         | ID | Mutation | Expected | Actual | Match |\n| --- | --- | --- | --- | --- |\n",
    );
    for row in &rows {
        use std::fmt::Write;
        writeln!(
            report,
            "| {} | {} | {} | {} | {} |",
            row.id, row.mutation, row.expected, row.actual, row.match_label
        )
        .unwrap();
    }
    fs::write("results/rq123_cases.md", report).expect("RQ123 markdown");
    println!(
        "RQ1–RQ3 synthetic slice: {matched}/{} labels match ({reviewed} reviewed, {proposed} proposed)",
        rows.len(),
    );
    if matched != rows.len() {
        std::process::exit(1);
    }
}
