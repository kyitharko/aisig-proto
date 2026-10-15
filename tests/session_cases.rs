//! RQ5 session-slice cases must match tests/cases/session_cases.toml exactly.
//! Labels are literal data written before the implementation; all owner-reviewed.

use std::collections::BTreeSet;

use aisig_proto::experiment::cases::load;
use aisig_proto::experiment::session_cases::{run_all, SESSION_CASES_PATH, SESSION_CASE_IDS};

#[test]
fn every_session_label_has_a_runner_and_vice_versa() {
    let labels = load(SESSION_CASES_PATH).expect("session labels load");
    let labelled: BTreeSet<String> = labels.iter().map(|l| l.id.clone()).collect();
    let runnable: BTreeSet<String> = SESSION_CASE_IDS.iter().map(|s| s.to_string()).collect();
    assert_eq!(labelled, runnable);
    assert_eq!(labels.len(), 29);
    // SS01-SS24 and SI01-SI05 all reviewed.
    assert_eq!(
        labels
            .iter()
            .filter(|l| l.label_status == "reviewed")
            .count(),
        29
    );
    assert_eq!(
        labels
            .iter()
            .filter(|l| l.label_status == "proposed")
            .count(),
        0
    );
}

#[test]
fn session_outcomes_match_labels() {
    let labels = load(SESSION_CASES_PATH).expect("session labels load");
    let failures: Vec<String> = run_all(&labels)
        .into_iter()
        .filter(|r| r.actual != r.label.expected)
        .map(|r| {
            format!(
                "{}: expected `{}`, got `{}`",
                r.label.id, r.label.expected, r.actual
            )
        })
        .collect();
    assert!(
        failures.is_empty(),
        "session mismatches:\n{}",
        failures.join("\n")
    );
}
