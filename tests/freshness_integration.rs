//! RQ7 freshness-slice test gate (review finding 4). Loads every freshness label, checks a
//! one-to-one mapping with the runners, and requires exact outcomes — so `cargo test` gates
//! the 34 freshness labels (not merely the two freshness unit tests).

use std::collections::HashSet;

use aisig_proto::experiment::cases;
use aisig_proto::experiment::freshness_cases::{self, FRESHNESS_CASES_PATH, FRESHNESS_CASE_IDS};

#[test]
fn freshness_labels_map_one_to_one_to_runners() {
    let labels = cases::load(FRESHNESS_CASES_PATH).expect("load freshness labels");

    // No duplicate label ids.
    let mut seen = HashSet::new();
    for l in &labels {
        assert!(seen.insert(l.id.as_str()), "duplicate freshness label {}", l.id);
    }

    // The label set and the runner-id set are exactly equal (one-to-one).
    let label_ids: HashSet<&str> = labels.iter().map(|l| l.id.as_str()).collect();
    let runner_ids: HashSet<&str> = FRESHNESS_CASE_IDS.iter().copied().collect();
    let only_labels: Vec<_> = label_ids.difference(&runner_ids).collect();
    let only_runners: Vec<_> = runner_ids.difference(&label_ids).collect();
    assert!(
        only_labels.is_empty() && only_runners.is_empty(),
        "freshness labels and runners must be one-to-one; labels-only={only_labels:?}, runners-only={only_runners:?}"
    );

    // Every runner id resolves to an actual runner.
    for id in FRESHNESS_CASE_IDS {
        assert!(freshness_cases::run(id).is_some(), "no runner for {id}");
    }
}

#[test]
fn every_freshness_label_matches_its_runner_exactly() {
    let labels = cases::load(FRESHNESS_CASES_PATH).expect("load freshness labels");
    let mut mismatches = Vec::new();
    for l in &labels {
        let actual = freshness_cases::run(&l.id).unwrap_or_else(|| format!("no runner for {}", l.id));
        if actual != l.expected {
            mismatches.push(format!(
                "{}: expected `{}`, got `{}`",
                l.id, l.expected, actual
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "freshness label mismatches ({}):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
