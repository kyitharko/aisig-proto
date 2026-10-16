//! RQ8 Q1 privacy-slice test gate. Loads every proposed observation, checks a one-to-one
//! mapping with the runners, and requires exact outcomes in `cargo test`.

use std::collections::HashSet;

use aisig_proto::experiment::cases;
use aisig_proto::experiment::rq8_privacy::{self, RQ8_PRIVACY_CASES_PATH, RQ8_PRIVACY_CASE_IDS};

#[test]
fn rq8_privacy_labels_map_one_to_one_to_runners() {
    let labels = cases::load(RQ8_PRIVACY_CASES_PATH).expect("load rq8 privacy labels");

    let mut seen = HashSet::new();
    for l in &labels {
        assert!(
            seen.insert(l.id.as_str()),
            "duplicate rq8 privacy label {}",
            l.id
        );
    }

    let label_ids: HashSet<&str> = labels.iter().map(|l| l.id.as_str()).collect();
    let runner_ids: HashSet<&str> = RQ8_PRIVACY_CASE_IDS.iter().copied().collect();
    let only_labels: Vec<_> = label_ids.difference(&runner_ids).collect();
    let only_runners: Vec<_> = runner_ids.difference(&label_ids).collect();
    assert!(
        only_labels.is_empty() && only_runners.is_empty(),
        "rq8 privacy labels and runners must be one-to-one; labels-only={only_labels:?}, runners-only={only_runners:?}"
    );

    for id in RQ8_PRIVACY_CASE_IDS {
        assert!(rq8_privacy::run(id).is_some(), "no runner for {id}");
    }
}

#[test]
fn every_rq8_privacy_label_matches_its_runner_exactly() {
    let labels = cases::load(RQ8_PRIVACY_CASES_PATH).expect("load rq8 privacy labels");
    let mut mismatches = Vec::new();
    for l in &labels {
        let actual = rq8_privacy::run(&l.id).unwrap_or_else(|| format!("no runner for {}", l.id));
        if actual != l.expected {
            mismatches.push(format!(
                "{}: expected `{}`, got `{}`",
                l.id, l.expected, actual
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "rq8 privacy observation mismatches ({}):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
