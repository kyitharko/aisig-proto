use aisig_proto::experiment::rq123_cases::{labels_cover_mutations, load_default, run_all};

#[test]
fn every_label_has_exactly_one_runner_and_review_status_is_explicit() {
    let labels = load_default().unwrap();
    assert!(labels_cover_mutations(&labels));
    assert_eq!(labels.len(), 25);
    assert_eq!(
        labels
            .iter()
            .filter(|l| l.label_status == "reviewed")
            .count(),
        24
    );
    assert_eq!(
        labels
            .iter()
            .filter(|l| l.label_status == "proposed")
            .map(|l| l.id.as_str())
            .collect::<Vec<_>>(),
        vec!["AA25"]
    );
}

#[test]
fn every_outcome_matches_its_preregistered_label() {
    let rows = run_all(&load_default().unwrap());
    for row in rows {
        assert!(
            row.match_label,
            "{} {}: expected {}, got {}",
            row.id, row.mutation, row.expected, row.actual
        );
    }
}
