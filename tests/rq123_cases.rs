use aisig_proto::experiment::rq123_cases::{labels_cover_mutations, load_default, run_all};

#[test]
fn every_proposed_label_has_exactly_one_runner() {
    let labels = load_default().unwrap();
    assert!(labels_cover_mutations(&labels));
    assert_eq!(labels.len(), 24);
    assert!(labels.iter().all(|l| l.label_status == "proposed"));
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
