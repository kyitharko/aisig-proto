//! The chain-aware verifier must agree exactly (class, stage, reason) with every label in
//! tests/cases/reviewed_cases.toml. Labels are literal data; nothing here computes them.

use std::collections::BTreeSet;

use aisig_proto::decision::DecisionClass;
use aisig_proto::experiment::cases::{load_default, CaseLabel};
use aisig_proto::experiment::fixture::Scenario;
use aisig_proto::experiment::mutations::CHAIN_CASE_IDS;
use aisig_proto::experiment::report::{run_chain_cases, run_scope_queries};

fn labels() -> Vec<CaseLabel> {
    load_default().expect("labels file loads")
}

#[test]
fn every_label_has_a_mutation_and_vice_versa() {
    let labelled: BTreeSet<String> = labels()
        .into_iter()
        .filter(|l| l.is_chain())
        .map(|l| l.id)
        .collect();
    let mutated: BTreeSet<String> = CHAIN_CASE_IDS.iter().map(|s| s.to_string()).collect();
    assert_eq!(labelled, mutated);
    assert_eq!(labelled.len(), 93);
}

#[test]
fn label_counts_match_experiment_doc() {
    let ls = labels();
    let chain: Vec<_> = ls.iter().filter(|l| l.is_chain()).collect();
    let count = |c| {
        chain
            .iter()
            .filter(|l| l.expected_class() == Some(c))
            .count()
    };
    assert_eq!(count(DecisionClass::Accept), 11);
    assert_eq!(count(DecisionClass::Reject), 71);
    assert_eq!(count(DecisionClass::Indeterminate), 11);
    assert_eq!(
        chain
            .iter()
            .filter(|l| l.label_status == "proposed")
            .count(),
        0
    );
    let kind = |k: &str| ls.iter().filter(|l| l.kind == k).count();
    assert_eq!(kind("exact_node_query"), 11);
    assert_eq!(kind("subtree_query"), 4);
}

#[test]
fn chain_verifier_matches_labels() {
    let rows = run_chain_cases(&labels());
    let failures: Vec<String> = rows
        .iter()
        .filter(|r| !r.label.matches(&r.chain))
        .map(|r| {
            format!(
                "{} [{}]: expected `{}`, got `{}`",
                r.label.id,
                r.label.label_status,
                r.label.expected_display(),
                r.chain
            )
        })
        .collect();
    assert!(
        failures.is_empty(),
        "label mismatches:\n{}",
        failures.join("\n")
    );
}

#[test]
fn scope_queries_match_labels() {
    let rows = run_scope_queries(&labels());
    let failures: Vec<String> = rows
        .iter()
        .filter(|q| q.actual != q.label.expected)
        .map(|q| {
            format!(
                "{}: expected {}, got {}",
                q.label.id, q.label.expected, q.actual
            )
        })
        .collect();
    assert!(
        failures.is_empty(),
        "scope query mismatches:\n{}",
        failures.join("\n")
    );
}

#[test]
fn root_slot_contents_never_change_the_chain_decision() {
    let base = Scenario::base();
    let prepared = base.prepare();
    let expected = prepared.run();
    let variants: Vec<Option<Vec<u8>>> = vec![
        None,
        Some(Vec::new()),
        Some(b"{}".to_vec()),
        Some(b"\xff\xfe not json".to_vec()),
        base.build().grant.clone(),
    ];
    for root in variants {
        let mut bundle = base.build();
        bundle.root = root;
        assert_eq!(prepared.verifier().verify(&bundle), expected);
    }
}
