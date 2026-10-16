//! RQ6 enforcement cases must match tests/cases/enforcement_cases.toml (EE01–EE26 reviewed,
//! EE27 proposed), plus trust-boundary checks. Labels are literal data written before the
//! implementation.

use std::collections::BTreeSet;

use aisig_proto::experiment::cases::load;
use aisig_proto::experiment::enforcement_cases::{
    render_markdown, run, run_all, ENFORCEMENT_CASES_PATH, ENFORCEMENT_CASE_IDS,
};

fn labels() -> Vec<aisig_proto::experiment::cases::CaseLabel> {
    load(ENFORCEMENT_CASES_PATH).expect("enforcement labels load")
}

#[test]
fn every_label_has_a_runner_and_vice_versa() {
    let ls = labels();
    let labelled: BTreeSet<String> = ls.iter().map(|l| l.id.clone()).collect();
    let runnable: BTreeSet<String> = ENFORCEMENT_CASE_IDS.iter().map(|s| s.to_string()).collect();
    assert_eq!(labelled, runnable);
    assert_eq!(ls.len(), 28);
    assert_eq!(
        ls.iter().filter(|l| l.label_status == "reviewed").count(),
        28
    );
    assert_eq!(
        ls.iter().filter(|l| l.label_status == "proposed").count(),
        0
    );
}

#[test]
fn enforcement_outcomes_match_labels() {
    let failures: Vec<String> = run_all(&labels())
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
        "enforcement mismatches:\n{}",
        failures.join("\n")
    );
}

/// Every non-Allow leaves the sink empty; the one Allow family carries effects=1. The
/// `effects=N` suffix is produced by measuring sink growth, so this is a real check.
#[test]
fn only_allow_performs_an_effect() {
    for id in ENFORCEMENT_CASE_IDS {
        let out = run(id).unwrap();
        if out.starts_with("Allow") {
            assert!(out.ends_with("effects=1"), "{id}: {out}");
        } else {
            assert!(out.ends_with("effects=0"), "{id}: {out}");
        }
    }
}

/// A DB parent subtree is PartiallyAllowed with no explicit exclusion (grant targets only
/// the billing child). This is the case that motivated the rename to
/// DenySubtreePartiallyAllowed (EE27).
#[test]
fn db_parent_subtree_partially_allowed_without_exclusion() {
    let out = run("EE27").unwrap();
    assert_eq!(out, "Deny / scope / DenySubtreePartiallyAllowed effects=0");
}

/// A non-canonical target presented as wire bytes is rejected at the validate stage; it
/// cannot reach scope or perform. Combined with the compile_fail doctest in
/// `src/enforcement.rs` (no `AssetRef` target field exists), a pre-built non-canonical
/// `AssetRef` cannot enter mediation.
#[test]
fn noncanonical_target_denied_at_validate() {
    let out = run("EE25").unwrap();
    assert_eq!(out, "Deny / validate / DenyNoncanonicalTarget effects=0");
}

#[test]
fn markdown_report_renders() {
    let md = render_markdown(&run_all(&labels()));
    assert!(md.contains("RQ6 enforcement-slice cases"));
}
