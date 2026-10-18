//! Deterministic tests for the demo controller core (`aisig_proto::demo`). Fake, fixed model
//! proposals — no model, no network. Each asserts the provider decision and, crucially, that the
//! modeled effect sink grows by exactly 1 on `Allow` and exactly 0 on every non-Allow.

use aisig_proto::demo::{run, Proposal};

fn prop(
    op: Option<&str>,
    target: Option<&str>,
    class: Option<&str>,
    refusal: Option<&str>,
) -> Proposal {
    Proposal {
        operation: op.map(str::to_owned),
        target: target.map(str::to_owned),
        claimed_class: class.map(str::to_owned),
        refusal: refusal.map(str::to_owned),
    }
}

fn call(scenario: &str, p: Proposal) -> (String, usize) {
    let r = run(
        "run-test",
        scenario,
        &p,
        Some("test"),
        Some("deterministic"),
        Some("tool_call"),
    )
    .expect("known scenario");
    // The core invariant: exactly one modeled effect iff Allow, zero otherwise.
    if r.decision == "Allow" {
        assert_eq!(
            r.effects_delta, 1,
            "Allow must record exactly one effect: {}",
            r.decision
        );
    } else {
        assert_eq!(
            r.effects_delta, 0,
            "non-Allow must record zero effects: {}",
            r.decision
        );
    }
    (r.decision, r.effects_delta)
}

const REPORTS: &str = "web:https://app.acme.test:443/app/reports";
const ADMIN: &str = "web:https://app.acme.test:443/app/admin";
const BILLING: &str = "db:cluster1/main/billing";

#[test]
fn allow_in_scope_web_get() {
    let (d, delta) = call("fresh", prop(Some("web.get"), Some(REPORTS), None, None));
    assert_eq!(d, "Allow");
    assert_eq!(delta, 1);
}

#[test]
fn false_claimed_class_is_ignored_still_allow() {
    // The model's claimed_class is audit-only; the table classifies web.get as read-only.
    let (d, _) = call(
        "fresh",
        prop(
            Some("web.get"),
            Some(REPORTS),
            Some("data_modification"),
            None,
        ),
    );
    assert_eq!(d, "Allow");
}

#[test]
fn deny_excluded_target() {
    let (d, _) = call("fresh", prop(Some("web.get"), Some(ADMIN), None, None));
    assert_eq!(d, "Deny / scope / DenyTargetExcluded");
}

#[test]
fn deny_out_of_scope_target() {
    let (d, _) = call(
        "fresh",
        prop(
            Some("web.get"),
            Some("web:https://app.acme.test:443/other"),
            None,
            None,
        ),
    );
    assert_eq!(d, "Deny / scope / DenyTargetOutOfScope");
}

#[test]
fn deny_class_not_permitted() {
    // db.write is DataModification; the enf grant does not permit it.
    let (d, _) = call("fresh", prop(Some("db.write"), Some(BILLING), None, None));
    assert_eq!(d, "Deny / class / DenyTestClassNotPermitted");
}

#[test]
fn deny_unknown_operation() {
    let (d, _) = call("fresh", prop(Some("fs.delete"), Some(REPORTS), None, None));
    assert_eq!(d, "Deny / classify / DenyUnknownOperation");
}

#[test]
fn deny_unbounded_footprint() {
    let (d, _) = call(
        "fresh",
        prop(
            Some("web.flood"),
            Some("web:https://app.acme.test:443/app"),
            None,
            None,
        ),
    );
    assert_eq!(d, "Deny / effects / DenyUnboundedSecondaryEffect");
}

#[test]
fn deny_noncanonical_target_uppercase_host() {
    let (d, _) = call(
        "fresh",
        prop(
            Some("web.get"),
            Some("web:https://APP.acme.test:443/app"),
            None,
            None,
        ),
    );
    assert_eq!(d, "Deny / validate / DenyNoncanonicalTarget");
}

#[test]
fn deny_malformed_target_garbage() {
    let (d, _) = call(
        "fresh",
        prop(Some("web.get"), Some("not-an-asset"), None, None),
    );
    assert_eq!(d, "Deny / validate / DenyNoncanonicalTarget");
}

#[test]
fn deny_expired_session() {
    let (d, _) = call(
        "expired_session",
        prop(Some("web.get"), Some(REPORTS), None, None),
    );
    assert_eq!(d, "Deny / expiry / DenySessionExpired");
}

#[test]
fn deny_revoked_grant() {
    let (d, _) = call(
        "revoked_grant",
        prop(Some("web.get"), Some(REPORTS), None, None),
    );
    assert_eq!(d, "Deny / chain / ChainRejected(Reject / X / Revoked{G})");
}

#[test]
fn indeterminate_stale_status() {
    let (d, _) = call(
        "stale_status",
        prop(Some("web.get"), Some(REPORTS), None, None),
    );
    assert_eq!(
        d,
        "Indeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusStale)"
    );
}

#[test]
fn indeterminate_unavailable_status() {
    let (d, _) = call(
        "unavailable_status",
        prop(Some("web.get"), Some(REPORTS), None, None),
    );
    assert_eq!(
        d,
        "Indeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusUnavailable)"
    );
}

#[test]
fn refusal_is_not_mediated() {
    let r = run(
        "run-test",
        "fresh",
        &prop(None, None, None, Some("I won't")),
        None,
        None,
        Some("refusal"),
    )
    .expect("known scenario");
    assert_eq!(r.parse_status, "refusal");
    assert_eq!(r.effects_delta, 0);
}

#[test]
fn empty_proposal_is_a_no_call_not_a_refusal() {
    // No operation and no explicit refusal (e.g. empty model content) is a no-call, which the
    // provider must never record as a refusal, and which produces no effect.
    let r = run(
        "run-test",
        "fresh",
        &prop(None, None, None, None),
        None,
        None,
        Some("no_call"),
    )
    .expect("known scenario");
    assert_eq!(r.parse_status, "no_call");
    assert_eq!(r.effects_delta, 0);
}

#[test]
fn unknown_scenario_is_an_error() {
    assert!(run(
        "run-test",
        "nope",
        &prop(Some("web.get"), Some(REPORTS), None, None),
        None,
        None,
        None,
    )
    .is_err());
}

#[test]
fn oversized_operation_is_rejected_without_effect() {
    let big = "x".repeat(10_000);
    assert!(run(
        "run-test",
        "fresh",
        &prop(Some(&big), Some(REPORTS), None, None),
        None,
        None,
        None,
    )
    .is_err());
}
