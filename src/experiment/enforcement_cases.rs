//! RQ6 enforcement-slice cases (docs/experiment.md §12). Each case builds the scenario it
//! describes, runs one mediation, and returns `<decision> effects=<n>` where n is the
//! growth of the effect sink (so the zero-effect-after-denial property is measured).
//! Expected values live only in tests/cases/enforcement_cases.toml.

use serde_json::{json, Value};

use crate::codec::canonical_json;
use crate::decision::Slot;
use crate::enforcement::{
    EffectSink, InMemorySessionAuthStore, Mediate, MediationRequest, Mediator,
};
use crate::evidence::ObjStatus;
use crate::model::TestClass;
use crate::session::{
    encode_proof, InMemoryChallengeStore, IssueOutcome, OsRandom, SessionAuthorization,
    SessionDecision, SessionService, RESPONSE_TAG,
};

use super::cases::CaseLabel;
use super::fixture::{asset, del, put, secret, set, PostOp, Scenario};

const SESSION: &str = "sess-p-0001";
const MED_NOW: (&str, i64) = ("2026-10-15T10:30:00Z", 2);

pub const ENFORCEMENT_CASES_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/cases/enforcement_cases.toml"
);

pub const ENFORCEMENT_CASE_IDS: &[&str] = &[
    "EE01", "EE02", "EE03", "EE04", "EE05", "EE06", "EE07", "EE08", "EE09", "EE10", "EE11", "EE12",
    "EE13", "EE14", "EE15", "EE16", "EE17", "EE18", "EE19", "EE20", "EE21", "EE22", "EE23", "EE24",
    "EE25", "EE26", "EE27", "EE28",
];

/// Base enforcement grant: adds read_only_data_access to the base grant's test scope
/// (within D_U's ceiling), so web.get and db.read are in class scope.
fn enf_scenario() -> Scenario {
    let mut s = Scenario::base();
    put(
        s.grant(),
        "test_scope",
        json!({
            "classes": set(vec![json!("injection_testing"), json!("read_only_data_access"), json!("recon")]),
            "kind": "classes"
        }),
    );
    s
}

/// Obtain a genuine SessionAuthorization for `SESSION` by issuing and redeeming at 10:00Z
/// (only `redeem` constructs one). The returned auth is durable server-side state.
fn auth_for(scn: &Scenario) -> SessionAuthorization {
    let store = InMemoryChallengeStore::default();
    let mut s = scn.clone();
    s.set_clock("2026-10-15T10:00:00Z", 2);
    let prepared = s.prepare();
    let svc = SessionService::new(prepared.verifier(), &store, &OsRandom);
    let IssueOutcome::Issued(c) = svc.issue(&prepared.bundle, SESSION) else {
        panic!("enforcement fixture issuance must succeed");
    };
    let c = *c;
    let proof = encode_proof(
        &c.challenge_id,
        &secret("tester-1").sign(RESPONSE_TAG, &c.wire_bytes()),
    );
    match svc.redeem(&prepared.bundle, SESSION, Some(&proof)) {
        SessionDecision::Accept(a) => *a,
        other => panic!("enforcement fixture redemption must accept, got {other}"),
    }
}

fn target_wire(short: &str) -> Vec<u8> {
    canonical_json(&asset(short)).expect("asset is canonicalizable")
}

fn web_wire(path: &str) -> Vec<u8> {
    target_wire(&format!("web:https://app.acme.test:443{path}"))
}

#[allow(clippy::too_many_arguments)]
fn mediate(
    scn: &Scenario,
    now: Option<(&str, i64)>,
    auth_ref: &str,
    auth: Option<&SessionAuthorization>,
    store_down: bool,
    op: &str,
    target_wire: Vec<u8>,
    claim: Option<TestClass>,
) -> String {
    let mut scn = scn.clone();
    match now {
        Some((t, e)) => scn.set_clock(t, e),
        None => scn.clock.reading = None,
    }
    let prepared = scn.prepare();
    let store = InMemorySessionAuthStore::default();
    if let Some(a) = auth {
        store.insert(SESSION, a.clone());
    }
    store.set_unavailable(store_down);
    let sink = EffectSink::new();
    let med = Mediator {
        chain: prepared.verifier(),
        sessions: &store,
        sink: &sink,
    };
    let req = MediationRequest {
        bundle: prepared.bundle.clone(),
        operation: op.to_owned(),
        target_wire,
        claimed_class: claim,
    };
    let before = sink.len();
    let decision = med.mediate(auth_ref, &req);
    let delta = sink.len() - before;
    // A non-Allow must never have appended an effect.
    if !matches!(decision, Mediate::Allow(_)) {
        assert_eq!(delta, 0, "non-Allow performed {delta} effects: {decision}");
    }
    format!("{decision} effects={delta}")
}

/// Run enforcement case `id`; `None` for an unknown id.
pub fn run(id: &str) -> Option<String> {
    let s0 = enf_scenario();
    let a0 = auth_for(&s0);
    let some = Some(MED_NOW);
    let out = match id {
        "EE01" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.get",
            web_wire("/app/reports"),
            None,
        ),
        "EE02" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.head",
            web_wire("/app"),
            None,
        ),
        "EE03" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.injection_probe",
            web_wire("/app/reports"),
            None,
        ),
        "EE04" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "db.read",
            target_wire("db:cluster1/main/billing"),
            None,
        ),
        "EE05" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.get",
            web_wire("/app/admin"),
            None,
        ),
        "EE06" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.get",
            web_wire("/app/admin/users/7"),
            None,
        ),
        "EE07" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.get",
            web_wire("/app/private/report"),
            None,
        ),
        "EE08" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.get",
            web_wire("/other"),
            None,
        ),
        "EE09" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.get",
            target_wire("web:https://shop.globex.test:443/"),
            None,
        ),
        "EE10" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "db.write",
            target_wire("db:cluster1/main/billing"),
            None,
        ),
        "EE11" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.auth_probe",
            web_wire("/app/reports"),
            None,
        ),
        "EE12" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "db.write",
            target_wire("db:cluster1/main/billing"),
            Some(TestClass::Recon),
        ),
        "EE13" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "fs.delete",
            web_wire("/app"),
            None,
        ),
        "EE14" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "db.read",
            web_wire("/app/reports"),
            None,
        ),
        "EE15" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.flood",
            web_wire("/app"),
            None,
        ),
        "EE16" => mediate(
            &s0,
            Some(("2026-10-15T11:00:00Z", 0)),
            SESSION,
            Some(&a0),
            false,
            "web.get",
            web_wire("/app/reports"),
            None,
        ),
        "EE17" => mediate(
            &s0,
            some,
            "sess-p-9999",
            Some(&a0),
            false,
            "web.get",
            web_wire("/app/reports"),
            None,
        ),
        "EE18" => {
            let mut s2 = enf_scenario();
            put(s2.grant(), "engagement_id", json!("eng-acme-2026-10-15-02"));
            // auth is for the base enforcement G (a0); the bundle presents the re-signed G2.
            mediate(
                &s2,
                some,
                SESSION,
                Some(&a0),
                false,
                "web.get",
                web_wire("/app/reports"),
                None,
            )
        }
        "EE19" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            true,
            "web.get",
            web_wire("/app/reports"),
            None,
        ),
        "EE20" => {
            let mut sd = s0.clone();
            sd.status.unavailable = true;
            mediate(
                &sd,
                some,
                SESSION,
                Some(&a0),
                false,
                "web.get",
                web_wire("/app/reports"),
                None,
            )
        }
        "EE21" => mediate(
            &s0,
            None,
            SESSION,
            Some(&a0),
            false,
            "web.get",
            web_wire("/app/reports"),
            None,
        ),
        "EE22" => {
            let mut sa = s0.clone();
            let mut altered: Value = sa.grant().clone();
            put(
                &mut altered,
                "test_scope",
                json!({"classes": ["auth_testing"], "kind": "classes"}),
            );
            sa.post
                .push(PostOp::ReplacePayloadKeepSig(Slot::Grant, altered));
            mediate(
                &sa,
                some,
                SESSION,
                Some(&a0),
                false,
                "web.get",
                web_wire("/app/reports"),
                None,
            )
        }
        "EE23" => {
            let mut sr = enf_scenario();
            put(
                sr.grant(),
                "test_scope",
                json!({"classes": ["recon"], "kind": "classes"}),
            );
            let ar = auth_for(&sr);
            mediate(
                &sr,
                some,
                SESSION,
                Some(&ar),
                false,
                "web.get",
                web_wire("/app/reports"),
                None,
            )
        }
        "EE24" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.injection_probe",
            web_wire("/app"),
            None,
        ),
        "EE25" => mediate(
            &s0,
            some,
            SESSION,
            Some(&a0),
            false,
            "web.get",
            target_wire("web:https://APP.acme.test:443/app"),
            None,
        ),
        "EE26" => {
            let mut sv = s0.clone();
            sv.status.grant = Some(ObjStatus::Revoked);
            mediate(
                &sv,
                some,
                SESSION,
                Some(&a0),
                false,
                "web.get",
                web_wire("/app/reports"),
                None,
            )
        }
        "EE27" => {
            let mut sb = enf_scenario();
            put(
                sb.grant(),
                "targets",
                set(vec![asset("db:cluster1/main/billing")]),
            );
            del(sb.grant(), "exclusions");
            put(
                sb.grant(),
                "test_scope",
                json!({"classes": ["read_only_data_access"], "kind": "classes"}),
            );
            let ab = auth_for(&sb);
            mediate(
                &sb,
                some,
                SESSION,
                Some(&ab),
                false,
                "db.write",
                target_wire("db:cluster1/main"),
                None,
            )
        }
        "EE28" => mediate(
            &s0,
            Some(("2026-10-15T10:30:00Z", -5)),
            SESSION,
            Some(&a0),
            false,
            "web.get",
            web_wire("/app/reports"),
            None,
        ),
        _ => return None,
    };
    Some(out)
}

pub struct EnforcementRow {
    pub label: CaseLabel,
    pub actual: String,
}

pub fn run_all(labels: &[CaseLabel]) -> Vec<EnforcementRow> {
    labels
        .iter()
        .map(|l| EnforcementRow {
            label: l.clone(),
            actual: run(&l.id).unwrap_or_else(|| format!("no runner for {}", l.id)),
        })
        .collect()
}

pub fn render_markdown(rows: &[EnforcementRow]) -> String {
    let matched = rows.iter().filter(|r| r.actual == r.label.expected).count();
    let mut out = String::from("# RQ6 enforcement-slice cases (generated)\n\n");
    out.push_str("Generated by `cargo run --release --bin eval`. Labels from ");
    out.push_str("`tests/cases/enforcement_cases.toml` (27 reviewed, EE28 proposed). ");
    out.push_str("Separate from the chain, lookup and session results.\n\n");
    out.push_str(&format!("Matched {matched}/{} labels.\n\n", rows.len()));
    out.push_str(
        "| ID | Label status | Expected | Actual | Match |\n| --- | --- | --- | --- | --- |\n",
    );
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | `{}` | `{}` | {} |\n",
            r.label.id,
            r.label.label_status,
            r.label.expected,
            r.actual,
            if r.actual == r.label.expected {
                "yes"
            } else {
                "**NO**"
            }
        ));
    }
    out
}

pub fn render_json(rows: &[EnforcementRow]) -> Value {
    json!({
        "matched": rows.iter().filter(|r| r.actual == r.label.expected).count(),
        "total": rows.len(),
        "cases": rows.iter().map(|r| json!({
            "id": r.label.id,
            "label_status": r.label.label_status,
            "expected": r.label.expected,
            "actual": r.actual,
            "match": r.actual == r.label.expected,
        })).collect::<Vec<_>>(),
    })
}

/// Reproduction evidence (RQ6), capturing the behaviour BEFORE the fix. These assertions
/// document the bugs at this commit and are rewritten to assert the fixed behaviour in the
/// fix commit (git history keeps both). See docs/report.md.
#[cfg(test)]
mod repro {
    use super::super::fixture::{ts, P_AUD};
    use super::*;
    use crate::enforcement::{
        EffectSink, InMemorySessionAuthStore, Mediate, MediationRequest, Mediator,
    };
    use crate::evidence::{ClockReading, SequenceClock};
    use crate::verifier::{ChainVerifier, Evidence};

    fn rd(t: &str, e: i64) -> Option<ClockReading> {
        Some(ClockReading {
            now: ts(t),
            epsilon: e,
        })
    }

    fn mediate_seq(seq: SequenceClock) -> Mediate {
        let s = enf_scenario();
        let auth = auth_for(&s);
        let store = InMemorySessionAuthStore::default();
        store.insert(SESSION, auth);
        let sink = EffectSink::new();
        let status = s.status_source();
        let ev = Evidence {
            registry: &s.registry,
            bindings: &s.bindings,
            clock: &seq,
            status: &status,
        };
        let med = Mediator {
            chain: ChainVerifier {
                audience: P_AUD,
                evidence: ev,
            },
            sessions: &store,
            sink: &sink,
        };
        let req = MediationRequest {
            bundle: s.build(),
            operation: "web.get".to_owned(),
            target_wire: web_wire("/app/reports"),
            claimed_class: None,
        };
        med.mediate(SESSION, &req)
    }

    // FIXED (was BUG 1a): the clock is read once; a later None at perform no longer
    // exists, so there is no panic. A sequence whose 3rd reading is None is still Allowed,
    // reading only the first entry.
    #[test]
    fn perform_does_not_reread_clock_no_panic() {
        let seq = SequenceClock::new(vec![
            rd("2026-10-15T10:30:00Z", 2),
            rd("2026-10-15T10:30:00Z", 2),
            None,
        ]);
        match mediate_seq(seq) {
            Mediate::Allow(r) => assert_eq!(r.performed_at(), ts("2026-10-15T10:30:00Z")),
            other => panic!("expected Allow from the single snapshot, got {other}"),
        }
    }

    // FIXED (was BUG 1b): performed_at is the single decision-time snapshot (the first
    // reading), never a later/stale clock value.
    #[test]
    fn performed_at_is_the_decision_snapshot_not_a_later_read() {
        let seq = SequenceClock::new(vec![
            rd("2026-10-15T10:30:00Z", 2),
            rd("2026-10-15T23:00:00Z", 0), // would be used by the old chain-time read
            rd("2026-10-15T23:00:00Z", 0), // would be used by the old perform read
        ]);
        match mediate_seq(seq) {
            Mediate::Allow(r) => assert_eq!(r.performed_at(), ts("2026-10-15T10:30:00Z")),
            other => panic!("expected Allow stamped with the snapshot, got {other}"),
        }
    }

    // FIXED (was BUG 2): the sink's append is module-private; an external caller cannot
    // call record on a cloned receipt. Only one mediation -> exactly one effect. (A
    // compile_fail doctest in src/enforcement.rs shows `sink.record(..)` does not compile.)
    #[test]
    fn external_caller_cannot_append_a_cloned_receipt() {
        let s = enf_scenario();
        let auth = auth_for(&s);
        let store = InMemorySessionAuthStore::default();
        store.insert(SESSION, auth);
        let sink = EffectSink::new();
        let mut s2 = s.clone();
        s2.set_clock("2026-10-15T10:30:00Z", 2);
        let prepared = s2.prepare();
        let med = Mediator {
            chain: prepared.verifier(),
            sessions: &store,
            sink: &sink,
        };
        let req = MediationRequest {
            bundle: prepared.bundle.clone(),
            operation: "web.get".to_owned(),
            target_wire: web_wire("/app/reports"),
            claimed_class: None,
        };
        let before = sink.len();
        let _cloned_receipt = match med.mediate(SESSION, &req) {
            Mediate::Allow(r) => (*r).clone(),
            other => panic!("expected Allow, got {other}"),
        };
        // Holding the cloned receipt grants no way to append; only read access exists.
        assert_eq!(
            sink.len(),
            before + 1,
            "exactly one effect from one mediation"
        );
        assert_eq!(sink.receipts().len(), before + 1);
    }
}
