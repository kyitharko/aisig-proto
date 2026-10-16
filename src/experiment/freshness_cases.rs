//! RQ7 freshness-slice cases (docs/freshness.md f2 §9). Each case builds the scenario it
//! describes, wires a synthetic status responder behind a [`FreshnessOracle`], runs the real
//! chain verifier / session service / mediator, and returns the outcome string. Expected
//! values live only in `tests/cases/freshness_cases.toml` and are all `proposed`: the labels
//! are the oracle, never adjusted to match output.
//!
//! Separate from the chain, lookup, session and enforcement slices; the existing
//! 94 / 15 / 34 / 28 outcomes are untouched (those runs use the always-current status source).

use std::collections::HashMap;

use serde_json::json;

use crate::codec::{canonical_json, TypeTag};
use crate::enforcement::{EffectSink, InMemorySessionAuthStore, MediationRequest, Mediator};
use crate::evidence::StatusKey;
use crate::freshness::{
    FreshnessOracle, HwmStore, ResponderStatus, SignedResponse, StatusResponder, DEFAULT_F_SECONDS,
};
use crate::session::{
    encode_proof, InMemoryChallengeStore, IssueOutcome, OsRandom, SessionAuthorization,
    SessionDecision, SessionService, RESPONSE_TAG,
};
use crate::verifier::{ChainVerifier, Evidence};

use super::cases::CaseLabel;
use super::fixture::{asset, put, registration_key, secret, set, ts, Scenario, ACME, P_AUD};

pub const FRESHNESS_CASES_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/cases/freshness_cases.toml"
);

const SESSION: &str = "sess-p-0001";
/// Label of the pinned responder key `K_R` for Acme (an RQ1-style out-of-band pin).
const RESPONDER: &str = "acme-status-responder";
/// Default fresh-response timestamps (docs/freshness.md §8).
const KNOWN: &str = "2026-10-15T09:59:00Z";
const EXP: &str = "2026-10-15T11:00:00Z";
/// Mediation decision instant for the inheritance cases (matches the RQ6 slice).
const MED: &str = "2026-10-15T10:30:00Z";

pub const FRESHNESS_CASE_IDS: &[&str] = &[
    "FR01", "FR02", "FR03", "FR04", "FR05", "FR06", "FR07", "FR08", "FR09", "FR11", "FR12", "FR13",
    "FR14", "FR15", "FR16", "FB01", "FB02", "FB03", "FB04", "FB05", "FB06", "FB07", "FB08", "FB09",
    "FS01", "FS02", "FS03", "FS04", "FR17", "FR18", "FR19",
];

// ---------------------------------------------------------------------------
// Responder / oracle helpers
// ---------------------------------------------------------------------------

fn keys(s: &Scenario) -> (StatusKey, StatusKey, StatusKey) {
    let k = |t, spec: &_| registration_key(t, spec).expect("fixture object has identity");
    (
        k(TypeTag::AdminDelegation, s.admin.as_ref().expect("admin")),
        k(
            TypeTag::IssuerDelegation,
            s.issuer.as_ref().expect("issuer"),
        ),
        k(TypeTag::EngagementGrant, s.grant.as_ref().expect("grant")),
    )
}

fn pinned() -> HashMap<String, [u8; 32]> {
    let mut m = HashMap::new();
    m.insert(ACME.to_owned(), secret(RESPONDER).public_bytes());
    m
}

/// A signed response for `key`, signed by `signer`'s key.
#[allow(clippy::too_many_arguments)]
fn signed(
    signer: &str,
    key: &StatusKey,
    status: ResponderStatus,
    epoch: u64,
    known: &str,
    published: &str,
    expires: &str,
) -> SignedResponse {
    SignedResponse::build(
        &secret(signer),
        key,
        status,
        epoch,
        ts(known),
        ts(published),
        ts(expires),
    )
}

fn resp(
    key: &StatusKey,
    status: ResponderStatus,
    epoch: u64,
    known: &str,
    published: &str,
    expires: &str,
) -> SignedResponse {
    signed(RESPONDER, key, status, epoch, known, published, expires)
}

fn fresh(key: &StatusKey) -> SignedResponse {
    resp(key, ResponderStatus::Active, 1, KNOWN, KNOWN, EXP)
}

/// Responder with C_A and D_U fresh Active (so the status stage reaches G).
fn base_responder(ak: &StatusKey, dk: &StatusKey) -> StatusResponder {
    let mut r = StatusResponder::new();
    r.insert(ak.clone(), fresh(ak));
    r.insert(dk.clone(), fresh(dk));
    r
}

fn oracle<'a>(
    responder: &'a StatusResponder,
    pins: &'a HashMap<String, [u8; 32]>,
    hwm: &'a HwmStore,
) -> FreshnessOracle<'a> {
    FreshnessOracle {
        responder,
        pinned: pins,
        f_seconds: DEFAULT_F_SECONDS,
        hwm,
    }
}

fn chain_decision(s: &Scenario, responder: &StatusResponder, hwm: &HwmStore) -> String {
    let pins = pinned();
    let o = oracle(responder, &pins, hwm);
    let bundle = s.build();
    let v = ChainVerifier {
        audience: P_AUD,
        evidence: Evidence {
            registry: &s.registry,
            bindings: &s.bindings,
            clock: &s.clock,
            status: &o,
        },
    };
    v.verify(&bundle).to_string()
}

/// Build the base scenario (now = 10:00:00Z, ε = 2) with C_A/D_U fresh, let `setup` describe
/// G's response and any pre-seeded high-water-mark, then return the chain decision.
fn chain_case(
    setup: impl FnOnce(&StatusKey, &StatusKey, &StatusKey, &mut StatusResponder, &HwmStore),
) -> String {
    let s = Scenario::base();
    let (ak, dk, gk) = keys(&s);
    let mut responder = base_responder(&ak, &dk);
    let hwm = HwmStore::new();
    setup(&ak, &dk, &gk, &mut responder, &hwm);
    chain_decision(&s, &responder, &hwm)
}

// ---------------------------------------------------------------------------
// Session / mediation helpers (inheritance cases)
// ---------------------------------------------------------------------------

fn session_service<'a>(
    s: &'a Scenario,
    o: &'a FreshnessOracle<'a>,
    store: &'a InMemoryChallengeStore,
) -> SessionService<'a> {
    let v = ChainVerifier {
        audience: P_AUD,
        evidence: Evidence {
            registry: &s.registry,
            bindings: &s.bindings,
            clock: &s.clock,
            status: o,
        },
    };
    SessionService::new(v, store, &OsRandom)
}

fn issue_decision(s: &Scenario, responder: &StatusResponder) -> String {
    let pins = pinned();
    let hwm = HwmStore::new();
    let o = oracle(responder, &pins, &hwm);
    let store = InMemoryChallengeStore::default();
    session_service(s, &o, &store)
        .issue(&s.build(), SESSION)
        .to_string()
}

fn tester_proof(c: &crate::session::Challenge) -> Vec<u8> {
    encode_proof(
        &c.challenge_id,
        &secret("tester-1").sign(RESPONSE_TAG, &c.wire_bytes()),
    )
}

/// Enforcement grant: base grant plus read_only_data_access (so web.get is in class scope).
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

fn web_wire(path: &str) -> Vec<u8> {
    canonical_json(&asset(&format!("web:https://app.acme.test:443{path}")))
        .expect("asset is canonicalizable")
}

/// Issue and redeem at 10:00:00Z against a fresh responder to obtain a genuine
/// SessionAuthorization (only `redeem` constructs one).
fn fresh_auth(s: &Scenario) -> SessionAuthorization {
    let (ak, dk, gk) = keys(s);
    let pins = pinned();
    let mut responder = base_responder(&ak, &dk);
    responder.insert(gk.clone(), fresh(&gk));
    let hwm = HwmStore::new();
    let o = oracle(&responder, &pins, &hwm);
    let store = InMemoryChallengeStore::default();
    let svc = session_service(s, &o, &store);
    let bundle = s.build();
    let c = match svc.issue(&bundle, SESSION) {
        IssueOutcome::Issued(c) => *c,
        other => panic!("fresh auth issuance must succeed, got {other}"),
    };
    match svc.redeem(&bundle, SESSION, Some(&tester_proof(&c))) {
        SessionDecision::Accept(a) => *a,
        other => panic!("fresh auth redemption must accept, got {other}"),
    }
}

/// Mediate one web.get on /app/reports with a responder whose G carries `g_resp`.
fn mediate_with_g(g_resp: SignedResponse) -> String {
    let s = enf_scenario();
    let auth = fresh_auth(&s);
    let mut sm = s.clone();
    sm.set_clock(MED, 2);
    let (ak, dk, gk) = keys(&sm);
    let pins = pinned();
    let mut responder = base_responder(&ak, &dk);
    responder.insert(gk.clone(), g_resp);
    let hwm = HwmStore::new();
    let o = oracle(&responder, &pins, &hwm);
    let v = ChainVerifier {
        audience: P_AUD,
        evidence: Evidence {
            registry: &sm.registry,
            bindings: &sm.bindings,
            clock: &sm.clock,
            status: &o,
        },
    };
    let store = InMemorySessionAuthStore::default();
    store.insert(SESSION, auth);
    let sink = EffectSink::new();
    let med = Mediator {
        chain: v,
        sessions: &store,
        sink: &sink,
    };
    let req = MediationRequest {
        bundle: sm.build(),
        operation: "web.get".to_owned(),
        target_wire: web_wire("/app/reports"),
        claimed_class: None,
    };
    let before = sink.len();
    let decision = med.mediate(SESSION, &req);
    format!("{decision} effects={}", sink.len() - before)
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// Run freshness case `id`; `None` for an unknown id.
pub fn run(id: &str) -> Option<String> {
    use ResponderStatus::{Active, Revoked, Superseded};
    let out = match id {
        // --- policy ---
        "FR01" => chain_case(|_, _, gk, r, _| r.insert(gk.clone(), fresh(gk))),
        "FR02" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(gk, Active, 1, KNOWN, KNOWN, "2026-10-15T09:59:58Z"),
            )
        }),
        "FR03" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(gk, Active, 1, "2026-10-15T08:00:00Z", KNOWN, EXP),
            )
        }),
        "FR04" => chain_case(|_, _, gk, r, _| {
            r.insert(gk.clone(), resp(gk, Revoked, 1, KNOWN, KNOWN, EXP))
        }),
        "FR05" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(
                    gk,
                    Revoked,
                    1,
                    "2026-10-15T08:58:00Z",
                    "2026-10-15T08:59:00Z",
                    "2026-10-15T09:00:00Z",
                ),
            )
        }),
        "FR06" => chain_case(|ak, _, gk, r, _| {
            r.insert(ak.clone(), resp(ak, Superseded, 1, KNOWN, KNOWN, EXP));
            r.insert(gk.clone(), fresh(gk));
        }),
        "FR07" => chain_case(|_, _, _, _, _| { /* no G response filed */ }),
        "FR08" => chain_case(|_, _, gk, r, _| {
            r.insert(gk.clone(), fresh(gk));
            r.unavailable = true;
        }),
        "FR09" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(
                    gk,
                    Active,
                    1,
                    "2026-10-15T10:05:00Z",
                    "2026-10-15T10:05:00Z",
                    "2026-10-15T11:05:00Z",
                ),
            )
        }),
        "FR11" => chain_case(|_, _, gk, r, h| {
            r.insert(gk.clone(), fresh(gk));
            h.seed_epoch(gk, 2, [0u8; 32]);
        }),
        "FR12" => chain_case(|_, dk, gk, r, _| {
            // A valid response about D_U, offered for G: embedded status_key ≠ G's key.
            r.insert(gk.clone(), fresh(dk));
        }),
        "FR13" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(
                    gk,
                    Revoked,
                    1,
                    "2026-10-15T08:00:00Z",
                    "2026-10-15T08:00:00Z",
                    "2026-10-15T08:30:00Z",
                ),
            )
        }),
        "FR14" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                signed("rogue-responder", gk, Active, 1, KNOWN, KNOWN, EXP),
            )
        }),
        "FR15" => chain_case(|_, _, gk, r, _| {
            // published_at < status_known_at: out of order.
            r.insert(
                gk.clone(),
                resp(gk, Active, 1, KNOWN, "2026-10-15T09:58:00Z", EXP),
            )
        }),
        "FR16" => chain_case(|_, _, gk, r, h| {
            h.seed_sticky_revoked(gk);
            r.insert(gk.clone(), resp(gk, Active, 3, KNOWN, KNOWN, EXP));
        }),
        // --- boundary (interval [09:59:58Z, 10:00:02Z], F = 3600 s) ---
        "FB01" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(gk, Active, 1, "2026-10-15T09:00:02Z", KNOWN, EXP),
            )
        }),
        "FB02" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(gk, Active, 1, "2026-10-15T09:00:00Z", KNOWN, EXP),
            )
        }),
        "FB03" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(gk, Active, 1, KNOWN, KNOWN, "2026-10-15T10:00:03Z"),
            )
        }),
        "FB04" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(gk, Active, 1, KNOWN, KNOWN, "2026-10-15T10:00:01Z"),
            )
        }),
        "FB05" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(gk, Active, 1, KNOWN, KNOWN, "2026-10-15T09:59:58Z"),
            )
        }),
        "FB06" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(
                    gk,
                    Active,
                    1,
                    "2026-10-15T10:00:02Z",
                    "2026-10-15T10:00:02Z",
                    "2026-10-15T11:00:02Z",
                ),
            )
        }),
        "FB07" => chain_case(|_, _, gk, r, _| {
            r.insert(
                gk.clone(),
                resp(
                    gk,
                    Active,
                    1,
                    "2026-10-15T10:00:03Z",
                    "2026-10-15T10:00:03Z",
                    "2026-10-15T11:00:03Z",
                ),
            )
        }),
        "FB08" => chain_case(|_, _, gk, r, h| {
            let g = resp(gk, Active, 2, KNOWN, KNOWN, EXP);
            h.seed_epoch(gk, 2, g.digest()); // same signed response at the hwm epoch
            r.insert(gk.clone(), g);
        }),
        "FB09" => chain_case(|_, _, gk, r, h| {
            h.seed_epoch(gk, 2, [0xABu8; 32]); // a different signed response at the hwm epoch
            r.insert(gk.clone(), resp(gk, Active, 2, KNOWN, KNOWN, EXP));
        }),
        // --- session issuance ---
        "FS01" => {
            let s = Scenario::base();
            let (ak, dk, gk) = keys(&s);
            let mut r = base_responder(&ak, &dk);
            r.insert(gk.clone(), fresh(&gk));
            issue_decision(&s, &r)
        }
        "FS02" => {
            let s = Scenario::base();
            let (ak, dk, gk) = keys(&s);
            let mut r = base_responder(&ak, &dk);
            r.insert(
                gk.clone(),
                resp(&gk, Active, 1, KNOWN, KNOWN, "2026-10-15T09:59:58Z"),
            );
            issue_decision(&s, &r)
        }
        "FS03" => {
            let s = Scenario::base();
            let (ak, dk, gk) = keys(&s);
            let mut r = base_responder(&ak, &dk);
            r.insert(gk.clone(), resp(&gk, Revoked, 1, KNOWN, KNOWN, EXP));
            issue_decision(&s, &r)
        }
        "FS04" => {
            let s = Scenario::base();
            let (ak, dk, _gk) = keys(&s);
            let mut r = base_responder(&ak, &dk);
            r.unavailable = true;
            issue_decision(&s, &r)
        }
        // --- redemption / mediation inheritance ---
        "FR17" => fr17(),
        "FR18" => mediate_with_g(resp(
            &keys(&enf_scenario()).2,
            Active,
            1,
            KNOWN,
            KNOWN,
            "2026-10-15T09:59:58Z",
        )),
        "FR19" => mediate_with_g(resp(
            &keys(&enf_scenario()).2,
            Revoked,
            1,
            KNOWN,
            KNOWN,
            EXP,
        )),
        _ => return None,
    };
    Some(out)
}

/// Issue fresh (minting a challenge), then redeem the same challenge when G has gone stale.
fn fr17() -> String {
    let s = Scenario::base();
    let (ak, dk, gk) = keys(&s);
    let pins = pinned();
    let bundle = s.build();
    let store = InMemoryChallengeStore::default();

    // issue — fresh responder.
    let mut fresh_resp = base_responder(&ak, &dk);
    fresh_resp.insert(gk.clone(), fresh(&gk));
    let fresh_hwm = HwmStore::new();
    let o_fresh = oracle(&fresh_resp, &pins, &fresh_hwm);
    let c = match session_service(&s, &o_fresh, &store).issue(&bundle, SESSION) {
        IssueOutcome::Issued(c) => *c,
        other => return format!("issue failed: {other}"),
    };

    // redeem — G now stale (expired).
    let mut stale_resp = base_responder(&ak, &dk);
    stale_resp.insert(
        gk.clone(),
        resp(
            &gk,
            ResponderStatus::Active,
            1,
            KNOWN,
            KNOWN,
            "2026-10-15T09:59:58Z",
        ),
    );
    let stale_hwm = HwmStore::new();
    let o_stale = oracle(&stale_resp, &pins, &stale_hwm);
    session_service(&s, &o_stale, &store)
        .redeem(&bundle, SESSION, Some(&tester_proof(&c)))
        .to_string()
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

pub struct FreshnessRow {
    pub label: CaseLabel,
    pub actual: String,
}

pub fn run_all(labels: &[CaseLabel]) -> Vec<FreshnessRow> {
    labels
        .iter()
        .map(|l| FreshnessRow {
            label: l.clone(),
            actual: run(&l.id).unwrap_or_else(|| format!("no runner for {}", l.id)),
        })
        .collect()
}

pub fn render_markdown(rows: &[FreshnessRow]) -> String {
    let matched = rows.iter().filter(|r| r.actual == r.label.expected).count();
    let mut out = String::from("# RQ7 freshness-slice cases (generated)\n\n");
    out.push_str("Generated by `cargo run --release --bin eval`. Labels come from ");
    out.push_str("`tests/cases/freshness_cases.toml` (all **proposed**; the oracle for the ");
    out.push_str("implementation, awaiting owner review). Separate from the chain, lookup, ");
    out.push_str("session and enforcement results.\n\n");
    out.push_str(&format!(
        "Matched {matched}/{} proposed labels.\n\n",
        rows.len()
    ));
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

pub fn render_json(rows: &[FreshnessRow]) -> serde_json::Value {
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
