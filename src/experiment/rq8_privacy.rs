//! RQ8 Q1 privacy slice (docs/rq8.md "Q1 measurement slice 1"): a synthetic field-disclosure
//! inventory and a deterministic linkability comparison. Each observation is extracted from the
//! ACTUAL canonical signed bytes / wire forms (the effect receipt from its struct getters) and
//! compared against `tests/cases/rq8_privacy_cases.toml`, whose labels are the oracle and are
//! never adjusted to match output.
//!
//! Synthetic only: synthetic org, test-only keys, `.test` hosts, in-memory fixtures. No network,
//! no real data. This is a structural observation about the encoding, not a privacy guarantee.

use serde_json::{json, Value};

use crate::codec::{canonical_json, TypeTag};
use crate::enforcement::{
    EffectReceipt, EffectSink, InMemorySessionAuthStore, Mediate, MediationRequest, Mediator,
};
use crate::evidence::StatusKey;
use crate::freshness::{ResponderStatus, SignedResponse};
use crate::session::{
    encode_proof, Challenge, GrantRef, InMemoryChallengeStore, IssueOutcome, OsRandom,
    SessionDecision, SessionService, RESPONSE_TAG, SESSION_FORMAT,
};

use super::cases::CaseLabel;
use super::fixture::{asset, put, registration_key, secret, set, ts, Scenario, P_AUD};

pub const RQ8_PRIVACY_CASES_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/cases/rq8_privacy_cases.toml"
);

const SESSION: &str = "sess-p-0001";
const RESPONDER: &str = "acme-status-responder";
const KNOWN: &str = "2026-10-15T09:59:00Z";
const EXP: &str = "2026-10-15T11:00:00Z";

pub const RQ8_PRIVACY_CASE_IDS: &[&str] = &[
    "FD01", "FD02", "FD03", "FD04", "FD05", "FD06", "FD07", "FD08", "PO1", "PO2", "PO3", "PO5",
    "PL01", "PL02",
];

// ---------------------------------------------------------------------------
// Field extraction (from actual bytes)
// ---------------------------------------------------------------------------

fn sorted_keys(v: &Value) -> String {
    let mut keys: Vec<&str> = v
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys.join(",")
}

/// Sorted top-level field names of a value's canonical signed bytes (re-parsed from the bytes).
fn fields_of_canonical(v: &Value) -> String {
    let bytes = canonical_json(v).expect("canonicalizable");
    let parsed: Value = serde_json::from_slice(&bytes).expect("canonical json");
    sorted_keys(&parsed)
}

/// Sorted top-level field names of a wire/canonical byte string.
fn fields_of_bytes(b: &[u8]) -> String {
    let parsed: Value = serde_json::from_slice(b).expect("json");
    sorted_keys(&parsed)
}

fn grant_payload(s: &Scenario) -> &Value {
    &s.grant.as_ref().expect("grant").payload
}

fn grant_status_key(s: &Scenario) -> StatusKey {
    registration_key(TypeTag::EngagementGrant, s.grant.as_ref().expect("grant"))
        .expect("grant identity")
}

/// A default fresh status response for the grant (to inspect what R produces / its StatusKey).
fn status_response(key: &StatusKey) -> SignedResponse {
    SignedResponse::build(
        &secret(RESPONDER),
        key,
        ResponderStatus::Active,
        1,
        ts(KNOWN),
        ts(KNOWN),
        ts(EXP),
    )
}

/// Sorted field names of the `status_key` object inside an actual status response — exactly what
/// O3 (the responder) receives as a query.
fn status_key_fields(key: &StatusKey) -> String {
    let parsed: Value =
        serde_json::from_slice(status_response(key).payload()).expect("response json");
    sorted_keys(parsed.get("status_key").expect("status_key object"))
}

/// A P-issued challenge, to inspect its wire fields (fixed non-secret values; only the field
/// names are reported).
fn sample_challenge(key: &StatusKey) -> Vec<u8> {
    Challenge {
        audience: P_AUD.to_owned(),
        challenge_id: "0".repeat(32),
        expires_at: ts("2026-10-15T10:02:00Z"),
        format: SESSION_FORMAT.to_owned(),
        grant: GrantRef::from(key),
        issued_at: ts("2026-10-15T10:00:00Z"),
        nonce: "nonce".to_owned(),
        session_id: SESSION.to_owned(),
    }
    .wire_bytes()
}

/// A genuine effect receipt from a real mediation Allow, to inventory the fields O5 logs. The
/// receipt is an in-memory record (not a wire object), so its fields come from its getters.
fn receipt_fields() -> String {
    let r = sample_receipt();
    let obj = json!({
        "session_ref": r.session_ref(),
        "operation": r.operation(),
        "target": r.target(),
        "test_class": format!("{:?}", r.test_class()),
        "effects": format!("{:?}", r.effects()),
        "performed_at": r.performed_at(),
    });
    sorted_keys(&obj)
}

fn sample_receipt() -> EffectReceipt {
    let mut s = Scenario::base();
    // read_only_data_access so web.get is in class scope.
    put(
        s.grant(),
        "test_scope",
        json!({
            "classes": set(vec![json!("injection_testing"), json!("read_only_data_access"), json!("recon")]),
            "kind": "classes"
        }),
    );
    // Issue + redeem at 10:00:00Z to obtain a genuine SessionAuthorization.
    s.set_clock("2026-10-15T10:00:00Z", 2);
    let store = InMemoryChallengeStore::default();
    let auth = {
        let prepared = s.prepare();
        let svc = SessionService::new(prepared.verifier(), &store, &OsRandom);
        let c = match svc.issue(&prepared.bundle, SESSION) {
            IssueOutcome::Issued(c) => *c,
            other => panic!("rq8 receipt fixture issuance must succeed, got {other}"),
        };
        let proof = encode_proof(
            &c.challenge_id,
            &secret("tester-1").sign(RESPONSE_TAG, &c.wire_bytes()),
        );
        match svc.redeem(&prepared.bundle, SESSION, Some(&proof)) {
            SessionDecision::Accept(a) => *a,
            other => panic!("rq8 receipt fixture redemption must accept, got {other}"),
        }
    };
    // Mediate one web.get at 10:30:00Z -> Allow, yielding a receipt.
    s.set_clock("2026-10-15T10:30:00Z", 2);
    let authstore = InMemorySessionAuthStore::default();
    authstore.insert(SESSION, auth);
    let prepared = s.prepare();
    let sink = EffectSink::new();
    let med = Mediator {
        chain: prepared.verifier(),
        sessions: &authstore,
        sink: &sink,
    };
    let req = MediationRequest {
        bundle: prepared.bundle.clone(),
        operation: "web.get".to_owned(),
        target_wire: canonical_json(&asset("web:https://app.acme.test:443/app/reports"))
            .expect("canonicalizable"),
        claimed_class: None,
    };
    match med.mediate(SESSION, &req) {
        Mediate::Allow(r) => *r,
        other => panic!("rq8 receipt fixture mediation must Allow, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// Linkability
// ---------------------------------------------------------------------------

fn eq(b: bool) -> &'static str {
    if b {
        "equal"
    } else {
        "differ"
    }
}

fn grant_field<'a>(s: &'a Scenario, field: &str) -> &'a str {
    grant_payload(s)
        .get(field)
        .and_then(Value::as_str)
        .expect("string grant field")
}

/// Compare two grants on signed bytes, key ids and exact StatusKey, each reported separately.
fn linkability(a: &Scenario, b: &Scenario) -> String {
    let signed_bytes = canonical_json(grant_payload(a)).expect("canon")
        == canonical_json(grant_payload(b)).expect("canon");
    let issuer_key_id = grant_field(a, "issuer_key_id") == grant_field(b, "issuer_key_id");
    let tester_key_id = grant_field(a, "tester_key") == grant_field(b, "tester_key");
    let status_key = grant_status_key(a) == grant_status_key(b);
    format!(
        "signed_bytes={} issuer_key_id={} tester_key_id={} status_key={}",
        eq(signed_bytes),
        eq(issuer_key_id),
        eq(tester_key_id),
        eq(status_key),
    )
}

/// A legitimately reissued grant: same parties, new engagement id, re-signed.
fn reissued_grant() -> Scenario {
    let mut s = Scenario::base();
    put(s.grant(), "engagement_id", json!("eng-acme-2026-10-15-02"));
    s
}

// ---------------------------------------------------------------------------
// Observer -> artifacts, from an executed synthetic flow (trace)
// ---------------------------------------------------------------------------

/// What an executed synthetic flow shows each observer receiving, with proof-of-execution flags
/// so the derivation can be gated (a hard-coded list cannot set these honestly).
struct FlowTrace {
    o1: Vec<&'static str>,
    o2: Vec<&'static str>,
    o3: Vec<&'static str>,
    o5: Vec<&'static str>,
    #[allow(dead_code)] // read by the reproduction/regression tests
    chain_accepted: bool,
    #[allow(dead_code)]
    r_signed_response_received: bool,
    #[allow(dead_code)]
    challenge_issued: bool,
    #[allow(dead_code)]
    proof_verified: bool,
    #[allow(dead_code)]
    receipt_recorded: bool,
}

fn observer_set(mut v: Vec<&'static str>) -> String {
    v.sort_unstable();
    v.join(",")
}

/// REPRODUCTION STUB (finding: hard-coded PO lists): returns fixed observer sets WITHOUT
/// executing any flow. The proof-of-execution flags are all false. Replaced in the fix commit
/// by a function that actually runs the freshness-aware flow and derives the sets from it.
fn observe_flow() -> FlowTrace {
    FlowTrace {
        o1: vec!["admin", "grant", "issuer"],
        o2: vec!["admin", "challenge", "grant", "issuer", "proof", "status_response"],
        o3: vec!["status_key"],
        o5: vec!["effect_receipt"],
        chain_accepted: false,
        r_signed_response_received: false,
        challenge_issued: false,
        proof_verified: false,
        receipt_recorded: false,
    }
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// Run RQ8 privacy case `id`; `None` for an unknown id.
pub fn run(id: &str) -> Option<String> {
    let s = Scenario::base();
    let gk = grant_status_key(&s);
    let out = match id {
        "FD01" => fields_of_canonical(&s.admin.as_ref().expect("admin").payload),
        "FD02" => fields_of_canonical(&s.issuer.as_ref().expect("issuer").payload),
        "FD03" => fields_of_canonical(grant_payload(&s)),
        "FD04" => fields_of_bytes(status_response(&gk).payload()),
        "FD05" => status_key_fields(&gk),
        "FD06" => fields_of_bytes(&sample_challenge(&gk)),
        "FD07" => fields_of_bytes(&encode_proof("abc", &[0u8; 64])),
        "FD08" => receipt_fields(),
        // Observer -> artifacts actually received, derived from an executed synthetic flow.
        "PO1" => observer_set(observe_flow().o1),
        "PO2" => observer_set(observe_flow().o2),
        "PO3" => observer_set(observe_flow().o3),
        "PO5" => observer_set(observe_flow().o5),
        // Linkability: identical presentation vs a legitimate reissue.
        "PL01" => linkability(&s, &Scenario::base()),
        "PL02" => linkability(&s, &reissued_grant()),
        _ => return None,
    };
    Some(out)
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

pub struct PrivacyRow {
    pub label: CaseLabel,
    pub actual: String,
}

pub fn run_all(labels: &[CaseLabel]) -> Vec<PrivacyRow> {
    labels
        .iter()
        .map(|l| PrivacyRow {
            label: l.clone(),
            actual: run(&l.id).unwrap_or_else(|| format!("no runner for {}", l.id)),
        })
        .collect()
}

pub fn render_markdown(rows: &[PrivacyRow]) -> String {
    let matched = rows.iter().filter(|r| r.actual == r.label.expected).count();
    let mut out =
        String::from("# RQ8 Q1 privacy slice — field disclosure & linkability (generated)\n\n");
    out.push_str("Generated by `cargo run --release --bin eval`. Labels (proposed) come from ");
    out.push_str("`tests/cases/rq8_privacy_cases.toml`; method in `docs/rq8.md`. Synthetic only, ");
    out.push_str("no network, no real data; a structural observation, not a privacy guarantee. ");
    out.push_str("O4 network/traffic metadata is unmeasured.\n\n");
    out.push_str(&format!(
        "Matched {matched}/{} proposed observations.\n\n",
        rows.len()
    ));
    out.push_str("| ID | Label status | Note | Expected | Actual | Match |\n| --- | --- | --- | --- | --- | --- |\n");
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | {} | `{}` | `{}` | {} |\n",
            r.label.id,
            r.label.label_status,
            r.label.note,
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

pub fn render_json(rows: &[PrivacyRow]) -> Value {
    json!({
        "matched": rows.iter().filter(|r| r.actual == r.label.expected).count(),
        "total": rows.len(),
        "cases": rows.iter().map(|r| json!({
            "id": r.label.id,
            "label_status": r.label.label_status,
            "note": r.label.note,
            "expected": r.label.expected,
            "actual": r.actual,
            "match": r.actual == r.label.expected,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod repro {
    use super::*;

    fn grant_u32(s: &Scenario, field: &str) -> u64 {
        grant_payload(s)
            .get(field)
            .and_then(Value::as_u64)
            .expect("numeric grant field")
    }

    // Finding 1 (RED): PL02 must be a legitimate reissue under a new `version` or `id`
    // (spec §6: re-signing different content under the same (org,type,id,version) is
    // unsupported). The current `reissued_grant` only changes `engagement_id`, keeping id and
    // version, so this fails until the fix bumps the version.
    #[test]
    fn reissue_changes_grant_version_or_id() {
        let base = Scenario::base();
        let reissue = reissued_grant();
        let version_changed = grant_u32(&base, "version") != grant_u32(&reissue, "version");
        let id_changed = grant_field(&base, "id") != grant_field(&reissue, "id");
        assert!(
            version_changed || id_changed,
            "a legitimate reissue must change grant version or id (spec §6); got same \
             (id, version) with different content, which is an unsupported re-sign"
        );
    }

    // Finding 3 (RED): the PO observer lists must be derived from an executed freshness-aware
    // flow (chain Accept, an R-signed response actually returned to P, a challenge issued, a
    // proof verified, a receipt recorded). The reproduction stub hard-codes the lists and sets
    // every proof-of-execution flag false, so this fails until the flow is executed.
    #[test]
    fn po_observations_require_an_executed_flow() {
        let t = observe_flow();
        assert!(
            t.chain_accepted
                && t.r_signed_response_received
                && t.challenge_issued
                && t.proof_verified
                && t.receipt_recorded,
            "PO observations must come from an executed freshness-aware flow, not a hard-coded list"
        );
    }
}
