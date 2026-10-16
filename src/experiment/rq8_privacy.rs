//! RQ8 Q1 privacy slice (docs/rq8.md "Q1 measurement slice 1"): a synthetic field-disclosure
//! inventory and a deterministic linkability comparison. Each observation is extracted from the
//! ACTUAL canonical signed bytes / wire forms (the effect receipt from its struct getters) and
//! compared against `tests/cases/rq8_privacy_cases.toml`, whose labels are the oracle and are
//! never adjusted to match output.
//!
//! Synthetic only: synthetic org, test-only keys, `.test` hosts, in-memory fixtures. No network,
//! no real data. This is a structural observation about the encoding, not a privacy guarantee.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::codec::{b64_decode, canonical_json, TypeTag};
use crate::crypto;
use crate::decision::{Decision, Slot};
use crate::enforcement::{
    EffectReceipt, EffectSink, InMemorySessionAuthStore, Mediate, MediationRequest, Mediator,
};
use crate::evidence::StatusKey;
use crate::freshness::{
    FreshnessOracle, HwmStore, ResponderStatus, SignedResponse, StatusResponder, DEFAULT_F_SECONDS,
};
use crate::session::{
    encode_proof, Challenge, InMemoryChallengeStore, IssueOutcome, OsRandom, SessionDecision,
    SessionService, RESPONSE_TAG,
};
use crate::verifier::{decode_chain, Bundle, ChainVerifier, Evidence};

use super::cases::CaseLabel;
use super::fixture::{asset, put, registration_key, secret, set, ts, Scenario, ACME, P_AUD};

pub const RQ8_PRIVACY_CASES_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/cases/rq8_privacy_cases.toml"
);

const SESSION: &str = "sess-p-0001";
const RESPONDER: &str = "acme-status-responder";
const KNOWN: &str = "2026-10-15T09:59:00Z";
const EXP: &str = "2026-10-15T11:00:00Z";

pub const RQ8_PRIVACY_CASE_IDS: &[&str] = &[
    "FD01", "FD02", "FD03", "FD04", "FD05", "FD06", "FD07", "FD08", "FD09", "FD10", "PO1", "PO2",
    "PO3", "PO5", "PL01", "PL02",
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

/// Sorted top-level field names of a wire/canonical byte string.
fn fields_of_bytes(b: &[u8]) -> String {
    let parsed: Value = serde_json::from_slice(b).expect("json");
    sorted_keys(&parsed)
}

/// Field names of a built bundle's slot, read from the DECODED signed payload bytes.
fn decoded_payload_fields(slot: Slot) -> String {
    let bundle = Scenario::base().build();
    let chain = decode_chain(&bundle).expect("decode the base bundle");
    let payload = match slot {
        Slot::Admin => chain.admin().payload(),
        Slot::Issuer => chain.issuer().payload(),
        Slot::Grant => chain.grant().payload(),
        Slot::Root => unreachable!("the root slot is not part of the decoded chain"),
    };
    fields_of_bytes(payload)
}

/// Field names of an envelope's signed payload (base64-decoded from the built bundle slot).
fn envelope_payload_fields(envelope: &[u8]) -> String {
    let v: Value = serde_json::from_slice(envelope).expect("envelope json");
    let payload_b64 = v
        .get("payload")
        .and_then(Value::as_str)
        .expect("payload b64");
    let payload = b64_decode(payload_b64).expect("b64 payload");
    fields_of_bytes(&payload)
}

/// FD09: the root slot (OrganizationRoot) signed payload field names — raw bundle data that a
/// holder and P can see even though the verifier ignores the slot.
fn root_payload_fields() -> String {
    let bundle = Scenario::base().build();
    let root = bundle.root.as_ref().expect("base bundle has a root slot");
    envelope_payload_fields(root)
}

/// FD10: the in-memory `MediationRequest` struct P receives from the agent — its field names,
/// distinct from the raw bundle bytes the `bundle` field carries.
fn mediation_request_fields() -> String {
    let req = MediationRequest {
        bundle: Scenario::base().build(),
        operation: "web.get".to_owned(),
        target_wire: Vec::new(),
        claimed_class: None,
    };
    // Tie the reported names to the actual struct fields.
    let _ = (
        &req.bundle,
        &req.operation,
        &req.target_wire,
        &req.claimed_class,
    );
    observer_set(vec!["bundle", "claimed_class", "operation", "target_wire"])
}

/// Artifacts a bundle discloses: one per present slot (the verifier ignores `root`, but a
/// holder and P still see its bytes).
fn bundle_artifacts(b: &Bundle) -> Vec<&'static str> {
    let mut v = Vec::new();
    if b.root.is_some() {
        v.push("root");
    }
    if b.admin.is_some() {
        v.push("admin");
    }
    if b.issuer.is_some() {
        v.push("issuer");
    }
    if b.grant.is_some() {
        v.push("grant");
    }
    v
}

#[cfg(test)]
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

/// A genuinely issued challenge (via `SessionService::issue`), to inspect its wire fields.
fn issued_challenge() -> Challenge {
    let mut s = Scenario::base();
    s.set_clock("2026-10-15T10:00:00Z", 2);
    let store = InMemoryChallengeStore::default();
    let prepared = s.prepare();
    let svc = SessionService::new(prepared.verifier(), &store, &OsRandom);
    match svc.issue(&prepared.bundle, SESSION) {
        IssueOutcome::Issued(c) => *c,
        other => panic!("rq8 challenge fixture issuance must succeed, got {other}"),
    }
}

/// A valid signed tester proof over an issued challenge, to inspect its wire fields.
fn valid_proof() -> Vec<u8> {
    let c = issued_challenge();
    encode_proof(
        &c.challenge_id,
        &secret("tester-1").sign(RESPONSE_TAG, &c.wire_bytes()),
    )
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

/// Base fixture plus read_only_data_access in the grant's test scope, so web.get is in class
/// scope for the mediation step.
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

fn sample_receipt() -> EffectReceipt {
    let mut s = enf_scenario();
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

#[cfg(test)]
fn grant_field<'a>(s: &'a Scenario, field: &str) -> &'a str {
    grant_payload(s)
        .get(field)
        .and_then(Value::as_str)
        .expect("string grant field")
}

/// A grant, built and verified (chain `Accept`): the exact payload bytes covered by its
/// signature, the signed `issuer_key_id`, the derived `keyid(tester_key)`, and its exact
/// `StatusKey` — all read from the decoded, verified chain.
struct GrantView {
    signed_payload: Vec<u8>,
    issuer_key_id: String,
    tester_key_id: String,
    status_key: StatusKey,
}

fn grant_view(s: &Scenario) -> GrantView {
    let prepared = s.prepare();
    assert_eq!(
        prepared.run(),
        Decision::Accept,
        "a linkability grant must build and verify (chain Accept)"
    );
    let chain = decode_chain(&prepared.bundle).expect("decode the verified bundle");
    let body = chain.grant().body();
    GrantView {
        signed_payload: chain.grant().payload().to_vec(),
        issuer_key_id: body.issuer_key_id.clone(),
        tester_key_id: crypto::key_id(body.tester_key.bytes()),
        status_key: chain.status_keys()[2].1.clone(),
    }
}

/// Compare two built+verified grants, reporting signed bytes, key ids, and each StatusKey
/// component separately (so a `digest` difference is not read as an absence of correlation).
fn linkability(a: &Scenario, b: &Scenario) -> String {
    let a = grant_view(a);
    let b = grant_view(b);
    format!(
        "signed_bytes={} issuer_key_id={} tester_key_id={} status_key.org_id={} \
         status_key.object_type={} status_key.id={} status_key.version={} status_key.digest={}",
        eq(a.signed_payload == b.signed_payload),
        eq(a.issuer_key_id == b.issuer_key_id),
        eq(a.tester_key_id == b.tester_key_id),
        eq(a.status_key.org_id == b.status_key.org_id),
        eq(a.status_key.object_type == b.status_key.object_type),
        eq(a.status_key.id == b.status_key.id),
        eq(a.status_key.version == b.status_key.version),
        eq(a.status_key.digest == b.status_key.digest),
    )
}

/// A legitimately reissued grant under a **new version** (spec §6: a new `version` or `id` is
/// required; re-signing different content under the same `(org, type, id, version)` is
/// unsupported). Same org, same grant `id`, same parties — so `org_id`/`id`/key ids still
/// correlate while the signed bytes, `version` and `digest` change.
fn reissued_grant() -> Scenario {
    let mut s = Scenario::base();
    // A new engagement, reissued under a new version (spec §6 requires a new version or id).
    put(s.grant(), "engagement_id", json!("eng-acme-2026-10-15-02"));
    put(s.grant(), "version", json!(2));
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
    request_received: bool,
    #[allow(dead_code)]
    receipt_recorded: bool,
}

fn observer_set(mut v: Vec<&'static str>) -> String {
    v.sort_unstable();
    v.join(",")
}

/// The full observed flow (with mediation).
fn observe_flow() -> FlowTrace {
    run_flow(true)
}

/// Execute a synthetic freshness-aware flow and derive each observer's received-artifact set
/// from what actually ran: a chain verification where P validates R-signed status responses
/// (so O3 is queried and O2 receives a response), a session issue + redeem (challenge, proof),
/// and, when `mediate` is set, a mediation (P receives the request; a receipt is produced on
/// Allow). Bundle artifacts come from the built bundle's present slots. No network; synthetic.
fn run_flow(mediate: bool) -> FlowTrace {
    let mut s = enf_scenario();
    s.set_clock("2026-10-15T10:00:00Z", 2);
    let ak = registration_key(TypeTag::AdminDelegation, s.admin.as_ref().expect("admin"))
        .expect("admin identity");
    let dk = registration_key(
        TypeTag::IssuerDelegation,
        s.issuer.as_ref().expect("issuer"),
    )
    .expect("issuer identity");
    let gk = grant_status_key(&s);
    let mut responder = StatusResponder::new();
    responder.insert(ak.clone(), status_response(&ak));
    responder.insert(dk.clone(), status_response(&dk));
    responder.insert(gk.clone(), status_response(&gk));
    let mut pins = HashMap::new();
    pins.insert(ACME.to_owned(), secret(RESPONDER).public_bytes());
    let hwm = HwmStore::new();
    let oracle = FreshnessOracle {
        responder: &responder,
        pinned: &pins,
        f_seconds: DEFAULT_F_SECONDS,
        hwm: &hwm,
    };
    let ev = Evidence {
        registry: &s.registry,
        bindings: &s.bindings,
        clock: &s.clock,
        status: &oracle,
    };
    let bundle = s.build();

    // Chain verification against the freshness-aware oracle: Accept requires validating an
    // R-signed response for each object, so P genuinely queried R (O3) and received a response.
    let chain_accepted = ChainVerifier {
        audience: P_AUD,
        evidence: ev,
    }
    .verify(&bundle)
        == Decision::Accept;
    let r_signed_response_received = chain_accepted;

    // Session issue + redeem.
    let store = InMemoryChallengeStore::default();
    let svc = SessionService::new(
        ChainVerifier {
            audience: P_AUD,
            evidence: ev,
        },
        &store,
        &OsRandom,
    );
    let challenge = match svc.issue(&bundle, SESSION) {
        IssueOutcome::Issued(c) => Some(*c),
        _ => None,
    };
    let challenge_issued = challenge.is_some();
    let auth = challenge.as_ref().and_then(|c| {
        let proof = encode_proof(
            &c.challenge_id,
            &secret("tester-1").sign(RESPONSE_TAG, &c.wire_bytes()),
        );
        match svc.redeem(&bundle, SESSION, Some(&proof)) {
            SessionDecision::Accept(a) => Some(*a),
            _ => None,
        }
    });
    let proof_verified = auth.is_some();

    // Mediation at 10:30:00Z (same freshness oracle, a later snapshot). P receives the request
    // (whether or not it Allows); a receipt is produced on Allow.
    let (request_received, receipt_recorded) = match auth {
        Some(auth) if mediate => {
            let mut sm = s.clone();
            sm.set_clock("2026-10-15T10:30:00Z", 2);
            let ev2 = Evidence {
                registry: &sm.registry,
                bindings: &sm.bindings,
                clock: &sm.clock,
                status: &oracle,
            };
            let authstore = InMemorySessionAuthStore::default();
            authstore.insert(SESSION, auth);
            let sink = EffectSink::new();
            let med = Mediator {
                chain: ChainVerifier {
                    audience: P_AUD,
                    evidence: ev2,
                },
                sessions: &authstore,
                sink: &sink,
            };
            let req = MediationRequest {
                bundle: sm.build(),
                operation: "web.get".to_owned(),
                target_wire: canonical_json(&asset("web:https://app.acme.test:443/app/reports"))
                    .expect("canonicalizable"),
                claimed_class: None,
            };
            let allowed = matches!(med.mediate(SESSION, &req), Mediate::Allow(_));
            (true, allowed)
        }
        _ => (false, false),
    };

    // Derive each observer's set from what actually executed. Bundle artifacts (incl. the
    // ignored-but-visible `root`) come from the built bundle's present slots.
    let o1 = bundle_artifacts(&bundle);
    let mut o2 = bundle_artifacts(&bundle);
    if r_signed_response_received {
        o2.push("status_response");
    }
    if challenge_issued {
        o2.push("challenge");
    }
    if proof_verified {
        o2.push("proof");
    }
    if request_received {
        o2.push("mediation_request");
    }
    let mut o3 = Vec::new();
    if r_signed_response_received {
        o3.push("status_key");
    }
    let mut o5 = Vec::new();
    if receipt_recorded {
        o5.push("effect_receipt");
    }
    FlowTrace {
        o1,
        o2,
        o3,
        o5,
        chain_accepted,
        r_signed_response_received,
        challenge_issued,
        proof_verified,
        request_received,
        receipt_recorded,
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
        // FD01–FD03: top-level field names from the DECODED signed payload bytes of the built
        // bundle (admin/issuer/grant). FD09: the root slot's signed payload (raw bundle data).
        "FD01" => decoded_payload_fields(Slot::Admin),
        "FD02" => decoded_payload_fields(Slot::Issuer),
        "FD03" => decoded_payload_fields(Slot::Grant),
        "FD04" => fields_of_bytes(status_response(&gk).payload()),
        "FD05" => status_key_fields(&gk),
        "FD06" => fields_of_bytes(&issued_challenge().wire_bytes()),
        "FD07" => fields_of_bytes(&valid_proof()),
        "FD08" => receipt_fields(),
        "FD09" => root_payload_fields(),
        "FD10" => mediation_request_fields(),
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

    // The PO observer lists must be derived from an executed freshness-aware flow (chain Accept,
    // an R-signed response actually returned to P, a challenge issued, a proof verified, the
    // request received, a receipt recorded), not a hard-coded list.
    #[test]
    fn po_observations_require_an_executed_flow() {
        let t = observe_flow();
        assert!(
            t.chain_accepted
                && t.r_signed_response_received
                && t.challenge_issued
                && t.proof_verified
                && t.request_received
                && t.receipt_recorded,
            "PO observations must come from an executed freshness-aware flow, not a hard-coded list"
        );
    }

    // Removing the optional root slot changes the observed bundle artifacts (root is ignored by
    // the verifier but still visible to a holder and to P).
    #[test]
    fn removing_root_changes_observed_bundle_artifacts() {
        let full = Scenario::base().build();
        assert!(
            bundle_artifacts(&full).contains(&"root"),
            "base bundle has a root"
        );
        let mut s = Scenario::base();
        s.root = None;
        let without = s.build();
        assert!(!bundle_artifacts(&without).contains(&"root"));
        assert_eq!(bundle_artifacts(&without), vec!["admin", "issuer", "grant"]);
    }

    // Skipping mediation removes the request and receipt observations (and their flags).
    #[test]
    fn skipping_mediation_removes_request_and_receipt() {
        let with = run_flow(true);
        assert!(with.o2.contains(&"mediation_request") && with.o5.contains(&"effect_receipt"));
        let without = run_flow(false);
        assert!(!without.request_received && !without.receipt_recorded);
        assert!(!without.o2.contains(&"mediation_request"));
        assert!(without.o5.is_empty());
    }
}
