//! Small-model authorization **demo** (docs/model-demo.md). A provider-owned controller core:
//! it takes a fixed synthetic scenario id and **one untrusted model action proposal** and runs
//! the existing verifier/session/mediator to decide whether a **modeled** in-memory effect
//! occurs. The model proposes only `operation`, `target` and an audit-only `claimed_class`; it
//! never supplies the trusted bundle, clock, status, challenge, proof, keys, authenticated
//! session, or the effect sink — the provider builds those from the selected synthetic fixture.
//!
//! Nothing here performs a real scan, fetches a model-selected target, writes a real database,
//! or runs a shell command. The only "effect" is an append to an in-memory [`EffectSink`] that
//! **only** `Mediator::mediate` can perform, and only on `Allow`. Malformed or unsupported
//! proposals are rejected with no effect.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::codec::canonical_json;
use crate::enforcement::{EffectSink, InMemorySessionAuthStore, MediationRequest, Mediator};
use crate::evidence::{ClockReading, FixedClock, ObjStatus};
use crate::experiment::fixture::{put, secret, set, ts, Prepared, Scenario, P_AUD};
use crate::freshness::{
    FreshnessOracle, HwmStore, ResponderStatus, SignedResponse, StatusResponder, DEFAULT_F_SECONDS,
};
use crate::model::TestClass;
use crate::session::{
    encode_proof, InMemoryChallengeStore, IssueOutcome, OsRandom, SessionAuthorization,
    SessionDecision, SessionService, RESPONSE_TAG,
};
use crate::verifier::{ChainVerifier, Evidence};

pub const FIXTURE_VERSION: &str = "demo-enf-base-v1";
const SESSION: &str = "sess-p-0001";
const RESPONDER: &str = "acme-status-responder";
const ISSUE_AT: &str = "2026-10-15T10:00:00Z";
const MED_AT: &str = "2026-10-15T10:30:00Z";
const EXPIRED_AT: &str = "2026-10-15T11:00:00Z";

// Input bounds (reject oversized proposals with no effect).
const MAX_OP: usize = 64;
const MAX_TARGET: usize = 512;
const MAX_CLASS: usize = 64;
const MAX_REFUSAL: usize = 4096;
const MAX_META: usize = 2048;
const MAX_VARIANT: usize = 64;
const MAX_PARSE: usize = 64;

/// One synthetic environment the controller offers. The model does not choose it.
pub struct ScenarioDef {
    pub id: &'static str,
    pub description: &'static str,
}

pub const SCENARIOS: &[ScenarioDef] = &[
    ScenarioDef {
        id: "fresh",
        description: "valid session, active status, in-window: proposals decided on their merits",
    },
    ScenarioDef {
        id: "expired_session",
        description: "session authorized earlier; mediation clock is past the grant window end",
    },
    ScenarioDef {
        id: "revoked_grant",
        description: "grant status is Revoked at mediation time (chain reject)",
    },
    ScenarioDef {
        id: "stale_status",
        description:
            "RQ7 freshness-aware flow with a stale responder answer for G (chain indeterminate)",
    },
    ScenarioDef {
        id: "unavailable_status",
        description: "status source unavailable at mediation time (chain indeterminate)",
    },
];

/// An untrusted model action proposal (or a refusal). The model supplies only these fields.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// A tool-table operation, e.g. `web.get`. Absent when the model refused.
    #[serde(default)]
    pub operation: Option<String>,
    /// An asset shorthand, e.g. `web:https://app.acme.test:443/app/reports` or `db:cluster1/main/billing`.
    #[serde(default)]
    pub target: Option<String>,
    /// Audit-only: logged, never used in the decision.
    #[serde(default)]
    pub claimed_class: Option<String>,
    /// Set when the model declined to call a tool (free text).
    #[serde(default)]
    pub refusal: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DemoError {
    UnknownScenario,
    Oversized(&'static str),
}

impl std::fmt::Display for DemoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemoError::UnknownScenario => write!(f, "unknown scenario id"),
            DemoError::Oversized(field) => write!(f, "oversized field: {field}"),
        }
    }
}

/// The recorded trace of one run. Serialized to JSON by the controller and the results writer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: String,
    pub scenario_id: String,
    pub fixture_version: String,
    pub prompt_variant_id: Option<String>,
    /// Untrusted model metadata, echoed back for audit (bounded).
    pub model_metadata: Option<String>,
    /// Untrusted client-side parse classification (e.g. the n8n parser's `no_call`,
    /// `malformed_args`, `unknown_tool`, `multiple_calls`). Audit-only, echoed verbatim; the
    /// provider's own trusted `parse_status` below is derived from the proposal, not from this.
    pub model_parse: Option<String>,
    pub proposal: Proposal,
    /// Provider-derived classification of the proposal: `tool_call` (an operation is present and
    /// was mediated), `refusal` (the model explicitly declined), or `no_call` (no operation and
    /// no explicit refusal — including empty model content, which is a no-call, not a refusal).
    pub parse_status: String,
    /// The `Mediate` decision string, or a no-mediation note for a refusal/empty proposal.
    pub decision: String,
    pub effects_before: usize,
    pub effects_after: usize,
    pub effects_delta: usize,
    pub verify_ms: u128,
}

fn check_bounds(
    scenario_id: &str,
    p: &Proposal,
    variant: Option<&str>,
    meta: Option<&str>,
    model_parse: Option<&str>,
) -> Result<(), DemoError> {
    if !SCENARIOS.iter().any(|s| s.id == scenario_id) {
        return Err(DemoError::UnknownScenario);
    }
    if p.operation.as_deref().is_some_and(|s| s.len() > MAX_OP) {
        return Err(DemoError::Oversized("operation"));
    }
    if p.target.as_deref().is_some_and(|s| s.len() > MAX_TARGET) {
        return Err(DemoError::Oversized("target"));
    }
    if p.claimed_class
        .as_deref()
        .is_some_and(|s| s.len() > MAX_CLASS)
    {
        return Err(DemoError::Oversized("claimed_class"));
    }
    if p.refusal.as_deref().is_some_and(|s| s.len() > MAX_REFUSAL) {
        return Err(DemoError::Oversized("refusal"));
    }
    if variant.is_some_and(|s| s.len() > MAX_VARIANT) {
        return Err(DemoError::Oversized("prompt_variant_id"));
    }
    if meta.is_some_and(|s| s.len() > MAX_META) {
        return Err(DemoError::Oversized("model_metadata"));
    }
    if model_parse.is_some_and(|s| s.len() > MAX_PARSE) {
        return Err(DemoError::Oversized("model_parse"));
    }
    Ok(())
}

/// The enforcement base grant (recon + read_only_data_access + injection_testing in scope).
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

/// A genuine `SessionAuthorization` from issue + redeem at 10:00:00Z against the active-status
/// base grant. This is a **simulated** tester (fixture keys), not real-world identity proof.
fn simulated_auth() -> SessionAuthorization {
    let mut s = enf_scenario();
    s.set_clock(ISSUE_AT, 2);
    let store = InMemoryChallengeStore::default();
    let prepared = s.prepare();
    let svc = SessionService::new(prepared.verifier(), &store, &OsRandom);
    let c = match svc.issue(&prepared.bundle, SESSION) {
        IssueOutcome::Issued(c) => *c,
        other => panic!("demo fixture issuance must succeed, got {other}"),
    };
    let proof = encode_proof(
        &c.challenge_id,
        &secret("tester-1").sign(RESPONSE_TAG, &c.wire_bytes()),
    );
    match svc.redeem(&prepared.bundle, SESSION, Some(&proof)) {
        SessionDecision::Accept(a) => *a,
        other => panic!("demo fixture redemption must accept, got {other}"),
    }
}

/// Non-panicking asset shorthand → canonical wire bytes. Returns the raw string bytes when the
/// shorthand is not well formed, so the mediator's validate stage rejects it (no effect).
fn target_wire(target: &str) -> Vec<u8> {
    if let Some(v) = safe_asset(target) {
        if let Ok(bytes) = canonical_json(&v) {
            return bytes;
        }
    }
    target.as_bytes().to_vec()
}

fn safe_asset(short: &str) -> Option<Value> {
    if let Some(rest) = short.strip_prefix("web:") {
        let (scheme, rest) = rest.split_once("://")?;
        let slash = rest.find('/').unwrap_or(rest.len());
        let (hostport, path) = rest.split_at(slash);
        let (host, port) = hostport.rsplit_once(':')?;
        let path = if path.is_empty() { "/" } else { path };
        let port: u64 = port.parse().ok()?;
        Some(json!({"host": host, "kind": "web", "path": path, "port": port, "scheme": scheme}))
    } else if let Some(rest) = short.strip_prefix("db:") {
        let parts: Vec<&str> = rest.split('/').collect();
        let mut v = json!({"cluster": parts[0], "kind": "db"});
        if let Some(d) = parts.get(1) {
            v["database"] = json!(d);
        }
        if let Some(sc) = parts.get(2) {
            v["schema"] = json!(sc);
        }
        Some(v)
    } else {
        None
    }
}

fn claimed_class(name: Option<&str>) -> Option<TestClass> {
    match name? {
        "recon" => Some(TestClass::Recon),
        "auth_testing" => Some(TestClass::AuthTesting),
        "injection_testing" => Some(TestClass::InjectionTesting),
        "read_only_data_access" => Some(TestClass::ReadOnlyDataAccess),
        "data_modification" => Some(TestClass::DataModification),
        "availability_stress" => Some(TestClass::AvailabilityStress),
        _ => None,
    }
}

/// Run `mediate` for a proposal in the given mediation scenario `s` (clock/status already set),
/// using the default in-memory status source. Returns (decision string, before, after, ms).
fn mediate_default(
    s: &Scenario,
    auth: &SessionAuthorization,
    p: &Proposal,
) -> (String, usize, usize, u128) {
    let prepared = s.prepare();
    let store = InMemorySessionAuthStore::default();
    store.insert(SESSION, auth.clone());
    let sink = EffectSink::new();
    let med = Mediator {
        chain: prepared.verifier(),
        sessions: &store,
        sink: &sink,
    };
    run_mediation(&med, &sink, &prepared, p)
}

/// RQ7 freshness-aware mediation: P validates an R-signed status response for G (here a stale
/// one, so the chain is Indeterminate). Returns (decision string, before, after, ms).
fn mediate_stale_freshness(
    auth: &SessionAuthorization,
    p: &Proposal,
) -> (String, usize, usize, u128) {
    let mut s = enf_scenario();
    s.set_clock(MED_AT, 2);
    let keys = |t, spec: &_| crate::experiment::fixture::registration_key(t, spec).expect("id");
    let ak = keys(
        crate::codec::TypeTag::AdminDelegation,
        s.admin.as_ref().unwrap(),
    );
    let dk = keys(
        crate::codec::TypeTag::IssuerDelegation,
        s.issuer.as_ref().unwrap(),
    );
    let gk = keys(
        crate::codec::TypeTag::EngagementGrant,
        s.grant.as_ref().unwrap(),
    );
    let fresh = |k: &_| {
        SignedResponse::build(
            &secret(RESPONDER),
            k,
            ResponderStatus::Active,
            1,
            ts("2026-10-15T09:59:00Z"),
            ts("2026-10-15T09:59:00Z"),
            ts("2026-10-15T11:00:00Z"),
        )
    };
    let mut responder = StatusResponder::new();
    responder.insert(ak.clone(), fresh(&ak));
    responder.insert(dk.clone(), fresh(&dk));
    // G response is stale (expired for the whole interval).
    responder.insert(
        gk.clone(),
        SignedResponse::build(
            &secret(RESPONDER),
            &gk,
            ResponderStatus::Active,
            1,
            ts("2026-10-15T09:59:00Z"),
            ts("2026-10-15T09:59:00Z"),
            ts("2026-10-15T09:59:58Z"),
        ),
    );
    let mut pins = std::collections::HashMap::new();
    pins.insert(
        crate::experiment::fixture::ACME.to_owned(),
        secret(RESPONDER).public_bytes(),
    );
    let hwm = HwmStore::new();
    let oracle = FreshnessOracle {
        responder: &responder,
        pinned: &pins,
        f_seconds: DEFAULT_F_SECONDS,
        hwm: &hwm,
    };
    let clock = FixedClock {
        reading: Some(ClockReading {
            now: ts(MED_AT),
            epsilon: 2,
        }),
    };
    let bundle = s.build();
    let store = InMemorySessionAuthStore::default();
    store.insert(SESSION, auth.clone());
    let sink = EffectSink::new();
    let med = Mediator {
        chain: ChainVerifier {
            audience: P_AUD,
            evidence: Evidence {
                registry: &s.registry,
                bindings: &s.bindings,
                clock: &clock,
                status: &oracle,
            },
        },
        sessions: &store,
        sink: &sink,
    };
    let before = sink.len();
    let op = p.operation.clone().unwrap_or_default();
    let tw = p.target.as_deref().map(target_wire).unwrap_or_default();
    let req = MediationRequest {
        bundle,
        operation: op,
        target_wire: tw,
        claimed_class: claimed_class(p.claimed_class.as_deref()),
    };
    let t = Instant::now();
    let decision = med.mediate(SESSION, &req);
    let ms = t.elapsed().as_millis();
    let after = sink.len();
    (decision.to_string(), before, after, ms)
}

fn run_mediation(
    med: &Mediator,
    sink: &EffectSink,
    prepared: &Prepared,
    p: &Proposal,
) -> (String, usize, usize, u128) {
    let before = sink.len();
    let op = p.operation.clone().unwrap_or_default();
    let tw = p.target.as_deref().map(target_wire).unwrap_or_default();
    let req = MediationRequest {
        bundle: prepared.bundle.clone(),
        operation: op,
        target_wire: tw,
        claimed_class: claimed_class(p.claimed_class.as_deref()),
    };
    let t = Instant::now();
    let decision = med.mediate(SESSION, &req);
    let ms = t.elapsed().as_millis();
    let after = sink.len();
    (decision.to_string(), before, after, ms)
}

/// Decide one untrusted proposal in a fixed synthetic scenario. Never performs a real effect.
pub fn run(
    run_id: &str,
    scenario_id: &str,
    proposal: &Proposal,
    prompt_variant_id: Option<&str>,
    model_metadata: Option<&str>,
    model_parse: Option<&str>,
) -> Result<RunRecord, DemoError> {
    check_bounds(
        scenario_id,
        proposal,
        prompt_variant_id,
        model_metadata,
        model_parse,
    )?;

    let record =
        |parse_status: &str, decision: String, before: usize, after: usize, ms: u128| RunRecord {
            run_id: run_id.to_owned(),
            scenario_id: scenario_id.to_owned(),
            fixture_version: FIXTURE_VERSION.to_owned(),
            prompt_variant_id: prompt_variant_id.map(str::to_owned),
            model_metadata: model_metadata.map(str::to_owned),
            model_parse: model_parse.map(str::to_owned),
            proposal: proposal.clone(),
            parse_status: parse_status.to_owned(),
            decision,
            effects_before: before,
            effects_after: after,
            effects_delta: after - before,
            verify_ms: ms,
        };

    // No operation proposed → never mediated, so no effect can occur. An explicit refusal and a
    // plain no-call (including empty model content) are classified separately; neither is treated
    // as the other, and empty content is a no-call, not evidence of a refusal.
    if proposal.operation.is_none() {
        let (status, note) = if proposal.refusal.is_some() {
            (
                "refusal",
                "no mediation: model explicitly refused (no tool call)",
            )
        } else {
            (
                "no_call",
                "no mediation: no tool call (no operation proposed)",
            )
        };
        return Ok(record(status, note.to_owned(), 0, 0, 0));
    }

    let auth = simulated_auth();
    let (decision, before, after, ms) = match scenario_id {
        "fresh" => {
            let mut s = enf_scenario();
            s.set_clock(MED_AT, 2);
            mediate_default(&s, &auth, proposal)
        }
        "expired_session" => {
            let mut s = enf_scenario();
            s.set_clock(EXPIRED_AT, 0);
            mediate_default(&s, &auth, proposal)
        }
        "revoked_grant" => {
            let mut s = enf_scenario();
            s.set_clock(MED_AT, 2);
            s.status.grant = Some(ObjStatus::Revoked);
            mediate_default(&s, &auth, proposal)
        }
        "unavailable_status" => {
            let mut s = enf_scenario();
            s.set_clock(MED_AT, 2);
            s.status.unavailable = true;
            mediate_default(&s, &auth, proposal)
        }
        "stale_status" => mediate_stale_freshness(&auth, proposal),
        _ => unreachable!("scenario id checked in check_bounds"),
    };
    Ok(record("tool_call", decision, before, after, ms))
}

/// The `GET /v1/scenarios` body: ids, descriptions, and the fixture version. No key bytes.
pub fn scenarios_json() -> Value {
    json!({
        "fixture_version": FIXTURE_VERSION,
        "scenarios": SCENARIOS.iter().map(|s| json!({"id": s.id, "description": s.description})).collect::<Vec<_>>(),
    })
}
