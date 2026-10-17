//! RQ8 Q3 onboarding/cost slice 1 (docs/rq8.md "Q3 measurement slice 1"): canonical artifact
//! byte sizes measured from the actual fixture bytes (OB*), and a per-party step/critical-path
//! map held as data (OS-*, a structural model, not a measurement). No human time, monetary
//! cost, storage bill, or operational effort is inferred from bytes or step counts. Gated
//! against `tests/cases/rq8_onboarding_cases.toml` (proposed, owner review). Synthetic only.

use serde_json::{json, Value};

use crate::codec::b64_decode;
use crate::enforcement::MediationRequest;
use crate::verifier::{decode_chain, Bundle};

use super::cases::CaseLabel;
use super::fixture::{asset, Scenario};
use crate::codec::canonical_json;

pub const RQ8_ONBOARDING_CASES_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/cases/rq8_onboarding_cases.toml"
);

pub const RQ8_ONBOARDING_CASE_IDS: &[&str] = &[
    "OB01", "OB02", "OB03", "OB04", "OB05", "OB06", "OB07", "OB08", "OB09", "OB10", "OB11", "OS-O",
    "OS-A", "OS-U", "OS-T", "OS-P", "OS-R",
];

// ---------------------------------------------------------------------------
// Artifact byte sizes (measured from actual fixture bytes)
// ---------------------------------------------------------------------------

/// All the canonical byte sizes, measured from one built base bundle.
struct Sizes {
    ca_payload: usize,
    ca_envelope: usize,
    du_payload: usize,
    du_envelope: usize,
    g_payload: usize,
    g_envelope: usize,
    root_payload: usize,
    root_envelope: usize,
    signature: usize,
    bundle_total: usize,
}

fn envelope_payload_len(envelope: &[u8]) -> usize {
    let v: Value = serde_json::from_slice(envelope).expect("envelope json");
    let b64 = v
        .get("payload")
        .and_then(Value::as_str)
        .expect("payload b64");
    b64_decode(b64).expect("b64 payload").len()
}

fn measure() -> Sizes {
    let bundle = Scenario::base().build();
    let chain = decode_chain(&bundle).expect("decode base bundle");
    let env = |slot: &Option<Vec<u8>>| slot.as_ref().expect("slot present").len();
    let ca_envelope = env(&bundle.admin);
    let du_envelope = env(&bundle.issuer);
    let g_envelope = env(&bundle.grant);
    let root_envelope = env(&bundle.root);
    Sizes {
        ca_payload: chain.admin().payload().len(),
        ca_envelope,
        du_payload: chain.issuer().payload().len(),
        du_envelope,
        g_payload: chain.grant().payload().len(),
        g_envelope,
        root_payload: envelope_payload_len(bundle.root.as_ref().expect("root slot")),
        root_envelope,
        signature: chain.grant().sig().len(),
        bundle_total: ca_envelope + du_envelope + g_envelope + root_envelope,
    }
}

/// Sum of a request's bundle slot envelopes — the bundle it re-carries (a duplication).
fn request_bundle_bytes() -> usize {
    let bundle = Scenario::base().build();
    let req = MediationRequest {
        bundle,
        operation: "web.get".to_owned(),
        target_wire: canonical_json(&asset("web:https://app.acme.test:443/app")).expect("canon"),
        claimed_class: None,
    };
    let b: &Bundle = &req.bundle;
    [&b.root, &b.admin, &b.issuer, &b.grant]
        .iter()
        .map(|s| s.as_ref().map_or(0, Vec::len))
        .sum()
}

// ---------------------------------------------------------------------------
// Step / critical-path map (structural model, not a measurement)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Tag {
    Implemented,
    AssumedOob,
    DesignOnly,
}

/// The step map of docs/rq8.md Q3 slice 1, as data: (party, tag).
const STEPS: &[(&str, Tag)] = &[
    ("O", Tag::Implemented), // generate K_O
    ("O", Tag::Implemented), // issue C_A (sign K_O)
    ("O", Tag::AssumedOob),  // pin K_O at P (RQ1)
    ("O", Tag::DesignOnly),  // rotate/retire root
    ("A", Tag::Implemented), // admin: hold K_admin
    ("A", Tag::Implemented), // admin: issue D_U (sign K_admin)
    ("U", Tag::Implemented), // issuer: hold K_authorizer
    ("U", Tag::Implemented), // issuer: issue G (sign K_authorizer)
    ("T", Tag::Implemented), // hold K_T
    ("T", Tag::AssumedOob),  // receive G delivery
    ("T", Tag::Implemented), // respond to challenge
    ("P", Tag::AssumedOob),  // pin org root K_O (RQ1)
    ("P", Tag::AssumedOob),  // pin responder K_R (RQ7)
    ("P", Tag::AssumedOob),  // rely on asset-binding evidence (RQ2)
    ("P", Tag::Implemented), // verify chain
    ("P", Tag::Implemented), // query status/freshness
    ("P", Tag::Implemented), // issue+redeem session
    ("P", Tag::Implemented), // mediate action
    ("R", Tag::AssumedOob),  // provisioned / hold K_R
    ("R", Tag::Implemented), // sign status responses
    ("R", Tag::Implemented), // epoch/known-at/expiry discipline
];

fn party_counts(party: &str) -> (usize, usize, usize) {
    let (mut impl_, mut oob, mut design) = (0, 0, 0);
    for (p, tag) in STEPS {
        if *p != party {
            continue;
        }
        match tag {
            Tag::Implemented => impl_ += 1,
            Tag::AssumedOob => oob += 1,
            Tag::DesignOnly => design += 1,
        }
    }
    (impl_, oob, design)
}

fn party_observation(party: &str) -> String {
    let (i, o, d) = party_counts(party);
    format!("party={party} implemented={i} assumed_oob={o} design_only={d}")
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// Run RQ8 onboarding case `id`; `None` for an unknown id.
pub fn run(id: &str) -> Option<String> {
    let s = measure();
    let out = match id {
        "OB01" => format!("cA_signed_payload_bytes={}", s.ca_payload),
        "OB02" => format!("cA_envelope_bytes={}", s.ca_envelope),
        "OB03" => format!("dU_signed_payload_bytes={}", s.du_payload),
        "OB04" => format!("dU_envelope_bytes={}", s.du_envelope),
        "OB05" => format!("g_signed_payload_bytes={}", s.g_payload),
        "OB06" => format!("g_envelope_bytes={}", s.g_envelope),
        "OB07" => format!("root_signed_payload_bytes={}", s.root_payload),
        "OB08" => format!("root_envelope_bytes={}", s.root_envelope),
        "OB09" => format!("signature_bytes={}", s.signature),
        "OB10" => format!("bundle_total_envelope_bytes={}", s.bundle_total),
        // In-memory bundle-slot bytes only; no transmission-cost claim (no wire encoding here).
        "OB11" => format!(
            "mediation_request_bundle_slot_bytes={}",
            request_bundle_bytes()
        ),
        "OS-O" => party_observation("O"),
        "OS-A" => party_observation("A"),
        "OS-U" => party_observation("U"),
        "OS-T" => party_observation("T"),
        "OS-P" => party_observation("P"),
        "OS-R" => party_observation("R"),
        _ => return None,
    };
    Some(out)
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

pub struct OnboardingRow {
    pub label: CaseLabel,
    pub actual: String,
}

pub fn run_all(labels: &[CaseLabel]) -> Vec<OnboardingRow> {
    labels
        .iter()
        .map(|l| OnboardingRow {
            label: l.clone(),
            actual: run(&l.id).unwrap_or_else(|| format!("no runner for {}", l.id)),
        })
        .collect()
}

pub fn render_markdown(rows: &[OnboardingRow]) -> String {
    let matched = rows.iter().filter(|r| r.actual == r.label.expected).count();
    let mut out = String::from(
        "# RQ8 Q3 onboarding/cost slice 1 — step map & artifact sizes (generated)\n\n",
    );
    out.push_str("Generated by `cargo run --release --bin eval`. Labels (proposed) come from ");
    out.push_str("`tests/cases/rq8_onboarding_cases.toml`; method in `docs/rq8.md`. OB* are byte ");
    out.push_str("sizes **measured** from the actual fixture bytes (signed payload / signature / ");
    out.push_str("full envelope / in-memory, stated per label); OS-* are per-party step-map ");
    out.push_str("counts (a structural model, not a measurement). No human/monetary/storage cost ");
    out.push_str("is inferred.\n\n");
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

pub fn render_json(rows: &[OnboardingRow]) -> Value {
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
