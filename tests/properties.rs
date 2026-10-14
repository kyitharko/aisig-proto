//! Property-based tests (docs/experiment.md §8). Expected outcomes are fixed by the
//! generator or mutation kind, never computed by the comparator under test.
//! Seed: AISIG_PROPTEST_SEED (default below); failure persistence is disabled.

use aisig_proto::decision::{Decision, DecisionClass, Obj, Reason, Slot, Stage};
use aisig_proto::experiment::fixture::*;
use aisig_proto::model::{Ts, MAX_RPS};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};
use serde_json::{json, Value};

const DEFAULT_SEED: u64 = 0x5EED_2026_1015;

fn config() -> Config {
    let seed = std::env::var("AISIG_PROPTEST_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED);
    eprintln!("properties proptest rng_seed = {seed}");
    Config {
        cases: 128,
        rng_seed: RngSeed::Fixed(seed),
        failure_persistence: None,
        ..Config::default()
    }
}

const WEB_TARGETS: &[&str] = &[
    "/app",
    "/app/reports",
    "/app/search/v1",
    "/app/api",
    "/app/docs/guide",
];
/// None of these contains any WEB_TARGETS entry, so every generated grant is admissible.
const EXTRA_EXCLUSIONS: &[&str] = &[
    "/app/private",
    "/app/reports/old",
    "/app/api/internal",
    "/app/search/v1/debug",
];
const CEILING: &[&str] = &[
    "recon",
    "auth_testing",
    "injection_testing",
    "read_only_data_access",
];

/// Parameters of a grant that is valid under the base D_U by construction.
#[derive(Debug, Clone)]
struct ValidGrant {
    web: Vec<bool>,
    db: bool,
    extra_exclusions: Vec<bool>,
    classes: Vec<bool>,
    start_back: i64,
    end_fwd: i64,
    rps: Option<(u64, bool)>,
}

fn valid_grant() -> impl Strategy<Value = ValidGrant> {
    (
        prop::collection::vec(any::<bool>(), WEB_TARGETS.len()),
        any::<bool>(),
        prop::collection::vec(any::<bool>(), EXTRA_EXCLUSIONS.len()),
        prop::collection::vec(any::<bool>(), CEILING.len()),
        3i64..=3 * 86_400,
        3i64..=3 * 86_400,
        prop::option::of((1u64..=1000, any::<bool>())),
    )
        .prop_map(
            |(web, db, extra_exclusions, classes, start_back, end_fwd, rps)| ValidGrant {
                web,
                db,
                extra_exclusions,
                classes,
                start_back,
                end_fwd,
                rps,
            },
        )
}

const NOW: &str = "2026-10-15T10:00:00Z";

impl ValidGrant {
    fn window(&self) -> (Ts, Ts) {
        let now = ts(NOW).0;
        (Ts(now - self.start_back), Ts(now + self.end_fwd))
    }

    fn scenario(&self) -> Scenario {
        let mut s = Scenario::base();
        let mut targets: Vec<Value> = WEB_TARGETS
            .iter()
            .zip(&self.web)
            .filter(|(_, on)| **on)
            .map(|(p, _)| web(p))
            .collect();
        if self.db || targets.is_empty() {
            targets.push(asset("db:cluster1/main/billing"));
        }
        let mut exclusions: Vec<Value> = EXTRA_EXCLUSIONS
            .iter()
            .zip(&self.extra_exclusions)
            .filter(|(_, on)| **on)
            .map(|(p, _)| web(p))
            .collect();
        if self.web[0] {
            exclusions.push(web("/app/admin")); // mandatory when /app is targeted
        }
        put(s.grant(), "targets", set(targets));
        if exclusions.is_empty() {
            del(s.grant(), "exclusions");
        } else {
            put(s.grant(), "exclusions", set(exclusions));
        }
        let mut classes: Vec<Value> = CEILING
            .iter()
            .zip(&self.classes)
            .filter(|(_, on)| **on)
            .map(|(c, _)| json!(c))
            .collect();
        if classes.is_empty() {
            classes.push(json!("recon"));
        }
        put(
            s.grant(),
            "test_scope",
            json!({"classes": set(classes), "kind": "classes"}),
        );
        let (start, end) = self.window();
        put(
            s.grant(),
            "window",
            json!({"end": end.to_string(), "start": start.to_string()}),
        );
        if let Some((v, critical)) = self.rps {
            put(
                s.grant(),
                "constraints",
                json!([constraint(MAX_RPS, critical, &v.to_string())]),
            );
        }
        s
    }
}

fn obj_of(slot: Slot) -> Obj {
    match slot {
        Slot::Root => Obj::Root,
        Slot::Admin => Obj::Admin,
        Slot::Issuer => Obj::Issuer,
        Slot::Grant => Obj::Grant,
    }
}

fn chain_slot() -> impl Strategy<Value = Slot> {
    prop_oneof![Just(Slot::Admin), Just(Slot::Issuer), Just(Slot::Grant)]
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn generated_valid_chains_accept(g in valid_grant()) {
        prop_assert_eq!(g.scenario().run(), Decision::Accept);
    }

    #[test]
    fn signature_bit_flip_rejects_at_signature_stage(g in valid_grant(), slot in chain_slot(), bit in 0usize..512) {
        let mut s = g.scenario();
        s.post.push(PostOp::FlipSigBit(slot, bit));
        prop_assert_eq!(s.run(), Decision::reject(Stage::Signature, Reason::InvalidSignature(obj_of(slot))));
    }

    #[test]
    fn payload_bit_flip_rejects_before_policy(g in valid_grant(), slot in chain_slot(), bit in any::<usize>()) {
        let mut s = g.scenario();
        s.post.push(PostOp::FlipPayloadBit(slot, bit));
        let d = s.run();
        prop_assert_eq!(d.class(), DecisionClass::Reject, "got {}", d);
        let stage = d.finding().unwrap().stage;
        prop_assert!(matches!(stage, Stage::Format | Stage::Anchor | Stage::Signature), "got {}", d);
    }

    #[test]
    fn target_outside_envelope_rejects(g in valid_grant(), n in 0u32..1000) {
        let mut s = g.scenario();
        add_to_set(s.grant(), "targets", web(&format!("/other{n}")));
        prop_assert_eq!(s.run(), Decision::reject(Stage::Policy, Reason::TargetOutsideEnvelope));
    }

    #[test]
    fn clock_outside_window_rejects(g in valid_grant(), delta in 0i64..3600, after in any::<bool>()) {
        let mut s = g.scenario();
        let (start, end) = g.window();
        let eps = 2;
        let (now, want) = if after {
            (Ts(end.0 + eps + delta), Reason::Expired(Obj::Grant))
        } else {
            (Ts(start.0 - eps - 1 - delta), Reason::NotYetValid(Obj::Grant))
        };
        s.set_clock(&now.to_string(), eps);
        prop_assert_eq!(s.run(), Decision::reject(Stage::Time, want));
    }

    #[test]
    fn unavailable_evidence_never_accepts(g in valid_grant(), which in 0u8..4) {
        let mut s = g.scenario();
        let want = match which {
            0 => { s.registry.unavailable = true; Decision::indeterminate(Stage::Anchor, Reason::RegistryUnavailable) }
            1 => { s.bindings.unavailable = true; Decision::indeterminate(Stage::Binding, Reason::BindingUnavailable) }
            2 => { s.clock.reading = None; Decision::indeterminate(Stage::Time, Reason::ClockUnavailable) }
            _ => { s.status.unavailable = true; Decision::indeterminate(Stage::Status, Reason::StatusUnavailable) }
        };
        prop_assert_eq!(s.run(), want);
    }
}
