//! Hand-written case mutations (docs/experiment.md §4). Each one transforms the base
//! scenario; none calls the verifier or its comparators. Expected labels live separately
//! in tests/cases/reviewed_cases.toml.

use serde_json::json;

use crate::codec::TypeTag;
use crate::decision::Slot;
use crate::evidence::{ObjStatus, RootStatus};
use crate::model::MAX_RPS;

use super::fixture::*;

/// All chain-case ids, in table order.
pub const CHAIN_CASE_IDS: &[&str] = &[
    "V01", "V02", "V03", "V04", "V05", "V06", "V07", "V08", "V09", "V10", //
    "R01", "R02", "R03", "R04", "R05", "R06", "R07", "R08", //
    "S01", "S02", "S03", "S04", "S05", "S06", "S07", //
    "D01", "D02", "D03", "D04", "D05", "D06", "D07", "D08", "D09", "D10", "D11", //
    "M01", "M02", "M03", "M04", "M05", "M06", "M07", "M08", "M09", "M10", "M11", "M12", "M13",
    "M14", "M15", "M16", "M17", "M18", "M19", "M20", "M21", //
    "T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09", "T10", "T11", //
    "X01", "X02", "X03", "X04", "X05", "X06", "X07", "X08", "X09", //
    "A01", "A02", "A03", //
    "F01", "F02", "F03", "F04", "F05", "F06", "F07", //
    "B01", "B02", "B03", //
    "P01", "P02", "P03",
];

const APP: &str = "web:https://app.acme.test:443/app";
const BILLING: &str = "db:cluster1/main/billing";

/// Replace one grant target (by shorthand) with another raw asset value.
fn replace_target(s: &mut Scenario, old: &str, new: serde_json::Value) {
    let old = asset(old);
    let mut items: Vec<_> = field(s.grant(), "targets")
        .as_array()
        .expect("targets")
        .iter()
        .filter(|a| **a != old)
        .cloned()
        .collect();
    items.push(new);
    put(s.grant(), "targets", set(items));
}

fn add_everywhere(s: &mut Scenario, short: &str) {
    add_to_set(s.admin(), "bounds.included", asset(short));
    add_to_set(s.issuer(), "envelope.included", asset(short));
    add_to_set(s.grant(), "targets", asset(short));
}

/// Register only the original base G (Active), not the re-signed G that the caller
/// will produce by mutating the grant payload.
fn reissue_grant_keeping_original_status(s: &mut Scenario) {
    let original = s.grant_spec().clone();
    s.status
        .extra
        .push((TypeTag::EngagementGrant, original, ObjStatus::Active));
    s.status.grant = None;
}

/// Apply the mutation for `id`. Returns false for an unknown id.
pub fn apply(id: &str, s: &mut Scenario) -> bool {
    match id {
        // ---- V: valid chains
        "V01" => {}
        "V02" => {
            put(s.grant(), "targets", set(vec![web("/app/reports")]));
            del(s.grant(), "exclusions");
        }
        "V03" => {
            put(s.grant(), "targets", set(vec![asset(BILLING)]));
            del(s.grant(), "exclusions");
        }
        "V04" => add_to_set(s.grant(), "exclusions", web("/app/search")),
        "V05" => put(
            s.grant(),
            "constraints",
            json!([constraint("x-note", false, "synthetic")]),
        ),
        "V06" => {
            del(s.admin(), "bounds.test_ceiling");
            del(s.issuer(), "envelope.test_ceiling");
            put(s.grant(), "test_scope", json!({"kind": "unrestricted"}));
        }
        "V07" => put(s.grant(), "window.end", json!("2026-10-22T09:00:00Z")),
        "V08" => put(
            s.grant(),
            "constraints",
            json!([constraint(MAX_RPS, true, "10")]),
        ),
        "V09" => s
            .post
            .push(PostOp::SetRaw(Slot::Root, b"not an envelope".to_vec())),
        "V10" => s.root = None,

        // ---- R: root / anchor
        "R01" => {
            s.root_spec().payload = root_payload(ACME, "attacker");
            s.root_spec().signer = "attacker".into();
            s.admin_spec().signer = "attacker".into();
            put(s.admin(), "issuer_key_id", json!(kid("attacker")));
        }
        "R02" => {
            s.root_spec().payload = root_payload(INITECH, "initech-root");
            s.root_spec().signer = "initech-root".into();
            put(s.admin(), "org_id", json!(INITECH));
            put(s.admin(), "issuer_key_id", json!(kid("initech-root")));
            put(s.admin(), "subject_key", json!(pub_b64("initech-admin")));
            s.admin_spec().signer = "initech-root".into();
            put(s.issuer(), "org_id", json!(INITECH));
            put(s.issuer(), "issuer_key_id", json!(kid("initech-admin")));
            put(
                s.issuer(),
                "subject_key",
                json!(pub_b64("initech-authorizer")),
            );
            s.issuer_spec().signer = "initech-admin".into();
            put(s.grant(), "org_id", json!(INITECH));
            put(s.grant(), "issuer_key_id", json!(kid("initech-authorizer")));
            s.grant_spec().signer = "initech-authorizer".into();
        }
        "R03" => s.acme_record().status = RootStatus::Revoked,
        "R04" => s.registry.unavailable = true,
        "R05" => s.acme_record().validity.end = ts("2026-10-15T09:30:00Z"),
        "R06" => s.acme_record().usage = "tls-server".into(),
        "R07" => s.acme_record().org_id = GLOBEX.into(),
        "R08" => s.acme_record().algorithm = "Ed448".into(),

        // ---- S: signature and encoding
        "S01" => s.post.push(PostOp::FlipSigBit(Slot::Grant, 0)),
        "S02" => s.issuer_spec().signer = "acme-authorizer".into(),
        "S03" => {
            let mut widened = s.admin().clone();
            add_to_set(&mut widened, "bounds.included", asset("db:cluster2"));
            s.post
                .push(PostOp::ReplacePayloadKeepSig(Slot::Admin, widened));
        }
        "S04" => s.grant_spec().alg = "Ed448".into(),
        "S05" => s.grant_spec().encoding = Encoding::Pretty,
        "S06" => {
            let canonical = crate::codec::canonical_json(s.grant()).expect("canonical");
            let text = String::from_utf8(canonical).expect("utf8");
            let dup = format!("{{\"engagement_id\":\"eng-dup\",{}", &text[1..]);
            s.grant_spec().encoding = Encoding::Raw(dup.into_bytes());
        }
        "S07" => s.grant_spec().sign_tag = "IssuerDelegation".into(),

        // ---- D: delegation and linkage
        "D01" => put(s.admin(), "rights", json!(["account_administration"])),
        "D02" => put(s.issuer(), "issuer_key_id", json!(kid("attacker"))),
        "D03" => put(s.issuer(), "parent.id", json!("ca-acme-999")),
        "D04" => put(s.admin(), "version", json!(2)),
        "D05" => add_to_set(s.issuer(), "envelope.included", asset("db:cluster2")),
        "D06" => add_to_set(
            s.issuer(),
            "envelope.test_ceiling",
            json!("availability_stress"),
        ),
        "D07" => put(s.issuer(), "validity.end", json!("2027-01-15T00:00:00Z")),
        "D08" => put(
            s.issuer(),
            "envelope.max_engagement_seconds",
            json!(5_184_000),
        ),
        "D09" => {
            s.issuer = None;
            put(s.grant(), "parent", json!({"id": ADMIN_ID, "version": 1}));
            put(s.grant(), "issuer_key_id", json!(kid("acme-admin")));
            s.grant_spec().signer = "acme-admin".into();
        }
        "D10" => s.post.push(PostOp::Copy {
            from: Slot::Issuer,
            to: Slot::Grant,
        }),
        "D11" => put(s.grant(), "issuer_key_id", json!(kid("acme-admin"))),

        // ---- M: MayIssue, scope and asset syntax
        "M01" => add_to_set(s.grant(), "targets", asset("db:cluster1/main/hr")),
        "M02" => put(s.grant(), "org_id", json!(GLOBEX)),
        "M03" => replace_target(s, APP, web("/application")),
        "M04" => {
            put(s.grant(), "targets", set(vec![web("/app/admin")]));
            del(s.grant(), "exclusions");
        }
        "M05" => put(s.grant(), "exclusions", set(vec![web("/app/private")])),
        "M06" => put(
            s.grant(),
            "exclusions",
            set(vec![web("/app/admin/settings"), web("/app/private")]),
        ),
        "M07" => add_to_set(s.grant(), "test_scope.classes", json!("data_modification")),
        "M08" => del(s.grant(), "test_scope"),
        "M09" => put(s.grant(), "window.end", json!("2026-10-23T09:00:00Z")),
        "M10" => replace_target(s, APP, asset("web:https://APP.acme.test:443/app")),
        "M11" => replace_target(s, APP, web("/app/../admin")),
        "M12" => replace_target(s, APP, asset("web:https://*.acme.test:443/app")),
        "M13" => replace_target(s, APP, asset("web:https://app.acme.test:8443/app")),
        "M14" => replace_target(s, APP, asset("web:http://app.acme.test:443/app")),
        "M15" => replace_target(s, BILLING, asset("db:cluster1/main")),
        "M16" => put(s.issuer(), "envelope.included", set(vec![web("/app")])),
        "M17" => {
            put(
                s.issuer(),
                "constraints",
                json!([constraint(MAX_RPS, true, "5")]),
            );
            put(
                s.grant(),
                "constraints",
                json!([constraint(MAX_RPS, true, "10")]),
            );
        }
        "M18" => put(
            s.issuer(),
            "constraints",
            json!([constraint(MAX_RPS, true, "5")]),
        ),
        "M19" => replace_target(s, APP, web("/app/")),
        "M20" => add_to_set(s.grant(), "targets", web("/app/private")),
        "M21" => put(s.grant(), "test_scope", json!({"kind": "unrestricted"})),

        // ---- T: time
        "T01" => s.set_clock("2026-10-15T08:59:00Z", 2),
        "T02" => s.set_clock("2026-10-15T11:00:00Z", 0),
        "T03" => s.set_clock("2026-10-15T09:00:00Z", 0),
        "T04" => s.set_clock("2026-10-15T10:59:59Z", 2),
        "T05" => s.set_clock("2026-10-15T09:00:01Z", 2),
        "T06" => put(
            s.grant(),
            "window",
            json!({"end": "2026-10-15T09:00:00Z", "start": "2026-10-15T11:00:00Z"}),
        ),
        "T07" => put(s.grant(), "window.start", json!("2026-10-15T09:00:00")),
        "T08" => put(
            s.grant(),
            "window.start",
            json!("2026-10-15T15:30:00+06:30"),
        ),
        "T09" => put(s.issuer(), "validity.end", json!("2026-10-15T10:30:00Z")),
        "T10" => s.clock.reading = None,
        "T11" => put(s.grant(), "window.start", json!("2026-10-15T09:00:00.000Z")),

        // ---- X: status
        "X01" => s.status.grant = Some(ObjStatus::Revoked),
        "X02" => s.status.issuer = Some(ObjStatus::Revoked),
        "X03" => s.status.admin = Some(ObjStatus::Revoked),
        "X04" => s.status.unavailable = true,
        "X05" => s.status.grant = None,
        "X06" => s.status.admin = Some(ObjStatus::Superseded),
        "X07" => {
            // New G reusing C_A's id/version; no record for this G (C_A keeps its own).
            put(s.grant(), "id", json!(ADMIN_ID));
            s.status.grant = None;
        }
        "X08" => {
            reissue_grant_keeping_original_status(s);
            put(s.grant(), "tester_key", json!(pub_b64("tester-2")));
        }
        "X09" => {
            reissue_grant_keeping_original_status(s);
            put(
                s.grant(),
                "test_scope.classes",
                set(vec![json!("auth_testing"), json!("recon")]),
            );
        }

        // ---- A: audience
        "A01" => put(s.grant(), "audience", json!(Q_AUD)),
        "A02" => put(s.issuer(), "audience", json!(Q_AUD)),
        "A03" => del(s.grant(), "audience"),

        // ---- F: fields and constraints
        "F01" => put(
            s.grant(),
            "constraints",
            json!([constraint("x-geo-fence", true, "zone-a")]),
        ),
        "F02" => put(
            s.issuer(),
            "constraints",
            json!([constraint("x-geo-fence", true, "zone-a")]),
        ),
        "F03" => put(s.grant(), "scan_everything", json!(true)),
        "F04" => put(s.grant(), "format", json!("aisig/v1")),
        "F05" => del(s.grant(), "tester_key"),
        "F06" => put(
            s.grant(),
            "constraints",
            json!([
                constraint(MAX_RPS, true, "10"),
                constraint(MAX_RPS, true, "20")
            ]),
        ),
        "F07" => add_to_set(s.grant(), "test_scope.classes", json!("zero_day_deploy")),

        // ---- B: asset binding
        "B01" => add_everywhere(s, "web:https://legacy.acme.test:443/"),
        "B02" => add_everywhere(s, "web:https://shop.globex.test:443/"),
        "B03" => s.bindings.unavailable = true,

        // ---- P: precedence (two factors)
        "P01" => {
            apply("S01", s);
            apply("X04", s);
        }
        "P02" => {
            apply("B01", s);
            s.set_clock("2026-10-15T11:00:00Z", 0);
        }
        "P03" => {
            apply("R04", s);
            apply("M01", s);
        }

        _ => return false,
    }
    true
}

/// The base scenario with case `id` applied.
pub fn scenario_for(id: &str) -> Option<Scenario> {
    let mut s = Scenario::base();
    apply(id, &mut s).then_some(s)
}
