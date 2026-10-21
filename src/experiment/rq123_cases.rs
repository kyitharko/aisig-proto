//! Synthetic RQ1–RQ3 case runner. Labels were committed before this runner.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::asset_authority::{
    AssetManifest, AssetRecord, AssetRequest, AuthorityBundle, AuthorityVerifier, ExactRef,
    Outcome, Role, RoleDelegation,
};
use crate::codec::{
    b64_decode, b64_encode, canonical_bytes, canonical_json, canonical_sort, EnvelopeWire, SigWire,
    TypeTag,
};
use crate::crypto;
use crate::evidence::{
    ClockReading, FixedClock, InMemoryRegistry, InMemoryStatus, ObjStatus, RootRecord, RootStatus,
    StatusKey,
};
use crate::experiment::fixture::{
    asset_ref, kid, public_key, secret, ts, window, ACME, P_AUD, Q_AUD,
};
use crate::model::{AssetRef, TestClass, Window};
use crate::verifier::ROOT_USAGE;

pub const CASES_PATH: &str = "tests/cases/rq123_cases.toml";
const FORMAT: &str = "aisig-rq123/v1";
const MANIFEST_FORMAT: &str = "aisig-asset-manifest/v1";
const A: &str = "web:https://app.acme.test:443/app/reports";
const B: &str = "db:cluster1/main/billing";

#[derive(Clone, Debug, Deserialize)]
pub struct Label {
    pub id: String,
    pub mutation: String,
    pub expected: String,
    pub label_status: String,
}

#[derive(Deserialize)]
struct Labels {
    cases: Vec<Label>,
}

#[derive(Serialize)]
pub struct Row {
    pub id: String,
    pub mutation: String,
    pub label_status: String,
    pub expected: String,
    pub actual: String,
    pub match_label: bool,
}

pub fn load_default() -> Result<Vec<Label>, String> {
    let text = std::fs::read_to_string(CASES_PATH).map_err(|e| e.to_string())?;
    let parsed: Labels = toml::from_str(&text).map_err(|e| e.to_string())?;
    Ok(parsed.cases)
}

fn signed<T: Serialize>(tag: TypeTag, body: &T, signer: &str) -> (Vec<u8>, Vec<u8>) {
    let payload = canonical_bytes(body).expect("fixture canonical payload");
    let signature = secret(signer).sign(tag.as_str(), &payload);
    let env = EnvelopeWire {
        payload: b64_encode(&payload),
        sig: SigWire {
            alg: "Ed25519".to_owned(),
            key_id: kid(signer),
            value: b64_encode(&signature),
        },
        type_tag: tag.as_str().to_owned(),
    };
    (env.to_bytes(), payload)
}

fn exact(id: &str, version: u32, tag: TypeTag, payload: &[u8]) -> ExactRef {
    ExactRef {
        id: id.to_owned(),
        version,
        digest: hex::encode(crypto::object_digest(tag.as_str(), payload)),
    }
}

fn snapshot_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"aisig-asset-manifest/v1\0");
    h.update(bytes);
    hex::encode(h.finalize())
}

fn read_classes() -> Vec<TestClass> {
    let mut classes = vec![TestClass::Recon, TestClass::ReadOnlyDataAccess];
    canonical_sort(&mut classes);
    classes
}

fn root_registry() -> InMemoryRegistry {
    let mut records = HashMap::new();
    records.insert(
        ACME.to_owned(),
        RootRecord {
            org_id: ACME.to_owned(),
            root_key: public_key("acme-root"),
            key_id: kid("acme-root"),
            algorithm: "Ed25519".to_owned(),
            validity: window("2026-01-01T00:00:00Z", "2027-12-31T00:00:00Z"),
            usage: ROOT_USAGE.to_owned(),
            version: 1,
            evidence_ref: "synthetic-manual-vetting-assumption".to_owned(),
            accepted_at: ts("2026-01-01T00:00:00Z"),
            status: RootStatus::Active,
        },
    );
    InMemoryRegistry {
        records,
        unavailable: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn edge(
    id: &str,
    role: Role,
    issuer: &str,
    subject: &str,
    subject_user_id: &str,
    assets: Vec<AssetRef>,
    may_delegate: bool,
    may_register_asset: bool,
) -> RoleDelegation {
    let mut assets = assets;
    canonical_sort(&mut assets);
    RoleDelegation {
        format: FORMAT.to_owned(),
        id: id.to_owned(),
        version: 1,
        org_id: ACME.to_owned(),
        audience: P_AUD.to_owned(),
        issuer_key_id: kid(issuer),
        parent: None,
        role,
        subject_user_id: subject_user_id.to_owned(),
        subject_key: public_key(subject),
        assets,
        classes: read_classes(),
        may_delegate,
        may_register_asset,
        validity: window("2026-10-15T09:00:00Z", "2026-10-15T11:00:00Z"),
    }
}

/// The literal one-to-one mapping is deliberately separate from the verifier.
pub const MUTATIONS: &[&str] = &[
    "senior_1_asset_a",
    "senior_2_asset_b_same_junior",
    "cto_registers_asset_a",
    "unrecognized_root_signs_first_edge",
    "request_signed_by_wrong_key",
    "junior_edge_parent_points_to_other_senior",
    "junior_scope_expands_beyond_senior",
    "asset_b_requested_under_asset_a_path",
    "record_issuer_lacks_registration_right",
    "record_digest_not_manifest_digest",
    "manifest_changed_after_record_signing",
    "senior_edge_expired",
    "senior_edge_revoked",
    "asset_record_status_missing",
    "request_targets_wrong_provider",
    "request_claims_different_user_id",
    "request_uses_record_from_other_path",
    "unrelated_senior_revoked_other_path_still_valid",
    "junior_class_expands_beyond_senior",
    "record_asset_outside_registrar_scope",
    "clock_uncertainty_overlaps_record_expiry",
    "status_source_unavailable",
    "modified_request_payload_keeps_original_signature",
    "malformed_noncanonical_manifest",
    "foreign_signed_record_and_request_on_other_path",
];

pub fn labels_cover_mutations(labels: &[Label]) -> bool {
    let actual: BTreeSet<&str> = labels.iter().map(|l| l.mutation.as_str()).collect();
    let known: BTreeSet<&str> = MUTATIONS.iter().copied().collect();
    actual == known
        && labels.len() == actual.len()
        && labels
            .iter()
            .map(|l| l.id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == labels.len()
}

pub fn run(mutation: &str) -> Outcome {
    assert!(
        MUTATIONS.contains(&mutation),
        "missing RQ123 runner {mutation}"
    );
    let on_b = matches!(
        mutation,
        "senior_2_asset_b_same_junior" | "unrelated_senior_revoked_other_path_still_valid"
    );
    let selected = if on_b { B } else { A };
    let senior_key = if on_b { "senior-2" } else { "senior-1" };
    let permitted = asset_ref(selected);
    let asset_a = asset_ref(A);
    let asset_b = asset_ref(B);

    let mut root_signer = "acme-root";
    let mut junior_scope = permitted.clone();
    let mut senior_register = true;
    let mut record_asset = permitted.clone();
    let mut requested_asset = permitted.clone();
    let mut registrar_idx = 1usize;
    let mut record_signer = senior_key;
    let mut request_signer = "junior";
    let mut request_audience = P_AUD;
    let mut user_id = "user-junior";
    let mut digest_override = false;
    let mut alter_manifest = false;
    let mut expired = false;
    let mut record_overlap = false;
    let mut bad_leaf_parent = false;
    let mut foreign_record = false;
    let mut splice_foreign_record = false;
    let mut tamper_request = false;
    let mut noncanonical_manifest = false;
    let mut senior_revoked = false;
    let mut record_unknown = false;
    let mut status_unavailable = false;
    let mut sibling_revoked = false;
    let mut leaf_expands_class = false;

    match mutation {
        "unrecognized_root_signs_first_edge" => root_signer = "attacker",
        "request_signed_by_wrong_key" => request_signer = "attacker",
        "junior_edge_parent_points_to_other_senior" => bad_leaf_parent = true,
        "junior_scope_expands_beyond_senior" => junior_scope = asset_b.clone(),
        "asset_b_requested_under_asset_a_path" => requested_asset = asset_b.clone(),
        "record_issuer_lacks_registration_right" => senior_register = false,
        "record_digest_not_manifest_digest" => digest_override = true,
        "manifest_changed_after_record_signing" => alter_manifest = true,
        "senior_edge_expired" => expired = true,
        "senior_edge_revoked" => senior_revoked = true,
        "asset_record_status_missing" => record_unknown = true,
        "request_targets_wrong_provider" => request_audience = Q_AUD,
        "request_claims_different_user_id" => user_id = "user-other",
        "request_uses_record_from_other_path" => foreign_record = true,
        "foreign_signed_record_and_request_on_other_path" => splice_foreign_record = true,
        "unrelated_senior_revoked_other_path_still_valid" => sibling_revoked = true,
        "junior_class_expands_beyond_senior" => leaf_expands_class = true,
        "record_asset_outside_registrar_scope" => record_asset = asset_b.clone(),
        "clock_uncertainty_overlaps_record_expiry" => record_overlap = true,
        "status_source_unavailable" => status_unavailable = true,
        "modified_request_payload_keeps_original_signature" => tamper_request = true,
        "malformed_noncanonical_manifest" => noncanonical_manifest = true,
        "cto_registers_asset_a" => {
            registrar_idx = 0;
            record_signer = "cto";
        }
        "senior_1_asset_a" | "senior_2_asset_b_same_junior" => {}
        _ => unreachable!(),
    }

    let mut edges = [
        edge(
            "edge-cto",
            Role::Cto,
            root_signer,
            "cto",
            "user-cto",
            vec![asset_a.clone(), asset_b.clone()],
            true,
            true,
        ),
        edge(
            if on_b {
                "edge-senior-2"
            } else {
                "edge-senior-1"
            },
            Role::Senior,
            "cto",
            senior_key,
            if on_b {
                "user-senior-2"
            } else {
                "user-senior-1"
            },
            vec![permitted.clone()],
            true,
            senior_register,
        ),
        edge(
            "edge-junior",
            Role::Junior,
            senior_key,
            "junior",
            "user-junior",
            vec![junior_scope],
            false,
            false,
        ),
    ];
    if leaf_expands_class {
        edges[2].classes.push(TestClass::DataModification);
        canonical_sort(&mut edges[2].classes);
    }
    if expired {
        let end = ts("2026-10-15T09:30:00Z");
        edges[1].validity.end = end;
        edges[2].validity.end = end;
    }

    let mut signed_edges = Vec::new();
    let mut refs: Vec<ExactRef> = Vec::new();
    for (i, e) in edges.iter_mut().enumerate() {
        if i > 0 {
            e.parent = Some(refs[i - 1].clone());
        }
        if i == 2 && bad_leaf_parent {
            // A validly signed leaf names another Senior's exact edge.
            let mut other = edge(
                "edge-senior-2",
                Role::Senior,
                "cto",
                "senior-2",
                "user-senior-2",
                vec![asset_b.clone()],
                true,
                true,
            );
            other.parent = Some(refs[0].clone());
            let (_, payload) = signed(TypeTag::RoleDelegation, &other, "cto");
            e.parent = Some(exact(&other.id, 1, TypeTag::RoleDelegation, &payload));
        }
        let signer = [root_signer, "cto", senior_key][i];
        let (raw, payload) = signed(TypeTag::RoleDelegation, e, signer);
        refs.push(exact(&e.id, e.version, TypeTag::RoleDelegation, &payload));
        signed_edges.push((raw, payload));
    }

    let mut manifest = AssetManifest {
        format: MANIFEST_FORMAT.to_owned(),
        asset: if record_asset == asset_b {
            asset_b.clone()
        } else {
            permitted.clone()
        },
        asset_version: 1,
        snapshot_marker: if on_b || record_asset == asset_b {
            "synthetic-db-snapshot-one".to_owned()
        } else {
            "synthetic-web-snapshot-one".to_owned()
        },
    };
    let manifest_clean = canonical_bytes(&manifest).expect("fixture manifest");
    let digest = if digest_override {
        "0".repeat(64)
    } else {
        snapshot_digest(&manifest_clean)
    };
    let validity: Window = if expired {
        window("2026-10-15T09:00:00Z", "2026-10-15T09:30:00Z")
    } else if record_overlap {
        window("2026-10-15T09:00:00Z", "2026-10-15T10:00:01Z")
    } else {
        window("2026-10-15T09:00:00Z", "2026-10-15T11:00:00Z")
    };
    let record = AssetRecord {
        format: FORMAT.to_owned(),
        id: "asset-record-one".to_owned(),
        version: 1,
        org_id: ACME.to_owned(),
        audience: P_AUD.to_owned(),
        issuer_key_id: kid(record_signer),
        registrar: refs[registrar_idx].clone(),
        junior: refs[2].clone(),
        asset: record_asset,
        asset_version: 1,
        manifest_digest: digest.clone(),
        classes: vec![TestClass::ReadOnlyDataAccess],
        validity,
    };
    let (mut record_raw, record_payload) = signed(TypeTag::AssetRecord, &record, record_signer);
    let mut request = AssetRequest {
        format: FORMAT.to_owned(),
        id: "asset-request-one".to_owned(),
        version: 1,
        org_id: ACME.to_owned(),
        audience: request_audience.to_owned(),
        issuer_key_id: kid("junior"),
        subject_user_id: user_id.to_owned(),
        junior: refs[2].clone(),
        record: exact(
            &record.id,
            record.version,
            TypeTag::AssetRecord,
            &record_payload,
        ),
        asset: requested_asset,
        asset_version: 1,
        manifest_digest: digest,
        class: TestClass::ReadOnlyDataAccess,
    };
    let mut foreign_path = None;
    let mut foreign_keys = Vec::new();
    if foreign_record || splice_foreign_record {
        // Construct a genuinely signed B record under B's Senior→Junior path.
        // AA17 names it from A's request; AA25 submits it with the A path.
        let mut other_senior = edge(
            "edge-senior-2",
            Role::Senior,
            "cto",
            "senior-2",
            "user-senior-2",
            vec![asset_b.clone()],
            true,
            true,
        );
        other_senior.parent = Some(refs[0].clone());
        let (other_senior_raw, senior_payload) =
            signed(TypeTag::RoleDelegation, &other_senior, "cto");
        let senior_ref = exact(
            &other_senior.id,
            1,
            TypeTag::RoleDelegation,
            &senior_payload,
        );
        let mut other_junior = edge(
            "edge-junior",
            Role::Junior,
            "senior-2",
            "junior",
            "user-junior",
            vec![asset_b.clone()],
            false,
            false,
        );
        other_junior.parent = Some(senior_ref.clone());
        let (other_junior_raw, junior_payload) =
            signed(TypeTag::RoleDelegation, &other_junior, "senior-2");
        let other_junior_ref = exact(
            &other_junior.id,
            1,
            TypeTag::RoleDelegation,
            &junior_payload,
        );
        let other_manifest = AssetManifest {
            format: MANIFEST_FORMAT.to_owned(),
            asset: asset_b.clone(),
            asset_version: 1,
            snapshot_marker: "synthetic-db-snapshot-one".to_owned(),
        };
        let other_manifest_bytes = canonical_bytes(&other_manifest).unwrap();
        let other_record = AssetRecord {
            id: "asset-record-from-other-path".to_owned(),
            registrar: senior_ref,
            junior: other_junior_ref.clone(),
            asset: asset_b.clone(),
            manifest_digest: snapshot_digest(&other_manifest_bytes),
            issuer_key_id: kid("senior-2"),
            ..record.clone()
        };
        let (other_record_raw, other_payload) =
            signed(TypeTag::AssetRecord, &other_record, "senior-2");
        request.record = exact(&other_record.id, 1, TypeTag::AssetRecord, &other_payload);
        if splice_foreign_record {
            // Unlike AA17, submit the signed B record and its matching signed
            // request with the A path. The same B objects must Accept on B's
            // complete path before this cross-path test counts as meaningful.
            request.junior = other_junior_ref;
            request.asset = asset_b.clone();
            request.manifest_digest = other_record.manifest_digest.clone();
            record_raw = other_record_raw;
            manifest = other_manifest;
            foreign_path = Some(vec![
                signed_edges[0].0.clone(),
                other_senior_raw,
                other_junior_raw,
            ]);
            foreign_keys = vec![
                StatusKey::for_object(
                    ACME,
                    TypeTag::RoleDelegation,
                    &other_senior.id,
                    other_senior.version,
                    &senior_payload,
                ),
                StatusKey::for_object(
                    ACME,
                    TypeTag::RoleDelegation,
                    &other_junior.id,
                    other_junior.version,
                    &junior_payload,
                ),
                StatusKey::for_object(
                    ACME,
                    TypeTag::AssetRecord,
                    &other_record.id,
                    other_record.version,
                    &other_payload,
                ),
            ];
        }
    }
    let (mut request_raw, _) = signed(TypeTag::AssetRequest, &request, request_signer);
    if tamper_request {
        let mut env: EnvelopeWire = serde_json::from_slice(&request_raw).unwrap();
        let mut payload: Value =
            serde_json::from_slice(&b64_decode(&env.payload).unwrap()).unwrap();
        payload["subject_user_id"] = Value::String("tampered-after-signing".to_owned());
        env.payload = b64_encode(&canonical_json(&payload).unwrap());
        request_raw = env.to_bytes();
    }
    if alter_manifest {
        manifest.snapshot_marker = "synthetic-marker-modified".to_owned();
    }
    let manifest_raw = if noncanonical_manifest {
        serde_json::to_vec_pretty(&manifest).unwrap()
    } else {
        canonical_bytes(&manifest).unwrap()
    };

    let mut status = InMemoryStatus::default();
    for (i, (_, payload)) in signed_edges.iter().enumerate() {
        status.entries.insert(
            StatusKey::for_object(ACME, TypeTag::RoleDelegation, &edges[i].id, 1, payload),
            if senior_revoked && i == 1 {
                ObjStatus::Revoked
            } else {
                ObjStatus::Active
            },
        );
    }
    if !record_unknown {
        status.entries.insert(
            StatusKey::for_object(ACME, TypeTag::AssetRecord, &record.id, 1, &record_payload),
            ObjStatus::Active,
        );
    }
    for key in foreign_keys {
        status.entries.insert(key, ObjStatus::Active);
    }
    if sibling_revoked {
        let mut sibling = edge(
            "edge-senior-1",
            Role::Senior,
            "cto",
            "senior-1",
            "user-senior-1",
            vec![asset_a],
            true,
            true,
        );
        sibling.parent = Some(refs[0].clone());
        let (_, payload) = signed(TypeTag::RoleDelegation, &sibling, "cto");
        status.entries.insert(
            StatusKey::for_object(ACME, TypeTag::RoleDelegation, &sibling.id, 1, &payload),
            ObjStatus::Revoked,
        );
    }
    status.unavailable = status_unavailable;
    let clock = FixedClock {
        reading: Some(ClockReading {
            now: ts("2026-10-15T10:00:00Z"),
            epsilon: 2,
        }),
    };
    let registry = root_registry();
    let bundle = AuthorityBundle {
        path: signed_edges.into_iter().map(|(raw, _)| raw).collect(),
        record: record_raw,
        request: request_raw,
        manifest: manifest_raw,
    };
    let verifier = AuthorityVerifier {
        audience: P_AUD,
        registry: &registry,
        clock: &clock,
        status: &status,
    };
    if let Some(path) = foreign_path {
        let valid_b = AuthorityBundle {
            path,
            record: bundle.record.clone(),
            request: bundle.request.clone(),
            manifest: bundle.manifest.clone(),
        };
        assert_eq!(
            verifier.verify(&valid_b),
            Outcome::Accept,
            "AA25 foreign signed objects must work on their own B path"
        );
    }
    verifier.verify(&bundle)
}

pub fn run_all(labels: &[Label]) -> Vec<Row> {
    labels
        .iter()
        .map(|label| {
            let actual = run(&label.mutation).to_string();
            Row {
                id: label.id.clone(),
                mutation: label.mutation.clone(),
                label_status: label.label_status.clone(),
                match_label: label.expected == actual,
                expected: label.expected.clone(),
                actual,
            }
        })
        .collect()
}
