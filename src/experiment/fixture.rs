//! The base synthetic fixture (docs/experiment.md §2) and a scenario builder.
//!
//! Payloads are kept as JSON values so mutations can express malformed inputs that the
//! typed model would refuse to represent. All keys derive from public labels and are
//! deliberately insecure test material.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::baseline::verify_signature_only;
use crate::codec::{b64_encode, canonical_json, canonical_sort, EnvelopeWire, SigWire, TypeTag};
use crate::crypto::{self, SecretKey};
use crate::decision::{Decision, Slot};
use crate::evidence::{
    ClockReading, FixedClock, InMemoryBindings, InMemoryRegistry, InMemoryStatus, ObjStatus,
    RootRecord, RootStatus,
};
use crate::model::{AssetRef, PublicKey, Ts, Window};
use crate::verifier::{Bundle, ChainVerifier, Evidence, ROOT_USAGE};

pub const P_AUD: &str = "urn:aisig:provider:p-synthetic";
pub const Q_AUD: &str = "urn:aisig:provider:q-synthetic";
pub const ACME: &str = "org-acme-synthetic";
pub const GLOBEX: &str = "org-globex-synthetic";
pub const INITECH: &str = "org-initech-synthetic";

pub const ADMIN_ID: &str = "ca-acme-001";
pub const ISSUER_ID: &str = "du-acme-001";
pub const GRANT_ID: &str = "g-acme-001";

/// Test-only key: Ed25519 seed = SHA-256("aisig-synthetic-key:" ‖ label).
pub fn secret(label: &str) -> SecretKey {
    let seed: [u8; 32] = Sha256::digest(format!("aisig-synthetic-key:{label}").as_bytes()).into();
    SecretKey::from_seed(&seed)
}

pub fn public_key(label: &str) -> PublicKey {
    PublicKey::from_bytes(secret(label).public_bytes()).expect("derived keys are valid points")
}

pub fn kid(label: &str) -> String {
    crypto::key_id(&secret(label).public_bytes())
}

pub fn pub_b64(label: &str) -> String {
    b64_encode(&secret(label).public_bytes())
}

pub fn ts(s: &str) -> Ts {
    Ts::parse(s).expect("fixture times are canonical")
}

pub fn window(start: &str, end: &str) -> Window {
    Window {
        start: ts(start),
        end: ts(end),
    }
}

/// Shorthand (`web:https://host:port/path`, `db:cluster/db/schema`) to raw asset JSON.
/// Does not validate, so mutations can build non-canonical assets.
pub fn asset(short: &str) -> Value {
    if let Some(rest) = short.strip_prefix("web:") {
        let (scheme, rest) = rest.split_once("://").expect("web shorthand has ://");
        let slash = rest.find('/').unwrap_or(rest.len());
        let (hostport, path) = rest.split_at(slash);
        let (host, port) = hostport.rsplit_once(':').expect("web shorthand has a port");
        let path = if path.is_empty() { "/" } else { path };
        let port: u64 = port.parse().expect("numeric port");
        json!({"host": host, "kind": "web", "path": path, "port": port, "scheme": scheme})
    } else if let Some(rest) = short.strip_prefix("db:") {
        let parts: Vec<&str> = rest.split('/').collect();
        let mut v = json!({"cluster": parts[0], "kind": "db"});
        if let Some(d) = parts.get(1) {
            v["database"] = json!(d);
        }
        if let Some(s) = parts.get(2) {
            v["schema"] = json!(s);
        }
        v
    } else {
        panic!("unknown asset shorthand {short}")
    }
}

/// Shorthand to a validated asset.
pub fn asset_ref(short: &str) -> AssetRef {
    serde_json::from_value(asset(short)).expect("valid asset shorthand")
}

/// A canonical set (sorted by canonical bytes, deduplicated).
pub fn set(items: Vec<Value>) -> Value {
    let mut v = items;
    canonical_sort(&mut v);
    Value::Array(v)
}

pub fn web(path: &str) -> Value {
    asset(&format!("web:https://app.acme.test:443{path}"))
}

// ---------------------------------------------------------------------------
// JSON path helpers for mutations
// ---------------------------------------------------------------------------

pub fn field<'a>(v: &'a mut Value, path: &str) -> &'a mut Value {
    let mut cur = v;
    for k in path.split('.') {
        cur = cur.get_mut(k).unwrap_or_else(|| panic!("no field {path}"));
    }
    cur
}

pub fn put(v: &mut Value, path: &str, x: Value) {
    let (parent, key) = match path.rsplit_once('.') {
        Some((p, k)) => (field(v, p), k),
        None => (v, path),
    };
    parent
        .as_object_mut()
        .expect("object")
        .insert(key.to_owned(), x);
}

pub fn del(v: &mut Value, path: &str) {
    let (parent, key) = match path.rsplit_once('.') {
        Some((p, k)) => (field(v, p), k),
        None => (v, path),
    };
    parent.as_object_mut().expect("object").remove(key);
}

/// Push into a set-valued array and restore canonical order.
pub fn add_to_set(v: &mut Value, path: &str, x: Value) {
    let mut items = field(v, path).as_array().expect("array").clone();
    items.push(x);
    put(v, path, set(items));
}

pub fn constraint(name: &str, critical: bool, value: &str) -> Value {
    json!({"critical": critical, "name": name, "value": value})
}

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Encoding {
    Canonical,
    Pretty,
    Raw(Vec<u8>),
}

/// How one bundle slot is produced: payload, signer, and envelope fields.
#[derive(Clone, Debug)]
pub struct SlotSpec {
    pub payload: Value,
    pub signer: String,
    pub envelope_type: String,
    /// Type tag used in the signed bytes (normally equal to `envelope_type`).
    pub sign_tag: String,
    pub alg: String,
    pub encoding: Encoding,
}

impl SlotSpec {
    pub fn new(tag: TypeTag, signer: &str, payload: Value) -> Self {
        SlotSpec {
            payload,
            signer: signer.to_owned(),
            envelope_type: tag.as_str().to_owned(),
            sign_tag: tag.as_str().to_owned(),
            alg: "Ed25519".to_owned(),
            encoding: Encoding::Canonical,
        }
    }
}

/// Post-signing manipulations of built envelopes.
#[derive(Clone, Debug)]
pub enum PostOp {
    FlipSigBit(Slot, usize),
    FlipPayloadBit(Slot, usize),
    ReplacePayloadKeepSig(Slot, Value),
    SetRaw(Slot, Vec<u8>),
    Remove(Slot),
    Copy { from: Slot, to: Slot },
}

#[derive(Clone, Debug)]
struct Parts {
    env_type: String,
    payload: Vec<u8>,
    alg: String,
    key_id: String,
    sig: [u8; 64],
}

#[derive(Clone, Debug)]
enum Built {
    Parts(Parts),
    Raw(Vec<u8>),
    Absent,
}

fn slot_index(s: Slot) -> usize {
    match s {
        Slot::Root => 0,
        Slot::Admin => 1,
        Slot::Issuer => 2,
        Slot::Grant => 3,
    }
}

#[derive(Clone, Debug)]
pub struct Scenario {
    pub root: Option<SlotSpec>,
    pub admin: Option<SlotSpec>,
    pub issuer: Option<SlotSpec>,
    pub grant: Option<SlotSpec>,
    pub post: Vec<PostOp>,
    pub registry: InMemoryRegistry,
    pub bindings: InMemoryBindings,
    pub clock: FixedClock,
    pub status: InMemoryStatus,
}

pub fn root_payload(org: &str, label: &str) -> Value {
    json!({
        "algorithm": "Ed25519",
        "format": "aisig/v0",
        "key_id": kid(label),
        "org_id": org,
        "root_key": pub_b64(label),
        "usage": ROOT_USAGE,
        "validity": {"end": "2027-12-31T00:00:00Z", "start": "2026-01-01T00:00:00Z"},
        "version": 1
    })
}

pub fn root_record(org: &str, label: &str) -> RootRecord {
    RootRecord {
        org_id: org.to_owned(),
        root_key: public_key(label),
        key_id: kid(label),
        algorithm: "Ed25519".to_owned(),
        validity: window("2026-01-01T00:00:00Z", "2027-12-31T00:00:00Z"),
        usage: ROOT_USAGE.to_owned(),
        version: 1,
        evidence_ref: format!("synthetic-manual-review:{org}"),
        accepted_at: ts("2026-01-01T00:00:00Z"),
        status: RootStatus::Active,
    }
}

impl Scenario {
    /// The base fixture of docs/experiment.md §2.
    pub fn base() -> Scenario {
        let admin = json!({
            "audience": P_AUD,
            "bounds": {
                "included": set(vec![asset("web:https://app.acme.test:443/"), asset("db:cluster1")]),
                "max_engagement_seconds": 2_592_000,
                "test_ceiling": set(vec![
                    json!("recon"), json!("auth_testing"), json!("injection_testing"),
                    json!("read_only_data_access"), json!("data_modification"),
                ]),
            },
            "format": "aisig/v0",
            "id": ADMIN_ID,
            "issuer_key_id": kid("acme-root"),
            "org_id": ACME,
            "rights": ["may_delegate_grant_issuer"],
            "subject_key": pub_b64("acme-admin"),
            "validity": {"end": "2026-12-31T00:00:00Z", "start": "2026-10-01T00:00:00Z"},
            "version": 1
        });
        let issuer = json!({
            "audience": P_AUD,
            "envelope": {
                "included": set(vec![web("/app"), asset("db:cluster1/main/billing")]),
                "mandatory_exclusions": set(vec![web("/app/admin")]),
                "max_engagement_seconds": 604_800,
                "test_ceiling": set(vec![
                    json!("recon"), json!("auth_testing"), json!("injection_testing"),
                    json!("read_only_data_access"),
                ]),
            },
            "format": "aisig/v0",
            "id": ISSUER_ID,
            "issuer_key_id": kid("acme-admin"),
            "org_id": ACME,
            "parent": {"id": ADMIN_ID, "version": 1},
            "right": "may_issue_engagement",
            "subject_key": pub_b64("acme-authorizer"),
            "validity": {"end": "2026-11-30T00:00:00Z", "start": "2026-10-10T00:00:00Z"},
            "version": 1
        });
        let grant = json!({
            "audience": P_AUD,
            "engagement_id": "eng-acme-2026-10-15-01",
            "exclusions": set(vec![web("/app/admin"), web("/app/private")]),
            "format": "aisig/v0",
            "id": GRANT_ID,
            "issuer_key_id": kid("acme-authorizer"),
            "org_id": ACME,
            "parent": {"id": ISSUER_ID, "version": 1},
            "targets": set(vec![web("/app"), asset("db:cluster1/main/billing")]),
            "test_scope": {"classes": set(vec![json!("recon"), json!("injection_testing")]), "kind": "classes"},
            "tester_key": pub_b64("tester-1"),
            "version": 1,
            "window": {"end": "2026-10-15T11:00:00Z", "start": "2026-10-15T09:00:00Z"}
        });

        let mut registry = InMemoryRegistry::default();
        registry
            .records
            .insert(ACME.into(), root_record(ACME, "acme-root"));
        registry
            .records
            .insert(GLOBEX.into(), root_record(GLOBEX, "globex-root"));

        let bindings = InMemoryBindings {
            bindings: vec![
                (ACME.into(), asset_ref("web:https://app.acme.test:443/")),
                (ACME.into(), asset_ref("db:cluster1")),
                (
                    GLOBEX.into(),
                    asset_ref("web:https://shop.globex.test:443/"),
                ),
                (GLOBEX.into(), asset_ref("db:cluster2")),
            ],
            unavailable: false,
        };

        let mut status = InMemoryStatus::default();
        for id in [ADMIN_ID, ISSUER_ID, GRANT_ID] {
            status.entries.insert((id.into(), 1), ObjStatus::Active);
        }

        Scenario {
            root: Some(SlotSpec::new(
                TypeTag::OrganizationRoot,
                "acme-root",
                root_payload(ACME, "acme-root"),
            )),
            admin: Some(SlotSpec::new(TypeTag::AdminDelegation, "acme-root", admin)),
            issuer: Some(SlotSpec::new(
                TypeTag::IssuerDelegation,
                "acme-admin",
                issuer,
            )),
            grant: Some(SlotSpec::new(
                TypeTag::EngagementGrant,
                "acme-authorizer",
                grant,
            )),
            post: Vec::new(),
            registry,
            bindings,
            clock: FixedClock {
                reading: Some(ClockReading {
                    now: ts("2026-10-15T10:00:00Z"),
                    epsilon: 2,
                }),
            },
            status,
        }
    }

    pub fn root_spec(&mut self) -> &mut SlotSpec {
        self.root.as_mut().expect("root slot present")
    }
    pub fn admin_spec(&mut self) -> &mut SlotSpec {
        self.admin.as_mut().expect("admin slot present")
    }
    pub fn issuer_spec(&mut self) -> &mut SlotSpec {
        self.issuer.as_mut().expect("issuer slot present")
    }
    pub fn grant_spec(&mut self) -> &mut SlotSpec {
        self.grant.as_mut().expect("grant slot present")
    }
    pub fn admin(&mut self) -> &mut Value {
        &mut self.admin_spec().payload
    }
    pub fn issuer(&mut self) -> &mut Value {
        &mut self.issuer_spec().payload
    }
    pub fn grant(&mut self) -> &mut Value {
        &mut self.grant_spec().payload
    }

    pub fn set_clock(&mut self, now: &str, epsilon: i64) {
        self.clock.reading = Some(ClockReading {
            now: ts(now),
            epsilon,
        });
    }

    pub fn acme_record(&mut self) -> &mut RootRecord {
        self.registry.records.get_mut(ACME).expect("acme record")
    }

    pub fn build(&self) -> Bundle {
        let mut slots: [Built; 4] = [&self.root, &self.admin, &self.issuer, &self.grant]
            .map(|spec| build_slot(spec.as_ref()));
        for op in &self.post {
            apply_post(&mut slots, op);
        }
        let [root, admin, issuer, grant] = slots.map(into_bytes);
        Bundle {
            root,
            admin,
            issuer,
            grant,
        }
    }

    pub fn evidence(&self) -> Evidence<'_> {
        Evidence {
            registry: &self.registry,
            bindings: &self.bindings,
            clock: &self.clock,
            status: &self.status,
        }
    }

    pub fn verifier(&self) -> ChainVerifier<'_> {
        ChainVerifier {
            audience: P_AUD,
            evidence: self.evidence(),
        }
    }

    /// Chain-aware decision.
    pub fn run(&self) -> Decision {
        self.verifier().verify(&self.build())
    }

    /// Signature-only baseline decision.
    pub fn run_baseline(&self) -> Decision {
        verify_signature_only(&self.build())
    }
}

fn build_slot(spec: Option<&SlotSpec>) -> Built {
    let Some(s) = spec else {
        return Built::Absent;
    };
    let payload = match &s.encoding {
        Encoding::Canonical => {
            canonical_json(&s.payload).expect("fixture payloads are canonicalizable")
        }
        Encoding::Pretty => serde_json::to_vec_pretty(&s.payload).expect("json"),
        Encoding::Raw(b) => b.clone(),
    };
    let sig = secret(&s.signer).sign(&s.sign_tag, &payload);
    Built::Parts(Parts {
        env_type: s.envelope_type.clone(),
        payload,
        alg: s.alg.clone(),
        key_id: kid(&s.signer),
        sig,
    })
}

fn apply_post(slots: &mut [Built; 4], op: &PostOp) {
    match op {
        PostOp::FlipSigBit(s, bit) => {
            if let Built::Parts(p) = &mut slots[slot_index(*s)] {
                let bit = bit % 512;
                p.sig[bit / 8] ^= 1 << (bit % 8);
            }
        }
        PostOp::FlipPayloadBit(s, bit) => {
            if let Built::Parts(p) = &mut slots[slot_index(*s)] {
                let bit = bit % (p.payload.len() * 8);
                p.payload[bit / 8] ^= 1 << (bit % 8);
            }
        }
        PostOp::ReplacePayloadKeepSig(s, v) => {
            if let Built::Parts(p) = &mut slots[slot_index(*s)] {
                p.payload = canonical_json(v).expect("canonicalizable");
            }
        }
        PostOp::SetRaw(s, b) => slots[slot_index(*s)] = Built::Raw(b.clone()),
        PostOp::Remove(s) => slots[slot_index(*s)] = Built::Absent,
        PostOp::Copy { from, to } => slots[slot_index(*to)] = slots[slot_index(*from)].clone(),
    }
}

fn into_bytes(b: Built) -> Option<Vec<u8>> {
    match b {
        Built::Absent => None,
        Built::Raw(r) => Some(r),
        Built::Parts(p) => Some(
            EnvelopeWire {
                payload: b64_encode(&p.payload),
                sig: SigWire {
                    alg: p.alg,
                    key_id: p.key_id,
                    value: b64_encode(&p.sig),
                },
                type_tag: p.env_type,
            }
            .to_bytes(),
        ),
    }
}

/// Status entries keyed by (id, version), for mutations.
pub fn status_key(id: &str, version: u32) -> (String, u32) {
    (id.to_owned(), version)
}
