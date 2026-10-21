//! RQ1–RQ3 synthetic extension: pinned root, bounded role delegations, signed
//! asset snapshot and one signed Junior request. See docs/rq123.md.
//!
//! This is a separate decision. It never performs a tool effect and does not
//! replace the existing chain/session/enforcement APIs.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::codec::{
    b64_decode, canonical_bytes, check_canonical_set, strict_parse, EnvelopeWire, TypeTag,
};
use crate::crypto;
use crate::evidence::{ObjStatus, RootRegistry, RootStatus, StatusKey, StatusSource, TrustedClock};
use crate::model::{AssetRef, PublicKey, TestClass, Window};
use crate::verifier::{ROOT_ALGORITHM, ROOT_USAGE};

const FORMAT: &str = "aisig-rq123/v1";
const MANIFEST_FORMAT: &str = "aisig-asset-manifest/v1";
const MANIFEST_DOMAIN: &[u8] = b"aisig-asset-manifest/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Cto,
    Senior,
    Junior,
}

/// Exact identity of the signed payload, including its type-separated digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRef {
    pub id: String,
    pub version: u32,
    pub digest: String,
}

/// Organization authority conveyed to one key. Roles are checked, but authority
/// comes from the signed bounds and flags, never the role name alone.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDelegation {
    pub format: String,
    pub id: String,
    pub version: u32,
    pub org_id: String,
    pub audience: String,
    pub issuer_key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ExactRef>,
    pub role: Role,
    pub subject_user_id: String,
    pub subject_key: PublicKey,
    pub assets: Vec<AssetRef>,
    pub classes: Vec<TestClass>,
    pub may_delegate: bool,
    pub may_register_asset: bool,
    pub validity: Window,
}

/// One snapshot declaration, signed by an authorized CTO or Senior on this path.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetRecord {
    pub format: String,
    pub id: String,
    pub version: u32,
    pub org_id: String,
    pub audience: String,
    pub issuer_key_id: String,
    pub registrar: ExactRef,
    pub junior: ExactRef,
    pub asset: AssetRef,
    pub asset_version: u32,
    pub manifest_digest: String,
    pub classes: Vec<TestClass>,
    pub validity: Window,
}

/// The signed claimant. This proves the Junior key signed one request, not a
/// provider session or the right to execute an actual tool.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetRequest {
    pub format: String,
    pub id: String,
    pub version: u32,
    pub org_id: String,
    pub audience: String,
    pub issuer_key_id: String,
    pub subject_user_id: String,
    pub junior: ExactRef,
    pub record: ExactRef,
    pub asset: AssetRef,
    pub asset_version: u32,
    pub manifest_digest: String,
    pub class: TestClass,
}

/// Synthetic public snapshot, not a secret or a live asset-control proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetManifest {
    pub format: String,
    pub asset: AssetRef,
    pub asset_version: u32,
    pub snapshot_marker: String,
}

/// Every signed input remains raw until the verifier decodes it. A caller cannot
/// submit an edited pre-decoded structure for a decision.
#[derive(Clone, Debug)]
pub struct AuthorityBundle {
    pub path: Vec<Vec<u8>>,
    pub record: Vec<u8>,
    pub request: Vec<u8>,
    pub manifest: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accept,
    Reject(&'static str),
    Indeterminate(&'static str),
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Accept => f.write_str("Accept"),
            Outcome::Reject(reason) => write!(f, "Reject / {reason}"),
            Outcome::Indeterminate(reason) => write!(f, "Indeterminate / {reason}"),
        }
    }
}

fn reject(reason: &'static str) -> Outcome {
    Outcome::Reject(reason)
}

fn unknown(reason: &'static str) -> Outcome {
    Outcome::Indeterminate(reason)
}

#[derive(Clone)]
struct Signed<T> {
    body: T,
    payload: Vec<u8>,
    sig: [u8; 64],
}

fn decode<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
    tag: TypeTag,
) -> Result<Signed<T>, Outcome> {
    let value = strict_parse(bytes).map_err(|_| reject("MalformedInput"))?;
    let envelope: EnvelopeWire =
        serde_json::from_value(value).map_err(|_| reject("MalformedInput"))?;
    if canonical_bytes(&envelope).ok().as_deref() != Some(bytes)
        || envelope.type_tag != tag.as_str()
        || envelope.sig.alg != ROOT_ALGORITHM
    {
        return Err(reject("MalformedInput"));
    }
    let payload = b64_decode(&envelope.payload).ok_or(reject("MalformedInput"))?;
    let sig: [u8; 64] = b64_decode(&envelope.sig.value)
        .and_then(|x| x.try_into().ok())
        .ok_or(reject("MalformedInput"))?;
    let value = strict_parse(&payload).map_err(|_| reject("MalformedInput"))?;
    let body: T = serde_json::from_value(value).map_err(|_| reject("MalformedInput"))?;
    if canonical_bytes(&body).ok().as_deref() != Some(payload.as_slice()) {
        return Err(reject("MalformedInput"));
    }
    Ok(Signed { body, payload, sig })
}

fn required_string(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn digest_shape(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn valid_ref(r: &ExactRef) -> bool {
    required_string(&r.id) && r.version > 0 && digest_shape(&r.digest)
}

fn valid_set<T: Serialize>(xs: &[T]) -> bool {
    !xs.is_empty() && check_canonical_set(xs).is_ok()
}

fn validate_edge(e: &RoleDelegation) -> bool {
    e.format == FORMAT
        && required_string(&e.id)
        && e.version > 0
        && required_string(&e.org_id)
        && required_string(&e.audience)
        && digest_shape(&e.issuer_key_id)
        && required_string(&e.subject_user_id)
        && e.parent.as_ref().is_none_or(valid_ref)
        && valid_set(&e.assets)
        && valid_set(&e.classes)
}

fn validate_record(r: &AssetRecord) -> bool {
    r.format == FORMAT
        && required_string(&r.id)
        && r.version > 0
        && required_string(&r.org_id)
        && required_string(&r.audience)
        && digest_shape(&r.issuer_key_id)
        && valid_ref(&r.registrar)
        && valid_ref(&r.junior)
        && r.asset_version > 0
        && digest_shape(&r.manifest_digest)
        && valid_set(&r.classes)
}

fn validate_request(r: &AssetRequest) -> bool {
    r.format == FORMAT
        && required_string(&r.id)
        && r.version > 0
        && required_string(&r.org_id)
        && required_string(&r.audience)
        && digest_shape(&r.issuer_key_id)
        && required_string(&r.subject_user_id)
        && valid_ref(&r.junior)
        && valid_ref(&r.record)
        && r.asset_version > 0
        && digest_shape(&r.manifest_digest)
}

fn manifest_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn reference<T>(id: &str, version: u32, tag: TypeTag, signed: &Signed<T>) -> ExactRef {
    ExactRef {
        id: id.to_owned(),
        version,
        digest: hex::encode(crypto::object_digest(tag.as_str(), &signed.payload)),
    }
}

fn covers(bounds: &[AssetRef], asset: &AssetRef) -> bool {
    bounds.iter().any(|b| asset.within(b))
}

/// Synthetic provider inputs. The registry is the RQ1 assumption; the signed
/// record replaces a trusted per-asset binding *within this separate slice*.
pub struct AuthorityVerifier<'a> {
    pub audience: &'a str,
    pub registry: &'a dyn RootRegistry,
    pub clock: &'a dyn TrustedClock,
    pub status: &'a dyn StatusSource,
}

impl AuthorityVerifier<'_> {
    pub fn verify(&self, raw: &AuthorityBundle) -> Outcome {
        // Strict decoding before a signature or policy check. Exactly three role
        // edges in this first experiment; no graph search or ambiguous path merge.
        if raw.path.len() != 3 {
            return reject("MalformedInput");
        }
        let edges: Vec<Signed<RoleDelegation>> = match raw
            .path
            .iter()
            .map(|bytes| decode(bytes, TypeTag::RoleDelegation))
            .collect::<Result<_, _>>()
        {
            Ok(edges) => edges,
            Err(outcome) => return outcome,
        };
        let record: Signed<AssetRecord> = match decode(&raw.record, TypeTag::AssetRecord) {
            Ok(r) => r,
            Err(o) => return o,
        };
        let request: Signed<AssetRequest> = match decode(&raw.request, TypeTag::AssetRequest) {
            Ok(r) => r,
            Err(o) => return o,
        };
        let manifest_val = match strict_parse(&raw.manifest) {
            Ok(m) => m,
            Err(_) => return reject("MalformedInput"),
        };
        let manifest: AssetManifest = match serde_json::from_value(manifest_val) {
            Ok(m) => m,
            Err(_) => return reject("MalformedInput"),
        };
        if canonical_bytes(&manifest).ok().as_deref() != Some(raw.manifest.as_slice())
            || manifest.format != MANIFEST_FORMAT
            || manifest.asset_version == 0
            || !required_string(&manifest.snapshot_marker)
            || edges.iter().any(|e| !validate_edge(&e.body))
            || !validate_record(&record.body)
            || !validate_request(&request.body)
        {
            return reject("MalformedInput");
        }

        let org = &edges[0].body.org_id;
        let root = match self.registry.lookup(org) {
            Err(_) => return unknown("RegistryUnavailable"),
            Ok(Some(r)) => r,
            Ok(None) => return reject("RootNotPinned"),
        };
        if root.org_id.as_str() != org.as_str()
            || root.key_id != root.root_key.key_id()
            || root.algorithm != ROOT_ALGORITHM
            || root.usage != ROOT_USAGE
            || root.status != RootStatus::Active
            || root.key_id != edges[0].body.issuer_key_id
        {
            return reject("RootNotPinned");
        }

        let refs: Vec<ExactRef> = edges
            .iter()
            .map(|e| reference(&e.body.id, e.body.version, TypeTag::RoleDelegation, e))
            .collect();
        for (i, e) in edges.iter().enumerate() {
            let key = if i == 0 {
                &root.root_key
            } else {
                &edges[i - 1].body.subject_key
            };
            if !crypto::verify(
                key.bytes(),
                TypeTag::RoleDelegation.as_str(),
                &e.payload,
                &e.sig,
            ) {
                return reject("InvalidSignature");
            }
            if e.body.issuer_key_id != key.key_id()
                || e.body.parent.as_ref() != i.checked_sub(1).map(|p| &refs[p])
                || e.body.org_id.as_str() != org.as_str()
                || e.body.audience.as_str() != self.audience
                || e.body.role != [Role::Cto, Role::Senior, Role::Junior][i]
            {
                return reject("PathMismatch");
            }
        }

        let r = &record.body;
        let q = &request.body;
        let leaf = &edges[2].body;
        let registrar_idx = if r.registrar == refs[0] {
            0
        } else if r.registrar == refs[1] {
            1
        } else {
            return reject("PathMismatch");
        };
        let registrar = &edges[registrar_idx].body;
        if !crypto::verify(
            registrar.subject_key.bytes(),
            TypeTag::AssetRecord.as_str(),
            &record.payload,
            &record.sig,
        ) {
            return reject("InvalidSignature");
        }
        if !crypto::verify(
            leaf.subject_key.bytes(),
            TypeTag::AssetRequest.as_str(),
            &request.payload,
            &request.sig,
        ) {
            return reject("InvalidSignature");
        }
        let rr = reference(&r.id, r.version, TypeTag::AssetRecord, &record);
        if r.junior != refs[2]
            || q.junior != refs[2]
            || q.record != rr
            || r.issuer_key_id != registrar.subject_key.key_id()
            || q.issuer_key_id != leaf.subject_key.key_id()
            || r.org_id.as_str() != org.as_str()
            || q.org_id.as_str() != org.as_str()
            || r.audience.as_str() != self.audience
        {
            return reject("PathMismatch");
        }
        if q.audience.as_str() != self.audience {
            return reject("WrongAudience");
        }
        if q.subject_user_id != leaf.subject_user_id {
            return reject("UserMismatch");
        }

        for (parent, child) in edges.iter().zip(edges.iter().skip(1)) {
            let p = &parent.body;
            let c = &child.body;
            if !p.may_delegate
                || (c.may_register_asset && !p.may_register_asset)
                || !p.validity.contains_window(&c.validity)
                || c.assets.iter().any(|a| !covers(&p.assets, a))
                || c.classes.iter().any(|x| !p.classes.contains(x))
            {
                return reject("DelegationAmplifies");
            }
        }
        if !registrar.may_register_asset {
            return reject("RecordIssuerUnauthorized");
        }
        if !covers(&registrar.assets, &r.asset) || !covers(&leaf.assets, &r.asset) {
            return reject("AssetOutsideScope");
        }
        if r.classes
            .iter()
            .any(|c| !registrar.classes.contains(c) || !leaf.classes.contains(c))
            || !registrar.validity.contains_window(&r.validity)
            || !leaf.validity.contains_window(&r.validity)
        {
            return reject("DelegationAmplifies");
        }
        if q.asset != r.asset || manifest.asset != r.asset {
            return reject("AssetOutsideScope");
        }
        if !r.classes.contains(&q.class) || !leaf.classes.contains(&q.class) {
            return reject("ClassNotPermitted");
        }
        if q.asset_version != r.asset_version || manifest.asset_version != r.asset_version {
            return reject("SnapshotDigestMismatch");
        }
        let digest = manifest_hash(&raw.manifest);
        if r.manifest_digest != digest || q.manifest_digest != digest {
            return reject("SnapshotDigestMismatch");
        }

        let mut pending_time = None;
        match self.clock.now() {
            None => pending_time = Some("ClockUnavailable"),
            Some(reading) if reading.epsilon < 0 => {
                pending_time = Some("InvalidClockReading");
            }
            Some(reading) => {
                let low = reading.now.0.saturating_sub(reading.epsilon);
                let high = reading.now.0.saturating_add(reading.epsilon);
                for w in std::iter::once(root.validity)
                    .chain(edges.iter().map(|x| x.body.validity))
                    .chain(std::iter::once(r.validity))
                {
                    if high < w.start.0 {
                        return reject("NotYetValid");
                    }
                    if low >= w.end.0 {
                        return reject("Expired");
                    }
                    if low < w.start.0 || high >= w.end.0 {
                        pending_time = Some("ClockUncertainty");
                    }
                }
            }
        }

        // Check every exact status so a later Revoked dominates an earlier
        // Unknown. An outage itself prevents further answers.
        let keys = edges
            .iter()
            .map(|e| {
                StatusKey::for_object(
                    org,
                    TypeTag::RoleDelegation,
                    &e.body.id,
                    e.body.version,
                    &e.payload,
                )
            })
            .chain(std::iter::once(StatusKey::for_object(
                org,
                TypeTag::AssetRecord,
                &r.id,
                r.version,
                &record.payload,
            )));
        let mut missing = false;
        for k in keys {
            match self.status.status(&k) {
                Ok(ObjStatus::Active) => {}
                Ok(ObjStatus::Revoked | ObjStatus::Superseded) => return reject("Revoked"),
                Ok(ObjStatus::Unknown) => missing = true,
                Err(_) => return unknown("StatusUnavailable"),
            }
        }
        if let Some(reason) = pending_time {
            unknown(reason)
        } else if missing {
            unknown("StatusUnknown")
        } else {
            Outcome::Accept
        }
    }
}
