//! Typed payloads and assets with decode-time validation (spec §2).
//!
//! Validation errors that serde must carry are raised as `codec::FormatError` so the
//! decoder can recover the exact format-stage reason.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::codec::{b64_decode, b64_encode, check_canonical_set, FormatError, Payload, TypeTag};
use crate::crypto;
use crate::decision::Reason;

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// A UTC instant with second precision (unix seconds). Canonical text: `YYYY-MM-DDTHH:MM:SSZ`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ts(pub i64);

impl Ts {
    /// Accepts only the canonical form (spec §2.1). Never normalizes.
    pub fn parse(s: &str) -> Result<Ts, FormatError> {
        let dt =
            OffsetDateTime::parse(s, &Rfc3339).map_err(|_| FormatError(Reason::MalformedTime))?;
        let ts = Ts(dt.unix_timestamp());
        if dt.nanosecond() != 0 || ts.to_string() != s {
            return Err(FormatError(Reason::NonCanonicalTime));
        }
        Ok(ts)
    }
}

impl fmt::Display for Ts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_desc = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
        match OffsetDateTime::from_unix_timestamp(self.0)
            .ok()
            .and_then(|d| d.format(&fmt_desc).ok())
        {
            Some(s) => f.write_str(&s),
            None => write!(f, "invalid-time({})", self.0),
        }
    }
}

impl Serialize for Ts {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Ts {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ts::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowWire {
    end: Ts,
    start: Ts,
}

/// Half-open validity window `[start, end)` with `start < end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WindowWire", into = "WindowWire")]
pub struct Window {
    pub start: Ts,
    pub end: Ts,
}

impl TryFrom<WindowWire> for Window {
    type Error = FormatError;
    fn try_from(w: WindowWire) -> Result<Self, FormatError> {
        if w.start < w.end {
            Ok(Window {
                start: w.start,
                end: w.end,
            })
        } else {
            Err(FormatError(Reason::MalformedWindow))
        }
    }
}

impl From<Window> for WindowWire {
    fn from(w: Window) -> Self {
        WindowWire {
            end: w.end,
            start: w.start,
        }
    }
}

impl Window {
    /// `inner ⊆ self` as intervals.
    pub fn contains_window(&self, inner: &Window) -> bool {
        inner.start >= self.start && inner.end <= self.end
    }

    pub fn duration_seconds(&self) -> i64 {
        self.end.0 - self.start.0
    }
}

// ---------------------------------------------------------------------------
// Keys and references
// ---------------------------------------------------------------------------

/// An Ed25519 public key with its key id computed once at decode time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 32],
    id: String,
}

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, FormatError> {
        if !crypto::is_valid_public_key(&bytes) {
            return Err(FormatError(Reason::MalformedKey));
        }
        Ok(PublicKey {
            bytes,
            id: crypto::key_id(&bytes),
        })
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn key_id(&self) -> &str {
        &self.id
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64_encode(&self.bytes))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes: [u8; 32] = b64_decode(&s)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom(FormatError(Reason::MalformedKey)))?;
        PublicKey::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjRef {
    pub id: String,
    pub version: u32,
}

// ---------------------------------------------------------------------------
// Test scope and constraints
// ---------------------------------------------------------------------------

/// Vocabulary `aisig-testclass/v0`: owner-chosen technique classes, not tool names.
/// The mapping from a class to concrete actions is unresolved (RQ6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestClass {
    Recon,
    AuthTesting,
    InjectionTesting,
    ReadOnlyDataAccess,
    DataModification,
    AvailabilityStress,
}

/// The grant's required, explicit test scope (spec §2.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TestScope {
    Unrestricted,
    Classes { classes: Vec<TestClass> },
}

pub const MAX_RPS: &str = "max_requests_per_second";
pub const KNOWN_CONSTRAINTS: &[&str] = &[MAX_RPS];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraint {
    pub critical: bool,
    pub name: String,
    pub value: String,
}

/// Value of the known `max_requests_per_second` constraint, if present.
pub fn max_rps(constraints: &[Constraint]) -> Option<u64> {
    constraints
        .iter()
        .find(|c| c.name == MAX_RPS)
        .and_then(|c| c.value.parse().ok())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRight {
    MayDelegateGrantIssuer,
    AccountAdministration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerRight {
    MayIssueEngagement,
}

// ---------------------------------------------------------------------------
// Assets (spec §2.2). Semantics (`within`, scopes) live in `crate::asset`.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WebOriginPath {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Path segments; empty for `/`.
    pub segments: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DatabaseSchema {
    pub cluster: String,
    pub database: Option<String>,
    pub schema: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "AssetWire", into = "AssetWire")]
pub enum AssetRef {
    Web(WebOriginPath),
    Db(DatabaseSchema),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AssetWire {
    Web {
        host: String,
        path: String,
        port: u64,
        scheme: String,
    },
    Db {
        cluster: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        database: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<String>,
    },
}

fn validate_host(host: &str) -> Result<(), Reason> {
    if host.contains('*') {
        return Err(Reason::UnsupportedAssetSyntax);
    }
    if !host.is_ascii() || host.is_empty() || host.len() > 253 {
        return Err(Reason::MalformedAsset);
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) || host.ends_with('.') {
        return Err(Reason::NonCanonicalAsset);
    }
    for label in host.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(Reason::MalformedAsset);
        }
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<Vec<String>, Reason> {
    if !path.starts_with('/') {
        return Err(Reason::MalformedAsset);
    }
    if path == "/" {
        return Ok(Vec::new());
    }
    if path.ends_with('/') || path.contains('%') {
        return Err(Reason::NonCanonicalAsset);
    }
    let mut segments = Vec::new();
    for seg in path[1..].split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(Reason::NonCanonicalAsset);
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
        {
            return Err(Reason::MalformedAsset);
        }
        segments.push(seg.to_owned());
    }
    Ok(segments)
}

fn validate_db_name(name: &str) -> Result<(), Reason> {
    let ok = (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(Reason::MalformedAsset)
    }
}

impl TryFrom<AssetWire> for AssetRef {
    type Error = FormatError;
    fn try_from(w: AssetWire) -> Result<Self, FormatError> {
        let r = match w {
            AssetWire::Web {
                host,
                path,
                port,
                scheme,
            } => {
                let scheme = match scheme.as_str() {
                    "https" => Scheme::Https,
                    "http" => Scheme::Http,
                    _ => return Err(FormatError(Reason::UnsupportedAssetSyntax)),
                };
                validate_host(&host).map_err(FormatError)?;
                let port = u16::try_from(port)
                    .ok()
                    .filter(|p| *p >= 1)
                    .ok_or(FormatError(Reason::MalformedAsset))?;
                let segments = validate_path(&path).map_err(FormatError)?;
                AssetRef::Web(WebOriginPath {
                    scheme,
                    host,
                    port,
                    segments,
                })
            }
            AssetWire::Db {
                cluster,
                database,
                schema,
            } => {
                validate_db_name(&cluster).map_err(FormatError)?;
                if let Some(d) = &database {
                    validate_db_name(d).map_err(FormatError)?;
                }
                if let Some(s) = &schema {
                    if database.is_none() {
                        return Err(FormatError(Reason::MalformedAsset));
                    }
                    validate_db_name(s).map_err(FormatError)?;
                }
                AssetRef::Db(DatabaseSchema {
                    cluster,
                    database,
                    schema,
                })
            }
        };
        Ok(r)
    }
}

impl From<AssetRef> for AssetWire {
    fn from(a: AssetRef) -> Self {
        match a {
            AssetRef::Web(w) => AssetWire::Web {
                host: w.host,
                path: format!("/{}", w.segments.join("/")),
                port: u64::from(w.port),
                scheme: w.scheme.as_str().to_owned(),
            },
            AssetRef::Db(d) => AssetWire::Db {
                cluster: d.cluster,
                database: d.database,
                schema: d.schema,
            },
        }
    }
}

impl fmt::Display for AssetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetRef::Web(w) => write!(
                f,
                "web:{}://{}:{}/{}",
                w.scheme.as_str(),
                w.host,
                w.port,
                w.segments.join("/")
            ),
            AssetRef::Db(d) => {
                write!(f, "db:{}", d.cluster)?;
                if let Some(x) = &d.database {
                    write!(f, "/{x}")?;
                }
                if let Some(x) = &d.schema {
                    write!(f, "/{x}")?;
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Signed payloads
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRoot {
    pub algorithm: String,
    pub format: String,
    pub key_id: String,
    pub org_id: String,
    pub root_key: PublicKey,
    pub usage: String,
    pub validity: Window,
    pub version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminBounds {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<AssetRef>,
    pub included: Vec<AssetRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_engagement_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_ceiling: Option<Vec<TestClass>>,
}

/// C_A: organization root → admin (spec §2.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminDelegation {
    pub audience: String,
    pub bounds: AdminBounds,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    pub format: String,
    pub id: String,
    pub issuer_key_id: String,
    pub org_id: String,
    pub rights: Vec<AdminRight>,
    pub subject_key: PublicKey,
    pub validity: Window,
    pub version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerEnvelope {
    pub included: Vec<AssetRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mandatory_exclusions: Vec<AssetRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_engagement_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_ceiling: Option<Vec<TestClass>>,
}

/// D_U: admin → authorizer, permission to *issue* grants (spec §2.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerDelegation {
    pub audience: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    pub envelope: IssuerEnvelope,
    pub format: String,
    pub id: String,
    pub issuer_key_id: String,
    pub org_id: String,
    pub parent: ObjRef,
    pub right: IssuerRight,
    pub subject_key: PublicKey,
    pub validity: Window,
    pub version: u32,
}

/// G: authorizer → tester, permission to *test* (spec §2.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementGrant {
    pub audience: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    pub engagement_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<AssetRef>,
    pub format: String,
    pub id: String,
    pub issuer_key_id: String,
    pub org_id: String,
    pub parent: ObjRef,
    pub targets: Vec<AssetRef>,
    pub test_scope: TestScope,
    pub tester_key: PublicKey,
    pub version: u32,
    pub window: Window,
}

// ---------------------------------------------------------------------------
// Spec §3 step 5 checks
// ---------------------------------------------------------------------------

fn printable(s: &str) -> Result<(), Reason> {
    if !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        Ok(())
    } else {
        Err(Reason::MalformedField)
    }
}

fn non_empty_set<T: Serialize>(items: &[T]) -> Result<(), Reason> {
    if items.is_empty() {
        return Err(Reason::MalformedField);
    }
    check_canonical_set(items)
}

fn optional_ceiling(c: &Option<Vec<TestClass>>) -> Result<(), Reason> {
    match c {
        Some(v) => non_empty_set(v),
        None => Ok(()),
    }
}

fn positive(x: &Option<u64>) -> Result<(), Reason> {
    match x {
        Some(0) => Err(Reason::MalformedField),
        _ => Ok(()),
    }
}

fn version(v: u32) -> Result<(), Reason> {
    if v >= 1 {
        Ok(())
    } else {
        Err(Reason::MalformedField)
    }
}

fn check_constraints(cs: &[Constraint]) -> Result<(), Reason> {
    for (i, a) in cs.iter().enumerate() {
        if cs[i + 1..].iter().any(|b| b.name == a.name) {
            return Err(Reason::DuplicateConstraintName);
        }
    }
    for w in cs.windows(2) {
        if w[0].name >= w[1].name {
            return Err(Reason::NonCanonicalEncoding);
        }
    }
    for c in cs {
        printable(&c.name)?;
        printable(&c.value)?;
        if c.name == MAX_RPS {
            let v = &c.value;
            let ok = !v.starts_with('0')
                && v.bytes().all(|b| b.is_ascii_digit())
                && v.parse::<u64>().is_ok();
            if !ok {
                return Err(Reason::MalformedField);
            }
        }
    }
    Ok(())
}

impl Payload for OrganizationRoot {
    const TAG: TypeTag = TypeTag::OrganizationRoot;
    fn check(&self) -> Result<(), Reason> {
        printable(&self.org_id)?;
        version(self.version)
    }
}

impl Payload for AdminDelegation {
    const TAG: TypeTag = TypeTag::AdminDelegation;
    fn check(&self) -> Result<(), Reason> {
        check_constraints(&self.constraints)?;
        for s in [&self.audience, &self.id, &self.issuer_key_id, &self.org_id] {
            printable(s)?;
        }
        version(self.version)?;
        non_empty_set(&self.rights)?;
        non_empty_set(&self.bounds.included)?;
        check_canonical_set(&self.bounds.excluded)?;
        optional_ceiling(&self.bounds.test_ceiling)?;
        positive(&self.bounds.max_engagement_seconds)
    }
}

impl Payload for IssuerDelegation {
    const TAG: TypeTag = TypeTag::IssuerDelegation;
    fn check(&self) -> Result<(), Reason> {
        check_constraints(&self.constraints)?;
        for s in [
            &self.audience,
            &self.id,
            &self.issuer_key_id,
            &self.org_id,
            &self.parent.id,
        ] {
            printable(s)?;
        }
        version(self.version)?;
        version(self.parent.version)?;
        non_empty_set(&self.envelope.included)?;
        check_canonical_set(&self.envelope.mandatory_exclusions)?;
        optional_ceiling(&self.envelope.test_ceiling)?;
        positive(&self.envelope.max_engagement_seconds)
    }
}

impl Payload for EngagementGrant {
    const TAG: TypeTag = TypeTag::EngagementGrant;
    fn check(&self) -> Result<(), Reason> {
        check_constraints(&self.constraints)?;
        for s in [
            &self.audience,
            &self.engagement_id,
            &self.id,
            &self.issuer_key_id,
            &self.org_id,
            &self.parent.id,
        ] {
            printable(s)?;
        }
        version(self.version)?;
        version(self.parent.version)?;
        non_empty_set(&self.targets)?;
        check_canonical_set(&self.exclusions)?;
        if let TestScope::Classes { classes } = &self.test_scope {
            non_empty_set(classes)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(json: &str) -> Result<AssetRef, Reason> {
        serde_json::from_str::<AssetRef>(json)
            .map_err(|e| crate::codec::classify_error(&e.to_string()))
    }

    #[test]
    fn time_canonical_only() {
        assert_eq!(
            Ts::parse("2026-10-15T09:00:00Z").unwrap().to_string(),
            "2026-10-15T09:00:00Z"
        );
        assert_eq!(
            Ts::parse("2026-10-15T09:00:00"),
            Err(FormatError(Reason::MalformedTime))
        );
        assert_eq!(
            Ts::parse("2026-10-15T15:30:00+06:30"),
            Err(FormatError(Reason::NonCanonicalTime))
        );
        assert_eq!(
            Ts::parse("2026-10-15T09:00:00.000Z"),
            Err(FormatError(Reason::NonCanonicalTime))
        );
        assert_eq!(
            Ts::parse("2026-10-15t09:00:00z"),
            Err(FormatError(Reason::NonCanonicalTime))
        );
    }

    #[test]
    fn asset_validation_reasons() {
        let ok =
            r#"{"host":"app.acme.test","kind":"web","path":"/app","port":443,"scheme":"https"}"#;
        assert!(asset(ok).is_ok());
        let upper = ok.replace("app.acme", "APP.acme");
        assert_eq!(asset(&upper), Err(Reason::NonCanonicalAsset));
        let wild = ok.replace("app.acme", "*.acme");
        assert_eq!(asset(&wild), Err(Reason::UnsupportedAssetSyntax));
        let dots = ok.replace("\"/app\"", "\"/app/../admin\"");
        assert_eq!(asset(&dots), Err(Reason::NonCanonicalAsset));
        let slash = ok.replace("\"/app\"", "\"/app/\"");
        assert_eq!(asset(&slash), Err(Reason::NonCanonicalAsset));
        let db_bad = r#"{"cluster":"c1","kind":"db","schema":"s"}"#;
        assert_eq!(asset(db_bad), Err(Reason::MalformedAsset));
        let unknown_kind = r#"{"kind":"cloud","id":"x"}"#;
        assert_eq!(asset(unknown_kind), Err(Reason::UnknownEnumValue));
    }

    #[test]
    fn test_scope_wire_forms() {
        let u: TestScope = serde_json::from_str(r#"{"kind":"unrestricted"}"#).unwrap();
        assert_eq!(u, TestScope::Unrestricted);
        let c: TestScope =
            serde_json::from_str(r#"{"classes":["recon"],"kind":"classes"}"#).unwrap();
        assert_eq!(
            c,
            TestScope::Classes {
                classes: vec![TestClass::Recon]
            }
        );
        let e = serde_json::from_str::<TestScope>(
            r#"{"classes":["zero_day_deploy"],"kind":"classes"}"#,
        )
        .unwrap_err();
        assert_eq!(
            crate::codec::classify_error(&e.to_string()),
            Reason::UnknownEnumValue
        );
    }

    #[test]
    fn constraint_rules() {
        let c = |n: &str, v: &str| Constraint {
            critical: true,
            name: n.into(),
            value: v.into(),
        };
        assert_eq!(
            check_constraints(&[c(MAX_RPS, "1"), c(MAX_RPS, "2")]),
            Err(Reason::DuplicateConstraintName)
        );
        assert_eq!(
            check_constraints(&[c("b", "1"), c("a", "1")]),
            Err(Reason::NonCanonicalEncoding)
        );
        assert_eq!(
            check_constraints(&[c(MAX_RPS, "05")]),
            Err(Reason::MalformedField)
        );
        assert!(check_constraints(&[c(MAX_RPS, "10"), c("x-note", "y")]).is_ok());
    }
}
