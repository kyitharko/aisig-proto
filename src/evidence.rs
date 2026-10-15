//! Evidence interfaces and in-memory fixtures (spec §6).
//!
//! These stand in for RQ1 (organization registry), RQ2 (asset binding) and RQ7 (status).
//! They are simulations: they answer instantly and are trusted by construction.

use std::collections::HashMap;

use crate::codec::TypeTag;
use crate::crypto;
use crate::model::{AssetRef, PublicKey, Ts, Window};

/// The evidence source could not be consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unavailable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootStatus {
    Active,
    Suspended,
    Revoked,
}

/// P's pinned record for an organization root (spec §2.3).
#[derive(Clone, Debug)]
pub struct RootRecord {
    pub org_id: String,
    pub root_key: PublicKey,
    pub key_id: String,
    pub algorithm: String,
    pub validity: Window,
    pub usage: String,
    pub version: u32,
    pub evidence_ref: String,
    pub accepted_at: Ts,
    pub status: RootStatus,
}

pub trait RootRegistry {
    /// `Ok(None)`: the registry answered and holds no record for `org_id`.
    fn lookup(&self, org_id: &str) -> Result<Option<&RootRecord>, Unavailable>;
}

pub trait AssetBindings {
    /// Org ids whose recorded bindings contain `asset`.
    fn owners_of(&self, asset: &AssetRef) -> Result<Vec<&str>, Unavailable>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockReading {
    pub now: Ts,
    /// Symmetric uncertainty ε in seconds.
    pub epsilon: i64,
}

pub trait TrustedClock {
    fn now(&self) -> Option<ClockReading>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjStatus {
    Active,
    Revoked,
    Superseded,
    Unknown,
}

/// Exact-object status identity (spec §6): a record answers only for this key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StatusKey {
    pub org_id: String,
    pub object_type: TypeTag,
    pub id: String,
    pub version: u32,
    /// SHA-256 of `signed_bytes(object_type, payload)`.
    pub digest: [u8; 32],
}

impl StatusKey {
    /// Derive the key from an object's identifying fields and its exact signed payload bytes.
    pub fn for_object(
        org_id: &str,
        object_type: TypeTag,
        id: &str,
        version: u32,
        payload: &[u8],
    ) -> Self {
        StatusKey {
            org_id: org_id.to_owned(),
            object_type,
            id: id.to_owned(),
            version,
            digest: crypto::object_digest(object_type.as_str(), payload),
        }
    }
}

pub trait StatusSource {
    /// Status of the exact object named by `key`; `Unknown` if no record matches it exactly.
    fn status(&self, key: &StatusKey) -> Result<ObjStatus, Unavailable>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryRegistry {
    pub records: HashMap<String, RootRecord>,
    pub unavailable: bool,
}

impl RootRegistry for InMemoryRegistry {
    fn lookup(&self, org_id: &str) -> Result<Option<&RootRecord>, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(self.records.get(org_id))
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryBindings {
    pub bindings: Vec<(String, AssetRef)>,
    pub unavailable: bool,
}

impl AssetBindings for InMemoryBindings {
    fn owners_of(&self, asset: &AssetRef) -> Result<Vec<&str>, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(self
            .bindings
            .iter()
            .filter(|(_, bound)| asset.within(bound))
            .map(|(org, _)| org.as_str())
            .collect())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    pub reading: Option<ClockReading>,
}

impl TrustedClock for FixedClock {
    fn now(&self) -> Option<ClockReading> {
        self.reading
    }
}

/// A clock that returns a fixed sequence of readings across successive `now()` calls,
/// repeating the last entry once exhausted. Used to model a clock that advances between
/// the chain check and a later read (RQ5 issuance clock edge case). Test support only.
#[derive(Debug)]
pub struct SequenceClock {
    readings: Vec<Option<ClockReading>>,
    next: std::sync::atomic::AtomicUsize,
}

impl SequenceClock {
    pub fn new(readings: Vec<Option<ClockReading>>) -> Self {
        assert!(
            !readings.is_empty(),
            "SequenceClock needs at least one reading"
        );
        SequenceClock {
            readings,
            next: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl TrustedClock for SequenceClock {
    fn now(&self) -> Option<ClockReading> {
        let i = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.readings
            .get(i)
            .copied()
            .unwrap_or_else(|| *self.readings.last().unwrap())
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryStatus {
    pub entries: HashMap<StatusKey, ObjStatus>,
    pub unavailable: bool,
}

impl StatusSource for InMemoryStatus {
    fn status(&self, key: &StatusKey) -> Result<ObjStatus, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(self.entries.get(key).copied().unwrap_or(ObjStatus::Unknown))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_answers_only_for_the_exact_object() {
        let key =
            |t: TypeTag, id: &str, payload: &[u8]| StatusKey::for_object("org", t, id, 1, payload);
        let registered = key(TypeTag::AdminDelegation, "x-1", b"{\"a\":1}");
        let mut src = InMemoryStatus::default();
        src.entries.insert(registered.clone(), ObjStatus::Active);
        assert_eq!(src.status(&registered), Ok(ObjStatus::Active));
        // Same id/version, other type.
        assert_eq!(
            src.status(&key(TypeTag::EngagementGrant, "x-1", b"{\"a\":1}")),
            Ok(ObjStatus::Unknown)
        );
        // Same type/id/version, other signed content.
        assert_eq!(
            src.status(&key(TypeTag::AdminDelegation, "x-1", b"{\"a\":2}")),
            Ok(ObjStatus::Unknown)
        );
        // Same content, other org.
        let other_org =
            StatusKey::for_object("org-2", TypeTag::AdminDelegation, "x-1", 1, b"{\"a\":1}");
        assert_eq!(src.status(&other_org), Ok(ObjStatus::Unknown));
    }
}
