//! Evidence interfaces and in-memory fixtures (spec §6).
//!
//! These stand in for RQ1 (organization registry), RQ2 (asset binding) and RQ7 (status).
//! They are simulations: they answer instantly and are trusted by construction.

use std::collections::HashMap;

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

pub trait StatusSource {
    fn status(&self, id: &str, version: u32) -> Result<ObjStatus, Unavailable>;
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

#[derive(Clone, Debug, Default)]
pub struct InMemoryStatus {
    pub entries: HashMap<(String, u32), ObjStatus>,
    pub unavailable: bool,
}

impl StatusSource for InMemoryStatus {
    fn status(&self, id: &str, version: u32) -> Result<ObjStatus, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(self
            .entries
            .get(&(id.to_owned(), version))
            .copied()
            .unwrap_or(ObjStatus::Unknown))
    }
}
