//! ValidChain_P decision procedure (spec §7).
//!
//! Trust boundary (spec §7.5): the only public decision entry point is
//! [`ChainVerifier::verify`] on raw bundle bytes. [`decode_chain`] is public for inspection,
//! but its result is read-only and cannot be handed back for a decision.
//!
//! ```
//! use aisig_proto::experiment::fixture::Scenario;
//! use aisig_proto::verifier::decode_chain;
//! let s = Scenario::base();
//! let chain = decode_chain(&s.build()).unwrap();
//! let _scope = &chain.grant().body().test_scope; // read access is fine
//! ```
//!
//! Decoded bodies cannot be replaced (private field):
//!
//! ```compile_fail,E0616
//! use aisig_proto::experiment::fixture::Scenario;
//! use aisig_proto::model::{TestClass, TestScope};
//! use aisig_proto::verifier::decode_chain;
//! let s = Scenario::base();
//! let mut chain = decode_chain(&s.build()).unwrap();
//! chain.grant.body.test_scope = TestScope::Classes { classes: vec![TestClass::AuthTesting] };
//! ```
//!
//! A decoded chain cannot be submitted for a decision (no public pre-decoded API):
//!
//! ```compile_fail,E0599
//! use aisig_proto::experiment::fixture::Scenario;
//! use aisig_proto::verifier::decode_chain;
//! let s = Scenario::base();
//! let p = s.prepare();
//! let chain = decode_chain(&p.bundle).unwrap();
//! let _ = p.verifier().verify_decoded(&chain);
//! ```

use crate::codec::{decode_signed, Signed, TypeTag};
use crate::crypto;
use crate::decision::{Decision, Finding, Obj, Reason, Slot, Stage};
use crate::evidence::{
    AssetBindings, ClockReading, ObjStatus, RootRegistry, RootStatus, StatusKey, StatusSource,
    TrustedClock,
};
use crate::model::{AdminDelegation, EngagementGrant, IssuerDelegation, Window};
use crate::policy::{check_linkage, check_policy, ChainView};

pub const ROOT_USAGE: &str = "org-delegation-root";
pub const ROOT_ALGORITHM: &str = "Ed25519";

/// Raw envelope bytes per slot (spec §2.7).
#[derive(Clone, Debug, Default)]
pub struct Bundle {
    /// Optional self-signed root. Never read by [`ChainVerifier`].
    pub root: Option<Vec<u8>>,
    pub admin: Option<Vec<u8>>,
    pub issuer: Option<Vec<u8>>,
    pub grant: Option<Vec<u8>>,
}

/// A decoded chain, obtainable only from [`decode_chain`]. Read-only: fields are private
/// and each [`Signed`] body is bound to its signed payload. Decoding is not verification;
/// the only public way to obtain a decision is [`ChainVerifier::verify`] on raw bytes.
#[derive(Clone, Debug)]
pub struct DecodedChain {
    admin: Signed<AdminDelegation>,
    issuer: Signed<IssuerDelegation>,
    grant: Signed<EngagementGrant>,
}

impl DecodedChain {
    pub fn admin(&self) -> &Signed<AdminDelegation> {
        &self.admin
    }

    pub fn issuer(&self) -> &Signed<IssuerDelegation> {
        &self.issuer
    }

    pub fn grant(&self) -> &Signed<EngagementGrant> {
        &self.grant
    }

    pub fn view(&self) -> ChainView<'_> {
        ChainView {
            admin: self.admin.body(),
            issuer: self.issuer.body(),
            grant: self.grant.body(),
        }
    }

    /// Exact-object status keys of C_A, D_U, G (spec §6), in status-stage order.
    pub fn status_keys(&self) -> [(Obj, StatusKey); 3] {
        let (a, d, g) = (&self.admin, &self.issuer, &self.grant);
        let key = |org: &str, t: TypeTag, id: &str, v: u32, payload: &[u8]| {
            StatusKey::for_object(org, t, id, v, payload)
        };
        [
            (
                Obj::Admin,
                key(
                    &a.body().org_id,
                    TypeTag::AdminDelegation,
                    &a.body().id,
                    a.body().version,
                    a.payload(),
                ),
            ),
            (
                Obj::Issuer,
                key(
                    &d.body().org_id,
                    TypeTag::IssuerDelegation,
                    &d.body().id,
                    d.body().version,
                    d.payload(),
                ),
            ),
            (
                Obj::Grant,
                key(
                    &g.body().org_id,
                    TypeTag::EngagementGrant,
                    &g.body().id,
                    g.body().version,
                    g.payload(),
                ),
            ),
        ]
    }
}

/// Stage F. Ignores `bundle.root` entirely.
pub fn decode_chain(bundle: &Bundle) -> Result<DecodedChain, Reason> {
    let admin = bundle
        .admin
        .as_deref()
        .ok_or(Reason::MissingRequiredObject(Slot::Admin))?;
    let issuer = bundle
        .issuer
        .as_deref()
        .ok_or(Reason::MissingRequiredObject(Slot::Issuer))?;
    let grant = bundle
        .grant
        .as_deref()
        .ok_or(Reason::MissingRequiredObject(Slot::Grant))?;
    Ok(DecodedChain {
        admin: decode_signed(admin, Slot::Admin)?,
        issuer: decode_signed(issuer, Slot::Issuer)?,
        grant: decode_signed(grant, Slot::Grant)?,
    })
}

/// The evidence sources P consults. All are injected; all may be unavailable.
#[derive(Clone, Copy)]
pub struct Evidence<'a> {
    pub registry: &'a dyn RootRegistry,
    pub bindings: &'a dyn AssetBindings,
    pub clock: &'a dyn TrustedClock,
    pub status: &'a dyn StatusSource,
}

pub struct ChainVerifier<'a> {
    /// P's own audience identifier.
    pub audience: &'a str,
    pub evidence: Evidence<'a>,
}

enum TimeVerdict {
    Ok,
    NotYet,
    Expired,
    Uncertain,
}

fn time_check(w: &Window, r: &ClockReading) -> TimeVerdict {
    // Clamp a hand-built negative epsilon to 0 and saturate so an extreme reading cannot
    // overflow (debug panic / release wrap). Behaviour is unchanged for epsilon >= 0 and
    // any realistic time.
    let eps = r.epsilon.max(0);
    let lo = r.now.0.saturating_sub(eps);
    let hi = r.now.0.saturating_add(eps);
    if w.start.0 <= lo && hi < w.end.0 {
        TimeVerdict::Ok
    } else if hi < w.start.0 {
        TimeVerdict::NotYet
    } else if lo >= w.end.0 {
        TimeVerdict::Expired
    } else {
        TimeVerdict::Uncertain
    }
}

/// Collects the first Indeterminate while evaluation continues (spec §7.1).
#[derive(Default)]
struct Pending(Option<Finding>);

impl Pending {
    fn note(&mut self, stage: Stage, reason: Reason) {
        if self.0.is_none() {
            self.0 = Some(Finding { stage, reason });
        }
    }
}

macro_rules! reject {
    ($stage:expr, $reason:expr) => {
        return Decision::reject($stage, $reason)
    };
}

impl ChainVerifier<'_> {
    /// ValidChain_P over raw envelope bytes. This is the only public decision entry point
    /// (spec §7.5): callers cannot supply pre-decoded or modified bodies.
    pub fn verify(&self, bundle: &Bundle) -> Decision {
        self.verify_with_chain(bundle).0
    }

    /// The chain decision together with the chain this verifier decoded from `bundle`
    /// (`None` only when decoding failed). Crate-internal: used by the RQ5 session
    /// service to read the accepted G without a public pre-decoded decision path.
    pub(crate) fn verify_with_chain(&self, bundle: &Bundle) -> (Decision, Option<DecodedChain>) {
        match decode_chain(bundle) {
            Ok(chain) => (self.evaluate(&chain), Some(chain)),
            Err(reason) => (Decision::reject(Stage::Format, reason), None),
        }
    }

    /// Stages N through X on a chain this verifier has just decoded. Private by design: a
    /// public pre-decoded entry point allowed policy to run on a body that differed from
    /// the verified payload (r3 review; tests/predecoded_api.rs).
    fn evaluate(&self, chain: &DecodedChain) -> Decision {
        let ev = &self.evidence;
        let (a, d, g) = (&chain.admin, &chain.issuer, &chain.grant);
        let mut pending = Pending::default();

        // N — anchor. Unavailable ⇒ continue under hypothesis H (spec §7.2).
        let anchor = match ev.registry.lookup(&a.body().org_id) {
            Err(_) => {
                pending.note(Stage::Anchor, Reason::RegistryUnavailable);
                None
            }
            Ok(None) => reject!(Stage::Anchor, Reason::UnpinnedOrganization),
            Ok(Some(rec)) => {
                // The record itself must name O and Ed25519; the lookup key alone does not.
                if rec.org_id != a.body().org_id {
                    reject!(Stage::Anchor, Reason::RootOrgMismatch);
                }
                if rec.algorithm != ROOT_ALGORITHM {
                    reject!(Stage::Anchor, Reason::RootAlgorithmMismatch);
                }
                if rec.key_id != a.body().issuer_key_id || rec.root_key.key_id() != rec.key_id {
                    reject!(Stage::Anchor, Reason::RootKeyNotPinned);
                }
                if rec.usage != ROOT_USAGE {
                    reject!(Stage::Anchor, Reason::RootUsageMismatch);
                }
                if rec.status != RootStatus::Active {
                    reject!(Stage::Anchor, Reason::RootNotActive);
                }
                Some(rec)
            }
        };

        // S — signatures. C_A only with the pinned key; D_U and G with chain keys
        // (asserted, not authenticated, when the anchor is unavailable).
        if let Some(rec) = anchor {
            if !crypto::verify(
                rec.root_key.bytes(),
                "AdminDelegation",
                a.payload(),
                a.sig(),
            ) {
                reject!(Stage::Signature, Reason::InvalidSignature(Obj::Admin));
            }
        }
        if !crypto::verify(
            a.body().subject_key.bytes(),
            "IssuerDelegation",
            d.payload(),
            d.sig(),
        ) {
            reject!(Stage::Signature, Reason::InvalidSignature(Obj::Issuer));
        }
        if !crypto::verify(
            d.body().subject_key.bytes(),
            "EngagementGrant",
            g.payload(),
            g.sig(),
        ) {
            reject!(Stage::Signature, Reason::InvalidSignature(Obj::Grant));
        }

        // L, P — pure predicates.
        let view = chain.view();
        if let Err(r) = check_linkage(&view, self.audience) {
            reject!(Stage::Linkage, r);
        }
        if let Err(r) = check_policy(&view) {
            reject!(Stage::Policy, r);
        }

        // B — binding of every grant target to O.
        for target in &g.body().targets {
            match ev.bindings.owners_of(target) {
                Err(_) => {
                    pending.note(Stage::Binding, Reason::BindingUnavailable);
                    break;
                }
                Ok(owners) if owners.contains(&a.body().org_id.as_str()) => {}
                Ok(owners) if !owners.is_empty() => {
                    reject!(Stage::Binding, Reason::AssetBoundToOtherOrg)
                }
                Ok(_) => pending.note(Stage::Binding, Reason::NoBindingEvidence),
            }
        }

        // T — root record (only if the registry answered), then C_A, D_U, G.
        match ev.clock.now() {
            None => pending.note(Stage::Time, Reason::ClockUnavailable),
            Some(reading) => {
                let windows = anchor
                    .map(|rec| (Obj::Root, rec.validity))
                    .into_iter()
                    .chain([
                        (Obj::Admin, a.body().validity),
                        (Obj::Issuer, d.body().validity),
                        (Obj::Grant, g.body().window),
                    ]);
                for (obj, w) in windows {
                    match time_check(&w, &reading) {
                        TimeVerdict::Ok => {}
                        TimeVerdict::NotYet => reject!(Stage::Time, Reason::NotYetValid(obj)),
                        TimeVerdict::Expired => reject!(Stage::Time, Reason::Expired(obj)),
                        TimeVerdict::Uncertain => {
                            pending.note(Stage::Time, Reason::ClockUncertainty(obj))
                        }
                    }
                }
            }
        }

        // X — status of the exact signed C_A, D_U, G (spec §6 StatusKey).
        for (obj, key) in chain.status_keys() {
            match ev.status.status(&key) {
                Err(_) => {
                    pending.note(Stage::Status, Reason::StatusUnavailable);
                    break;
                }
                Ok(ObjStatus::Active) => {}
                Ok(ObjStatus::Revoked) => reject!(Stage::Status, Reason::Revoked(obj)),
                Ok(ObjStatus::Superseded) => reject!(Stage::Status, Reason::Superseded(obj)),
                Ok(ObjStatus::Unknown) => pending.note(Stage::Status, Reason::StatusUnknown(obj)),
            }
        }

        match pending.0 {
            Some(f) => Decision::Indeterminate(f),
            None => Decision::Accept,
        }
    }
}

#[cfg(test)]
mod time_check_tests {
    use super::{time_check, TimeVerdict};
    use crate::evidence::ClockReading;
    use crate::model::{Ts, Window};

    #[test]
    fn extreme_epsilon_does_not_overflow() {
        let w = Window {
            start: Ts(0),
            end: Ts(100),
        };
        // Extreme and negative epsilons must not panic; epsilon is clamped to >= 0 and
        // bounds saturate. A huge epsilon straddles every edge -> Uncertain.
        for eps in [i64::MAX, i64::MIN, -5] {
            let r = ClockReading {
                now: Ts(50),
                epsilon: eps,
            };
            let v = time_check(&w, &r);
            if eps < 0 {
                // clamped to 0: now=50 strictly inside [0,100) -> Ok
                assert!(matches!(v, TimeVerdict::Ok), "eps={eps}");
            } else {
                assert!(matches!(v, TimeVerdict::Uncertain), "eps={eps}");
            }
        }
    }
}
