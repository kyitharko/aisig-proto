//! RQ6 slice e2: provider-mediated synthetic tool adapter (docs/enforcement.md).
//!
//! A `ProviderExec` decision, separate from `ValidChain_P` (chain) and `SessionAuth`
//! (RQ5). Every modeled effect must pass through [`Mediator::mediate`], which runs the nine
//! documented stages and appends to a private sink only at `perform`. Nothing here contacts
//! a real system; an "effect" is a record in an in-memory sink.
//!
//! The mediation request carries the target as canonical wire bytes, never a pre-built
//! `AssetRef`, so a non-canonical target cannot be smuggled past validation:
//!
//! ```compile_fail,E0560
//! use aisig_proto::enforcement::MediationRequest;
//! use aisig_proto::verifier::Bundle;
//! // There is no `target: AssetRef` field; the target is `target_wire: Vec<u8>`.
//! let _ = MediationRequest { bundle: Bundle::default(), operation: String::new(),
//!     target: aisig_proto::model::AssetRef::Db(todo!()), claimed_class: None };
//! ```
//!
//! The effect sink's append is module-private: external code cannot grow it, even holding a
//! cloned receipt. Only `Mediator::mediate` (at perform) appends.
//!
//! ```compile_fail,E0624
//! use aisig_proto::enforcement::EffectSink;
//! let sink = EffectSink::new();
//! // `record` is private to the enforcement module; this does not compile.
//! sink.record(todo!());
//! ```

use std::fmt;
use std::sync::Mutex;

use serde_json::Value;

use crate::asset::{exact_node_lookup, subtree_lookup, ExactNodeAnswer, SubtreeAnswer};
use crate::codec::{canonical_bytes, strict_parse};
use crate::decision::{Decision, DecisionClass};
use crate::evidence::{ClockReading, FixedClock, StatusKey, Unavailable};
use crate::model::{AssetRef, TestClass, TestScope, Ts};
use crate::policy::grant_scope;
use crate::session::{GrantRef, SessionAuthorization};
use crate::verifier::{Bundle, ChainVerifier, Evidence};

// ---------------------------------------------------------------------------
// Versioned operation table `aisig-tooltable/v0` (docs/enforcement.md §3)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    ReadMetadata,
    ReadData,
    WriteData,
    Authenticate,
    Probe,
    StressAvailability,
}

/// The target kind an operation applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    Web,
    Db,
}

/// Where an operation's effect reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Footprint {
    /// The target node only.
    Node,
    /// The target's whole subtree.
    Subtree,
    /// Beyond the target (origin, other tenants); cannot be confined by scope.
    Unbounded,
}

/// A provider-owned classification of one synthetic operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpSpec {
    pub primary_class: TestClass,
    pub target_kind: TargetKind,
    pub effects: Vec<Effect>,
    pub footprint: Footprint,
}

fn kind_of(a: &AssetRef) -> TargetKind {
    match a {
        AssetRef::Web(_) => TargetKind::Web,
        AssetRef::Db(_) => TargetKind::Db,
    }
}

/// `aisig-tooltable/v0`. Provider-owned and frozen for this slice. The agent's claimed
/// class is never consulted; classification comes from here.
pub fn tooltable_v0(operation: &str) -> Option<OpSpec> {
    use Effect::*;
    use Footprint::*;
    use TargetKind::*;
    use TestClass::*;
    let spec = |primary_class, target_kind, effects: &[Effect], footprint| OpSpec {
        primary_class,
        target_kind,
        effects: effects.to_vec(),
        footprint,
    };
    Some(match operation {
        "web.head" => spec(Recon, Web, &[ReadMetadata], Node),
        "web.get" => spec(ReadOnlyDataAccess, Web, &[ReadMetadata, ReadData], Node),
        "web.auth_probe" => spec(AuthTesting, Web, &[Authenticate, ReadMetadata], Node),
        "web.injection_probe" => spec(InjectionTesting, Web, &[Probe, ReadData], Subtree),
        "web.flood" => spec(AvailabilityStress, Web, &[StressAvailability], Unbounded),
        "db.read" => spec(ReadOnlyDataAccess, Db, &[ReadData], Node),
        "db.write" => spec(DataModification, Db, &[WriteData], Subtree),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Request, stores, sink
// ---------------------------------------------------------------------------

/// An agent-supplied mediation request. **No `session_ref` field**: the authenticated
/// `session_ref` is a separate argument P supplies from its server context (§4a). The
/// target is canonical wire bytes, decoded and validated by the mediator (stage validate).
#[derive(Clone, Debug)]
pub struct MediationRequest {
    pub bundle: Bundle,
    pub operation: String,
    pub target_wire: Vec<u8>,
    /// Logged, never used in the decision.
    pub claimed_class: Option<TestClass>,
}

/// P's store of session authorizations, keyed by the server-held `session_ref`.
pub trait SessionAuthStore {
    fn get(&self, session_ref: &str) -> Result<Option<SessionAuthorization>, Unavailable>;
}

#[derive(Debug, Default)]
pub struct InMemorySessionAuthStore {
    entries: Mutex<Vec<(String, SessionAuthorization)>>,
    unavailable: std::sync::atomic::AtomicBool,
}

impl InMemorySessionAuthStore {
    pub fn insert(&self, session_ref: &str, auth: SessionAuthorization) {
        self.entries
            .lock()
            .expect("lock")
            .push((session_ref.to_owned(), auth));
    }
    pub fn set_unavailable(&self, v: bool) {
        self.unavailable
            .store(v, std::sync::atomic::Ordering::SeqCst);
    }
}

impl SessionAuthStore for InMemorySessionAuthStore {
    fn get(&self, session_ref: &str) -> Result<Option<SessionAuthorization>, Unavailable> {
        if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Unavailable);
        }
        let e = self.entries.lock().map_err(|_| Unavailable)?;
        Ok(e.iter()
            .find(|(r, _)| r == session_ref)
            .map(|(_, a)| a.clone()))
    }
}

/// The record of one performed synthetic effect. Private fields; only [`Mediator::mediate`]
/// (at `perform`) constructs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectReceipt {
    session_ref: String,
    operation: String,
    target: AssetRef,
    test_class: TestClass,
    effects: Vec<Effect>,
    performed_at: Ts,
}

impl EffectReceipt {
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn target(&self) -> &AssetRef {
        &self.target
    }
    pub fn test_class(&self) -> TestClass {
        self.test_class
    }
    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }
    pub fn performed_at(&self) -> Ts {
        self.performed_at
    }
}

/// The only place a modeled effect is recorded. A concrete in-memory type, not a public
/// trait: its append (`record`) is module-private, so only [`Mediator::mediate`] (at
/// `perform`) can grow it. External callers get read-only inspection (`len`, `receipts`),
/// so a cloned [`EffectReceipt`] cannot drive a second effect. "Synthetic in-memory effects
/// only" — there is no public sink interface to implement.
#[derive(Debug, Default)]
pub struct EffectSink {
    records: Mutex<Vec<EffectReceipt>>,
}

impl EffectSink {
    pub fn new() -> Self {
        EffectSink::default()
    }
    /// Module-private append. Reachable only from within this module (i.e. `perform`).
    fn record(&self, receipt: EffectReceipt) {
        self.records.lock().expect("lock").push(receipt);
    }
    pub fn len(&self) -> usize {
        self.records.lock().expect("lock").len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Read-only snapshot of the recorded receipts.
    pub fn receipts(&self) -> Vec<EffectReceipt> {
        self.records.lock().expect("lock").clone()
    }
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediationStage {
    Validate,
    Session,
    Expiry,
    Chain,
    Classify,
    Effects,
    Scope,
    Class,
}

impl fmt::Display for MediationStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MediationStage::Validate => "validate",
            MediationStage::Session => "session",
            MediationStage::Expiry => "expiry",
            MediationStage::Chain => "chain",
            MediationStage::Classify => "classify",
            MediationStage::Effects => "effects",
            MediationStage::Scope => "scope",
            MediationStage::Class => "class",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediationReason {
    DenyNoncanonicalTarget,
    SessionStateUnavailable,
    DenyNoSession,
    ClockUnavailable,
    InvalidClockReading,
    DenySessionExpired,
    ClockUncertainty,
    ChainRejected(Decision),
    ChainIndeterminate(Decision),
    DenyGrantMismatch,
    DenyUnknownOperation,
    DenyTargetTypeMismatch,
    DenyUnboundedSecondaryEffect,
    DenyTargetExcluded,
    DenyTargetOutOfScope,
    DenySubtreePartiallyAllowed,
    DenySubtreeNoneAllowed,
    DenyTestClassNotPermitted,
}

impl fmt::Display for MediationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediationReason::ChainRejected(d) => write!(f, "ChainRejected({d})"),
            MediationReason::ChainIndeterminate(d) => write!(f, "ChainIndeterminate({d})"),
            other => write!(f, "{other:?}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediationFinding {
    pub stage: MediationStage,
    pub reason: MediationReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mediate {
    Allow(Box<EffectReceipt>),
    Deny(MediationFinding),
    Indeterminate(MediationFinding),
}

impl Mediate {
    fn deny(stage: MediationStage, reason: MediationReason) -> Self {
        Mediate::Deny(MediationFinding { stage, reason })
    }
    fn indeterminate(stage: MediationStage, reason: MediationReason) -> Self {
        Mediate::Indeterminate(MediationFinding { stage, reason })
    }
    pub fn is_allow(&self) -> bool {
        matches!(self, Mediate::Allow(_))
    }
    pub fn finding(&self) -> Option<&MediationFinding> {
        match self {
            Mediate::Allow(_) => None,
            Mediate::Deny(f) | Mediate::Indeterminate(f) => Some(f),
        }
    }
}

impl fmt::Display for Mediate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mediate::Allow(_) => f.write_str("Allow"),
            Mediate::Deny(x) => write!(f, "Deny / {} / {}", x.stage, x.reason),
            Mediate::Indeterminate(x) => write!(f, "Indeterminate / {} / {}", x.stage, x.reason),
        }
    }
}

// ---------------------------------------------------------------------------
// Mediator
// ---------------------------------------------------------------------------

pub struct Mediator<'a> {
    pub chain: ChainVerifier<'a>,
    pub sessions: &'a dyn SessionAuthStore,
    pub sink: &'a EffectSink,
}

/// Decode `target_wire` through the validated path: strict JSON, typed `AssetRef`
/// (validates host/path/etc.), then canonical re-encode equality (spec §3).
fn validate_target(wire: &[u8]) -> Option<AssetRef> {
    let value: Value = strict_parse(wire).ok()?;
    let asset: AssetRef = serde_json::from_value(value).ok()?;
    if canonical_bytes(&asset).ok()? != wire {
        return None;
    }
    Some(asset)
}

impl Mediator<'_> {
    /// Mediate one action. `authenticated_session_ref` comes from P's server context, not
    /// the request (§4a). Stages run in the documented order; the sink is written only at
    /// `perform`, so every non-Allow leaves the sink length unchanged.
    pub fn mediate(&self, authenticated_session_ref: &str, req: &MediationRequest) -> Mediate {
        use MediationReason as R;
        use MediationStage as S;
        let mut pending: Option<MediationFinding> = None;
        let mut note = |stage, reason| {
            if pending.is_none() {
                pending = Some(MediationFinding { stage, reason });
            }
        };

        // 1. validate
        let Some(target) = validate_target(&req.target_wire) else {
            return Mediate::deny(S::Validate, R::DenyNoncanonicalTarget);
        };

        // 2. session
        let auth = match self.sessions.get(authenticated_session_ref) {
            Err(_) => return Mediate::indeterminate(S::Session, R::SessionStateUnavailable),
            Ok(None) => return Mediate::deny(S::Session, R::DenyNoSession),
            Ok(Some(a)) => a,
        };

        // 3. expiry. Read the clock ONCE into a snapshot reused by expiry, the chain-time
        // check (stage 4) and the receipt (stage 9); never re-read.
        let snapshot: Option<ClockReading> = self.chain.evidence.clock.now();
        match snapshot {
            None => note(S::Expiry, R::ClockUnavailable),
            Some(r) if r.epsilon < 0 => {
                // Invalid uncertainty (spec §6 requires ε ≥ 0); reject, do not clamp. The
                // window check is skipped; perform is unreachable (pending is set).
                note(S::Expiry, R::InvalidClockReading);
            }
            Some(r) => {
                let lo = r.now.0.saturating_sub(r.epsilon);
                let hi = r.now.0.saturating_add(r.epsilon);
                if lo >= auth.grant_window_end().0 {
                    return Mediate::deny(S::Expiry, R::DenySessionExpired);
                }
                if hi >= auth.grant_window_end().0 {
                    note(S::Expiry, R::ClockUncertainty);
                }
            }
        }

        // 4. chain (status stage included) + grant-ref match. Run the chain verification
        // against a clock frozen to the stage-3 snapshot, so the chain-time check uses the
        // same instant as expiry (one decision-time reading for the whole mediation).
        let frozen = FixedClock { reading: snapshot };
        let frozen_verifier = ChainVerifier {
            audience: self.chain.audience,
            evidence: Evidence {
                registry: self.chain.evidence.registry,
                bindings: self.chain.evidence.bindings,
                clock: &frozen,
                status: self.chain.evidence.status,
            },
        };
        let (decision, chain) = frozen_verifier.verify_with_chain(&req.bundle);
        match decision.class() {
            DecisionClass::Reject => return Mediate::deny(S::Chain, R::ChainRejected(decision)),
            DecisionClass::Indeterminate => note(S::Chain, R::ChainIndeterminate(decision.clone())),
            DecisionClass::Accept => {}
        }
        let Some(chain) = chain else {
            return Mediate::deny(S::Chain, R::ChainRejected(decision));
        };
        let [_, _, (_, grant_key)]: [(_, StatusKey); 3] = chain.status_keys();
        if GrantRef::from(&grant_key) != *auth.grant() {
            return Mediate::deny(S::Chain, R::DenyGrantMismatch);
        }

        // 5. classify (from the table, never the claim)
        let Some(spec) = tooltable_v0(&req.operation) else {
            return Mediate::deny(S::Classify, R::DenyUnknownOperation);
        };

        // 6. effects
        if kind_of(&target) != spec.target_kind {
            return Mediate::deny(S::Effects, R::DenyTargetTypeMismatch);
        }
        if spec.footprint == Footprint::Unbounded {
            return Mediate::deny(S::Effects, R::DenyUnboundedSecondaryEffect);
        }

        // 7. scope (validated target vs the accepted G's effective scope)
        let g = chain.grant().body();
        let scope = grant_scope(g);
        match spec.footprint {
            Footprint::Node => match exact_node_lookup(&scope, &target) {
                ExactNodeAnswer::InScope => {}
                ExactNodeAnswer::Excluded => return Mediate::deny(S::Scope, R::DenyTargetExcluded),
                ExactNodeAnswer::OutOfScope => {
                    return Mediate::deny(S::Scope, R::DenyTargetOutOfScope)
                }
            },
            Footprint::Subtree => match subtree_lookup(&scope, &target) {
                SubtreeAnswer::WhollyAllowed => {}
                SubtreeAnswer::PartiallyAllowed => {
                    return Mediate::deny(S::Scope, R::DenySubtreePartiallyAllowed)
                }
                SubtreeAnswer::NoneAllowed => {
                    return Mediate::deny(S::Scope, R::DenySubtreeNoneAllowed)
                }
            },
            Footprint::Unbounded => unreachable!("denied at effects"),
        }

        // 8. class (primary class only; modeled effects are descriptive)
        let permitted = match &g.test_scope {
            TestScope::Unrestricted => true,
            TestScope::Classes { classes } => classes.contains(&spec.primary_class),
        };
        if !permitted {
            return Mediate::deny(S::Class, R::DenyTestClassNotPermitted);
        }

        // 9. perform — only if nothing was recorded Indeterminate. No clock re-read:
        // performed_at is the stage-3 snapshot instant. Reaching here implies the snapshot
        // was present (an absent snapshot is recorded Indeterminate at expiry above).
        if let Some(f) = pending {
            return Mediate::Indeterminate(f);
        }
        let performed_at = snapshot
            .expect("snapshot present: an absent reading is recorded Indeterminate at expiry")
            .now;
        let receipt = EffectReceipt {
            session_ref: authenticated_session_ref.to_owned(),
            operation: req.operation.clone(),
            target,
            test_class: spec.primary_class,
            effects: spec.effects.clone(),
            performed_at,
        };
        self.sink.record(receipt.clone());
        Mediate::Allow(Box::new(receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tooltable_is_provider_owned_and_total_on_known_ops() {
        assert_eq!(
            tooltable_v0("web.get").unwrap().primary_class,
            TestClass::ReadOnlyDataAccess
        );
        assert_eq!(
            tooltable_v0("web.head").unwrap().primary_class,
            TestClass::Recon
        );
        assert_eq!(
            tooltable_v0("web.flood").unwrap().footprint,
            Footprint::Unbounded
        );
        assert!(tooltable_v0("fs.delete").is_none());
    }

    #[test]
    fn validate_target_rejects_noncanonical() {
        let ok =
            br#"{"host":"app.acme.test","kind":"web","path":"/app","port":443,"scheme":"https"}"#;
        assert!(validate_target(ok).is_some());
        let upper =
            br#"{"host":"APP.acme.test","kind":"web","path":"/app","port":443,"scheme":"https"}"#;
        assert!(validate_target(upper).is_none());
        // reordered keys: valid JSON, valid asset, but not canonical bytes
        let reordered =
            br#"{"kind":"web","host":"app.acme.test","path":"/app","port":443,"scheme":"https"}"#;
        assert!(validate_target(reordered).is_none());
    }
}
