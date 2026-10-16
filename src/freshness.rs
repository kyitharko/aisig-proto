//! RQ7 slice — status freshness and bounded revocation reliance (docs/freshness.md f2).
//!
//! A synthetic, in-memory status responder R and a freshness-aware [`FreshnessOracle`] that
//! plugs into the chain verifier's status stage (spec §6, stage X) via
//! [`crate::verifier::StatusOracle`]. Nothing here contacts a real CA, OCSP/CRL endpoint or
//! network: responses are modeled signed statements, timestamps are fixture values, and the
//! clock is injected. The freshness policy never changes the pre-RQ7 outcomes; it is used
//! only where an oracle backed by R is wired in (the RQ7 case runner).
//!
//! The oracle receives the single decision-time clock snapshot the verifier reads once, so
//! the whole-interval freshness check and the chain-time window checks share one instant
//! (docs/freshness.md §4; this includes the RQ6 mediator's frozen snapshot).

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::codec::{canonical_bytes, strict_parse};
use crate::crypto::{self, SecretKey};
use crate::decision::{Obj, Reason};
use crate::evidence::{ClockReading, StatusKey};
use crate::model::Ts;
use crate::verifier::{StatusOracle, StatusStageOutcome};

/// Domain tag of a responder statement; distinct from every chain/session object tag.
pub const RESPONSE_TAG: &str = "StatusResponse";
/// The single global freshness bound F used by the fixture (docs/freshness.md §8).
pub const DEFAULT_F_SECONDS: i64 = 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponderStatus {
    Active,
    Revoked,
    Superseded,
}

impl ResponderStatus {
    fn as_str(self) -> &'static str {
        match self {
            ResponderStatus::Active => "Active",
            ResponderStatus::Revoked => "Revoked",
            ResponderStatus::Superseded => "Superseded",
        }
    }
}

/// The exact object a response is about: the `StatusKey` fields (spec §6), on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusKeyWire {
    digest: String,
    id: String,
    object_type: String,
    org_id: String,
    version: u32,
}

impl From<&StatusKey> for StatusKeyWire {
    fn from(k: &StatusKey) -> Self {
        StatusKeyWire {
            digest: hex::encode(k.digest),
            id: k.id.clone(),
            object_type: k.object_type.as_str().to_owned(),
            org_id: k.org_id.clone(),
            version: k.version,
        }
    }
}

/// Exactly what R signs (docs/freshness.md §2): three responder timestamps, the status, a
/// monotonic epoch, and the exact object key. P's `observed_at`/`now`/`ε` are never here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWire {
    published_at: Ts,
    response_expires_at: Ts,
    status: String,
    status_epoch: u64,
    status_key: StatusKeyWire,
    status_known_at: Ts,
}

/// A responder statement as bytes plus R's signature over `signed_bytes(RESPONSE_TAG, bytes)`.
#[derive(Clone, Debug)]
pub struct SignedResponse {
    payload: Vec<u8>,
    sig: [u8; 64],
}

impl SignedResponse {
    /// Build and sign a response. `signer` is R's key (pin its public half per org in
    /// [`FreshnessOracle::pinned`]); a non-pinned signer is how FR14 is modeled.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        signer: &SecretKey,
        key: &StatusKey,
        status: ResponderStatus,
        epoch: u64,
        known_at: Ts,
        published_at: Ts,
        expires_at: Ts,
    ) -> SignedResponse {
        let wire = ResponseWire {
            published_at,
            response_expires_at: expires_at,
            status: status.as_str().to_owned(),
            status_epoch: epoch,
            status_key: StatusKeyWire::from(key),
            status_known_at: known_at,
        };
        let payload = canonical_bytes(&wire).expect("response fields are canonicalizable");
        let sig = signer.sign(RESPONSE_TAG, &payload);
        SignedResponse { payload, sig }
    }

    /// SHA-256 of the signed bytes: identity of the whole statement (docs/freshness.md §4),
    /// distinct from the object digest inside `StatusKey`.
    pub fn digest(&self) -> [u8; 32] {
        crypto::object_digest(RESPONSE_TAG, &self.payload)
    }
}

/// Decode and strictly re-canonicalize a response (spec §3 encoding rules, canonical UTC `Z`
/// via `Ts`). `None` means the bytes are not a well-formed canonical `StatusResponse`.
fn decode_response(bytes: &[u8]) -> Option<ResponseWire> {
    let value = strict_parse(bytes).ok()?;
    let wire: ResponseWire = serde_json::from_value(value).ok()?;
    if canonical_bytes(&wire).ok()? != bytes {
        return None;
    }
    Some(wire)
}

/// The modeled status responder R: the signed responses it will return, by exact `StatusKey`.
#[derive(Debug, Default)]
pub struct StatusResponder {
    responses: HashMap<StatusKey, SignedResponse>,
    pub unavailable: bool,
}

impl StatusResponder {
    pub fn new() -> Self {
        StatusResponder::default()
    }

    /// File a response under the key P will look it up by. (For FR12 the stored response's
    /// embedded `status_key` is deliberately a *different* object.)
    pub fn insert(&mut self, key: StatusKey, response: SignedResponse) {
        self.responses.insert(key, response);
    }

    fn get(&self, key: &StatusKey) -> Option<&SignedResponse> {
        self.responses.get(key)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sticky {
    Revoked,
    Superseded,
}

#[derive(Clone, Copy, Debug, Default)]
struct HwmEntry {
    /// `None` until the first Active is accepted; then `(epoch, response-digest)`. Using an
    /// `Option` (rather than a sentinel epoch 0) keeps `status_epoch = 0` a real, valid epoch
    /// so an identical epoch-0 response replays idempotently (review finding 1; FB10).
    recorded: Option<(u64, [u8; 32])>,
    sticky: Option<Sticky>,
}

/// Read-only epoch verdict, used for the early rollback/conflict *reason* (and its precedence
/// over expiry). The authoritative commit is [`HwmStore::accept`], which re-checks atomically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EpochCmp {
    Ok,
    Rollback,
    Conflict,
}

/// Outcome of the atomic Active commit ([`HwmStore::accept`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActiveCommit {
    /// Accepted; the high-water-mark now reflects this response.
    Committed,
    /// A `Revoked`/`Superseded` was recorded before this commit acquired the lock.
    StickyRevoked,
    StickySuperseded,
    /// A newer epoch was committed before this one acquired the lock.
    Rollback,
    /// A different signed response holds this epoch.
    Conflict,
}

/// P's in-memory high-water-mark per `StatusKey`: the greatest accepted epoch, the digest of
/// the response accepted at that epoch, and a sticky revoked/superseded flag. **Not persisted
/// across restarts** (docs/freshness.md §4 restart limitation).
///
/// The store exposes **no public mutation path**. The only way its state changes at runtime is
/// through [`FreshnessOracle`] (which holds `&HwmStore`); the seeding seams are crate-internal
/// (`pub(crate)`), so an external holder of a `&HwmStore` cannot clear a recorded sticky
/// revocation and let a previously signed, still-fresh Active through:
///
/// ```compile_fail,E0603
/// use aisig_proto::codec::TypeTag;
/// use aisig_proto::evidence::StatusKey;
/// use aisig_proto::freshness::HwmStore;
/// let hwm = HwmStore::new();
/// let k = StatusKey::for_object("org", TypeTag::EngagementGrant, "g", 1, b"{}");
/// // `seed_epoch` is pub(crate): replacing the entry would clear the sticky flag.
/// hwm.seed_epoch(&k, 0, [0u8; 32]);
/// ```
///
/// ```compile_fail,E0603
/// use aisig_proto::codec::TypeTag;
/// use aisig_proto::evidence::StatusKey;
/// use aisig_proto::freshness::HwmStore;
/// let hwm = HwmStore::new();
/// let k = StatusKey::for_object("org", TypeTag::EngagementGrant, "g", 1, b"{}");
/// // `seed_sticky_revoked` is pub(crate) too: no external mutation of the HWM.
/// hwm.seed_sticky_revoked(&k);
/// ```
#[derive(Debug, Default)]
pub struct HwmStore(Mutex<HashMap<StatusKey, HwmEntry>>);

impl HwmStore {
    pub fn new() -> Self {
        HwmStore::default()
    }

    fn sticky(&self, key: &StatusKey) -> Option<Sticky> {
        self.0
            .lock()
            .expect("hwm lock")
            .get(key)
            .and_then(|e| e.sticky)
    }

    fn set_sticky(&self, key: &StatusKey, kind: Sticky) {
        let mut m = self.0.lock().expect("hwm lock");
        m.entry(key.clone()).or_default().sticky = Some(kind);
    }

    fn epoch_cmp(&self, key: &StatusKey, epoch: u64, digest: [u8; 32]) -> EpochCmp {
        match self
            .0
            .lock()
            .expect("hwm lock")
            .get(key)
            .and_then(|e| e.recorded)
        {
            None => EpochCmp::Ok,
            Some((hep, _)) if epoch < hep => EpochCmp::Rollback,
            Some((hep, hdg)) if epoch == hep && hdg != digest => EpochCmp::Conflict,
            Some(_) => EpochCmp::Ok,
        }
    }

    /// Atomically decide and commit an Active response: under **one** lock acquisition (the
    /// decision's linearization point), re-check the sticky flag and the recorded epoch, then
    /// advance the high-water-mark only if the response is still acceptable (docs/freshness.md
    /// §4). This closes the window between the earlier read-only checks and the commit.
    fn accept(&self, key: &StatusKey, epoch: u64, digest: [u8; 32]) -> ActiveCommit {
        let mut m = self.0.lock().expect("hwm lock");
        let e = m.entry(key.clone()).or_default();
        if let Some(s) = e.sticky {
            return match s {
                Sticky::Revoked => ActiveCommit::StickyRevoked,
                Sticky::Superseded => ActiveCommit::StickySuperseded,
            };
        }
        match e.recorded {
            None => {
                e.recorded = Some((epoch, digest));
                ActiveCommit::Committed
            }
            Some((hep, _)) if epoch < hep => ActiveCommit::Rollback,
            Some((hep, hdg)) if epoch == hep => {
                if hdg == digest {
                    ActiveCommit::Committed
                } else {
                    ActiveCommit::Conflict
                }
            }
            Some(_) => {
                e.recorded = Some((epoch, digest));
                ActiveCommit::Committed
            }
        }
    }

    /// Crate-internal setup seam: pre-seed P's remembered high-water-mark for a key (models a
    /// response P accepted earlier). Used by the RQ7 case runner for rollback/conflict/
    /// idempotent. **Not public:** it replaces the entry (clearing any sticky revocation), so
    /// exposing it would let an external holder of a `&HwmStore` undo a recorded revocation.
    pub(crate) fn seed_epoch(&self, key: &StatusKey, epoch: u64, digest: [u8; 32]) {
        let mut m = self.0.lock().expect("hwm lock");
        m.insert(
            key.clone(),
            HwmEntry {
                recorded: Some((epoch, digest)),
                sticky: None,
            },
        );
    }

    /// Crate-internal setup seam: mark a key as having already shown a validated
    /// Revoked/Superseded. Not public, for the same reason as [`HwmStore::seed_epoch`].
    pub(crate) fn seed_sticky_revoked(&self, key: &StatusKey) {
        self.set_sticky(key, Sticky::Revoked);
    }

    /// Test accessor: the recorded high-water epoch (`None` if no Active has been accepted)
    /// and the sticky flag.
    #[cfg(test)]
    fn snapshot(&self, key: &StatusKey) -> (Option<u64>, Option<Sticky>) {
        match self.0.lock().expect("hwm lock").get(key) {
            None => (None, None),
            Some(e) => (e.recorded.map(|(ep, _)| ep), e.sticky),
        }
    }
}

/// The freshness-aware status stage (docs/freshness.md §3–§4). Borrows the responder, the
/// per-org pinned responder keys `K_R`, the global `F`, and the high-water-mark store.
pub struct FreshnessOracle<'a> {
    pub responder: &'a StatusResponder,
    /// org_id → pinned responder public key `K_R`.
    pub pinned: &'a HashMap<String, [u8; 32]>,
    pub f_seconds: i64,
    pub hwm: &'a HwmStore,
}

impl StatusOracle for FreshnessOracle<'_> {
    fn evaluate(
        &self,
        obj: Obj,
        key: &StatusKey,
        reading: Option<ClockReading>,
    ) -> StatusStageOutcome {
        use StatusStageOutcome as O;

        // Precedence 1: sticky revoked/superseded (one-way; no clock needed).
        if let Some(s) = self.hwm.sticky(key) {
            return match s {
                Sticky::Revoked => O::Reject(Reason::Revoked(obj)),
                Sticky::Superseded => O::Reject(Reason::Superseded(obj)),
            };
        }

        // Lookup (§3): unavailable / no response for this exact key / a candidate.
        if self.responder.unavailable {
            return O::Unavailable;
        }
        let Some(resp) = self.responder.get(key) else {
            return O::Indeterminate(Reason::StatusUnknown(obj));
        };

        // Validation gate (§3): canonical decode, pinned-key signature, ordering, status enum.
        let Some(wire) = decode_response(&resp.payload) else {
            return O::Indeterminate(Reason::StatusResponseInvalid);
        };
        let Some(kr) = self.pinned.get(&key.org_id) else {
            return O::Indeterminate(Reason::StatusResponseInvalid);
        };
        if !crypto::verify(kr, RESPONSE_TAG, &resp.payload, &resp.sig) {
            return O::Indeterminate(Reason::StatusResponseInvalid);
        }
        // Exact-key match is a *matching* condition: a response about a different object is
        // "no answer for this one" → StatusUnknown, not invalid (docs/freshness.md §3, FR12).
        if wire.status_key != StatusKeyWire::from(key) {
            return O::Indeterminate(Reason::StatusUnknown(obj));
        }
        if !(wire.status_known_at.0 <= wire.published_at.0
            && wire.published_at.0 <= wire.response_expires_at.0)
        {
            return O::Indeterminate(Reason::StatusResponseInvalid);
        }
        let status = match wire.status.as_str() {
            "Active" => ResponderStatus::Active,
            "Revoked" => ResponderStatus::Revoked,
            "Superseded" => ResponderStatus::Superseded,
            _ => return O::Indeterminate(Reason::StatusResponseInvalid),
        };

        // Precedence 2: this response is Revoked/Superseded → Reject, set sticky, ignore age.
        match status {
            ResponderStatus::Revoked => {
                self.hwm.set_sticky(key, Sticky::Revoked);
                return O::Reject(Reason::Revoked(obj));
            }
            ResponderStatus::Superseded => {
                self.hwm.set_sticky(key, Sticky::Superseded);
                return O::Reject(Reason::Superseded(obj));
            }
            ResponderStatus::Active => {}
        }

        // Active needs the clock. A missing/negative reading is already noted Indeterminate at
        // the time stage; here it means freshness cannot be established (never Accept).
        let Some(r) = reading.filter(|r| r.epsilon >= 0) else {
            return O::Indeterminate(Reason::StatusFreshnessUncertain);
        };
        let lo = r.now.0.saturating_sub(r.epsilon); // now − ε
        let hi = r.now.0.saturating_add(r.epsilon); // now + ε

        // Precedence 3: future over the whole interval (docs/freshness.md §4).
        let latest = wire.published_at.0.max(wire.status_known_at.0);
        if latest > lo {
            return O::Indeterminate(Reason::StatusTimestampInFuture);
        }

        // Precedence 4: epoch rollback / same-epoch conflict (read-only reason; precedence
        // over expiry). The atomic commit below is authoritative for the accept path.
        let resp_digest = resp.digest();
        match self.hwm.epoch_cmp(key, wire.status_epoch, resp_digest) {
            EpochCmp::Rollback => return O::Indeterminate(Reason::StatusRollback),
            EpochCmp::Conflict => return O::Indeterminate(Reason::StatusEpochConflict),
            EpochCmp::Ok => {}
        }

        // Precedence 5: expiry over the whole interval.
        if lo >= wire.response_expires_at.0 {
            return O::Indeterminate(Reason::StatusStale);
        }
        if wire.response_expires_at.0 <= hi {
            return O::Indeterminate(Reason::StatusFreshnessUncertain);
        }

        // Precedence 6: freshness (age) over the whole interval.
        let age_min = lo - wire.status_known_at.0;
        let age_max = hi - wire.status_known_at.0;
        if age_min > self.f_seconds {
            return O::Indeterminate(Reason::StatusStale);
        }
        if age_max > self.f_seconds {
            return O::Indeterminate(Reason::StatusFreshnessUncertain);
        }

        // Precedence 7: atomic commit (docs/freshness.md §4). Re-check sticky + epoch and
        // advance the high-water-mark under one lock — the decision's linearization point —
        // so an Active cannot commit after a concurrent revocation or over a newer epoch.
        match self.hwm.accept(key, wire.status_epoch, resp_digest) {
            ActiveCommit::Committed => O::Ok,
            ActiveCommit::StickyRevoked => O::Reject(Reason::Revoked(obj)),
            ActiveCommit::StickySuperseded => O::Reject(Reason::Superseded(obj)),
            ActiveCommit::Rollback => O::Indeterminate(Reason::StatusRollback),
            ActiveCommit::Conflict => O::Indeterminate(Reason::StatusEpochConflict),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kr() -> SecretKey {
        SecretKey::from_seed(&[9u8; 32])
    }

    fn key() -> StatusKey {
        StatusKey::for_object(
            "org-acme-synthetic",
            crate::codec::TypeTag::EngagementGrant,
            "g-1",
            1,
            b"{\"a\":1}",
        )
    }

    fn pinned() -> HashMap<String, [u8; 32]> {
        let mut m = HashMap::new();
        m.insert("org-acme-synthetic".to_owned(), kr().public_bytes());
        m
    }

    fn reading() -> Option<ClockReading> {
        Some(ClockReading {
            now: ts("2026-10-15T10:00:00Z"),
            epsilon: 2,
        })
    }

    fn ts(s: &str) -> Ts {
        Ts::parse(s).expect("canonical")
    }

    fn active(epoch: u64, known: &str, pubd: &str, exp: &str) -> SignedResponse {
        SignedResponse::build(
            &kr(),
            &key(),
            ResponderStatus::Active,
            epoch,
            ts(known),
            ts(pubd),
            ts(exp),
        )
    }

    #[test]
    fn fresh_active_is_ok() {
        let mut r = StatusResponder::new();
        r.insert(
            key(),
            active(
                1,
                "2026-10-15T09:59:00Z",
                "2026-10-15T09:59:00Z",
                "2026-10-15T11:00:00Z",
            ),
        );
        let pins = pinned();
        let hwm = HwmStore::new();
        let oracle = FreshnessOracle {
            responder: &r,
            pinned: &pins,
            f_seconds: DEFAULT_F_SECONDS,
            hwm: &hwm,
        };
        assert_eq!(
            oracle.evaluate(Obj::Grant, &key(), reading()),
            StatusStageOutcome::Ok
        );
    }

    #[test]
    fn wrong_signer_is_invalid() {
        let mut r = StatusResponder::new();
        let rogue = SecretKey::from_seed(&[1u8; 32]);
        let resp = SignedResponse::build(
            &rogue,
            &key(),
            ResponderStatus::Active,
            1,
            ts("2026-10-15T09:59:00Z"),
            ts("2026-10-15T09:59:00Z"),
            ts("2026-10-15T11:00:00Z"),
        );
        r.insert(key(), resp);
        let pins = pinned();
        let hwm = HwmStore::new();
        let oracle = FreshnessOracle {
            responder: &r,
            pinned: &pins,
            f_seconds: DEFAULT_F_SECONDS,
            hwm: &hwm,
        };
        assert_eq!(
            oracle.evaluate(Obj::Grant, &key(), reading()),
            StatusStageOutcome::Indeterminate(Reason::StatusResponseInvalid)
        );
    }

    // Reproduction (finding 1): epoch 0 is a valid epoch. Accept an epoch-0 Active, then
    // replay the identical signed response against the same HWM; it must remain accepted.
    #[test]
    fn epoch_zero_active_replays_idempotently() {
        let r0 = active(
            0,
            "2026-10-15T09:59:00Z",
            "2026-10-15T09:59:00Z",
            "2026-10-15T11:00:00Z",
        );
        let mut r = StatusResponder::new();
        r.insert(key(), r0);
        let pins = pinned();
        let hwm = HwmStore::new();
        let oracle = FreshnessOracle {
            responder: &r,
            pinned: &pins,
            f_seconds: DEFAULT_F_SECONDS,
            hwm: &hwm,
        };
        assert_eq!(
            oracle.evaluate(Obj::Grant, &key(), reading()),
            StatusStageOutcome::Ok,
            "first epoch-0 Active must be accepted"
        );
        assert_eq!(
            oracle.evaluate(Obj::Grant, &key(), reading()),
            StatusStageOutcome::Ok,
            "an identical epoch-0 Active must replay idempotently, not conflict"
        );
    }

    // Reproduction (finding 2): a validated Revoked commits between an Active request's initial
    // checks and its final commit. The commit must be atomic: the Active must not advance the
    // high-water-mark over a recorded revocation.
    #[test]
    fn active_does_not_commit_after_a_concurrent_revocation() {
        let hwm = HwmStore::new();
        let k = key();
        let dg = [7u8; 32];
        // Active request's initial checks pass (no sticky, epoch fine):
        assert!(hwm.sticky(&k).is_none());
        assert_eq!(hwm.epoch_cmp(&k, 1, dg), EpochCmp::Ok);
        // A validated Revoked commits in the window:
        hwm.set_sticky(&k, Sticky::Revoked);
        // The Active's final commit must be atomic: it observes the revocation and refuses.
        assert_eq!(hwm.accept(&k, 1, dg), ActiveCommit::StickyRevoked);
        let (recorded, sticky) = hwm.snapshot(&k);
        assert_eq!(sticky, Some(Sticky::Revoked));
        assert!(
            recorded.is_none(),
            "an Active must not commit its epoch after a recorded revocation (got {recorded:?})"
        );
    }

    // Reproduction/retained regression (seed_epoch privacy): a validated Revoked makes a later
    // still-fresh, validly signed (not forged) Active Reject by the sticky flag. Clearing the
    // high-water-mark via seed_epoch would wrongly accept that Active — which is exactly why
    // the seeding seams are now crate-internal (pub(crate); the external boundary is guarded by
    // the compile_fail doctests on HwmStore). No responder signature is forged here.
    #[test]
    fn sticky_revocation_dominates_a_signed_active_until_the_hwm_is_reseeded() {
        let pins = pinned();
        let hwm = HwmStore::new();

        // A real, K_R-signed Revoked response records the sticky flag.
        let mut r_rev = StatusResponder::new();
        r_rev.insert(
            key(),
            SignedResponse::build(
                &kr(),
                &key(),
                ResponderStatus::Revoked,
                1,
                ts("2026-10-15T09:59:00Z"),
                ts("2026-10-15T09:59:00Z"),
                ts("2026-10-15T11:00:00Z"),
            ),
        );
        let oracle_rev = FreshnessOracle {
            responder: &r_rev,
            pinned: &pins,
            f_seconds: DEFAULT_F_SECONDS,
            hwm: &hwm,
        };
        assert_eq!(
            oracle_rev.evaluate(Obj::Grant, &key(), reading()),
            StatusStageOutcome::Reject(Reason::Revoked(Obj::Grant))
        );

        // A real, K_R-signed fresh Active (not forged).
        let mut r_act = StatusResponder::new();
        r_act.insert(
            key(),
            active(
                2,
                "2026-10-15T09:59:00Z",
                "2026-10-15T09:59:00Z",
                "2026-10-15T11:00:00Z",
            ),
        );
        let oracle_act = FreshnessOracle {
            responder: &r_act,
            pinned: &pins,
            f_seconds: DEFAULT_F_SECONDS,
            hwm: &hwm,
        };
        // Retained regression: the sticky revocation dominates the fresh Active.
        assert_eq!(
            oracle_act.evaluate(Obj::Grant, &key(), reading()),
            StatusStageOutcome::Reject(Reason::Revoked(Obj::Grant))
        );

        // The hazard, now reachable only crate-internally: reseeding clears the sticky flag,
        // after which the still-fresh, validly signed Active is accepted.
        hwm.seed_epoch(&key(), 0, [0u8; 32]);
        assert_eq!(
            oracle_act.evaluate(Obj::Grant, &key(), reading()),
            StatusStageOutcome::Ok
        );
    }

    // Regression (finding 2): competing Active epochs. Once a newer epoch has committed, an
    // older epoch's commit must roll back rather than report success — the atomic commit takes
    // the epoch decision at the lock, not from an earlier read.
    #[test]
    fn competing_epochs_older_does_not_commit_after_newer() {
        let hwm = HwmStore::new();
        let k = key();
        // The older request reads an empty store (would-be Ok)...
        assert_eq!(hwm.epoch_cmp(&k, 1, [1u8; 32]), EpochCmp::Ok);
        // ...but a newer epoch commits first...
        assert_eq!(hwm.accept(&k, 2, [2u8; 32]), ActiveCommit::Committed);
        // ...so the older commit must roll back, not succeed.
        assert_eq!(hwm.accept(&k, 1, [1u8; 32]), ActiveCommit::Rollback);
        assert_eq!(hwm.snapshot(&k).0, Some(2));
    }
}
