//! RQ5 slice s1: tester proof of possession bound to a provider-held session
//! (docs/session.md).
//!
//! This is a separate decision from ValidChain_P. A chain `Accept` is never a session
//! authorization; a [`SessionAuthorization`] exists only as the result of a successful
//! [`SessionService::redeem`].
//!
//! ```compile_fail,E0451
//! // A SessionAuthorization cannot be fabricated from a chain Accept or by hand.
//! use aisig_proto::session::{GrantRef, SessionAuthorization};
//! let _ = SessionAuthorization { session_id: String::new(), ..todo!() };
//! ```
//!
//! Not claimed: channel binding, relay or phishing resistance, per-request proof of
//! possession after redemption, tool enforcement (RQ6), status freshness (RQ7).

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::codec::{b64_decode, b64_encode, canonical_bytes, strict_parse};
use crate::crypto;
use crate::decision::{Decision, DecisionClass};
use crate::evidence::{StatusKey, Unavailable};
use crate::model::Ts;
use crate::verifier::{Bundle, ChainVerifier};

pub const SESSION_FORMAT: &str = "aisig-session/v0";
/// Domain tag of the tester's signed response; distinct from every chain object tag.
pub const RESPONSE_TAG: &str = "SessionChallengeResponse";
pub const DEFAULT_TTL_SECONDS: i64 = 120;

// ---------------------------------------------------------------------------
// Challenge and proof wire forms
// ---------------------------------------------------------------------------

/// The exact signed G a challenge is bound to: its StatusKey fields (spec §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRef {
    pub digest: String,
    pub id: String,
    pub object_type: String,
    pub org_id: String,
    pub version: u32,
}

impl From<&StatusKey> for GrantRef {
    fn from(k: &StatusKey) -> Self {
        GrantRef {
            digest: hex::encode(k.digest),
            id: k.id.clone(),
            object_type: k.object_type.as_str().to_owned(),
            org_id: k.org_id.clone(),
            version: k.version,
        }
    }
}

/// A provider-issued challenge (docs/session.md §3). P keeps the authoritative copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub audience: String,
    pub challenge_id: String,
    pub expires_at: Ts,
    pub format: String,
    pub grant: GrantRef,
    pub issued_at: Ts,
    pub nonce: String,
    pub session_id: String,
}

impl Challenge {
    /// Canonical bytes of the challenge (spec §3 canonical JSON rules).
    pub fn wire_bytes(&self) -> Vec<u8> {
        canonical_bytes(self).expect("challenge fields are strings, integers and times")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofWire {
    challenge_id: String,
    format: String,
    sig: String,
}

/// Encode a tester response: `{challenge_id, format, sig}`. The signature must cover
/// `signed_bytes(RESPONSE_TAG, challenge.wire_bytes())`.
pub fn encode_proof(challenge_id: &str, sig: &[u8; 64]) -> Vec<u8> {
    canonical_bytes(&ProofWire {
        challenge_id: challenge_id.to_owned(),
        format: SESSION_FORMAT.to_owned(),
        sig: b64_encode(sig),
    })
    .expect("proof fields are strings")
}

fn decode_proof(bytes: &[u8]) -> Option<(String, [u8; 64])> {
    let value = strict_parse(bytes).ok()?;
    let w: ProofWire = serde_json::from_value(value).ok()?;
    if w.format != SESSION_FORMAT {
        return None;
    }
    let sig = b64_decode(&w.sig)?.try_into().ok()?;
    Some((w.challenge_id, sig))
}

// ---------------------------------------------------------------------------
// Provider-held challenge state and randomness
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeState {
    Pending,
    Consumed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// This call moved the record from Pending to Consumed.
    Consumed,
    AlreadyConsumed,
    NotFound,
}

/// P's challenge store. `consume` must be an atomic compare-and-set.
pub trait ChallengeStore: Send + Sync {
    fn insert(&self, challenge: Challenge) -> Result<(), Unavailable>;
    fn get(&self, challenge_id: &str) -> Result<Option<(Challenge, ChallengeState)>, Unavailable>;
    fn consume(&self, challenge_id: &str) -> Result<ConsumeOutcome, Unavailable>;
}

/// In-memory store: one lock, no expiry sweeping. Synthetic.
#[derive(Debug, Default)]
pub struct InMemoryChallengeStore {
    records: Mutex<HashMap<String, (Challenge, ChallengeState)>>,
    unavailable: AtomicBool,
}

impl InMemoryChallengeStore {
    pub fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    /// Test/inspection helper: current state of a record.
    pub fn state(&self, challenge_id: &str) -> Option<ChallengeState> {
        self.records
            .lock()
            .expect("lock")
            .get(challenge_id)
            .map(|(_, s)| *s)
    }

    fn check(&self) -> Result<(), Unavailable> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(Unavailable)
        } else {
            Ok(())
        }
    }
}

impl ChallengeStore for InMemoryChallengeStore {
    fn insert(&self, challenge: Challenge) -> Result<(), Unavailable> {
        self.check()?;
        let mut records = self.records.lock().map_err(|_| Unavailable)?;
        if records.contains_key(&challenge.challenge_id) {
            return Err(Unavailable); // never overwrite an existing challenge
        }
        records.insert(
            challenge.challenge_id.clone(),
            (challenge, ChallengeState::Pending),
        );
        Ok(())
    }

    fn get(&self, challenge_id: &str) -> Result<Option<(Challenge, ChallengeState)>, Unavailable> {
        self.check()?;
        let records = self.records.lock().map_err(|_| Unavailable)?;
        Ok(records.get(challenge_id).cloned())
    }

    fn consume(&self, challenge_id: &str) -> Result<ConsumeOutcome, Unavailable> {
        self.check()?;
        let mut records = self.records.lock().map_err(|_| Unavailable)?;
        Ok(match records.get_mut(challenge_id) {
            None => ConsumeOutcome::NotFound,
            Some((_, state @ ChallengeState::Pending)) => {
                *state = ChallengeState::Consumed;
                ConsumeOutcome::Consumed
            }
            Some((_, ChallengeState::Consumed)) => ConsumeOutcome::AlreadyConsumed,
        })
    }
}

/// Source of unpredictable bytes for nonces and challenge ids.
pub trait RandomSource: Sync {
    fn fill(&self, buf: &mut [u8]) -> Result<(), Unavailable>;
}

/// The operating system CSPRNG (`getrandom`).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), Unavailable> {
        getrandom::fill(buf).map_err(|_| Unavailable)
    }
}

// ---------------------------------------------------------------------------
// Session decision
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStage {
    Chain,
    Proof,
    Challenge,
    Binding,
    Time,
    Pop,
    Consume,
}

impl fmt::Display for SessionStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SessionStage::Chain => "chain",
            SessionStage::Proof => "proof",
            SessionStage::Challenge => "challenge",
            SessionStage::Binding => "binding",
            SessionStage::Time => "time",
            SessionStage::Pop => "pop",
            SessionStage::Consume => "consume",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionReason {
    ChainRejected(Decision),
    ChainIndeterminate(Decision),
    MissingProof,
    MalformedProof,
    ChallengeStateUnavailable,
    UnknownChallenge,
    ChallengeAlreadyConsumed,
    ChallengeAudienceMismatch,
    SessionMismatch,
    GrantMismatch,
    ClockUnavailable,
    ClockUncertainty,
    ChallengeExpired,
    InvalidProofSignature,
}

impl fmt::Display for SessionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionReason::ChainRejected(d) => write!(f, "ChainRejected({d})"),
            SessionReason::ChainIndeterminate(d) => write!(f, "ChainIndeterminate({d})"),
            other => write!(f, "{other:?}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionFinding {
    pub stage: SessionStage,
    pub reason: SessionReason,
}

/// What P may attach to its session after a successful redemption. Fields are private:
/// the only constructor is [`SessionService::redeem`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionAuthorization {
    session_id: String,
    challenge_id: String,
    audience: String,
    grant: GrantRef,
    tester_key_id: String,
    authorized_at: Ts,
    grant_window_end: Ts,
}

impl SessionAuthorization {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn grant(&self) -> &GrantRef {
        &self.grant
    }
    pub fn tester_key_id(&self) -> &str {
        &self.tester_key_id
    }
    pub fn authorized_at(&self) -> Ts {
        self.authorized_at
    }
    /// P must not treat the session as authorized at or after this instant.
    pub fn grant_window_end(&self) -> Ts {
        self.grant_window_end
    }
}

/// The RQ5 session decision. Distinct from the chain [`Decision`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionDecision {
    Accept(Box<SessionAuthorization>),
    Reject(SessionFinding),
    Indeterminate(SessionFinding),
}

impl SessionDecision {
    fn reject(stage: SessionStage, reason: SessionReason) -> Self {
        SessionDecision::Reject(SessionFinding { stage, reason })
    }

    pub fn finding(&self) -> Option<&SessionFinding> {
        match self {
            SessionDecision::Accept(_) => None,
            SessionDecision::Reject(f) | SessionDecision::Indeterminate(f) => Some(f),
        }
    }
}

impl fmt::Display for SessionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionDecision::Accept(_) => f.write_str("SessionAccept"),
            SessionDecision::Reject(x) => write!(f, "SessionReject / {} / {}", x.stage, x.reason),
            SessionDecision::Indeterminate(x) => {
                write!(f, "SessionIndeterminate / {} / {}", x.stage, x.reason)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueFailure {
    ClockUnavailable,
    NonceUnavailable,
    ChallengeStateUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueOutcome {
    Issued(Box<Challenge>),
    /// The chain was not accepted; no challenge was created.
    Refused(Decision),
    Unavailable(IssueFailure),
}

impl fmt::Display for IssueOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueOutcome::Issued(c) => write!(f, "Issued expires_at={}", c.expires_at),
            IssueOutcome::Refused(d) => write!(f, "IssueRefused / {d}"),
            IssueOutcome::Unavailable(x) => write!(f, "IssueUnavailable / {x:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Issues and redeems challenges for P. Both operations take raw bundle bytes and
/// re-run the chain verifier; there is no pre-decoded entry point (spec §7.5).
pub struct SessionService<'a> {
    chain: ChainVerifier<'a>,
    store: &'a dyn ChallengeStore,
    random: &'a dyn RandomSource,
}

impl<'a> SessionService<'a> {
    pub fn new(
        chain: ChainVerifier<'a>,
        store: &'a dyn ChallengeStore,
        random: &'a dyn RandomSource,
    ) -> Self {
        SessionService {
            chain,
            store,
            random,
        }
    }

    /// docs/session.md §4. `session_id` must come from P's own session state.
    pub fn issue(&self, bundle: &Bundle, session_id: &str) -> IssueOutcome {
        let (decision, chain) = self.chain.verify_with_chain(bundle);
        let (Decision::Accept, Some(chain)) = (&decision, chain) else {
            return IssueOutcome::Refused(decision);
        };
        let Some(reading) = self.chain.evidence.clock.now() else {
            return IssueOutcome::Unavailable(IssueFailure::ClockUnavailable);
        };
        let grant = chain.grant().body();
        // Fixed 120 s TTL, clamped to the grant. Checked add: on overflow (unreachable with
        // any RFC 3339 clock) fall back to the grant end, which never exceeds the grant.
        let expires_at = Ts(match reading.now.0.checked_add(DEFAULT_TTL_SECONDS) {
            Some(end) => end.min(grant.window.end.0),
            None => grant.window.end.0,
        });
        let mut nonce = [0u8; 32];
        let mut id = [0u8; 16];
        if self.random.fill(&mut nonce).is_err() || self.random.fill(&mut id).is_err() {
            return IssueOutcome::Unavailable(IssueFailure::NonceUnavailable);
        }
        let [_, _, (_, grant_key)] = chain.status_keys();
        let challenge = Challenge {
            audience: self.chain.audience.to_owned(),
            challenge_id: hex::encode(id),
            expires_at,
            format: SESSION_FORMAT.to_owned(),
            grant: GrantRef::from(&grant_key),
            issued_at: reading.now,
            nonce: b64_encode(&nonce),
            session_id: session_id.to_owned(),
        };
        match self.store.insert(challenge.clone()) {
            Ok(()) => IssueOutcome::Issued(Box::new(challenge)),
            Err(_) => IssueOutcome::Unavailable(IssueFailure::ChallengeStateUnavailable),
        }
    }

    /// docs/session.md §5. `session_id` must come from P's own session state, never from
    /// the bundle or the proof.
    pub fn redeem(
        &self,
        bundle: &Bundle,
        session_id: &str,
        proof: Option<&[u8]>,
    ) -> SessionDecision {
        use SessionReason as R;
        use SessionStage as S;
        let mut pending: Option<SessionFinding> = None;

        // chain — re-verified now. Under a chain Indeterminate the decoded chain is used
        // only to find contradictions (Reject), never to support Accept.
        let (decision, chain) = self.chain.verify_with_chain(bundle);
        match decision.class() {
            DecisionClass::Reject => {
                return SessionDecision::reject(S::Chain, R::ChainRejected(decision))
            }
            DecisionClass::Indeterminate => note(
                &mut pending,
                S::Chain,
                R::ChainIndeterminate(decision.clone()),
            ),
            DecisionClass::Accept => {}
        }
        let Some(chain) = chain else {
            return SessionDecision::reject(S::Chain, R::ChainRejected(decision));
        };

        // proof
        let Some(bytes) = proof else {
            return SessionDecision::reject(S::Proof, R::MissingProof);
        };
        let Some((challenge_id, sig)) = decode_proof(bytes) else {
            return SessionDecision::reject(S::Proof, R::MalformedProof);
        };

        // challenge
        let record = match self.store.get(&challenge_id) {
            Err(_) => {
                note(&mut pending, S::Challenge, R::ChallengeStateUnavailable);
                return finish_indeterminate(pending);
            }
            Ok(None) => return SessionDecision::reject(S::Challenge, R::UnknownChallenge),
            Ok(Some((_, ChallengeState::Consumed))) => {
                return SessionDecision::reject(S::Challenge, R::ChallengeAlreadyConsumed)
            }
            Ok(Some((record, ChallengeState::Pending))) => record,
        };

        // binding
        if record.audience != self.chain.audience {
            return SessionDecision::reject(S::Binding, R::ChallengeAudienceMismatch);
        }
        if record.session_id != session_id {
            return SessionDecision::reject(S::Binding, R::SessionMismatch);
        }
        let [_, _, (_, grant_key)] = chain.status_keys();
        let grant_ref = GrantRef::from(&grant_key);
        if record.grant != grant_ref {
            return SessionDecision::reject(S::Binding, R::GrantMismatch);
        }

        // time — half-open expiry with clock uncertainty (spec §6 rule).
        let reading = self.chain.evidence.clock.now();
        match reading {
            None => note(&mut pending, S::Time, R::ClockUnavailable),
            Some(r) => {
                let (lo, hi) = (r.now.0 - r.epsilon, r.now.0 + r.epsilon);
                if lo >= record.expires_at.0 {
                    return SessionDecision::reject(S::Time, R::ChallengeExpired);
                }
                if hi >= record.expires_at.0 {
                    note(&mut pending, S::Time, R::ClockUncertainty);
                }
            }
        }

        // pop — over P's stored record, with K_T from the decoded G.
        let grant = chain.grant().body();
        if !crypto::verify(
            grant.tester_key.bytes(),
            RESPONSE_TAG,
            &record.wire_bytes(),
            &sig,
        ) {
            return SessionDecision::reject(S::Pop, R::InvalidProofSignature);
        }

        // consume — only when every other stage is positive.
        if pending.is_some() {
            return finish_indeterminate(pending);
        }
        let Some(r) = reading else {
            unreachable!("a missing clock reading is recorded as Indeterminate above");
        };
        match self.store.consume(&challenge_id) {
            Ok(ConsumeOutcome::Consumed) => {
                SessionDecision::Accept(Box::new(SessionAuthorization {
                    session_id: session_id.to_owned(),
                    challenge_id,
                    audience: record.audience,
                    grant: grant_ref,
                    tester_key_id: grant.tester_key.key_id().to_owned(),
                    authorized_at: r.now,
                    grant_window_end: grant.window.end,
                }))
            }
            Ok(ConsumeOutcome::AlreadyConsumed) => {
                SessionDecision::reject(S::Consume, R::ChallengeAlreadyConsumed)
            }
            Ok(ConsumeOutcome::NotFound) => {
                SessionDecision::reject(S::Consume, R::UnknownChallenge)
            }
            Err(_) => SessionDecision::Indeterminate(SessionFinding {
                stage: S::Consume,
                reason: R::ChallengeStateUnavailable,
            }),
        }
    }
}

/// Record the first Indeterminate finding; evaluation continues (Reject dominates).
fn note(pending: &mut Option<SessionFinding>, stage: SessionStage, reason: SessionReason) {
    if pending.is_none() {
        *pending = Some(SessionFinding { stage, reason });
    }
}

fn finish_indeterminate(pending: Option<SessionFinding>) -> SessionDecision {
    SessionDecision::Indeterminate(pending.expect("an Indeterminate finding was recorded"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_parsing_is_strict() {
        let good = encode_proof("abc", &[7u8; 64]);
        assert_eq!(decode_proof(&good), Some(("abc".to_owned(), [7u8; 64])));
        let dup =
            br#"{"challenge_id":"a","challenge_id":"b","format":"aisig-session/v0","sig":"x"}"#;
        assert_eq!(decode_proof(dup), None);
        let wrong_format = String::from_utf8(good.clone())
            .unwrap()
            .replace("aisig-session/v0", "aisig-session/v1");
        assert_eq!(decode_proof(wrong_format.as_bytes()), None);
        let short = encode_proof("abc", &[7u8; 64]);
        let short = String::from_utf8(short).unwrap();
        let short = short.replace(&b64_encode(&[7u8; 64]), &b64_encode(&[7u8; 63]));
        assert_eq!(decode_proof(short.as_bytes()), None);
    }

    #[test]
    fn os_random_draws_differ() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        OsRandom.fill(&mut a).unwrap();
        OsRandom.fill(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn store_consume_is_one_time() {
        let store = InMemoryChallengeStore::default();
        let c = Challenge {
            audience: "a".into(),
            challenge_id: "id".into(),
            expires_at: Ts(10),
            format: SESSION_FORMAT.into(),
            grant: GrantRef {
                digest: "d".into(),
                id: "g".into(),
                object_type: "EngagementGrant".into(),
                org_id: "o".into(),
                version: 1,
            },
            issued_at: Ts(0),
            nonce: "n".into(),
            session_id: "s".into(),
        };
        store.insert(c.clone()).unwrap();
        assert!(store.insert(c).is_err(), "never overwrite");
        assert_eq!(store.consume("id"), Ok(ConsumeOutcome::Consumed));
        assert_eq!(store.consume("id"), Ok(ConsumeOutcome::AlreadyConsumed));
        assert_eq!(store.consume("nope"), Ok(ConsumeOutcome::NotFound));
        store.set_unavailable(true);
        assert_eq!(store.get("id"), Err(Unavailable));
    }
}
