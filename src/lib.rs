//! Research prototype for provider-verified authorization chains (spec: docs/spec.md).
//!
//! Synthetic data only. Nothing in this crate connects to a network or tests a target.
//!
//! Module boundaries follow the spec:
//! - [`codec`]: envelopes, strict decoding, canonical JSON, signed bytes (stage F).
//! - [`crypto`]: Ed25519 verification over exact bytes, key ids (stage S). No policy.
//! - [`model`]: typed payloads and assets with decode-time validation.
//! - [`asset`]: `within`, admissibility, `ScopeWithin`, scope queries (spec §4).
//! - [`policy`]: linkage and policy predicates (stages L, P). Pure; no crypto.
//! - [`evidence`]: registry, binding, clock and status interfaces plus in-memory fixtures.
//! - [`verifier`]: the ValidChain_P decision procedure (spec §7).
//! - [`baseline`]: the deliberately weak signature-only verifier (spec §7.4).
//! - [`enforcement`]: RQ6 slice e2 — provider-mediated synthetic tool adapter
//!   (docs/enforcement.md). A ProviderExec decision, separate from chain and session.
//! - [`session`]: RQ5 slice — tester proof of possession bound to a provider session
//!   (docs/session.md). Separate from the chain decision.
//! - [`experiment`]: synthetic fixture, case mutations, label loading and reporting.

pub mod asset;
pub mod baseline;
pub mod codec;
pub mod crypto;
pub mod decision;
pub mod enforcement;
pub mod evidence;
pub mod experiment;
pub mod model;
pub mod policy;
pub mod session;
pub mod verifier;
