//! Regression tests for the predecoded-API issue from the r3 review.
//!
//! Before the fix (reproduced at commit bcfe70f), `ChainVerifier::verify_decoded` was public
//! and `DecodedChain`/`Signed<T>` had public mutable fields. Changing only the decoded grant
//! body's test_scope from the signed [injection_testing, recon] to [auth_testing] (within
//! D_U's ceiling) returned Accept. The fix removes the public pre-decoded entry point and
//! makes decoded objects read-only; the doctests in src/verifier.rs check at compile time
//! that both the field assignment and the `verify_decoded` call no longer compile.
//! The tests below cover the remaining public path.

use aisig_proto::codec::decode_payload;
use aisig_proto::decision::{Decision, Obj, Reason, Slot, Stage};
use aisig_proto::experiment::fixture::{put, PostOp, Scenario};
use aisig_proto::model::{EngagementGrant, TestClass, TestScope};
use aisig_proto::verifier::decode_chain;
use serde_json::json;

#[test]
fn decoded_bodies_are_the_decoding_of_their_signed_payloads() {
    let s = Scenario::base();
    let chain = decode_chain(&s.build()).expect("base chain decodes");
    let g = chain.grant();
    let redecoded: EngagementGrant = decode_payload(g.payload()).expect("payload decodes");
    assert_eq!(g.body(), &redecoded);
    assert_eq!(
        g.body().test_scope,
        TestScope::Classes {
            classes: vec![TestClass::InjectionTesting, TestClass::Recon]
        }
    );
}

/// The same alteration attempted through the only public decision path: the grant payload
/// in the raw bundle is replaced by one with test_scope [auth_testing], keeping the
/// original signature. The signature no longer covers the bytes, so verify() rejects.
#[test]
fn same_alteration_through_raw_bundle_is_rejected_at_signature_stage() {
    let mut s = Scenario::base();
    assert_eq!(s.run(), Decision::Accept);
    let mut altered = s.grant().clone();
    put(
        &mut altered,
        "test_scope",
        json!({"classes": ["auth_testing"], "kind": "classes"}),
    );
    s.post
        .push(PostOp::ReplacePayloadKeepSig(Slot::Grant, altered));
    assert_eq!(
        s.run(),
        Decision::reject(Stage::Signature, Reason::InvalidSignature(Obj::Grant))
    );
}
