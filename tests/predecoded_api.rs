//! Regression test for the public predecoded-API issue reported in the r3 review.
//!
//! Starting from an accepted base chain, change only the decoded grant body's test_scope
//! (signed: [injection_testing, recon]) to [auth_testing], which is within D_U's ceiling,
//! leaving the signed payload and signature unchanged. A sound verifier must not accept a
//! policy body that differs from the verified payload.

use aisig_proto::decision::Decision;
use aisig_proto::experiment::fixture::Scenario;
use aisig_proto::model::{TestClass, TestScope};
use aisig_proto::verifier::decode_chain;

#[test]
fn altered_decoded_body_is_not_accepted() {
    let scenario = Scenario::base();
    let prepared = scenario.prepare();
    let verifier = prepared.verifier();
    let mut chain = decode_chain(&prepared.bundle).expect("base chain decodes");
    assert_eq!(verifier.verify_decoded(&chain), Decision::Accept);

    chain.grant.body.test_scope = TestScope::Classes {
        classes: vec![TestClass::AuthTesting],
    };
    let d = verifier.verify_decoded(&chain);
    assert_ne!(d, Decision::Accept, "altered body accepted: {d}");
}
