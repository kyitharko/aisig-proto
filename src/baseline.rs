//! Deliberately weak signature-only baseline (spec §7.4). A comparison point, not a design.
//!
//! It parses the bundle leniently, trusts the key in the presented self-signed root, and
//! accepts iff the four signatures verify under keys found in the bundle itself.

use serde_json::Value;

use crate::codec::b64_decode;
use crate::crypto;
use crate::decision::{Decision, Obj, Reason, Slot, Stage};
use crate::verifier::Bundle;

struct Loose {
    type_tag: String,
    payload: Vec<u8>,
    body: Value,
    sig: [u8; 64],
}

fn loose(bytes: Option<&[u8]>) -> Option<Loose> {
    let env: Value = serde_json::from_slice(bytes?).ok()?;
    let payload = b64_decode(env.get("payload")?.as_str()?)?;
    let sig = b64_decode(env.get("sig")?.get("value")?.as_str()?)?
        .try_into()
        .ok()?;
    Some(Loose {
        type_tag: env.get("type")?.as_str()?.to_owned(),
        body: serde_json::from_slice(&payload).ok()?,
        payload,
        sig,
    })
}

fn key(body: &Value, field: &str) -> Option<[u8; 32]> {
    b64_decode(body.get(field)?.as_str()?)?.try_into().ok()
}

pub fn verify_signature_only(bundle: &Bundle) -> Decision {
    let slots = [
        (Slot::Root, &bundle.root),
        (Slot::Admin, &bundle.admin),
        (Slot::Issuer, &bundle.issuer),
        (Slot::Grant, &bundle.grant),
    ];
    let mut parsed = Vec::with_capacity(4);
    for (slot, bytes) in slots {
        match loose(bytes.as_deref()) {
            Some(l) => parsed.push(l),
            None => return Decision::reject(Stage::Format, Reason::MissingRequiredObject(slot)),
        }
    }
    let (root, admin, issuer, grant) = (&parsed[0], &parsed[1], &parsed[2], &parsed[3]);
    let checks = [
        (Obj::Root, key(&root.body, "root_key"), root),
        (Obj::Admin, key(&root.body, "root_key"), admin),
        (Obj::Issuer, key(&admin.body, "subject_key"), issuer),
        (Obj::Grant, key(&issuer.body, "subject_key"), grant),
    ];
    for (obj, k, l) in checks {
        let ok = k.is_some_and(|k| crypto::verify(&k, &l.type_tag, &l.payload, &l.sig));
        if !ok {
            return Decision::reject(Stage::Signature, Reason::InvalidSignature(obj));
        }
    }
    Decision::Accept
}
