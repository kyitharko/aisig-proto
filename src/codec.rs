//! Envelopes, strict decoding, canonical JSON and signed bytes (spec §3, stage F).

use std::collections::BTreeSet;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::decision::{Reason, Slot};

/// Payload format and signature-domain version.
pub const FORMAT_V0: &str = "aisig/v0";
const SIG_DOMAIN: &[u8] = b"aisig-v0";
const MAX_SAFE_INT: u64 = (1 << 53) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypeTag {
    OrganizationRoot,
    AdminDelegation,
    IssuerDelegation,
    EngagementGrant,
}

impl TypeTag {
    pub fn as_str(self) -> &'static str {
        match self {
            TypeTag::OrganizationRoot => "OrganizationRoot",
            TypeTag::AdminDelegation => "AdminDelegation",
            TypeTag::IssuerDelegation => "IssuerDelegation",
            TypeTag::EngagementGrant => "EngagementGrant",
        }
    }
}

/// `"aisig-v0" || 0x00 || type || 0x00 || payload` (spec §3).
pub fn signed_bytes(type_tag: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIG_DOMAIN.len() + type_tag.len() + payload.len() + 2);
    out.extend_from_slice(SIG_DOMAIN);
    out.push(0);
    out.extend_from_slice(type_tag.as_bytes());
    out.push(0);
    out.extend_from_slice(payload);
    out
}

pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// A format-stage reason carried through serde's string error channel as `aisig:<Reason>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatError(pub Reason);

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aisig:{}", self.0)
    }
}

/// Map a serde error message to a format-stage reason (spec §3 steps 2 and 4).
pub fn classify_error(msg: &str) -> Reason {
    if let Some(rest) = msg.strip_prefix("aisig:") {
        let code: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if let Some(r) = Reason::from_format_code(&code) {
            return r;
        }
    }
    if msg.starts_with("duplicate field") {
        Reason::DuplicateField
    } else if msg.starts_with("unknown field") {
        Reason::UnknownField
    } else if msg.starts_with("missing field") {
        Reason::MissingRequiredField
    } else if msg.starts_with("unknown variant") {
        Reason::UnknownEnumValue
    } else {
        Reason::MalformedField
    }
}

// ---------------------------------------------------------------------------
// Strict parsing: duplicate keys, null and floats are errors.
// ---------------------------------------------------------------------------

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a canonical-subset JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::Bool(v)))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<StrictValue, E> {
        if v > MAX_SAFE_INT {
            return Err(E::custom(FormatError(Reason::MalformedField)));
        }
        Ok(StrictValue(Value::from(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<StrictValue, E> {
        if v.unsigned_abs() > MAX_SAFE_INT {
            return Err(E::custom(FormatError(Reason::MalformedField)));
        }
        Ok(StrictValue(Value::from(v)))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<StrictValue, E> {
        Err(E::custom(FormatError(Reason::MalformedField)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::String(v.to_owned())))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::String(v)))
    }

    fn visit_unit<E: de::Error>(self) -> Result<StrictValue, E> {
        Err(E::custom(FormatError(Reason::NonCanonicalEncoding)))
    }

    fn visit_none<E: de::Error>(self) -> Result<StrictValue, E> {
        Err(E::custom(FormatError(Reason::NonCanonicalEncoding)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StrictValue, A::Error> {
        let mut out = Vec::new();
        while let Some(StrictValue(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(StrictValue(Value::Array(out)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictValue, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom(FormatError(Reason::DuplicateField)));
            }
            let StrictValue(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(StrictValue(Value::Object(out)))
    }
}

/// Parse JSON bytes, rejecting duplicate keys, `null`, floats and unsafe integers.
pub fn strict_parse(bytes: &[u8]) -> Result<Value, Reason> {
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|s| s.0)
        .map_err(|e| classify_error(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Canonical JSON (spec §3): sorted keys, no whitespace, no null, no floats.
// ---------------------------------------------------------------------------

pub fn canonical_json(v: &Value) -> Result<Vec<u8>, Reason> {
    let mut out = Vec::new();
    write_canonical(v, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<(), Reason> {
    match v {
        Value::Null => return Err(Reason::NonCanonicalEncoding),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            let ok = n.as_u64().is_some_and(|x| x <= MAX_SAFE_INT)
                || n.as_i64().is_some_and(|x| x.unsigned_abs() <= MAX_SAFE_INT);
            if !ok {
                return Err(Reason::MalformedField);
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => out.extend_from_slice(
            serde_json::to_string(s)
                .map_err(|_| Reason::MalformedField)?
                .as_bytes(),
        ),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let keys: BTreeSet<&String> = map.keys().collect();
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_string(k)
                        .map_err(|_| Reason::MalformedField)?
                        .as_bytes(),
                );
                out.push(b':');
                write_canonical(&map[k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Canonical bytes of any serializable value.
pub fn canonical_bytes<T: Serialize + ?Sized>(t: &T) -> Result<Vec<u8>, Reason> {
    let v = serde_json::to_value(t).map_err(|_| Reason::MalformedField)?;
    canonical_json(&v)
}

/// Set-valued arrays must be strictly increasing by canonical element bytes (spec §3 rule 4).
pub fn check_canonical_set<T: Serialize>(items: &[T]) -> Result<(), Reason> {
    let mut prev: Option<Vec<u8>> = None;
    for item in items {
        let cur = canonical_bytes(item)?;
        if let Some(p) = &prev {
            if p >= &cur {
                return Err(Reason::NonCanonicalEncoding);
            }
        }
        prev = Some(cur);
    }
    Ok(())
}

/// Sort and deduplicate a set by canonical element bytes (signer-side helper).
pub fn canonical_sort<T: Serialize>(items: &mut Vec<T>) {
    let mut keyed: Vec<(Vec<u8>, T)> = items
        .drain(..)
        .map(|t| (canonical_bytes(&t).unwrap_or_default(), t))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    items.extend(keyed.into_iter().map(|(_, t)| t));
}

// ---------------------------------------------------------------------------
// Payloads and envelopes.
// ---------------------------------------------------------------------------

/// A signed payload type with its slot-specific type tag and set rules.
pub trait Payload: Serialize + DeserializeOwned {
    const TAG: TypeTag;
    /// Spec §3 step 5: set, constraint and value rules not expressible in serde.
    fn check(&self) -> Result<(), Reason>;
}

/// Decode payload bytes with spec §3 steps 2–6.
pub fn decode_payload<T: Payload>(bytes: &[u8]) -> Result<T, Reason> {
    let value = strict_parse(bytes)?;
    if let Some(f) = value.get("format") {
        if f.as_str() != Some(FORMAT_V0) {
            return Err(Reason::UnsupportedVersion);
        }
    }
    let body: T = serde_json::from_value(value).map_err(|e| classify_error(&e.to_string()))?;
    body.check()?;
    if canonical_bytes(&body)? != bytes {
        return Err(Reason::NonCanonicalEncoding);
    }
    Ok(body)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigWire {
    pub alg: String,
    pub key_id: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeWire {
    pub payload: String,
    pub sig: SigWire,
    #[serde(rename = "type")]
    pub type_tag: String,
}

impl EnvelopeWire {
    pub fn to_bytes(&self) -> Vec<u8> {
        canonical_bytes(self).expect("envelope fields are strings")
    }
}

/// A decoded, not-yet-verified signed object.
#[derive(Debug, Clone)]
pub struct Signed<T> {
    pub body: T,
    pub payload: Vec<u8>,
    pub sig: [u8; 64],
    /// `sig.key_id` from the envelope: a lookup hint only, never trusted.
    pub key_hint: String,
}

/// Decode one envelope from a bundle slot (spec §3 steps 1–6).
pub fn decode_signed<T: Payload>(bytes: &[u8], slot: Slot) -> Result<Signed<T>, Reason> {
    let value = strict_parse(bytes).map_err(|_| Reason::MalformedEnvelope)?;
    let env: EnvelopeWire = serde_json::from_value(value).map_err(|_| Reason::MalformedEnvelope)?;
    if env.type_tag != T::TAG.as_str() {
        return Err(Reason::WrongObjectType(slot));
    }
    if env.sig.alg != "Ed25519" {
        return Err(Reason::UnsupportedAlgorithm);
    }
    let payload = b64_decode(&env.payload).ok_or(Reason::MalformedEnvelope)?;
    let sig: [u8; 64] = b64_decode(&env.sig.value)
        .and_then(|s| s.try_into().ok())
        .ok_or(Reason::MalformedEnvelope)?;
    let body = decode_payload::<T>(&payload)?;
    Ok(Signed {
        body,
        payload,
        sig,
        key_hint: env.sig.key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys_and_strips_whitespace() {
        let v: Value =
            serde_json::from_str(r#"{ "b": [1, 2], "a": {"d": true, "c": "x"} }"#).unwrap();
        assert_eq!(
            canonical_json(&v).unwrap(),
            br#"{"a":{"c":"x","d":true},"b":[1,2]}"#
        );
    }

    #[test]
    fn strict_parse_rejects_duplicates_null_and_floats() {
        assert_eq!(
            strict_parse(br#"{"a":1,"a":2}"#),
            Err(Reason::DuplicateField)
        );
        assert_eq!(
            strict_parse(br#"{"a":{"b":1,"b":1}}"#),
            Err(Reason::DuplicateField)
        );
        assert_eq!(
            strict_parse(br#"{"a":null}"#),
            Err(Reason::NonCanonicalEncoding)
        );
        assert_eq!(strict_parse(br#"{"a":1.5}"#), Err(Reason::MalformedField));
        assert_eq!(
            strict_parse(br#"{"a":9007199254740992}"#),
            Err(Reason::MalformedField)
        );
        assert!(strict_parse(br#"{"a":9007199254740991}"#).is_ok());
    }

    #[test]
    fn canonical_rejects_null() {
        assert_eq!(
            canonical_json(&json!({"a": null})),
            Err(Reason::NonCanonicalEncoding)
        );
    }

    #[test]
    fn signed_bytes_are_domain_separated_by_type() {
        let a = signed_bytes("IssuerDelegation", b"{}");
        let b = signed_bytes("EngagementGrant", b"{}");
        assert_ne!(a, b);
        assert!(a.starts_with(b"aisig-v0\0IssuerDelegation\0"));
    }

    #[test]
    fn canonical_set_order() {
        assert!(check_canonical_set(&["a", "b"]).is_ok());
        assert_eq!(
            check_canonical_set(&["b", "a"]),
            Err(Reason::NonCanonicalEncoding)
        );
        assert_eq!(
            check_canonical_set(&["a", "a"]),
            Err(Reason::NonCanonicalEncoding)
        );
        let mut v = vec!["c", "a", "b", "a"];
        canonical_sort(&mut v);
        assert_eq!(v, vec!["a", "b", "c"]);
    }
}
