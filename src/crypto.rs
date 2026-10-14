//! Ed25519 signing/verification over exact signed bytes, and key ids (spec §3).
//!
//! This module only answers "does this signature verify under this key over these bytes".
//! It never decides authority or scope. Primitives come from `ed25519-dalek` and `sha2`.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::codec::signed_bytes;

/// keyid(K): lowercase hex SHA-256 of the raw 32-byte public key.
pub fn key_id(public_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// digest(X) = SHA-256(signed_bytes(type_tag, payload)) — the content identity used for
/// exact-object status records (spec §6). Excludes the signature bytes.
pub fn object_digest(type_tag: &str, payload: &[u8]) -> [u8; 32] {
    Sha256::digest(signed_bytes(type_tag, payload)).into()
}

/// True iff the 32 bytes decode to a valid Ed25519 public key.
pub fn is_valid_public_key(public_key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok()
}

/// V_K(X): strict Ed25519 verification of `sig` over `signed_bytes(type_tag, payload)`.
pub fn verify(public_key: &[u8; 32], type_tag: &str, payload: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    vk.verify_strict(
        &signed_bytes(type_tag, payload),
        &Signature::from_bytes(sig),
    )
    .is_ok()
}

/// A signing key for synthetic fixtures only.
pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SecretKey(SigningKey::from_bytes(seed))
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, type_tag: &str, payload: &[u8]) -> [u8; 64] {
        self.0.sign(&signed_bytes(type_tag, payload)).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_domain_separation() {
        let sk = SecretKey::from_seed(&[7u8; 32]);
        let pk = sk.public_bytes();
        let sig = sk.sign("EngagementGrant", b"payload");
        assert!(verify(&pk, "EngagementGrant", b"payload", &sig));
        assert!(!verify(&pk, "IssuerDelegation", b"payload", &sig));
        assert!(!verify(&pk, "EngagementGrant", b"payload!", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&pk, "EngagementGrant", b"payload", &bad));
        assert_eq!(key_id(&pk).len(), 64);
    }
}
