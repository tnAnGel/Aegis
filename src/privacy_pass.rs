//! V201 — Privacy Pass token verification (RFC 9576-shaped).
//!
//! Privacy Pass lets the operator accept anonymous proof-of-trust
//! tokens issued by a third party (Cloudflare, Apple Private Access
//! Tokens, Fastly issuers) without learning anything about the
//! client. Browser already trusted by the issuer presents a token;
//! Aegis verifies it cryptographically and bypasses the challenge
//! ladder for the next N requests.
//!
//! ## Wire shape
//!
//! Client sends header:
//!
//! ```text
//! Authorization: PrivateToken token=<base64url(token_bytes)>,
//!                            issuer-name=cloudflare-research.com
//! ```
//!
//! Token layout (RFC 9578 Type-1, simplified for our verifier):
//!
//! ```text
//! 0..2     token_type (u16 BE) — 0x0002 for publicly verifiable
//! 2..34    nonce (32 bytes)
//! 34..66   challenge_digest (32 bytes)
//! 66..98   token_key_id (32 bytes)
//! 98..end  signature (length depends on key family — Ed25519 = 64)
//! ```
//!
//! Verification:
//! 1. Look up `token_key_id` in [TrustedIssuerRegistry]
//! 2. Reconstruct the signed message
//! 3. Verify signature with issuer's public key
//! 4. Mark `nonce` as spent in the replay cache (TTL = token validity)
//!
//! ## What's NOT shipped here
//!
//! - Full BSS (Blind Signature Scheme) — operators using Type-2
//!   private tokens need a separate issuer client. We ship Type-1
//!   public verification because every major issuer publishes their
//!   key.
//! - Issuer key rotation — implemented as a static registry; admin
//!   API can swap keys at runtime.
//! - HTTP semantic encoding (RFC 9578) — we accept a simplified
//!   raw token bytes form for now.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TrustedIssuer {
    pub key_id: [u8; 32],
    pub name: String,
    /// Ed25519 public key bytes (32 bytes) when key family is Ed25519.
    pub public_key: Vec<u8>,
    pub algorithm: SignatureAlgorithm,
    /// How long a verified token confers trust before re-challenging.
    pub trust_duration: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// V242 — real production algorithm (RFC 8032 Ed25519), verified
    /// with `VerifyingKey::verify_strict`.
    Ed25519,
    /// Test-only: SHA-256 HMAC. NOT FOR PRODUCTION — the "key" is a
    /// shared secret, which defeats the point of Privacy Pass (anonymous
    /// PUBLIC-key verification). Retained only so the verifier plumbing
    /// can be exercised without a keypair. Use `Ed25519` in production.
    HmacSha256,
}

impl SignatureAlgorithm {
    /// Lowercase wire/admin name. Matches the strings the admin POST
    /// endpoint accepts (`ed25519` | `hmac_sha256`).
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::HmacSha256 => "hmac_sha256",
        }
    }
}

/// V242 — panel-safe view of a registered issuer. Never contains private
/// material; the key is reduced to a fingerprint. Returned by
/// [`PrivacyPassVerifier::list_issuers`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IssuerInfo {
    pub name: String,
    /// RFC 9578 `token_key_id` (the on-wire issuer selector), full hex.
    pub key_id_hex: String,
    /// `ed25519` | `hmac_sha256`.
    pub algorithm: String,
    /// `sha256:<first 16 hex>` of the public key bytes. A fingerprint —
    /// not the key itself — so the panel never handles key blobs.
    pub public_key_fingerprint: String,
    pub trust_duration_secs: u64,
}

#[derive(Debug)]
pub struct Token {
    pub token_type: u16,
    pub nonce: [u8; 32],
    pub challenge_digest: [u8; 32],
    pub key_id: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Valid,
    UnknownIssuer,
    BadSignature,
    Replayed,
    Malformed,
    /// V233 — the issuer's signature algorithm is recognised but not
    /// yet implemented by this verifier (currently: Ed25519). Distinct
    /// from `BadSignature` so an operator who registers an Ed25519
    /// issuer sees a configuration error instead of silently having
    /// every token rejected as a forgery. Fails closed (no trust
    /// granted) but is observable.
    UnsupportedAlgorithm,
}

pub struct PrivacyPassVerifier {
    issuers: RwLock<HashMap<[u8; 32], TrustedIssuer>>,
    nonce_cache: RwLock<HashMap<[u8; 32], Instant>>,
    /// Hard cap on nonce cache size; oldest entries dropped first
    /// when exceeded. Replay window is at least one trust_duration.
    cache_capacity: usize,
}

impl PrivacyPassVerifier {
    pub fn new(cache_capacity: usize) -> Self {
        Self {
            issuers: RwLock::new(HashMap::new()),
            nonce_cache: RwLock::new(HashMap::new()),
            cache_capacity,
        }
    }

    pub fn register_issuer(&self, issuer: TrustedIssuer) {
        self.issuers.write().unwrap().insert(issuer.key_id, issuer);
    }

    pub fn issuer_count(&self) -> usize {
        self.issuers.read().unwrap().len()
    }

    /// V242 — snapshot of every registered issuer in a form safe to
    /// serialise into the admin panel.
    ///
    /// IMPORTANT: Privacy Pass Type-1 issuer keys are PUBLIC verification
    /// keys, never secrets — but we still expose only a fingerprint of the
    /// key material (not the raw bytes) so the panel never has to handle
    /// key blobs and the contract stays correct if a future algorithm
    /// carries private material. `key_id` is the wire identifier (RFC 9578
    /// `token_key_id`), so it is intentionally returned in full.
    pub fn list_issuers(&self) -> Vec<IssuerInfo> {
        let g = self.issuers.read().unwrap();
        let mut out: Vec<IssuerInfo> = g
            .values()
            .map(|i| IssuerInfo {
                name: i.name.clone(),
                key_id_hex: hex_lower(&i.key_id),
                algorithm: i.algorithm.as_str().to_string(),
                public_key_fingerprint: public_key_fingerprint(&i.public_key),
                trust_duration_secs: i.trust_duration.as_secs(),
            })
            .collect();
        // Stable ordering so the panel doesn't reshuffle rows each poll.
        out.sort_by(|a, b| a.key_id_hex.cmp(&b.key_id_hex));
        out
    }

    /// Parse the raw token bytes from a wire representation. Returns
    /// `None` for malformed input.
    pub fn parse_token(bytes: &[u8]) -> Option<Token> {
        if bytes.len() < 98 {
            return None;
        }
        let token_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes[2..34]);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[34..66]);
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&bytes[66..98]);
        let signature = bytes[98..].to_vec();
        Some(Token {
            token_type,
            nonce,
            challenge_digest: digest,
            key_id,
            signature,
        })
    }

    pub fn verify(&self, token: &Token) -> VerifyOutcome {
        let issuer = match self.issuers.read().unwrap().get(&token.key_id).cloned() {
            Some(i) => i,
            None => return VerifyOutcome::UnknownIssuer,
        };
        // Reconstruct signed message: token_type || nonce ||
        // challenge_digest || key_id.
        let mut msg = Vec::with_capacity(98);
        msg.extend_from_slice(&token.token_type.to_be_bytes());
        msg.extend_from_slice(&token.nonce);
        msg.extend_from_slice(&token.challenge_digest);
        msg.extend_from_slice(&token.key_id);

        // V242 — Ed25519 is the real production algorithm. A malformed
        // issuer public key (wrong length / not on-curve) is a
        // configuration error and surfaces as `UnsupportedAlgorithm`
        // (distinct from a forged token) so the operator can diagnose it;
        // a well-formed key with a non-matching signature is a genuine
        // `BadSignature`.
        let valid = match issuer.algorithm {
            SignatureAlgorithm::Ed25519 => {
                match verify_ed25519(&msg, &token.signature, &issuer.public_key) {
                    Ok(()) => true,
                    Err(Ed25519Error::BadSignature) => false,
                    Err(Ed25519Error::InvalidKey) => return VerifyOutcome::UnsupportedAlgorithm,
                }
            }
            SignatureAlgorithm::HmacSha256 => {
                verify_hmac_sha256(&msg, &token.signature, &issuer.public_key)
            }
        };
        if !valid {
            return VerifyOutcome::BadSignature;
        }
        // Replay check.
        if !self.try_mark_seen(token.nonce, issuer.trust_duration) {
            return VerifyOutcome::Replayed;
        }
        VerifyOutcome::Valid
    }

    fn try_mark_seen(&self, nonce: [u8; 32], ttl: Duration) -> bool {
        let mut g = self.nonce_cache.write().unwrap();
        if g.contains_key(&nonce) {
            return false;
        }
        if g.len() >= self.cache_capacity {
            // Evict oldest single entry.
            if let Some((k, _)) = g.iter().min_by_key(|(_, t)| **t).map(|(k, t)| (*k, *t)) {
                g.remove(&k);
            }
        }
        g.insert(nonce, Instant::now() + ttl);
        true
    }

    /// Background GC — drop expired nonces. Call from the same tick
    /// that runs actuator wheel maintenance.
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let mut g = self.nonce_cache.write().unwrap();
        let before = g.len();
        g.retain(|_, expires| *expires > now);
        before - g.len()
    }

    pub fn nonce_cache_size(&self) -> usize {
        self.nonce_cache.read().unwrap().len()
    }
}

impl Default for PrivacyPassVerifier {
    fn default() -> Self {
        Self::new(100_000)
    }
}

/// V242 — structured error for the Ed25519 verification path.
///
/// Distinguishing these two cases is security-relevant: an `InvalidKey`
/// is an operator misconfiguration (it surfaces as
/// `VerifyOutcome::UnsupportedAlgorithm` so it is diagnosable), whereas
/// `BadSignature` is a genuine verification failure / forgery attempt
/// and must read identically to any other bad token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519Error {
    /// The issuer's registered public key is not a valid Ed25519 point
    /// (wrong length, or not a canonical compressed point on the curve).
    InvalidKey,
    /// The signature does not verify against the message + public key,
    /// or is not 64 bytes / not canonical.
    BadSignature,
}

/// V242 — real Ed25519 verification (RFC 8032 / RFC 9578 Type-1 tokens).
///
/// Uses `VerifyingKey::verify_strict`, which — unlike the bare `verify` —
/// rejects signatures that exploit point malleability / small-order
/// (torsion) components. For a primitive that grants a challenge-ladder
/// bypass, the stricter check is the correct default: it guarantees the
/// signature is bound to exactly one public key.
fn verify_ed25519(msg: &[u8], sig: &[u8], pubkey: &[u8]) -> Result<(), Ed25519Error> {
    use ed25519_dalek::{Signature, VerifyingKey};

    // Public key must be exactly 32 bytes and a valid compressed point.
    let pk_bytes: &[u8; 32] = pubkey.try_into().map_err(|_| Ed25519Error::InvalidKey)?;
    let key = VerifyingKey::from_bytes(pk_bytes).map_err(|_| Ed25519Error::InvalidKey)?;

    // Signature must be exactly 64 bytes. A wrong length is an attacker-
    // controlled token field, so this is a BadSignature, not a config
    // error.
    let sig_bytes: &[u8; 64] = sig.try_into().map_err(|_| Ed25519Error::BadSignature)?;
    let signature = Signature::from_bytes(sig_bytes);

    key.verify_strict(msg, &signature)
        .map_err(|_| Ed25519Error::BadSignature)
}

/// V242 — lowercase hex encoding (no external dep; `base64` is for b64).
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// V242 — short, stable fingerprint of an issuer's PUBLIC key for the
/// admin panel. SHA-256 of the key bytes, truncated to 8 bytes / 16 hex
/// chars and prefixed with the hash name. This is for human display /
/// dedup only — never for verification.
fn public_key_fingerprint(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(public_key);
    format!("sha256:{}", hex_lower(&digest[..8]))
}

fn verify_hmac_sha256(msg: &[u8], sig: &[u8], key: &[u8]) -> bool {
    // V233 — was `SHA256(key || msg)`, a raw prefix-MAC vulnerable to
    // length-extension: an attacker who observes one valid (msg, tag)
    // token — and tokens travel in a request header, so they are not
    // secret — can forge a tag for `msg || pad || suffix` without the
    // key and have it verify, granting a 24h challenge-ladder bypass.
    // Replaced with a real HMAC-SHA256 (RFC 2104) via the `hmac` crate.
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    if sig.len() != 32 {
        return false;
    }
    // `new_from_slice` accepts a key of any length (HMAC handles
    // shorter/longer keys per RFC 2104); it is infallible for Hmac.
    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(msg);
    // V233 — constant-time tag comparison via the `Mac` trait. Do NOT
    // use `==` here: `verify_slice` is the constant-time check and
    // also length-checks the attacker-supplied tag.
    mac.verify_slice(sig).is_ok()
}

// V233 — no longer on the HMAC verification path: `Mac::verify_slice`
// now performs the constant-time tag comparison. Retained as a correct,
// dependency-free constant-time primitive for future callers; marked
// `allow(dead_code)` so it does not break a `-D warnings` build.
#[allow(dead_code)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // V233 — token fixtures now sign with a real HMAC-SHA256, matching
    // the verifier. Previously this used the broken `SHA256(key||msg)`
    // prefix-MAC.
    fn hmac_tag(msg: &[u8], key: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    fn make_token(key_id: [u8; 32], nonce: [u8; 32], key: &[u8]) -> Token {
        let challenge_digest = [0x42u8; 32];
        let token_type = 0x0002u16;
        let mut msg = Vec::with_capacity(98);
        msg.extend_from_slice(&token_type.to_be_bytes());
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&challenge_digest);
        msg.extend_from_slice(&key_id);
        let signature = hmac_tag(&msg, key);
        Token {
            token_type,
            nonce,
            challenge_digest,
            key_id,
            signature,
        }
    }

    fn issuer(key_id: [u8; 32], key: &[u8]) -> TrustedIssuer {
        TrustedIssuer {
            key_id,
            name: "test-issuer".into(),
            public_key: key.to_vec(),
            algorithm: SignatureAlgorithm::HmacSha256,
            trust_duration: Duration::from_secs(3600),
        }
    }

    #[test]
    fn valid_token_passes() {
        let v = PrivacyPassVerifier::new(100);
        let key = b"test-key-32-bytes-for-hmac-sha2!";
        let kid = [1u8; 32];
        v.register_issuer(issuer(kid, key));
        let t = make_token(kid, [3u8; 32], key);
        assert_eq!(v.verify(&t), VerifyOutcome::Valid);
    }

    #[test]
    fn replay_is_rejected() {
        let v = PrivacyPassVerifier::new(100);
        let key = b"replay-test-key-32-bytes-aaaaaaa";
        let kid = [2u8; 32];
        v.register_issuer(issuer(kid, key));
        let t = make_token(kid, [4u8; 32], key);
        assert_eq!(v.verify(&t), VerifyOutcome::Valid);
        assert_eq!(v.verify(&t), VerifyOutcome::Replayed);
    }

    #[test]
    fn unknown_issuer_fails() {
        let v = PrivacyPassVerifier::new(100);
        let key = b"some-key-32-bytes-for-test-only!";
        let t = make_token([9u8; 32], [5u8; 32], key);
        assert_eq!(v.verify(&t), VerifyOutcome::UnknownIssuer);
    }

    #[test]
    fn bad_signature_fails() {
        let v = PrivacyPassVerifier::new(100);
        let kid = [3u8; 32];
        v.register_issuer(issuer(kid, b"correct-key-bytes-aaaaaaaaaaaaaa"));
        let mut t = make_token(kid, [6u8; 32], b"wrong-key-bytes-aaaaaaaaaaaaaaaa");
        // Don't allow it to pass via replay cache contention.
        t.nonce = [7u8; 32];
        assert_eq!(v.verify(&t), VerifyOutcome::BadSignature);
    }

    #[test]
    fn malformed_token_returns_none() {
        let short = vec![0u8; 50];
        assert!(PrivacyPassVerifier::parse_token(&short).is_none());
    }

    #[test]
    fn parse_then_verify_round_trip() {
        let v = PrivacyPassVerifier::new(100);
        let key = b"round-trip-key-aaaaaaaaaaaaaaaaa";
        let kid = [4u8; 32];
        v.register_issuer(issuer(kid, key));
        let original = make_token(kid, [8u8; 32], key);
        let mut wire = Vec::new();
        wire.extend_from_slice(&original.token_type.to_be_bytes());
        wire.extend_from_slice(&original.nonce);
        wire.extend_from_slice(&original.challenge_digest);
        wire.extend_from_slice(&original.key_id);
        wire.extend_from_slice(&original.signature);
        let parsed = PrivacyPassVerifier::parse_token(&wire).unwrap();
        assert_eq!(v.verify(&parsed), VerifyOutcome::Valid);
    }

    #[test]
    fn gc_drops_expired_nonces() {
        let v = PrivacyPassVerifier::new(100);
        let kid = [5u8; 32];
        v.register_issuer(TrustedIssuer {
            key_id: kid,
            name: "ttl".into(),
            public_key: b"short-ttl-key-aaaaaaaaaaaaaaaaaaa".to_vec(),
            algorithm: SignatureAlgorithm::HmacSha256,
            trust_duration: Duration::from_millis(50),
        });
        let t = make_token(kid, [9u8; 32], b"short-ttl-key-aaaaaaaaaaaaaaaaaaa");
        assert_eq!(v.verify(&t), VerifyOutcome::Valid);
        assert_eq!(v.nonce_cache_size(), 1);
        std::thread::sleep(Duration::from_millis(80));
        let dropped = v.gc();
        assert_eq!(dropped, 1);
    }

    #[test]
    fn issuer_registration_idempotent_per_key_id() {
        let v = PrivacyPassVerifier::new(100);
        let key = b"first-issuer-key-aaaaaaaaaaaaaaa";
        let kid = [6u8; 32];
        v.register_issuer(issuer(kid, key));
        v.register_issuer(issuer(kid, b"different-key-but-same-id-aaaaaa"));
        assert_eq!(v.issuer_count(), 1);
    }

    /// V233 — regression test for the length-extension auth bypass.
    ///
    /// The old verifier computed `SHA256(key || msg)`. SHA-256 is a
    /// Merkle-Damgard hash, so from a known `(msg, tag)` pair an
    /// attacker can compute the tag for `msg || glue_padding || suffix`
    /// WITHOUT the key — the textbook length-extension attack.
    ///
    /// This test forges a token by appending bytes to a captured
    /// token's signed message and asserts the real HMAC verifier
    /// rejects it. (We do not reconstruct the full SHA-256 internal
    /// state here — any tampered message must fail, and HMAC's nested
    /// construction makes length extension impossible by design.)
    #[test]
    fn length_extended_token_is_rejected() {
        let v = PrivacyPassVerifier::new(100);
        let key = b"length-ext-victim-key-aaaaaaaaaa";
        let kid = [10u8; 32];
        v.register_issuer(issuer(kid, key));

        // A legitimately issued, valid token.
        let genuine = make_token(kid, [11u8; 32], key);
        assert_eq!(v.verify(&genuine), VerifyOutcome::Valid);

        // Attacker observes `genuine` on the wire (tokens are in a
        // request header — not secret) and tampers with the signed
        // message. With the broken prefix-MAC, an extension of the
        // message would carry a forgeable tag. With real HMAC, the
        // captured tag no longer authenticates the changed message.
        let mut forged = make_token(kid, [12u8; 32], key);
        // Reuse the GENUINE token's tag against a DIFFERENT message —
        // this is exactly what a length-extension forgery yields: an
        // old tag paired with `msg || suffix`.
        forged.signature = genuine.signature.clone();
        // The challenge_digest stands in for attacker-appended bytes.
        forged.challenge_digest = [0xAAu8; 32];
        assert_eq!(v.verify(&forged), VerifyOutcome::BadSignature);

        // Also: a tag that is the genuine tag with extra bytes glued
        // on (length-extension always lengthens the output region in
        // a naive scheme) must fail the length check, not panic.
        let mut extended = make_token(kid, [13u8; 32], key);
        extended.signature = {
            let mut s = genuine.signature.clone();
            s.extend_from_slice(b"attacker-suffix");
            s
        };
        assert_eq!(v.verify(&extended), VerifyOutcome::BadSignature);
    }

    /// V233 — a token whose signed message is altered after issuance
    /// must fail: confirms the HMAC actually covers every field.
    #[test]
    fn tampered_message_fails_verification() {
        let v = PrivacyPassVerifier::new(100);
        let key = b"tamper-detect-key-aaaaaaaaaaaaaa";
        let kid = [14u8; 32];
        v.register_issuer(issuer(kid, key));

        let mut t = make_token(kid, [15u8; 32], key);
        // Flip a single bit in the nonce — signature now covers a
        // different message than the one presented.
        t.nonce[0] ^= 0x01;
        assert_eq!(v.verify(&t), VerifyOutcome::BadSignature);
    }

    /// V242 — an issuer registered with Ed25519 but a malformed public
    /// key (wrong length) is a config error → `UnsupportedAlgorithm`
    /// (fails closed but is diagnosable), not a silent `BadSignature`.
    #[test]
    fn ed25519_malformed_key_reports_unsupported() {
        let v = PrivacyPassVerifier::new(100);
        let kid = [16u8; 32];
        v.register_issuer(TrustedIssuer {
            key_id: kid,
            name: "ed25519-bad-key".into(),
            // Not 32 bytes → not a valid Ed25519 public key.
            public_key: vec![0u8; 16],
            algorithm: SignatureAlgorithm::Ed25519,
            trust_duration: Duration::from_secs(3600),
        });
        let t = make_token(kid, [17u8; 32], b"irrelevant-key-aaaaaaaaaaaaaaaaa");
        assert_eq!(v.verify(&t), VerifyOutcome::UnsupportedAlgorithm);
    }

    // ---- V242 Ed25519 real-verification tests ------------------------

    use ed25519_dalek::{Signer, SigningKey};

    /// Build the canonical signed message for a token (token_type ||
    /// nonce || challenge_digest || key_id) — same layout `verify` uses.
    fn signed_message(
        token_type: u16,
        nonce: &[u8; 32],
        digest: &[u8; 32],
        key_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(98);
        msg.extend_from_slice(&token_type.to_be_bytes());
        msg.extend_from_slice(nonce);
        msg.extend_from_slice(digest);
        msg.extend_from_slice(key_id);
        msg
    }

    fn make_ed25519_token(signing: &SigningKey, key_id: [u8; 32], nonce: [u8; 32]) -> Token {
        let challenge_digest = [0x42u8; 32];
        let token_type = 0x0002u16;
        let msg = signed_message(token_type, &nonce, &challenge_digest, &key_id);
        let sig = signing.sign(&msg);
        Token {
            token_type,
            nonce,
            challenge_digest,
            key_id,
            signature: sig.to_bytes().to_vec(),
        }
    }

    #[test]
    fn ed25519_valid_token_passes() {
        let v = PrivacyPassVerifier::new(100);
        // Deterministic test keypair from a fixed seed.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = signing.verifying_key().to_bytes().to_vec();
        let kid = [20u8; 32];
        v.register_issuer(TrustedIssuer {
            key_id: kid,
            name: "ed25519-prod".into(),
            public_key: pubkey,
            algorithm: SignatureAlgorithm::Ed25519,
            trust_duration: Duration::from_secs(3600),
        });
        let t = make_ed25519_token(&signing, kid, [21u8; 32]);
        assert_eq!(v.verify(&t), VerifyOutcome::Valid);
    }

    #[test]
    fn ed25519_bad_signature_rejected() {
        let v = PrivacyPassVerifier::new(100);
        let signing = SigningKey::from_bytes(&[8u8; 32]);
        let pubkey = signing.verifying_key().to_bytes().to_vec();
        let kid = [22u8; 32];
        v.register_issuer(TrustedIssuer {
            key_id: kid,
            name: "ed25519-prod".into(),
            public_key: pubkey,
            algorithm: SignatureAlgorithm::Ed25519,
            trust_duration: Duration::from_secs(3600),
        });
        let mut t = make_ed25519_token(&signing, kid, [23u8; 32]);
        // Flip a bit in the signature → must fail verification.
        t.signature[0] ^= 0x01;
        assert_eq!(v.verify(&t), VerifyOutcome::BadSignature);
    }

    #[test]
    fn ed25519_signature_from_other_key_rejected() {
        let v = PrivacyPassVerifier::new(100);
        let real = SigningKey::from_bytes(&[9u8; 32]);
        let attacker = SigningKey::from_bytes(&[10u8; 32]);
        let kid = [24u8; 32];
        v.register_issuer(TrustedIssuer {
            key_id: kid,
            name: "ed25519-prod".into(),
            public_key: real.verifying_key().to_bytes().to_vec(),
            algorithm: SignatureAlgorithm::Ed25519,
            trust_duration: Duration::from_secs(3600),
        });
        // Signed by the attacker's key, not the registered issuer's.
        let t = make_ed25519_token(&attacker, kid, [25u8; 32]);
        assert_eq!(v.verify(&t), VerifyOutcome::BadSignature);
    }

    #[test]
    fn ed25519_wrong_length_signature_rejected() {
        let v = PrivacyPassVerifier::new(100);
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let kid = [26u8; 32];
        v.register_issuer(TrustedIssuer {
            key_id: kid,
            name: "ed25519-prod".into(),
            public_key: signing.verifying_key().to_bytes().to_vec(),
            algorithm: SignatureAlgorithm::Ed25519,
            trust_duration: Duration::from_secs(3600),
        });
        let mut t = make_ed25519_token(&signing, kid, [27u8; 32]);
        t.signature.truncate(32); // not 64 bytes
        assert_eq!(v.verify(&t), VerifyOutcome::BadSignature);
    }

    // ---- V242 runtime registry / list_issuers tests ------------------

    #[test]
    fn register_then_list_issuers() {
        let v = PrivacyPassVerifier::new(100);
        v.register_issuer(issuer([30u8; 32], b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        let signing = SigningKey::from_bytes(&[31u8; 32]);
        v.register_issuer(TrustedIssuer {
            key_id: [31u8; 32],
            name: "ed25519-listed".into(),
            public_key: signing.verifying_key().to_bytes().to_vec(),
            algorithm: SignatureAlgorithm::Ed25519,
            trust_duration: Duration::from_secs(7200),
        });

        let list = v.list_issuers();
        assert_eq!(list.len(), 2);
        // Sorted by key_id_hex → [30..] (1e...) before [31..] (1f...).
        assert_eq!(list[0].key_id_hex, hex_lower(&[30u8; 32]));
        assert_eq!(list[0].algorithm, "hmac_sha256");
        assert_eq!(list[1].name, "ed25519-listed");
        assert_eq!(list[1].algorithm, "ed25519");
        assert_eq!(list[1].trust_duration_secs, 7200);
        // Fingerprint is present, prefixed, and NOT the raw key.
        assert!(list[1].public_key_fingerprint.starts_with("sha256:"));
        assert_eq!(list[1].public_key_fingerprint.len(), "sha256:".len() + 16);
    }

    #[test]
    fn list_issuers_never_leaks_key_bytes() {
        let v = PrivacyPassVerifier::new(100);
        let secret_key = b"super-secret-hmac-key-aaaaaaaaaa";
        v.register_issuer(issuer([32u8; 32], secret_key));
        let info = &v.list_issuers()[0];
        // The raw key must not appear anywhere in the serialised view.
        let json = serde_json::to_string(info).unwrap();
        let key_hex = hex_lower(secret_key);
        assert!(!json.contains(&key_hex));
        assert!(!json.contains("super-secret"));
    }

    #[test]
    fn signature_algorithm_as_str_round_trip() {
        assert_eq!(SignatureAlgorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(SignatureAlgorithm::HmacSha256.as_str(), "hmac_sha256");
    }
}
