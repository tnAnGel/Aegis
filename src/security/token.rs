use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn sign_token(secret: &str, ip: &str, nonce: &str, exp: i64) -> String {
    let payload = format!("{ip}:{nonce}:{exp}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}", URL_SAFE_NO_PAD.encode(payload), sig)
}

pub fn verify_token(secret: &str, token: &str, ip: &str, now: i64) -> Option<(String, i64)> {
    let mut it = token.split('.');
    let p = it.next()?;
    let s = it.next()?;
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    // V233: constant-time HMAC verification. Decode the attacker-supplied
    // base64 signature to raw bytes and let `Mac::verify_slice` compare in
    // constant time; never compare the base64 strings (timing oracle). A
    // base64-decode failure returns `None` the same as a bad signature.
    let supplied = URL_SAFE_NO_PAD.decode(s).ok()?;
    mac.verify_slice(&supplied).ok()?;
    let parts: Vec<&str> = payload.split(':').collect();
    if parts.len() != 3 || parts[0] != ip {
        return None;
    }
    let nonce = parts[1].to_string();
    let exp = parts[2].parse::<i64>().ok()?;
    if now > exp {
        return None;
    }
    Some((nonce, exp))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "super-secret-key";

    #[test]
    fn sign_verify_round_trip() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-1", 9_999_999_999);
        let (nonce, exp) = verify_token(SECRET, &token, "10.0.0.1", 0).expect("valid");
        assert_eq!(nonce, "nonce-1");
        assert_eq!(exp, 9_999_999_999);
    }

    #[test]
    fn expired_token_rejected() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-2", 100);
        assert!(verify_token(SECRET, &token, "10.0.0.1", 200).is_none());
    }

    #[test]
    fn wrong_ip_rejected() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-3", 9_999_999_999);
        assert!(verify_token(SECRET, &token, "10.0.0.2", 0).is_none());
    }

    #[test]
    fn tampered_payload_rejected() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-4", 9_999_999_999);
        let mut parts = token.split('.');
        let _ = parts.next();
        let sig = parts.next().unwrap();
        let forged_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("10.0.0.1:nonce-4:9999999999extra");
        let forged = format!("{forged_payload}.{sig}");
        assert!(verify_token(SECRET, &forged, "10.0.0.1", 0).is_none());
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = sign_token(SECRET, "10.0.0.1", "n", 9_999_999_999);
        assert!(verify_token("other-secret", &token, "10.0.0.1", 0).is_none());
    }

    // V233: a forged signature must fail constant-time verification.
    #[test]
    fn wrong_signature_rejected() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-5", 9_999_999_999);
        let payload = token.split('.').next().unwrap();
        // 32-byte all-zero HMAC, correctly base64-encoded but wrong value.
        let forged_sig = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let forged = format!("{payload}.{forged_sig}");
        assert!(verify_token(SECRET, &forged, "10.0.0.1", 0).is_none());
    }

    // V233: flipping a single byte of a valid signature must still fail.
    #[test]
    fn single_byte_flipped_signature_rejected() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-6", 9_999_999_999);
        let (payload, sig) = token.split_once('.').unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(sig).unwrap();
        raw[0] ^= 0x01;
        let forged = format!("{payload}.{}", URL_SAFE_NO_PAD.encode(&raw));
        assert!(verify_token(SECRET, &forged, "10.0.0.1", 0).is_none());
    }

    // V233: a non-base64 signature must return `None`, not panic or early-exit.
    #[test]
    fn malformed_base64_signature_rejected() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-7", 9_999_999_999);
        let payload = token.split('.').next().unwrap();
        let forged = format!("{payload}.not*valid*base64");
        assert!(verify_token(SECRET, &forged, "10.0.0.1", 0).is_none());
    }

    // V233: a signature of the wrong length must return `None`.
    #[test]
    fn wrong_length_signature_rejected() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-8", 9_999_999_999);
        let payload = token.split('.').next().unwrap();
        let short_sig = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let forged = format!("{payload}.{short_sig}");
        assert!(verify_token(SECRET, &forged, "10.0.0.1", 0).is_none());
    }

    // V233: a correct signature must still verify after the fix.
    #[test]
    fn correct_signature_still_verifies() {
        let token = sign_token(SECRET, "10.0.0.1", "nonce-9", 9_999_999_999);
        let (nonce, exp) = verify_token(SECRET, &token, "10.0.0.1", 0).expect("valid");
        assert_eq!(nonce, "nonce-9");
        assert_eq!(exp, 9_999_999_999);
    }
}
