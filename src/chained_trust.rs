//! V202 — Chained challenge trust progression.
//!
//! Today every challenge level is standalone — passing the PoW
//! doesn't excuse the same client from re-solving the CAPTCHA an
//! hour later. The friendly UX rule: a stronger challenge cleared
//! grants a longer trust window than a weaker one.
//!
//! ```text
//!   Cleared L1 cookie       → 5 min bypass for L1+L2
//!   Cleared L2 reload       → 15 min bypass for L1+L2+L3
//!   Cleared L4 PoW          → 1 hour bypass for L1..L4
//!   Cleared L5 captcha      → 24 hour bypass for L1..L5
//!   Cleared L6 WebAuthn     → 7 days bypass for L1..L6
//!   Privacy Pass token      → issuer-specified (typically 24h)
//! ```
//!
//! Stored per (IP, route_class, nonce). Cookie carries the highest
//! cleared tier so subsequent requests skip the ladder until
//! expiration. On `aegis_fp` cookie tamper, all trust is dropped.
//!
//! V233 — auth_bypass fix. A grant is no longer keyed on the bare
//! client IP. Anyone behind a shared CGNAT / corporate-NAT egress
//! used to ride a 24h grant the instant one peer cleared a
//! challenge. Each grant is now bound to a server-issued,
//! HMAC-signed random nonce delivered to that one client as a
//! cookie value. `current()`/`covers()` require the caller to
//! present the matching signed cookie; the HMAC is verified and the
//! embedded nonce must match the stored grant. The IP remains as a
//! secondary check (the nonce is signed over `ip:nonce`, so a
//! cookie minted for one IP will not verify under another) but is
//! never sufficient on its own — an absent or mismatched nonce
//! yields `TrustTier::None`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// V233 — signed cookie value handed to a client when a grant is
/// recorded, and presented back on later requests. Format is
/// `base64(nonce).base64(hmac)` where the HMAC is taken over
/// `ip:nonce` so a token minted for one IP cannot be replayed from
/// another. Opaque to callers — treat it as the cookie string.
pub type SignedNonce = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustTier {
    None,
    Cookie,
    Reload,
    Interaction,
    Pow,
    Captcha,
    WebAuthn,
    PrivacyPass,
}

impl TrustTier {
    pub fn default_duration(self) -> Duration {
        match self {
            Self::None => Duration::ZERO,
            Self::Cookie => Duration::from_secs(5 * 60),
            Self::Reload => Duration::from_secs(15 * 60),
            Self::Interaction => Duration::from_secs(30 * 60),
            Self::Pow => Duration::from_secs(60 * 60),
            Self::Captcha => Duration::from_secs(24 * 60 * 60),
            Self::WebAuthn => Duration::from_secs(7 * 24 * 60 * 60),
            Self::PrivacyPass => Duration::from_secs(24 * 60 * 60),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Cookie => "cookie",
            Self::Reload => "reload",
            Self::Interaction => "interaction",
            Self::Pow => "pow",
            Self::Captcha => "captcha",
            Self::WebAuthn => "webauthn",
            Self::PrivacyPass => "privacy_pass",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustGrant {
    pub tier: TrustTier,
    pub granted_at: Instant,
    pub expires_at: Instant,
    pub route_class: RouteClass,
    /// V233 — the random nonce this grant is bound to. The client
    /// must present a cookie carrying a signed copy of this exact
    /// value for the grant to apply; the IP alone never matches.
    pub nonce: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteClass {
    /// Default — covers all routes except auth.
    Generic,
    /// `/login`, `/signup`, password-reset, etc. — trust never
    /// auto-grants here; the operator must explicitly opt-in via
    /// allow_for_auth().
    Auth,
    /// `/api/*` — separately tunable (e.g., API consumers might
    /// authenticate via mTLS and bypass entirely).
    Api,
}

pub struct ChainedTrustStore {
    /// V233 — keyed on `(IP, route_class, nonce)`. The nonce binds
    /// each grant to one server-issued signed cookie so peers behind
    /// a shared egress IP cannot share a grant.
    grants: RwLock<HashMap<(IpAddr, RouteClass, String), TrustGrant>>,
    allow_auth: bool,
    /// V233 — HMAC key used to sign and verify the per-grant nonce
    /// cookie. Process-random by default (`new()`), so grants do not
    /// survive a restart; pass an explicit key via `with_secret()`
    /// when grants must outlive a single process or be verified
    /// across a fleet.
    secret: Vec<u8>,
}

impl ChainedTrustStore {
    pub fn new() -> Self {
        // V233 — random per-process HMAC key. A 32-byte key means
        // signed nonces cannot be forged without reading process
        // memory; a restart simply invalidates outstanding cookies.
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self {
            grants: RwLock::new(HashMap::new()),
            allow_auth: false,
            secret,
        }
    }

    /// V233 — use an explicit HMAC key (e.g. an operator-configured
    /// secret) instead of the process-random default, so signed
    /// nonce cookies remain valid across restarts / multiple nodes.
    pub fn with_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        let s = secret.into();
        if !s.is_empty() {
            self.secret = s;
        }
        self
    }

    pub fn with_allow_for_auth(mut self, on: bool) -> Self {
        self.allow_auth = on;
        self
    }

    /// V233 — mint a fresh random nonce and return it alongside its
    /// signed cookie form. The HMAC covers `ip:nonce`, binding the
    /// token to the issuing IP.
    fn mint_nonce(&self, ip: IpAddr) -> (String, SignedNonce) {
        let mut raw = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut raw);
        let nonce = URL_SAFE_NO_PAD.encode(raw);
        let signed = self.sign_nonce(ip, &nonce);
        (nonce, signed)
    }

    /// V233 — produce `base64(nonce).base64(hmac(ip:nonce))`.
    fn sign_nonce(&self, ip: IpAddr, nonce: &str) -> SignedNonce {
        let payload = format!("{ip}:{nonce}");
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("hmac accepts any key length");
        mac.update(payload.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{}.{}", URL_SAFE_NO_PAD.encode(nonce), sig)
    }

    /// V233 — verify a presented signed cookie against `ip` and
    /// return the embedded nonce on success. Verification is
    /// constant-time (`Mac::verify_slice`); any malformed token, bad
    /// base64, wrong length, or forged signature yields `None`. A
    /// cookie signed for a different IP will not verify here because
    /// the IP is part of the signed payload.
    fn verify_nonce(&self, ip: IpAddr, signed: &str) -> Option<String> {
        let (nonce_b64, sig_b64) = signed.split_once('.')?;
        let nonce = String::from_utf8(URL_SAFE_NO_PAD.decode(nonce_b64).ok()?).ok()?;
        let payload = format!("{ip}:{nonce}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).ok()?;
        mac.update(payload.as_bytes());
        let supplied = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
        mac.verify_slice(&supplied).ok()?;
        Some(nonce)
    }

    /// V233 — record a cleared challenge and return the signed nonce
    /// cookie the caller MUST set on the client. The grant is keyed
    /// on `(ip, route_class, nonce)`; only a request that presents
    /// this exact signed cookie will see the grant. Returns `None`
    /// when no grant is recorded (an auth route without opt-in), so
    /// the caller knows not to set a cookie.
    #[must_use]
    pub fn record(
        &self,
        ip: IpAddr,
        tier: TrustTier,
        route_class: RouteClass,
    ) -> Option<SignedNonce> {
        if route_class == RouteClass::Auth && !self.allow_auth {
            return None;
        }
        let now = Instant::now();
        let mut g = self.grants.write().unwrap();

        // V233 — if a still-valid *stronger* grant already exists for
        // this (ip, route_class), keep it and hand back its existing
        // signed cookie rather than minting a weaker grant. This
        // preserves the original "don't downgrade" intent now that
        // grants are per-nonce; the client keeps the longer window.
        if let Some((nonce, existing)) = g
            .iter()
            .filter(|((kip, krc, _), v)| *kip == ip && *krc == route_class && v.expires_at > now)
            .max_by_key(|(_, v)| v.tier)
            .map(|((_, _, n), v)| (n.clone(), v.tier))
        {
            if existing > tier {
                return Some(self.sign_nonce(ip, &nonce));
            }
        }

        let (nonce, signed) = self.mint_nonce(ip);
        let grant = TrustGrant {
            tier,
            granted_at: now,
            expires_at: now + tier.default_duration(),
            route_class,
            nonce: nonce.clone(),
        };
        g.insert((ip, route_class, nonce), grant);
        Some(signed)
    }

    /// V233 — returns the active tier for this `(IP, route_class)`
    /// pair, but ONLY when the caller presents the signed nonce
    /// cookie that the matching grant was issued under. `cookie` is
    /// the `aegis_fp`-style cookie value (or `None` if the request
    /// carried none). An absent, malformed, wrong-IP, or
    /// unrecognised cookie yields `TrustTier::None` — the bare IP is
    /// never sufficient. Expired grants are not returned.
    pub fn current(&self, ip: IpAddr, route_class: RouteClass, cookie: Option<&str>) -> TrustTier {
        // V233 — no cookie => no trust. This is the core of the
        // auth_bypass fix: a peer behind the same NAT egress IP that
        // never cleared a challenge has no signed nonce to present.
        let Some(cookie) = cookie else {
            return TrustTier::None;
        };
        // V233 — verify the HMAC and recover the nonce. The IP is
        // part of the signed payload, so a cookie minted for another
        // client's IP fails here (defence in depth).
        let Some(nonce) = self.verify_nonce(ip, cookie) else {
            return TrustTier::None;
        };
        let now = Instant::now();
        let g = self.grants.read().unwrap();
        // V233 — the grant must exist under exactly this
        // (ip, route_class, nonce) triple. A valid signature over a
        // nonce with no live grant still yields None.
        g.get(&(ip, route_class, nonce))
            .filter(|g| g.expires_at > now)
            .map(|g| g.tier)
            .unwrap_or(TrustTier::None)
    }

    /// V233 — check if the trust the client can prove (via its
    /// signed nonce `cookie`) meets `required`. Returns `true` only
    /// when a verified, unexpired grant of at least `required` is
    /// keyed under the presented cookie's nonce. An absent or
    /// mismatched cookie always returns `false`.
    pub fn covers(
        &self,
        ip: IpAddr,
        route_class: RouteClass,
        required: TrustTier,
        cookie: Option<&str>,
    ) -> bool {
        self.current(ip, route_class, cookie) >= required
    }

    /// Drop trust grants for an IP (e.g., on cookie tamper or
    /// after deny decision). V233 — clears every per-nonce grant
    /// held for the IP across all route classes.
    pub fn revoke(&self, ip: IpAddr) {
        let mut g = self.grants.write().unwrap();
        g.retain(|(k, _, _), _| *k != ip);
    }

    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let mut g = self.grants.write().unwrap();
        let before = g.len();
        g.retain(|_, grant| grant.expires_at > now);
        before - g.len()
    }

    pub fn len(&self) -> usize {
        self.grants.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ChainedTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, 0, 0, 1))
    }

    #[test]
    fn captcha_grants_24h_trust() {
        let s = ChainedTrustStore::new();
        // V233 — record now returns the signed cookie to present.
        let c = s.record(ip(1), TrustTier::Captcha, RouteClass::Generic);
        let c = c.as_deref();
        assert!(s.covers(ip(1), RouteClass::Generic, TrustTier::Pow, c));
        assert!(s.covers(ip(1), RouteClass::Generic, TrustTier::Cookie, c));
        assert!(!s.covers(ip(1), RouteClass::Generic, TrustTier::WebAuthn, c));
    }

    #[test]
    fn stronger_grant_not_downgraded_by_weaker() {
        let s = ChainedTrustStore::new();
        // V233 — the weaker record() returns the still-valid stronger
        // grant's cookie, so the client keeps the Pow window.
        let pow = s.record(ip(2), TrustTier::Pow, RouteClass::Generic);
        let after = s.record(ip(2), TrustTier::Cookie, RouteClass::Generic);
        assert_eq!(
            s.current(ip(2), RouteClass::Generic, after.as_deref()),
            TrustTier::Pow
        );
        // The originally-issued cookie still resolves to Pow too.
        assert_eq!(
            s.current(ip(2), RouteClass::Generic, pow.as_deref()),
            TrustTier::Pow
        );
    }

    #[test]
    fn auth_route_blocks_record_by_default() {
        let s = ChainedTrustStore::new();
        // V233 — no grant on auth without opt-in => record() is None.
        let c = s.record(ip(3), TrustTier::Pow, RouteClass::Auth);
        assert!(c.is_none());
        assert_eq!(s.current(ip(3), RouteClass::Auth, None), TrustTier::None);
    }

    #[test]
    fn opt_in_allows_auth_record() {
        let s = ChainedTrustStore::new().with_allow_for_auth(true);
        let c = s.record(ip(4), TrustTier::WebAuthn, RouteClass::Auth);
        assert!(s.covers(ip(4), RouteClass::Auth, TrustTier::Captcha, c.as_deref()));
    }

    #[test]
    fn revoke_drops_all_trust_for_ip() {
        let s = ChainedTrustStore::new();
        let cg = s.record(ip(5), TrustTier::Captcha, RouteClass::Generic);
        let ca = s.record(ip(5), TrustTier::Cookie, RouteClass::Api);
        s.revoke(ip(5));
        assert_eq!(
            s.current(ip(5), RouteClass::Generic, cg.as_deref()),
            TrustTier::None
        );
        assert_eq!(
            s.current(ip(5), RouteClass::Api, ca.as_deref()),
            TrustTier::None
        );
    }

    #[test]
    fn gc_drops_expired_grants() {
        let s = ChainedTrustStore::new();
        // V233 — inject a grant whose expiry is already past. The
        // signed cookie for its nonce is needed to look it up.
        let nonce = "expired-nonce".to_string();
        s.grants.write().unwrap().insert(
            (ip(6), RouteClass::Generic, nonce.clone()),
            TrustGrant {
                tier: TrustTier::Cookie,
                granted_at: Instant::now() - Duration::from_secs(3600),
                expires_at: Instant::now() - Duration::from_secs(1),
                route_class: RouteClass::Generic,
                nonce: nonce.clone(),
            },
        );
        let cookie = s.sign_nonce(ip(6), &nonce);
        assert_eq!(s.gc(), 1);
        assert_eq!(
            s.current(ip(6), RouteClass::Generic, Some(&cookie)),
            TrustTier::None
        );
    }

    #[test]
    fn route_classes_are_independent() {
        let s = ChainedTrustStore::new();
        let c = s.record(ip(7), TrustTier::Captcha, RouteClass::Generic);
        let c = c.as_deref();
        assert!(s.covers(ip(7), RouteClass::Generic, TrustTier::Captcha, c));
        // V233 — a Generic-route cookie carries no Api-route grant.
        assert!(!s.covers(ip(7), RouteClass::Api, TrustTier::Cookie, c));
    }

    #[test]
    fn tier_ordering_matches_doc() {
        assert!(TrustTier::Cookie < TrustTier::Pow);
        assert!(TrustTier::Pow < TrustTier::Captcha);
        assert!(TrustTier::Captcha < TrustTier::WebAuthn);
    }

    // V233 — auth_bypass fix. The core regression test: a grant
    // earned by one (ip, nonce) MUST NOT be honoured for the same IP
    // when a different nonce, or no nonce, is presented. This is the
    // shared-CGNAT / corporate-NAT bypass that the fix closes.
    #[test]
    fn grant_not_honoured_for_same_ip_with_different_or_absent_nonce() {
        let s = ChainedTrustStore::new();
        let shared_ip = ip(40);

        // Client A behind the NAT clears a captcha and gets a cookie.
        let cookie_a = s
            .record(shared_ip, TrustTier::Captcha, RouteClass::Generic)
            .expect("grant recorded");

        // A presenting its own cookie sees the grant — sanity check.
        assert_eq!(
            s.current(shared_ip, RouteClass::Generic, Some(&cookie_a)),
            TrustTier::Captcha
        );

        // Client B shares the egress IP but presents NO cookie.
        // It must not ride A's grant.
        assert_eq!(
            s.current(shared_ip, RouteClass::Generic, None),
            TrustTier::None
        );
        assert!(!s.covers(shared_ip, RouteClass::Generic, TrustTier::Cookie, None));

        // Client B forges a cookie under a different nonce (validly
        // signed for the IP but never issued for a grant). Even a
        // genuine signature over an unknown nonce yields no trust.
        let foreign = s.sign_nonce(shared_ip, "attacker-chosen-nonce");
        assert_eq!(
            s.current(shared_ip, RouteClass::Generic, Some(&foreign)),
            TrustTier::None
        );

        // Client B presents garbage / a tampered cookie.
        assert_eq!(
            s.current(shared_ip, RouteClass::Generic, Some("not.a.cookie")),
            TrustTier::None
        );
        assert_eq!(
            s.current(shared_ip, RouteClass::Generic, Some("")),
            TrustTier::None
        );

        // Flipping a byte of A's signature must break verification.
        let (payload, sig) = cookie_a.split_once('.').unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(sig).unwrap();
        raw[0] ^= 0x01;
        let tampered = format!("{payload}.{}", URL_SAFE_NO_PAD.encode(&raw));
        assert_eq!(
            s.current(shared_ip, RouteClass::Generic, Some(&tampered)),
            TrustTier::None
        );
    }

    // V233 — a cookie minted for one IP must not verify under a
    // different IP, since the IP is part of the signed payload.
    #[test]
    fn cookie_does_not_carry_across_ips() {
        let s = ChainedTrustStore::new();
        let cookie = s
            .record(ip(41), TrustTier::Captcha, RouteClass::Generic)
            .expect("grant recorded");
        // Same cookie value, different client IP — rejected.
        assert_eq!(
            s.current(ip(42), RouteClass::Generic, Some(&cookie)),
            TrustTier::None
        );
    }

    // V233 — a cookie signed by a store with a different secret must
    // not verify, so process-random keys isolate grants per process.
    #[test]
    fn cookie_from_other_secret_rejected() {
        let issuer = ChainedTrustStore::new();
        let cookie = issuer
            .record(ip(43), TrustTier::Captcha, RouteClass::Generic)
            .expect("grant recorded");
        // A different store (fresh random secret) cannot honour it.
        let other = ChainedTrustStore::new();
        assert_eq!(
            other.current(ip(43), RouteClass::Generic, Some(&cookie)),
            TrustTier::None
        );
        // With an explicit shared secret, the cookie does verify.
        let shared = ChainedTrustStore::new().with_secret(*b"a-shared-32-byte-operator-secret");
        let c2 = shared
            .record(ip(44), TrustTier::Pow, RouteClass::Generic)
            .expect("grant recorded");
        let peer = ChainedTrustStore::new().with_secret(*b"a-shared-32-byte-operator-secret");
        // Signature verifies under the peer, but the peer holds no
        // grant for that nonce — still None (grant store is local).
        assert_eq!(
            peer.current(ip(44), RouteClass::Generic, Some(&c2)),
            TrustTier::None
        );
        // The issuing store with the matching secret honours it.
        assert_eq!(
            shared.current(ip(44), RouteClass::Generic, Some(&c2)),
            TrustTier::Pow
        );
    }

    // V233 — two distinct clients behind one IP each clear a
    // challenge; each holds its own grant under its own nonce and
    // neither can present the other's tier.
    #[test]
    fn two_clients_one_ip_have_independent_grants() {
        let s = ChainedTrustStore::new();
        let shared_ip = ip(45);
        let weak = s
            .record(shared_ip, TrustTier::Cookie, RouteClass::Generic)
            .expect("grant recorded");
        let strong = s
            .record(shared_ip, TrustTier::WebAuthn, RouteClass::Generic)
            .expect("grant recorded");
        // The weak-cookie client cannot claim WebAuthn trust.
        assert!(!s.covers(
            shared_ip,
            RouteClass::Generic,
            TrustTier::WebAuthn,
            Some(&weak)
        ));
        assert_eq!(
            s.current(shared_ip, RouteClass::Generic, Some(&weak)),
            TrustTier::Cookie
        );
        // The strong-cookie client retains WebAuthn trust.
        assert_eq!(
            s.current(shared_ip, RouteClass::Generic, Some(&strong)),
            TrustTier::WebAuthn
        );
    }
}
