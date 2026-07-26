//! V131 — Proof-of-Work CAPTCHA (custom, asymmetric CPU cost).
//!
//! Designed against the case where a single attacker proxies many
//! sessions through one host. External CAPTCHA providers (hCaptcha /
//! Turnstile — see V132) cost the operator money per request and lean
//! on third-party heuristics; this tier instead burns the attacker's
//! own CPU, scaling linearly with concurrency.
//!
//! ## Protocol
//!
//! Server issues a token `{nonce, difficulty, exp, hmac}`:
//!
//! * `nonce`      — 16 random bytes (base64-url).
//! * `difficulty` — required leading zero bits in SHA-256(nonce ‖ solution).
//! * `exp`        — unix seconds, monotonic clock skip; default 120s.
//! * `hmac`       — HMAC-SHA256(secret, nonce ‖ difficulty ‖ exp).
//!
//! Encoded as URL-safe base64; embedded into the challenge HTML
//! alongside a tiny JS worker that hunts for `solution: u64` such
//! that `leading_zeros(sha256(nonce ‖ solution_le_bytes)) ≥ difficulty`.
//!
//! Client submits `{token, solution}` (cookie or form). Server checks:
//!
//! 1. HMAC matches (rejects tampering / forged tokens).
//! 2. Not expired (rejects replay across mode shifts).
//! 3. SHA-256 prefix meets difficulty (rejects unsolved tokens).
//!
//! All three checks are O(1). Attacker work is O(2^difficulty) per
//! token, average ~2^(difficulty-1) hashes.
//!
//! ## Asymmetry numbers (modern x86, ~30 MH/s sha256 single-core)
//!
//! | difficulty | avg client work | server verify |
//! |-----------:|----------------:|--------------:|
//! |         16 |          ~1 ms  |       <100 µs |
//! |         20 |          ~17 ms |       <100 µs |
//! |         22 |          ~70 ms |       <100 µs |
//! |         24 |         ~280 ms |       <100 µs |
//! |         26 |         ~1.1 s  |       <100 µs |
//! |         28 |         ~4.5 s  |       <100 µs |
//!
//! Operator picks difficulty per risk band (see `DifficultyLadder`).
//! Adaptive mode auto-raises under attack via the existing mode
//! controller — bot pays seconds per session, we still answer at
//! line rate.
//!
//! ## Stateless verify
//!
//! Token carries its own integrity (HMAC) and expiry (`exp`). No
//! per-IP server state is needed for verify, which means a fleet of
//! Aegis instances behind a load balancer all accept each other's
//! tokens with a shared secret. Replay within the TTL is the only
//! cheat surface; ladder TTL is short on purpose.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Hard upper bound — refuse to issue difficulties so large the
/// client browser would visibly hang. Operator can tune lower via
/// config; we just clamp the absolute max.
const MAX_DIFFICULTY: u8 = 28;
/// Hard lower bound — anything under this is solvable in <1ms which
/// makes the PoW worthless against scripted attackers.
const MIN_DIFFICULTY: u8 = 12;

/// Per-risk-band difficulty. Picked to keep good-user friction below
/// 1s while making bot work climb exponentially under attack.
#[derive(Debug, Clone, Copy)]
pub struct DifficultyLadder {
    pub baseline: u8,
    pub elevated: u8,
    pub attack: u8,
    pub critical: u8,
}

impl Default for DifficultyLadder {
    fn default() -> Self {
        // Baseline: nearly invisible to humans (~17ms).
        // Critical: ~4.5s sustained per session — single-PC attacker
        // proxying 50 sessions burns one core for ~4 minutes per
        // round of tokens.
        Self {
            baseline: 20,
            elevated: 22,
            attack: 24,
            critical: 28,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskBand {
    Baseline,
    Elevated,
    Attack,
    Critical,
}

impl DifficultyLadder {
    pub fn for_band(&self, band: RiskBand) -> u8 {
        let d = match band {
            RiskBand::Baseline => self.baseline,
            RiskBand::Elevated => self.elevated,
            RiskBand::Attack => self.attack,
            RiskBand::Critical => self.critical,
        };
        d.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
    }
}

/// Issuer/verifier. Stateless aside from the HMAC secret.
#[derive(Clone)]
pub struct PowIssuer {
    secret: Vec<u8>,
    ttl_secs: u64,
    ladder: DifficultyLadder,
}

impl PowIssuer {
    pub fn new(secret: impl Into<Vec<u8>>, ttl_secs: u64, ladder: DifficultyLadder) -> Self {
        Self {
            secret: secret.into(),
            ttl_secs,
            ladder,
        }
    }

    pub fn with_default_ladder(secret: impl Into<Vec<u8>>) -> Self {
        Self::new(secret, 120, DifficultyLadder::default())
    }

    /// Produce a fresh token for the given risk band. Embeds difficulty,
    /// 16-byte nonce, expiry, and HMAC. URL-safe base64, no padding.
    ///
    /// V234 — this is the unbound form (empty binding); it delegates to
    /// [`issue_bound`] so there is one MAC code path. Token bytes are
    /// unchanged vs. the pre-V234 implementation.
    pub fn issue(&self, band: RiskBand) -> PowToken {
        self.issue_bound(band, b"")
    }

    /// Validate a `{encoded_token, solution}` submission. Returns the
    /// token's difficulty on success (for logging / telemetry).
    pub fn verify(&self, encoded_token: &str, solution: u64, now_unix: u64) -> VerifyResult {
        self.verify_bound(encoded_token, solution, now_unix, b"")
    }

    /// V234 — IP-bound issue. Identical to [`PowIssuer::issue`] but the
    /// HMAC additionally covers `binding` (the caller passes the client
    /// IP string). A token minted for one IP fails [`verify_bound`]
    /// under any other IP, so an attacker cannot farm one solved
    /// challenge across a botnet — each source address must do its own
    /// work. The wire format is unchanged (`nonce ‖ difficulty ‖ exp ‖
    /// mac`); only the bytes fed into the MAC differ.
    pub fn issue_bound(&self, band: RiskBand, binding: &[u8]) -> PowToken {
        self.issue_bound_with_difficulty(self.ladder.for_band(band), binding)
    }

    /// V243 — issue a token with an EXPLICIT difficulty, bypassing the
    /// risk-band ladder. Used for the in-browser interstitial PoW: the
    /// ladder's `attack`/`critical` bands (24/28 bits ≈ 8M/134M hashes)
    /// are tuned for native/server hashing and are unsolvable in a
    /// browser's JS in reasonable time — they made "Checking your
    /// browser" spin forever. The challenge rungs instead use
    /// [`BROWSER_POW_DIFFICULTY`], which a batched WebCrypto solver
    /// clears in well under a second. Verification is unaffected (it
    /// reads the difficulty out of the token).
    pub fn issue_bound_with_difficulty(&self, difficulty: u8, binding: &[u8]) -> PowToken {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let exp = now.saturating_add(self.ttl_secs);
        let mac = self.sign_bound(&nonce, difficulty, exp, binding);
        PowToken {
            nonce,
            difficulty,
            exp,
            mac,
        }
    }

    /// V234 — IP-bound verify. See [`issue_bound`]. The `binding` bytes
    /// must byte-match what was passed to `issue_bound`, or the HMAC
    /// check fails with [`VerifyResult::BadSignature`] — this is what
    /// enforces the per-IP single-tenancy of a solved challenge.
    pub fn verify_bound(
        &self,
        encoded_token: &str,
        solution: u64,
        now_unix: u64,
        binding: &[u8],
    ) -> VerifyResult {
        let token = match PowToken::decode(encoded_token) {
            Some(t) => t,
            None => return VerifyResult::Malformed,
        };
        // Recompute the expected MAC and compare in constant time
        // (`ct_eq`) so a forged token can't be probed via timing.
        let expect = self.sign_bound(&token.nonce, token.difficulty, token.exp, binding);
        if !ct_eq(&expect, &token.mac) {
            return VerifyResult::BadSignature;
        }
        if now_unix > token.exp {
            return VerifyResult::Expired;
        }
        if !solution_satisfies(&token.nonce, solution, token.difficulty) {
            return VerifyResult::WrongSolution;
        }
        VerifyResult::Ok {
            difficulty: token.difficulty,
        }
    }

    /// V234 — HMAC over `nonce ‖ difficulty ‖ exp ‖ binding`. With an
    /// empty `binding` this is byte-identical to the original [`sign`],
    /// so unbound `issue`/`verify` keep their existing token bytes.
    fn sign_bound(&self, nonce: &[u8; 16], difficulty: u8, exp: u64, binding: &[u8]) -> [u8; 32] {
        let mut m =
            <HmacSha256 as Mac>::new_from_slice(&self.secret).expect("hmac accepts any key size");
        m.update(nonce);
        m.update(&[difficulty]);
        m.update(&exp.to_be_bytes());
        m.update(binding);
        let out = m.finalize().into_bytes();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&out);
        buf
    }
}

/// V234 — constant-time 32-byte comparison. Used by [`PowIssuer::
/// verify_bound`] so a forged MAC cannot be probed via a timing
/// side-channel. Folds every byte difference into one accumulator
/// and only branches on the final result.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    Ok { difficulty: u8 },
    Malformed,
    BadSignature,
    Expired,
    WrongSolution,
}

/// Self-describing PoW challenge. Encoded as URL-safe base64 of the
/// fixed-layout struct: nonce(16) ‖ difficulty(1) ‖ exp(8 BE) ‖ mac(32).
#[derive(Debug, Clone)]
pub struct PowToken {
    pub nonce: [u8; 16],
    pub difficulty: u8,
    pub exp: u64,
    pub mac: [u8; 32],
}

impl PowToken {
    pub const ENCODED_RAW_LEN: usize = 16 + 1 + 8 + 32;

    pub fn encode(&self) -> String {
        let mut buf = [0u8; Self::ENCODED_RAW_LEN];
        buf[0..16].copy_from_slice(&self.nonce);
        buf[16] = self.difficulty;
        buf[17..25].copy_from_slice(&self.exp.to_be_bytes());
        buf[25..57].copy_from_slice(&self.mac);
        URL_SAFE_NO_PAD.encode(buf)
    }

    pub fn decode(s: &str) -> Option<Self> {
        let raw = URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
        if raw.len() != Self::ENCODED_RAW_LEN {
            return None;
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&raw[0..16]);
        let difficulty = raw[16];
        let mut exp_b = [0u8; 8];
        exp_b.copy_from_slice(&raw[17..25]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&raw[25..57]);
        Some(Self {
            nonce,
            difficulty,
            exp: u64::from_be_bytes(exp_b),
            mac,
        })
    }
}

/// SHA-256(nonce ‖ solution.to_le_bytes()) has ≥ `bits` leading zero bits?
pub fn solution_satisfies(nonce: &[u8; 16], solution: u64, bits: u8) -> bool {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(solution.to_le_bytes());
    let digest = h.finalize();
    leading_zero_bits(&digest) >= u32::from(bits)
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0u32;
    for b in bytes {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// Inverse of [solution_satisfies] — naive search used in tests AND
/// embedded into the JS client (port: bigint loop). For production
/// the JS worker uses SubtleCrypto.digest in a tight loop; same shape.
#[doc(hidden)]
pub fn solve(nonce: &[u8; 16], difficulty: u8) -> u64 {
    let mut sol = 0u64;
    loop {
        if solution_satisfies(nonce, sol, difficulty) {
            return sol;
        }
        sol = sol.wrapping_add(1);
    }
}

/// JS snippet served alongside the issued token. Uses SubtleCrypto
/// (universally available in modern browsers, including in Web
/// Workers) to compute SHA-256 in a loop. Same nonce ‖ LE u64
/// layout as `solution_satisfies`. Operator embeds this into the
/// existing challenge HTML; submission shape is `{token, solution}`.
/// V243 — difficulty used for the in-browser interstitial PoW. Decoupled
/// from the server-side risk bands (which assume native hashing). A batched
/// WebCrypto solver clears ~2^16 hashes in well under a second on typical
/// hardware; the real defense is the rest of the chain — this PoW is a
/// "ran our JS in a real browser + paid a small cost" liveness gate, so a
/// modest difficulty is correct. Tunable if needed.
pub const BROWSER_POW_DIFFICULTY: u8 = 16;

pub const POW_CLIENT_JS: &str = r#"
// Aegis PoW solver. Inputs: token (base64), difficulty (int).
// V243 — batched WebCrypto: fire a window of digests concurrently and let
// the engine pipeline them, instead of awaiting one hash at a time (which
// was thousands× slower and made the page spin forever).
async function aegisSolvePow(token, difficulty) {
  const raw = Uint8Array.from(
    atob(token.replace(/-/g, '+').replace(/_/g, '/')),
    c => c.charCodeAt(0)
  );
  const nonce = raw.slice(0, 16);
  function lead(d) {
    let n = 0;
    for (const b of d) { if (b === 0) { n += 8; continue; } n += Math.clz32(b) - 24; break; }
    return n;
  }
  const BATCH = 512;
  let base = 0n;
  for (;;) {
    const jobs = [];
    for (let k = 0; k < BATCH; k++) {
      const buf = new Uint8Array(24);
      buf.set(nonce, 0);
      new DataView(buf.buffer).setBigUint64(16, base + BigInt(k), true);
      jobs.push(crypto.subtle.digest('SHA-256', buf));
    }
    const digs = await Promise.all(jobs);
    for (let k = 0; k < BATCH; k++) {
      if (lead(new Uint8Array(digs[k])) >= difficulty) return (base + BigInt(k)).toString();
    }
    base += BigInt(BATCH);
  }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_matches_expectations() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x7f]), 1);
        assert_eq!(leading_zero_bits(&[0x00, 0x80]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x10]), 19);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x00, 0x00]), 32);
    }

    #[test]
    fn ladder_clamps_to_bounds() {
        let l = DifficultyLadder {
            baseline: 4,
            elevated: 100,
            attack: 0,
            critical: 200,
        };
        assert_eq!(l.for_band(RiskBand::Baseline), MIN_DIFFICULTY);
        assert_eq!(l.for_band(RiskBand::Elevated), MAX_DIFFICULTY);
        assert_eq!(l.for_band(RiskBand::Attack), MIN_DIFFICULTY);
        assert_eq!(l.for_band(RiskBand::Critical), MAX_DIFFICULTY);
    }

    #[test]
    fn token_roundtrip_encode_decode() {
        let iss = PowIssuer::with_default_ladder(b"secret".to_vec());
        let tok = iss.issue(RiskBand::Baseline);
        let enc = tok.encode();
        let back = PowToken::decode(&enc).expect("decode");
        assert_eq!(back.nonce, tok.nonce);
        assert_eq!(back.difficulty, tok.difficulty);
        assert_eq!(back.exp, tok.exp);
        assert_eq!(back.mac, tok.mac);
    }

    #[test]
    fn solver_finds_solution_low_difficulty() {
        // Use a tiny difficulty so the brute-force in-test stays fast.
        let nonce = [7u8; 16];
        let sol = solve(&nonce, 10);
        assert!(solution_satisfies(&nonce, sol, 10));
        assert!(!solution_satisfies(&nonce, sol.wrapping_sub(1), 10) || sol == 0);
    }

    #[test]
    fn verify_accepts_legit_solution() {
        let iss = PowIssuer::new(
            b"k".to_vec(),
            120,
            DifficultyLadder {
                baseline: 10,
                elevated: 10,
                attack: 10,
                critical: 10,
            },
        );
        let tok = iss.issue(RiskBand::Baseline);
        let sol = solve(&tok.nonce, tok.difficulty);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert_eq!(
            iss.verify(&tok.encode(), sol, now),
            VerifyResult::Ok {
                difficulty: tok.difficulty
            }
        );
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let iss = PowIssuer::with_default_ladder(b"k".to_vec());
        let tok = iss.issue(RiskBand::Baseline);
        // Easiest invariant-preserving tweak: re-encode with a flipped
        // difficulty, which invalidates the HMAC.
        let mut t2 = tok.clone();
        t2.difficulty = t2.difficulty.wrapping_add(1);
        let enc = t2.encode();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert_eq!(iss.verify(&enc, 0, now), VerifyResult::BadSignature);
    }

    #[test]
    fn verify_rejects_expired_token() {
        let iss = PowIssuer::new(b"k".to_vec(), 10, DifficultyLadder::default());
        let tok = iss.issue(RiskBand::Baseline);
        // Pretend wall clock advanced past expiry.
        let now = tok.exp + 1;
        assert_eq!(iss.verify(&tok.encode(), 0, now), VerifyResult::Expired);
    }

    #[test]
    fn verify_rejects_wrong_solution() {
        let iss = PowIssuer::new(
            b"k".to_vec(),
            120,
            DifficultyLadder {
                baseline: 20,
                elevated: 20,
                attack: 20,
                critical: 20,
            },
        );
        let tok = iss.issue(RiskBand::Baseline);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // A random solution overwhelmingly will not satisfy 20-bit prefix.
        assert_eq!(
            iss.verify(&tok.encode(), 0xdead_beef, now),
            VerifyResult::WrongSolution
        );
    }

    #[test]
    fn verify_rejects_malformed_input() {
        let iss = PowIssuer::with_default_ladder(b"k".to_vec());
        assert_eq!(iss.verify("not-base64-!@#", 0, 0), VerifyResult::Malformed);
        assert_eq!(iss.verify("AAAA", 0, 0), VerifyResult::Malformed);
    }

    #[test]
    fn different_secrets_dont_cross_verify() {
        let a = PowIssuer::with_default_ladder(b"secret-a".to_vec());
        let b = PowIssuer::with_default_ladder(b"secret-b".to_vec());
        let tok = a.issue(RiskBand::Baseline);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert_eq!(b.verify(&tok.encode(), 0, now), VerifyResult::BadSignature);
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn low_difficulty_issuer() -> PowIssuer {
        PowIssuer::new(
            b"k".to_vec(),
            120,
            DifficultyLadder {
                baseline: 10,
                elevated: 10,
                attack: 10,
                critical: 10,
            },
        )
    }

    // V234 — an unbound `issue` is verifiable by the unbound `verify`
    // (the empty-binding default), confirming the delegation keeps the
    // pre-V234 token bytes byte-identical.
    #[test]
    fn v234_unbound_issue_verifies_with_plain_verify() {
        let iss = low_difficulty_issuer();
        let tok = iss.issue(RiskBand::Baseline);
        let sol = solve(&tok.nonce, tok.difficulty);
        assert_eq!(
            iss.verify(&tok.encode(), sol, now_secs()),
            VerifyResult::Ok {
                difficulty: tok.difficulty
            }
        );
    }

    // V234 — a token minted with an IP binding verifies only when the
    // SAME binding bytes are supplied to `verify_bound`.
    #[test]
    fn v234_ip_bound_token_round_trips() {
        let iss = low_difficulty_issuer();
        let tok = iss.issue_bound(RiskBand::Baseline, b"203.0.113.7");
        let sol = solve(&tok.nonce, tok.difficulty);
        assert_eq!(
            iss.verify_bound(&tok.encode(), sol, now_secs(), b"203.0.113.7"),
            VerifyResult::Ok {
                difficulty: tok.difficulty
            }
        );
    }

    // V234 — the core anti-botnet property: a solution farmed under
    // one IP binding is rejected under a different binding.
    #[test]
    fn v234_ip_bound_token_rejected_under_other_ip() {
        let iss = low_difficulty_issuer();
        let tok = iss.issue_bound(RiskBand::Baseline, b"203.0.113.7");
        let sol = solve(&tok.nonce, tok.difficulty);
        assert_eq!(
            iss.verify_bound(&tok.encode(), sol, now_secs(), b"198.51.100.9"),
            VerifyResult::BadSignature
        );
        // And the unbound `verify` (empty binding) also rejects it.
        assert_eq!(
            iss.verify(&tok.encode(), sol, now_secs()),
            VerifyResult::BadSignature
        );
    }

    // V234 — `verify_bound` still enforces expiry and difficulty when
    // the binding matches.
    #[test]
    fn v234_verify_bound_enforces_expiry_and_difficulty() {
        let iss = PowIssuer::new(
            b"k".to_vec(),
            10,
            DifficultyLadder {
                baseline: 24,
                elevated: 24,
                attack: 24,
                critical: 24,
            },
        );
        let tok = iss.issue_bound(RiskBand::Baseline, b"ip");
        // Expired even though the binding matches.
        assert_eq!(
            iss.verify_bound(&tok.encode(), 0, tok.exp + 1, b"ip"),
            VerifyResult::Expired
        );
        // Wrong solution, binding + freshness fine.
        assert_eq!(
            iss.verify_bound(&tok.encode(), 0xdead_beef, now_secs(), b"ip"),
            VerifyResult::WrongSolution
        );
    }
}
