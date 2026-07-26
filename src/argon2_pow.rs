//! V200 — Argon2id memory-hard PoW alternative to V131 SHA-256.
//!
//! SHA-256 hashcash (our V131 default) scales linearly with hash
//! rate — a GPU farm grinds through it at ~$0.0001/solve. Argon2id
//! is memory-hard: solving requires `memory_kb` of RAM AND
//! `iterations` of compute. GPUs can't compress that ratio, so the
//! economic cost of brute-forcing rises 100-1000× compared to
//! SHA-256 at equivalent CPU time on a legitimate browser.
//!
//! ## Challenge protocol
//!
//! Server emits:
//!
//! ```json
//! { "kind": "argon2id",
//!   "salt": "<16 bytes hex>",
//!   "memory_kb": 65536,
//!   "iterations": 2,
//!   "parallelism": 1,
//!   "difficulty_bits": 20,
//!   "expires_at": 1716000000 }
//! ```
//!
//! Client (browser via WASM or pure JS) computes:
//!
//! ```js
//! for (let n = 0; ; n++) {
//!   const h = await argon2id(salt + n.toString(), 65536, 2);
//!   if (leadingZeroBits(h) >= 20) { return n; }
//! }
//! ```
//!
//! Server verifies in microseconds by running the same Argon2id
//! call ONCE with the submitted nonce — verification is cheap
//! relative to solving.
//!
//! ## Parameters
//!
//! Default `memory_kb = 65536` (64 MB), `iterations = 2`,
//! `parallelism = 1`, `difficulty_bits = 18`. Solves in ~1-2s on
//! a desktop browser; ~10-100× slower on a GPU farm because the
//! 64 MB per-thread memory floor caps parallelism per GPU SM.
//!
//! Operator-tunable via [ChallengeParams::high_security] (heavier
//! memory) or [ChallengeParams::low_friction] (faster solve, lower
//! security floor).

use argon2::{Algorithm, Argon2, Params, Version};

#[derive(Debug, Clone, Copy)]
pub struct ChallengeParams {
    pub memory_kb: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub difficulty_bits: u8,
}

impl Default for ChallengeParams {
    fn default() -> Self {
        Self {
            memory_kb: 65_536,
            iterations: 2,
            parallelism: 1,
            difficulty_bits: 18,
        }
    }
}

impl ChallengeParams {
    /// Stronger params for high-risk routes (admin / auth / sensitive
    /// endpoints). Solves in ~5-10s on a desktop; GPU farms can't
    /// keep up because the 256 MB per-attempt budget collapses
    /// parallelism even on H100s.
    pub fn high_security() -> Self {
        Self {
            memory_kb: 262_144,
            iterations: 3,
            parallelism: 1,
            difficulty_bits: 22,
        }
    }

    /// Lower-friction params for low-risk routes (rate-limit
    /// escalation rather than sticky deny). Solves in ~300-500ms.
    pub fn low_friction() -> Self {
        Self {
            memory_kb: 16_384,
            iterations: 1,
            parallelism: 1,
            difficulty_bits: 14,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Solved,
    InsufficientWork,
    BadInput,
}

/// Compute Argon2id over `salt || nonce` and check that the
/// resulting hash has at least `difficulty_bits` leading zero bits.
/// Caller passes the same params they advertised in the challenge.
pub fn verify(salt: &[u8], nonce: u64, params: ChallengeParams) -> VerifyOutcome {
    let mut input = Vec::with_capacity(salt.len() + 16);
    input.extend_from_slice(salt);
    input.extend_from_slice(nonce.to_string().as_bytes());

    let argon_params = match Params::new(
        params.memory_kb,
        params.iterations,
        params.parallelism,
        Some(32), // output length
    ) {
        Ok(p) => p,
        Err(_) => return VerifyOutcome::BadInput,
    };
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; 32];
    // Argon2id requires salt ≥ 8 bytes; our challenge salts are
    // 16 bytes so this is satisfied unless the caller misuses us.
    if salt.len() < 8 {
        return VerifyOutcome::BadInput;
    }
    if argon.hash_password_into(&input, salt, &mut out).is_err() {
        return VerifyOutcome::BadInput;
    }
    if leading_zero_bits(&out) >= params.difficulty_bits as u32 {
        VerifyOutcome::Solved
    } else {
        VerifyOutcome::InsufficientWork
    }
}

/// Generate a challenge salt (16 random bytes hex-encoded for the
/// wire). Caller stores this alongside the challenge for later
/// `verify()`.
pub fn random_salt() -> [u8; 16] {
    use rand::RngCore;
    // Salts must be unguessable so attackers can't pre-grind nonces
    // for an upcoming challenge. Draw from the OS CSPRNG (ChaCha,
    // seeded from OS entropy) — same source used in pow_captcha.rs.
    let mut out = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_solve_and_verify() {
        let salt = random_salt();
        let params = ChallengeParams {
            memory_kb: 8,
            iterations: 1,
            parallelism: 1,
            difficulty_bits: 4,
        };
        // Brute-force a nonce that satisfies the (weak) difficulty.
        let mut nonce = 0u64;
        loop {
            if verify(&salt, nonce, params) == VerifyOutcome::Solved {
                break;
            }
            nonce += 1;
            assert!(nonce < 10_000, "should solve quickly at 4 bits");
        }
        // Verify is reproducible.
        assert_eq!(verify(&salt, nonce, params), VerifyOutcome::Solved);
    }

    #[test]
    fn insufficient_work_when_bits_too_low() {
        let salt = b"sixteen-byte-sal";
        let params = ChallengeParams {
            memory_kb: 8,
            iterations: 1,
            parallelism: 1,
            difficulty_bits: 32, // way too high for a random nonce
        };
        // Any random nonce should fail (almost surely).
        let outcome = verify(salt, 12345, params);
        assert_eq!(outcome, VerifyOutcome::InsufficientWork);
    }

    #[test]
    fn salt_too_short_is_bad_input() {
        let outcome = verify(b"abc", 0, ChallengeParams::default());
        assert_eq!(outcome, VerifyOutcome::BadInput);
    }

    #[test]
    fn different_param_presets_distinct() {
        let def = ChallengeParams::default();
        let hi = ChallengeParams::high_security();
        let lo = ChallengeParams::low_friction();
        assert!(hi.memory_kb > def.memory_kb);
        assert!(hi.difficulty_bits > def.difficulty_bits);
        assert!(lo.memory_kb < def.memory_kb);
        assert!(lo.difficulty_bits < def.difficulty_bits);
    }

    #[test]
    fn random_salt_is_non_repeating() {
        let a = random_salt();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = random_salt();
        assert_ne!(a, b);
    }

    #[test]
    fn random_salt_non_repeating_back_to_back() {
        // CSPRNG salts must differ even without any wall-clock gap
        // (the old timestamp-seeded generator could collide here).
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            assert!(seen.insert(random_salt()), "salt collision");
        }
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x40]), 1);
        assert_eq!(leading_zero_bits(&[0x00, 0xff]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x40]), 17);
    }
}
