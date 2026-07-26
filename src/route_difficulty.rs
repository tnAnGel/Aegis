//! V186 — Anubis-style per-route challenge difficulty.
//!
//! Anubis (`TecharoHQ/anubis`) demonstrated that PoW gates work best
//! when difficulty scales with *server cost* of the protected route.
//! Cheap routes (static assets) want low difficulty (challenge
//! survival > server load), expensive routes (search, regenerate
//! token, password reset) can afford to make the client pay seconds
//! of CPU before allowing.
//!
//! The V42 challenge ladder previously had one global PoW difficulty
//! tier. This module exposes a per-(host, path-pattern) override
//! consulted before the ladder hands work to the PoW emitter.
//!
//! Two presets shipped:
//!
//! * `ai-scraper-mode` — if UA contains GPTBot/CCBot/Claude-Web/etc.
//!   bump difficulty by +4 bits. Mostly mirrors Anubis's default UA
//!   triggers.
//! * `auth-endpoint` — wildcards `*/login`, `*/signup`, `*/reset`
//!   get +6 bits and a forced JS PoW (no cookie-only bypass).
//!
//! Both presets are operator-toggleable in the admin UI; the path-
//! pattern matcher reuses the V162 domain-policy syntax (exact,
//! `/foo/*`, `*/bar`).

use std::collections::BTreeMap;
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    CookieRedirect,
    Captcha,
    JsPow { difficulty_bits: u8 },
}

#[derive(Debug, Clone)]
pub struct DifficultyOverride {
    pub host: String,
    pub path_pattern: String,
    pub difficulty_bits: u8,
    pub force_kind: Option<ChallengeKind>,
}

#[derive(Default)]
pub struct DifficultyTable {
    inner: RwLock<Vec<DifficultyOverride>>,
    /// Cached UA → difficulty bonus. Sorted, scan-once.
    ua_bumps: RwLock<BTreeMap<String, u8>>,
    enable_ai_scraper_preset: bool,
    enable_auth_preset: bool,
}

impl DifficultyTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable_ai_scraper_preset(mut self, on: bool) -> Self {
        self.enable_ai_scraper_preset = on;
        if on {
            let mut g = self.ua_bumps.write().unwrap();
            for bot in [
                "gptbot",
                "ccbot",
                "claude-web",
                "anthropic-ai",
                "perplexitybot",
                "youbot",
                "facebookbot",
                "amazonbot",
                "google-extended",
                "bytespider",
            ] {
                g.insert(bot.into(), 4);
            }
            drop(g);
        }
        self
    }

    pub fn enable_auth_preset(mut self, on: bool) -> Self {
        self.enable_auth_preset = on;
        if on {
            let mut g = self.inner.write().unwrap();
            for p in ["*/login", "*/signup", "*/register", "*/reset", "*/forgot"] {
                g.push(DifficultyOverride {
                    host: "*".into(),
                    path_pattern: p.into(),
                    difficulty_bits: 22, // baseline 16 + 6
                    force_kind: Some(ChallengeKind::JsPow {
                        difficulty_bits: 22,
                    }),
                });
            }
        }
        self
    }

    pub fn push(&self, ov: DifficultyOverride) {
        self.inner.write().unwrap().push(ov);
    }

    /// Compute effective challenge for a request. Returns the kind
    /// the caller should emit and the final difficulty bits.
    pub fn decide(
        &self,
        host: &str,
        path: &str,
        ua: &str,
        baseline_bits: u8,
        baseline_kind: ChallengeKind,
    ) -> (ChallengeKind, u8) {
        let g = self.inner.read().unwrap();
        let mut bits = baseline_bits;
        let mut kind = baseline_kind;
        for ov in g.iter() {
            if host_matches(&ov.host, host) && path_matches(&ov.path_pattern, path) {
                bits = bits.max(ov.difficulty_bits);
                if let Some(k) = ov.force_kind {
                    kind = k;
                }
            }
        }
        drop(g);
        // UA-driven bump.
        let bumps = self.ua_bumps.read().unwrap();
        let ua_lower = ua.to_ascii_lowercase();
        let bonus: u8 = bumps
            .iter()
            .filter(|(needle, _)| ua_lower.contains(needle.as_str()))
            .map(|(_, b)| *b)
            .max()
            .unwrap_or(0);
        bits = bits.saturating_add(bonus);
        // Normalise: if bits > baseline and current kind isn't PoW,
        // upgrade to PoW with the bumped difficulty.
        if bits > baseline_bits && !matches!(kind, ChallengeKind::JsPow { .. }) {
            kind = ChallengeKind::JsPow {
                difficulty_bits: bits,
            };
        } else if let ChallengeKind::JsPow { .. } = kind {
            kind = ChallengeKind::JsPow {
                difficulty_bits: bits,
            };
        }
        (kind, bits)
    }

    pub fn overrides(&self) -> Vec<DifficultyOverride> {
        self.inner.read().unwrap().clone()
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    pattern == "*" || pattern.eq_ignore_ascii_case(host)
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(suffix) = pattern.strip_prefix("*/") {
        return path.ends_with(&format!("/{suffix}")) || path == suffix;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_passes_through_when_no_override() {
        let t = DifficultyTable::new();
        let (k, b) = t.decide("x", "/", "Mozilla", 16, ChallengeKind::CookieRedirect);
        assert_eq!(b, 16);
        assert_eq!(k, ChallengeKind::CookieRedirect);
    }

    #[test]
    fn ai_scraper_preset_bumps_difficulty_and_forces_pow() {
        let t = DifficultyTable::new().enable_ai_scraper_preset(true);
        let (k, b) = t.decide(
            "x",
            "/",
            "Mozilla/5.0 (compatible; GPTBot/1.2)",
            16,
            ChallengeKind::CookieRedirect,
        );
        assert_eq!(b, 20);
        assert!(matches!(k, ChallengeKind::JsPow { .. }));
    }

    #[test]
    fn auth_preset_protects_login() {
        let t = DifficultyTable::new().enable_auth_preset(true);
        let (k, b) = t.decide(
            "evil.com",
            "/api/v1/login",
            "curl/8",
            16,
            ChallengeKind::CookieRedirect,
        );
        assert_eq!(b, 22);
        assert!(matches!(
            k,
            ChallengeKind::JsPow {
                difficulty_bits: 22
            }
        ));
    }

    #[test]
    fn explicit_override_takes_max() {
        let t = DifficultyTable::new();
        t.push(DifficultyOverride {
            host: "search.com".into(),
            path_pattern: "/q/*".into(),
            difficulty_bits: 24,
            force_kind: Some(ChallengeKind::JsPow {
                difficulty_bits: 24,
            }),
        });
        let (_, b) = t.decide(
            "search.com",
            "/q/expensive",
            "Mozilla",
            16,
            ChallengeKind::CookieRedirect,
        );
        assert_eq!(b, 24);
    }

    #[test]
    fn path_pattern_matches() {
        assert!(path_matches("/admin/*", "/admin/users"));
        assert!(path_matches("*/login", "/api/v1/login"));
        assert!(!path_matches("/admin", "/admin/x"));
    }
}
