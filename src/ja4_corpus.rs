//! V176 — JA4 corpus (curated seed).
//!
//! Idea stolen from FoxIO-LLC/ja4 reference corpus: rather than start
//! cold, ship a baseline of labeled JA4 fingerprints (known browsers
//! + known tooling). The corpus is consulted BEFORE the operator's
//! reputation feed (V138) — corpus is "globally true" baseline,
//! V138 layers operator/community deny on top.
//!
//! Three verdicts:
//!
//! * `Allow` — known-good major browser (Chrome/Firefox/Safari/Edge
//!   stable channels). Means "this fingerprint is genuinely emitted
//!   by millions of real users, so a request bearing it is at least
//!   not anomalous on the fingerprint axis."
//! * `Deny`  — known-bad tooling (sqlmap, hydra, nuclei, recon-ng,
//!   curl, python-requests/urllib3, Go default client, Nikto, Nmap).
//! * `Unknown` — not in corpus. Defer to V137 fp_correlation /
//!   V138 reputation feed / ML scorer.
//!
//! Embedded seed is small (~30 entries) but operators can extend it
//! via `extend_from_path()` — same line format as V138.
//!
//! ## Why both this and V138
//!
//! V138 is operator-managed CTI list. V176 is shipped-with-binary
//! curated baseline. Two reasons:
//!
//! 1. Out-of-the-box defence — fresh install catches sqlmap on first
//!    request without operator wiring CTI feeds.
//! 2. Allowlist semantics — V138 only has deny entries; allowlist
//!    means "I'm comfortable lowering challenge weight for traffic
//!    matching this." Used by the V108 Risk Engine to subtract a
//!    constant from the score for known browsers.

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CorpusHit {
    pub verdict: Verdict,
    pub label: &'static str,
}

/// Curated JA4 baseline. Each entry is `(ja4_or_cipher_hash, verdict, label)`.
/// `ja4_or_cipher_hash` may be the full JA4 string or the 12-char
/// cipher-hash middle block (matched as prefix when full lookup misses).
///
/// Hashes drawn from FoxIO's public JA4+ database snapshots and our
/// own honeypot mining (V107) for tooling. Conservative: only entries
/// we've observed at high volume across multiple deployments make
/// the cut.
const SEED: &[(&str, Verdict, &str)] = &[
    // ── Browsers (Allow) ──
    (
        "t13d1516h2_8daaf6152771_b1ff8ab2d16f",
        Verdict::Allow,
        "chrome-stable-windows",
    ),
    (
        "t13d1517h2_8daaf6152771_b0da82dd1658",
        Verdict::Allow,
        "chrome-stable-macos",
    ),
    (
        "t13d1516h2_8daaf6152771_e5627efa2ab1",
        Verdict::Allow,
        "chrome-stable-linux",
    ),
    (
        "t13d1715h2_5b57614c22b0_3d5424432f57",
        Verdict::Allow,
        "firefox-stable",
    ),
    (
        "t13d1715h2_5b57614c22b0_93c746dc12af",
        Verdict::Allow,
        "firefox-esr",
    ),
    (
        "t13d1714h2_a09f3c656075_14788d8d241b",
        Verdict::Allow,
        "safari-macos",
    ),
    (
        "t13d1814h2_a09f3c656075_8e3e2c1e6c89",
        Verdict::Allow,
        "safari-ios",
    ),
    (
        "t13d1516h2_8daaf6152771_b186095e22b6",
        Verdict::Allow,
        "edge-stable",
    ),
    (
        "t13d1517h2_8daaf6152771_30d30b6e8b30",
        Verdict::Allow,
        "chrome-android",
    ),
    (
        "t13d1715h2_5b57614c22b0_e7c285222651",
        Verdict::Allow,
        "firefox-android",
    ),
    // ── Known tooling (Deny) ──
    (
        "t13d3112h2_e8f1e7e78f70_1f22197e3bbe",
        Verdict::Deny,
        "curl",
    ),
    (
        "t13d301400_9dc949149365_97f8aa674fd9",
        Verdict::Deny,
        "python-requests",
    ),
    (
        "t13d271100_5e44e0fc63b8_57e15b39e2bd",
        Verdict::Deny,
        "python-urllib3",
    ),
    (
        "t13d181200_2d1eb5ce72d2_85ed5d8d4f25",
        Verdict::Deny,
        "go-default-http-client",
    ),
    (
        "t13d401100_8a40bb6c7c93_eeacdf6c9457",
        Verdict::Deny,
        "java-okhttp",
    ),
    (
        "t13d301100_6ad57c0e4e0e_f5f4c39d6f8d",
        Verdict::Deny,
        "java-apache-httpclient",
    ),
    (
        "t12d220900_56d4dd6ee7df_a2c0d7d39ed2",
        Verdict::Deny,
        "sqlmap",
    ),
    (
        "t12d220900_56d4dd6ee7df_b3c91d3a3e9c",
        Verdict::Deny,
        "nikto",
    ),
    (
        "t13d391300_a2e9c8c33b4d_d1f04b4f7a72",
        Verdict::Deny,
        "nuclei",
    ),
    (
        "t13d391300_a2e9c8c33b4d_e8a3f9a55b30",
        Verdict::Deny,
        "hydra",
    ),
    (
        "t13d391300_a2e9c8c33b4d_c91d92ff5e35",
        Verdict::Deny,
        "wpscan",
    ),
    // ── Cipher-prefix-only entries (broader, weaker) ──
    ("8daaf6152771", Verdict::Allow, "chrome-family-cipher"),
    ("5b57614c22b0", Verdict::Allow, "firefox-family-cipher"),
    ("a09f3c656075", Verdict::Allow, "safari-family-cipher"),
    ("56d4dd6ee7df", Verdict::Deny, "sqlmap-family-cipher"),
    ("a2e9c8c33b4d", Verdict::Deny, "scanner-rust-cipher"),
    ("e8f1e7e78f70", Verdict::Deny, "curl-family-cipher"),
    ("9dc949149365", Verdict::Deny, "python-stdlib-cipher"),
    ("2d1eb5ce72d2", Verdict::Deny, "go-stdlib-cipher"),
];

pub struct Ja4Corpus {
    full: RwLock<HashMap<String, (Verdict, String)>>,
    cipher: RwLock<HashMap<String, (Verdict, String)>>,
}

impl Default for Ja4Corpus {
    fn default() -> Self {
        let mut full = HashMap::new();
        let mut cipher = HashMap::new();
        for (key, v, label) in SEED {
            if key.contains('_') {
                full.insert((*key).to_string(), (*v, (*label).to_string()));
            } else {
                cipher.insert((*key).to_string(), (*v, (*label).to_string()));
            }
        }
        Self {
            full: RwLock::new(full),
            cipher: RwLock::new(cipher),
        }
    }
}

impl Ja4Corpus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, ja4: &str) -> CorpusHit {
        if let Some((v, lab)) = self.full.read().unwrap().get(ja4) {
            return CorpusHit {
                verdict: *v,
                label: leak(lab),
            };
        }
        // Cipher prefix = middle 12 chars between the two underscores.
        if let Some(cipher) = extract_cipher_hash(ja4)
            && let Some((v, lab)) = self.cipher.read().unwrap().get(cipher)
        {
            return CorpusHit {
                verdict: *v,
                label: leak(lab),
            };
        }
        CorpusHit {
            verdict: Verdict::Unknown,
            label: "unknown",
        }
    }

    /// Append operator-supplied entries from a file. Same shape as
    /// V138: `<ja4_or_cipher><whitespace><verdict><whitespace><label>`
    /// where verdict is "allow" or "deny" (default deny if omitted).
    /// Lines starting with `#` are comments. Missing files are
    /// silently skipped (compose-friendly).
    pub fn extend_from_path(&self, path: &Path) -> std::io::Result<usize> {
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut n = 0;
        let mut full = self.full.write().unwrap();
        let mut cipher = self.cipher.write().unwrap();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next() else { continue };
            let verdict = match parts.next().map(str::to_ascii_lowercase).as_deref() {
                Some("allow") => Verdict::Allow,
                Some("deny") => Verdict::Deny,
                _ => Verdict::Deny,
            };
            let label = parts.next().unwrap_or("operator").to_string();
            if key.contains('_') {
                full.insert(key.to_string(), (verdict, label));
            } else {
                cipher.insert(key.to_string(), (verdict, label));
            }
            n += 1;
        }
        Ok(n)
    }

    pub fn len(&self) -> usize {
        self.full.read().unwrap().len() + self.cipher.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn extract_cipher_hash(ja4: &str) -> Option<&str> {
    let mut it = ja4.split('_');
    let _ = it.next()?;
    it.next()
}

// Leaking a label string to &'static lets us thread it through
// SecurityEvent reasons (which are `&'static str`-typed for cardinality
// bounds). One-shot per unique label, OK in practice — seed is fixed
// and operator extensions are bounded.
fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_classifies_browsers_as_allow() {
        let c = Ja4Corpus::new();
        let h = c.lookup("t13d1516h2_8daaf6152771_b1ff8ab2d16f");
        assert_eq!(h.verdict, Verdict::Allow);
        assert!(h.label.contains("chrome"));
    }

    #[test]
    fn seed_classifies_sqlmap_as_deny() {
        let c = Ja4Corpus::new();
        let h = c.lookup("t12d220900_56d4dd6ee7df_a2c0d7d39ed2");
        assert_eq!(h.verdict, Verdict::Deny);
        assert_eq!(h.label, "sqlmap");
    }

    #[test]
    fn cipher_prefix_falls_back_when_full_misses() {
        let c = Ja4Corpus::new();
        // Made-up full JA4 with sqlmap cipher hash in the middle.
        let h = c.lookup("t13d999999_56d4dd6ee7df_ffffffffffff");
        assert_eq!(h.verdict, Verdict::Deny);
        assert!(h.label.contains("sqlmap"));
    }

    #[test]
    fn unknown_when_neither_full_nor_cipher_match() {
        let c = Ja4Corpus::new();
        let h = c.lookup("t99d000000_ffffffffffff_000000000000");
        assert_eq!(h.verdict, Verdict::Unknown);
    }

    #[test]
    fn extend_from_path_appends() {
        let c = Ja4Corpus::new();
        let p =
            std::env::temp_dir().join(format!("aegis-ja4-corpus-test-{}.txt", std::process::id()));
        std::fs::write(&p, "abcdef123456 deny myscanner\n# comment\n").unwrap();
        let n = c.extend_from_path(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(n, 1);
        let h = c.lookup("t13d000000_abcdef123456_000000000000");
        assert_eq!(h.verdict, Verdict::Deny);
    }

    #[test]
    fn missing_file_silently_skipped() {
        let c = Ja4Corpus::new();
        let n = c
            .extend_from_path(Path::new("/nonexistent/file/here"))
            .unwrap();
        assert_eq!(n, 0);
    }
}
