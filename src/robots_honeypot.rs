//! V149 — robots.txt honeypot auto-labeling.
//!
//! Aegis already has the V36 honeypot machinery, but operators need
//! to *author* honeypot paths. robots.txt is a free source of those:
//! every `Disallow:` line is a path the operator has publicly
//! declared off-limits to compliant crawlers. A client that visits
//! a Disallow'd path has self-selected as a non-compliant crawler —
//! exactly the population our ML model wants more labels for.
//!
//! V149 wires that signal into the V135 [MlTrainer] feedback loop:
//!
//! 1. Parse `robots.txt` (operator-supplied path; we don't generate
//!    one — that's the site's job).
//! 2. On each request, check whether the path matches any
//!    `Disallow:` pattern under `User-agent: *`.
//! 3. If yes, automatically push a `Label::Malicious` sample into
//!    the trainer. The next retrain learns the request shape.
//!
//! ## Optional refinement: "honoured robots.txt first?" check
//!
//! Some legitimate clients (RSS readers, link-preview bots) hit
//! `Disallow`'d paths *without* malice. To reduce false-positive
//! labels, [RobotsHoneypot::observe_request] takes an optional
//! `honoured_robots: bool` flag — when the operator wires per-IP
//! state tracking "did this IP fetch /robots.txt first?", only the
//! IPs that DIDN'T fetch it get labeled. Setting the flag to
//! `false` (the default if unwired) keeps the original behaviour:
//! every Disallow visit = label.
//!
//! ## Hot-path cost
//!
//! Matching is O(|patterns|) per request. Operators typically have
//! O(10²) Disallow lines, so the linear scan is fine at line rate.
//! For O(10³)+ patterns a prefix-trie would help — out of scope
//! here.

use std::sync::Arc;

use crate::ddos::ml_score_v2::{FeaturesV2, ascii_entropy};
use crate::ddos::ml_training::{Label, LabelledSample, MlTrainer, empty_features};

/// Parsed robots.txt rules. Only the `User-agent: *` (or unscoped)
/// `Disallow:` lines are captured — per-bot rules would need richer
/// matching logic that's not the point here.
#[derive(Debug, Default, Clone)]
pub struct RobotsRules {
    /// Disallow patterns. Each may end in `*` for prefix match;
    /// without `*`, plain prefix match (robots.txt convention).
    /// Empty string ("Disallow:") means "nothing disallowed" — we
    /// drop it on parse.
    pub disallow: Vec<String>,
    /// Allow patterns that override Disallow (robots.txt allows
    /// nested permits). Same prefix-match semantics as Disallow.
    pub allow: Vec<String>,
}

impl RobotsRules {
    /// Parse a robots.txt text body. Only the rules under
    /// `User-agent: *` are loaded; per-bot stanzas are ignored.
    pub fn parse(contents: &str) -> Self {
        let mut rules = RobotsRules::default();
        let mut in_wildcard_stanza = false;
        for raw in contents.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = match line.split_once(':') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
                None => continue,
            };
            match key.as_str() {
                "user-agent" => {
                    in_wildcard_stanza = value == "*";
                }
                "disallow" if in_wildcard_stanza => {
                    if !value.is_empty() {
                        rules.disallow.push(value.to_string());
                    }
                }
                "allow" if in_wildcard_stanza && !value.is_empty() => {
                    rules.allow.push(value.to_string());
                }
                _ => {}
            }
        }
        rules
    }

    /// Does the path match any Disallow pattern (and not an
    /// overriding Allow)?
    pub fn is_disallowed(&self, path: &str) -> bool {
        if !self.disallow.iter().any(|p| matches_pattern(path, p)) {
            return false;
        }
        // Allow overrides Disallow — robots.txt convention.
        !self.allow.iter().any(|p| matches_pattern(path, p))
    }

    /// Total rule count (Disallow + Allow). Useful for /metrics.
    pub fn len(&self) -> usize {
        self.disallow.len() + self.allow.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Match a request path against a robots.txt pattern. `*` is a
/// wildcard (any chars); without `*`, plain prefix match.
fn matches_pattern(path: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        glob_match(path, pattern)
    } else {
        path.starts_with(pattern)
    }
}

/// Tiny glob matcher: `*` matches any sequence including empty.
/// Implementation is the canonical two-pointer pattern with
/// star-backtrack. O(|path| * |stars|) worst case; in practice the
/// patterns are short.
fn glob_match(path: &str, pattern: &str) -> bool {
    let p = path.as_bytes();
    let pat = pattern.as_bytes();
    let mut i = 0usize;
    let mut j = 0usize;
    let mut star: Option<usize> = None;
    let mut match_i = 0usize;
    while i < p.len() {
        if j < pat.len() && pat[j] == b'*' {
            star = Some(j);
            match_i = i;
            j += 1;
        } else if j < pat.len() && pat[j] == p[i] {
            i += 1;
            j += 1;
        } else if let Some(s) = star {
            j = s + 1;
            match_i += 1;
            i = match_i;
        } else {
            return false;
        }
    }
    while j < pat.len() && pat[j] == b'*' {
        j += 1;
    }
    j == pat.len()
}

/// Honeypot wrapper. Holds the parsed rules and a reference to the
/// trainer it labels into.
pub struct RobotsHoneypot {
    pub rules: RobotsRules,
    pub trainer: Arc<MlTrainer>,
}

impl RobotsHoneypot {
    pub fn new(rules: RobotsRules, trainer: Arc<MlTrainer>) -> Self {
        Self { rules, trainer }
    }

    /// Observe a request. When `path` matches a Disallow pattern
    /// AND the client did NOT honour robots.txt first, push a
    /// Malicious sample into the trainer. Returns true if a label
    /// was emitted.
    pub fn observe_request(&self, path: &str, honoured_robots: bool) -> bool {
        if honoured_robots {
            return false;
        }
        if !self.rules.is_disallowed(path) {
            return false;
        }
        self.trainer.add_sample(LabelledSample {
            features: synthesise_features(path),
            label: Label::Malicious,
        });
        true
    }
}

/// Build a [FeaturesV2] vector that captures the *category* of a
/// robots-violating crawler request: long URI hint, high entropy
/// (scanning paths look random), no browser headers, no fingerprint.
/// We don't have the full request context in this hook — caller
/// gets the path only — so we keep the synthesised vector
/// intentionally generic.
fn synthesise_features(path: &str) -> FeaturesV2 {
    let mut f = empty_features();
    f.uri_length = (path.len() as f32 / 8192.0).min(1.0);
    f.uri_entropy = ascii_entropy(path);
    // High prior on attacker shape: missing browser headers, no
    // JA4, mildly elevated fingerprint-inconsistency baseline.
    f.has_user_agent = 0.0;
    f.has_accept_language = 0.0;
    f.has_accept_encoding = 0.0;
    f.ja4_present = 0.0;
    f.fp_consistency_score = 0.3;
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_robots() -> &'static str {
        "# Header comment\n\
         User-agent: *\n\
         Disallow: /admin/\n\
         Disallow: /private/\n\
         Disallow: /*.log\n\
         Allow: /admin/public/\n\
         \n\
         User-agent: Googlebot\n\
         Disallow: /no-google/\n\
         "
    }

    #[test]
    fn parser_loads_wildcard_stanza_only() {
        let r = RobotsRules::parse(sample_robots());
        // /admin/, /private/, /*.log
        assert_eq!(r.disallow.len(), 3);
        assert_eq!(r.allow.len(), 1);
        // /no-google/ from Googlebot stanza is NOT picked up.
        assert!(!r.disallow.iter().any(|p| p == "/no-google/"));
    }

    #[test]
    fn parser_strips_inline_comments() {
        let r = RobotsRules::parse("User-agent: *\nDisallow: /secret/  # private\n");
        assert_eq!(r.disallow, vec!["/secret/".to_string()]);
    }

    #[test]
    fn parser_skips_empty_disallow() {
        // "Disallow:" with no value = nothing disallowed → must NOT be indexed.
        let r = RobotsRules::parse("User-agent: *\nDisallow:\n");
        assert!(r.disallow.is_empty());
    }

    #[test]
    fn prefix_match_works_for_simple_disallow() {
        let r = RobotsRules::parse("User-agent: *\nDisallow: /admin/\n");
        assert!(r.is_disallowed("/admin/users"));
        assert!(r.is_disallowed("/admin/"));
        assert!(!r.is_disallowed("/public/"));
    }

    #[test]
    fn allow_overrides_disallow() {
        let r = RobotsRules::parse(sample_robots());
        // /admin/ is disallowed but /admin/public/ is allowed.
        assert!(r.is_disallowed("/admin/users"));
        assert!(!r.is_disallowed("/admin/public/index.html"));
    }

    #[test]
    fn wildcard_match_with_star() {
        let r = RobotsRules::parse("User-agent: *\nDisallow: /*.log\n");
        assert!(r.is_disallowed("/error.log"));
        assert!(r.is_disallowed("/path/to/access.log"));
        assert!(!r.is_disallowed("/error.txt"));
    }

    #[test]
    fn glob_handles_multiple_stars() {
        assert!(glob_match("/a/b/c.log", "/*/*.log"));
        assert!(glob_match("/anything.log", "/*.log"));
        assert!(!glob_match("/anything.txt", "/*.log"));
    }

    #[test]
    fn glob_handles_trailing_star() {
        assert!(glob_match("/foo/anything", "/foo/*"));
        assert!(glob_match("/foo/", "/foo/*"));
    }

    #[test]
    fn glob_empty_pattern_matches_empty_path() {
        assert!(glob_match("", ""));
        assert!(!glob_match("x", ""));
    }

    #[test]
    fn honeypot_labels_disallowed_path_as_malicious() {
        use crate::ddos::ml_score_v2::MlScorerV2;
        use std::sync::Arc;
        let trainer = Arc::new(MlTrainer::new(Arc::new(MlScorerV2::new(true))));
        let rules = RobotsRules::parse("User-agent: *\nDisallow: /admin/\n");
        let hp = RobotsHoneypot::new(rules, trainer.clone());
        assert!(hp.observe_request("/admin/secret", false));
        assert_eq!(trainer.sample_count(), 1);
    }

    #[test]
    fn honeypot_skips_allowed_path() {
        use crate::ddos::ml_score_v2::MlScorerV2;
        use std::sync::Arc;
        let trainer = Arc::new(MlTrainer::new(Arc::new(MlScorerV2::new(true))));
        let hp = RobotsHoneypot::new(
            RobotsRules::parse("User-agent: *\nDisallow: /admin/\n"),
            trainer.clone(),
        );
        assert!(!hp.observe_request("/public/", false));
        assert_eq!(trainer.sample_count(), 0);
    }

    #[test]
    fn honeypot_skips_when_client_honoured_robots() {
        use crate::ddos::ml_score_v2::MlScorerV2;
        use std::sync::Arc;
        let trainer = Arc::new(MlTrainer::new(Arc::new(MlScorerV2::new(true))));
        let hp = RobotsHoneypot::new(
            RobotsRules::parse("User-agent: *\nDisallow: /admin/\n"),
            trainer.clone(),
        );
        // honoured_robots=true → no label even though path is disallowed.
        assert!(!hp.observe_request("/admin/secret", true));
        assert_eq!(trainer.sample_count(), 0);
    }

    #[test]
    fn synthesise_features_marks_attacker_shape() {
        let f = synthesise_features("/admin/aXz4qPj8K7nMz2Lw");
        assert_eq!(f.has_user_agent, 0.0);
        assert_eq!(f.ja4_present, 0.0);
        assert!(f.uri_entropy > 0.0);
        assert!(f.fp_consistency_score > 0.0);
    }

    #[test]
    fn rules_len_counts_both_directions() {
        let r = RobotsRules::parse(sample_robots());
        assert_eq!(r.len(), 4); // 3 disallow + 1 allow
        assert!(!r.is_empty());
    }

    #[test]
    fn empty_robots_text_yields_empty_rules() {
        let r = RobotsRules::parse("");
        assert!(r.is_empty());
    }
}
