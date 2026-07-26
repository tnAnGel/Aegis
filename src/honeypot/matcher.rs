//! Path-pattern matcher for honeypot decisions.
//!
//! Patterns mirror the existing rate-limit URI-budget syntax (`/foo`
//! exact, `/foo/*` prefix) plus a `*/foo` suffix form for the "match
//! at any depth" case (e.g. `*/.env` catches `/some/sub/.env`).
//!
//! A single matcher is built once per (host, snapshot) and shared
//! across requests via Arc. Lookup is O(prefixes + suffixes + exacts)
//! which scales fine to thousands of patterns — DashMap-of-exacts +
//! Vec scans for the wildcards keep the constant factors low.

use std::collections::HashSet;

#[derive(Debug)]
pub struct HoneypotMatcher {
    /// `O(1)` exact-path matches.
    exacts: HashSet<String>,
    /// `O(n)` prefix matches — pattern was `/foo/*`, stored as `/foo/`.
    prefixes: Vec<String>,
    /// `O(n)` suffix matches — pattern was `*/foo`, stored as `/foo`.
    suffixes: Vec<String>,
}

impl HoneypotMatcher {
    /// Build a matcher from an iterator of raw pattern strings.
    /// Strips query strings, normalises case-insensitivity by
    /// lowercasing — honeypot paths are matched case-blind because
    /// scanners frequently uppercase parts of their probes.
    ///
    /// V233 — pattern bodies are run through
    /// `crate::normalisation::canonical_path` so they are normalised the
    /// same way `matches` normalises the request path (percent-decoded,
    /// dot-segments collapsed, lower-cased). The wildcard sigils
    /// (`*/`, `/*`, trailing `*`) are stripped *before* canonicalisation
    /// so the markers themselves are never folded away.
    ///
    /// V234 — **degenerate-pattern guard.** `canonical_path` strips the
    /// query string, so a query-only probe pattern like the legacy
    /// Drupal `/?q=admin` collapses to the bare root `/`. Storing that
    /// as an exact would tarpit *every* request to the site root — a
    /// catastrophic false positive that takes the whole domain down.
    /// Any pattern whose canonical body is the bare root (`/`) is
    /// therefore dropped here: a honeypot must never match `/`, `*` or
    /// `/*`, because the root is always a legitimate path. This guard
    /// is the load-bearing one — it also neutralises any operator-
    /// supplied `custom_paths` entry that would otherwise collapse to
    /// the root.
    pub fn from_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut exacts = HashSet::new();
        let mut prefixes = Vec::new();
        let mut suffixes = Vec::new();
        for p in patterns {
            let raw = p.as_ref().trim();
            if raw.is_empty() {
                continue;
            }
            if let Some(rest) = raw.strip_prefix("*/") {
                // `*/foo` → suffix `/foo`. Canonicalise `/{rest}` so an
                // encoded body matches; keep the slashed form. A suffix
                // that collapsed to the bare `/` would match every
                // directory-style request — drop it.
                let suffix = crate::normalisation::canonical_path(&format!("/{rest}"));
                if suffix != "/" {
                    suffixes.push(suffix);
                }
            } else if let Some(prefix) = raw.strip_suffix("/*") {
                // `/foo/*` → prefix `/foo/`. A body that collapsed to
                // `/` would yield prefix `//`, which matches the root —
                // drop it.
                let body = crate::normalisation::canonical_path(prefix);
                if body != "/" {
                    prefixes.push(format!("{body}/"));
                }
            } else if let Some(prefix) = raw.strip_suffix('*') {
                // `/foo*` bare-star prefix. Canonicalising the body
                // here can be lossy if the star sits mid-segment, but
                // `canonical_path` only collapses `/`-delimited
                // structure, so a trailing partial segment is left
                // intact. A body that collapsed to `/` would match
                // every path — drop it.
                let body = crate::normalisation::canonical_path(prefix);
                if body != "/" {
                    prefixes.push(body);
                }
            } else {
                // Exact pattern. `canonical_path` strips the query, so
                // a query-only probe (`/?q=admin`) collapses to `/`;
                // never store a root-matching exact.
                let exact = crate::normalisation::canonical_path(raw);
                if exact != "/" {
                    exacts.insert(exact);
                }
            }
        }
        Self {
            exacts,
            prefixes,
            suffixes,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.exacts.is_empty() && self.prefixes.is_empty() && self.suffixes.is_empty()
    }

    /// True iff `path` matches any registered pattern. Matches are
    /// case-insensitive.
    ///
    /// V233 — the input path is canonicalised via
    /// `crate::normalisation::canonical_path` before matching: it is
    /// percent-decoded, has its `.`/`..` dot-segments and repeated
    /// slashes collapsed, and is lower-cased (which also strips the
    /// query string). Previously `matches` only stripped the query and
    /// lower-cased, so `/%61dmin/x.php` (`%61`=`a`) slipped past a
    /// `/admin/*` honeypot rule while the upstream still served
    /// `/admin/x.php`. Pattern bodies are canonicalised the same way in
    /// `from_patterns`, so both sides agree. `canonical_path` is
    /// panic-free on any input.
    pub fn matches(&self, path: &str) -> bool {
        let bare = crate::normalisation::canonical_path(path);
        if self.exacts.contains(&bare) {
            return true;
        }
        // V233 — `canonical_path` collapses a trailing `/`, so a bare
        // directory request `/wp-admin/` canonicalises to `/wp-admin`.
        // A `/wp-admin/*` pattern (stored as prefix `/wp-admin/`) must
        // still match that directory request, so each prefix matches
        // either by `starts_with` OR by the path equalling the prefix
        // with its trailing slash trimmed.
        if self
            .prefixes
            .iter()
            .any(|p| bare.starts_with(p) || p.strip_suffix('/') == Some(bare.as_str()))
        {
            return true;
        }
        if self.suffixes.iter().any(|s| bare.ends_with(s)) {
            return true;
        }
        false
    }

    /// Diagnostic counts for the admin UI.
    pub fn stats(&self) -> (usize, usize, usize) {
        (self.exacts.len(), self.prefixes.len(), self.suffixes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_path_hits() {
        let m = HoneypotMatcher::from_patterns(["/wp-login.php"]);
        assert!(m.matches("/wp-login.php"));
        assert!(!m.matches("/wp-login.phpx"));
    }

    #[test]
    fn prefix_match() {
        let m = HoneypotMatcher::from_patterns(["/wp-admin/*"]);
        assert!(m.matches("/wp-admin/"));
        assert!(m.matches("/wp-admin/index.php"));
        assert!(m.matches("/wp-admin/network/site-info.php"));
        // V233 — `canonical_path` collapses the trailing slash, so
        // `/wp-admin/` and `/wp-admin` canonicalise to the same string;
        // a `/wp-admin/*` prefix now also catches the bare directory
        // path. This matches `DomainPolicy`'s `/foo/*` semantics (which
        // already match `/foo`) and is the more secure behaviour — a
        // scanner probing the bare `/wp-admin` should still be caught.
        assert!(m.matches("/wp-admin"));
        // A sibling path that merely shares the prefix as a substring
        // is still not a match.
        assert!(!m.matches("/wp-administrator"));
    }

    #[test]
    fn suffix_match() {
        let m = HoneypotMatcher::from_patterns(["*/.env"]);
        assert!(m.matches("/.env"));
        assert!(m.matches("/api/.env"));
        assert!(m.matches("/foo/bar/.env"));
        assert!(!m.matches("/.env.local"));
    }

    #[test]
    fn case_insensitive() {
        let m = HoneypotMatcher::from_patterns(["/WP-Admin/*"]);
        assert!(m.matches("/wp-admin/x.php"));
        assert!(m.matches("/WP-ADMIN/x.php"));
    }

    #[test]
    fn query_string_stripped() {
        let m = HoneypotMatcher::from_patterns(["/admin"]);
        assert!(m.matches("/admin?foo=bar"));
    }

    #[test]
    fn empty_matcher_matches_nothing() {
        let m = HoneypotMatcher::from_patterns(Vec::<&str>::new());
        assert!(m.is_empty());
        assert!(!m.matches("/wp-admin/"));
    }

    #[test]
    fn stats_reports_counts() {
        let m = HoneypotMatcher::from_patterns(["/a", "/b/*", "*/c"]);
        assert_eq!(m.stats(), (1, 1, 1));
    }

    // ── V233 — canonical-path matching (honeypot bypass fix) ─────────

    #[test]
    fn percent_encoded_path_still_hits_honeypot() {
        // `/%61dmin/x.php` (`%61`=`a`) must hit a `/admin/*` rule —
        // the upstream serves the decoded path.
        let m = HoneypotMatcher::from_patterns(["/admin/*"]);
        assert!(m.matches("/%61dmin/x.php"));
        assert!(m.matches("/%61dmin"));
    }

    #[test]
    fn dot_segments_collapsed_before_match() {
        // `*/.env` suffix must catch a dot-segmented / encoded probe.
        let m = HoneypotMatcher::from_patterns(["*/.env"]);
        assert!(m.matches("/app/../config/.env"));
        assert!(m.matches("/app/%2e%2e/config/%2eenv"));
    }

    #[test]
    fn encoded_exact_path_hits() {
        let m = HoneypotMatcher::from_patterns(["/wp-login.php"]);
        // `%2d`=`-`, `%2e`=`.` — encoded exact path.
        assert!(m.matches("/wp%2dlogin%2ephp"));
    }

    #[test]
    fn double_encoded_path_hits() {
        // `%2561` → `%61` → `a` within the canonicaliser pass budget.
        let m = HoneypotMatcher::from_patterns(["/admin"]);
        assert!(m.matches("/%2561dmin"));
    }

    #[test]
    fn repeated_slashes_collapsed() {
        let m = HoneypotMatcher::from_patterns(["/wp-admin/*"]);
        assert!(m.matches("/wp-admin//index.php"));
        assert!(m.matches("//wp-admin/index.php"));
    }

    #[test]
    fn no_panic_on_malformed_path() {
        let m = HoneypotMatcher::from_patterns(["/admin/*", "*/.env"]);
        for path in ["/%", "/admin/%zz", "/%c0%ae", "", "/../../..", "/%00"] {
            let _ = m.matches(path); // must not panic
        }
    }

    #[test]
    fn encoded_pattern_body_matches_plain_path() {
        // Operator-supplied pattern with an encoded body is
        // canonicalised at build time, so a plain request still hits.
        let m = HoneypotMatcher::from_patterns(["/%61dmin/*"]);
        assert!(m.matches("/admin/users"));
    }

    // ── V234 — degenerate-pattern guard (root-path tarpit fix) ───────

    #[test]
    fn query_only_pattern_never_matches_root() {
        // The legacy Drupal `/?q=admin` probe: `canonical_path` strips
        // the query string, collapsing the pattern to the bare root
        // `/`. Such a pattern MUST be dropped — otherwise every request
        // to the site root is tarpitted (the V234 hang regression).
        let m = HoneypotMatcher::from_patterns(["/?q=admin", "/?q=user/register"]);
        assert!(
            m.is_empty(),
            "query-only patterns must be dropped, not stored"
        );
        assert!(!m.matches("/"));
        assert!(!m.matches("/?q=admin"));
        assert!(!m.matches("/anything"));
    }

    #[test]
    fn degenerate_patterns_never_match_root() {
        // Every shape that could collapse to the root must be dropped:
        // bare `/`, dot-segments, `/*`, `*`, `*/`, and friends. None of
        // them may cause `/` (or any legitimate path) to be tarpitted.
        for pat in [
            "/", "/.", "/..", "/*", "*", "*/", "*/.", "*/..", "/./*", "/../*", "/?x=1", "?foo",
            "/#frag",
        ] {
            let m = HoneypotMatcher::from_patterns([pat]);
            assert!(
                !m.matches("/"),
                "pattern {pat:?} must not tarpit the site root",
            );
            assert!(
                !m.matches("/index.html"),
                "pattern {pat:?} must not tarpit a legitimate page",
            );
        }
    }

    #[test]
    fn real_patterns_still_match_after_guard() {
        // The guard must only drop degenerate patterns — genuine
        // honeypot paths still compile and match.
        let m = HoneypotMatcher::from_patterns(["/wp-login.php", "/wp-admin/*", "*/.env"]);
        assert!(m.matches("/wp-login.php"));
        assert!(m.matches("/wp-admin/x.php"));
        assert!(m.matches("/sub/.env"));
        assert!(!m.matches("/"));
    }
}
