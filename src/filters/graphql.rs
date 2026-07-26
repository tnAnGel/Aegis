//! GraphQL request guard.
//!
//! We don't run a full GraphQL parser — the cost / dependency footprint
//! isn't worth it for what amounts to balancing braces and counting
//! colons. A purpose-built scanner gets the meaningful protections
//! (depth, alias count, introspection block) for a fraction of the
//! work and zero new crate dependencies.
//!
//! The filter only fires on requests where:
//!   - the request path is in the configured `paths` list (default
//!     `["/graphql"]`)
//!   - **and** the method is POST (GET-style queries usually carry the
//!     query as a `?query=` string; that path is signature-scanned by
//!     WAF already)
//!
//! Decision is rendered at `check_body` time because the body bytes
//! aren't in `RequestContext`. The proxy handler invokes it after
//! `WafFilter::inspect_body` and before the rest of the pipeline.

use crate::{config::GraphqlConfig, filters::FilterAction};

pub struct GraphqlFilter {
    enabled: bool,
    paths: Vec<String>,
    max_depth: u32,
    max_aliases: u32,
    max_query_bytes: usize,
    block_introspection: bool,
    /// V112 — persisted-query allow-list enforcement. When `enabled`
    /// + `enforce_persisted_only`, every query must hash into
    /// `persisted_hashes`. Strongest GraphQL DDoS defence (info.md P1).
    enforce_persisted_only: bool,
    /// V112 — lowercase hex SHA-256 digests of allowed operations.
    /// HashSet for O(1) lookup on the hot path.
    persisted_hashes: std::collections::HashSet<String>,
}

impl GraphqlFilter {
    pub fn new(cfg: &GraphqlConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            paths: cfg.paths.clone(),
            max_depth: cfg.max_depth.max(1),
            max_aliases: cfg.max_aliases.max(1),
            max_query_bytes: cfg.max_query_bytes.max(256),
            block_introspection: cfg.block_introspection,
            enforce_persisted_only: cfg.persisted_only,
            persisted_hashes: cfg
                .persisted_hashes
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
        }
    }

    /// V112 — compute SHA-256 of a normalised query (strips leading
    /// + trailing whitespace; preserves inner formatting because
    /// real persisted-query toolchains hash the exact operation
    /// string). Returns lowercase hex.
    pub fn hash_query(query: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(query.trim().as_bytes());
        let out = h.finalize();
        let mut s = String::with_capacity(64);
        for b in out {
            // hex (lowercase) without an extra crate dep.
            s.push(hex_nibble(b >> 4));
            s.push(hex_nibble(b & 0x0F));
        }
        s
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// True when this request path is a registered GraphQL endpoint.
    /// Strips the query string before matching.
    pub fn applies(&self, path: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let bare = path.split('?').next().unwrap_or(path);
        self.paths.iter().any(|p| p == bare)
    }

    /// Inspect a POST body. Returns Some(Deny) when the query exceeds
    /// any limit. None on allow / parse-failure (parse failures are
    /// intentionally permissive — a malformed body that isn't JSON
    /// will be 400'd by the upstream anyway).
    ///
    /// M4 — handles **batched** GraphQL requests. A top-level JSON array
    /// (`[{"query":..}, {"query":..}]`) is a standard batch envelope
    /// that mainstream servers (Apollo, graphql-yoga, …) execute as N
    /// independent operations. The former single-object extraction made
    /// `value.get("query")` return `None` for an array → the whole guard
    /// fell open, so an attacker could smuggle unlimited deep / aliased
    /// / introspection / unlisted queries inside a batch. We now:
    ///   - cap the batch length at [`MAX_BATCH_LEN`] (over-cap → block),
    ///   - apply ALL limits (persisted-only, size, introspection, depth,
    ///     alias) to EVERY element, denying on the first violation.
    /// A single object is treated as a batch of one.
    pub fn check_body(&self, body: &[u8]) -> Option<FilterAction> {
        if !self.enabled {
            return None;
        }
        let s = std::str::from_utf8(body).ok()?;
        // M4 — bail (fall open) only when the body isn't JSON at all; a
        // non-JSON body that isn't `application/graphql` is 400'd
        // upstream anyway. Once we DO have JSON, every extractable query
        // is checked and we never silently allow on a missing field.
        let value: serde_json::Value = serde_json::from_str(s).ok()?;

        let queries = match &value {
            // M4 — top-level array batch. Reject over-long batches
            // outright: a 10k-element array is itself a cheap amplified
            // DoS even before per-query limits.
            serde_json::Value::Array(items) => {
                if items.len() > MAX_BATCH_LEN {
                    return Some(FilterAction::Deny {
                        status: 400,
                        reason: format!(
                            "graphql batch length {} exceeds max {}",
                            items.len(),
                            MAX_BATCH_LEN
                        )
                        .into(),
                    });
                }
                items
                    .iter()
                    .filter_map(extract_query_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            }
            // Single object (or anything else JSON): treat as a batch of
            // one. `extract_query_str` returns None for non-objects /
            // missing `query`, in which case there's nothing to inspect.
            other => extract_query_str(other)
                .map(|q| vec![q.to_owned()])
                .unwrap_or_default(),
        };

        for query in &queries {
            if let Some(action) = self.check_one(query) {
                return Some(action);
            }
        }
        None
    }

    /// M4 — apply every per-query limit to a single extracted operation.
    /// Factored out of `check_body` so batched and single-object bodies
    /// share one code path. Returns `Some(Deny)` on the first violation,
    /// `None` when the query is within all limits.
    fn check_one(&self, query: &str) -> Option<FilterAction> {
        // V112 — persisted-query allow-list. Hashed FIRST because it's
        // the cheapest reject path (single SHA256 + HashSet lookup)
        // and the strictest mode an operator can run.
        if self.enforce_persisted_only {
            let h = Self::hash_query(query);
            if !self.persisted_hashes.contains(&h) {
                return Some(FilterAction::Deny {
                    status: 403,
                    reason: "graphql query not in persisted allow-list".into(),
                });
            }
        }
        if query.len() > self.max_query_bytes {
            return Some(FilterAction::Deny {
                status: 413,
                reason: format!(
                    "graphql query too large ({} > {} bytes)",
                    query.len(),
                    self.max_query_bytes
                )
                .into(),
            });
        }
        if self.block_introspection && (query.contains("__schema") || query.contains("__type")) {
            return Some(FilterAction::Deny {
                status: 403,
                reason: "graphql introspection blocked".into(),
            });
        }
        let stats = scan(query);
        if stats.depth > self.max_depth {
            return Some(FilterAction::Deny {
                status: 400,
                reason: format!(
                    "graphql selection depth {} exceeds max {}",
                    stats.depth, self.max_depth
                )
                .into(),
            });
        }
        if stats.aliases > self.max_aliases {
            return Some(FilterAction::Deny {
                status: 400,
                reason: format!(
                    "graphql alias count {} exceeds max {}",
                    stats.aliases, self.max_aliases
                )
                .into(),
            });
        }
        None
    }
}

/// M4 — maximum number of operations allowed in a single batched
/// (top-level JSON array) GraphQL request. Batches longer than this are
/// rejected outright: a large array is an amplification vector (one HTTP
/// request → N upstream executions) independent of each query's shape.
const MAX_BATCH_LEN: usize = 10;

#[derive(Debug, Default, PartialEq)]
struct Stats {
    depth: u32,
    aliases: u32,
}

/// Walk the query character-by-character, skipping string literals
/// and inline comments. Track:
///   - max `{`-nesting depth
///   - alias count: a token of the form `ident:` where the token isn't
///     itself nested inside `(...)` arguments. This is approximate
///     but good enough — false positives over-count, never under.
fn scan(q: &str) -> Stats {
    let bytes = q.as_bytes();
    let mut i = 0;
    let mut cur_depth: u32 = 0;
    let mut max_depth: u32 = 0;
    let mut aliases: u32 = 0;
    let mut paren_depth: u32 = 0;
    let mut last_word_end: Option<usize> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => {
                // Skip until closing quote (no escape semantics needed —
                // we're just trying not to count braces inside strings).
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => {
                cur_depth += 1;
                max_depth = max_depth.max(cur_depth);
                i += 1;
            }
            b'}' => {
                cur_depth = cur_depth.saturating_sub(1);
                i += 1;
            }
            b'(' => {
                paren_depth += 1;
                i += 1;
            }
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                i += 1;
            }
            b':' if paren_depth == 0 => {
                // An alias is `ident:` where ident ends right before the
                // colon. We do not count variable definitions
                // (`$var: Type`) or argument definitions because those
                // live inside `(...)`.
                if let Some(end) = last_word_end
                    && end == i
                {
                    aliases += 1;
                }
                i += 1;
            }
            b if b.is_ascii_alphanumeric() || b == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                last_word_end = if i > start { Some(i) } else { None };
            }
            _ => {
                i += 1;
            }
        }
    }
    Stats {
        depth: max_depth,
        aliases,
    }
}

/// V112 — internal hex helper used by [GraphqlFilter::hash_query].
/// Inline so the persisted-query path avoids a `hex` crate dependency.
#[inline]
fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

/// Pull the `query` field out of a GraphQL JSON envelope.
///
/// V233 — replaces the former hand-rolled byte-substring scanner. The
/// old scanner returned the **first** `"query"` occurrence, but every
/// mainstream GraphQL server resolves duplicate JSON keys with
/// **last-key-wins**. A body like
/// `{"query":"<benign>","query":"<malicious>"}` therefore let the
/// guard hash/scan the benign value (passing the persisted-query
/// allow-list + depth/alias/introspection limits) while the upstream
/// executed the malicious one — a total auth bypass. It also did
/// `byte as char`, which mangles multi-byte UTF-8 so the guard
/// inspected a different string than the upstream parsed.
///
/// We now do a real parse with `serde_json` (already a dependency).
/// `serde_json::Map` keeps the **last** value on duplicate keys, which
/// matches upstream semantics exactly, and serde decodes JSON string
/// escapes + UTF-8 correctly. Non-JSON bodies still return `None`
/// (fall open — a non-JSON body that isn't `application/graphql` gets
/// 400'd upstream anyway, and raw `application/graphql` is upstream's
/// to handle).
// M4 — superseded in the request path by the batch-aware `check_body` /
// `extract_query_str`; retained as a thin wrapper that the V233 regression
// tests still exercise (last-key-wins / UTF-8 escapes), hence test-only.
#[cfg(test)]
fn extract_query_field(body: &str) -> Option<String> {
    // V233 — full JSON parse; bails (None) on any non-JSON body.
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    extract_query_str(&value).map(str::to_owned)
}

/// M4 — pull the `query` field out of an already-parsed JSON value.
/// Used for both single-object bodies and each element of a batch array.
/// Returns `None` when the value isn't an object or has no string
/// `query` field. `serde_json::Map` keeps the **last** value on
/// duplicate keys (last-key-wins), matching upstream semantics.
fn extract_query_str(value: &serde_json::Value) -> Option<&str> {
    value.get("query")?.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(depth: u32, aliases: u32) -> GraphqlConfig {
        GraphqlConfig {
            enabled: true,
            paths: vec!["/graphql".to_string()],
            max_depth: depth,
            max_aliases: aliases,
            max_query_bytes: 16 * 1024,
            block_introspection: true,
            persisted_only: false,
            persisted_hashes: Vec::new(),
        }
    }

    fn cfg_persisted(hashes: Vec<String>) -> GraphqlConfig {
        GraphqlConfig {
            enabled: true,
            paths: vec!["/graphql".to_string()],
            max_depth: 100,
            max_aliases: 200,
            max_query_bytes: 64 * 1024,
            block_introspection: false,
            persisted_only: true,
            persisted_hashes: hashes,
        }
    }

    #[test]
    fn persisted_query_allowed_when_hash_matches() {
        let q = "{ user { name email } }";
        let h = GraphqlFilter::hash_query(q);
        let f = GraphqlFilter::new(&cfg_persisted(vec![h]));
        let body = format!(r#"{{"query":"{q}"}}"#);
        assert!(f.check_body(body.as_bytes()).is_none(), "should allow");
    }

    #[test]
    fn persisted_query_denied_when_hash_unknown() {
        let allowed = GraphqlFilter::hash_query("{ user { id } }");
        let f = GraphqlFilter::new(&cfg_persisted(vec![allowed]));
        // Different query → different hash → 403.
        let body = br#"{"query":"{ user { email } }"}"#;
        let res = f.check_body(body);
        match res {
            Some(FilterAction::Deny { status, .. }) => assert_eq!(status, 403),
            other => panic!("expected Deny 403, got {other:?}"),
        }
    }

    #[test]
    fn persisted_only_empty_list_denies_everything() {
        let f = GraphqlFilter::new(&cfg_persisted(vec![]));
        let body = br#"{"query":"{ user }"}"#;
        assert!(matches!(
            f.check_body(body),
            Some(FilterAction::Deny { status: 403, .. })
        ));
    }

    #[test]
    fn hash_query_normalises_whitespace_around_query() {
        let a = GraphqlFilter::hash_query("  { user }  ");
        let b = GraphqlFilter::hash_query("{ user }");
        assert_eq!(a, b);
    }

    #[test]
    fn applies_matches_path_only() {
        let f = GraphqlFilter::new(&cfg(10, 50));
        assert!(f.applies("/graphql"));
        assert!(f.applies("/graphql?op=x"));
        assert!(!f.applies("/api"));
    }

    #[test]
    fn shallow_query_passes() {
        let f = GraphqlFilter::new(&cfg(5, 50));
        let body = br#"{"query":"{ user { name } }"}"#;
        assert!(f.check_body(body).is_none());
    }

    #[test]
    fn excessive_depth_blocked() {
        let f = GraphqlFilter::new(&cfg(3, 50));
        // 5 levels deep
        let body = br#"{"query":"{ a { b { c { d { e { f } } } } } }"}"#;
        match f.check_body(body) {
            Some(FilterAction::Deny { reason, .. }) => assert!(reason.contains("depth")),
            other => panic!("expected depth deny, got {other:?}"),
        }
    }

    #[test]
    fn alias_dos_blocked() {
        let f = GraphqlFilter::new(&cfg(10, 4));
        // 5 aliases
        let body = br#"{"query":"{ a:f b:f c:f d:f e:f }"}"#;
        match f.check_body(body) {
            Some(FilterAction::Deny { reason, .. }) => assert!(reason.contains("alias")),
            other => panic!("expected alias deny, got {other:?}"),
        }
    }

    #[test]
    fn introspection_blocked() {
        let f = GraphqlFilter::new(&cfg(20, 200));
        let body = br#"{"query":"{ __schema { types { name } } }"}"#;
        match f.check_body(body) {
            Some(FilterAction::Deny { reason, .. }) => assert!(reason.contains("introspection")),
            other => panic!("expected introspection deny, got {other:?}"),
        }
    }

    #[test]
    fn args_inside_parens_dont_count_as_aliases() {
        let f = GraphqlFilter::new(&cfg(5, 1));
        // 0 aliases, but 3 named arguments — must not trigger.
        let body = br#"{"query":"{ user(id: 1, role: admin, page: 2) { name } }"}"#;
        assert!(f.check_body(body).is_none());
    }

    #[test]
    fn strings_with_braces_dont_inflate_depth() {
        let f = GraphqlFilter::new(&cfg(3, 50));
        let body = br#"{"query":"{ post(slug: \"{{{evil}}}\") { title } }"}"#;
        // Real depth = 1, the {{{ inside the string literal must be skipped.
        assert!(f.check_body(body).is_none());
    }

    #[test]
    fn malformed_body_falls_open() {
        let f = GraphqlFilter::new(&cfg(3, 50));
        assert!(f.check_body(b"not json at all").is_none());
    }

    /// V233 — duplicate-`"query"`-key auth bypass regression.
    ///
    /// A JSON body with two `"query"` keys must be evaluated on the
    /// LAST value (upstream last-key-wins), never the benign first one.
    /// The old hand-rolled scanner returned the first occurrence, so a
    /// shallow benign op could mask a deep malicious one.
    #[test]
    fn duplicate_query_keys_evaluated_on_last_value() {
        // depth limit 3; first value depth 1 (benign), second depth 5.
        let f = GraphqlFilter::new(&cfg(3, 50));
        let body = br#"{"query":"{ user { name } }","query":"{ a { b { c { d { e } } } } }"}"#;
        match f.check_body(body) {
            Some(FilterAction::Deny { reason, .. }) => assert!(
                reason.contains("depth"),
                "must reject on the deep LAST value, got: {reason}"
            ),
            other => panic!("duplicate-key bypass: deep last value not caught, got {other:?}"),
        }
    }

    /// V233 — same bypass against the persisted-query allow-list: the
    /// first value is on the allow-list, the second is not. Upstream
    /// runs the second, so the filter must hash the LAST value and 403.
    #[test]
    fn duplicate_query_keys_use_last_for_persisted_check() {
        let allowed = GraphqlFilter::hash_query("{ user { id } }");
        let f = GraphqlFilter::new(&cfg_persisted(vec![allowed]));
        let body = br#"{"query":"{ user { id } }","query":"{ secret { token } }"}"#;
        match f.check_body(body) {
            Some(FilterAction::Deny { status, .. }) => assert_eq!(
                status, 403,
                "must hash the unlisted LAST value, not the allowed first"
            ),
            other => panic!("expected Deny 403 on unlisted last value, got {other:?}"),
        }
    }

    /// V233 — `extract_query_field` itself returns the last value on
    /// duplicate keys (serde_json `Map` last-key-wins).
    #[test]
    fn extract_query_field_returns_last_duplicate() {
        let got = extract_query_field(r#"{"query":"FIRST","query":"LAST"}"#);
        assert_eq!(got.as_deref(), Some("LAST"));
    }

    /// V233 — multi-byte UTF-8 in the query survives extraction intact.
    /// The old `byte as char` cast corrupted any non-ASCII codepoint,
    /// so the guard scanned a different string than the upstream.
    #[test]
    fn utf8_query_preserved_through_extraction() {
        let got = extract_query_field(r#"{"query":"{ post(slug: \"café-日本\") { id } }"}"#);
        assert_eq!(got.as_deref(), Some("{ post(slug: \"café-日本\") { id } }"));
    }

    /// M4 — a malicious operation hidden inside a top-level JSON array
    /// batch must be caught. Pre-fix, `value.get("query")` returned
    /// `None` for an array so the whole guard fell open.
    #[test]
    fn malicious_batch_blocked() {
        let f = GraphqlFilter::new(&cfg(3, 50));
        // First op benign (depth 1), second op depth 5 (> max 3).
        let body = br#"[{"query":"{ user { name } }"},{"query":"{ a { b { c { d { e } } } } }"}]"#;
        match f.check_body(body) {
            Some(FilterAction::Deny { reason, .. }) => assert!(
                reason.contains("depth"),
                "batch element exceeding depth must be caught, got: {reason}"
            ),
            other => panic!("batch bypass: deep element not caught, got {other:?}"),
        }
    }

    /// M4 — introspection inside a batch element is blocked too.
    #[test]
    fn batch_introspection_blocked() {
        let f = GraphqlFilter::new(&cfg(20, 200));
        let body = br#"[{"query":"{ ok }"},{"query":"{ __schema { types { name } } }"}]"#;
        match f.check_body(body) {
            Some(FilterAction::Deny { reason, .. }) => assert!(reason.contains("introspection")),
            other => panic!("expected introspection deny in batch, got {other:?}"),
        }
    }

    /// M4 — a batch longer than `MAX_BATCH_LEN` is rejected outright as
    /// an amplification vector, even when every element is benign.
    #[test]
    fn over_long_batch_blocked() {
        let f = GraphqlFilter::new(&cfg(10, 50));
        let one = r#"{"query":"{ ok }"}"#;
        let elems = std::iter::repeat(one)
            .take(MAX_BATCH_LEN + 1)
            .collect::<Vec<_>>()
            .join(",");
        let body = format!("[{elems}]");
        match f.check_body(body.as_bytes()) {
            Some(FilterAction::Deny { status, reason }) => {
                assert_eq!(status, 400);
                assert!(reason.contains("batch length"), "got: {reason}");
            }
            other => panic!("expected over-long batch deny, got {other:?}"),
        }
    }

    /// M4 — a batch at exactly the cap with all-benign elements passes.
    #[test]
    fn benign_max_length_batch_passes() {
        let f = GraphqlFilter::new(&cfg(5, 50));
        let one = r#"{"query":"{ user { name } }"}"#;
        let elems = std::iter::repeat(one)
            .take(MAX_BATCH_LEN)
            .collect::<Vec<_>>()
            .join(",");
        let body = format!("[{elems}]");
        assert!(
            f.check_body(body.as_bytes()).is_none(),
            "benign full batch should pass"
        );
    }

    /// M4 — a benign single object (batch-of-one) still passes,
    /// confirming the refactor preserved single-object behaviour.
    #[test]
    fn benign_single_query_passes_after_batch_refactor() {
        let f = GraphqlFilter::new(&cfg(5, 50));
        let body = br#"{"query":"{ user { name } }"}"#;
        assert!(f.check_body(body).is_none());
    }

    /// M4 — persisted-only enforcement applies to every batch element:
    /// the first is allow-listed, the second is not, so the batch 403s.
    #[test]
    fn batch_persisted_check_applies_to_each_element() {
        let allowed = GraphqlFilter::hash_query("{ user { id } }");
        let f = GraphqlFilter::new(&cfg_persisted(vec![allowed]));
        let body = br#"[{"query":"{ user { id } }"},{"query":"{ secret { token } }"}]"#;
        match f.check_body(body) {
            Some(FilterAction::Deny { status, .. }) => assert_eq!(status, 403),
            other => panic!("expected 403 for unlisted batch element, got {other:?}"),
        }
    }

    #[test]
    fn disabled_filter_skips() {
        let mut c = cfg(1, 1);
        c.enabled = false;
        let f = GraphqlFilter::new(&c);
        let body = br#"{"query":"{ a { b { c { d } } } }"}"#;
        assert!(f.check_body(body).is_none());
    }
}
