//! V124 — Wirefilter expression WAF (info.md / Synapse parity).
//!
//! Cloudflare's `wirefilter-engine` crate lets operators write
//! compositional security expressions instead of the flat
//! `{field, op, value}` WafRule shape we shipped in V95.
//!
//! Example expressions (wirefilter 0.6 operator set — `matches` for
//! regex, no function syntax):
//!
//! ```text
//! http.request.method eq "POST" and http.request.path matches "^/admin"
//! http.request.query contains "UNION SELECT" or http.request.query contains "1=1"
//! http.request.content_length > 10485760 and http.request.method eq "POST"
//! http.request.path matches "^/login" and ip.src in {10.0.0.0/8 192.168.0.0/16}
//! ```
//!
//! Each operator-supplied rule is parsed ONCE at config load (or
//! hot-reload) into a [Filter] AST + compiled [FilterAst], then
//! evaluated per-request through an [ExecutionContext] populated from
//! the [RequestContext].
//!
//! Field schema (V124 subset; extend at the [build_scheme] site):
//!
//! | Field                           | Type   | Source                          |
//! |---------------------------------|--------|---------------------------------|
//! | `http.request.method`           | Bytes  | `ctx.method` uppercase          |
//! | `http.request.path`             | Bytes  | `ctx.path` (no query)           |
//! | `http.request.query`            | Bytes  | query string after `?`          |
//! | `http.request.uri`              | Bytes  | full path?query                 |
//! | `http.request.host`             | Bytes  | `ctx.host`                      |
//! | `http.request.user_agent`       | Bytes  | UA header                       |
//! | `http.request.content_length`   | Int    | header `content-length`         |
//! | `http.request.header_count`     | Int    | total header count              |
//! | `ip.src`                        | Ip     | `ctx.client_ip`                 |
//! | `signal.ja4`                    | Bytes  | `ctx.ja4`                       |
//! | `signal.ja4h`                   | Bytes  | `ctx.ja4h`                      |
//! | `signal.ja4t`                   | Bytes  | `ctx.ja4t`                      |
//!
//! Actions supported: `block`, `challenge`, `log` (matches but doesn't
//! enforce — same shadow-mode discipline as V109 per-rule mode).
//!
//! Coexists with V95 plain WafRule. Operator opts in per-rule via
//! `expression: "..."` instead of the {field, op, value} triple.

use std::sync::Arc;

use arc_swap::ArcSwap;
// Crate package name is `wirefilter-engine` but the lib name is `wirefilter`.
use wirefilter::{ExecutionContext, Filter, Scheme, Type};

use crate::{filters::FilterAction, proxy::request_context::RequestContext};

/// One parsed wirefilter rule.
pub struct WireRule {
    pub id: String,
    pub action: WireAction,
    /// Compiled filter — parsed once, evaluated per request.
    filter: Filter<'static>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireAction {
    Block,
    Challenge,
    /// Match-but-don't-enforce — same shadow-mode discipline as V109.
    Log,
}

impl WireAction {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "block" | "deny" => Some(WireAction::Block),
            "challenge" | "captcha" => Some(WireAction::Challenge),
            "log" | "observe" | "shadow" => Some(WireAction::Log),
            _ => None,
        }
    }
}

/// Compiled rule set. ArcSwap so the hot-path lookup is lock-free
/// and hot-reload doesn't block matchers.
pub struct WirefilterEngine {
    scheme: &'static Scheme,
    rules: ArcSwap<Vec<WireRule>>,
}

impl Default for WirefilterEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WirefilterEngine {
    pub fn new() -> Self {
        Self {
            scheme: build_scheme(),
            rules: ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Compile and install a batch of `(id, expression, action)`
    /// rules. Returns a list of parse errors; rules that parsed
    /// cleanly are installed atomically. Rules that failed are
    /// reported but don't prevent the others from taking effect —
    /// matches the V109 "drop new rule in shadow, see if it parses,
    /// then promote" workflow.
    pub fn load(&self, raw: &[(&str, &str, WireAction)]) -> Vec<WireParseError> {
        let mut compiled = Vec::with_capacity(raw.len());
        let mut errors = Vec::new();
        for (id, expr, action) in raw {
            match self.scheme.parse(expr) {
                Ok(ast) => match ast.compile() {
                    filter => compiled.push(WireRule {
                        id: id.to_string(),
                        action: *action,
                        filter,
                    }),
                },
                Err(e) => errors.push(WireParseError {
                    id: id.to_string(),
                    expression: expr.to_string(),
                    error: e.to_string(),
                }),
            }
        }
        // wirefilter's `Filter` is neither Send nor Sync, so clippy flags the
        // Arc. The value never crosses a thread boundary: `load()` is called
        // from the config-reload path and the ArcSwap is read on the same
        // worker thread that evaluates requests (one worker = one thread).
        #[allow(clippy::arc_with_non_send_sync)]
        let compiled = Arc::new(compiled);
        self.rules.store(compiled);
        errors
    }

    /// Evaluate request against every loaded rule. Returns the FIRST
    /// matching rule's action (rules evaluated in declaration order).
    /// `None` = no rule matched.
    pub fn evaluate(&self, ctx: &RequestContext) -> Option<WireMatch> {
        let rules = self.rules.load();
        if rules.is_empty() {
            return None;
        }
        // Stage the owned String data so it outlives `exec`.
        let staged = RequestStaging::from_ctx(ctx);
        let mut exec = ExecutionContext::new(self.scheme);
        // SAFETY of the lifetime transmute below:
        //   * `staged` is a stack local declared BEFORE `exec`.
        //   * Rust drops locals in reverse declaration order: `exec`
        //     drops first, THEN `staged`.
        //   * `exec` only ever reads the staged borrows during its
        //     own lifetime (i.e. before drop).
        //   * The 'static lifetime on the references inside `exec`
        //     is a wirefilter API constraint (Scheme is &'static),
        //     not an actual access pattern; we know the data is
        //     valid for the full body of this function.
        // Therefore extending the borrow's apparent lifetime is sound.
        let staged_static: &'static RequestStaging =
            unsafe { std::mem::transmute::<&RequestStaging, &'static RequestStaging>(&staged) };
        if populate_exec(&mut exec, staged_static, ctx.client_ip).is_err() {
            return None;
        }
        for rule in rules.iter() {
            if rule.filter.execute(&exec).unwrap_or(false) {
                return Some(WireMatch {
                    rule_id: rule.id.clone(),
                    action: rule.action,
                });
            }
        }
        None
    }

    /// Adapter for callers that want a [FilterAction] directly.
    /// Returns `Allow` when nothing matched OR when the matched
    /// rule was in `Log` mode (shadow).
    pub fn evaluate_action(&self, ctx: &RequestContext) -> FilterAction {
        match self.evaluate(ctx) {
            None => FilterAction::Allow,
            Some(m) => match m.action {
                WireAction::Block => FilterAction::Deny {
                    status: 403,
                    reason: format!("waf wirefilter rule {} block", sanitize_id(&m.rule_id)).into(),
                },
                WireAction::Challenge => FilterAction::Challenge {
                    level: crate::filters::ChallengeLevel::Captcha,
                    reason: format!("waf wirefilter rule {} challenge", sanitize_id(&m.rule_id))
                        .into(),
                },
                WireAction::Log => FilterAction::Allow,
            },
        }
    }

    /// Diagnostic: current loaded rule count.
    pub fn rule_count(&self) -> usize {
        self.rules.load().len()
    }
}

#[derive(Debug, Clone)]
pub struct WireMatch {
    pub rule_id: String,
    pub action: WireAction,
}

#[derive(Debug, Clone)]
pub struct WireParseError {
    pub id: String,
    pub expression: String,
    pub error: String,
}

fn sanitize_id(id: &str) -> String {
    id.replace(['\r', '\n'], "_")
}

/// V124 — schema definition. Field names + types operators reference
/// inside expressions. `&'static Scheme` because every Filter<'a>
/// borrows from the schema; we lazy-init it once per process.
fn build_scheme() -> &'static Scheme {
    static ONCE: std::sync::OnceLock<Scheme> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let mut scheme = Scheme::new();
        scheme
            .add_field("http.request.method".to_string(), Type::Bytes)
            .unwrap();
        scheme
            .add_field("http.request.path".to_string(), Type::Bytes)
            .unwrap();
        scheme
            .add_field("http.request.query".to_string(), Type::Bytes)
            .unwrap();
        scheme
            .add_field("http.request.uri".to_string(), Type::Bytes)
            .unwrap();
        scheme
            .add_field("http.request.host".to_string(), Type::Bytes)
            .unwrap();
        scheme
            .add_field("http.request.user_agent".to_string(), Type::Bytes)
            .unwrap();
        scheme
            .add_field("http.request.content_length".to_string(), Type::Int)
            .unwrap();
        scheme
            .add_field("http.request.header_count".to_string(), Type::Int)
            .unwrap();
        scheme.add_field("ip.src".to_string(), Type::Ip).unwrap();
        scheme
            .add_field("signal.ja4".to_string(), Type::Bytes)
            .unwrap();
        scheme
            .add_field("signal.ja4h".to_string(), Type::Bytes)
            .unwrap();
        scheme
            .add_field("signal.ja4t".to_string(), Type::Bytes)
            .unwrap();
        scheme
    })
}

/// Owned strings derived from a RequestContext. Lives long enough
/// to lend &str / &[u8] views to the wirefilter ExecutionContext
/// (which requires borrowed values to outlive the context itself).
struct RequestStaging {
    method_upper: String,
    bare_path: String,
    query: String,
    full_uri: String,
    host: String,
    ua: String,
    content_length: i32,
    header_count: i32,
    ja4: String,
    ja4h: String,
    ja4t: String,
}

impl RequestStaging {
    fn from_ctx(ctx: &RequestContext) -> Self {
        let path = ctx.path.as_str();
        let (bare, q) = match path.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (path.to_string(), String::new()),
        };
        let content_length = ctx
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            // Wirefilter 0.6 Int = i32; saturate huge bodies to MAX
            // so `> threshold` still fires for any large request.
            .map(|n| n.min(i32::MAX as i64) as i32)
            .unwrap_or(0);
        Self {
            method_upper: ctx.method.as_str().to_ascii_uppercase(),
            bare_path: bare,
            query: q,
            full_uri: path.to_string(),
            host: ctx.host.clone(),
            ua: ctx.user_agent.clone().unwrap_or_default(),
            content_length,
            header_count: ctx.headers.len() as i32,
            ja4: ctx.ja4.clone().unwrap_or_default(),
            ja4h: ctx.ja4h().unwrap_or("").to_owned(),
            ja4t: ctx.ja4t.clone().unwrap_or_default(),
        }
    }
}

/// Populate the execution context with borrowed views into the
/// staged data. All fields are always set (with empty defaults) so
/// expressions that reference a missing field don't fail at runtime.
fn populate_exec<'a>(
    exec: &mut ExecutionContext<'a>,
    s: &'a RequestStaging,
    client_ip: std::net::IpAddr,
) -> Result<(), wirefilter::FieldValueTypeMismatchError> {
    exec.set_field_value("http.request.method", s.method_upper.as_bytes())?;
    exec.set_field_value("http.request.path", s.bare_path.as_bytes())?;
    exec.set_field_value("http.request.query", s.query.as_bytes())?;
    exec.set_field_value("http.request.uri", s.full_uri.as_bytes())?;
    exec.set_field_value("http.request.host", s.host.as_bytes())?;
    exec.set_field_value("http.request.user_agent", s.ua.as_bytes())?;
    exec.set_field_value("http.request.content_length", s.content_length)?;
    exec.set_field_value("http.request.header_count", s.header_count)?;
    exec.set_field_value("ip.src", client_ip)?;
    exec.set_field_value("signal.ja4", s.ja4.as_bytes())?;
    exec.set_field_value("signal.ja4h", s.ja4h.as_bytes())?;
    exec.set_field_value("signal.ja4t", s.ja4t.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(ip: &str, method: &str, path: &str) -> RequestContext {
        let mut c = RequestContext::test_with(ip, path);
        c.method = method.parse().unwrap_or(http::Method::GET);
        c
    }

    #[test]
    fn simple_method_match_blocks() {
        let e = WirefilterEngine::new();
        let errs = e.load(&[(
            "block-post",
            "http.request.method eq \"POST\"",
            WireAction::Block,
        )]);
        assert!(errs.is_empty(), "parse errors: {errs:?}");
        let post = ctx_with("1.1.1.1", "POST", "/api");
        let get = ctx_with("1.1.1.1", "GET", "/api");
        assert!(matches!(
            e.evaluate_action(&post),
            FilterAction::Deny { .. }
        ));
        assert_eq!(e.evaluate_action(&get), FilterAction::Allow);
    }

    #[test]
    fn regex_path_match_works() {
        // wirefilter 0.6 has `matches` (regex) instead of starts_with.
        // Operators write `^/admin` to anchor at the start.
        let e = WirefilterEngine::new();
        let errs = e.load(&[(
            "admin-guard",
            "http.request.path matches \"^/admin\"",
            WireAction::Block,
        )]);
        assert!(errs.is_empty(), "{errs:?}");
        let admin = ctx_with("1.1.1.1", "GET", "/admin/users");
        let public = ctx_with("1.1.1.1", "GET", "/");
        assert!(matches!(
            e.evaluate_action(&admin),
            FilterAction::Deny { .. }
        ));
        assert_eq!(e.evaluate_action(&public), FilterAction::Allow);
    }

    #[test]
    fn compositional_and_or_works() {
        let e = WirefilterEngine::new();
        let errs = e.load(&[(
            "large-post-to-api",
            "http.request.method eq \"POST\" and http.request.content_length > 1048576 and http.request.path matches \"^/api\"",
            WireAction::Block,
        )]);
        assert!(errs.is_empty(), "{errs:?}");
        // Matches all three.
        let big_post_api = {
            let mut c = ctx_with("1.1.1.1", "POST", "/api/upload");
            std::sync::Arc::make_mut(&mut c.headers)
                .insert("content-length", http::HeaderValue::from_static("2097152"));
            c
        };
        // Small POST to /api — doesn't match (under size).
        let small_post_api = {
            let mut c = ctx_with("1.1.1.1", "POST", "/api/upload");
            std::sync::Arc::make_mut(&mut c.headers)
                .insert("content-length", http::HeaderValue::from_static("100"));
            c
        };
        assert!(matches!(
            e.evaluate_action(&big_post_api),
            FilterAction::Deny { .. }
        ));
        assert_eq!(e.evaluate_action(&small_post_api), FilterAction::Allow);
    }

    #[test]
    fn ip_src_field_supports_v4_literal() {
        let e = WirefilterEngine::new();
        let errs = e.load(&[("block-1111", "ip.src eq 1.1.1.1", WireAction::Block)]);
        assert!(errs.is_empty(), "{errs:?}");
        assert!(matches!(
            e.evaluate_action(&ctx_with("1.1.1.1", "GET", "/")),
            FilterAction::Deny { .. }
        ));
        assert_eq!(
            e.evaluate_action(&ctx_with("2.2.2.2", "GET", "/")),
            FilterAction::Allow
        );
    }

    #[test]
    fn log_action_does_not_enforce() {
        let e = WirefilterEngine::new();
        let errs = e.load(&[(
            "audit-post",
            "http.request.method eq \"POST\"",
            WireAction::Log,
        )]);
        assert!(errs.is_empty());
        // Match is recorded but action is Allow (shadow mode).
        let post = ctx_with("1.1.1.1", "POST", "/api");
        assert_eq!(e.evaluate_action(&post), FilterAction::Allow);
        // The underlying evaluate() still returns Some so SecurityEvent
        // V116 emit can observe the shadow match.
        let m = e.evaluate(&post).expect("should match");
        assert_eq!(m.action, WireAction::Log);
    }

    #[test]
    fn malformed_expression_reports_error_but_others_load() {
        let e = WirefilterEngine::new();
        let errs = e.load(&[
            ("good", "http.request.method eq \"GET\"", WireAction::Block),
            ("bad", "this is not a valid expression", WireAction::Block),
        ]);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].id, "bad");
        assert_eq!(e.rule_count(), 1);
        // Good rule still works.
        assert!(matches!(
            e.evaluate_action(&ctx_with("1.1.1.1", "GET", "/")),
            FilterAction::Deny { .. }
        ));
    }

    #[test]
    fn empty_rule_set_allows() {
        let e = WirefilterEngine::new();
        assert_eq!(
            e.evaluate_action(&ctx_with("1.1.1.1", "GET", "/")),
            FilterAction::Allow
        );
    }

    #[test]
    fn contains_caught_for_body_like_query() {
        let e = WirefilterEngine::new();
        let errs = e.load(&[(
            "sqli",
            "http.request.query contains \"union select\"",
            WireAction::Block,
        )]);
        assert!(errs.is_empty(), "{errs:?}");
        let attack = ctx_with("1.1.1.1", "GET", "/?q=union select 1,2");
        let benign = ctx_with("1.1.1.1", "GET", "/?q=hello");
        assert!(matches!(
            e.evaluate_action(&attack),
            FilterAction::Deny { .. }
        ));
        assert_eq!(e.evaluate_action(&benign), FilterAction::Allow);
    }
}
