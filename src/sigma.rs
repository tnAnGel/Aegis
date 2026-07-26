//! V196 — Sigma rule importer.
//!
//! SigmaHQ ships 3000+ community-maintained detection rules in a
//! standard YAML format ([sigmahq/sigma](https://github.com/SigmaHQ/sigma)).
//! A meaningful subset — `logsource.category: webserver` —  maps
//! directly onto Aegis's WAF: their fields (`c-uri`, `cs-method`,
//! `cs-user-agent`, `cs(Referer)`, etc.) are HTTP request fields we
//! already match against.
//!
//! This module parses Sigma YAML and emits [crate::config::WafRule]
//! values. The CLI binary `aegis-sigma-import` walks a directory of
//! `*.yml` files and writes a consolidated `<output>.toml` ready to
//! load via `waf.rule_files`.
//!
//! ## What we support
//!
//! Fields (Sigma → Aegis WafRule.field):
//!
//! | Sigma                              | Aegis              |
//! |------------------------------------|--------------------|
//! | `c-uri`, `cs-uri`, `cs-uri-stem`   | `path`             |
//! | `cs-uri-query`, `c-uri-query`      | `query`            |
//! | `cs-method`                        | `method`           |
//! | `c-useragent`, `cs-user-agent`     | `user_agent`       |
//! | `cs(User-Agent)`                   | `user_agent`       |
//! | `cs(Host)`, `cs-host`              | `host`             |
//! | `cs(Referer)`                      | `header:referer`   |
//! | `cs(Cookie)`                       | `header:cookie`    |
//! | `cs(X-Forwarded-For)`              | `header:x-forwarded-for` |
//! | generic `cs(Some-Header)`          | `header:some-header` |
//! | `c-ip`, `src_ip`                   | `client_ip`        |
//!
//! Modifiers (Sigma `field|modifier` → WafRule.op):
//!
//! | Modifier      | Aegis op       |
//! |---------------|----------------|
//! | (none)        | `equals`       |
//! | `contains`    | `contains`     |
//! | `startswith`  | `starts_with`  |
//! | `endswith`    | `ends_with`    |
//! | `re`          | `regex`        |
//! | `all`         | (multiple rules with same id) |
//!
//! List values (`field: [a, b, c]`) emit one rule per element, all
//! sharing the same Sigma id (so block decisions log a single id
//! per hit, regardless of which list entry matched).
//!
//! ## Compound emission (V197)
//!
//! Earlier versions FLATTENED a selection block's keys into independent
//! single-condition WafRules sharing one id. That was wrong: a Sigma
//! `selection` is an **AND** across its field keys, so flattening turned
//! `c-uri|contains: /x AND cs-method: POST` into two OR'd rules — and the
//! bare `method == POST` rule blocked ALL POST traffic (an FP storm that
//! broke the live site). The whole bundled corpus had to be disabled.
//!
//! We now emit **compound** rules using [crate::config::WafRule::all_of]
//! ([crate::config::WafAndGroup]). A compound rule fires only when its
//! PRIMARY `{field, op, value}` matches AND every `all_of` group matches
//! (each group is an OR over its `any_of` values). This faithfully
//! reproduces Sigma AND-of-(OR) selection semantics.
//!
//! For a single selection block we:
//!
//! 1. Collect each `field[|modifier]` key as a group
//!    `(aegis_field, op, [values])` — the value list is the OR set.
//! 2. Pick a **selective** primary field, preferring (in order):
//!    `query`, `uri`/`path`, `user_agent`. We NEVER pick `method` or
//!    `host` as primary. If the block's only field(s) are method/host
//!    (no selective field) we SKIP with reason
//!    `too-broad-no-selective-field` — these are precisely the FP rules.
//! 3. Emit ONE WafRule per primary value (`value` = that element),
//!    putting every OTHER group into `all_of` as a [crate::config::WafAndGroup]
//!    `{field, op, any_of}` — including method/host, which are fine as
//!    AND constraints, just never as the sole trigger.
//! 4. Preserve the id scheme, action, severity, tags and mode.
//!
//! ## Condition support
//!
//! * `selection` — single block; keys AND'd via the compound model
//!   above (one block → compound rules, NOT independent broad rules).
//! * `1 of selection_*` / `any of selection_*` — OR'd across blocks,
//!   each block independently contributes its own compound rules.
//! * `selection and not filter` — emits the `selection` compound rules
//!   and drops the filter (we can't express AND-then-NOT here; operator
//!   can post-filter).
//! * Complex AND across multiple selection blocks → conjuncts that are
//!   known blocks each contribute their own compound rules (best-effort).
//!
//! Level mapping:
//!
//! | Sigma level | Aegis severity | action       |
//! |-------------|----------------|--------------|
//! | critical    | critical       | block        |
//! | high        | high           | block        |
//! | medium      | medium         | challenge    |
//! | low         | low            | log (shadow) |
//! | informational | low          | log (shadow) |

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::config::{WafAndGroup, WafRule};

/// Subset of a Sigma rule we care about. Fields outside this subset
/// (falsepositives, references, etc.) are preserved in audit logs but
/// don't affect WafRule output.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SigmaRule {
    pub title: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub logsource: LogSource,
    pub detection: Detection,
    #[serde(default)]
    pub level: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LogSource {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Detection {
    /// Selection blocks — keys are user-named (`selection`,
    /// `selection_uri`, `filter`, etc.). Each value is a mapping of
    /// `field[|modifier]` → scalar / list.
    #[serde(flatten)]
    pub blocks: BTreeMap<String, serde_yml::Value>,
    pub condition: String,
}

/// Top-level conversion entry point.
#[derive(Debug, Clone)]
pub struct ConversionOutput {
    /// Rules ready to feed into WafConfig.custom_rules.
    pub rules: Vec<WafRule>,
    /// Sigma rules we skipped + the reason. Surfaced to the operator
    /// so they can hand-port the complex ones.
    pub skipped: Vec<SkipNote>,
    /// One Aegis SecurityEvent reason tag per Sigma id that converted
    /// (for cross-referencing the original Sigma rule when a hit fires).
    pub tag_map: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SkipNote {
    pub source_file: String,
    pub title: String,
    pub reason: String,
}

pub fn parse_yaml(input: &str) -> Result<SigmaRule, String> {
    serde_yml::from_str(input).map_err(|e| format!("yaml: {e}"))
}

/// Decide whether a parsed Sigma rule describes traffic an HTTP edge can
/// actually see.
///
/// Accepted:
/// * `logsource.category: webserver` / `web` — server access logs, the
///   native fit;
/// * `logsource.category: proxy` — forward-proxy access logs. Their field
///   vocabulary (`c-useragent`, `c-uri`, `cs-method`, `cs-host`) is the same
///   HTTP request Aegis inspects, so the detections port over directly. This
///   is where the User-Agent corpus lives: hack tools, exploit frameworks,
///   crypto miners, APT tooling, empty and base64 agents;
/// * webserver products (`apache`, `nginx`, `iis`, `haproxy`, `caddy`).
///
/// Everything else — `process_creation`, `file_event`, `registry_set`,
/// `image_load`, `ps_script`, `dns_query` and friends — is endpoint
/// telemetry. Those rules match on process command lines and registry keys;
/// there is no HTTP request in them to match against, so they are skipped
/// rather than emitted as rules that could never fire.
pub fn is_http_edge_rule(rule: &SigmaRule) -> bool {
    let cat = rule.logsource.category.as_deref().unwrap_or("");
    if cat.eq_ignore_ascii_case("webserver")
        || cat.eq_ignore_ascii_case("web")
        || cat.eq_ignore_ascii_case("proxy")
    {
        return true;
    }
    let prod = rule.logsource.product.as_deref().unwrap_or("");
    matches!(
        prod.to_ascii_lowercase().as_str(),
        "apache" | "nginx" | "iis" | "haproxy" | "caddy"
    )
}

/// Backwards-compatible alias for [`is_http_edge_rule`].
pub fn is_webserver_rule(rule: &SigmaRule) -> bool {
    is_http_edge_rule(rule)
}

pub fn convert(rule: &SigmaRule, source_file: &str) -> Result<Vec<WafRule>, String> {
    if !is_http_edge_rule(rule) {
        return Err("not an HTTP-edge rule (endpoint telemetry)".into());
    }

    // Lower-bound on rule identity — Sigma rules usually have a uuid
    // `id`; fall back to a slug of the title.
    let base_id = rule
        .id
        .clone()
        .or_else(|| Some(slugify(&rule.title)))
        .unwrap_or_else(|| format!("sigma-{}", short_hash(&rule.title)));
    let id_prefix = format!(
        "sigma_{}",
        base_id.replace(['-', ' '], "_").to_ascii_lowercase()
    );

    let (action, severity, mode) = level_to_aegis(rule.level.as_deref());

    // Parse condition — decide which selection blocks contribute and
    // whether the union (OR) or per-block conjunction (AND) is wanted.
    let plan = parse_condition(&rule.detection.condition, &rule.detection.blocks)?;

    // A rule whose `not <filter>` clause we could not express matches strictly
    // more than its author intended. Import it for visibility, but never let it
    // block: log-only, shadow mode, tagged so the operator can find them.
    let (action, severity, mode, mut tags_extra): (&str, &str, Option<&str>, Vec<String>) =
        if plan.lossy_negation {
            (
                "log",
                "low",
                Some("shadow"),
                vec!["aegis.import.filter-clause-dropped".to_string()],
            )
        } else {
            (action, severity, mode, Vec::new())
        };

    // Proxy access-log rules were written from the opposite vantage point: they
    // watch requests leaving a network, where a browser-shaped User-Agent is a
    // tell (malware impersonating Chrome). At a reverse proxy the same string is
    // simply a visitor's browser — the upstream `proxy_ua_frameworks` rule even
    // says so inline about its Googlebot entry ("only use in proxy logs — not
    // for detection in web server logs"). Enforcing those verbatim blocked
    // Googlebot on the test stand. Tool-shaped agents (sqlmap/, nikto/) carry
    // over fine; browser-shaped literals do not, so they are dropped.
    let is_proxy_rule = rule
        .logsource
        .category
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case("proxy"));
    let mut out = Vec::new();
    let mut suffix = 0u32;
    let mut tags = rule.tags.iter().take(8).cloned().collect::<Vec<_>>();
    tags.append(&mut tags_extra);

    // Collect one group-set per selection block first; emission happens after,
    // because a conjunction condition has to merge them into a single rule.
    let mut block_sets: Vec<Vec<FieldGroup>> = Vec::new();
    for block_name in plan.include_blocks {
        let value = rule
            .detection
            .blocks
            .get(&block_name)
            .ok_or_else(|| format!("missing block {block_name}"))?;
        // Sigma `keywords` convention: bare list of strings that
        // match anywhere in the event. For webserver rules that
        // overwhelmingly means "in the URI" — emit contains rules
        // against `path`. Best-effort but captures the common case
        // (LFI/RCE keyword lists).
        if block_name.contains("keyword")
            && let Some(seq) = value.as_sequence()
        {
            for item in seq {
                let Some(s) = item.as_str() else { continue };
                let Some((op, v)) = normalise_glob("contains", s) else {
                    continue;
                };
                if v.is_empty() {
                    continue;
                }
                suffix += 1;
                out.push(WafRule {
                    id: format!("{id_prefix}__{suffix}"),
                    field: "path".into(),
                    op: op.to_string(),
                    value: v,
                    action: action.to_string(),
                    severity: Some(severity.to_string()),
                    tags: tags.clone(),
                    score: None,
                    mode: mode.map(|s| s.to_string()),
                    // Keyword hits are a single `path contains` condition —
                    // no compound AND constraints. `path` is selective, so
                    // these are not FP-prone the way a bare method rule is.
                    all_of: Vec::new(),
                });
            }
            continue;
        }
        let mapping = value
            .as_mapping()
            .ok_or_else(|| format!("block {block_name} is not a mapping"))?;
        // Step 1: collect every field key in this selection block as a
        // group (aegis_field, op, [values]). A Sigma selection ANDs its
        // keys together; list values within a key are an OR set. We turn
        // this into the compound model below rather than flattening into
        // independent (over-broad) rules.
        let mut groups: Vec<FieldGroup> = Vec::new();
        for (field_node, val_node) in mapping {
            let field_spec = field_node
                .as_str()
                .ok_or_else(|| "non-string field name".to_string())?;
            let (raw_field, modifier_chain) = split_modifier(field_spec);
            let aegis_field = match map_field(raw_field) {
                Some(f) => f,
                None => continue,
            };
            // Sigma allows stacked modifiers like `cs-uri|contains|all`.
            // We collapse the chain to a single base modifier (the
            // last "primary" op) and ignore meta modifiers like `all`.
            // The strict AND-all semantic of `|all` is best-effort — the
            // OR-of-values in an any_of group can't enforce "all of",
            // so the operator can tighten later.
            let mut primary = "";
            for part in modifier_chain.split('|').filter(|p| !p.is_empty()) {
                match part {
                    "contains" | "startswith" | "endswith" | "re" | "regex" | "" => {
                        primary = part;
                    }
                    "all" | "any" | "ignorecase" | "cased" | "wide" | "utf16" | "utf16le"
                    | "utf16be" | "base64" | "base64offset" | "windash" | "expand" => {
                        // Meta modifier — currently ignored (best-effort).
                    }
                    other => {
                        return Err(format!("unsupported modifier |{other}| in {field_spec}"));
                    }
                }
            }
            let base_op = match primary {
                "" => "equals",
                "contains" => "contains",
                "startswith" => "starts_with",
                "endswith" => "ends_with",
                "re" | "regex" => "regex",
                other => return Err(format!("unsupported modifier |{other}| in {field_spec}")),
            };
            let raw_values: Vec<String> = extract_values(val_node)?
                .into_iter()
                .filter(|v| !v.is_empty())
                .collect();
            if raw_values.is_empty() {
                continue;
            }
            // `c-uri-extension` in a proxy log is the bare file extension
            // ("exe", "dll"), not a path. Mapping it straight onto `path`
            // would emit `path equals "exe"`, which can never match a real
            // request path. Rewrite it into the equivalent suffix test.
            let raw_lc = raw_field.to_ascii_lowercase();
            let (raw_lc, _) = split_modifier(&raw_lc);
            let is_extension = matches!(raw_lc, "c-uri-extension" | "uri-extension");

            // Sigma values may carry `*` wildcards. We have no glob matcher,
            // so translate the expressible shapes into the equivalent op and
            // drop the rest rather than matching a literal asterisk.
            let mut per_op: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
            for v in raw_values {
                if is_extension {
                    let v = if v.starts_with('.') {
                        v
                    } else {
                        format!(".{v}")
                    };
                    per_op.entry("ends_with").or_default().push(v);
                    continue;
                }
                let Some((op, v)) = normalise_glob(base_op, &v) else {
                    continue;
                };
                if v.is_empty() {
                    continue;
                }
                // Proxy-vantage guard, see the comment on `is_proxy_rule`.
                if is_proxy_rule
                    && aegis_field == "user_agent"
                    && matches!(op, "equals" | "starts_with")
                    && v.to_ascii_lowercase().starts_with("mozilla/")
                {
                    continue;
                }
                per_op.entry(op).or_default().push(v);
            }
            for (op, values) in per_op {
                groups.push(FieldGroup {
                    field: aegis_field.to_string(),
                    op: op.to_string(),
                    values,
                });
            }
        }
        if !groups.is_empty() {
            block_sets.push(groups);
        }
    }

    // A conjunction condition (`all of selection_*`, `a and b`) means every
    // block must match the SAME request, so merge them into one compound rule.
    // Emitting them separately is what let the CVE-2023-25157 payload list
    // escape as a standalone `query contains "SELECT"`.
    if plan.conjunction && block_sets.len() > 1 {
        let merged: Vec<FieldGroup> = block_sets.into_iter().flatten().collect();
        block_sets = vec![merged];
    }

    for groups in block_sets {
        // Step 2: pick a SELECTIVE primary. method/host alone are FP
        // magnets (e.g. `method == POST` blocks every POST), so a block
        // with no selective field is skipped entirely.
        let primary_idx = match select_primary(&groups) {
            Some(i) => i,
            None => return Err("too-broad-no-selective-field".into()),
        };
        // Step 3: every non-primary group becomes an AND constraint
        // (an OR over its values). Built once, shared by each emitted
        // per-value primary rule.
        let all_of: Vec<WafAndGroup> = groups
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != primary_idx)
            .map(|(_, g)| WafAndGroup {
                field: g.field.clone(),
                op: g.op.clone(),
                any_of: g.values.clone(),
            })
            .collect();
        // Expand the primary's value list into one WafRule per value.
        let primary = &groups[primary_idx];
        for v in &primary.values {
            suffix += 1;
            out.push(WafRule {
                id: format!("{id_prefix}__{suffix}"),
                field: primary.field.clone(),
                op: primary.op.clone(),
                value: v.clone(),
                action: action.to_string(),
                severity: Some(severity.to_string()),
                tags: tags.clone(),
                score: None,
                mode: mode.map(|s| s.to_string()),
                all_of: all_of.clone(),
            });
        }
    }
    let _ = source_file; // currently unused — caller already knows it
    if out.is_empty() {
        return Err("no convertible field/op pairs after mapping".into());
    }
    Ok(out)
}

struct ConditionPlan {
    include_blocks: Vec<String>,
    /// True when the Sigma condition ANDs the blocks together (`all of
    /// selection_*`, `a and b`). The blocks must then be merged into ONE
    /// compound rule. Emitting them independently is what turned
    /// CVE-2023-25157 — which requires a GeoServer path AND a CQL filter AND
    /// an SQL token — into a bare `query contains "SELECT"` that blocked an
    /// ordinary search box.
    conjunction: bool,
    /// True when the condition carried a `not <filter>` clause we cannot
    /// express. The emitted rule is then strictly broader than its author
    /// intended, so it is imported in shadow mode instead of enforcing.
    lossy_negation: bool,
}

/// One Sigma selection field key collected for compound emission:
/// the mapped Aegis field, the operator, and the (OR'd) value list.
struct FieldGroup {
    field: String,
    op: String,
    values: Vec<String>,
}

/// Selectivity ranking for choosing the PRIMARY trigger of a compound
/// rule. Lower = more selective = preferred. `method` and `host` are
/// deliberately excluded: a rule whose primary is `method` or `host`
/// matches a huge slice of legitimate traffic (the FP storm that broke
/// the live site). They're still fine as `all_of` AND constraints.
fn primary_selectivity(field: &str) -> Option<u8> {
    match field {
        "query" => Some(0),
        // `uri` and `path` are the same selective surface in our model;
        // map_field emits `path` for URI variants.
        "uri" | "path" => Some(1),
        "user_agent" => Some(2),
        // Everything else (headers, client_ip, query-ish customs) is
        // acceptable as a primary but less preferred than the curated
        // selective set. method/host are explicitly NOT primary-eligible.
        "method" | "host" => None,
        _ => Some(3),
    }
}

/// Choose the index of the group to use as the compound rule's primary
/// trigger, preferring the most selective field. Returns `None` when no
/// group is primary-eligible (block is method/host only) — the caller
/// then skips the rule with `too-broad-no-selective-field`.
fn select_primary(groups: &[FieldGroup]) -> Option<usize> {
    groups
        .iter()
        .enumerate()
        .filter_map(|(i, g)| primary_selectivity(&g.field).map(|rank| (rank, i)))
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, i)| i)
}

fn parse_condition(
    condition: &str,
    blocks: &BTreeMap<String, serde_yml::Value>,
) -> Result<ConditionPlan, String> {
    let cond = condition.trim();
    // 1) Simple "selection" — single block reference.
    if let Some(b) = blocks.get(cond)
        && b.is_mapping()
    {
        return Ok(ConditionPlan {
            include_blocks: vec![cond.to_string()],
            conjunction: false,
            lossy_negation: false,
        });
    }
    // 2) "1 of <prefix>*" or "any of <prefix>*" — OR across matching blocks.
    let lower = cond.to_ascii_lowercase();
    for prefix in ["1 of ", "any of ", "one of "] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            let pat = rest.trim().trim_matches('"').trim_matches('\'');
            let needle = pat.trim_end_matches('*');
            let mut included = Vec::new();
            for k in blocks.keys() {
                if k.starts_with(needle) {
                    included.push(k.clone());
                }
            }
            if !included.is_empty() {
                return Ok(ConditionPlan {
                    include_blocks: included,
                    conjunction: false,
                    lossy_negation: false,
                });
            }
        }
    }
    // 3) "all of <prefix>*" — AND across matching blocks. The blocks are
    //    merged into a single compound rule downstream (`conjunction: true`);
    //    emitting them independently would drop the author's conjunction and
    //    leave each half firing on its own.
    for prefix in ["all of "] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            let pat = rest.trim().trim_matches('"').trim_matches('\'');
            let needle = pat.trim_end_matches('*');
            let mut included = Vec::new();
            for k in blocks.keys() {
                if k.starts_with(needle) {
                    included.push(k.clone());
                }
            }
            if !included.is_empty() {
                return Ok(ConditionPlan {
                    include_blocks: included,
                    conjunction: true,
                    lossy_negation: false,
                });
            }
        }
    }
    // 4) "X or Y" — union of two named blocks (OR semantics matches
    //    our flat rule emission perfectly).
    if let Some((left, right)) = lower.split_once(" or ")
        && !left.contains(" and ")
        && !right.contains(" and ")
    {
        let l = left.trim();
        let r = right.trim();
        if blocks.contains_key(l) && blocks.contains_key(r) {
            return Ok(ConditionPlan {
                include_blocks: vec![l.to_string(), r.to_string()],
                conjunction: false,
                lossy_negation: false,
            });
        }
    }
    // 5) "X and Y and not Z" — AND the known conjuncts, record that a
    //    negation was dropped so the caller can de-fang the rule.
    let parts: Vec<&str> = lower.split(" and ").collect();
    if parts.len() >= 2 {
        let mut included = Vec::new();
        let mut dropped_negation = false;
        for raw in parts {
            let p = raw.trim();
            if p.strip_prefix("not ").is_some() {
                dropped_negation = true;
                continue;
            }
            if blocks.contains_key(p) {
                included.push(p.to_string());
            }
        }
        if !included.is_empty() {
            let conjunction = included.len() > 1;
            return Ok(ConditionPlan {
                include_blocks: included,
                conjunction,
                lossy_negation: dropped_negation,
            });
        }
    }
    // 6) "selection and not filter" — emit selection, flagging the dropped
    //    filter (subsumed by (5) but kept for the trivial case).
    if let Some((left, _right)) = lower.split_once(" and not ")
        && blocks.contains_key(left.trim())
    {
        return Ok(ConditionPlan {
            include_blocks: vec![left.trim().to_string()],
            conjunction: false,
            lossy_negation: true,
        });
    }
    // 7) Single bare identifier that's a key.
    if blocks.contains_key(cond) {
        return Ok(ConditionPlan {
            include_blocks: vec![cond.to_string()],
            conjunction: false,
            lossy_negation: false,
        });
    }
    Err(format!("unsupported condition: {condition}"))
}

/// Translate a Sigma value that may carry `*` wildcards into an operator the
/// Aegis matcher can express, or `None` when it cannot.
///
/// Sigma treats `*` as a wildcard, so importing the value literally would look
/// for an actual asterisk in the request. The three expressible shapes map onto
/// our ops; an interior wildcard (`a*b`) has no equivalent and is dropped
/// rather than mistranslated.
fn normalise_glob(base_op: &str, value: &str) -> Option<(&'static str, String)> {
    // A regex value keeps its own semantics — `*` is a quantifier there.
    if base_op == "regex" {
        return Some(("regex", value.to_string()));
    }
    let lead = value.starts_with('*');
    let trail = value.ends_with('*');
    let core = value.trim_matches('*');
    if core.is_empty() {
        return None;
    }
    if core.contains('*') {
        // Interior wildcard: not expressible.
        return None;
    }
    let op = match (lead, trail) {
        (true, true) => "contains",
        (true, false) => "ends_with",
        (false, true) => "starts_with",
        (false, false) => {
            return Some((
                match base_op {
                    "contains" => "contains",
                    "starts_with" => "starts_with",
                    "ends_with" => "ends_with",
                    _ => "equals",
                },
                core.to_string(),
            ));
        }
    };
    Some((op, core.to_string()))
}

fn map_field(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    // Strip surrounding `cs(...)` Sigma generic-header wrap.
    let unwrapped = if let Some(inner) = n.strip_prefix("cs(").and_then(|s| s.strip_suffix(')')) {
        inner.to_string()
    } else {
        n.clone()
    };
    match unwrapped.as_str() {
        // URI variants.
        "c-uri" | "cs-uri" | "cs-uri-stem" | "uri" | "request" | "request_uri" | "url"
        | "request.uri" | "uri_path" => Some("path"),
        // Query.
        "cs-uri-query" | "c-uri-query" | "query" | "query_string" => Some("query"),
        // Method.
        "cs-method" | "method" => Some("method"),
        // User-Agent variants.
        "c-useragent" | "cs-user-agent" | "user-agent" | "useragent" | "user_agent" => {
            Some("user_agent")
        }
        // Host header.
        "cs-host" | "host" | "vhost" => Some("host"),
        // IP.
        "c-ip" | "src_ip" | "source_ip" | "client_ip" | "src" => Some("client_ip"),
        // Proxy access-log vocabulary (`logsource.category: proxy`). Same
        // HTTP request, different column names.
        "c-uri-extension" | "uri-extension" => Some("path"),
        "c-uri-stem" => Some("path"),
        "cs-uri-path" => Some("path"),
        "cs-referer" | "cs-referrer" | "c-referer" => Some("header:referer"),
        "cs-cookie" => Some("header:cookie"),
        "cs-bytes" | "sc-bytes" | "sc-status" | "time-taken" | "cs-version" => None,
        // Generic header mappings — map common Sigma names to header:*.
        "referer" | "referrer" => Some("header:referer"),
        "cookie" => Some("header:cookie"),
        "x-forwarded-for" => Some("header:x-forwarded-for"),
        "authorization" => Some("header:authorization"),
        "accept" => Some("header:accept"),
        "accept-language" => Some("header:accept-language"),
        "origin" => Some("header:origin"),
        "content-type" => Some("header:content-type"),
        _ => None,
    }
}

/// Extract `(raw_field, modifier)` from a Sigma `field|modifier` spec.
fn split_modifier(spec: &str) -> (&str, &str) {
    match spec.split_once('|') {
        Some((f, m)) => (f, m),
        None => (spec, ""),
    }
}

fn extract_values(node: &serde_yml::Value) -> Result<Vec<String>, String> {
    match node {
        serde_yml::Value::String(s) => Ok(vec![s.clone()]),
        serde_yml::Value::Bool(b) => Ok(vec![b.to_string()]),
        serde_yml::Value::Number(n) => Ok(vec![n.to_string()]),
        serde_yml::Value::Sequence(seq) => {
            let mut out = Vec::with_capacity(seq.len());
            for item in seq {
                match item {
                    serde_yml::Value::String(s) => out.push(s.clone()),
                    serde_yml::Value::Bool(b) => out.push(b.to_string()),
                    serde_yml::Value::Number(n) => out.push(n.to_string()),
                    _ => return Err("nested non-scalar list entry".into()),
                }
            }
            Ok(out)
        }
        _ => Err("non-scalar/non-list value".into()),
    }
}

fn level_to_aegis(level: Option<&str>) -> (&'static str, &'static str, Option<&'static str>) {
    match level.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => ("block", "critical", Some("enforce")),
        Some("high") => ("block", "high", Some("enforce")),
        Some("medium") => ("challenge", "medium", Some("enforce")),
        Some("low") | Some("informational") => ("log", "low", Some("shadow")),
        _ => ("challenge", "medium", Some("enforce")),
    }
}

fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if matches!(c, ' ' | '-' | '_' | '.') {
            out.push('_');
        }
    }
    if out.is_empty() { "rule".into() } else { out }
}

fn short_hash(s: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:x}", h.finish() & 0xffff_ffff)
}

/// Walk a directory of `*.yml` Sigma files, convert each, accumulate
/// rules + skip notes. Returns the consolidated [ConversionOutput].
/// Recursive — Sigma rule packs are nested by category/product.
pub fn convert_directory(root: &Path) -> std::io::Result<ConversionOutput> {
    let mut out = ConversionOutput {
        rules: Vec::new(),
        skipped: Vec::new(),
        tag_map: BTreeMap::new(),
    };
    // Silence panic backtraces during the walk — libyml panics on a few
    // malformed upstream rules are caught per-document (see walk) and
    // recorded as skips; we don't want their noise on the import log.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = walk(root, &mut out);
    std::panic::set_hook(prev_hook);
    result?;
    Ok(out)
}

fn walk(dir: &Path, out: &mut ConversionOutput) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out)?;
            continue;
        }
        if !matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml") | Some("yaml")
        ) {
            continue;
        }
        let source_file = path.display().to_string();
        let bytes = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Sigma files sometimes pack multiple rules with `---`
        // separators; handle both.
        for doc in bytes.split("\n---") {
            let trimmed = doc.trim_start_matches('-').trim();
            if trimmed.is_empty() {
                continue;
            }
            // SECURITY/ROBUSTNESS: serde_yml's libyml backend (RUSTSEC-2025-0067,
            // unsound) panics on some real-world Sigma YAML ("String join would
            // overflow memory bounds"). Catch it per-document so one malformed
            // upstream rule is skipped instead of aborting the whole import.
            let parsed =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse_yaml(trimmed)));
            match parsed {
                Ok(Ok(rule)) => match convert(&rule, &source_file) {
                    Ok(rules) => {
                        if let Some(id) = rule.id.clone() {
                            out.tag_map.insert(id, rule.title.clone());
                        }
                        out.rules.extend(rules);
                    }
                    Err(reason) => out.skipped.push(SkipNote {
                        source_file: source_file.clone(),
                        title: rule.title.clone(),
                        reason,
                    }),
                },
                Ok(Err(e)) => out.skipped.push(SkipNote {
                    source_file: source_file.clone(),
                    title: "<unparseable>".into(),
                    reason: e,
                }),
                Err(_) => out.skipped.push(SkipNote {
                    source_file: source_file.clone(),
                    title: "<panic>".into(),
                    reason: "yaml parser panicked (libyml unsoundness) — skipped".into(),
                }),
            }
        }
    }
    Ok(())
}

/// Render the converted rules as a TOML rule file compatible with
/// WafConfig.rule_files. Sorted by id for deterministic diffs.
pub fn render_toml(rules: &[WafRule]) -> String {
    let mut out = String::with_capacity(rules.len() * 120);
    out.push_str("# Auto-generated from Sigma rules.\n");
    out.push_str("# DO NOT EDIT BY HAND — re-run aegis-sigma-import.\n\n");
    let mut sorted: Vec<&WafRule> = rules.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    for r in sorted {
        out.push_str("[[rules]]\n");
        out.push_str(&format!("id = {}\n", toml_escape(&r.id)));
        out.push_str(&format!("field = {}\n", toml_escape(&r.field)));
        out.push_str(&format!("op = {}\n", toml_escape(&r.op)));
        out.push_str(&format!("value = {}\n", toml_escape(&r.value)));
        out.push_str(&format!("action = {}\n", toml_escape(&r.action)));
        if let Some(s) = &r.severity {
            out.push_str(&format!("severity = {}\n", toml_escape(s)));
        }
        if let Some(m) = &r.mode {
            out.push_str(&format!("mode = {}\n", toml_escape(m)));
        }
        if !r.tags.is_empty() {
            out.push_str("tags = [");
            for (i, t) in r.tags.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&toml_escape(t));
            }
            out.push_str("]\n");
        }
        // Compound AND constraints — one inline-table per group so the
        // emitted rule reproduces the Sigma selection's AND-of-(OR)
        // semantics. Empty all_of (legacy single-condition rules) emits
        // nothing, keeping the diff identical for those.
        for g in &r.all_of {
            out.push_str("[[rules.all_of]]\n");
            out.push_str(&format!("field = {}\n", toml_escape(&g.field)));
            out.push_str(&format!("op = {}\n", toml_escape(&g.op)));
            out.push_str("any_of = [");
            for (i, v) in g.any_of.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&toml_escape(v));
            }
            out.push_str("]\n");
        }
        out.push('\n');
    }
    out
}

fn toml_escape(s: &str) -> String {
    // Single-line basic string — escape backslash and quote.
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webserver_rule_yaml() -> &'static str {
        r#"
title: Webshell access attempt
id: 11111111-2222-3333-4444-555555555555
status: stable
description: Detects webshell access
author: test
tags:
  - attack.t1505
level: high
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains:
      - /shell.php
      - /cmd.jsp
    cs-method: GET
  condition: selection
"#
    }

    #[test]
    fn parses_a_real_looking_sigma_rule() {
        let r = parse_yaml(webserver_rule_yaml()).unwrap();
        assert_eq!(r.title, "Webshell access attempt");
        assert_eq!(r.level.as_deref(), Some("high"));
        assert_eq!(r.logsource.category.as_deref(), Some("webserver"));
        assert!(r.detection.blocks.contains_key("selection"));
        assert_eq!(r.detection.condition.trim(), "selection");
    }

    #[test]
    fn converts_to_compound_waf_rules() {
        let r = parse_yaml(webserver_rule_yaml()).unwrap();
        let rules = convert(&r, "test.yml").unwrap();
        // The selection ANDs `c-uri|contains: [/shell.php, /cmd.jsp]`
        // with `cs-method: GET`. The selective primary is `path`, so we
        // emit ONE rule per URI value (2), each carrying the method as an
        // all_of AND constraint — NOT three independent (broad) rules.
        assert_eq!(rules.len(), 2);
        for rule in &rules {
            assert_eq!(rule.action, "block");
            assert_eq!(rule.severity.as_deref(), Some("high"));
            assert!(rule.id.starts_with("sigma_"));
            // Primary trigger is the selective path field, never method.
            assert_eq!(rule.field, "path");
            assert_eq!(rule.op, "contains");
            // Method is preserved as an AND constraint, not a primary.
            assert_eq!(rule.all_of.len(), 1);
            assert_eq!(rule.all_of[0].field, "method");
            assert_eq!(rule.all_of[0].op, "equals");
            assert_eq!(rule.all_of[0].any_of, vec!["GET".to_string()]);
        }
        // Both URI list entries became per-value primaries.
        let values: std::collections::HashSet<_> = rules.iter().map(|r| r.value.as_str()).collect();
        assert!(values.contains("/shell.php"));
        assert!(values.contains("/cmd.jsp"));
    }

    #[test]
    fn method_only_selection_is_skipped() {
        // A bare `method == POST` selection is the exact FP rule that
        // broke the live site — it must be skipped, not emitted.
        let yaml = r#"
title: All POST requests
logsource:
  category: webserver
detection:
  selection:
    cs-method: POST
  condition: selection
"#;
        let r = parse_yaml(yaml).unwrap();
        let err = convert(&r, "x.yml").unwrap_err();
        assert_eq!(err, "too-broad-no-selective-field");
    }

    #[test]
    fn method_and_host_only_selection_is_skipped() {
        // method + host with no selective field is still too broad.
        let yaml = r#"
title: POST to host
logsource:
  category: webserver
detection:
  selection:
    cs-method: POST
    cs-host: api.example.com
  condition: selection
"#;
        let r = parse_yaml(yaml).unwrap();
        let err = convert(&r, "x.yml").unwrap_err();
        assert_eq!(err, "too-broad-no-selective-field");
    }

    #[test]
    fn list_values_become_per_value_primaries_and_any_of_groups() {
        // Primary list expands to one rule per value; a non-primary list
        // field collapses into a single any_of OR group shared by each.
        let yaml = r#"
title: Multi-value compound
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains:
      - /a
      - /b
      - /c
    cs-method:
      - GET
      - POST
  condition: selection
level: high
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        // 3 URI primaries (NOT 3 * 2), each with the method OR-group.
        assert_eq!(rules.len(), 3);
        let primaries: std::collections::HashSet<_> =
            rules.iter().map(|r| r.value.as_str()).collect();
        assert_eq!(primaries.len(), 3);
        assert!(primaries.contains("/a"));
        assert!(primaries.contains("/b"));
        assert!(primaries.contains("/c"));
        for rule in &rules {
            assert_eq!(rule.field, "path");
            assert_eq!(rule.all_of.len(), 1);
            let g = &rule.all_of[0];
            assert_eq!(g.field, "method");
            assert_eq!(g.op, "equals");
            assert_eq!(g.any_of, vec!["GET".to_string(), "POST".to_string()]);
        }
    }

    #[test]
    fn query_is_preferred_over_uri_as_primary() {
        // When both query and uri are present, query (more selective)
        // wins the primary slot; uri drops into all_of.
        let yaml = r#"
title: Query primary
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains: id=1 OR 1=1
    c-uri|contains: /search
  condition: selection
level: high
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].field, "query");
        assert_eq!(rules[0].value, "id=1 OR 1=1");
        assert_eq!(rules[0].all_of.len(), 1);
        assert_eq!(rules[0].all_of[0].field, "path");
    }

    #[test]
    fn skips_non_webserver_rule() {
        let yaml = r#"
title: SSH brute force
logsource:
  product: linux
  service: auth
detection:
  selection:
    program: sshd
  condition: selection
"#;
        let r = parse_yaml(yaml).unwrap();
        assert!(!is_http_edge_rule(&r));
        let err = convert(&r, "x.yml").unwrap_err();
        assert!(err.contains("not an HTTP-edge rule"));
    }

    /// Proxy access-log rules describe the same HTTP request a reverse proxy
    /// sees, so they must convert — this is where the hack-tool / exploit-
    /// framework User-Agent corpus lives.
    #[test]
    fn converts_proxy_category_user_agent_rule() {
        let yaml = r#"
title: Hack Tool User Agent
id: 11111111-2222-3333-4444-555555555555
level: high
logsource:
  category: proxy
detection:
  selection:
    c-useragent|contains:
      - 'sqlmap/'
      - 'nikto/'
  condition: selection
"#;
        let r = parse_yaml(yaml).unwrap();
        assert!(is_http_edge_rule(&r));
        let rules = convert(&r, "proxy_ua_hacktool.yml").unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.field == "user_agent"));
        assert!(rules.iter().all(|r| r.op == "contains"));
        assert!(rules.iter().any(|r| r.value == "sqlmap/"));
    }

    /// `c-uri-extension` carries a bare extension ("exe"), not a path. Mapping
    /// it straight onto `path` with `equals` would emit a rule that can never
    /// match a real request path, so it becomes a suffix test instead.
    #[test]
    fn uri_extension_becomes_path_suffix() {
        let yaml = r#"
title: Executable download
id: 66666666-7777-8888-9999-000000000000
level: low
logsource:
  category: proxy
detection:
  selection:
    c-uri-extension:
      - 'exe'
      - 'dll'
  condition: selection
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "proxy_download.yml").unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.field == "path"));
        assert!(rules.iter().all(|r| r.op == "ends_with"));
        assert!(rules.iter().any(|r| r.value == ".exe"));
        assert!(rules.iter().any(|r| r.value == ".dll"));
    }

    #[test]
    fn handles_apache_product() {
        let yaml = r#"
title: Suspicious Apache request
logsource:
  product: apache
detection:
  selection:
    c-useragent|contains: sqlmap
  condition: selection
level: critical
"#;
        let r = parse_yaml(yaml).unwrap();
        assert!(is_webserver_rule(&r));
        let rules = convert(&r, "x.yml").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].field, "user_agent");
        assert_eq!(rules[0].op, "contains");
        assert_eq!(rules[0].action, "block");
    }

    #[test]
    fn handles_one_of_condition() {
        let yaml = r#"
title: Multi-selection rule
logsource:
  category: webserver
detection:
  selection_uri:
    c-uri|contains: /.env
  selection_ua:
    c-useragent|contains: nikto
  condition: 1 of selection_*
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        // 2 rules from 2 selection blocks
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn header_mapping_recognises_cs_wrapper() {
        let yaml = r#"
title: Bad referer
logsource:
  category: webserver
detection:
  selection:
    'cs(Referer)|contains': evil.example
  condition: selection
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        assert_eq!(rules[0].field, "header:referer");
    }

    #[test]
    fn condition_and_not_filter_keeps_selection() {
        let yaml = r#"
title: AND-NOT rule
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains: /admin
  filter:
    c-ip: 10.0.0.1
  condition: selection and not filter
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].field, "path");
    }

    #[test]
    fn unsupported_modifier_errors_clearly() {
        let yaml = r#"
title: Weird modifier
logsource:
  category: webserver
detection:
  selection:
    c-uri|hexencode: dGVzdA==
  condition: selection
"#;
        let r = parse_yaml(yaml).unwrap();
        let err = convert(&r, "x.yml").unwrap_err();
        assert!(err.contains("unsupported modifier"), "got: {err}");
    }

    #[test]
    fn stacked_modifier_chain_picks_primary() {
        // Sigma allows `field|contains|all` — we extract the
        // primary op (contains) and ignore the meta modifier (all).
        let yaml = r#"
title: Stacked modifier
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains|all:
      - /admin
      - /backup
  condition: selection
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.op == "contains"));
    }

    #[test]
    fn keywords_block_emits_path_contains() {
        let yaml = r#"
title: LFI keywords
logsource:
  category: webserver
detection:
  keywords:
    - ../etc/passwd
    - /proc/self/environ
  condition: keywords
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.field == "path"));
        assert!(rules.iter().all(|r| r.op == "contains"));
    }

    #[test]
    fn or_between_two_blocks() {
        let yaml = r#"
title: Or test
logsource:
  category: webserver
detection:
  selection1:
    c-uri|contains: /a
  selection2:
    c-uri|contains: /b
  condition: selection1 or selection2
"#;
        let r = parse_yaml(yaml).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn level_critical_maps_to_block_enforce() {
        let (action, severity, mode) = level_to_aegis(Some("critical"));
        assert_eq!(action, "block");
        assert_eq!(severity, "critical");
        assert_eq!(mode, Some("enforce"));
    }

    #[test]
    fn level_low_maps_to_log_shadow() {
        let (action, _, mode) = level_to_aegis(Some("low"));
        assert_eq!(action, "log");
        assert_eq!(mode, Some("shadow"));
    }

    #[test]
    fn render_toml_round_trips_through_parser() {
        let r = parse_yaml(webserver_rule_yaml()).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        let toml_str = render_toml(&rules);
        assert!(toml_str.contains("[[rules]]"));
        // Compound constraints must round-trip into the TOML.
        assert!(toml_str.contains("[[rules.all_of]]"));
        assert!(toml_str.contains("any_of = ["));
        let parsed: toml::Value = toml::from_str(&toml_str).unwrap();
        let rules_arr = parsed.get("rules").and_then(|v| v.as_array()).unwrap();
        // 2 URI primaries (compound), down from the old flattened 3.
        assert_eq!(rules_arr.len(), 2);
        // First rule carries its method all_of group.
        let all_of = rules_arr[0]
            .get("all_of")
            .and_then(|v| v.as_array())
            .expect("all_of present");
        assert_eq!(all_of.len(), 1);
        assert_eq!(
            all_of[0].get("field").and_then(|v| v.as_str()),
            Some("method")
        );
    }

    #[test]
    fn render_toml_round_trips_into_waf_rule_file() {
        // The generated TOML must deserialize back into WafRule with the
        // compound all_of intact (the shape aegis-sigma-import writes and
        // the proxy loads via waf.rule_files).
        let r = parse_yaml(webserver_rule_yaml()).unwrap();
        let rules = convert(&r, "x.yml").unwrap();
        let toml_str = render_toml(&rules);
        let parsed: crate::config::WafRuleFile = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.rules.len(), 2);
        assert!(parsed.rules.iter().all(|r| r.field == "path"));
        assert!(parsed.rules.iter().all(|r| r.all_of.len() == 1));
        assert_eq!(parsed.rules[0].all_of[0].field, "method");
    }

    #[test]
    fn convert_directory_processes_nested_tree() {
        let tmp = std::env::temp_dir().join(format!("aegis-sigma-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let sub = tmp.join("webserver");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("a.yml"), webserver_rule_yaml()).unwrap();
        std::fs::write(
            sub.join("b.yml"),
            r#"
title: Other rule
logsource:
  category: webserver
detection:
  selection:
    cs-method: POST
  condition: selection
"#,
        )
        .unwrap();
        std::fs::write(
            sub.join("c.yml"),
            r#"
title: Skip me
logsource:
  product: linux
detection:
  selection:
    foo: bar
  condition: selection
"#,
        )
        .unwrap();
        let out = convert_directory(&tmp).unwrap();
        // a.yml -> 2 compound URI rules. b.yml (method-only POST) is now
        // SKIPPED as too-broad. c.yml (linux) skipped as non-webserver.
        assert_eq!(out.rules.len(), 2);
        assert!(out.rules.iter().all(|r| r.field == "path"));
        assert_eq!(out.skipped.len(), 2);
        let reasons: Vec<&str> = out.skipped.iter().map(|s| s.reason.as_str()).collect();
        assert!(reasons.iter().any(|r| r.contains("not an HTTP-edge rule")));
        assert!(reasons.contains(&"too-broad-no-selective-field"));
        std::fs::remove_dir_all(&tmp).ok();
    }
}
