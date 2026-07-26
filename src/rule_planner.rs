//! V181 — Coraza-style phase-indexed compiled rule plan.
//!
//! Real-world WAF deployments accumulate dozens to hundreds of
//! wirefilter expressions over time. Serially evaluating each against
//! every request is wasteful: most rules only touch one phase
//! (headers / URI / body / response) and most fields are touched by
//! at most a handful of rules.
//!
//! The planner bucketises compiled rules into phase-keyed dispatch
//! tables. At request time we visit only the buckets relevant to the
//! data we've already parsed (e.g., body bucket skipped on bodyless
//! requests; response bucket skipped on early-deny paths).
//!
//! Plan shape:
//!
//! ```text
//!     Phase::RequestUriOrQuery → [rule_id, rule_id, …]
//!     Phase::RequestHeaders    → [rule_id, …]
//!     Phase::RequestBody       → [rule_id, …]
//!     Phase::ResponseHeaders   → [rule_id, …]
//!     Phase::ResponseBody      → [rule_id, …]
//! ```
//!
//! Each rule is also tagged with the *field names* it references so
//! the runner can further skip rules whose field set isn't present
//! (e.g., a rule against `http.request.body.form.password` skips for
//! every GET).
//!
//! This module is intentionally engine-agnostic — it operates on
//! [RuleDescriptor] structs that the wirefilter compiler (or any
//! other rule source) populates. Keeps the planner unit-testable
//! without dragging in the wirefilter dep.

use std::collections::{BTreeMap, BTreeSet};

// V230 — FxHash for internal u32-keyed maps. Rule IDs are operator-assigned
// and never attacker-controlled, so the DoS-resistance of SipHash is wasted
// overhead here. FxHash on u32 is ~5x faster.
use rustc_hash::FxHashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    RequestUriOrQuery,
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
}

#[derive(Debug, Clone)]
pub struct RuleDescriptor {
    pub id: u32,
    pub name: String,
    pub fields: BTreeSet<String>,
    pub severity: u8, // 1..5
}

impl RuleDescriptor {
    /// Infer phase set from referenced field names. Conservative —
    /// unknown prefixes don't add phases (they'll be evaluated under
    /// RequestHeaders by default as a catch-all).
    pub fn phases(&self) -> BTreeSet<Phase> {
        let mut out = BTreeSet::new();
        for f in &self.fields {
            if f.starts_with("http.request.uri") || f.starts_with("http.request.query") {
                out.insert(Phase::RequestUriOrQuery);
            } else if f.starts_with("http.request.headers") {
                out.insert(Phase::RequestHeaders);
            } else if f.starts_with("http.request.body") {
                out.insert(Phase::RequestBody);
            } else if f.starts_with("http.response.headers") {
                out.insert(Phase::ResponseHeaders);
            } else if f.starts_with("http.response.body") {
                out.insert(Phase::ResponseBody);
            }
        }
        if out.is_empty() {
            out.insert(Phase::RequestHeaders);
        }
        out
    }
}

#[derive(Debug, Default)]
pub struct RulePlan {
    by_phase: BTreeMap<Phase, Vec<u32>>,
    // V230 — FxHashMap: u32 rule IDs are non-adversarial.
    by_id: FxHashMap<u32, RuleDescriptor>,
    /// Per-rule field set for skip-if-not-present checks.
    // V230 — FxHashMap: u32 rule IDs are non-adversarial.
    fields_by_id: FxHashMap<u32, BTreeSet<String>>,
}

impl RulePlan {
    pub fn from_rules<I: IntoIterator<Item = RuleDescriptor>>(rules: I) -> Self {
        let mut plan = Self::default();
        for rule in rules {
            for phase in rule.phases() {
                plan.by_phase.entry(phase).or_default().push(rule.id);
            }
            plan.fields_by_id.insert(rule.id, rule.fields.clone());
            plan.by_id.insert(rule.id, rule);
        }
        // Sort each bucket by severity DESC so highest-severity hits
        // surface first when the runner short-circuits.
        for ids in plan.by_phase.values_mut() {
            ids.sort_by(|a, b| {
                let sa = plan.by_id.get(a).map(|r| r.severity).unwrap_or(0);
                let sb = plan.by_id.get(b).map(|r| r.severity).unwrap_or(0);
                sb.cmp(&sa).then(a.cmp(b))
            });
        }
        plan
    }

    pub fn rules_for_phase(&self, phase: Phase) -> &[u32] {
        self.by_phase.get(&phase).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Filter the bucket further by which fields are actually
    /// populated for this request. `available_fields` is supplied by
    /// the runner.
    pub fn rules_for_phase_with_fields(
        &self,
        phase: Phase,
        available_fields: &BTreeSet<String>,
    ) -> Vec<u32> {
        self.rules_for_phase(phase)
            .iter()
            .copied()
            .filter(|id| {
                self.fields_by_id
                    .get(id)
                    .map(|fields| fields.is_subset(available_fields) || fields.is_empty())
                    .unwrap_or(true)
            })
            .collect()
    }

    pub fn descriptor(&self, id: u32) -> Option<&RuleDescriptor> {
        self.by_id.get(&id)
    }

    pub fn total_rules(&self) -> usize {
        self.by_id.len()
    }

    pub fn phase_count(&self) -> usize {
        self.by_phase.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: u32, fields: &[&str], severity: u8) -> RuleDescriptor {
        RuleDescriptor {
            id,
            name: format!("rule_{id}"),
            fields: fields.iter().map(|s| s.to_string()).collect(),
            severity,
        }
    }

    #[test]
    fn buckets_by_phase() {
        let plan = RulePlan::from_rules(vec![
            rule(1, &["http.request.uri.path"], 3),
            rule(2, &["http.request.body.raw"], 5),
            rule(3, &["http.request.headers.cookie"], 2),
            rule(4, &["http.response.headers.server"], 1),
        ]);
        assert_eq!(plan.rules_for_phase(Phase::RequestUriOrQuery), [1]);
        assert_eq!(plan.rules_for_phase(Phase::RequestBody), [2]);
        assert_eq!(plan.rules_for_phase(Phase::RequestHeaders), [3]);
        assert_eq!(plan.rules_for_phase(Phase::ResponseHeaders), [4]);
    }

    #[test]
    fn severity_orders_within_bucket() {
        let plan = RulePlan::from_rules(vec![
            rule(1, &["http.request.uri.path"], 2),
            rule(2, &["http.request.uri.path"], 5),
            rule(3, &["http.request.uri.path"], 3),
        ]);
        let ids = plan.rules_for_phase(Phase::RequestUriOrQuery);
        assert_eq!(ids, [2, 3, 1]);
    }

    #[test]
    fn rule_touching_multiple_phases_indexed_in_all() {
        let plan = RulePlan::from_rules(vec![rule(
            1,
            &["http.request.uri.path", "http.request.body.raw"],
            3,
        )]);
        assert_eq!(plan.rules_for_phase(Phase::RequestUriOrQuery), [1]);
        assert_eq!(plan.rules_for_phase(Phase::RequestBody), [1]);
    }

    #[test]
    fn field_filter_skips_when_field_missing() {
        let plan = RulePlan::from_rules(vec![rule(1, &["http.request.body.form.password"], 5)]);
        let no_body: BTreeSet<String> = BTreeSet::new();
        let with_body: BTreeSet<String> = ["http.request.body.form.password"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(
            plan.rules_for_phase_with_fields(Phase::RequestBody, &no_body)
                .is_empty()
        );
        assert_eq!(
            plan.rules_for_phase_with_fields(Phase::RequestBody, &with_body),
            [1]
        );
    }

    #[test]
    fn fieldless_rule_goes_to_headers_bucket() {
        let plan = RulePlan::from_rules(vec![rule(1, &[], 3)]);
        assert_eq!(plan.rules_for_phase(Phase::RequestHeaders), [1]);
    }
}
