//! V99 — Self-improving signature mining (Phase E.4).
//!
//! Takes a corpus of attack payloads (tarpit / honeypot logs) and
//! extracts repeated byte n-grams that occur frequently across attacks
//! but rarely in clean traffic. The output is a list of
//! [SignatureCandidate]s ranked by confidence — operators review and
//! promote them into the WAF rules file.
//!
//! Design choices
//! --------------
//! * Pure-stdlib + byte-level n-gram extraction (no regex / parser
//!   crate). Fits in one file.
//! * N-gram length range is [4, 16] — short enough to catch common
//!   attack tokens (`/etc/passwd`, `<script>`, `union sel`), long
//!   enough to avoid trigram garbage.
//! * Confidence = `attack_support × (1 - benign_support)` where
//!   support is the fraction of corpora the n-gram appears in.
//!   Pure attack-only patterns score ≈1.0; n-grams common in benign
//!   traffic score ≈0.
//! * Lowercase + trim before mining so attack variants like
//!   `UNION SELECT` vs `union select` collapse into one candidate.
//!
//! What this is NOT
//! ----------------
//! * Not a write-back path. Approved signatures land in the operator's
//!   WAF rule file via copy-paste from the admin response, intentionally
//!   — auto-writing to WAF config from miner output is too sharp an
//!   edge for any prod deployment.
//! * Not online / streaming. Miner runs as a discrete admin request on
//!   a supplied corpus. Streaming version is V101+ scope.

use std::collections::HashMap;

/// Bounds on n-gram length. 4 catches `1=1<`, `<scr`, `etc/`; 16 is
/// enough for whole `union all select` style multi-word tokens.
const MIN_N: usize = 4;
const MAX_N: usize = 16;

/// Maximum number of candidates returned. Bounded so a giant corpus
/// can't produce an unreadable admin response.
const MAX_CANDIDATES: usize = 50;

#[derive(Debug, Clone, PartialEq)]
pub struct SignatureCandidate {
    pub ngram: String,
    pub confidence: f32,
    pub attack_support: f32,
    pub benign_support: f32,
    pub suggested_category: &'static str,
}

/// Mine signature candidates from `attacks` (suspicious payloads)
/// using `benign` as a contrast set (clean traffic samples).
///
/// Returns up to [MAX_CANDIDATES] candidates ranked by confidence.
/// Empty inputs return empty output.
pub fn mine(attacks: &[String], benign: &[String]) -> Vec<SignatureCandidate> {
    if attacks.is_empty() {
        return Vec::new();
    }

    let attack_norm: Vec<String> = attacks.iter().map(|s| normalise(s)).collect();
    let benign_norm: Vec<String> = benign.iter().map(|s| normalise(s)).collect();

    // Count how many DOCUMENTS each n-gram appears in (document
    // frequency, not term frequency) for both corpora. Document
    // frequency is what gives us "this n-gram is characteristic of
    // attacks", not "this attack used the n-gram 1000 times".
    let attack_df = document_frequency(&attack_norm);
    let benign_df = document_frequency(&benign_norm);

    let a_total = attack_norm.len() as f32;
    let b_total = benign_norm.len().max(1) as f32;

    let mut candidates: Vec<SignatureCandidate> = attack_df
        .into_iter()
        // Require the n-gram to appear in at least 2 attacks AND in at
        // least 25% of them. Single-attack patterns are too narrow;
        // <25% support means it's an outlier, not a signature.
        .filter(|(_, count)| *count >= 2 && (*count as f32 / a_total) >= 0.25)
        .map(|(ngram, attack_count)| {
            let attack_support = attack_count as f32 / a_total;
            let benign_support = benign_df.get(&ngram).copied().unwrap_or(0) as f32 / b_total;
            // Penalise n-grams common in benign traffic.
            let confidence = attack_support * (1.0 - benign_support).clamp(0.0, 1.0);
            let suggested_category = guess_category(&ngram);
            SignatureCandidate {
                ngram,
                confidence,
                attack_support,
                benign_support,
                suggested_category,
            }
        })
        .collect();

    // Primary: confidence descending. Secondary: ngram length
    // descending so when several candidates tie on confidence
    // (common with low-document-count corpora) the longer pattern
    // wins, which gives the dedup pass below a stable longest-first
    // ordering to collapse substring chains.
    candidates.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.ngram.len().cmp(&a.ngram.len()))
            .then_with(|| a.ngram.cmp(&b.ngram))
    });
    candidates.truncate(MAX_CANDIDATES * 8);

    // Greedy de-duplication: drop any candidate that is a substring of
    // a kept-longer candidate. Walks the sorted list (longest first
    // within each confidence bucket) so the kept set is the maximal
    // patterns. Also drops candidates that strictly contain a kept
    // shorter pattern that has higher confidence — but since the
    // primary sort is by confidence, "higher confidence" candidates
    // are always processed first, so this is just substring containment.
    let mut deduped: Vec<SignatureCandidate> = Vec::new();
    for c in candidates {
        let dominated = deduped
            .iter()
            .any(|d| d.ngram.contains(&c.ngram) || c.ngram.contains(&d.ngram));
        if !dominated {
            deduped.push(c);
        }
        if deduped.len() >= MAX_CANDIDATES {
            break;
        }
    }
    deduped
}

/// Lowercase + collapse whitespace so attack variants normalise to
/// the same form. Doesn't URL-decode — let the WAF's `canon()` do
/// that at match time so the same payload form ends up in the rules
/// file and the canonicalised request.
fn normalise(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_ws = false;
    for c in lower.chars() {
        let ws = c.is_whitespace();
        if ws && prev_ws {
            continue;
        }
        out.push(if ws { ' ' } else { c });
        prev_ws = ws;
    }
    out.trim().to_string()
}

/// For each unique n-gram in `corpus`, count how many distinct
/// documents contain it. Iterates each doc once, building a per-doc
/// HashSet so duplicates within a doc don't double-count.
fn document_frequency(corpus: &[String]) -> HashMap<String, u32> {
    let mut df: HashMap<String, u32> = HashMap::new();
    for doc in corpus {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let bytes = doc.as_bytes();
        for n in MIN_N..=MAX_N.min(bytes.len()) {
            if bytes.len() < n {
                break;
            }
            for win in bytes.windows(n) {
                // Skip n-grams with non-ASCII control or pure-whitespace
                // content — they're noise for signature purposes.
                if win.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                if let Ok(s) = std::str::from_utf8(win) {
                    seen.insert(s.to_string());
                }
            }
        }
        for k in seen {
            *df.entry(k).or_insert(0) += 1;
        }
    }
    df
}

/// Best-effort category guess based on token shape. Operator can
/// override when promoting to a WAF rule.
fn guess_category(ngram: &str) -> &'static str {
    let s = ngram;
    if s.contains("union")
        || s.contains("select")
        || s.contains("information_schema")
        || s.contains("sleep(")
        || s.contains("' or ")
        || s.contains("1=1")
    {
        return "sqli";
    }
    if s.contains("<script")
        || s.contains("javascript:")
        || s.contains("onerror=")
        || s.contains("onload=")
    {
        return "xss";
    }
    if s.contains("/etc/")
        || s.contains("../../")
        || s.contains("..\\..\\")
        || s.contains("/proc/self/")
    {
        return "path_traversal";
    }
    if s.contains("|bash")
        || s.contains("|sh")
        || s.contains(";cat ")
        || s.contains("&&rm ")
        || s.contains("/bin/sh")
    {
        return "cmdi";
    }
    if s.contains("169.254.169.254") || s.contains("file://") || s.contains("gopher://") {
        return "ssrf";
    }
    "custom"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mines_obvious_sqli_signature() {
        let attacks: Vec<String> = vec![
            "/api/users?id=1' union select 1,2,3-- ".to_string(),
            "/login?u=a' union select * from users-- ".to_string(),
            "/?q=foo' union select null,version()--".to_string(),
            "/?id=99' UNION SELECT password FROM admins --".to_string(),
        ];
        let benign: Vec<String> = vec![
            "/api/users".to_string(),
            "/login".to_string(),
            "/index.html".to_string(),
            "/static/app.js".to_string(),
        ];
        let cands = mine(&attacks, &benign);
        assert!(!cands.is_empty(), "expected at least one candidate");
        // Top candidate must contain the union-select token.
        assert!(
            cands[0].ngram.contains("union") || cands[0].ngram.contains("select"),
            "top candidate should be sqli-shaped, got {:?}",
            cands[0]
        );
        assert_eq!(cands[0].suggested_category, "sqli");
    }

    #[test]
    fn rejects_ngrams_common_in_benign() {
        let attacks: Vec<String> = vec![
            "/login?next=/dashboard".to_string(),
            "/login?next=/profile".to_string(),
            "/login?next=/billing".to_string(),
        ];
        let benign: Vec<String> = vec![
            "/login?next=/home".to_string(),
            "/login?next=/help".to_string(),
            "/login?next=/about".to_string(),
            "/login?next=/contact".to_string(),
        ];
        let cands = mine(&attacks, &benign);
        // The shared prefix "/login?next=/" appears in BOTH corpora
        // → benign_support ≈ 1.0 → confidence ≈ 0 → filtered or
        // ranked very low. Top candidate (if any) should have low
        // confidence.
        if let Some(top) = cands.first() {
            assert!(
                top.confidence < 0.5,
                "shared-with-benign pattern shouldn't dominate, got {top:?}"
            );
        }
    }

    #[test]
    fn deduplicates_substring_candidates() {
        // Mix in payload variation so sibling 16-windows have
        // different document supports (matches real attack corpora —
        // pure repeats are degenerate and the dedup pass is only
        // expected to collapse strict substring chains, not arbitrary
        // overlapping siblings).
        let attacks: Vec<String> = vec![
            "<script>alert(1)</script>".to_string(),
            "<script>alert(2)</script>".to_string(),
            "<script>alert(/xss/)</script>".to_string(),
            "<script>alert(document.cookie)</script>".to_string(),
            "<script>alert('owned')</script>".to_string(),
        ];
        let cands = mine(&attacks, &[]);
        // The shared prefix `<script>alert(` is present in ALL docs,
        // so it should appear as a top candidate. After dedup, no
        // strict substring of any kept candidate should also be kept.
        for (i, a) in cands.iter().enumerate() {
            for b in cands.iter().skip(i + 1) {
                assert!(
                    !a.ngram.contains(&b.ngram) && !b.ngram.contains(&a.ngram),
                    "dedup violated: {:?} and {:?} share substring relation",
                    a.ngram,
                    b.ngram,
                );
            }
        }
        // The script>alert( token must show up somewhere in top-5.
        let top5: Vec<&str> = cands.iter().take(5).map(|c| c.ngram.as_str()).collect();
        assert!(
            top5.iter().any(|s| s.contains("script>alert")),
            "expected `<script>alert(` family in top-5, got {top5:?}"
        );
    }

    #[test]
    fn empty_attacks_returns_empty() {
        let cands = mine(&[], &["/login".to_string()]);
        assert!(cands.is_empty());
    }

    #[test]
    fn single_attack_filtered_out() {
        // Single attack → no document-frequency support → no candidates.
        let cands = mine(&["' or 1=1--".to_string()], &[]);
        assert!(
            cands.is_empty(),
            "single-doc support is below the threshold"
        );
    }

    #[test]
    fn category_guesser_classifies_correctly() {
        assert_eq!(guess_category("union select"), "sqli");
        assert_eq!(guess_category("<script>alert"), "xss");
        assert_eq!(guess_category("/etc/passwd"), "path_traversal");
        assert_eq!(guess_category("|bash -c"), "cmdi");
        assert_eq!(guess_category("169.254.169.254/latest"), "ssrf");
        assert_eq!(guess_category("plain text"), "custom");
    }
}
