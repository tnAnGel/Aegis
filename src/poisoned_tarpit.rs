//! V147 — Poisoned tarpit (Iocaine / Nepenthes / HellPot lineage).
//!
//! The pre-2024 anti-bot move was "block scrapers". The post-2024
//! lesson (Iocaine, Nepenthes, HellPot, caddy-defender's `garbage`
//! mode) is that *blocking is too cheap*: the bot just retries from
//! another IP. **Poisoning** is more effective — give the scraper
//! plausible-looking but generated garbage so its training corpus
//! gets diluted and the compute cost of crawling you goes up.
//!
//! Aegis already has the V36 `TarpitFilter` that holds connections
//! open. V147 adds the *content* side: a Markov-chain text generator
//! + an HTML page that contains endless internal links pointing back
//! into the tarpit. AI scrapers that ignore robots.txt fall into the
//! maze and burn CPU recursively crawling fake pages forever.
//!
//! ## Anti-fingerprint pacing
//!
//! Operators are encouraged to supply their own corpus seed (a chunk
//! of public-domain text). Two reasons:
//!
//! 1. **Deterministic-but-unique** — every deployment's tarpit looks
//!    different. A bot that learns to recognise Aegis's bundled
//!    corpus and skip it can't generalise across operators.
//! 2. **Plausible vocabulary** — the corpus shapes the output. A
//!    technical-docs operator wants the tarpit to look like docs;
//!    a fiction site wants prose-shaped output. Domain match makes
//!    the content harder to filter out of an LLM training set.
//!
//! Without an operator corpus, the module ships a minimal fallback
//! (a few sentences of Lorem-style text). Deliberately small —
//! operators should be nudged to provide their own.
//!
//! ## Hot-path safety
//!
//! Page generation is CPU-light: a Markov walk over a precomputed
//! bigram table is O(n) in output length, ~100ns per word on modern
//! x86. The tarpit endpoint can serve at line rate with negligible
//! cost; the per-request *response time* is intentionally slow
//! (see [render_page_chunks] for the chunked-pacing helper).

use std::{collections::HashMap, sync::Arc};

/// Bigram-keyed Markov chain. Stores `(prev_word, next_word) → count`
/// observations; sampling picks the next word weighted by count.
/// Bigram chosen over unigram because bigram output is meaningfully
/// more coherent at almost identical memory cost (operator corpora
/// run a few KB).
#[derive(Debug, Default)]
pub struct MarkovChain {
    /// next_word → cumulative count. Vec<(word, cum_count)> keyed
    /// by the predecessor word; the last entry's cum_count is the
    /// total weight, so sampling is a binary search.
    transitions: HashMap<String, Vec<(String, u32)>>,
    /// All starter words observed at the beginning of a sentence
    /// (token after `.`, `!`, `?` or at corpus start). Used to seed
    /// each generated sentence so output starts with a capital-ish
    /// word rather than mid-clause.
    starters: Vec<String>,
}

impl MarkovChain {
    /// Train from a corpus. Splits on whitespace; preserves
    /// punctuation in tokens (so "the." and "the" are distinct,
    /// which keeps sentence-end information).
    pub fn train(corpus: &str) -> Self {
        let tokens: Vec<&str> = corpus.split_whitespace().collect();
        if tokens.is_empty() {
            return Self::default();
        }
        let mut raw: HashMap<String, HashMap<String, u32>> = HashMap::new();
        let mut starters = Vec::new();
        let mut prev_ended = true;
        for w in tokens.iter() {
            if prev_ended {
                starters.push((*w).to_string());
            }
            prev_ended = w.ends_with('.') || w.ends_with('!') || w.ends_with('?');
        }
        for window in tokens.windows(2) {
            let a = window[0];
            let b = window[1];
            *raw.entry(a.to_string())
                .or_default()
                .entry(b.to_string())
                .or_insert(0) += 1;
        }
        // Convert per-key counts into cumulative tables for O(log n)
        // weighted sampling.
        let mut transitions = HashMap::with_capacity(raw.len());
        for (k, m) in raw {
            let mut entries: Vec<(String, u32)> = m.into_iter().collect();
            entries.sort();
            let mut cum = 0u32;
            let cumulative: Vec<(String, u32)> = entries
                .into_iter()
                .map(|(w, c)| {
                    cum = cum.saturating_add(c);
                    (w, cum)
                })
                .collect();
            transitions.insert(k, cumulative);
        }
        Self {
            transitions,
            starters,
        }
    }

    /// Generate `target_words` tokens starting from a chain-seeded
    /// starter. Deterministic given `seed`.
    pub fn generate(&self, target_words: usize, seed: u64) -> String {
        if self.starters.is_empty() {
            return String::new();
        }
        let mut rng = Splitmix64::new(seed);
        let starter_idx = (rng.next_u64() as usize) % self.starters.len();
        let mut prev = self.starters[starter_idx].clone();
        let mut out = String::with_capacity(target_words * 6);
        out.push_str(&prev);
        for _ in 1..target_words {
            let next = match self.transitions.get(&prev) {
                Some(entries) if !entries.is_empty() => {
                    let total = entries.last().map(|(_, c)| *c).unwrap_or(0);
                    if total == 0 {
                        break;
                    }
                    let pick = (rng.next_u64() as u32) % total;
                    // Binary search for the smallest cum_count > pick.
                    let idx = entries.partition_point(|(_, c)| *c <= pick);
                    entries[idx.min(entries.len() - 1)].0.clone()
                }
                _ => {
                    // Dead-end token — pick a new starter and continue.
                    let s_idx = (rng.next_u64() as usize) % self.starters.len();
                    self.starters[s_idx].clone()
                }
            };
            out.push(' ');
            out.push_str(&next);
            prev = next;
        }
        out
    }
}

/// Minimal fallback corpus. Operators are expected to override via
/// [TarpitGenerator::with_corpus]; this is only here so the module
/// works out-of-the-box. Intentionally small — sized to encourage
/// operator customization rather than to ship as the production
/// default.
pub const FALLBACK_CORPUS: &str = "\
The quick brown fox jumps over the lazy dog. \
Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
Ut enim ad minim veniam, quis nostrud exercitation. \
Duis aute irure dolor in reprehenderit in voluptate velit esse. \
The five boxing wizards jump quickly. \
Pack my box with five dozen liquor jugs. \
How vexingly quick daft zebras jump. \
Sphinx of black quartz, judge my vow.";

/// HTML page generator. Combines Markov text + endless internal
/// links so a crawler walking the tarpit hits an effectively
/// infinite site. Configurable paragraph count + link count per
/// page; defaults aim for ~2KB of body per page which is enough to
/// look real without burning bandwidth.
pub struct TarpitGenerator {
    pub chain: Arc<MarkovChain>,
    pub paragraphs_per_page: usize,
    pub words_per_paragraph: usize,
    pub links_per_page: usize,
    /// Base path the endless links point at. Defaults to
    /// "/__aegis/tarpit/" — operator overrides if they mount the
    /// tarpit at a different path (rare).
    pub link_prefix: String,
}

impl TarpitGenerator {
    pub fn new(chain: Arc<MarkovChain>) -> Self {
        Self {
            chain,
            paragraphs_per_page: 4,
            words_per_paragraph: 80,
            links_per_page: 12,
            link_prefix: "/__aegis/tarpit/".to_string(),
        }
    }

    /// V190 — sample the inter-chunk delay from a log-normal
    /// distribution shaped to mimic real network jitter. Defeats
    /// response-latency fingerprinting that flags uniform sleeps.
    /// Caller drives the actual `tokio::time::sleep`; this is a pure
    /// duration provider.
    pub fn jittered_chunk_delay(&self, seed: u64) -> std::time::Duration {
        use crate::latency_jitter::{Distribution, sample};
        sample(Distribution::default_tarpit(), seed)
    }

    pub fn with_corpus(corpus: &str) -> Self {
        Self::new(Arc::new(MarkovChain::train(corpus)))
    }

    /// Render a full HTML page deterministically from `seed`. The
    /// same seed always yields the same page — important so a
    /// scraper that re-fetches doesn't see different content (would
    /// signal "this site is dynamic, prioritise"). Variation comes
    /// from the link slug in the URL: GET /__aegis/tarpit/abc123 →
    /// seed derived from "abc123".
    pub fn render(&self, seed: u64) -> String {
        let title = self.chain.generate(6, seed);
        let mut out = String::with_capacity(4096);
        out.push_str("<!DOCTYPE html><html><head><title>");
        out.push_str(&html_escape(&title));
        out.push_str("</title></head><body><h1>");
        out.push_str(&html_escape(&title));
        out.push_str("</h1>");
        for i in 0..self.paragraphs_per_page {
            let para_seed = seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(i as u64);
            let body = self.chain.generate(self.words_per_paragraph, para_seed);
            out.push_str("<p>");
            out.push_str(&html_escape(&body));
            out.push_str("</p>");
        }
        out.push_str("<nav><ul>");
        for i in 0..self.links_per_page {
            let link_seed = seed
                .wrapping_mul(0xBF58_476D_1CE4_E5B9)
                .wrapping_add(i as u64);
            let slug = slug_for(link_seed);
            let anchor = self.chain.generate(3, link_seed);
            // V230 — was format!() which allocates a throwaway String
            // per link; push_str on the existing buffer is one less
            // allocation per link (cold path, but ~links_per_page
            // saved allocations per render, ~free).
            out.push_str("<li><a href=\"");
            out.push_str(&self.link_prefix);
            out.push_str(&slug);
            out.push_str("\">");
            out.push_str(&html_escape(&anchor));
            out.push_str("</a></li>");
        }
        out.push_str("</ul></nav></body></html>");
        out
    }

    /// Split the rendered page into `n_chunks` roughly-equal slices
    /// for slow streaming. Caller awaits a delay between each chunk
    /// to maximise CPU/socket cost on the attacker side.
    pub fn render_chunks(&self, seed: u64, n_chunks: usize) -> Vec<String> {
        let full = self.render(seed);
        if n_chunks <= 1 {
            return vec![full];
        }
        let bytes = full.into_bytes();
        let per = bytes.len() / n_chunks;
        let mut out = Vec::with_capacity(n_chunks);
        for i in 0..n_chunks {
            let start = i * per;
            let end = if i == n_chunks - 1 {
                bytes.len()
            } else {
                (i + 1) * per
            };
            // UTF-8 safety: nudge end forward to a char boundary.
            let mut end = end;
            while end < bytes.len() && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
                end += 1;
            }
            out.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        }
        out
    }
}

/// Build a URL slug for the endless-links pool. Lowercase base36-ish
/// 8-char so the URL looks like a real article slug rather than a
/// random hash (less suspicious to heuristic-driven crawlers).
fn slug_for(seed: u64) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::with_capacity(8);
    let mut n = seed;
    for _ in 0..8 {
        s.push(CHARS[(n as usize) % CHARS.len()] as char);
        n /= CHARS.len() as u64;
    }
    s
}

/// Derive a Markov seed from a request slug. Stable hash so the same
/// slug always produces the same page content (essential — see [TarpitGenerator::render]).
pub fn seed_from_slug(slug: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64; // FNV-1a 64-bit offset
    for b in slug.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn html_escape(s: &str) -> String {
    // V230 — fast-path: most Markov-generated tokens contain no
    // escapable chars (operator corpora are usually plain prose).
    // A single bytes scan that bails into clone-on-write avoids the
    // per-char loop + String build for the common case. Cold path
    // overall, but render() calls this 1 + paragraphs + links times
    // per page, so the shortcut compounds.
    if !s
        .bytes()
        .any(|b| matches!(b, b'<' | b'>' | b'&' | b'"' | b'\''))
    {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Tiny deterministic PRNG. Duplicated locally so this module has
/// no cross-module dependency (ml_adversarial has its own copy).
struct Splitmix64 {
    state: u64,
}
impl Splitmix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_corpus() -> &'static str {
        "The cat sat on the mat. \
         A dog ran into the yard. \
         The cat watched the dog. \
         The yard was quiet again. \
         A bird flew over the cat."
    }

    #[test]
    fn markov_trains_non_empty_chain() {
        let m = MarkovChain::train(small_corpus());
        assert!(!m.transitions.is_empty());
        assert!(!m.starters.is_empty());
    }

    #[test]
    fn markov_empty_corpus_returns_empty_chain() {
        let m = MarkovChain::train("");
        assert!(m.transitions.is_empty());
        assert!(m.starters.is_empty());
        assert_eq!(m.generate(10, 0), "");
    }

    #[test]
    fn markov_generate_produces_target_word_count_approx() {
        let m = MarkovChain::train(small_corpus());
        let out = m.generate(20, 7);
        let words: Vec<&str> = out.split_whitespace().collect();
        // Bigram model + small corpus can dead-end; ensure we got
        // close to the target.
        assert!(words.len() >= 10, "produced only {} words", words.len());
    }

    #[test]
    fn markov_same_seed_is_deterministic() {
        let m = MarkovChain::train(small_corpus());
        let a = m.generate(30, 42);
        let b = m.generate(30, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn markov_different_seeds_diverge() {
        let m = MarkovChain::train(small_corpus());
        let a = m.generate(30, 1);
        let b = m.generate(30, 999_999);
        // Very small corpus → some collisions possible, but the
        // first token usually differs.
        assert_ne!(a, b);
    }

    #[test]
    fn fallback_corpus_trains() {
        let m = MarkovChain::train(FALLBACK_CORPUS);
        assert!(!m.transitions.is_empty());
        let out = m.generate(50, 12345);
        assert!(out.split_whitespace().count() >= 20);
    }

    #[test]
    fn tarpit_renders_valid_html_structure() {
        let g = TarpitGenerator::with_corpus(FALLBACK_CORPUS);
        let html = g.render(42);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.ends_with("</html>"));
        assert!(html.contains("<title>"));
        assert!(html.contains("<h1>"));
        assert!(html.contains("<nav>"));
    }

    #[test]
    fn tarpit_emits_paragraph_and_link_counts_per_config() {
        let mut g = TarpitGenerator::with_corpus(FALLBACK_CORPUS);
        g.paragraphs_per_page = 3;
        g.links_per_page = 5;
        let html = g.render(7);
        assert_eq!(html.matches("<p>").count(), 3);
        assert_eq!(html.matches("<li>").count(), 5);
    }

    #[test]
    fn tarpit_links_use_configured_prefix() {
        let g = TarpitGenerator::with_corpus(FALLBACK_CORPUS);
        let html = g.render(99);
        assert!(html.contains("href=\"/__aegis/tarpit/"));
    }

    #[test]
    fn tarpit_same_seed_produces_same_page() {
        let g = TarpitGenerator::with_corpus(FALLBACK_CORPUS);
        let a = g.render(123);
        let b = g.render(123);
        assert_eq!(a, b);
    }

    #[test]
    fn tarpit_different_seeds_produce_different_pages() {
        let g = TarpitGenerator::with_corpus(FALLBACK_CORPUS);
        let a = g.render(1);
        let b = g.render(99_999);
        assert_ne!(a, b);
    }

    #[test]
    fn render_chunks_concatenates_to_full_page() {
        let g = TarpitGenerator::with_corpus(FALLBACK_CORPUS);
        let full = g.render(77);
        let chunks = g.render_chunks(77, 5);
        let rebuilt: String = chunks.concat();
        assert_eq!(rebuilt, full);
        assert_eq!(chunks.len(), 5);
    }

    #[test]
    fn render_chunks_with_one_chunk_returns_full() {
        let g = TarpitGenerator::with_corpus(FALLBACK_CORPUS);
        let chunks = g.render_chunks(1, 1);
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn slug_is_deterministic_and_8_chars() {
        let s1 = slug_for(0xdead_beef);
        let s2 = slug_for(0xdead_beef);
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 8);
        assert!(s1.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn slug_different_seeds_differ() {
        assert_ne!(slug_for(1), slug_for(2));
    }

    #[test]
    fn seed_from_slug_is_stable() {
        let a = seed_from_slug("abc123");
        let b = seed_from_slug("abc123");
        assert_eq!(a, b);
        assert_ne!(a, seed_from_slug("abc124"));
    }

    #[test]
    fn html_escape_handles_dangerous_chars() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn tarpit_escapes_corpus_dangerous_chars() {
        // Build a corpus that includes injection-shaped tokens. The
        // generator must NOT pass them through raw.
        let corpus = "the <script>alert(1)</script> fox jumps";
        let g = TarpitGenerator::with_corpus(corpus);
        let html = g.render(1);
        // No raw <script> tag, even though the corpus had one.
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
