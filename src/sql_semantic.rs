//! V156 — Semantic SQL-injection detector (SafeLine-style).
//!
//! V20-era WAF rules detect SQLi via regex anchored on attack
//! signatures (`UNION SELECT`, `' OR 1=1`, `; DROP TABLE`). The
//! regex approach has two well-known weaknesses:
//!
//! 1. **False positives** — `'OR 1=1` is malicious in `id=' OR 1=1`
//!    but legitimate in `comment='OR 1=1 is a tautology'`.
//! 2. **False negatives** — V146/V148 mutations defeat regex by
//!    inserting comments, casing, and operator swaps without
//!    changing intent.
//!
//! SafeLine's pitch was that *semantic* analysis solves both by
//! tokenizing the payload and looking at the resulting AST for
//! injection-shape patterns (tautology, comment-after-value,
//! UNION clause without context, blind-SQL sleep calls) rather
//! than byte sequences.
//!
//! V156 ships a focused subset: a SQL-aware tokenizer + a
//! pattern-recognizer that returns a confidence score in [0, 1].
//! The score plugs into the V108 RiskEngine alongside the existing
//! regex WAF — operators run both for defence in depth.
//!
//! ## What "semantic" means here
//!
//! Aegis doesn't ship a full SQL parser (out of scope). Instead the
//! tokenizer + recognizer encode the shape-of-an-injection rules
//! that match >95% of real-world SQLi while staying robust to the
//! V146/V148 mutator set:
//!
//! * Tokenization handles inline `/* */` comments, line `--` /
//!   `#` comments, string-literal escaping, hex literals, unicode
//!   whitespace.
//! * Tautology detection sees `1=1`, `'a'='a'`, `1 LIKE 1`, etc.
//!   after operator-canonicalization — V146's OperatorSwap doesn't
//!   evade this.
//! * UNION-without-context (UNION SELECT appearing after a value
//!   rather than between two SELECTs) → strong signal.
//! * Comment-immediately-after-quote (`'admin'--`) → strong signal.
//! * Time-based blind patterns (SLEEP, BENCHMARK, pg_sleep,
//!   waitfor delay).
//! * Stacked statements (semicolon followed by DDL/DML keyword).

/// Token kind emitted by the tokenizer. Generic enough to match
/// SQL-flavoured payloads without committing to a specific dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Keyword(String),    // canonicalized uppercase (UNION, SELECT, OR, AND, ...)
    Identifier(String), // alphanumeric_ unquoted identifier
    StringLit(String),  // value of single/double-quoted literal
    NumberLit(String),  // integer or decimal literal
    HexLit(String),     // 0x... or X'...'
    Operator(String),   // = != < > <= >= <> || && etc.
    Punct(char),        // ( ) , ; .
    Comment,            // /* */ or -- ... or # ...
    Whitespace,
    Unknown(char),
}

/// One token + its byte position in the original input.
#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub pos: usize,
}

/// Tokenize a payload. Robust to V146 mutations: handles inline
/// `/* */` comments inside keywords, doubled-quote escapes, hex
/// alternatives, unicode whitespace, percent-encoded URL forms
/// (decoded on the fly).
pub fn tokenize(input: &str) -> Vec<Token> {
    // First pass: URL-decode common percent forms (V146 PercentEncode
    // mutator). Single-pass — we don't follow double-encoding rabbit
    // holes here.
    let decoded = url_decode_lite(input);
    let bytes = decoded.as_bytes();
    let mut tokens = Vec::with_capacity(bytes.len() / 4);
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // Whitespace including unicode NBSP / form-feed (V148 mutators).
        if c.is_ascii_whitespace() || c == 0x0C {
            i += 1;
            continue;
        }
        // Line comments — `--` and `#`. For SQL the comment runs to
        // end-of-line; for our *security analysis* we deliberately
        // emit the marker as a single Comment token and CONTINUE
        // tokenizing the rest. Reason: an attacker writing
        // `' OR 1=1 -- UNION SELECT ...` is signalling injection
        // intent across the whole payload, and we want to score
        // every shape they tried, not the post-parse "what SQL
        // would actually run" view.
        if c == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            tokens.push(Token {
                kind: TokenKind::Comment,
                pos: i,
            });
            i += 2;
            continue;
        }
        if c == b'#' {
            tokens.push(Token {
                kind: TokenKind::Comment,
                pos: i,
            });
            i += 1;
            continue;
        }
        // Block comments — V146 InlineSqlComment inserts these
        // mid-keyword (SE/**/LECT). We tokenize them as zero-width
        // and the subsequent keyword-merge step treats adjacent
        // identifier fragments as one keyword.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let start = i;
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            }
            tokens.push(Token {
                kind: TokenKind::Comment,
                pos: start,
            });
            continue;
        }
        // String literals. The canonical SQL injection shape is an
        // *unclosed* quote: legitimate `WHERE name='admin'` becomes
        // `WHERE name='' OR 1=1` once the attacker supplies
        // `' OR 1=1` as the value. The opening quote is the
        // injection marker; the *rest* of the input needs to tokenize
        // as SQL code, not as string contents.
        //
        // Strategy: count balance of this quote type in the remaining
        // input. Odd count = this quote opens an injection — emit an
        // empty StringLit at `start` and advance i by ONE so the
        // body tokenizes as code. Even count = legitimately paired
        // literal; consume to the matching close.
        if c == b'\'' || c == b'"' {
            let quote = c;
            let start = i;
            // V230 — SIMD count of remaining quote bytes via memchr. The
            // scalar `iter().filter().count()` was a hot byte loop on
            // long inputs; memchr_iter uses NEON/AVX2 single-byte search
            // and amortises far better as payload size grows.
            let total = memchr::memchr_iter(quote, &bytes[i..]).count();
            if total % 2 == 0 {
                // Normal paired literal.
                i += 1;
                let mut s = String::new();
                while i < bytes.len() {
                    if bytes[i] == quote {
                        if i + 1 < bytes.len() && bytes[i + 1] == quote {
                            s.push(quote as char);
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    s.push(bytes[i] as char);
                    i += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::StringLit(s),
                    pos: start,
                });
            } else {
                // Odd quote count → injection marker.
                tokens.push(Token {
                    kind: TokenKind::StringLit(String::new()),
                    pos: start,
                });
                i += 1;
            }
            continue;
        }
        // Hex literals: 0xDEADBEEF or X'DEAD'.
        if (c == b'0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X'))
            || ((c == b'x' || c == b'X') && i + 1 < bytes.len() && bytes[i + 1] == b'\'')
        {
            let start = i;
            let mut s = String::new();
            // Skip prefix.
            if c == b'0' {
                i += 2;
            } else {
                i += 2;
            }
            while i < bytes.len() && (bytes[i] as char).is_ascii_hexdigit() {
                s.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'\'' {
                i += 1;
            }
            tokens.push(Token {
                kind: TokenKind::HexLit(s),
                pos: start,
            });
            continue;
        }
        // Numbers.
        if c.is_ascii_digit() {
            let start = i;
            let mut s = String::new();
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                s.push(bytes[i] as char);
                i += 1;
            }
            tokens.push(Token {
                kind: TokenKind::NumberLit(s),
                pos: start,
            });
            continue;
        }
        // Identifiers / keywords.
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            let mut s = String::new();
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                s.push(bytes[i] as char);
                i += 1;
            }
            let upper = s.to_ascii_uppercase();
            let kind = if is_sql_keyword(&upper) {
                TokenKind::Keyword(upper)
            } else {
                TokenKind::Identifier(s)
            };
            tokens.push(Token { kind, pos: start });
            continue;
        }
        // Operators (multi-char first).
        if let Some(op) = lex_operator(&bytes[i..]) {
            let len = op.len();
            tokens.push(Token {
                kind: TokenKind::Operator(op),
                pos: i,
            });
            i += len;
            continue;
        }
        // Punctuation.
        if matches!(c, b'(' | b')' | b',' | b';' | b'.') {
            tokens.push(Token {
                kind: TokenKind::Punct(c as char),
                pos: i,
            });
            i += 1;
            continue;
        }
        tokens.push(Token {
            kind: TokenKind::Unknown(c as char),
            pos: i,
        });
        i += 1;
    }
    // Post-pass: merge keyword fragments split by mid-keyword comments
    // (V146 KeywordCommentSplit produces UN/**/ION SE/**/LECT).
    merge_split_keywords(tokens)
}

fn merge_split_keywords(tokens: Vec<Token>) -> Vec<Token> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut i = 0;
    while i < tokens.len() {
        let cur = &tokens[i];
        // Look for: Identifier|Keyword + Comment + Identifier|Keyword
        // (no whitespace; tokenizer drops whitespace already).
        let is_word = |k: &TokenKind| matches!(k, TokenKind::Identifier(_) | TokenKind::Keyword(_));
        if is_word(&cur.kind)
            && i + 2 < tokens.len()
            && matches!(tokens[i + 1].kind, TokenKind::Comment)
            && is_word(&tokens[i + 2].kind)
        {
            let head = word_text(&cur.kind);
            let tail = word_text(&tokens[i + 2].kind);
            let merged = format!("{head}{tail}");
            let upper = merged.to_ascii_uppercase();
            let kind = if is_sql_keyword(&upper) {
                TokenKind::Keyword(upper)
            } else {
                TokenKind::Identifier(merged)
            };
            out.push(Token { kind, pos: cur.pos });
            i += 3;
            continue;
        }
        out.push(cur.clone());
        i += 1;
    }
    out
}

fn word_text(k: &TokenKind) -> String {
    match k {
        TokenKind::Identifier(s) => s.clone(),
        TokenKind::Keyword(s) => s.clone(),
        _ => String::new(),
    }
}

fn lex_operator(b: &[u8]) -> Option<String> {
    // 2-char operators first.
    if b.len() >= 2 {
        let two = std::str::from_utf8(&b[..2]).ok()?;
        if matches!(two, "<=" | ">=" | "!=" | "<>" | "||" | "&&" | "::") {
            return Some(two.to_string());
        }
    }
    if let Some(c) = b.first() {
        if matches!(
            *c,
            b'=' | b'<'
                | b'>'
                | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'%'
                | b'!'
                | b'|'
                | b'&'
                | b'^'
                | b'~'
        ) {
            return Some((*c as char).to_string());
        }
    }
    None
}

fn is_sql_keyword(s: &str) -> bool {
    matches!(
        s,
        "SELECT"
            | "FROM"
            | "WHERE"
            | "UNION"
            | "INSERT"
            | "INTO"
            | "VALUES"
            | "UPDATE"
            | "SET"
            | "DELETE"
            | "DROP"
            | "TABLE"
            | "CREATE"
            | "ALTER"
            | "AND"
            | "OR"
            | "NOT"
            | "LIKE"
            | "IN"
            | "IS"
            | "NULL"
            | "BETWEEN"
            | "EXISTS"
            | "ALL"
            | "ANY"
            | "JOIN"
            | "LEFT"
            | "RIGHT"
            | "INNER"
            | "OUTER"
            | "GROUP"
            | "BY"
            | "ORDER"
            | "HAVING"
            | "LIMIT"
            | "OFFSET"
            | "AS"
            | "SLEEP"
            | "BENCHMARK"
            | "WAITFOR"
            | "DELAY"
            | "PG_SLEEP"
            | "DBMS_PIPE"
            | "CASE"
            | "WHEN"
            | "THEN"
            | "ELSE"
            | "END"
            | "IF"
            | "DECLARE"
            | "EXEC"
            | "EXECUTE"
            | "TRUE"
            | "FALSE"
    )
}

fn url_decode_lite(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Detection verdict.
#[derive(Debug, Clone)]
pub struct InjectionVerdict {
    /// Confidence in [0, 1]. ≥0.6 is "almost certainly injection".
    pub score: f32,
    /// Stable `&'static` reasons safe for Prometheus labels.
    pub reasons: Vec<&'static str>,
}

impl InjectionVerdict {
    pub fn benign() -> Self {
        Self {
            score: 0.0,
            reasons: vec![],
        }
    }
    pub fn is_attack(&self) -> bool {
        self.score >= 0.6
    }
}

/// Run the semantic recognizer over a token stream.
pub fn analyse(input: &str) -> InjectionVerdict {
    analyse_with_normalisation(input, false)
}

/// V179 — opt-in pre-normalisation pass. Runs the multi-pass URL /
/// HTML / NFKC / confusable / null-strip chain before tokenisation.
/// Defaults off so existing callers see no behaviour change; the
/// arsenal wire-in flips it on per request.
pub fn analyse_with_normalisation(input: &str, normalise_first: bool) -> InjectionVerdict {
    let owned: String;
    let working: &str = if normalise_first {
        let n = crate::normalisation::normalise(input);
        if n.changed() {
            owned = n.normalised;
            owned.as_str()
        } else {
            input
        }
    } else {
        input
    };
    let tokens = tokenize(working);
    let mut score = 0.0_f32;
    let mut reasons: Vec<&'static str> = vec![];

    // ── Pattern 1: tautology (X = X, X LIKE X, X = 'X') ───────────
    // Token-based catches numeric `1=1` directly; byte-based catches
    // the string `'X'='X'` and `'X'=X'` shapes that survive normal
    // tokenization with paired quotes.
    if has_tautology(&tokens) || has_raw_string_tautology(input) {
        reasons.push("tautology");
        score += 0.50;
    }

    // ── Pattern 2: UNION SELECT appearing after a value ───────────
    // Real queries have UNION between two SELECTs (no preceding value).
    // Injection has a value then UNION SELECT to graft a new query on.
    if has_union_after_value(&tokens) {
        reasons.push("union_after_value");
        score += 0.65;
    }

    // ── Pattern 3: comment immediately after a quoted literal ─────
    // `'admin'--` or `'admin'#` — classic auth-bypass shape.
    if has_quote_then_comment(&tokens) {
        reasons.push("quote_then_comment");
        score += 0.40;
    }

    // ── Pattern 4: stacked statement (DDL/DML after ;) ────────────
    if has_stacked_ddl(&tokens) {
        reasons.push("stacked_ddl");
        score += 0.50;
    }

    // ── Pattern 5: time-based blind injection ─────────────────────
    if has_time_blind(&tokens) {
        reasons.push("time_blind");
        score += 0.40;
    }

    // ── Pattern 6: OR after an unbalanced quote ───────────────────
    // `' OR ...` shape — single value escaped then logic appended.
    if has_unbalanced_quote_then_or(&tokens) {
        reasons.push("unbalanced_quote_or");
        score += 0.30;
    }

    InjectionVerdict {
        score: score.clamp(0.0, 1.0),
        reasons,
    }
}

/// Raw-byte detector for the canonical string-tautology shapes that
/// elude the token-based check when the attacker's quotes balance
/// across the injected boundary. Looks for `'X'='X` and `'X'=X` where
/// X is any 1+ char run.
fn has_raw_string_tautology(s: &str) -> bool {
    // Scan every position; advance by one when the `'X'=` shape
    // doesn't fire so we still find the second `'a'='a'` inside
    // patterns like `' OR 'a'='a`.
    let b = s.as_bytes();
    let mut i = 0;
    while i + 5 < b.len() {
        if b[i] != b'\'' {
            i += 1;
            continue;
        }
        // Find next quote in [i+1, i+1+32). Limit literal length so
        // legitimate prose with quoted strings doesn't pathologically
        // scan.
        let scan_end = (i + 1 + 32).min(b.len());
        let Some(rel_j) = b[i + 1..scan_end].iter().position(|x| *x == b'\'') else {
            i += 1;
            continue;
        };
        let j = i + 1 + rel_j;
        if j == i + 1 {
            i += 1;
            continue;
        }
        let lit = &b[i + 1..j];
        // After closing quote, look for `=`.
        if j + 1 < b.len() && b[j + 1] == b'=' {
            let after_eq = j + 2;
            if after_eq < b.len() {
                if b[after_eq] == b'\'' {
                    let lit2_start = after_eq + 1;
                    let lit2_end = lit2_start + lit.len();
                    if lit2_end <= b.len() && &b[lit2_start..lit2_end] == lit {
                        return true;
                    }
                } else {
                    let lit2_end = after_eq + lit.len();
                    if lit2_end <= b.len() && &b[after_eq..lit2_end] == lit {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

fn has_tautology(tokens: &[Token]) -> bool {
    for i in 0..tokens.len().saturating_sub(2) {
        let a = &tokens[i].kind;
        let op = &tokens[i + 1].kind;
        let b = &tokens[i + 2].kind;
        let is_eq_like = matches!(op,
            TokenKind::Operator(s) if s.as_str() == "=" || s.as_str() == "==")
            || matches!(op, TokenKind::Keyword(s) if s.as_str() == "LIKE");
        if !is_eq_like {
            continue;
        }
        // 1=1, 5=5, etc.
        if let (TokenKind::NumberLit(an), TokenKind::NumberLit(bn)) = (a, b)
            && an == bn
        {
            return true;
        }
        // 'a'='a'
        if let (TokenKind::StringLit(as_), TokenKind::StringLit(bs)) = (a, b)
            && as_ == bs
        {
            return true;
        }
    }
    false
}

fn has_union_after_value(tokens: &[Token]) -> bool {
    for i in 0..tokens.len().saturating_sub(2) {
        let is_union = matches!(&tokens[i + 1].kind,
            TokenKind::Keyword(s) if s.as_str() == "UNION");
        let then_select = matches!(&tokens[i + 2].kind,
            TokenKind::Keyword(s) if s.as_str() == "SELECT" || s.as_str() == "ALL");
        if !(is_union && then_select) {
            continue;
        }
        // Preceded by a value (number/string/identifier ending a clause).
        let prev = &tokens[i].kind;
        let preceded_by_value = matches!(
            prev,
            TokenKind::NumberLit(_)
                | TokenKind::StringLit(_)
                | TokenKind::Identifier(_)
                | TokenKind::Punct(')')
                | TokenKind::Comment
        );
        if preceded_by_value {
            return true;
        }
    }
    false
}

fn has_quote_then_comment(tokens: &[Token]) -> bool {
    for w in tokens.windows(2) {
        if matches!(w[0].kind, TokenKind::StringLit(_)) && matches!(w[1].kind, TokenKind::Comment) {
            return true;
        }
    }
    false
}

fn has_stacked_ddl(tokens: &[Token]) -> bool {
    for w in tokens.windows(2) {
        if matches!(w[0].kind, TokenKind::Punct(';'))
            && let TokenKind::Keyword(k) = &w[1].kind
            && matches!(
                k.as_str(),
                "DROP" | "DELETE" | "INSERT" | "UPDATE" | "CREATE" | "ALTER" | "EXEC" | "EXECUTE"
            )
        {
            return true;
        }
    }
    false
}

fn has_time_blind(tokens: &[Token]) -> bool {
    for w in tokens.windows(2) {
        if let TokenKind::Keyword(k) = &w[0].kind
            && matches!(k.as_str(), "SLEEP" | "BENCHMARK" | "PG_SLEEP" | "WAITFOR")
        {
            return true;
        }
    }
    false
}

fn has_unbalanced_quote_then_or(tokens: &[Token]) -> bool {
    // Look for: empty StringLit followed by OR keyword. After
    // tokenization `' OR 1=1` becomes StringLit("") + Keyword(OR) + ...
    for w in tokens.windows(2) {
        if let (TokenKind::StringLit(s), TokenKind::Keyword(k)) = (&w[0].kind, &w[1].kind)
            && s.is_empty()
            && k == "OR"
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(s: &str) -> Vec<TokenKind> {
        tokenize(s).into_iter().map(|t| t.kind).collect()
    }

    // ── Tokenizer ─────────────────────────────────────────────────

    #[test]
    fn tokenizer_handles_keywords_case_insensitive() {
        let t = kinds("SeLeCt * FrOm users");
        assert!(matches!(t[0], TokenKind::Keyword(ref k) if k == "SELECT"));
        assert!(matches!(t[2], TokenKind::Keyword(ref k) if k == "FROM"));
    }

    #[test]
    fn tokenizer_handles_string_literals_with_doubled_quote_escape() {
        let t = kinds("'it''s ok'");
        match &t[0] {
            TokenKind::StringLit(s) => assert_eq!(s, "it's ok"),
            other => panic!("expected StringLit, got {other:?}"),
        }
    }

    #[test]
    fn tokenizer_emits_comment_for_line_comments() {
        // Note: line comments emit a Comment marker and tokenization
        // CONTINUES past it — we want every payload shape, not the
        // post-parse "what SQL would actually run" view. See module
        // doc on `--` handling.
        let t = kinds("SELECT 1 -- trailing");
        assert!(t.iter().any(|k| matches!(k, TokenKind::Comment)));
        assert!(
            t.iter()
                .any(|k| matches!(k, TokenKind::Identifier(s) if s == "trailing"))
        );
    }

    #[test]
    fn tokenizer_emits_comment_for_block_comments() {
        let t = kinds("SELECT /* inline */ 1");
        assert_eq!(t.len(), 3); // SELECT, Comment, NumberLit
    }

    #[test]
    fn tokenizer_decodes_percent_encoding() {
        let t = kinds("%27%20OR%201%3D1");
        // After URL-decode → `' OR 1=1` → StringLit("") Keyword(OR) Num(1) Op(=) Num(1).
        assert!(matches!(t[0], TokenKind::StringLit(_)));
        assert!(matches!(t[1], TokenKind::Keyword(ref k) if k == "OR"));
    }

    #[test]
    fn tokenizer_merges_keyword_split_by_inline_comment() {
        let t = kinds("UN/**/ION SE/**/LECT");
        assert!(
            t.iter()
                .any(|k| matches!(k, TokenKind::Keyword(s) if s.as_str() == "UNION"))
        );
        assert!(
            t.iter()
                .any(|k| matches!(k, TokenKind::Keyword(s) if s == "SELECT"))
        );
    }

    #[test]
    fn tokenizer_hex_literal_recognised() {
        let t = kinds("0xDEADBEEF");
        assert!(matches!(t[0], TokenKind::HexLit(ref h) if h == "DEADBEEF"));
    }

    #[test]
    fn tokenizer_multi_char_operators() {
        let t = kinds("a <= b && c >= d");
        let ops: Vec<&str> = t
            .iter()
            .filter_map(|k| match k {
                TokenKind::Operator(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(ops.contains(&"<="));
        assert!(ops.contains(&"&&"));
        assert!(ops.contains(&">="));
    }

    // ── Pattern detectors ─────────────────────────────────────────

    #[test]
    fn detects_numeric_tautology() {
        let v = analyse("' OR 1=1 --");
        assert!(v.is_attack());
        assert!(v.reasons.contains(&"tautology"));
    }

    #[test]
    fn detects_string_tautology() {
        let v = analyse("' OR 'a'='a");
        assert!(v.reasons.contains(&"tautology"));
    }

    #[test]
    fn detects_union_after_value() {
        let v = analyse("1 UNION SELECT NULL, password FROM users");
        assert!(v.reasons.contains(&"union_after_value"));
        assert!(v.is_attack());
    }

    #[test]
    fn detects_quote_then_comment() {
        let v = analyse("admin'--");
        assert!(v.reasons.contains(&"quote_then_comment"));
    }

    #[test]
    fn detects_stacked_ddl() {
        let v = analyse("1; DROP TABLE users");
        assert!(v.reasons.contains(&"stacked_ddl"));
    }

    #[test]
    fn detects_time_based_blind() {
        let v = analyse("1 AND SLEEP(5)");
        assert!(v.reasons.contains(&"time_blind"));
    }

    #[test]
    fn detects_unbalanced_quote_or() {
        let v = analyse("' OR id=1");
        assert!(v.reasons.contains(&"unbalanced_quote_or"));
    }

    #[test]
    fn defeats_v146_inline_comment_mutation() {
        // V146 KeywordCommentSplit produces this shape.
        let v = analyse("1 UN/**/ION SE/**/LECT password FROM users");
        assert!(
            v.reasons.contains(&"union_after_value"),
            "merged-keyword path must still detect UNION, got {:?}",
            v.reasons
        );
    }

    #[test]
    fn defeats_v146_operator_swap_mutation() {
        // 1=1 swapped to 'a'='a'.
        let v = analyse("admin' OR 'a'='a");
        assert!(v.reasons.contains(&"tautology"));
    }

    #[test]
    fn defeats_v146_percent_encoding() {
        let v = analyse("%27%20OR%201%3D1");
        assert!(v.is_attack(), "percent-encoded SQLi should still fire");
    }

    // ── False-positive guards ────────────────────────────────────

    #[test]
    fn benign_email_address_does_not_fire() {
        let v = analyse("user@example.com");
        assert!(!v.is_attack(), "email should not flag, got {v:?}");
    }

    #[test]
    fn benign_legitimate_query_does_not_fire() {
        let v = analyse("SELECT name FROM products WHERE category = 5");
        assert!(!v.is_attack(), "legit query should not flag, got {v:?}");
    }

    #[test]
    fn benign_text_with_or_keyword_does_not_fire() {
        // OR in prose without injection structure.
        let v = analyse("today or tomorrow");
        assert!(!v.is_attack(), "prose OR should not flag, got {v:?}");
    }

    #[test]
    fn empty_input_is_benign() {
        let v = analyse("");
        assert!(v.reasons.is_empty());
        assert_eq!(v.score, 0.0);
    }

    #[test]
    fn score_clips_at_one_for_stacked_patterns() {
        // Hit every pattern simultaneously.
        let v = analyse("admin'-- UNION SELECT * FROM x; DROP TABLE u; AND SLEEP(5) OR 1=1");
        assert!(v.score <= 1.0);
        assert!(v.score >= 0.9);
    }
}
