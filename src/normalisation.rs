//! V179 — SafeLine-style normalisation chain.
//!
//! Attack payloads routinely arrive multi-encoded:
//!
//! * `%2527 UNION SELECT` — URL-encoded URL-encoded quote.
//! * `&#x3c;script&#x3e;` — HTML hex-entity encoded angle brackets.
//! * `‹script›` — Unicode confusable angle brackets (U+2039, U+203A).
//! * `＜script＞` — Full-width angle brackets (U+FF1C, U+FF1E).
//!
//! Single-pass decoders miss the doubly-encoded case; per-detector
//! normalisation invites inconsistency. This module runs payload
//! through a deterministic decode loop until it stabilises (or a
//! safety budget runs out) and records what was applied — auditable
//! transformation chain.
//!
//! Idea taken from SafeLine (chaitin/SafeLine): one canonical
//! normalisation pipeline shared by SQL/XSS/cmd detectors so a single
//! confusable substitution map covers them all.

use std::borrow::Cow;

/// Stages applied during normalisation, in order. Surfaced in
/// SecurityEvent details so the operator can replay the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    UrlDecode,
    HtmlEntityDecode,
    UnicodeNfkc,
    ConfusableFold,
    LowercaseAscii,
    StripNullBytes,
}

#[derive(Debug, Clone)]
pub struct NormalisedPayload {
    pub original: String,
    pub normalised: String,
    pub stages: Vec<Stage>,
    pub passes: u8,
}

impl NormalisedPayload {
    pub fn changed(&self) -> bool {
        self.normalised != self.original
    }
}

const MAX_PASSES: u8 = 4;

pub fn normalise(input: &str) -> NormalisedPayload {
    let original = input.to_string();
    let mut s: Cow<'_, str> = Cow::Borrowed(input);
    let mut stages: Vec<Stage> = Vec::new();
    let mut passes = 0;
    loop {
        let before = s.to_string();
        if let Some(d) = url_decode(&s) {
            stages.push(Stage::UrlDecode);
            s = Cow::Owned(d);
        }
        if let Some(d) = html_entity_decode(&s) {
            stages.push(Stage::HtmlEntityDecode);
            s = Cow::Owned(d);
        }
        if let Some(d) = unicode_nfkc(&s) {
            stages.push(Stage::UnicodeNfkc);
            s = Cow::Owned(d);
        }
        if let Some(d) = confusable_fold(&s) {
            stages.push(Stage::ConfusableFold);
            s = Cow::Owned(d);
        }
        if let Some(d) = strip_null_bytes(&s) {
            stages.push(Stage::StripNullBytes);
            s = Cow::Owned(d);
        }
        passes += 1;
        if s == before || passes >= MAX_PASSES {
            break;
        }
    }
    // Lowercase last — semantic detectors are case-insensitive.
    let lower = s.to_lowercase();
    if lower != *s {
        stages.push(Stage::LowercaseAscii);
    }
    NormalisedPayload {
        original,
        normalised: lower,
        stages,
        passes,
    }
}

fn url_decode(s: &str) -> Option<String> {
    // V230 — SIMD fast path. Use memchr to jump straight to the first
    // `%`; if there isn't one, return None without allocating. For
    // inputs with a long literal prefix this skips a large scalar scan
    // entirely (NEON/AVX2 single-byte search). The prefix bytes are
    // then copied verbatim before re-entering the decode loop.
    let bytes = s.as_bytes();
    let Some(first) = memchr::memchr(b'%', bytes) else {
        return None;
    };
    let mut out = String::with_capacity(s.len());
    // Copy the pre-`%` prefix as-is — all ASCII below 0x80 by virtue of
    // memchr finding `%` (0x25) and the rest being arbitrary bytes; we
    // mirror the original loop's `bytes[i] as char` widening.
    for &b in &bytes[..first] {
        out.push(b as char);
    }
    let mut i = first;
    let mut changed = false;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_digit(bytes[i + 1]);
            let lo = hex_digit(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as char);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    changed.then_some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ── V233 — request-path canonicaliser ────────────────────────────────
//
// Security controls (endpoint policy, honeypot) match against the
// request path. The upstream receives the *same* raw path and decodes
// it itself, so if matching and decoding disagree the control is
// bypassed: `/%61dmin/users` (`%61`=`a`) misses an `/admin/*` rule but
// the upstream serves `/admin/users`. Likewise `/public/..%2finternal/`
// is never collapsed before matching.
//
// `canonical_path` produces the form the upstream would actually see:
//   1. percent-decode into BYTES (not chars — the old `url_decode`
//      cast each decoded byte straight to `char`, so `%C0%AE` became
//      Latin-1 `À®` instead of bytes 0xC0,0xAE, defeating overlong-
//      UTF-8 detection). Decoded bytes go through `from_utf8_lossy`.
//   2. collapse `.` / `..` dot-segments per RFC 3986 §5.2.4.
//   3. collapse repeated `/`.
//   4. lower-case (both matchers are case-insensitive).
//
// Panic-free on ANY input: no `&str` byte-offset slicing, only byte
// indexing / iteration. Decoding is bounded to `CANON_MAX_PASSES` so a
// deeply multi-encoded path (`%2561` → `%61` → `a`) can't amplify
// unboundedly.

/// Max percent-decode passes in [`canonical_path`]. Two passes catches
/// the common single/double-encoding case; the bound stops a crafted
/// `%25...%25` chain from forcing many rescans.
const CANON_MAX_PASSES: u8 = 3;

/// Percent-decode `raw` into a byte buffer. Returns `(bytes, changed)`.
/// A `%` not followed by two hex digits is copied literally (it is not
/// a valid escape) — this is what keeps a malformed trailing `%`, `%2`,
/// or `%zz` from panicking or being dropped. Pure byte work; never
/// indexes a `str` by byte offset.
fn percent_decode_bytes(raw: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(raw.len());
    let mut changed = false;
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            // Need two more bytes for a complete escape.
            if let (Some(&h), Some(&l)) = (raw.get(i + 1), raw.get(i + 2))
                && let (Some(hi), Some(lo)) = (hex_digit(h), hex_digit(l))
            {
                out.push(hi * 16 + lo);
                i += 3;
                changed = true;
                continue;
            }
            // Malformed escape: emit the `%` verbatim, advance one.
        }
        out.push(raw[i]);
        i += 1;
    }
    (out, changed)
}

/// V233 — canonicalise a request path into the form the upstream would
/// actually resolve, so path-based security controls match the same
/// thing the origin serves.
///
/// Steps: bounded percent-decode (bytes → `from_utf8_lossy`), RFC 3986
/// §5.2.4 dot-segment removal, repeated-slash collapse, ASCII
/// lower-case. Panic-free on every input, including malformed `%`
/// escapes, raw multibyte / invalid UTF-8, and empty input.
///
/// Wiring note (for the later `pingora_http.rs` step): call as
/// `crate::normalisation::canonical_path(raw_path)` where `raw_path` is
/// the request path *without* the query string. The returned `String`
/// is lower-cased and safe to feed straight into
/// `HoneypotMatcher::matches` and `DomainPolicy::endpoint_action`.
pub fn canonical_path(raw: &str) -> String {
    // Drop any query/fragment defensively — callers should pass the
    // bare path, but a stray `?`/`#` must not leak into matching.
    let bare = raw.split(['?', '#']).next().unwrap_or(raw);

    // 1. Bounded percent-decode. Re-decode while the previous pass
    //    changed something (handles `%2561` → `%61` → `a`), capped so
    //    a crafted chain can't force unbounded rescans.
    let mut bytes: Vec<u8> = bare.as_bytes().to_vec();
    for _ in 0..CANON_MAX_PASSES {
        let (decoded, changed) = percent_decode_bytes(&bytes);
        bytes = decoded;
        if !changed {
            break;
        }
    }

    // Decoded bytes → String. `from_utf8_lossy` keeps invalid
    // sequences as U+FFFD instead of casting each byte to a Latin-1
    // `char`, so overlong encodings stay detectably broken rather than
    // silently turning into plausible text.
    let decoded = String::from_utf8_lossy(&bytes);

    // 2 + 3. Dot-segment removal (RFC 3986 §5.2.4) and repeated-slash
    //         collapse, done in one segment walk. We treat the path as
    //         `/`-delimited segments; `.` is dropped, `..` pops the
    //         last kept segment, empty segments (from `//`) are
    //         dropped. A leading `/` is preserved iff the input had
    //         one (or became empty).
    let had_leading_slash = decoded.as_bytes().first() == Some(&b'/');
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {
                // Empty segment (`//` or leading/trailing `/`) and `.`
                // contribute nothing.
            }
            ".." => {
                // Pop one real segment; never escape above root.
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut canon = String::with_capacity(decoded.len());
    if had_leading_slash {
        canon.push('/');
    }
    for (idx, seg) in segments.iter().enumerate() {
        if idx > 0 {
            canon.push('/');
        }
        canon.push_str(seg);
    }
    if canon.is_empty() {
        // Empty input or a path that collapsed entirely (`/..`, `/.`).
        // Normalise to `/` so matchers see a stable root.
        canon.push('/');
    }

    // 4. Lower-case for the case-insensitive matchers.
    canon.to_lowercase()
}

fn html_entity_decode(s: &str) -> Option<String> {
    if !s.contains('&') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut changed = false;
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        let mut entity = String::new();
        let mut found_semi = false;
        for next in chars.by_ref() {
            if next == ';' {
                found_semi = true;
                break;
            }
            if entity.len() > 8 {
                break;
            }
            entity.push(next);
        }
        if !found_semi {
            out.push('&');
            out.push_str(&entity);
            continue;
        }
        if let Some(decoded) = decode_entity(&entity) {
            out.push(decoded);
            changed = true;
        } else {
            out.push('&');
            out.push_str(&entity);
            out.push(';');
        }
    }
    changed.then_some(out)
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let rest = entity.strip_prefix('#')?;
            let code = if let Some(hex) = rest.strip_prefix('x').or_else(|| rest.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                rest.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

fn unicode_nfkc(s: &str) -> Option<String> {
    // Without a full NFKC table we still apply the high-leverage cases:
    // full-width ASCII U+FF01..U+FF5E → ASCII 0x21..0x7E.
    if !s.chars().any(|c| ('\u{FF01}'..='\u{FF5E}').contains(&c)) {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cu = c as u32;
        if (0xFF01..=0xFF5E).contains(&cu) {
            out.push(char::from_u32(cu - 0xFEE0).unwrap_or(c));
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn confusable_fold(s: &str) -> Option<String> {
    // Targeted confusables for the highest-leverage attack characters:
    // angle brackets, quotes, parens, semicolons.
    const TABLE: &[(char, char)] = &[
        ('‹', '<'),
        ('›', '>'),
        ('＜', '<'),
        ('＞', '>'),
        ('′', '\''),
        ('″', '"'),
        ('‘', '\''),
        ('’', '\''),
        ('“', '"'),
        ('”', '"'),
        ('（', '('),
        ('）', ')'),
        ('；', ';'),
        ('：', ':'),
        ('｜', '|'),
        ('！', '!'),
        ('＆', '&'),
        ('＝', '='),
    ];
    let mut changed = false;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if let Some(&(_, rep)) = TABLE.iter().find(|(orig, _)| *orig == c) {
            out.push(rep);
            changed = true;
        } else {
            out.push(c);
        }
    }
    changed.then_some(out)
}

fn strip_null_bytes(s: &str) -> Option<String> {
    if !s.contains('\0') {
        return None;
    }
    Some(s.replace('\0', ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_url_encoded_payload_decoded() {
        let p = normalise("%2527%20UNION%20SELECT");
        assert!(p.normalised.contains("' union select"));
        assert!(p.stages.contains(&Stage::UrlDecode));
        assert!(p.passes >= 2);
    }

    #[test]
    fn html_hex_entity_decoded() {
        let p = normalise("&#x3c;script&#x3e;");
        assert_eq!(p.normalised, "<script>");
        assert!(p.stages.contains(&Stage::HtmlEntityDecode));
    }

    #[test]
    fn html_named_entity_decoded() {
        let p = normalise("&lt;img&gt;");
        assert_eq!(p.normalised, "<img>");
    }

    #[test]
    fn confusable_angle_brackets_folded() {
        let p = normalise("‹script›alert(1)‹/script›");
        assert!(p.normalised.contains("<script>"));
        assert!(p.stages.contains(&Stage::ConfusableFold));
    }

    #[test]
    fn full_width_ascii_normalised() {
        let p = normalise("ＳＥＬＥＣＴ");
        assert_eq!(p.normalised, "select");
    }

    #[test]
    fn null_bytes_stripped() {
        let p = normalise("ad\0min");
        assert_eq!(p.normalised, "admin");
        assert!(p.stages.contains(&Stage::StripNullBytes));
    }

    #[test]
    fn clean_payload_unchanged() {
        let p = normalise("hello world");
        assert_eq!(p.normalised, "hello world");
        assert!(!p.changed());
    }

    #[test]
    fn passes_bounded() {
        let nasty = "%25".repeat(20);
        let p = normalise(&nasty);
        assert!(p.passes <= MAX_PASSES);
    }

    // ── V233 — canonical_path tests ──────────────────────────────────

    #[test]
    fn canon_percent_encoded_letter_decodes() {
        // `%61` = `a`: `/%61dmin` must canonicalise so an `/admin/*`
        // rule fires the same way the upstream resolves it.
        assert_eq!(canonical_path("/%61dmin"), "/admin");
        assert_eq!(canonical_path("/%61dmin/users"), "/admin/users");
    }

    #[test]
    fn canon_dot_dot_segment_collapsed() {
        assert_eq!(canonical_path("/a/../b"), "/b");
        // Encoded `..%2f` form must collapse too (the path-traversal
        // bypass in the finding).
        assert_eq!(canonical_path("/public/..%2finternal/"), "/internal");
    }

    #[test]
    fn canon_repeated_slashes_collapsed() {
        assert_eq!(canonical_path("/a//b"), "/a/b");
        assert_eq!(canonical_path("/a///b////c"), "/a/b/c");
    }

    #[test]
    fn canon_overlong_encoding_keeps_real_bytes() {
        // `%C0%AE` is an overlong encoding of `.`. The decoder must
        // yield the real bytes 0xC0,0xAE — NOT Latin-1 `À®`. 0xC0 0xAE
        // is invalid UTF-8, so `from_utf8_lossy` replaces it with
        // U+FFFD; the key point is byte 0xC0 is never silently widened
        // to the char U+00C0.
        let out = canonical_path("/%C0%AE");
        assert!(
            !out.contains('\u{C0}'),
            "overlong bytes must not become Latin-1 chars: {out:?}",
        );
        // The replacement char proves the raw invalid bytes survived
        // decoding rather than being reinterpreted as text.
        assert!(out.contains('\u{FFFD}'));
    }

    #[test]
    fn canon_no_panic_on_malformed_input() {
        // Trailing / truncated / non-hex `%` escapes and raw multibyte
        // / invalid-UTF-8 input must never panic.
        for input in [
            "",
            "%",
            "%2",
            "%zz",
            "/%",
            "/foo%",
            "/foo%2",
            "/foo%gg/bar",
            "/%%%%",
            "/..",
            "/../../..",
            "/%2e%2e/%2e%2e",
            "/café/日本語",
            "/%ff%fe%c0",
            "/%00admin",
        ] {
            let out = canonical_path(input);
            // Result is always non-empty (collapses to at least "/").
            assert!(!out.is_empty(), "empty output for {input:?}");
        }
    }

    #[test]
    fn canon_query_and_fragment_stripped() {
        assert_eq!(canonical_path("/admin?x=1"), "/admin");
        assert_eq!(canonical_path("/admin#frag"), "/admin");
    }

    #[test]
    fn canon_lowercases_for_case_insensitive_match() {
        assert_eq!(canonical_path("/ADMIN/Users"), "/admin/users");
    }

    #[test]
    fn canon_double_encoding_bounded_but_resolved() {
        // `%2561` → `%61` → `a` within the pass budget.
        assert_eq!(canonical_path("/%2561dmin"), "/admin");
    }

    #[test]
    fn canon_root_and_empty_normalise_to_slash() {
        assert_eq!(canonical_path("/"), "/");
        assert_eq!(canonical_path(""), "/");
        assert_eq!(canonical_path("/."), "/");
        assert_eq!(canonical_path("/.."), "/");
    }
}
