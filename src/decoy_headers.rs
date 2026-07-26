//! V188 — Scrapling-inverted Cloudflare decoy headers.
//!
//! Scrapling and similar adaptive scrapers inspect response headers
//! and cookies to identify which WAF/CDN protects a site, then load
//! the corresponding bypass strategy. If Aegis impersonates Cloudflare
//! headers on suspect requests, the attacker selects the wrong
//! playbook and burns time on bypasses that don't apply to us.
//!
//! Cheap, high-leverage deception layer. Only emitted to clients we
//! already suspect (challenge ladder hit, high ML score, or matched
//! a honeypot pattern) — never to clean traffic.
//!
//! Headers chosen to match Cloudflare's actual response shape:
//!
//! * `Server: cloudflare`
//! * `CF-RAY: <16-hex>-FRA` — deterministic per-conn so retries match
//! * `CF-Cache-Status: DYNAMIC|HIT|MISS`
//! * `Alt-Svc: h3=":443"; ma=86400`
//! * Cookie: `__cf_bm=…` — Cloudflare's bot-mitigation cookie
//!
//! Optional alternative families (operator-chosen): Akamai, Fastly,
//! AWS CloudFront. Same idea: pick the platform Scrapling/Botasaurus
//! has the *deepest* bypass code for, so they waste the most effort.
//!
//! V230 — Allocation audit. `build()` runs per high-threat response
//! (rare path, but hot-ish under sustained attack). Optimisations:
//!   * Header *names* were already `&'static str` — kept as-is.
//!   * Static header *values* (`"cloudflare"`, `"DYNAMIC"`, etc.) used
//!     `.into()` which still allocates a fresh `String` per call. We
//!     now use `String::from` on a static literal (same cost, but the
//!     intent is explicit) — the only way to drop these allocs entirely
//!     would be to change the return tuple to `Cow<'static, str>`,
//!     which is a breaking change for the pingora_http.rs:2140 caller
//!     that hands `v: String` to `insert_header(..)`. Left alone to
//!     respect the API-stability constraint.
//!   * `format!` calls replaced with direct `String::with_capacity` +
//!     hex push, avoiding the fmt machinery for the hot
//!     deterministic-hex values (`cf-ray`, request IDs, `via`). These
//!     yield correctly-sized single allocations with no temporary
//!     `Arguments` plumbing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyFamily {
    Cloudflare,
    Akamai,
    Fastly,
    CloudFront,
}

pub struct DecoyHeaders;

impl DecoyHeaders {
    // V230 — return type intentionally preserved as
    // `Vec<(&'static str, String)>`: callers in
    // `proxy/pingora_http.rs` move the owned `String` directly into
    // pingora's `insert_header(..)`. A `Cow<'static, str>` return
    // would force a caller-side change and is out of scope here.
    pub fn build(family: DecoyFamily, conn_id: u64) -> Vec<(&'static str, String)> {
        match family {
            DecoyFamily::Cloudflare => cloudflare(conn_id),
            DecoyFamily::Akamai => akamai(conn_id),
            DecoyFamily::Fastly => fastly(conn_id),
            DecoyFamily::CloudFront => cloudfront(conn_id),
        }
    }
}

fn cloudflare(conn_id: u64) -> Vec<(&'static str, String)> {
    // V230 — `format!("{:016x}-FRA", …)` replaced with direct
    // 20-byte allocation: 16 hex + literal "-FRA".
    let mixed = mix(conn_id);
    let mut ray = String::with_capacity(20);
    push_hex16(&mut ray, mixed);
    ray.push_str("-FRA");

    let bm = base64ish(mixed ^ 0xdeadbeef);

    // V230 — pre-size cookie buffer: `__cf_bm=` + 22-char base64 +
    // fixed suffix (≈98 bytes total). Avoids `format!`'s grow path.
    const COOKIE_PREFIX: &str = "__cf_bm=";
    const COOKIE_SUFFIX: &str =
        "; path=/; expires=Thu, 31-Dec-37 23:59:59 GMT; HttpOnly; Secure; SameSite=None";
    let mut cookie = String::with_capacity(COOKIE_PREFIX.len() + bm.len() + COOKIE_SUFFIX.len());
    cookie.push_str(COOKIE_PREFIX);
    cookie.push_str(&bm);
    cookie.push_str(COOKIE_SUFFIX);

    vec![
        ("server", String::from("cloudflare")),
        ("cf-ray", ray),
        ("cf-cache-status", String::from("DYNAMIC")),
        ("alt-svc", String::from("h3=\":443\"; ma=86400")),
        ("set-cookie", cookie),
    ]
}

fn akamai(conn_id: u64) -> Vec<(&'static str, String)> {
    // V230 — both hex fields written direct, no `format!`.
    let mixed = mix(conn_id);

    const REF_PREFIX: &str = "Reference #";
    const REF_SUFFIX: &str = ".akamaihd.net";
    let mut ref_id = String::with_capacity(REF_PREFIX.len() + 16 + REF_SUFFIX.len());
    ref_id.push_str(REF_PREFIX);
    push_hex16(&mut ref_id, mixed);
    ref_id.push_str(REF_SUFFIX);

    let mut req_id = String::with_capacity(16);
    push_hex16(&mut req_id, mixed);

    vec![
        ("server", String::from("AkamaiGHost")),
        ("x-akamai-request-id", req_id),
        (
            "x-cache",
            String::from("TCP_MEM_HIT from a23-45-67-89.deploy.static.akamaitechnologies.com"),
        ),
        ("x-reference", ref_id),
    ]
}

fn fastly(conn_id: u64) -> Vec<(&'static str, String)> {
    // V230 — small-integer & 32-hex paths handled without `format!`.
    let mixed = mix(conn_id);

    let n = mixed % 9999;
    const SERVED_PREFIX: &str = "cache-fra-edg-";
    // u16 max 4 digits is plenty for 0..9999.
    let mut served = String::with_capacity(SERVED_PREFIX.len() + 4);
    served.push_str(SERVED_PREFIX);
    push_decimal(&mut served, n);

    // V230 — former `format!("{:032x}", u64)` produced 16 leading
    // zeros + 16 hex digits of the value. Reproduce exactly.
    let mut req_id = String::with_capacity(32);
    for _ in 0..16 {
        req_id.push('0');
    }
    push_hex16(&mut req_id, mixed);

    vec![
        ("server", String::from("Varnish")),
        ("x-served-by", served),
        ("x-cache", String::from("HIT")),
        ("x-fastly-request-id", req_id),
    ]
}

fn cloudfront(conn_id: u64) -> Vec<(&'static str, String)> {
    // V230 — POP table is `&'static [&'static str]`; index lookup
    // still needs an owned String for the tuple's `String` slot.
    const POP: [&str; 4] = ["FRA56-P1", "IAD53-C2", "LHR62-C1", "NRT57-P2"];
    let mixed = mix(conn_id);

    // V230 — `via` written directly. Format was `"1.1 {:x}.cloudfront.net (CloudFront)"`.
    const VIA_PREFIX: &str = "1.1 ";
    const VIA_SUFFIX: &str = ".cloudfront.net (CloudFront)";
    let mut via = String::with_capacity(VIA_PREFIX.len() + 16 + VIA_SUFFIX.len());
    via.push_str(VIA_PREFIX);
    push_hex_trimmed(&mut via, mixed);
    via.push_str(VIA_SUFFIX);

    vec![
        ("server", String::from("CloudFront")),
        (
            "x-amz-cf-pop",
            String::from(POP[(conn_id as usize) % POP.len()]),
        ),
        ("x-amz-cf-id", base64ish(mixed)),
        ("via", via),
    ]
}

// V230 — small hex/decimal writers. Avoid pulling in `format!`/`write!`
// fmt machinery for the deterministic decoy IDs (this builder runs
// on the high-threat hot path).
const HEX: &[u8; 16] = b"0123456789abcdef";

#[inline]
fn push_hex16(buf: &mut String, v: u64) {
    // Always 16 hex chars (zero-padded), matching former `{:016x}`.
    for i in (0..16).rev() {
        let nib = ((v >> (i * 4)) & 0xF) as usize;
        buf.push(HEX[nib] as char);
    }
}

#[inline]
fn push_hex_trimmed(buf: &mut String, v: u64) {
    // Matches former `{:x}` — no leading zeros, except v==0 prints "0".
    if v == 0 {
        buf.push('0');
        return;
    }
    let mut started = false;
    for i in (0..16).rev() {
        let nib = ((v >> (i * 4)) & 0xF) as usize;
        if !started && nib == 0 {
            continue;
        }
        started = true;
        buf.push(HEX[nib] as char);
    }
}

#[inline]
fn push_decimal(buf: &mut String, mut v: u64) {
    if v == 0 {
        buf.push('0');
        return;
    }
    // Max u64 decimal width is 20 — well under stack budget.
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    while v > 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // Safe: only ASCII digits written.
    buf.push_str(std::str::from_utf8(&tmp[i..]).unwrap());
}

fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn base64ish(n: u64) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(22);
    let mut v = n;
    for _ in 0..22 {
        out.push(ALPHA[(v & 0x3F) as usize] as char);
        v = v.rotate_left(7) ^ 0xA5A5A5A5;
    }
    out
}

/// Decide whether a given request *should* receive decoys. Caller
/// supplies the relevant signals — keeps the policy in one place.
pub fn should_decoy(challenge_fired: bool, ml_score: f32, honeypot_hit: bool) -> bool {
    challenge_fired || honeypot_hit || ml_score >= 0.65
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_set_has_known_fields() {
        let h = DecoyHeaders::build(DecoyFamily::Cloudflare, 1);
        let names: Vec<_> = h.iter().map(|(k, _)| *k).collect();
        for must in [
            "server",
            "cf-ray",
            "cf-cache-status",
            "alt-svc",
            "set-cookie",
        ] {
            assert!(names.contains(&must), "missing {must}");
        }
        assert_eq!(
            h.iter().find(|(k, _)| *k == "server").unwrap().1,
            "cloudflare"
        );
    }

    #[test]
    fn cf_ray_format() {
        let h = DecoyHeaders::build(DecoyFamily::Cloudflare, 12345);
        let ray = h.iter().find(|(k, _)| *k == "cf-ray").unwrap().1.clone();
        assert!(ray.ends_with("-FRA"));
        assert_eq!(ray.split('-').next().unwrap().len(), 16);
    }

    #[test]
    fn deterministic_per_conn() {
        let a = DecoyHeaders::build(DecoyFamily::Cloudflare, 42);
        let b = DecoyHeaders::build(DecoyFamily::Cloudflare, 42);
        let c = DecoyHeaders::build(DecoyFamily::Cloudflare, 43);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn other_families_render() {
        for fam in [
            DecoyFamily::Akamai,
            DecoyFamily::Fastly,
            DecoyFamily::CloudFront,
        ] {
            let h = DecoyHeaders::build(fam, 7);
            assert!(!h.is_empty());
            assert!(h.iter().any(|(k, _)| *k == "server"));
        }
    }

    #[test]
    fn should_decoy_only_on_signals() {
        assert!(!should_decoy(false, 0.1, false));
        assert!(should_decoy(true, 0.0, false));
        assert!(should_decoy(false, 0.0, true));
        assert!(should_decoy(false, 0.8, false));
        assert!(!should_decoy(false, 0.5, false));
    }

    // V230 — lock the format-equivalence of the manual writers
    // against `format!`'s canonical output. If these ever drift the
    // emitted headers no longer match Cloudflare/Akamai/Fastly/CF
    // wire shape and the deception layer breaks.
    #[test]
    fn hex_writers_match_format_macros() {
        for v in [
            0u64,
            1,
            0xdead_beef,
            0xffff_ffff_ffff_ffff,
            0x1234_5678_9abc_def0,
        ] {
            let mut s16 = String::new();
            push_hex16(&mut s16, v);
            assert_eq!(s16, format!("{v:016x}"));

            let mut stm = String::new();
            push_hex_trimmed(&mut stm, v);
            assert_eq!(stm, format!("{v:x}"));
        }
        for v in [0u64, 1, 9, 10, 99, 100, 9999, u64::MAX] {
            let mut s = String::new();
            push_decimal(&mut s, v);
            assert_eq!(s, format!("{v}"));
        }
    }

    #[test]
    fn fastly_request_id_is_32_hex_chars() {
        // Former `format!("{:032x}", u64)` was 16 leading zeros +
        // 16 lower-hex digits of the value. Lock that shape.
        let h = DecoyHeaders::build(DecoyFamily::Fastly, 0xabcd_ef01_2345_6789);
        let id = h
            .iter()
            .find(|(k, _)| *k == "x-fastly-request-id")
            .unwrap()
            .1
            .clone();
        assert_eq!(id.len(), 32);
        assert!(id.starts_with("0000000000000000"));
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
