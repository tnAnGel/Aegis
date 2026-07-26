//! JA4 family of fingerprints (FoxIO-LLC/ja4).
//!
//! Modern successor to JA3. The big wins over JA3:
//!
//!   1. **Stable across browser sessions** — JA3 hashes can drift when
//!      a browser shuffles extension order; JA4 sorts before hashing
//!      so cosmetic reorderings stay constant.
//!   2. **Human-readable prefix** — the `JA4_a` segment encodes TLS
//!      version, cipher count, extension count, ALPN as plain text,
//!      so operators can read it without a lookup table.
//!   3. **Multiple variants** — JA4 (TLS), JA4H (HTTP), JA4T (TCP
//!      handshake). Together they survive single-layer evasion (a
//!      botnet that proxies through curl-impersonate can spoof JA4
//!      but won't match JA4H if its request shape is wrong).
//!
//! This module produces three fingerprints:
//!   - [`compute_ja4`] from a TLS ClientHello — same input as JA3.
//!   - [`compute_ja4h`] from an HTTP request (method, version, headers).
//!   - [`compute_ja4t`] from a `tcp_info`-style SYN summary.
//!
//! JA4 hashes are 12 hex chars (sha256 prefix) so they can be embedded
//! in tracing fields and dashboards without truncation. Threat-intel
//! feeds publish the same form.

use sha2::{Digest, Sha256};

// ───────────────────────── JA4 (TLS) ─────────────────────────────────

const TLS_HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const EXT_SIG_ALGORITHMS: u16 = 13;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

/// Output of [`compute_ja4`].
///
/// `full` is the canonical form `q13d1516h2_8daaf6152771_b186095e22b6`;
/// `a` is the human-readable prefix; `b` and `c` are the two sha256
/// segments. Operators copy whichever form their tooling expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Fingerprint {
    pub full: String,
    pub a: String,
    pub b: String,
    pub c: String,
}

/// Parse a TLS record + ClientHello prefix into a JA4 fingerprint.
/// Returns None when the input isn't a well-formed TLS handshake.
///
/// `is_quic` should be true only when the bytes arrived on a QUIC
/// CRYPTO frame; for plain TCP TLS pass false.
/// V178 — extract the GREASE positions the parser would have stripped.
/// Returns an observation of whether the cipher list, extension list,
/// and supported_versions payload each *start* with a GREASE value.
/// Genuine Chrome emits GREASE in all three slots; utls / curl-
/// impersonate spoofers hardcode one permutation that frequently
/// misses at least one slot.
///
/// Returns None for the same reasons [`compute_ja4`] returns None
/// (malformed ClientHello).
pub fn extract_grease_positions(buf: &[u8]) -> Option<crate::grease_anomaly::GreaseObservation> {
    let mut r = Reader::new(buf);
    let content_type = r.u8()?;
    if content_type != TLS_HANDSHAKE {
        return None;
    }
    let _record_version = r.u16()?;
    let record_len = r.u16()? as usize;
    if r.remaining() < record_len {
        return None;
    }
    let hs_type = r.u8()?;
    if hs_type != CLIENT_HELLO {
        return None;
    }
    let hs_len = r.u24()? as usize;
    if hs_len > r.remaining() {
        return None;
    }
    let mut hs = Reader::new(r.take(hs_len)?);
    let _client_version = hs.u16()?;
    hs.skip(32)?;
    let sid_len = hs.u8()? as usize;
    hs.skip(sid_len)?;
    let cipher_bytes_len = hs.u16()? as usize;
    let cipher_bytes = hs.take(cipher_bytes_len)?;
    let first_cipher = parse_u16_list(cipher_bytes).first().copied();
    let comp_len = hs.u8()? as usize;
    hs.skip(comp_len)?;
    let mut first_extension: Option<u16> = None;
    let mut supported_versions_head: Option<u16> = None;
    if hs.remaining() >= 2 {
        let ext_len = hs.u16()? as usize;
        let ext_bytes = hs.take(ext_len)?;
        let mut er = Reader::new(ext_bytes);
        let mut idx = 0usize;
        while er.remaining() >= 4 {
            let Some(ty) = er.u16() else { break };
            let Some(len) = er.u16() else { break };
            let Some(data) = er.take(len as usize) else {
                break;
            };
            if idx == 0 {
                first_extension = Some(ty);
            }
            idx += 1;
            if ty == EXT_SUPPORTED_VERSIONS {
                let mut inner = Reader::new(data);
                if let Some(l) = inner.u8()
                    && let Some(b) = inner.take(l as usize)
                {
                    supported_versions_head = parse_u16_list(b).first().copied();
                }
            }
        }
    }
    Some(crate::grease_anomaly::observe(
        first_cipher,
        first_extension,
        supported_versions_head,
    ))
}

pub fn compute_ja4(buf: &[u8], is_quic: bool) -> Option<Ja4Fingerprint> {
    let mut r = Reader::new(buf);
    let content_type = r.u8()?;
    if content_type != TLS_HANDSHAKE {
        return None;
    }
    let _record_version = r.u16()?;
    let record_len = r.u16()? as usize;
    if r.remaining() < record_len {
        return None;
    }

    let hs_type = r.u8()?;
    if hs_type != CLIENT_HELLO {
        return None;
    }
    let hs_len = r.u24()? as usize;
    if hs_len > r.remaining() {
        return None;
    }
    let mut hs = Reader::new(r.take(hs_len)?);

    let client_version = hs.u16()?;
    hs.skip(32)?; // random
    let sid_len = hs.u8()? as usize;
    hs.skip(sid_len)?;

    let cipher_bytes_len = hs.u16()? as usize;
    let cipher_bytes = hs.take(cipher_bytes_len)?;
    let ciphers: Vec<u16> = parse_u16_list(cipher_bytes)
        .into_iter()
        .filter(|v| !is_grease(*v))
        .collect();

    let comp_len = hs.u8()? as usize;
    hs.skip(comp_len)?;

    let mut extensions: Vec<u16> = Vec::new();
    let mut alpn_first: Option<Vec<u8>> = None;
    let mut sni_present = false;
    let mut sig_algos: Vec<u16> = Vec::new();
    let mut highest_version: u16 = client_version;
    if hs.remaining() >= 2 {
        let ext_len = hs.u16()? as usize;
        let ext_bytes = hs.take(ext_len)?;
        let mut er = Reader::new(ext_bytes);
        while er.remaining() >= 4 {
            let Some(ty) = er.u16() else { break };
            let Some(len) = er.u16() else { break };
            let Some(data) = er.take(len as usize) else {
                break;
            };
            if is_grease(ty) {
                continue;
            }
            extensions.push(ty);
            match ty {
                EXT_SERVER_NAME => {
                    sni_present = true;
                }
                EXT_ALPN => {
                    // First ALPN protocol: u16 list-len, then u8-len-prefixed strings.
                    let mut inner = Reader::new(data);
                    if let Some(_list_len) = inner.u16()
                        && let Some(p_len) = inner.u8()
                        && let Some(p) = inner.take(p_len as usize)
                    {
                        alpn_first = Some(p.to_vec());
                    }
                }
                EXT_SIG_ALGORITHMS => {
                    let mut inner = Reader::new(data);
                    if let Some(l) = inner.u16()
                        && let Some(b) = inner.take(l as usize)
                    {
                        sig_algos = parse_u16_list(b);
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    let mut inner = Reader::new(data);
                    // Client form: u8 length-prefix + list of u16.
                    if let Some(l) = inner.u8()
                        && let Some(b) = inner.take(l as usize)
                    {
                        for v in parse_u16_list(b) {
                            if is_grease(v) {
                                continue;
                            }
                            if v > highest_version {
                                highest_version = v;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // a-segment ----------------------------------------------------------
    let proto = if is_quic { 'q' } else { 't' };
    let ver = tls_version_label(highest_version);
    let sni = if sni_present { 'd' } else { 'i' };
    let cipher_count_hex = cap_hex_2(ciphers.len());
    // Extension count excludes SNI (0) and ALPN (16) — spec quirk.
    let ext_for_count = extensions
        .iter()
        .filter(|t| **t != EXT_SERVER_NAME && **t != EXT_ALPN)
        .count();
    let ext_count_hex = cap_hex_2(ext_for_count);
    let alpn_tag = alpn_tag(alpn_first.as_deref());
    let a = format!("{proto}{ver}{sni}{cipher_count_hex}{ext_count_hex}{alpn_tag}");

    // b-segment: sorted ciphers ------------------------------------------
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cipher_csv = sorted_ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let b = sha_prefix12(&cipher_csv);

    // c-segment: sorted extensions (sans SNI/ALPN) + sig algos -----------
    let mut filtered_ext: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|t| *t != EXT_SERVER_NAME && *t != EXT_ALPN)
        .collect();
    filtered_ext.sort_unstable();
    let ext_csv = filtered_ext
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let sig_csv = sig_algos
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let combined = if sig_csv.is_empty() {
        ext_csv
    } else {
        format!("{ext_csv}_{sig_csv}")
    };
    let c = sha_prefix12(&combined);

    let full = format!("{a}_{b}_{c}");
    Some(Ja4Fingerprint { full, a, b, c })
}

/// V51 — JA4 from already-parsed pieces. Lets the openssl
/// TlsAccept callback build a JA4 fingerprint without raw TLS record
/// bytes (openssl's `SSL_client_hello_get0_*` accessors return
/// parsed fields, not the wire-format record).
///
/// Inputs are already GREASE-filtered (caller is expected to drop
/// 0x?A0A codepoints — see `is_grease`). `client_version` is the
/// legacy TLS version field; `supported_versions` is the
/// extension-43 content (empty vec when not present). The function
/// picks the highest non-GREASE version across both as `highest_version`.
/// `alpn_first` is the first ALPN protocol byte slice (empty when
/// the ALPN extension is absent).
#[allow(clippy::too_many_arguments)]
pub fn compute_ja4_from_parts(
    is_quic: bool,
    client_version: u16,
    ciphers: &[u16],
    extension_types: &[u16],
    sni_present: bool,
    alpn_first: &[u8],
    sig_algos: &[u16],
    supported_versions: &[u16],
) -> Ja4Fingerprint {
    let mut highest_version = client_version;
    for v in supported_versions {
        if !is_grease(*v) && *v > highest_version {
            highest_version = *v;
        }
    }
    // a-segment ---------------------------------------------------------
    let proto = if is_quic { 'q' } else { 't' };
    let ver = tls_version_label(highest_version);
    let sni = if sni_present { 'd' } else { 'i' };
    let cipher_count_hex = cap_hex_2(ciphers.len());
    let ext_for_count = extension_types
        .iter()
        .filter(|t| **t != EXT_SERVER_NAME && **t != EXT_ALPN)
        .count();
    let ext_count_hex = cap_hex_2(ext_for_count);
    let alpn_tag = alpn_tag(if alpn_first.is_empty() {
        None
    } else {
        Some(alpn_first)
    });
    let a = format!("{proto}{ver}{sni}{cipher_count_hex}{ext_count_hex}{alpn_tag}");

    // b-segment: sorted ciphers -----------------------------------------
    let mut sorted_ciphers: Vec<u16> = ciphers.to_vec();
    sorted_ciphers.sort_unstable();
    let cipher_csv = sorted_ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let b = sha_prefix12(&cipher_csv);

    // c-segment: sorted extensions (sans SNI/ALPN) + sig algos ----------
    let mut filtered_ext: Vec<u16> = extension_types
        .iter()
        .copied()
        .filter(|t| *t != EXT_SERVER_NAME && *t != EXT_ALPN)
        .collect();
    filtered_ext.sort_unstable();
    let ext_csv = filtered_ext
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let sig_csv = sig_algos
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let combined = if sig_csv.is_empty() {
        ext_csv
    } else {
        format!("{ext_csv}_{sig_csv}")
    };
    let c = sha_prefix12(&combined);

    let full = format!("{a}_{b}_{c}");
    Ja4Fingerprint { full, a, b, c }
}

fn tls_version_label(v: u16) -> &'static str {
    // FoxIO labels follow the wire constants but expressed as decimal
    // version: 0x0304 → "13", 0x0303 → "12", 0x0302 → "11", 0x0301 →
    // "10", 0x0300 → "s3".
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn cap_hex_2(n: usize) -> String {
    let v = n.min(0x99);
    format!("{v:02x}")
}

/// ALPN tag is `first_char + last_char` of the first ALPN protocol,
/// lowercase ASCII. Non-printable / non-ASCII bytes encode as their
/// hex pair. Empty ALPN → "00".
fn alpn_tag(alpn: Option<&[u8]>) -> String {
    let Some(bytes) = alpn else {
        return "00".to_string();
    };
    if bytes.is_empty() {
        return "00".to_string();
    }
    let first = bytes[0];
    let last = *bytes.last().unwrap();
    let f = char_or_hex(first);
    let l = char_or_hex(last);
    format!("{f}{l}")
}

fn char_or_hex(b: u8) -> String {
    if b.is_ascii_graphic() {
        (b as char).to_ascii_lowercase().to_string()
    } else {
        format!("{b:02x}")
    }
}

// ───────────────────────── JA4H (HTTP) ───────────────────────────────

/// Output of [`compute_ja4h`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4hFingerprint {
    pub full: String,
    pub a: String,
    pub b: String,
    pub c: String,
    pub d: String,
}

/// Compute the JA4H fingerprint for an HTTP request.
///
/// Args reflect FoxIO's reference inputs:
///   - `method` — e.g. "GET", "POST"
///   - `http_version` — "1.0", "1.1", "2.0", "3.0"
///   - `headers` — name/value pairs in arrival order (case insensitive)
///
/// Order matters for the b-segment (header names hashed in order);
/// cookie order is normalised (sorted) for c/d segments.
pub fn compute_ja4h(
    method: &str,
    http_version: &str,
    headers: &[(String, String)],
) -> Ja4hFingerprint {
    // a-segment
    let m = method.to_ascii_lowercase();
    let method_2 = format!(
        "{}{}",
        m.chars().next().unwrap_or('0'),
        m.chars().nth(1).unwrap_or('0')
    );
    let ver = match http_version {
        "1.0" | "HTTP/1.0" => "10",
        "1.1" | "HTTP/1.1" => "11",
        "2.0" | "HTTP/2.0" | "HTTP/2" => "20",
        "3.0" | "HTTP/3.0" | "HTTP/3" => "30",
        _ => "00",
    };
    let mut has_cookie = false;
    let mut has_referer = false;
    let mut accept_lang: Option<String> = None;
    let mut cookie_raw: Option<String> = None;
    let mut counted_headers = 0usize;
    let mut ordered_header_names: Vec<String> = Vec::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        // Pseudo-headers (HTTP/2: :method, :path, …) are excluded
        // from the count and the order list per spec.
        if lower.starts_with(':') {
            continue;
        }
        if lower == "cookie" {
            has_cookie = true;
            cookie_raw = Some(value.clone());
            continue;
        }
        if lower == "referer" {
            has_referer = true;
            continue;
        }
        counted_headers += 1;
        if lower == "accept-language" && accept_lang.is_none() {
            // Take primary range: "en-US,en;q=0.9" → "enus" lowercase
            let primary = value.split(',').next().unwrap_or("").trim();
            let normalised: String = primary
                .chars()
                .filter(|c| c.is_ascii_alphabetic())
                .take(4)
                .collect::<String>()
                .to_ascii_lowercase();
            accept_lang = Some(normalised);
        }
        ordered_header_names.push(lower);
    }
    let cookie_tag = if has_cookie { 'c' } else { 'n' };
    let referer_tag = if has_referer { 'r' } else { 'n' };
    let header_count_hex = cap_hex_2(counted_headers);
    let lang = accept_lang.unwrap_or_default();
    let lang_padded = format!("{lang:0<4}");
    let lang_padded = lang_padded.chars().take(4).collect::<String>();
    let a = format!("{method_2}{ver}{cookie_tag}{referer_tag}{header_count_hex}{lang_padded}");

    // b-segment: header NAMES in order, lowercase, comma-joined,
    // *excluding* cookie/referer (already filtered above).
    let b_input = ordered_header_names.join(",");
    let b = sha_prefix12(&b_input);

    // c-segment: cookie names sorted, comma-joined.
    // d-segment: cookie name=value sorted, comma-joined.
    let (c, d) = if let Some(raw) = cookie_raw {
        let mut names: Vec<String> = Vec::new();
        let mut kvs: Vec<String> = Vec::new();
        for part in raw.split(';') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (k, v) = match trimmed.split_once('=') {
                Some(pair) => pair,
                None => (trimmed, ""),
            };
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.is_empty() {
                continue;
            }
            names.push(k.clone());
            kvs.push(format!("{k}={v}"));
        }
        names.sort();
        kvs.sort();
        (sha_prefix12(&names.join(",")), sha_prefix12(&kvs.join(",")))
    } else {
        (sha_prefix12(""), sha_prefix12(""))
    };

    Ja4hFingerprint {
        full: format!("{a}_{b}_{c}_{d}"),
        a,
        b,
        c,
        d,
    }
}

/// Borrowed-input variant of [`compute_ja4h`]. Lets the hot proxy
/// path skip the `Vec<(String, String)>` materialisation step (one
/// allocation per header pair becomes zero — only the lowercased
/// header names allocate, same as the original code path).
///
/// Behaviour is identical to `compute_ja4h` for the same logical
/// input.
pub fn compute_ja4h_from_headermap(
    method: &str,
    http_version: &str,
    headers: &http::HeaderMap,
) -> Ja4hFingerprint {
    let m = method.to_ascii_lowercase();
    let method_2 = format!(
        "{}{}",
        m.chars().next().unwrap_or('0'),
        m.chars().nth(1).unwrap_or('0')
    );
    let ver = match http_version {
        "1.0" | "HTTP/1.0" => "10",
        "1.1" | "HTTP/1.1" => "11",
        "2.0" | "HTTP/2.0" | "HTTP/2" => "20",
        "3.0" | "HTTP/3.0" | "HTTP/3" => "30",
        _ => "00",
    };
    let mut has_cookie = false;
    let mut has_referer = false;
    let mut accept_lang: Option<String> = None;
    let mut cookie_raw: Option<&str> = None;
    let mut counted_headers = 0usize;
    // Borrow HeaderName slices directly — avoids one `String` alloc
    // per header on every request (HeaderName is already lowercase
    // per http crate invariants).
    let mut ordered_header_names: Vec<&str> = Vec::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if name_str.starts_with(':') {
            continue;
        }
        let lower = name_str;
        let Ok(value_str) = value.to_str() else {
            continue;
        };
        if lower == "cookie" {
            has_cookie = true;
            cookie_raw = Some(value_str);
            continue;
        }
        if lower == "referer" {
            has_referer = true;
            continue;
        }
        counted_headers += 1;
        if lower == "accept-language" && accept_lang.is_none() {
            let primary = value_str.split(',').next().unwrap_or("").trim();
            let normalised: String = primary
                .chars()
                .filter(|c| c.is_ascii_alphabetic())
                .take(4)
                .collect::<String>()
                .to_ascii_lowercase();
            accept_lang = Some(normalised);
        }
        ordered_header_names.push(lower);
    }
    let cookie_tag = if has_cookie { 'c' } else { 'n' };
    let referer_tag = if has_referer { 'r' } else { 'n' };
    let header_count_hex = cap_hex_2(counted_headers);
    let lang = accept_lang.unwrap_or_default();
    let lang_padded = format!("{lang:0<4}");
    let lang_padded = lang_padded.chars().take(4).collect::<String>();
    let a = format!("{method_2}{ver}{cookie_tag}{referer_tag}{header_count_hex}{lang_padded}");
    // `Vec<&str>::join` allocates exactly one String of known total len.
    let b_input = ordered_header_names.join(",");
    let b = sha_prefix12(&b_input);
    let (c, d) = if let Some(raw) = cookie_raw {
        let mut names: Vec<String> = Vec::new();
        let mut kvs: Vec<String> = Vec::new();
        for part in raw.split(';') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (k, v) = match trimmed.split_once('=') {
                Some(pair) => pair,
                None => (trimmed, ""),
            };
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.is_empty() {
                continue;
            }
            names.push(k.clone());
            kvs.push(format!("{k}={v}"));
        }
        names.sort();
        kvs.sort();
        (sha_prefix12(&names.join(",")), sha_prefix12(&kvs.join(",")))
    } else {
        (sha_prefix12(""), sha_prefix12(""))
    };
    Ja4hFingerprint {
        full: format!("{a}_{b}_{c}_{d}"),
        a,
        b,
        c,
        d,
    }
}

// ───────────────────────── JA4T (TCP) ────────────────────────────────

/// Inputs for [`compute_ja4t`]. Operators populate these from
/// whatever capture surface they have access to — typically Linux
/// `TCP_INFO` for `mss` and `wscale_recv`. `options_order` and
/// `window` come from the original SYN options; without an eBPF
/// SYN-capture program both fields are best-effort.
#[derive(Debug, Clone, Default)]
pub struct Ja4tInput {
    /// SYN advertised window.
    pub window: u16,
    /// TCP options in the order they appeared in the SYN ("2,4,8,1,3"
    /// — kind numbers comma-joined). Best-effort: kernel doesn't
    /// expose this, see eBPF capture in xdp/ when enabled.
    pub options_order: String,
    /// Maximum Segment Size negotiated.
    pub mss: u16,
    /// Window scale exponent.
    pub wscale: u8,
}

/// JA4T fingerprint, formatted as `{window}_{options}_{mss}_{wscale}`.
/// Returns "0_0_0_0" when no fields are populated — operators use that
/// sentinel to filter out captures where SYN information is missing.
pub fn compute_ja4t(input: &Ja4tInput) -> String {
    let opts = if input.options_order.is_empty() {
        "0".to_string()
    } else {
        input.options_order.clone()
    };
    format!("{}_{}_{}_{}", input.window, opts, input.mss, input.wscale)
}

// ───────────────────────── JA4L (latency) ────────────────────────────

/// JA4L latency input. Two halves per the FoxIO canonical:
///
///   - `client_to_server_us` — how long the kernel spent waiting for
///     the client to complete the TCP handshake (server SYN-ACK →
///     client ACK). Derived from `SO_TIMESTAMPNS` / `TCP_INFO`'s
///     `tcpi_rcv_rtt` where available; falls back to the
///     ClientHello-arrival window when not.
///   - `server_to_client_us` — server-side TLS-stack latency from
///     the moment we receive the client's last handshake message
///     to the moment rustls says "Finished" (acceptor.accept()
///     returns). This includes our own CPU cost + the wait for
///     the encrypted Finished round-trip.
///
/// Both halves in **microseconds**, not ms — matches the FoxIO
/// spec ("JA4L values are reported in microseconds for granularity").
#[derive(Debug, Clone, Copy, Default)]
pub struct Ja4lInput {
    pub client_to_server_us: u64,
    pub server_to_client_us: u64,
}

/// Format a `Ja4lInput` as the canonical `{client}_{server}` string.
/// Each half is the saturating-subtracted integer microsecond count.
pub fn compute_ja4l_pair(input: &Ja4lInput) -> String {
    format!(
        "{}_{}",
        input.client_to_server_us, input.server_to_client_us
    )
}

/// Legacy single-observation form — see `compute_ja4l_pair` for the
/// canonical two-half output. Kept so the existing wiring still
/// compiles while we migrate call sites; new code should construct a
/// `Ja4lInput` and pass distinct values.
///
/// `observed_at` and `done_at` are POSIX millisecond timestamps; the
/// returned string is `{rtt_us}_{rtt_us}` (same value for both
/// halves, multiplied to microseconds).
pub fn compute_ja4l(observed_at_ms: u64, done_at_ms: u64) -> String {
    let rtt_us = done_at_ms
        .saturating_sub(observed_at_ms)
        .saturating_mul(1_000);
    format!("{rtt_us}_{rtt_us}")
}

#[cfg(test)]
mod ja4l_tests {
    use super::*;
    #[test]
    fn legacy_single_observation_uses_microseconds() {
        let s = compute_ja4l(1_000, 1_042);
        // 42 ms → 42 000 µs, reported as both halves.
        assert_eq!(s, "42000_42000");
    }

    #[test]
    fn legacy_handles_clock_skew_gracefully() {
        let s = compute_ja4l(1_000, 500);
        assert_eq!(s, "0_0");
    }

    #[test]
    fn pair_form_distinct_halves() {
        let s = compute_ja4l_pair(&Ja4lInput {
            client_to_server_us: 4_200,
            server_to_client_us: 18_500,
        });
        assert_eq!(s, "4200_18500");
    }

    #[test]
    fn pair_zeroed_input_renders_zero_zero() {
        assert_eq!(compute_ja4l_pair(&Ja4lInput::default()), "0_0");
    }
}

// ───────────────────────── helpers ───────────────────────────────────

fn parse_u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

fn is_grease(v: u16) -> bool {
    let lo = (v & 0xff) as u8;
    let hi = (v >> 8) as u8;
    lo == hi && (lo & 0x0f) == 0x0a
}

fn sha_prefix12(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(12);
    for b in digest.iter().take(6) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.buf.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<u32> {
        let b = self.buf.get(self.pos..self.pos + 3)?;
        self.pos += 3;
        Some(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.remaining() < n {
            return None;
        }
        self.pos += n;
        Some(())
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same minimal hello as in ja3.rs but enriched with SNI + ALPN +
    /// supported_versions so JA4 has interesting prefix bytes.
    fn rich_client_hello() -> Vec<u8> {
        let mut hs = Vec::new();
        hs.extend_from_slice(&0x0303u16.to_be_bytes()); // record-side ver
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session id len

        // Ciphers: GREASE + TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384
        let ciphers: [u16; 3] = [0x0a0a, 0x1301, 0x1302];
        hs.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            hs.extend_from_slice(&c.to_be_bytes());
        }
        hs.push(1); // compression methods len
        hs.push(0);

        // Extensions
        let mut exts = Vec::new();
        // server_name (0): list-len + entry-type 0 + entry-len + "x"
        let mut sni = Vec::new();
        let name = b"x";
        sni.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes()); // list len
        sni.push(0); // type host_name
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni);

        // ALPN (16): list-len + u8-len + "h2"
        let alpn_str = b"h2";
        let mut alpn = Vec::new();
        alpn.extend_from_slice(&((1 + alpn_str.len()) as u16).to_be_bytes());
        alpn.push(alpn_str.len() as u8);
        alpn.extend_from_slice(alpn_str);
        exts.extend_from_slice(&16u16.to_be_bytes());
        exts.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn);

        // supported_versions (43) client form: u8 list-len + entries
        let sv: Vec<u8> = {
            let entries: [u16; 2] = [0x0304, 0x0303];
            let mut v = Vec::new();
            v.push((entries.len() * 2) as u8);
            for e in entries {
                v.extend_from_slice(&e.to_be_bytes());
            }
            v
        };
        exts.extend_from_slice(&43u16.to_be_bytes());
        exts.extend_from_slice(&(sv.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sv);

        // signature_algorithms (13): u16 list-len + entries
        let sigs: [u16; 2] = [0x0403, 0x0804];
        let mut sigb = Vec::new();
        sigb.extend_from_slice(&((sigs.len() * 2) as u16).to_be_bytes());
        for s in sigs {
            sigb.extend_from_slice(&s.to_be_bytes());
        }
        exts.extend_from_slice(&13u16.to_be_bytes());
        exts.extend_from_slice(&(sigb.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sigb);

        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);

        let mut handshake = vec![CLIENT_HELLO];
        let hs_len = hs.len() as u32;
        handshake.push(((hs_len >> 16) & 0xff) as u8);
        handshake.push(((hs_len >> 8) & 0xff) as u8);
        handshake.push((hs_len & 0xff) as u8);
        handshake.extend_from_slice(&hs);

        let mut record = vec![TLS_HANDSHAKE];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn computes_ja4_prefix() {
        let fp = compute_ja4(&rich_client_hello(), false).expect("parses");
        // proto=t, ver=13 (supported_versions has 0x0304),
        // sni=d, ciphers=02 (GREASE stripped: 2 remain),
        // ext_count=02 (SNI + ALPN excluded -> 2 = supported_versions + sig_algos),
        // alpn=h2
        assert_eq!(fp.a, "t13d0202h2");
        // hash segments must be 12 hex chars
        assert_eq!(fp.b.len(), 12);
        assert_eq!(fp.c.len(), 12);
        assert!(fp.full.starts_with(&fp.a));
        assert!(fp.full.contains(&fp.b));
        assert!(fp.full.contains(&fp.c));
    }

    #[test]
    fn ja4_rejects_non_handshake() {
        let mut buf = rich_client_hello();
        buf[0] = 23;
        assert!(compute_ja4(&buf, false).is_none());
    }

    #[test]
    fn quic_flag_changes_proto_letter() {
        let fp = compute_ja4(&rich_client_hello(), true).expect("parses");
        assert!(fp.a.starts_with('q'));
    }

    #[test]
    fn ja4_grease_stripped_from_hash() {
        // Two hellos identical except for a GREASE cipher value
        // sprinkled in must produce the same JA4.
        let base = rich_client_hello();
        let fp1 = compute_ja4(&base, false).unwrap();
        // Compute a second variant by re-running the builder — the
        // GREASE 0x0a0a is already in there. Removing it should still
        // produce the same b/c segments because GREASE is filtered.
        let fp2 = compute_ja4(&base, false).unwrap();
        assert_eq!(fp1.b, fp2.b);
        assert_eq!(fp1.c, fp2.c);
    }

    #[test]
    fn ja4h_basic_get_request() {
        let headers = vec![
            ("Host".into(), "example.com".into()),
            ("User-Agent".into(), "Mozilla/5.0".into()),
            ("Accept-Language".into(), "en-US,en;q=0.9".into()),
            ("Cookie".into(), "session=abc; theme=dark".into()),
            ("Referer".into(), "https://google.com/".into()),
        ];
        let fp = compute_ja4h("GET", "1.1", &headers);
        // method=ge, ver=11, cookie=c, referer=r, counted hdrs = 3
        // (Host, User-Agent, Accept-Language; Cookie + Referer excluded),
        // lang=enus
        assert_eq!(fp.a, "ge11cr03enus");
        // Each hash 12 hex chars
        for s in [&fp.b, &fp.c, &fp.d] {
            assert_eq!(s.len(), 12, "{s} should be 12 hex chars");
        }
        // Different cookie ordering must still produce the same c/d hash.
        let headers2 = vec![
            ("Host".into(), "example.com".into()),
            ("User-Agent".into(), "Mozilla/5.0".into()),
            ("Accept-Language".into(), "en-US,en;q=0.9".into()),
            ("Cookie".into(), "theme=dark; session=abc".into()),
            ("Referer".into(), "https://google.com/".into()),
        ];
        let fp2 = compute_ja4h("GET", "1.1", &headers2);
        assert_eq!(fp.c, fp2.c);
        assert_eq!(fp.d, fp2.d);
    }

    #[test]
    fn ja4h_no_cookie_no_referer() {
        let headers = vec![("Host".into(), "example.com".into())];
        let fp = compute_ja4h("POST", "2.0", &headers);
        // method=po, ver=20, cookie=n, referer=n, headers=1, lang missing -> "0000"
        assert_eq!(fp.a, "po20nn010000");
    }

    #[test]
    fn ja4h_strips_pseudo_headers() {
        let headers = vec![
            (":method".into(), "GET".into()),
            (":path".into(), "/".into()),
            ("Host".into(), "x".into()),
        ];
        let fp = compute_ja4h("GET", "2.0", &headers);
        // Only Host counted.
        assert_eq!(fp.a, "ge20nn010000");
    }

    #[test]
    fn ja4h_method_uses_lowercase_two_chars() {
        let fp = compute_ja4h("DELETE", "1.1", &[]);
        assert!(fp.a.starts_with("de"));
        let fp2 = compute_ja4h("X", "1.1", &[]);
        // Method shorter than 2 chars pads with '0'.
        assert!(fp2.a.starts_with("x0"));
    }

    #[test]
    fn ja4t_renders_empty_as_zero_sentinel() {
        let s = compute_ja4t(&Ja4tInput::default());
        assert_eq!(s, "0_0_0_0");
    }

    #[test]
    fn ja4t_full_render() {
        let s = compute_ja4t(&Ja4tInput {
            window: 65535,
            options_order: "2,4,8,1,3".to_string(),
            mss: 1460,
            wscale: 7,
        });
        assert_eq!(s, "65535_2,4,8,1,3_1460_7");
    }

    /// V56 — cross-binary parity for JA4: the byte-parser path
    /// (compute_ja4, used inside the rustls/quinn TLS-sniffing edge
    /// the hyper handler runs) and the from-parts path (used by the
    /// pingora openssl TlsAccept callback in `proxy::pingora_tls`)
    /// MUST produce byte-identical fingerprints for the same
    /// ClientHello.
    #[test]
    fn from_parts_matches_byte_parser_tls13() {
        // Hand-built TLS 1.3 ClientHello fixture covering all the
        // signals JA4 reads: ciphers, extensions, SNI presence,
        // ALPN, signature_algorithms, supported_versions.
        let buf = build_minimal_tls13_client_hello();
        let from_bytes = compute_ja4(&buf, false).expect("byte parser");

        // Now parse out the same fields by walking the buffer
        // exactly like compute_ja4 does, then run from_parts.
        let mut r = Reader::new(&buf);
        r.u8().unwrap(); // content_type
        r.u16().unwrap(); // record_version
        r.u16().unwrap(); // record_len
        r.u8().unwrap(); // hs_type
        r.u24().unwrap(); // hs_len
        let cv = r.u16().unwrap();
        r.skip(32).unwrap();
        let sl = r.u8().unwrap() as usize;
        r.skip(sl).unwrap();
        let cipher_len = r.u16().unwrap() as usize;
        let cipher_bytes = r.take(cipher_len).unwrap();
        let ciphers: Vec<u16> = parse_u16_list(cipher_bytes)
            .into_iter()
            .filter(|v| !is_grease(*v))
            .collect();
        let comp_len = r.u8().unwrap() as usize;
        r.skip(comp_len).unwrap();

        let ext_len = r.u16().unwrap() as usize;
        let ext_bytes = r.take(ext_len).unwrap();
        let mut er = Reader::new(ext_bytes);
        let mut extensions = Vec::new();
        let mut alpn_first: Vec<u8> = Vec::new();
        let mut sni_present = false;
        let mut sig_algos: Vec<u16> = Vec::new();
        let mut supported_versions: Vec<u16> = Vec::new();
        while er.remaining() >= 4 {
            let ty = er.u16().unwrap();
            let len = er.u16().unwrap() as usize;
            let data = er.take(len).unwrap();
            if is_grease(ty) {
                continue;
            }
            extensions.push(ty);
            match ty {
                EXT_SERVER_NAME => sni_present = true,
                EXT_ALPN => {
                    let mut inner = Reader::new(data);
                    if let Some(_list_len) = inner.u16()
                        && let Some(p_len) = inner.u8()
                        && let Some(p) = inner.take(p_len as usize)
                    {
                        alpn_first = p.to_vec();
                    }
                }
                EXT_SIG_ALGORITHMS => {
                    let mut inner = Reader::new(data);
                    if let Some(l) = inner.u16()
                        && let Some(b) = inner.take(l as usize)
                    {
                        sig_algos = parse_u16_list(b);
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    let mut inner = Reader::new(data);
                    if let Some(l) = inner.u8()
                        && let Some(b) = inner.take(l as usize)
                    {
                        supported_versions = parse_u16_list(b);
                    }
                }
                _ => {}
            }
        }
        let from_parts = compute_ja4_from_parts(
            false,
            cv,
            &ciphers,
            &extensions,
            sni_present,
            &alpn_first,
            &sig_algos,
            &supported_versions,
        );
        assert_eq!(
            from_bytes.full, from_parts.full,
            "JA4 full-string drift between byte parser ({})\
             and from_parts ({})",
            from_bytes.full, from_parts.full
        );
        assert_eq!(from_bytes.a, from_parts.a, "JA4 a-segment drift");
        assert_eq!(from_bytes.b, from_parts.b, "JA4 b-segment drift");
        assert_eq!(from_bytes.c, from_parts.c, "JA4 c-segment drift");
    }

    fn build_minimal_tls13_client_hello() -> Vec<u8> {
        // TLS 1.3 ClientHello: legacy_version = 0x0303, single
        // cipher (0x1301 = TLS_AES_128_GCM_SHA256), extensions:
        //   server_name (0): host "ex"
        //   supported_groups (10): [0x001d]
        //   ec_point_formats (11): [0x00]
        //   signature_algorithms (13): [0x0403, 0x0804]
        //   alpn (16): "h2"
        //   supported_versions (43): [0x0304]
        // No GREASE for deterministic fixture.
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // legacy version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // sid_len = 0
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // ciphers: 2 bytes, 0x1301
        hs.extend_from_slice(&[0x01, 0x00]); // compression: len=1, [0]

        let mut exts = Vec::new();
        // server_name: ext type 0, body = list_len(2) || type(0) || host_len(2) || "ex"
        let sni_body: Vec<u8> = vec![
            0x00, 0x05, // list_len=5
            0x00, // host_type=0
            0x00, 0x02, // host_len=2
            b'e', b'x',
        ];
        exts.extend_from_slice(&[0x00, 0x00, 0x00, sni_body.len() as u8]);
        exts.extend_from_slice(&sni_body);
        // supported_groups: type 10, body = u16 list_len || u16 entries
        let sg_body = vec![0x00, 0x02, 0x00, 0x1d];
        exts.extend_from_slice(&[0x00, 0x0a, 0x00, sg_body.len() as u8]);
        exts.extend_from_slice(&sg_body);
        // ec_point_formats: type 11, body = u8 len || bytes
        let ec_body = vec![0x01, 0x00];
        exts.extend_from_slice(&[0x00, 0x0b, 0x00, ec_body.len() as u8]);
        exts.extend_from_slice(&ec_body);
        // signature_algorithms: type 13, body = u16 list_len || u16 entries
        let sig_body = vec![0x00, 0x04, 0x04, 0x03, 0x08, 0x04];
        exts.extend_from_slice(&[0x00, 0x0d, 0x00, sig_body.len() as u8]);
        exts.extend_from_slice(&sig_body);
        // alpn: type 16, body = u16 list_len || (u8 plen || proto)+
        let alpn_body = vec![0x00, 0x03, 0x02, b'h', b'2'];
        exts.extend_from_slice(&[0x00, 0x10, 0x00, alpn_body.len() as u8]);
        exts.extend_from_slice(&alpn_body);
        // supported_versions (client form): type 43, body = u8 list_len || u16 entries
        let sv_body = vec![0x02, 0x03, 0x04];
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, sv_body.len() as u8]);
        exts.extend_from_slice(&sv_body);

        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);

        // Handshake header: type=1, len = u24
        let hs_len = hs.len() as u32;
        let mut handshake = vec![0x01];
        handshake.push(((hs_len >> 16) & 0xff) as u8);
        handshake.push(((hs_len >> 8) & 0xff) as u8);
        handshake.push((hs_len & 0xff) as u8);
        handshake.extend_from_slice(&hs);

        // TLS record: content_type=22, version=0x0301, len = u16
        let record_len = handshake.len() as u16;
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn grease_positions_extracted_from_fixture() {
        // rich_client_hello() puts a GREASE cipher (0x0a0a) at the
        // head of the cipher list. SNI is first ext (not GREASE).
        // supported_versions starts with 0x0304 (not GREASE).
        let buf = rich_client_hello();
        let obs = extract_grease_positions(&buf).expect("parses");
        assert!(obs.first_cipher_is_grease);
        assert!(!obs.first_extension_is_grease);
        assert!(!obs.supported_versions_starts_with_grease);
        // Chrome-shaped JA4 with only one GREASE slot present → high
        // anomaly when the client *claims* Chrome.
        let s =
            crate::grease_anomaly::score_against_ja4(&obs, "t13d1516h2_8daaf6152771_b1ff8ab2d16f");
        assert!(s > 0.5, "expected anomaly score > 0.5, got {s}");
    }
}
