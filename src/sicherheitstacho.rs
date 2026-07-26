//! V185 — T-Pot Sicherheitstacho event export schema.
//!
//! T-Pot (telekom-security/tpotce) ships dozens of honeypots that
//! all converge on the Telekom CERT "Sicherheitstacho" normalised
//! event format. Adopting it gives Aegis free interop with every
//! consumer in the deception-tooling ecosystem (ELK ingest mappings,
//! threat-feed aggregators, the Sicherheitstacho public dashboard).
//!
//! Schema (relevant subset):
//!
//! ```json
//! {
//!   "@timestamp":  "2026-05-22T12:34:56Z",
//!   "type":        "Aegis",
//!   "src_ip":      "203.0.113.7",
//!   "src_port":    51234,
//!   "dst_port":    443,
//!   "country":     "RU",
//!   "asn":         "AS12345",
//!   "transport":   "TCP",
//!   "service":     "aegis-waf",
//!   "category":    "waf|honeypot|tarpit|challenge",
//!   "tags":        ["sqlmap", "phpmyadmin-probe"],
//!   "request": {
//!     "method":  "POST",
//!     "host":    "evil.test",
//!     "path":    "/phpmyadmin/index.php",
//!     "ua":      "Mozilla/5.0 …"
//!   }
//! }
//! ```
//!
//! The exporter takes an Aegis [SecurityEvent]-shaped struct and
//! produces Sicherheitstacho-compatible JSON. No serde dep — small
//! enough to hand-write so the module stays drop-in for the
//! event-bridge (V127) sink.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct EventInput<'a> {
    pub timestamp_unix_ms: Option<u64>,
    pub src_ip: &'a str,
    pub src_port: u16,
    pub dst_port: u16,
    pub country: Option<&'a str>,
    pub asn: Option<&'a str>,
    pub transport: &'a str,
    pub service: &'a str,
    pub category: Category,
    pub tags: &'a [&'a str],
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub user_agent: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Waf,
    Honeypot,
    Tarpit,
    Challenge,
    Block,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Waf => "waf",
            Self::Honeypot => "honeypot",
            Self::Tarpit => "tarpit",
            Self::Challenge => "challenge",
            Self::Block => "block",
        }
    }
}

/// Render input → single-line JSON, ready to push down a NDJSON socket.
pub fn render(input: &EventInput<'_>) -> String {
    let ts = input.timestamp_unix_ms.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });
    let ts_iso = unix_ms_to_iso(ts);
    let mut out = String::with_capacity(256);
    out.push('{');
    push_str_field(&mut out, "@timestamp", &ts_iso, true);
    push_str_field(&mut out, "type", "Aegis", false);
    push_str_field(&mut out, "src_ip", input.src_ip, false);
    push_int_field(&mut out, "src_port", input.src_port as u64, false);
    push_int_field(&mut out, "dst_port", input.dst_port as u64, false);
    if let Some(c) = input.country {
        push_str_field(&mut out, "country", c, false);
    }
    if let Some(a) = input.asn {
        push_str_field(&mut out, "asn", a, false);
    }
    push_str_field(&mut out, "transport", input.transport, false);
    push_str_field(&mut out, "service", input.service, false);
    push_str_field(&mut out, "category", input.category.as_str(), false);
    out.push_str(",\"tags\":[");
    for (i, t) in input.tags.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_string(&mut out, t);
    }
    out.push(']');
    out.push_str(",\"request\":{");
    push_str_field(&mut out, "method", input.method, true);
    push_str_field(&mut out, "host", input.host, false);
    push_str_field(&mut out, "path", input.path, false);
    if let Some(ua) = input.user_agent {
        push_str_field(&mut out, "ua", ua, false);
    }
    out.push('}');
    out.push('}');
    out
}

fn push_str_field(buf: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        buf.push(',');
    }
    push_json_string(buf, key);
    buf.push(':');
    push_json_string(buf, value);
}

fn push_int_field(buf: &mut String, key: &str, value: u64, first: bool) {
    if !first {
        buf.push(',');
    }
    push_json_string(buf, key);
    buf.push(':');
    buf.push_str(&value.to_string());
}

fn push_json_string(buf: &mut String, s: &str) {
    buf.push('"');
    for c in s.chars() {
        match c {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            c if (c as u32) < 0x20 => buf.push_str(&format!("\\u{:04x}", c as u32)),
            c => buf.push(c),
        }
    }
    buf.push('"');
}

/// Tiny ISO-8601 renderer (UTC). Sufficient for log timestamps;
/// avoids a chrono/jiff dep just for this.
fn unix_ms_to_iso(ms: u64) -> String {
    let secs = ms / 1000;
    let (year, month, day) = days_to_ymd((secs / 86_400) as i64);
    let sod = secs % 86_400;
    let hour = sod / 3600;
    let min = (sod % 3600) / 60;
    let sec = sod % 60;
    let milli = ms % 1000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{milli:03}Z")
}

fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from Hinnant (date library), proleptic Gregorian.
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 {
        mp as u32 + 3
    } else {
        mp as u32 - 9
    };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>() -> EventInput<'a> {
        EventInput {
            timestamp_unix_ms: Some(1_716_000_000_000),
            src_ip: "203.0.113.7",
            src_port: 51234,
            dst_port: 443,
            country: Some("RU"),
            asn: Some("AS12345"),
            transport: "TCP",
            service: "aegis-waf",
            category: Category::Honeypot,
            tags: &["sqlmap", "phpmyadmin-probe"],
            method: "POST",
            host: "evil.test",
            path: "/phpmyadmin/index.php",
            user_agent: Some("sqlmap/1.7"),
        }
    }

    #[test]
    fn render_contains_top_level_fields() {
        let s = render(&sample());
        for f in [
            "\"@timestamp\"",
            "\"type\":\"Aegis\"",
            "\"src_ip\":\"203.0.113.7\"",
            "\"src_port\":51234",
            "\"category\":\"honeypot\"",
            "\"tags\":[\"sqlmap\",\"phpmyadmin-probe\"]",
            "\"request\":{",
            "\"method\":\"POST\"",
        ] {
            assert!(s.contains(f), "missing field {f} in: {s}");
        }
    }

    #[test]
    fn iso_timestamp_format() {
        let s = unix_ms_to_iso(1_716_000_000_000);
        assert_eq!(s, "2024-05-18T02:40:00.000Z");
    }

    #[test]
    fn escaping_handles_quotes_and_newlines() {
        let inp = EventInput {
            timestamp_unix_ms: Some(0),
            src_ip: "1.1.1.1",
            src_port: 1,
            dst_port: 1,
            country: None,
            asn: None,
            transport: "TCP",
            service: "aegis",
            category: Category::Waf,
            tags: &[],
            method: "GET",
            host: "x",
            path: "/\"\n",
            user_agent: None,
        };
        let s = render(&inp);
        assert!(s.contains("\\\""));
        assert!(s.contains("\\n"));
        assert!(serde_json_check(&s));
    }

    fn serde_json_check(s: &str) -> bool {
        // Crude: matched quotes/braces only. Avoids serde_json dep
        // in lib (it's in dev-deps but we don't import here).
        let mut depth = 0i32;
        let mut in_str = false;
        let mut esc = false;
        for c in s.chars() {
            if esc {
                esc = false;
                continue;
            }
            if in_str {
                if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    in_str = false;
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
        }
        depth == 0 && !in_str
    }
}
