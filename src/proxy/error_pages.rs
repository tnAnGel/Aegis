//! Branded visitor-facing error pages.
//!
//! `branded_error_page` produces a self-contained HTML document with
//! inline CSS that AEGIS returns to site visitors when a request is
//! blocked or the upstream is unavailable. The page is dark-themed,
//! AEGIS-branded, and embeds an incident trace ID for support triage.
//!
//! ## Usage
//!
//! Call `branded_error_page(status, message, trace_id)` and set the
//! response `content-type` to `"text/html; charset=utf-8"`.
//!
//! ## What NOT to brand
//!
//! - Admin API endpoints — JSON errors for operator tooling.
//! - Challenge/tarpit bodies (already full HTML pages).
//! - `/__aegis/verify` reject (intentionally opaque, internal flow).
//!
//! ## Accept-header gating
//!
//! `should_brand(accept_header)` returns `true` when the client's
//! `Accept` header indicates it can render HTML. Callers use this to
//! fall back to the previous plain-text body for non-browser clients
//! (e.g. `curl`, JSON API consumers).

/// Derive a human-readable title from an HTTP status code.
fn status_title(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Authentication Required",
        403 => "Access Denied",
        404 => "Not Found",
        408 => "Request Timeout",
        429 => "Rate Limited",
        500 => "Internal Server Error",
        502 => "Gateway Unavailable",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// Render a self-contained branded HTML error page for site visitors.
///
/// `status`   — HTTP status code (e.g. 403, 429, 502, 503, 504).
/// `message`  — Short human-readable description shown to the visitor.
/// `trace_id` — Incident/trace identifier for support correlation.
///              Pass a per-request ID (e.g. `ctx.req_ctx.as_ref().map(|r| r.request_id)`)
///              or a random u64 when no request context is available.
///
/// Returns an owned `String` containing a complete HTML document with
/// inline CSS — no external resources, safe to cache, suitable for
/// delivery via `session.respond_error_with_body()` or `Response::builder()`.
pub fn branded_error_page(status: u16, message: &str, trace_id: u64) -> String {
    let title = status_title(status);
    let trace_hex = format!("{trace_id:016x}");
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{status} &#8212; AEGIS</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  :root{{
    --bg:#0d1117;--surface:#161b22;--border:#30363d;
    --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
    --warn:#f0883e;--danger:#f85149;
  }}
  body{{background:var(--bg);color:var(--text);font-family:
    -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
    "Helvetica Neue",Arial,sans-serif;
    min-height:100vh;display:flex;align-items:center;
    justify-content:center;padding:2rem}}
  .card{{background:var(--surface);border:1px solid var(--border);
    border-radius:12px;padding:2.5rem 3rem;max-width:480px;
    width:100%;text-align:center;box-shadow:0 8px 32px #0005}}
  .shield{{font-size:3rem;margin-bottom:1rem;display:block}}
  .code{{font-size:4rem;font-weight:700;line-height:1;
    color:var(--accent);font-variant-numeric:tabular-nums}}
  .title{{font-size:1.125rem;font-weight:600;margin:.75rem 0 .5rem;
    color:var(--text)}}
  .message{{color:var(--muted);font-size:.9rem;line-height:1.6;
    margin-bottom:1.75rem}}
  .trace{{display:inline-block;background:var(--bg);border:1px solid
    var(--border);border-radius:6px;padding:.25rem .75rem;
    font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,
    monospace;font-size:.75rem;color:var(--muted);
    word-break:break-all}}
  .trace-label{{font-size:.7rem;color:var(--muted);
    text-transform:uppercase;letter-spacing:.05em;
    margin-bottom:.35rem}}
  .footer{{margin-top:2rem;padding-top:1.25rem;
    border-top:1px solid var(--border);font-size:.75rem;
    color:var(--muted)}}
  .footer strong{{color:var(--accent)}}
</style>
</head>
<body>
<div class="card">
  <span class="shield">&#x1F6E1;</span>
  <div class="code">{status}</div>
  <div class="title">{title}</div>
  <p class="message">{message}</p>
  <div class="trace-label">Incident ID</div>
  <span class="trace">{trace_hex}</span>
  <div class="footer">Protected by <strong>AEGIS</strong></div>
</div>
</body>
</html>"#
    )
}

/// Returns `true` when the request's `Accept` header indicates the
/// client can render HTML (i.e. is likely a browser). Falls back to
/// `false` for absent or non-HTML accept values (API clients, `curl`,
/// etc.) so those callers continue to receive the previous plain-text
/// body rather than a raw HTML blob.
///
/// The check is intentionally permissive: any `accept` value that
/// contains `"text/html"` or `"*/*"` is treated as HTML-capable.
/// A fully-absent `accept` header defaults to `false` (API-style
/// caller; don't surprise them with HTML).
pub fn should_brand(accept_header: Option<&str>) -> bool {
    match accept_header {
        None => false,
        Some(v) => v.contains("text/html") || v.contains("*/*"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_titles() {
        assert_eq!(status_title(403), "Access Denied");
        assert_eq!(status_title(429), "Rate Limited");
        assert_eq!(status_title(503), "Service Unavailable");
        assert_eq!(status_title(999), "Error");
    }

    #[test]
    fn test_branded_page_contains_status() {
        let page = branded_error_page(403, "Access denied.", 0xdeadbeef12345678);
        assert!(page.contains("403"));
        assert!(page.contains("Access Denied"));
        assert!(page.contains("Access denied."));
        assert!(page.contains("deadbeef12345678"));
        assert!(page.contains("Protected by"));
        assert!(page.contains("AEGIS"));
    }

    #[test]
    fn test_trace_hex_padding() {
        let page = branded_error_page(503, "Unavailable.", 1);
        // Trace ID must be zero-padded to 16 hex digits.
        assert!(page.contains("0000000000000001"));
    }

    #[test]
    fn test_should_brand() {
        assert!(should_brand(Some(
            "text/html,application/xhtml+xml,*/*;q=0.9"
        )));
        assert!(should_brand(Some("*/*")));
        assert!(should_brand(Some("text/html")));
        assert!(!should_brand(Some("application/json")));
        assert!(!should_brand(Some("application/xml")));
        assert!(!should_brand(None));
    }
}
