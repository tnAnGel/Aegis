//! Shared cookie helpers used by both the hyper handler
//! (`src/proxy/http.rs`) and the pingora handler
//! (`src/proxy/pingora_challenge.rs`). Lives under `security/` so the
//! HMAC-token machinery (`security::token`) and this cookie reader
//! sit next to each other — they go hand-in-hand for the challenge
//! ladder.

use http::HeaderMap;

/// Pull a single cookie value by name out of a request's `Cookie`
/// header(s). Permissive parsing — trims whitespace, accepts
/// quoted values, returns the first match across all `Cookie`
/// headers. Returns `None` if absent or empty.
///
/// Both proxies use this in two places:
///   1. Reading `aegis_token` at /__aegis/verify to validate a
///      pending challenge.
///   2. Reading `aegis_fp` on every request to short-circuit the
///      challenge ladder for already-verified browsers.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for value in headers.get_all("cookie").iter() {
        let Ok(s) = value.to_str() else { continue };
        for part in s.split(';') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix(&prefix) {
                let v = rest.trim_matches('"');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// `; Secure` when configured to require HTTPS-only cookies, empty
/// string otherwise. Computed once per cookie rather than inlining
/// the conditional into every format! call.
pub fn secure_suffix(on: bool) -> &'static str {
    if on { "; Secure" } else { "" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(cookie: &str) -> HeaderMap {
        let mut hm = HeaderMap::new();
        hm.insert("cookie", cookie.parse().unwrap());
        hm
    }

    #[test]
    fn returns_value_when_present() {
        let hm = h("foo=bar; aegis_token=abc.def; lang=en");
        assert_eq!(read_cookie(&hm, "aegis_token"), Some("abc.def".to_string()));
    }

    #[test]
    fn returns_none_when_absent() {
        let hm = h("foo=bar");
        assert!(read_cookie(&hm, "aegis_token").is_none());
    }

    #[test]
    fn trims_quoted_values() {
        let hm = h(r#"aegis_token="quoted-value""#);
        assert_eq!(
            read_cookie(&hm, "aegis_token"),
            Some("quoted-value".to_string())
        );
    }
}
