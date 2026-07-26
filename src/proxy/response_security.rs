//! V117 — Response-side security headers + upstream-header sanitiser
//! (info.md P2).
//!
//! Two related response-rewrite jobs the proxy is well-placed to do:
//!
//! 1. **Inject** security headers that browsers honour to lock down
//!    XSS / clickjacking / mixed content: `Content-Security-Policy`,
//!    `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-
//!    Type-Options`, `Referrer-Policy`, `Permissions-Policy`. Upstream
//!    apps frequently forget; injecting at the edge is operationally
//!    cheap.
//! 2. **Strip** dangerous upstream headers that leak internal info
//!    or override our injected security headers: `Server`,
//!    `X-Powered-By`, `X-AspNet-Version`, `X-Generator`. If the
//!    upstream already set a security header we leave it alone (don't
//!    fight the app's own policy).
//!
//! Operator config (V118+ wires through DSL `defaults { security_headers
//! { ... } }`):
//!
//! ```toml
//! [security_headers]
//! enabled = true
//! csp = "default-src 'self'; script-src 'self' 'unsafe-inline'"
//! hsts = "max-age=31536000; includeSubDomains"
//! frame_options = "DENY"
//! content_type_options = "nosniff"
//! referrer_policy = "strict-origin-when-cross-origin"
//! permissions_policy = "geolocation=(), camera=()"
//! strip_server_headers = true
//! ```
//!
//! All fields optional. None = don't inject that header. Mode is
//! always "set if absent" — we never overwrite an existing upstream
//! security header.

use http::{HeaderMap, HeaderName, HeaderValue};

/// Operator-tunable defaults. Field set matches info.md's
/// response-side security checklist.
#[derive(Debug, Clone, Default)]
pub struct ResponseSecurityConfig {
    pub enabled: bool,
    pub csp: Option<String>,
    pub hsts: Option<String>,
    pub frame_options: Option<String>,
    pub content_type_options: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub strip_server_headers: bool,
}

/// Compiled view — `HeaderName`/`HeaderValue` pre-parsed so the
/// hot-path apply loop avoids string parsing per response.
pub struct ResponseSecurity {
    enabled: bool,
    inject: Vec<(HeaderName, HeaderValue)>,
    strip_server_headers: bool,
}

impl ResponseSecurity {
    pub fn new(cfg: &ResponseSecurityConfig) -> Self {
        if !cfg.enabled {
            return Self {
                enabled: false,
                inject: Vec::new(),
                strip_server_headers: false,
            };
        }
        let mut inject = Vec::new();
        push_if_some(&mut inject, "content-security-policy", &cfg.csp);
        push_if_some(&mut inject, "strict-transport-security", &cfg.hsts);
        push_if_some(&mut inject, "x-frame-options", &cfg.frame_options);
        push_if_some(
            &mut inject,
            "x-content-type-options",
            &cfg.content_type_options,
        );
        push_if_some(&mut inject, "referrer-policy", &cfg.referrer_policy);
        push_if_some(&mut inject, "permissions-policy", &cfg.permissions_policy);
        Self {
            enabled: true,
            inject,
            strip_server_headers: cfg.strip_server_headers,
        }
    }

    pub fn is_active(&self) -> bool {
        self.enabled && (!self.inject.is_empty() || self.strip_server_headers)
    }

    /// Apply rewrites to outbound response headers. Cheap when disabled
    /// (early return). Otherwise:
    /// * removes Server / X-Powered-By / X-AspNet-Version / X-Generator
    ///   when `strip_server_headers=true`.
    /// * injects each configured security header IFF the upstream
    ///   didn't already set its own value (don't fight the app).
    pub fn apply(&self, headers: &mut HeaderMap) {
        if !self.enabled {
            return;
        }
        if self.strip_server_headers {
            for h in &[
                "server",
                "x-powered-by",
                "x-aspnet-version",
                "x-aspnetmvc-version",
                "x-generator",
                "x-runtime",
                "x-version",
            ] {
                headers.remove(*h);
            }
        }
        for (name, value) in &self.inject {
            if !headers.contains_key(name) {
                headers.insert(name.clone(), value.clone());
            }
        }
    }
}

fn push_if_some(
    inject: &mut Vec<(HeaderName, HeaderValue)>,
    name: &'static str,
    value: &Option<String>,
) {
    if let Some(v) = value.as_deref()
        && let Ok(hv) = HeaderValue::from_str(v)
    {
        inject.push((HeaderName::from_static(name), hv));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_full() -> ResponseSecurityConfig {
        ResponseSecurityConfig {
            enabled: true,
            csp: Some("default-src 'self'".to_string()),
            hsts: Some("max-age=63072000; includeSubDomains".to_string()),
            frame_options: Some("DENY".to_string()),
            content_type_options: Some("nosniff".to_string()),
            referrer_policy: Some("no-referrer".to_string()),
            permissions_policy: Some("geolocation=()".to_string()),
            strip_server_headers: true,
        }
    }

    #[test]
    fn disabled_is_inactive() {
        let r = ResponseSecurity::new(&ResponseSecurityConfig {
            enabled: false,
            ..cfg_full()
        });
        assert!(!r.is_active());
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx/1.x"));
        r.apply(&mut h);
        assert_eq!(h.get("server").unwrap(), "nginx/1.x");
        assert!(h.get("x-frame-options").is_none());
    }

    #[test]
    fn strips_server_headers_when_configured() {
        let r = ResponseSecurity::new(&cfg_full());
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx/1.x"));
        h.insert("x-powered-by", HeaderValue::from_static("Express"));
        h.insert("content-type", HeaderValue::from_static("text/html"));
        r.apply(&mut h);
        assert!(h.get("server").is_none());
        assert!(h.get("x-powered-by").is_none());
        assert_eq!(h.get("content-type").unwrap(), "text/html");
    }

    #[test]
    fn injects_security_headers_when_absent() {
        let r = ResponseSecurity::new(&cfg_full());
        let mut h = HeaderMap::new();
        h.insert("content-type", HeaderValue::from_static("text/html"));
        r.apply(&mut h);
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
        assert!(h.get("content-security-policy").is_some());
        assert!(h.get("strict-transport-security").is_some());
    }

    #[test]
    fn does_not_overwrite_upstream_value() {
        let r = ResponseSecurity::new(&cfg_full());
        let mut h = HeaderMap::new();
        h.insert(
            "content-security-policy",
            HeaderValue::from_static("upstream-csp-value"),
        );
        r.apply(&mut h);
        assert_eq!(
            h.get("content-security-policy").unwrap(),
            "upstream-csp-value"
        );
    }

    #[test]
    fn empty_config_active_only_if_something_set() {
        let r = ResponseSecurity::new(&ResponseSecurityConfig {
            enabled: true,
            strip_server_headers: false,
            ..ResponseSecurityConfig::default()
        });
        assert!(!r.is_active(), "no injects + no strip → inactive");
    }
}
