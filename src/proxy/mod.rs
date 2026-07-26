/// Branded visitor-facing error pages (self-contained inline CSS, dark,
/// AEGIS-branded, status + human message + incident trace ID).
pub mod error_pages;
/// V111 — per-connection HTTP/2 abuse counters (stream/reset/settings/
/// ping/goaway churn + CONTINUATION byte cap). Stateless container;
/// wiring to a live h2 stack arrives when pingora exposes h2 hooks.
pub mod h2_guard;
pub mod health;
pub mod http;
pub mod http3;
#[cfg(feature = "pingora")]
pub mod pingora_admin;
#[cfg(feature = "pingora")]
pub mod pingora_background;
#[cfg(feature = "pingora")]
pub mod pingora_challenge;
#[cfg(feature = "pingora")]
pub mod pingora_http;
#[cfg(feature = "pingora")]
pub mod pingora_tls;
pub mod request_context;
pub mod response_cache;
/// V117 — response-side security headers (CSP, HSTS, X-Frame-Options,
/// X-Content-Type-Options, Referrer-Policy, Permissions-Policy) +
/// upstream-server-header stripping.
pub mod response_security;
pub mod upstream;
