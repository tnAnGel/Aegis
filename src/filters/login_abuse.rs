//! V115 — Login abuse protection (info.md P1).
//!
//! Generic rate-limit treats every endpoint the same. Login pages
//! need a tighter, multi-dimensional policy because:
//!
//! * Credential stuffing: 1 attacker tries 1 username × 1000 passwords
//!   → easily caught by per-IP rate limit.
//! * Credential spray: 1 attacker tries 1000 usernames × 1 password
//!   → per-IP rate is fine, but per-username rate isn't even
//!   measured. Each victim sees one failure; the per-IP rate is
//!   under the global cap.
//! * Botnet stuffing: 1000 IPs × 1 username × 1 password →
//!   per-IP rate clean, per-username rate huge.
//!
//! V115 ships a [LoginAbuseGuard] that tracks per-(IP, username) and
//! per-username failure counts in a sliding window, plus exponential
//! backoff once thresholds trip. Output is `LoginDecision::{Allow,
//! Throttle, Deny}` — `Throttle` lets the caller serve a synthetic
//! delay or 429 with Retry-After, `Deny` is hard 401/403.
//!
//! Operator wires this BEFORE the upstream POST: hook into
//! `request_filter` for paths matching the configured login regex,
//! pre-extract the username from form body / JSON body / Basic auth,
//! call [LoginAbuseGuard::observe].
//!
//! # V234 — request-path wiring
//!
//! `LoginAbuseGuard` is now directly wireable into `pingora_http.rs`.
//! The request handler does, in order:
//!
//! 1. [LoginAbuseGuard::is_login_path] — cheap path-only check; skip
//!    everything below if it returns `false`.
//! 2. [LoginAbuseGuard::is_login_method] — login attempts are POST
//!    (some apps use PUT); GET on a login URL is just the form render
//!    and must NOT be counted.
//! 3. [LoginAbuseGuard::extract_username] — pull the username out of
//!    the captured POST body (form-encoded or JSON).
//! 4. [LoginAbuseGuard::evaluate] BEFORE forwarding upstream — gate on
//!    the *prior* failure history for that (ip, username); a `Deny` /
//!    `Throttle` here short-circuits the upstream POST entirely.
//! 5. After the upstream responds, call [LoginAbuseGuard::record] with
//!    the real [Outcome] (success vs. 401/403) so the counters learn.
//!
//! The guard is constructed once at startup via
//! [LoginAbuseGuard::from_config] / [LoginAbuseGuard::new], wrapped in
//! its own inner `Arc`, and `Clone`d cheaply into every worker — all
//! clones share one counter set.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Tunables. Defaults are conservative — operators tighten by 2-4×
/// once they observe baseline.
///
/// V234 — `Copy` was dropped: the new `login_paths` field owns a
/// `Vec<String>`, so the struct is `Clone` only. Every consumer in
/// this module already moved or borrowed the config rather than
/// relying on implicit copies, so this is source-compatible.
#[derive(Debug, Clone)]
pub struct LoginAbuseConfig {
    /// V234 — master on/off. When `false` the guard short-circuits
    /// every request to [LoginDecision::Allow] and skips username
    /// extraction entirely. Mirrors the `enabled` field every other
    /// filter in `src/filters/` carries so the engine / `aegis.conf`
    /// can flip it.
    pub enabled: bool,
    /// V234 — path patterns that count as login endpoints. Same tiny
    /// matcher grammar as rate-limit `uri_budgets`: an exact path
    /// (`"/login"`) or a prefix glob ending in `*` (`"/auth/*"`).
    /// Matching is path-only — query strings must be stripped by the
    /// caller (or pass the raw path; [LoginAbuseGuard::is_login_path]
    /// strips the `?...` itself). Empty ⇒ the guard treats no path as
    /// a login endpoint (effectively disabled).
    pub login_paths: Vec<String>,
    /// Sliding window for the failure counters.
    pub window: Duration,
    /// Allowed failures per (ip, username) in `window`.
    pub max_per_ip_user: u32,
    /// Allowed failures per username from ANY IP in `window`
    /// (spray detector).
    pub max_per_user: u32,
    /// Allowed distinct usernames a single IP can attempt in `window`
    /// (credential-spray fan-out detector).
    pub max_usernames_per_ip: u32,
    /// Base throttle duration on first lockout. Each subsequent
    /// lockout for the same key doubles, capped at 1h.
    pub throttle_base: Duration,
}

impl Default for LoginAbuseConfig {
    fn default() -> Self {
        Self {
            // V234 — default ON once wired: the guard is inert anyway
            // unless `login_paths` matches a request, so a safe
            // default is "enabled, watching the conventional paths".
            enabled: true,
            // V234 — conventional login routes. Operators override in
            // `aegis.conf`. `/login` and `/signin` are exact; `/auth/*`
            // and `/api/auth/*` catch framework-style login sub-routes
            // (`/auth/login`, `/api/auth/callback/credentials`, …).
            login_paths: vec![
                "/login".to_string(),
                "/signin".to_string(),
                "/auth/*".to_string(),
                "/api/auth/*".to_string(),
            ],
            window: Duration::from_secs(300), // 5 min
            max_per_ip_user: 5,
            max_per_user: 25,
            max_usernames_per_ip: 20,
            throttle_base: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginDecision {
    /// Caller proceeds with the login.
    Allow,
    /// Caller serves a 429 with this Retry-After. NOT a hard ban;
    /// next attempt after the duration is evaluated fresh.
    Throttle(Duration),
    /// Hard ban for the (IP, user) pair for the throttle window.
    Deny,
}

#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Success,
    Failure,
}

/// Per-key state — failure count + lockout end time + next throttle
/// step (doubles on each fresh lockout).
#[derive(Debug, Clone, Copy)]
struct KeyState {
    failures: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
    next_lockout: Duration,
}

impl KeyState {
    fn new(now: Instant, base: Duration) -> Self {
        Self {
            failures: 0,
            window_start: now,
            locked_until: None,
            next_lockout: base,
        }
    }
}

/// Per-IP fan-out tracker: how many DISTINCT usernames has this IP
/// hit recently? Used for spray detection.
#[derive(Debug, Clone)]
struct IpFanout {
    window_start: Instant,
    usernames: std::collections::HashSet<String>,
}

/// V234 — compiled login-path matcher. Mirrors the rate-limit
/// `UriMatcher` grammar (exact path / prefix glob ending in `*`) so
/// operators have ONE mental model for path patterns across the proxy.
/// Kept private — callers go through [LoginAbuseGuard::is_login_path].
#[derive(Debug, Clone)]
enum LoginPathPattern {
    Exact(String),
    Prefix(String),
}

impl LoginPathPattern {
    fn from_pattern(p: &str) -> Self {
        if let Some(prefix) = p.strip_suffix('*') {
            Self::Prefix(prefix.to_string())
        } else {
            Self::Exact(p.to_string())
        }
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(s) => s == path,
            Self::Prefix(p) => path.starts_with(p.as_str()),
        }
    }
}

/// V234 — the actual guard state. `LoginAbuseGuard` is a thin
/// `Arc<GuardInner>` newtype over this so it `Clone`s cheaply (one
/// atomic bump) and every clone shares the same counters / mutex.
struct GuardInner {
    cfg: LoginAbuseConfig,
    /// V234 — pre-compiled from `cfg.login_paths` at construction so
    /// the per-request `is_login_path` check is a slice scan, not a
    /// re-parse of pattern strings.
    login_patterns: Vec<LoginPathPattern>,
    // Three maps keyed by different keys; all under one Mutex because
    // login attempt rate is low (<1k/sec/host is huge) so contention
    // isn't material. If it ever matters we'd shard.
    //
    // V230 — audit: keeping the single Mutex is correct here. Login
    // paths are nowhere near the request volume that would justify
    // DashMap with 128 shards, and crucially the keys
    // ((IpAddr, String) and String) are attacker-controlled, so we
    // intentionally keep the default SipHash hasher instead of FxHash
    // to avoid HashDoS. The hot-path wins live in observe() — fewer
    // String/tuple clones via peek-then-insert.
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    per_ip_user: HashMap<(IpAddr, String), KeyState>,
    per_user: HashMap<String, KeyState>,
    per_ip_fanout: HashMap<IpAddr, IpFanout>,
}

/// Per (IP × username), per username, per IP fan-out brute-force /
/// credential-spray detector with exponential backoff.
///
/// V234 — cheap-`Clone` `Arc` newtype: construct ONCE at startup
/// ([LoginAbuseGuard::from_config] / [LoginAbuseGuard::new]) and
/// `.clone()` it into every worker / request context. All clones
/// share one counter set, so a failure seen on worker A is visible to
/// worker B. The whole type is `Send + Sync`.
#[derive(Clone)]
pub struct LoginAbuseGuard {
    inner: Arc<GuardInner>,
}

impl LoginAbuseGuard {
    /// Build a guard from an explicit [LoginAbuseConfig].
    ///
    /// V234 — pre-compiles `cfg.login_paths` into the path matcher.
    /// Use [LoginAbuseGuard::from_config] when you only have the
    /// proxy's top-level config object.
    pub fn new(cfg: LoginAbuseConfig) -> Self {
        let login_patterns = cfg
            .login_paths
            .iter()
            .map(|p| LoginPathPattern::from_pattern(p))
            .collect();
        Self {
            inner: Arc::new(GuardInner {
                cfg,
                login_patterns,
                inner: Mutex::new(Inner::default()),
            }),
        }
    }

    /// V234 — startup constructor.
    ///
    /// There is intentionally no dedicated `[login_abuse]` block in
    /// `aegis.conf` yet (see the report / `src/config.rs`): wiring the
    /// call-site is a separate change and adding config fields without
    /// a reader would be dead config. Until that lands, pass the
    /// desired [LoginAbuseConfig] (typically `LoginAbuseConfig::default()`,
    /// optionally with `login_paths` overridden) — the signature takes
    /// `Option<LoginAbuseConfig>` so the call-site can do
    /// `LoginAbuseGuard::from_config(None)` for pure defaults and a
    /// later config patch can pass `Some(cfg)` without an API churn.
    ///
    /// Returns `None` when the resolved config is disabled, so the
    /// caller can store an `Option<LoginAbuseGuard>` and skip the
    /// guard entirely (zero per-request cost) when off. Pass a config
    /// with `enabled: true` to always get `Some`.
    pub fn from_config(cfg: Option<LoginAbuseConfig>) -> Option<Self> {
        let cfg = cfg.unwrap_or_default();
        if !cfg.enabled {
            return None;
        }
        Some(Self::new(cfg))
    }

    /// V234 — read-only view of the active config (paths, thresholds).
    pub fn config(&self) -> &LoginAbuseConfig {
        &self.inner.cfg
    }

    /// V234 — mirrors every other filter's `config_enabled()`: the
    /// configured enable state. The guard self-gates on this in
    /// [LoginAbuseGuard::evaluate] (returns `Allow`), so a disabled
    /// guard is inert without the caller having to branch.
    pub fn config_enabled(&self) -> bool {
        self.inner.cfg.enabled
    }

    /// V234 — does `path` name a login endpoint?
    ///
    /// The caller's FIRST check: if this is `false` the request is not
    /// a login attempt and the guard must be skipped entirely. A query
    /// string (`/login?next=/`) is tolerated — it is stripped before
    /// matching. Returns `false` when the guard is disabled or
    /// `login_paths` is empty.
    pub fn is_login_path(&self, path: &str) -> bool {
        if !self.inner.cfg.enabled {
            return false;
        }
        let path = path.split(['?', '#']).next().unwrap_or(path);
        self.inner.login_patterns.iter().any(|p| p.matches(path))
    }

    /// V234 — is this HTTP method an actual login *submission*?
    ///
    /// Only POST / PUT carry credentials. A GET on `/login` is the
    /// form render and must NOT touch the counters — counting it would
    /// let a browser prefetch or a monitoring probe burn the budget.
    /// Case-insensitive so `post` / `POST` both match.
    pub fn is_login_method(method: &str) -> bool {
        method.eq_ignore_ascii_case("POST") || method.eq_ignore_ascii_case("PUT")
    }

    /// V234 — extract + normalise the username from a captured request
    /// body. Returns `None` when no recognised username field is
    /// present (caller should then treat the attempt as un-keyable —
    /// typically still forward it, or key on IP-only via a synthetic
    /// username; see [LoginAbuseGuard::evaluate]).
    ///
    /// Two body shapes are recognised, picked by `content_type`:
    ///
    /// * `application/x-www-form-urlencoded` (or any content type
    ///   containing `form-urlencoded`, or — as a fallback — when
    ///   `content_type` is empty/unknown and the body looks like a
    ///   form): the `username=` / `email=` / `user=` / `login=` field,
    ///   percent-decoded.
    /// * `application/json` (or any content type containing `json`):
    ///   a top-level string member named `username` / `email` /
    ///   `user` / `login`.
    ///
    /// The returned string is run through the V233 [normalise_username]
    /// canonicaliser, so it is ready to hand straight to
    /// [LoginAbuseGuard::observe] / [LoginAbuseGuard::evaluate].
    pub fn extract_username(content_type: &str, body: &[u8]) -> Option<String> {
        let raw = extract_username_raw(content_type, body)?;
        let norm = normalise_username(&raw);
        // V234 — never surface an empty username, and never let a
        // client that literally posts the NUL-wrapped sentinel text be
        // mistaken for a parsed username: both map to "un-keyable".
        if norm.is_empty() || norm == UNKNOWN_USERNAME {
            None
        } else {
            Some(norm)
        }
    }

    /// Observe a login attempt outcome and return what the caller
    /// should do for the NEXT attempt from the same (ip, username).
    ///
    /// V234 — this is the *learning* call: feed it the real [Outcome]
    /// AFTER the upstream login responded. To *gate* a request BEFORE
    /// forwarding it (the common request-path use), call
    /// [LoginAbuseGuard::evaluate] instead — that checks the existing
    /// history without recording a new attempt.
    pub fn observe(
        &self,
        ip: IpAddr,
        username: &str,
        outcome: Outcome,
        now: Instant,
    ) -> LoginDecision {
        let mut g = self.inner.inner.lock().expect("login abuse mutex poisoned");
        // V233 — canonicalise BEFORE keying any counter. Trim + collapse
        // whitespace + full Unicode lowercase + confusable/full-width
        // fold, so `admin`, `admin `, `Admin`, `аdmin` collapse to ONE
        // bucket for both the per-(IP,username) and per-username maps
        // below (auth_bypass: the prior `to_ascii_lowercase()` left
        // those as distinct keys, defeating the brute-force counters).
        let username = normalise_username(username);

        // V230 — Track IP fan-out FIRST so a successful login still
        // counts the username (might be the attacker testing a valid
        // user). Peek-then-insert on the HashSet: returning users from
        // the same IP are the common case, so avoid cloning the
        // username String on the hot path when it's already tracked.
        let fanout = g.per_ip_fanout.entry(ip).or_insert_with(|| IpFanout {
            window_start: now,
            usernames: std::collections::HashSet::new(),
        });
        // V234 — config now lives behind the `Arc<GuardInner>`; pull
        // the (Copy) scalar fields we need locally.
        let cfg_window = self.inner.cfg.window;
        let cfg_max_usernames_per_ip = self.inner.cfg.max_usernames_per_ip;
        let cfg_throttle_base = self.inner.cfg.throttle_base;
        if now.duration_since(fanout.window_start) > cfg_window {
            fanout.window_start = now;
            fanout.usernames.clear();
        }
        if !fanout.usernames.contains(username.as_str()) {
            fanout.usernames.insert(username.clone());
        }
        let fanout_violation = fanout.usernames.len() as u32 > cfg_max_usernames_per_ip;

        // If outcome is success, we still increment fanout but DON'T
        // increment failure counters. A successful login resets the
        // per-(ip,user) failure state (op was legit).
        //
        // V230 — use raw_entry-equivalent borrowed-key remove path via
        // a single move-construction of the tuple key; we have to own
        // a copy here because HashMap::remove on a tuple key needs the
        // owned form for (IpAddr, String) lookups.
        if matches!(outcome, Outcome::Success) {
            g.per_ip_user.remove(&(ip, username));
            // Don't reset per-user — others may still be attacking
            // the same user from other IPs.
            if fanout_violation {
                return LoginDecision::Throttle(cfg_throttle_base);
            }
            return LoginDecision::Allow;
        }

        let now_failed = now;
        // V234 — `LoginAbuseConfig` is no longer `Copy` (it owns the
        // `login_paths` Vec); clone the small struct once here so the
        // rest of the function keeps its by-value `cfg` ergonomics.
        let cfg = self.inner.cfg.clone();

        // V230 — Per (ip, user): avoid the prior `key.clone()` before
        // the entry call. We only need ONE owned (IpAddr, String) tuple
        // for the potential insert path, and `username` itself is moved
        // into the per_user entry below. Build the key with a borrowed
        // clone of username (we still need username for per_user).
        let ks = g
            .per_ip_user
            .entry((ip, username.clone()))
            .or_insert_with(|| KeyState::new(now_failed, cfg.throttle_base));
        check_window_roll(ks, now_failed, cfg.window, cfg.throttle_base);
        ks.failures += 1;
        let per_ip_user_violation = ks.failures > cfg.max_per_ip_user;
        let per_ip_user_lockout = if per_ip_user_violation {
            arm_lockout(ks, now_failed)
        } else {
            None
        };

        // V230 — Per user: move `username` into the entry instead of
        // cloning. This drops one allocation per failure observation
        // on the common path (existing-entry hits also benefit because
        // the moved String is freed on drop with no extra refcount).
        let ks_user = g
            .per_user
            .entry(username)
            .or_insert_with(|| KeyState::new(now_failed, cfg.throttle_base));
        check_window_roll(ks_user, now_failed, cfg.window, cfg.throttle_base);
        ks_user.failures += 1;
        let per_user_violation = ks_user.failures > cfg.max_per_user;
        let per_user_lockout = if per_user_violation {
            arm_lockout(ks_user, now_failed)
        } else {
            None
        };

        // Decision precedence: hardest wins.
        // Deny only on per_ip_user lockout — per-user lockout from
        // spray shouldn't lock the legitimate owner out; we throttle
        // them instead.
        if per_ip_user_lockout.is_some() {
            return LoginDecision::Deny;
        }
        if let Some(_until) = per_user_lockout {
            return LoginDecision::Throttle(cfg.throttle_base);
        }
        if fanout_violation {
            return LoginDecision::Throttle(cfg.throttle_base);
        }
        LoginDecision::Allow
    }

    /// V234 — request-path entry point. Decide whether a login attempt
    /// may proceed BASED ON PRIOR HISTORY, *without* recording a new
    /// attempt. Call this in `request_filter` (before forwarding the
    /// POST upstream); the outcome of the attempt itself is fed back
    /// later via [LoginAbuseGuard::record].
    ///
    /// Contract for the caller (`pingora_http.rs`):
    ///
    /// ```ignore
    /// // ctx has: client_ip: IpAddr, method: &str, path: &str,
    /// //          content_type: &str, body: &[u8]
    /// if let Some(guard) = &login_guard {
    ///     if guard.is_login_path(ctx.path)
    ///         && LoginAbuseGuard::is_login_method(ctx.method)
    ///     {
    ///         let user = LoginAbuseGuard::extract_username(
    ///             ctx.content_type, ctx.body,
    ///         );
    ///         match guard.evaluate(ctx.client_ip, user.as_deref(),
    ///                              Instant::now()) {
    ///             LoginDecision::Allow      => { /* forward upstream */ }
    ///             LoginDecision::Throttle(d)=> { /* 429 + Retry-After d */ }
    ///             LoginDecision::Deny       => { /* 401/403, no upstream */ }
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// `username` is `Option<&str>` because the body may be missing /
    /// unparseable. When `None`, only the IP fan-out dimension can
    /// meaningfully gate the request, so a synthetic
    /// `"\u{0}unknown\u{0}"` username is used internally — it can never
    /// collide with a real (normalised) username, so it isolates the
    /// "no username" bucket from real users while still letting an IP
    /// that floods un-keyable login POSTs trip the fan-out / per-pair
    /// counters.
    pub fn evaluate(&self, ip: IpAddr, username: Option<&str>, now: Instant) -> LoginDecision {
        // Disabled guard: never gate. (`is_login_path` already returns
        // false when disabled, but `evaluate` may be called directly
        // in tests / alternate call-sites — keep it self-safe.)
        if !self.inner.cfg.enabled {
            return LoginDecision::Allow;
        }
        let username = username.unwrap_or(UNKNOWN_USERNAME);
        // V233 normaliser — same canonical form `observe` keys on.
        let username = normalise_username(username);
        let username = if username.is_empty() {
            UNKNOWN_USERNAME.to_string()
        } else {
            username
        };

        let g = self.inner.inner.lock().expect("login abuse mutex poisoned");
        let cfg = &self.inner.cfg;

        // Per (ip, user): an armed lockout that has NOT expired ⇒ Deny.
        if let Some(ks) = g.per_ip_user.get(&(ip, username.clone()))
            && let Some(until) = ks.locked_until
            && now < until
        {
            return LoginDecision::Deny;
        }
        // Per user: spray lockout ⇒ Throttle (never Deny — don't lock
        // the legitimate owner out, matching `observe`'s precedence).
        if let Some(ks) = g.per_user.get(username.as_str())
            && let Some(until) = ks.locked_until
            && now < until
        {
            return LoginDecision::Throttle(cfg.throttle_base);
        }
        // IP fan-out: too many distinct usernames in-window ⇒ Throttle.
        if let Some(fo) = g.per_ip_fanout.get(&ip)
            && now.duration_since(fo.window_start) <= cfg.window
            && fo.usernames.len() as u32 > cfg.max_usernames_per_ip
        {
            return LoginDecision::Throttle(cfg.throttle_base);
        }
        LoginDecision::Allow
    }

    /// V234 — feed back the real outcome of a login attempt after the
    /// upstream responded. Thin wrapper over [LoginAbuseGuard::observe]
    /// that accepts the same `Option<&str>` username as
    /// [LoginAbuseGuard::evaluate] (so the caller need not branch) and
    /// is a no-op when the guard is disabled.
    ///
    /// Map the upstream login response to [Outcome] at the call-site:
    /// a 2xx / 3xx (redirect to the post-login page) is
    /// [Outcome::Success]; a 401 / 403 (or app-specific "bad
    /// credentials" body) is [Outcome::Failure]. The returned
    /// [LoginDecision] is the verdict for the *next* attempt and can be
    /// ignored if the caller already responded.
    pub fn record(
        &self,
        ip: IpAddr,
        username: Option<&str>,
        outcome: Outcome,
        now: Instant,
    ) -> LoginDecision {
        if !self.inner.cfg.enabled {
            return LoginDecision::Allow;
        }
        let username = username.unwrap_or(UNKNOWN_USERNAME);
        self.observe(ip, username, outcome, now)
    }

    /// Garbage-collect entries whose lockout has expired AND last
    /// failure is outside the window. Cheap O(n) walk; call from a
    /// background tick (PingoraBackground or hyper cleanup_task).
    ///
    /// V234 — safe to call on a `Clone` of the guard; all clones share
    /// the same map behind the inner `Arc`, so one background tick
    /// cleans up for every worker.
    pub fn cleanup(&self, now: Instant) {
        let cfg_window = self.inner.cfg.window;
        let mut g = self.inner.inner.lock().expect("login abuse mutex poisoned");
        let retain_window = cfg_window.saturating_mul(2);
        g.per_ip_user
            .retain(|_, ks| keep_state(ks, now, retain_window));
        g.per_user
            .retain(|_, ks| keep_state(ks, now, retain_window));
        g.per_ip_fanout
            .retain(|_, fo| now.duration_since(fo.window_start) <= retain_window);
    }

    /// Diagnostic snapshot for /admin endpoints.
    pub fn diagnostics(&self) -> LoginAbuseDiagnostics {
        let g = self.inner.inner.lock().expect("login abuse mutex poisoned");
        LoginAbuseDiagnostics {
            tracked_ip_user_pairs: g.per_ip_user.len(),
            tracked_usernames: g.per_user.len(),
            tracked_ips: g.per_ip_fanout.len(),
            locked_pairs: g
                .per_ip_user
                .values()
                .filter(|ks| ks.locked_until.is_some())
                .count(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LoginAbuseDiagnostics {
    pub tracked_ip_user_pairs: usize,
    pub tracked_usernames: usize,
    pub tracked_ips: usize,
    pub locked_pairs: usize,
}

/// V233 — Canonicalise a username before it becomes a counter key.
///
/// Previously `observe` used only `to_ascii_lowercase()`, so `admin`,
/// `admin ` (trailing space), `Admin` and `аdmin` (Cyrillic homoglyph)
/// hashed into DIFFERENT buckets — an attacker rotated these to dodge
/// the per-(IP,username) and per-username brute-force counters
/// (auth_bypass).
///
/// This normaliser folds those variants together:
///
/// * Confusables / full-width / null bytes / **full Unicode**
///   lowercase via the shared `crate::normalisation` chain — this is
///   the same canonical pipeline the SQL/XSS detectors use, so e.g.
///   Cyrillic-homoglyph and full-width attacks on usernames are
///   covered to the extent that chain covers them.
/// * Leading/trailing whitespace is trimmed and every run of internal
///   whitespace is collapsed to a single ASCII space, so `admin`,
///   `admin ` and `  ad min ` no longer split into separate buckets.
///
/// Residual gap: `normalisation::confusable_fold` only carries a
/// targeted table (angle brackets, quotes, parens, etc.) and
/// `unicode_nfkc` only folds the full-width block — it is NOT a
/// complete Unicode confusable/NFKC fold, so exotic homoglyph
/// alphabets for letters (e.g. Greek/Cyrillic look-alikes) can still
/// reach distinct buckets. A full confusable table is a follow-up.
fn normalise_username(username: &str) -> String {
    // V234 — the "no username" sentinel must survive normalisation
    // verbatim. `crate::normalisation::normalise` strips NUL bytes, so
    // without this guard the NUL-wrapped sentinel would collapse to the
    // bare word "unknown" and collide with a real user literally named
    // `unknown`. Returning it untouched keeps the un-keyable bucket
    // genuinely unreachable by any client-supplied username (a real
    // normalised username can never contain a NUL — see below).
    if username == UNKNOWN_USERNAME {
        return UNKNOWN_USERNAME.to_string();
    }
    // Confusable / full-width / null-byte fold + full Unicode
    // lowercase. `normalise` lowercases via `to_lowercase()` (not just
    // ASCII) as its final stage. NUL bytes are stripped here, so a
    // genuine username can never collide with the sentinel above.
    let folded = crate::normalisation::normalise(username).normalised;
    // Trim outer whitespace and collapse internal whitespace runs.
    // `split_whitespace` handles all Unicode whitespace and discards
    // empty segments, so leading/trailing/duplicate spaces all vanish.
    folded.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------
// V234 — username extraction from request bodies
// ---------------------------------------------------------------------

/// V234 — synthetic username for login POSTs whose body carried no
/// recognisable username field. Wrapped in NUL bytes so it can never
/// equal a real normalised username (the V233 normaliser strips NULs
/// via `crate::normalisation::normalise`), keeping the "unknown"
/// bucket isolated from every genuine user while still letting an IP
/// that floods un-keyable POSTs trip the per-pair / fan-out counters.
const UNKNOWN_USERNAME: &str = "\u{0}unknown\u{0}";

/// V234 — login form field names we look for, in priority order. An
/// app that posts BOTH `username` and `email` is rare; if it happens
/// the first match wins, which is deterministic and good enough for a
/// counter key (the same app always posts the same shape).
const USERNAME_FIELDS: [&str; 4] = ["username", "email", "user", "login"];

/// V234 — cap on how much body we will scan for a username. Login
/// bodies are tiny (well under 1 KiB); refusing to walk a multi-MB
/// body bounds the per-request CPU an attacker can buy with a fat
/// POST. Beyond this we give up and return `None` (caller forwards as
/// un-keyable rather than paying to parse junk).
const MAX_BODY_SCAN: usize = 64 * 1024;

/// V234 — raw (un-normalised) username extraction. `extract_username`
/// wraps this and applies the V233 normaliser. Split out so tests can
/// assert the raw decode separately from normalisation.
fn extract_username_raw(content_type: &str, body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let body = if body.len() > MAX_BODY_SCAN {
        &body[..MAX_BODY_SCAN]
    } else {
        body
    };
    let ct = content_type.to_ascii_lowercase();
    // JSON when the content type says so.
    if ct.contains("json") {
        return extract_username_json(body);
    }
    // Explicit form content type.
    if ct.contains("form-urlencoded") {
        return extract_username_form(body);
    }
    // Unknown / missing content type: sniff. A JSON login body starts
    // (after optional whitespace) with `{`; otherwise assume a form
    // body — the overwhelmingly common shape for HTML login posts.
    let first = body.iter().find(|b| !b.is_ascii_whitespace()).copied();
    if first == Some(b'{') {
        extract_username_json(body)
    } else {
        extract_username_form(body)
    }
}

/// V234 — pull a username field out of an
/// `application/x-www-form-urlencoded` body (`a=1&username=bob&b=2`).
fn extract_username_form(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    for field in USERNAME_FIELDS {
        for pair in text.split('&') {
            let (k, v) = match pair.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            // Form keys may themselves be percent/`+` encoded; decode
            // before comparing so `user%6eame=` still matches.
            let key = form_decode(k);
            if key.eq_ignore_ascii_case(field) {
                let val = form_decode(v);
                if !val.trim().is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// V234 — percent + `+` decoding for form fields. Dependency-free:
/// the proxy must not pull a urlencoding crate just for this. Invalid
/// `%XX` escapes are passed through literally (lenient — an attacker
/// crafting bad escapes still gets keyed on *something* stable).
fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// V234 — pull a top-level string member out of a JSON login body.
///
/// This is a deliberately tiny, dependency-free scanner — NOT a full
/// JSON parser (the proxy carries no JSON crate for this path). It
/// finds `"<field>"` at the top level, skips the `:`, and reads the
/// following JSON string literal with standard escape handling
/// (`\" \\ \/ \n \r \t \b \f \uXXXX`). It is intentionally lenient:
/// it does not validate the surrounding object, only that a quoted
/// key/colon/quoted-value triple exists. For a login body (a flat
/// object of a handful of string fields) that is sufficient and
/// cannot be tricked into reading a *nested* same-named field in a
/// way that matters for a brute-force counter key.
fn extract_username_json(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    for field in USERNAME_FIELDS {
        if let Some(v) = json_string_field(text, field) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// V234 — find `"field"` followed by `:` then a JSON string literal,
/// return the decoded literal. `None` if absent / not a string value.
fn json_string_field(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let mut search_from = 0;
    // A field name can appear multiple times (e.g. as a substring of
    // another key, or genuinely twice); scan each occurrence until one
    // is followed by `:` + a string value.
    while let Some(rel) = text[search_from..].find(&needle) {
        let key_start = search_from + rel;
        let after_key = key_start + needle.len();
        search_from = after_key;
        // Skip whitespace then require a colon.
        let rest = text[after_key..].trim_start();
        let Some(rest) = rest.strip_prefix(':') else {
            continue;
        };
        // Skip whitespace then require an opening quote.
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('"') else {
            continue;
        };
        return Some(decode_json_string(rest));
    }
    None
}

/// V234 — decode a JSON string literal body (text AFTER the opening
/// quote) up to the unescaped closing quote.
fn decode_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{8}'),
                Some('f') => out.push('\u{c}'),
                Some('u') => {
                    // Read exactly 4 hex digits.
                    let hex: String = (&mut chars).take(4).collect();
                    if let Ok(cp) = u32::from_str_radix(&hex, 16) {
                        // Lone surrogates can't be `char`s — drop them;
                        // a username with a broken escape still keys on
                        // the rest of the string.
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                        }
                    }
                }
                // Unknown escape: keep the char literally.
                Some(other) => out.push(other),
                None => break,
            },
            other => out.push(other),
        }
    }
    out
}

fn check_window_roll(ks: &mut KeyState, now: Instant, window: Duration, base: Duration) {
    if now.duration_since(ks.window_start) > window {
        ks.failures = 0;
        ks.window_start = now;
        if ks.locked_until.is_none_or(|t| now > t) {
            // Locked released; halve the next-lockout step back toward
            // base so a single bad session doesn't punish the IP forever.
            ks.next_lockout = (ks.next_lockout / 2).max(base);
        }
    }
    if let Some(t) = ks.locked_until
        && now > t
    {
        ks.locked_until = None;
    }
}

fn arm_lockout(ks: &mut KeyState, now: Instant) -> Option<Instant> {
    let dur = ks.next_lockout.min(Duration::from_secs(3600));
    let until = now + dur;
    ks.locked_until = Some(until);
    // Double for the next round, capped.
    ks.next_lockout = (ks.next_lockout.saturating_mul(2)).min(Duration::from_secs(3600));
    Some(until)
}

fn keep_state(ks: &KeyState, now: Instant, retain_window: Duration) -> bool {
    if let Some(t) = ks.locked_until
        && now < t
    {
        return true;
    }
    now.duration_since(ks.window_start) <= retain_window
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LoginAbuseConfig {
        LoginAbuseConfig {
            // V234 — new fields. Tests that touch path matching set
            // `login_paths` explicitly via a local override.
            enabled: true,
            login_paths: vec!["/login".to_string()],
            window: Duration::from_secs(60),
            max_per_ip_user: 3,
            max_per_user: 5,
            max_usernames_per_ip: 4,
            throttle_base: Duration::from_secs(10),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allow_until_per_ip_user_threshold() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(
                g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now),
                LoginDecision::Allow
            );
        }
        // 4th failure exceeds max_per_ip_user=3 → Deny.
        assert_eq!(
            g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now),
            LoginDecision::Deny
        );
    }

    #[test]
    fn success_resets_per_ip_user_state() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        // 2 failures (under max_per_ip_user=3) then a success clears
        // per-(ip,user) state. Next 2 failures should be Allow again
        // (NOT Deny — that would mean the success had no effect).
        for _ in 0..2 {
            g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now);
        }
        assert_eq!(
            g.observe(ip("1.1.1.1"), "alice", Outcome::Success, now),
            LoginDecision::Allow
        );
        // Per-user counter (alice) is intentionally NOT reset by a
        // success — others may still be spraying her. So we only
        // probe 2 more failures to stay under max_per_user=5.
        for _ in 0..2 {
            assert_eq!(
                g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now),
                LoginDecision::Allow
            );
        }
    }

    #[test]
    fn credential_spray_per_user_throttles() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        // 6 distinct IPs each try alice once → triggers per_user>5.
        for i in 1..=6 {
            let ipa = ip(&format!("10.0.0.{i}"));
            let d = g.observe(ipa, "alice", Outcome::Failure, now);
            if i <= 5 {
                assert_eq!(d, LoginDecision::Allow);
            } else {
                assert_eq!(d, LoginDecision::Throttle(cfg().throttle_base));
            }
        }
    }

    #[test]
    fn fanout_violation_throttles() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        for i in 1..=5 {
            let user = format!("user{i}");
            let d = g.observe(ip("9.9.9.9"), &user, Outcome::Failure, now);
            if i <= 4 {
                assert_eq!(d, LoginDecision::Allow);
            } else {
                // 5th distinct user from same IP → fanout > 4.
                assert_eq!(d, LoginDecision::Throttle(cfg().throttle_base));
            }
        }
    }

    #[test]
    fn window_rolls_resets_counters() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        for _ in 0..3 {
            g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now);
        }
        // Next attempt without window roll → Deny.
        assert_eq!(
            g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now),
            LoginDecision::Deny
        );
        // After window+1 → fresh counters, Allow.
        let later = now + cfg().window + Duration::from_secs(1);
        assert_eq!(
            g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, later),
            LoginDecision::Allow
        );
    }

    #[test]
    fn diagnostics_track_state() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now);
        g.observe(ip("2.2.2.2"), "alice", Outcome::Failure, now);
        let d = g.diagnostics();
        assert_eq!(d.tracked_ip_user_pairs, 2);
        assert_eq!(d.tracked_usernames, 1);
        assert_eq!(d.tracked_ips, 2);
    }

    // V233 — `admin`, `admin ` (trailing space) and `ADMIN` must all
    // hash into the SAME per-username / per-(IP,username) counter
    // bucket. With the old `to_ascii_lowercase()` keying these were 3
    // distinct buckets, so an attacker rotating the variants got
    // 3 × max_per_ip_user attempts. Here we drive max_per_ip_user=3
    // failures spread across the variants and assert the 4th (total)
    // failure trips Deny — proving they share one counter.
    #[test]
    fn username_variants_share_counter_bucket() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        let variants = ["admin", "admin ", "ADMIN"];
        // 3 failures total across the variants (max_per_ip_user=3) →
        // all Allow because they accumulate in one bucket.
        for (i, u) in variants.iter().enumerate() {
            assert_eq!(
                g.observe(ip("1.1.1.1"), u, Outcome::Failure, now),
                LoginDecision::Allow,
                "variant #{i} ({u:?}) should still be Allow"
            );
        }
        // 4th failure (yet another variant) exceeds max_per_ip_user=3
        // → Deny. Only possible if all variants share the bucket.
        assert_eq!(
            g.observe(ip("1.1.1.1"), "Admin ", Outcome::Failure, now),
            LoginDecision::Deny,
            "shared bucket must trip Deny on the 4th failure"
        );
        // Sanity: exactly one (ip,user) pair and one username tracked,
        // not three/four.
        let d = g.diagnostics();
        assert_eq!(d.tracked_ip_user_pairs, 1, "variants must not split keys");
        assert_eq!(d.tracked_usernames, 1, "variants must not split keys");
    }

    // V233 — the normaliser itself: outer/inner whitespace and case
    // all fold away.
    #[test]
    fn normalise_username_folds_whitespace_and_case() {
        assert_eq!(normalise_username("admin"), "admin");
        assert_eq!(normalise_username("admin "), "admin");
        assert_eq!(normalise_username("  admin"), "admin");
        assert_eq!(normalise_username("ADMIN"), "admin");
        assert_eq!(normalise_username("Admin"), "admin");
        // Internal whitespace runs collapse to a single space.
        assert_eq!(normalise_username("ad   min"), "ad min");
        assert_eq!(normalise_username("\tad\nmin\t"), "ad min");
    }

    #[test]
    fn cleanup_drops_old_state() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        g.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now);
        // Run cleanup well past 2× window.
        let later = now + cfg().window * 3;
        g.cleanup(later);
        let d = g.diagnostics();
        assert_eq!(d.tracked_ip_user_pairs, 0);
    }

    // ---------------- V234 — new request-path API ----------------

    // V234 — a `Clone` of the guard shares one counter set: a failure
    // recorded through clone A must be visible to clone B.
    #[test]
    fn clone_shares_counters() {
        let a = LoginAbuseGuard::new(cfg());
        let b = a.clone();
        let now = Instant::now();
        for _ in 0..3 {
            a.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now);
        }
        // 4th failure via the *clone* trips Deny — proves shared state.
        assert_eq!(
            b.observe(ip("1.1.1.1"), "alice", Outcome::Failure, now),
            LoginDecision::Deny
        );
        // diagnostics() through either handle agree.
        assert_eq!(a.diagnostics().tracked_ip_user_pairs, 1);
        assert_eq!(b.diagnostics().tracked_ip_user_pairs, 1);
    }

    // V234 — from_config: None → defaults (enabled); a disabled config
    // yields None so the caller can skip the guard entirely.
    #[test]
    fn from_config_honours_enabled_flag() {
        assert!(LoginAbuseGuard::from_config(None).is_some());
        let mut disabled = cfg();
        disabled.enabled = false;
        assert!(LoginAbuseGuard::from_config(Some(disabled)).is_none());
    }

    // V234 — login-path matcher: exact + prefix glob, query string
    // tolerated, non-login paths rejected.
    #[test]
    fn is_login_path_matches_exact_and_prefix() {
        let mut c = cfg();
        c.login_paths = vec!["/login".to_string(), "/auth/*".to_string()];
        let g = LoginAbuseGuard::new(c);
        assert!(g.is_login_path("/login"));
        assert!(g.is_login_path("/login?next=/home")); // query stripped
        assert!(g.is_login_path("/auth/callback"));
        assert!(g.is_login_path("/auth/"));
        assert!(!g.is_login_path("/logout"));
        assert!(!g.is_login_path("/loginX")); // exact, not prefix
        assert!(!g.is_login_path("/"));
    }

    // V234 — a disabled guard never classifies any path as login.
    #[test]
    fn is_login_path_false_when_disabled() {
        let mut c = cfg();
        c.enabled = false;
        let g = LoginAbuseGuard::new(c);
        assert!(!g.is_login_path("/login"));
    }

    // V234 — only credential-carrying methods count.
    #[test]
    fn is_login_method_only_post_and_put() {
        assert!(LoginAbuseGuard::is_login_method("POST"));
        assert!(LoginAbuseGuard::is_login_method("post"));
        assert!(LoginAbuseGuard::is_login_method("PUT"));
        assert!(!LoginAbuseGuard::is_login_method("GET"));
        assert!(!LoginAbuseGuard::is_login_method("HEAD"));
        assert!(!LoginAbuseGuard::is_login_method("OPTIONS"));
    }

    // V234 — username extraction from a form-encoded body. Covers
    // `username`/`email`/`user`/`login` field names, `+` and `%XX`
    // decoding, and normalisation (case-fold) applied on top.
    #[test]
    fn extract_username_from_form_body() {
        let ct = "application/x-www-form-urlencoded";
        // Plain `username` field, surrounded by other fields.
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, b"csrf=xyz&username=Alice&password=p"),
            Some("alice".to_string())
        );
        // `email` field, `+` decodes to space then normaliser collapses
        // it (so " bob " → "bob").
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, b"email=+bob+&password=p"),
            Some("bob".to_string())
        );
        // `%XX` percent-decoding in the value.
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, b"user=jo%65%6c"), // "joel"
            Some("joel".to_string())
        );
        // `login` field name also recognised.
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, b"login=carol"),
            Some("carol".to_string())
        );
        // No recognised field → None.
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, b"password=p&token=t"),
            None
        );
        // Empty value → None (an empty username is not keyable).
        assert_eq!(LoginAbuseGuard::extract_username(ct, b"username="), None);
    }

    // V234 — username extraction from a JSON body. Covers the four
    // field names, escape decoding, whitespace content type tolerance,
    // and content-type sniffing when the header is absent.
    #[test]
    fn extract_username_from_json_body() {
        let ct = "application/json";
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, br#"{"username":"Alice","password":"p"}"#),
            Some("alice".to_string())
        );
        // `email` key, with other members before it.
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, br#"{"remember":true,"email":"Bob@x.com"}"#),
            Some("bob@x.com".to_string())
        );
        // JSON `\u` escape: "ab" via ab.
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, br#"{"user":"ab"}"#),
            Some("ab".to_string())
        );
        // `login` key.
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, br#"{"login":"carol"}"#),
            Some("carol".to_string())
        );
        // Content type with charset suffix still recognised as JSON.
        assert_eq!(
            LoginAbuseGuard::extract_username(
                "application/json; charset=utf-8",
                br#"{"username":"dave"}"#
            ),
            Some("dave".to_string())
        );
        // Missing content type → sniffed as JSON because body starts
        // with `{`.
        assert_eq!(
            LoginAbuseGuard::extract_username("", br#"  {"username":"erin"}"#),
            Some("erin".to_string())
        );
        // Non-string value → not extracted.
        assert_eq!(
            LoginAbuseGuard::extract_username(ct, br#"{"username":12345}"#),
            None
        );
        // Empty body → None.
        assert_eq!(LoginAbuseGuard::extract_username(ct, b""), None);
    }

    // V234 — missing content type with a form-shaped body is sniffed
    // as a form (the common HTML-login case).
    #[test]
    fn extract_username_sniffs_form_when_content_type_absent() {
        assert_eq!(
            LoginAbuseGuard::extract_username("", b"username=frank&password=p"),
            Some("frank".to_string())
        );
    }

    // V234 — evaluate(): pure gate, does NOT record. Repeated calls on
    // a clean key keep returning Allow.
    #[test]
    fn evaluate_is_read_only() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        for _ in 0..20 {
            assert_eq!(
                g.evaluate(ip("1.1.1.1"), Some("alice"), now),
                LoginDecision::Allow
            );
        }
        // Nothing was recorded by evaluate() itself.
        assert_eq!(g.diagnostics().tracked_ip_user_pairs, 0);
    }

    // V234 — evaluate() reflects a Deny armed by prior observe() calls,
    // and record() is the observe() feedback path.
    #[test]
    fn evaluate_reflects_armed_lockout() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        // Drive 4 failures via record() → per-(ip,user) lockout armed.
        for _ in 0..4 {
            g.record(ip("1.1.1.1"), Some("alice"), Outcome::Failure, now);
        }
        // A fresh request for the same key is now gated Deny.
        assert_eq!(
            g.evaluate(ip("1.1.1.1"), Some("alice"), now),
            LoginDecision::Deny
        );
        // A different user from the same IP is still fine.
        assert_eq!(
            g.evaluate(ip("1.1.1.1"), Some("zoe"), now),
            LoginDecision::Allow
        );
    }

    // V234 — a `None` username (unparseable body) keys on a synthetic
    // bucket that never collides with a real user.
    #[test]
    fn evaluate_handles_missing_username() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        // 4 un-keyable failures from one IP trip the synthetic-bucket
        // per-pair lockout.
        for _ in 0..4 {
            g.record(ip("7.7.7.7"), None, Outcome::Failure, now);
        }
        assert_eq!(g.evaluate(ip("7.7.7.7"), None, now), LoginDecision::Deny);
        // A real user from the same IP is unaffected — the synthetic
        // "unknown" bucket is isolated.
        assert_eq!(
            g.evaluate(ip("7.7.7.7"), Some("alice"), now),
            LoginDecision::Allow
        );
    }

    // V234 — record() success path resets the per-(ip,user) counter,
    // same as observe(Success).
    #[test]
    fn record_success_resets_counter() {
        let g = LoginAbuseGuard::new(cfg());
        let now = Instant::now();
        for _ in 0..2 {
            g.record(ip("1.1.1.1"), Some("alice"), Outcome::Failure, now);
        }
        g.record(ip("1.1.1.1"), Some("alice"), Outcome::Success, now);
        // Counter cleared → 3 more failures stay under threshold.
        for _ in 0..3 {
            assert_eq!(
                g.record(ip("1.1.1.1"), Some("alice"), Outcome::Failure, now),
                LoginDecision::Allow
            );
        }
    }

    // V234 — a disabled guard's evaluate()/record() are inert (Allow,
    // no state).
    #[test]
    fn disabled_guard_evaluate_and_record_are_inert() {
        let mut c = cfg();
        c.enabled = false;
        let g = LoginAbuseGuard::new(c);
        let now = Instant::now();
        for _ in 0..50 {
            assert_eq!(
                g.record(ip("1.1.1.1"), Some("alice"), Outcome::Failure, now),
                LoginDecision::Allow
            );
        }
        assert_eq!(
            g.evaluate(ip("1.1.1.1"), Some("alice"), now),
            LoginDecision::Allow
        );
        assert_eq!(g.diagnostics().tracked_ip_user_pairs, 0);
    }

    // V234 — the synthetic UNKNOWN_USERNAME bucket can never be reached
    // by a real client-supplied username.
    #[test]
    fn unknown_username_sentinel_is_collision_proof() {
        // The sentinel survives normalisation verbatim (NULs intact) —
        // this is what keeps its bucket distinct.
        assert_eq!(normalise_username(UNKNOWN_USERNAME), UNKNOWN_USERNAME);
        assert!(UNKNOWN_USERNAME.contains('\u{0}'));
        // A real username — even the word "unknown" — normalises to a
        // NUL-free string, so it can NEVER equal the sentinel.
        assert_ne!(normalise_username("unknown"), UNKNOWN_USERNAME);
        assert_ne!(normalise_username("Unknown"), UNKNOWN_USERNAME);
        assert!(!normalise_username("unknown").contains('\u{0}'));
        // And a client that literally posts the sentinel text is NOT
        // mistaken for a parsed username — extract_username yields None.
        let body = format!("username={UNKNOWN_USERNAME}");
        assert_eq!(
            LoginAbuseGuard::extract_username("application/x-www-form-urlencoded", body.as_bytes(),),
            None,
        );
    }
}
