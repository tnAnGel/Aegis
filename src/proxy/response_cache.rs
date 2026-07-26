//! Threat-aware response cache.
//!
//! Memoises cacheable upstream responses so subsequent requests for
//! the same `(method, host, path)` are served from RAM without
//! contacting the upstream. The "threat-aware" qualifier separates
//! this from a vanilla `proxy_cache`-style implementation:
//!
//! - **Low-threat / trusted clients** (those `ctx.is_trusted` returns
//!   true for, or anyone when no threat signal exists) get the cache
//!   hit.
//! - **High-threat clients** (recently denied / challenged IPs) get
//!   forced cache MISS — the response is fetched fresh from upstream
//!   and goes through the full filter pipeline. This blocks cache
//!   poisoning where an attacker influences cached content via
//!   header / query smuggling.
//!
//! Defense properties:
//!   * WAF still runs for high-threat IPs on every request (cache is
//!     just a perf shortcut, not a security bypass).
//!   * Cache entries store only the upstream response — they cannot
//!     contain attacker-controlled payload because cacheable responses
//!     are by definition deterministic for the cache key.
//!   * `Set-Cookie` responses are never cached (would cross-pollute
//!     sessions across users).
//!   * `Cache-Control: private | no-store` is honoured.
//!
//! Storage:
//!   * Single-process LRU keyed on `(Method, Host, Path)`. No shared
//!     state across worker processes — each process maintains its own
//!     cache, which is fine: the cost of a per-process duplicate is
//!     bounded by `max_entries` × `max_body_bytes`, and the upside is
//!     zero-coordination operation (no Redis hop, no lock contention).
//!   * Body bytes stored as `Bytes` (zero-copy on hit — just clone the
//!     Arc, no memcpy).

use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method, StatusCode,
    header::{AUTHORIZATION, COOKIE},
};
use lru::LruCache;
use rustc_hash::{FxHashMap, FxHasher};

use crate::config::ResponseCacheConfig;

/// Number of independent LRU shards. Each shard has its own mutex, so
/// concurrent lookups for different cache keys don't contend. Tuned
/// for typical 4-16 core servers — overhead of more shards is per-key
/// indirection, so we don't go wild.
const CACHE_SHARDS: usize = 32;

/// Composite key — same method+host+path → same cache slot.
/// Method is u8 discriminant (8 bytes total for the tuple), Host and
/// Path stored as owned `String` to avoid lifetimes leaking into the
/// LRU. Lowercased Host for case-insensitive match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    method: u8,
    pub host: String,
    pub path: String,
}

impl CacheKey {
    /// Build a new cache key. Most production Host headers are already
    /// all-lowercase (`example.com`, not `Example.Com`), so we probe
    /// for that fast path first — `to_ascii_lowercase()` always
    /// allocates a new String even when the content is byte-identical,
    /// which at 800k+ RPS is real per-request waste. V79 skips the
    /// alloc when no uppercase byte is present.
    fn new(method: &Method, host: &str, path: &str) -> Self {
        let host_owned = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            host.to_ascii_lowercase()
        } else {
            // Already lowercase: still need a String for storage, but
            // a single `String::from(&str)` is cheaper than
            // to_ascii_lowercase() (no per-byte conditional loop).
            String::from(host)
        };
        Self {
            method: method_byte(method),
            host: host_owned,
            path: path.to_string(),
        }
    }

    /// Case-insensitive host equality — used by purge filters.
    pub fn host_lower_eq(&self, other: &str) -> bool {
        self.host.eq_ignore_ascii_case(other)
    }
}

/// V230 — Borrow-shaped lookup key used by the hot `lookup()` path so
/// `LruCache::peek()` can probe the map without first allocating an
/// owned `CacheKey` (which mints two Strings, host + path). Composite
/// keys can't `Borrow` a single field, so we route through a trait
/// object that both `CacheKey` and a borrowed-view struct implement —
/// the canonical Rust idiom for zero-alloc map lookup on multi-field
/// keys. `peek<Q: ?Sized>` accepts `dyn CacheKeyLookup` directly.
///
/// Hash correctness: `derive(Hash)` on `CacheKey` walks fields in
/// declaration order (`method: u8`, `host: String`, `path: String`).
/// The manual `Hash` impl on `dyn CacheKeyLookup` mirrors that exact
/// sequence so the trait-object hash and the owned-key hash produce
/// byte-identical streams. Same for `PartialEq` — field-by-field.
///
/// Hot-path savings: ~2 String allocations + the lowercase walk on
/// every cache lookup. Owned `CacheKey` is still built for `store()`
/// / `purge_*` since those keep the key in the map.
pub(crate) trait CacheKeyLookup {
    fn method(&self) -> u8;
    fn host(&self) -> &str;
    fn path(&self) -> &str;
}

impl CacheKeyLookup for CacheKey {
    #[inline]
    fn method(&self) -> u8 {
        self.method
    }
    #[inline]
    fn host(&self) -> &str {
        &self.host
    }
    #[inline]
    fn path(&self) -> &str {
        &self.path
    }
}

impl Hash for dyn CacheKeyLookup + '_ {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Field-order MUST match `derive(Hash)` on CacheKey:
        //   method (u8) → host (String/str) → path (String/str).
        // `String::hash` defers to `str::hash`, so `&self.host` and
        // `&CacheKey.host` produce identical hasher writes.
        self.method().hash(state);
        self.host().hash(state);
        self.path().hash(state);
    }
}

impl PartialEq for dyn CacheKeyLookup + '_ {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.method() == other.method()
            && self.host() == other.host()
            && self.path() == other.path()
    }
}

impl Eq for dyn CacheKeyLookup + '_ {}

impl<'a> Borrow<dyn CacheKeyLookup + 'a> for CacheKey {
    #[inline]
    fn borrow(&self) -> &(dyn CacheKeyLookup + 'a) {
        self
    }
}

/// V230 — Stack-only borrowed view of a cache key. Cheap to build (3
/// small fields, no allocations), comparable to the owned `CacheKey`
/// in the map via the `CacheKeyLookup` trait object. Host is NOT
/// lowercased here — callers that need case-insensitive lookup must
/// pass an already-lowered host, or fall back to building an owned
/// `CacheKey` for the slow path. In practice every hot-path call site
/// already lowercases the host earlier (validated headers).
pub(crate) struct CacheKeyRef<'a> {
    method: u8,
    host: &'a str,
    path: &'a str,
}

impl<'a> CacheKeyRef<'a> {
    #[inline]
    fn new(method: u8, host: &'a str, path: &'a str) -> Self {
        Self { method, host, path }
    }
}

impl<'a> CacheKeyLookup for CacheKeyRef<'a> {
    #[inline]
    fn method(&self) -> u8 {
        self.method
    }
    #[inline]
    fn host(&self) -> &str {
        self.host
    }
    #[inline]
    fn path(&self) -> &str {
        self.path
    }
}

fn method_byte(m: &Method) -> u8 {
    match *m {
        Method::GET => 1,
        Method::HEAD => 2,
        // POST/PUT/DELETE/PATCH never cached per RFC 9111 §3.
        _ => 0,
    }
}

/// Cached upstream response. V84 — `headers` wrapped in `Arc` so
/// hot-path `cached.clone()` is a refcount bump on the header map
/// instead of a deep HeaderMap copy (which allocates per
/// HeaderName/HeaderValue). `body` was already `Bytes` (refcounted);
/// this brings parity for the headers field.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: Arc<HeaderMap>,
    pub body: Bytes,
    pub expires_at: Instant,
    /// V98 — when the entry was stored. Used by [ThreatTier::Medium]
    /// freshness check (entry must be in its first half-life).
    pub stored_at: Instant,
    /// V98 — original TTL at store time (= expires_at - stored_at).
    /// Stored explicitly because per-host / per-status overrides mean
    /// the cache-wide `default_ttl` can't reliably reconstruct it.
    pub ttl: Duration,
}

impl CachedResponse {
    pub fn is_fresh(&self, now: Instant) -> bool {
        self.expires_at > now
    }
}

/// Single cache entry summary returned by `dump()` for admin
/// inspection. No body content — operators don't need / shouldn't
/// see body in a debug dump (may contain PII or sensitive data).
#[derive(Debug, Clone)]
pub struct CacheEntryInfo {
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub body_bytes: usize,
    /// Seconds until entry expires. -1 if already expired.
    pub expires_in_secs: i64,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub skipped_high_threat: u64,
    pub skipped_uncacheable: u64,
    pub evictions: u64,
    pub not_modified: u64,
    /// V98 — tiered policy counters. served_low + served_medium +
    /// forced_miss_high should sum to total threat-tiered lookups.
    pub served_low: u64,
    pub served_medium: u64,
    pub forced_miss_high: u64,
}

/// V98 — per-IP threat tier used by the cache policy. The cache
/// already gates on a binary `is_high_threat: bool` (V14 era); the
/// tier widens that into low/medium/high so we can serve cached
/// responses to medium-threat IPs at reduced freshness instead of
/// forcing them upstream (cost = small) or letting them pollute the
/// cache (risk = real).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatTier {
    /// Score ≤ 33 of 100. Full TTL, normal hit. The vast majority of
    /// traffic.
    Low,
    /// Score 33-66. Hit only if the entry is fresher than TTL/2.
    /// Trades cache effectiveness for "did the operator just update
    /// content to neutralise an attack?" — medium-threat clients see
    /// the new content faster.
    Medium,
    /// Score > 66. Forced miss, always upstream. Same as the
    /// pre-V98 `is_high_threat=true` path.
    High,
}

impl ThreatTier {
    /// Derive tier from a 0..=100 ThreatScore-shaped float. Thresholds
    /// are deliberately conservative — operators expecting tight ACID
    /// freshness should keep cache off entirely.
    #[inline]
    pub fn from_score(score: f64) -> Self {
        if score > 66.0 {
            Self::High
        } else if score > 33.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Atomic counters used internally so the hot path never touches a
/// shared mutex. `stats()` collects them into a `CacheStats` snapshot.
#[derive(Default)]
struct AtomicStats {
    hits: AtomicU64,
    misses: AtomicU64,
    stores: AtomicU64,
    skipped_high_threat: AtomicU64,
    skipped_uncacheable: AtomicU64,
    evictions: AtomicU64,
    /// 304 Not Modified responses served instead of full body — counts
    /// `If-None-Match` / `If-Modified-Since` requests that matched the
    /// cached ETag and got a body-less response. Phase 3Y.1.
    not_modified: AtomicU64,
    /// V98 — per-tier policy outcomes.
    served_low: AtomicU64,
    served_medium: AtomicU64,
    forced_miss_high: AtomicU64,
}

/// Outcome of `lookup_conditional`. Distinguishes a hot cache hit
/// from a `304 Not Modified` short-circuit so the proxy can build
/// the appropriate response shape.
#[derive(Debug)]
pub enum CacheLookup {
    /// Fresh full body — serve as Response with status/headers/body.
    Hit(CachedResponse),
    /// Validator (ETag / Last-Modified) matched a conditional request.
    /// Serve a 304 Not Modified with only the validator headers — no
    /// body. Saves bandwidth + body serialization CPU.
    NotModified {
        etag: Option<HeaderValue>,
        last_modified: Option<HeaderValue>,
    },
    /// Either no entry, expired, or threat-policy forced MISS.
    Miss,
}

pub struct ResponseCache {
    enabled: bool,
    default_ttl: Duration,
    max_body_bytes: usize,
    /// Hosts the cache is enabled for. Empty = all hosts. Operators
    /// commonly enable cache only for known static/CDN-style hosts to
    /// keep dynamic endpoints fresh.
    allow_hosts: Option<Vec<String>>,
    /// Per-host TTL / body-size / enable overrides (Phase 3Y.3).
    /// HashMap because per-host config is read on every store; O(1)
    /// lookup matters at cache-store frequency.
    per_host: std::collections::HashMap<String, PerHostSettings>,
    /// Status-code → TTL override (Phase 3Y.6). Common use: cache
    /// 404s briefly (e.g. 10s) to absorb scanner bursts without
    /// hammering upstream, while keeping 200s long. Empty = single
    /// global TTL.
    ///
    /// V230 — `FxHashMap` instead of `std::HashMap`. Status codes are
    /// proxy-controlled (not attacker-influenced), so the DoS
    /// resistance of SipHash isn't needed; FxHash is ~5× faster and
    /// shaves a measurable slice off `store()` when status_ttl is
    /// populated.
    status_ttl: FxHashMap<u16, Duration>,
    /// Phase 3Y.7 — Stale-if-error window. Expired entries whose
    /// expiry was within this window of `now` can be served when
    /// upstream fails. Zero = disabled (default).
    stale_if_error: Duration,
    /// Sharded LRU. Each shard has its own RwLock so concurrent
    /// lookups for the SAME key run as parallel readers (V83 — was
    /// Mutex, every reader contended). Writers (store/evict) still
    /// serialise per-shard via write lock.
    ///
    /// Read path uses `peek` (LruCache::peek is `&self`, doesn't
    /// promote LRU position). For a 99.99% read workload that's
    /// most of the wins from a full lock-free cache without the
    /// architectural cost. LRU semantics degrade gracefully toward
    /// FIFO on never-evicted entries; for typical caches that
    /// barely matters because eviction is rare.
    shards: Box<[std::sync::RwLock<LruCache<CacheKey, CachedResponse>>]>,
    stats: AtomicStats,
    /// V21 — last-seen mtime of the AEGIS_CACHE_BROADCAST file. When
    /// the file's mtime advances, this worker applies purge_all on
    /// its local cache. Lets a single /admin/cache/purge cluster-
    /// invalidate without a sidecar or pub-sub.
    last_broadcast_mtime: ArcSwap<Option<SystemTime>>,
}

#[derive(Debug, Clone, Copy)]
struct PerHostSettings {
    ttl: Option<Duration>,
    max_body_bytes: Option<usize>,
    enabled: Option<bool>,
}

impl ResponseCache {
    pub fn new(cfg: &ResponseCacheConfig) -> Self {
        // Env override path — mirrors the same shape as DynamicTrust.
        // Operators sealed inside DSL-only configs can still flip the
        // cache on without re-cutting their config:
        //   AEGIS_RESPONSE_CACHE_ENABLE=1
        //   AEGIS_RESPONSE_CACHE_TTL=<seconds>
        //   AEGIS_RESPONSE_CACHE_MAX_ENTRIES=<n>
        //   AEGIS_RESPONSE_CACHE_MAX_BODY=<bytes>
        // As with DynamicTrust the override only *enables* — never
        // disables an already-enabled config.
        let env_enabled = std::env::var("AEGIS_RESPONSE_CACHE_ENABLE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let env_ttl: Option<u64> = std::env::var("AEGIS_RESPONSE_CACHE_TTL")
            .ok()
            .and_then(|v| v.parse().ok());
        let env_entries: Option<usize> = std::env::var("AEGIS_RESPONSE_CACHE_MAX_ENTRIES")
            .ok()
            .and_then(|v| v.parse().ok());
        let env_body: Option<usize> = std::env::var("AEGIS_RESPONSE_CACHE_MAX_BODY")
            .ok()
            .and_then(|v| v.parse().ok());

        let total_entries = env_entries.unwrap_or(cfg.max_entries).max(16);
        // Per-shard capacity: divide total by shard count, but each
        // shard gets at least 4 slots so a small max_entries config
        // still works (otherwise NonZeroUsize::new would panic).
        let per_shard = (total_entries / CACHE_SHARDS).max(4);
        let cap = std::num::NonZeroUsize::new(per_shard).expect("per-shard cap is non-zero");
        let shards: Vec<std::sync::RwLock<LruCache<CacheKey, CachedResponse>>> = (0..CACHE_SHARDS)
            .map(|_| std::sync::RwLock::new(LruCache::new(cap)))
            .collect();
        let allow_hosts = if cfg.hosts.is_empty() {
            None
        } else {
            Some(cfg.hosts.iter().map(|h| h.to_ascii_lowercase()).collect())
        };
        let mut per_host = std::collections::HashMap::new();
        for entry in &cfg.per_host {
            per_host.insert(
                entry.host.to_ascii_lowercase(),
                PerHostSettings {
                    ttl: entry.ttl_secs.map(Duration::from_secs),
                    max_body_bytes: entry.max_body_bytes,
                    enabled: entry.enabled,
                },
            );
        }
        let status_ttl: FxHashMap<u16, Duration> = cfg
            .status_ttl_secs
            .iter()
            .map(|(&code, &secs)| (code, Duration::from_secs(secs.max(1))))
            .collect();
        Self {
            enabled: cfg.enabled || env_enabled,
            default_ttl: Duration::from_secs(env_ttl.unwrap_or(cfg.default_ttl_secs).max(1)),
            max_body_bytes: env_body.unwrap_or(cfg.max_body_bytes),
            allow_hosts,
            per_host,
            status_ttl,
            stale_if_error: Duration::from_secs(cfg.stale_if_error_secs),
            shards: shards.into_boxed_slice(),
            stats: AtomicStats::default(),
            last_broadcast_mtime: ArcSwap::from_pointee(None),
        }
    }

    /// Phase 3Y.7 — Look up a stale-but-recently-expired entry when
    /// upstream fails. Returns `Some(cached)` when an entry exists
    /// AND it expired within the `stale_if_error` window AND threat
    /// policy permits (high-threat IPs never get stale either —
    /// no exception for them on upstream failure).
    pub fn lookup_stale_if_error(
        &self,
        method: &Method,
        host: &str,
        path: &str,
        is_high_threat: bool,
        now: Instant,
    ) -> Option<CachedResponse> {
        if !self.enabled
            || self.stale_if_error.is_zero()
            || is_high_threat
            || !self.host_eligible(host)
            || method_byte(method) == 0
        {
            return None;
        }
        let key = CacheKey::new(method, host, path);
        let shard = self.shard_for(&key);
        let guard = shard.read().unwrap();
        let entry = guard.peek(&key)?;
        // Entry's TTL must have expired (else `lookup` would have hit)
        // AND the staleness must be within our window.
        if entry.expires_at > now {
            return None; // fresh, would have hit via normal lookup
        }
        let stale_age = now.duration_since(entry.expires_at);
        if stale_age > self.stale_if_error {
            return None; // too stale to serve
        }
        let cached = entry.clone();
        drop(guard);
        self.stats.hits.fetch_add(1, Ordering::Relaxed);
        Some(cached)
    }

    fn settings_for(&self, host: &str) -> (Duration, usize, bool) {
        let lower = host.to_ascii_lowercase();
        if let Some(s) = self.per_host.get(&lower) {
            (
                s.ttl.unwrap_or(self.default_ttl),
                s.max_body_bytes.unwrap_or(self.max_body_bytes),
                s.enabled.unwrap_or(true),
            )
        } else {
            (self.default_ttl, self.max_body_bytes, true)
        }
    }

    /// Route a key to its shard via a stable hash. Same key → same
    /// shard, so LRU semantics are preserved (no risk of two shards
    /// holding the same key with divergent state).
    ///
    /// V230 — switched from `DefaultHasher` (SipHash) to `FxHasher`.
    /// The shard index doesn't need DoS resistance: collisions just
    /// route to the same shard, which is already collision-safe
    /// (LruCache itself hashes internally with the default hasher).
    /// FxHash is ~5× faster on small integer/string sequences and
    /// trims this single-digit-ns operation off the hot path.
    fn shard_for(&self, key: &CacheKey) -> &std::sync::RwLock<LruCache<CacheKey, CachedResponse>> {
        let mut h = FxHasher::default();
        key.hash(&mut h);
        &self.shards[(h.finish() as usize) % self.shards.len()]
    }

    /// V230 — shard router for the borrowed-key fast path. Same hash
    /// stream as `shard_for(&CacheKey)` because the trait-object hash
    /// (impl `Hash for dyn CacheKeyLookup`) walks the same fields in
    /// the same order as `derive(Hash)` on the owned key — so a
    /// lookup for "host/path" routes to the SAME shard the matching
    /// stored owned key was routed to.
    fn shard_for_lookup(
        &self,
        key: &dyn CacheKeyLookup,
    ) -> &std::sync::RwLock<LruCache<CacheKey, CachedResponse>> {
        let mut h = FxHasher::default();
        key.hash(&mut h);
        &self.shards[(h.finish() as usize) % self.shards.len()]
    }

    /// Snapshot stats for /admin/metrics rendering. Cheap — relaxed
    /// atomic loads, no lock. Numbers can be slightly inconsistent
    /// across counters (one CPU mid-update) — fine for metrics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.stats.hits.load(Ordering::Relaxed),
            misses: self.stats.misses.load(Ordering::Relaxed),
            stores: self.stats.stores.load(Ordering::Relaxed),
            skipped_high_threat: self.stats.skipped_high_threat.load(Ordering::Relaxed),
            skipped_uncacheable: self.stats.skipped_uncacheable.load(Ordering::Relaxed),
            evictions: self.stats.evictions.load(Ordering::Relaxed),
            not_modified: self.stats.not_modified.load(Ordering::Relaxed),
            served_low: self.stats.served_low.load(Ordering::Relaxed),
            served_medium: self.stats.served_medium.load(Ordering::Relaxed),
            forced_miss_high: self.stats.forced_miss_high.load(Ordering::Relaxed),
        }
    }

    /// V98 — tiered lookup. Same gating as [Self::lookup] plus per-tier
    /// policy: Low gets full TTL, Medium gets TTL/2 freshness window,
    /// High forces a miss + stats bump.
    ///
    /// The caller derives `tier` from any combination of: per-IP
    /// ThreatScorer score, SharedScorer cluster score, MlScorer
    /// inference output. A `ThreatTier::from_score(max(...))` is the
    /// common pattern.
    pub fn lookup_tiered(
        &self,
        method: &Method,
        host: &str,
        path: &str,
        tier: ThreatTier,
        now: Instant,
    ) -> Option<CachedResponse> {
        if !self.enabled || !self.host_eligible(host) {
            return None;
        }
        if matches!(tier, ThreatTier::High) {
            self.stats.forced_miss_high.fetch_add(1, Ordering::Relaxed);
            // Keep the legacy counter in sync so existing dashboards
            // that read `skipped_high_threat` don't go dark.
            self.stats
                .skipped_high_threat
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if method_byte(method) == 0 {
            return None;
        }
        let key = CacheKey::new(method, host, path);
        let shard = self.shard_for(&key);
        let peeked = {
            let store = shard.read().unwrap();
            store.peek(&key).cloned()
        };
        match peeked {
            Some(entry) if Self::tier_admits(&entry, tier, now) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                match tier {
                    ThreatTier::Low => {
                        self.stats.served_low.fetch_add(1, Ordering::Relaxed);
                    }
                    ThreatTier::Medium => {
                        self.stats.served_medium.fetch_add(1, Ordering::Relaxed);
                    }
                    ThreatTier::High => unreachable!("filtered above"),
                }
                Some(entry)
            }
            Some(_too_stale_for_tier) => {
                // Either expired entirely, or Medium-tier and past the
                // TTL/2 freshness window. Evict if truly expired so we
                // don't loop on the same stale entry; otherwise leave
                // it (Low-tier requests might still get a hit).
                if let Ok(mut store) = shard.write() {
                    if let Some(e) = store.peek(&key).cloned()
                        && !e.is_fresh(now)
                    {
                        store.pop(&key);
                        self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                    }
                }
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            None => {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// V98 — tier-aware freshness check. Low ⇒ stock `is_fresh`.
    /// Medium ⇒ entry's REMAINING lifetime must be ≥ original TTL/2
    /// (i.e. entry is no older than half its TTL).
    #[inline]
    fn tier_admits(entry: &CachedResponse, tier: ThreatTier, now: Instant) -> bool {
        if !entry.is_fresh(now) {
            return false;
        }
        match tier {
            ThreatTier::Low => true,
            ThreatTier::Medium => {
                let total = entry.ttl;
                let remaining = entry
                    .expires_at
                    .checked_duration_since(now)
                    .unwrap_or_default();
                // Admit when at least half the TTL remains — i.e. the
                // entry was stored in roughly the most recent half-TTL.
                remaining.as_millis() * 2 >= total.as_millis()
            }
            ThreatTier::High => false,
        }
    }

    /// Cap on per-entry body size in bytes. Exposed so the pingora
    /// body-accumulator (`response_body_filter`) can stop buffering
    /// once it knows the response will never fit, rather than holding
    /// half a GB in memory only to drop it at `store()` time.
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Lookup with threat-aware policy. Returns `Some(cached)` only when:
    ///   * cache is enabled
    ///   * host is in the allow-list (or list is empty)
    ///   * the client is not flagged high-threat
    ///   * there is a fresh entry for `(method, host, path)`
    pub fn lookup(
        &self,
        method: &Method,
        host: &str,
        path: &str,
        is_high_threat: bool,
        now: Instant,
    ) -> Option<CachedResponse> {
        if !self.enabled {
            return None;
        }
        if !self.host_eligible(host) {
            return None;
        }
        if is_high_threat {
            self.stats
                .skipped_high_threat
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let m_byte = method_byte(method);
        if m_byte == 0 {
            // POST/PUT/DELETE/etc. — never cached.
            return None;
        }
        // V230 — zero-alloc fast path. When the host is already
        // lowercase (the production-common case; see CacheKey::new
        // for the same shortcut on store), we can build a stack-only
        // `CacheKeyRef`, hash + probe it via `peek<dyn …>`, and skip
        // the two String allocations the owned `CacheKey` requires.
        // The cold path (mixed-case host, or a stale entry that needs
        // popping) still builds the owned key.
        let host_is_lower = !host.bytes().any(|b| b.is_ascii_uppercase());
        if host_is_lower {
            let key_ref = CacheKeyRef::new(m_byte, host, path);
            let shard = self.shard_for_lookup(&key_ref);
            let peeked = {
                let store = shard.read().unwrap();
                // `peek::<dyn CacheKeyLookup>` accepts the borrowed
                // view via the `Borrow` impl on `CacheKey`. Hash + Eq
                // match the derived impls bit-for-bit (field order /
                // String→str hash equivalence).
                store.peek(&key_ref as &dyn CacheKeyLookup).cloned()
            };
            match peeked {
                Some(entry) if entry.is_fresh(now) => {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(entry);
                }
                Some(_stale) => {
                    // Fall through to the cold path so we can build
                    // an owned key for the write-lock `pop`. (lru's
                    // `pop` also accepts the borrowed key, but the
                    // ergonomics of constructing the owned key only
                    // when actually needed is cleaner.)
                }
                None => {
                    self.stats.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        }
        // Cold / mixed-case host path — build the owned key.
        let key = CacheKey::new(method, host, path);
        let shard = self.shard_for(&key);
        // V83 — peek under a read lock. peek() is &self (doesn't
        // promote LRU position), so multiple concurrent lookups
        // run as parallel readers instead of serialising through
        // the previous Mutex. peek_clone gives us an owned copy
        // we can return after dropping the lock.
        let peeked = {
            let store = shard.read().unwrap();
            store.peek(&key).cloned()
        };
        match peeked {
            Some(entry) if entry.is_fresh(now) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                Some(entry)
            }
            Some(_stale) => {
                // Stale — escalate to write lock and pop. The race
                // window (drop read lock → acquire write lock) is
                // benign: at worst two workers both attempt the
                // pop and one of them no-ops. The bench fast-path
                // (always-fresh single URL) doesn't enter this
                // branch at all.
                if let Ok(mut store) = shard.write() {
                    store.pop(&key);
                }
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                None
            }
            None => {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// List cached entries (method, host, path, body_bytes, age_secs)
    /// for debugging via /admin/cache/dump. Capped at `limit` so an
    /// operator with a million entries doesn't bring down their admin
    /// interface; returns the first N walked across shards.
    pub fn dump(&self, limit: usize, now: Instant) -> Vec<CacheEntryInfo> {
        let mut out = Vec::with_capacity(limit.min(1024));
        'outer: for shard in self.shards.iter() {
            let guard = shard.read().unwrap();
            for (key, entry) in guard.iter() {
                if out.len() >= limit {
                    break 'outer;
                }
                let age = entry
                    .expires_at
                    .checked_duration_since(now)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(-1);
                out.push(CacheEntryInfo {
                    method: match key.method {
                        1 => "GET".to_string(),
                        2 => "HEAD".to_string(),
                        _ => "?".to_string(),
                    },
                    host: key.host.clone(),
                    path: key.path.clone(),
                    body_bytes: entry.body.len(),
                    status: entry.status.as_u16(),
                    expires_in_secs: age,
                });
            }
        }
        out
    }

    /// Purge entries matching a predicate. Returns the count of
    /// removed entries. Used by the admin `POST /admin/cache/purge`
    /// endpoint so operators can invalidate after upstream content
    /// change without waiting for TTL.
    ///
    /// Walks all shards under per-shard lock — runs at admin frequency
    /// (not per-request), so the cost is acceptable.
    pub fn purge_where<F>(&self, mut keep: F) -> usize
    where
        F: FnMut(&CacheKey) -> bool,
    {
        let mut removed = 0usize;
        for shard in self.shards.iter() {
            let mut guard = shard.write().unwrap();
            // LruCache doesn't have retain — collect keys to evict, then pop.
            let to_evict: Vec<CacheKey> = guard
                .iter()
                .filter_map(|(k, _)| if !keep(k) { Some(k.clone()) } else { None })
                .collect();
            for k in to_evict {
                guard.pop(&k);
                removed += 1;
            }
        }
        self.stats
            .evictions
            .fetch_add(removed as u64, Ordering::Relaxed);
        removed
    }

    /// Purge all entries. Returns count.
    pub fn purge_all(&self) -> usize {
        self.purge_where(|_| false)
    }

    /// Purge entries for a specific host (case-insensitive).
    pub fn purge_host(&self, host: &str) -> usize {
        let want = host.to_ascii_lowercase();
        self.purge_where(|k| !k.host.eq_ignore_ascii_case(&want))
    }

    /// Purge entries whose path starts with `prefix` (regardless of host).
    /// Common pattern: invalidate everything under `/api/v1/` after a release.
    pub fn purge_path_prefix(&self, prefix: &str) -> usize {
        self.purge_where(|k| !k.path.starts_with(prefix))
    }

    /// Purge a single exact entry (method + host + path).
    pub fn purge_exact(&self, method: &Method, host: &str, path: &str) -> usize {
        let key = CacheKey::new(method, host, path);
        let shard = self.shard_for(&key);
        let removed = shard.write().unwrap().pop(&key).is_some() as usize;
        self.stats
            .evictions
            .fetch_add(removed as u64, Ordering::Relaxed);
        removed
    }

    /// V21 — Touch the cross-worker purge-broadcast file. Each worker
    /// polls this file's mtime in the background cleanup task; when
    /// it advances, the worker purges its own local cache. This gives
    /// operators a single-command cluster-wide purge in multi-process
    /// deployments without needing a sidecar or pub/sub system.
    ///
    /// The broadcasting worker still does its own immediate purge
    /// (via the `purge_*` method directly); this signal is for the
    /// OTHER workers to follow.
    ///
    /// Path is taken from `AEGIS_CACHE_BROADCAST` env-var if set;
    /// otherwise no-op (cross-worker broadcast disabled).
    pub fn broadcast_purge() {
        if let Ok(path) = std::env::var("AEGIS_CACHE_BROADCAST") {
            // Create/touch the file. `utime`-equivalent via OpenOptions.
            // The actual content doesn't matter — only mtime is consulted.
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .and_then(|mut f| {
                    use std::io::Write;
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    writeln!(f, "{ts}")
                });
        }
    }

    /// V21 — Check if the cross-worker purge signal file has been
    /// touched since the last poll. Returns true when a purge should
    /// be applied (caller does `purge_all()`). Tracks the last-seen
    /// mtime internally via `last_broadcast_mtime`.
    pub fn check_broadcast_purge(&self) -> bool {
        let Ok(path) = std::env::var("AEGIS_CACHE_BROADCAST") else {
            return false;
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            return false;
        };
        let Ok(mtime) = meta.modified() else {
            return false;
        };
        let prev = self.last_broadcast_mtime.load();
        let prev_val: Option<SystemTime> = **prev;
        if prev_val == Some(mtime) {
            return false; // unchanged
        }
        if prev_val.is_none() {
            // First poll — establish baseline, don't purge.
            self.last_broadcast_mtime.store(Arc::new(Some(mtime)));
            return false;
        }
        self.last_broadcast_mtime.store(Arc::new(Some(mtime)));
        true
    }

    /// Insert a response if it's cacheable per RFC 9111 + our policy
    /// (see `is_cacheable_response`). No-op when the response doesn't
    /// qualify or when the cache is disabled / host not allowed.
    ///
    /// V233 — `request_headers` is the REQUEST's `HeaderMap`. A response
    /// to a request that carried `Authorization` or `Cookie` is treated
    /// as per-client private data and is NEVER stored: the cache key is
    /// only `(method, host, path)`, so caching such a response would
    /// serve one client's authenticated body to every other client
    /// (cross-client private-data disclosure). This guards against the
    /// common origin misconfig of returning a personalised 200 WITHOUT
    /// `Cache-Control: private`. See `is_cacheable_response`.
    #[allow(clippy::too_many_arguments)]
    pub fn store(
        &self,
        method: &Method,
        host: &str,
        path: &str,
        status: StatusCode,
        headers: &HeaderMap,
        request_headers: &HeaderMap,
        body: &Bytes,
        now: Instant,
    ) {
        if !self.enabled {
            return;
        }
        if !self.host_eligible(host) {
            return;
        }
        if method_byte(method) == 0 {
            return;
        }
        // Per-host settings (Phase 3Y.3) — TTL fallback / body-size
        // cap can differ per host. Defaults to the global config when
        // host has no override.
        let (host_ttl, host_max_body, _enabled) = self.settings_for(host);
        // V233 — pass the REQUEST headers so the cacheability decision
        // can refuse to store responses to credentialed requests.
        if !is_cacheable_response(status, headers, request_headers, body.len(), host_max_body) {
            self.stats
                .skipped_uncacheable
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        // TTL precedence (highest first):
        //   1. Upstream `Cache-Control: max-age` / `s-maxage`
        //   2. Per-status-code override (Phase 3Y.6)
        //   3. Per-host default (Phase 3Y.3)
        //   4. Global default
        let ttl = extract_max_age(headers)
            .or_else(|| self.status_ttl.get(&status.as_u16()).copied())
            .unwrap_or(host_ttl);
        // Phase 3Y.5b — auto-generate weak ETag when upstream didn't
        // provide one. Without this, only origins explicitly returning
        // ETag could benefit from 304 conditional GETs. With it, every
        // cacheable response gets a stable validator computed from the
        // body bytes — browsers / CDNs revalidating get bandwidth-free
        // 304s even for ETag-less origins (which is most of them).
        //
        // Weak (`W/`) prefix per RFC 9110 §8.8.1: we don't guarantee
        // byte-identical responses (e.g. origin may re-render with
        // different timestamps), only semantic equivalence at the
        // cached snapshot.
        let mut entry_headers = headers.clone();
        if !entry_headers.contains_key("etag") {
            let digest = auto_etag(body);
            if let Ok(val) = HeaderValue::from_str(&digest) {
                entry_headers.insert("etag", val);
            }
        }
        let entry = CachedResponse {
            status,
            headers: Arc::new(entry_headers),
            body: body.clone(),
            expires_at: now + ttl,
            stored_at: now,
            ttl,
        };
        let key = CacheKey::new(method, host, path);
        let shard = self.shard_for(&key);
        shard.write().unwrap().push(key, entry);
        self.stats.stores.fetch_add(1, Ordering::Relaxed);
    }

    /// Cheap gate used by the proxy hot-path to decide whether to even
    /// *buffer* the upstream response body. Buffering for caching is
    /// only worthwhile when (a) the cache is enabled, (b) the host is
    /// in the allow-list (or list empty), and (c) the request method
    /// is one we'd ever cache. Returns false for everything else —
    /// preserves the existing streaming path for non-cache deployments.
    pub fn should_consider(&self, method: &Method, host: &str) -> bool {
        self.enabled && method_byte(method) != 0 && self.host_eligible(host)
    }

    /// Conditional lookup that honours RFC 9111 §4.3 cache validators.
    /// When a cached entry exists AND the client sent an
    /// `If-None-Match` matching the entry's ETag (or an
    /// `If-Modified-Since` >= the entry's `Last-Modified`), return
    /// `NotModified` so the caller can serve a `304` without body.
    /// Otherwise behaves like `lookup`.
    ///
    /// Threat-aware policy still applies: high-threat IPs get `Miss`
    /// regardless of validators. We don't want a high-threat client
    /// to confirm cache contents via 304 fishing.
    pub fn lookup_conditional(
        &self,
        method: &Method,
        host: &str,
        path: &str,
        is_high_threat: bool,
        req_headers: &HeaderMap,
        now: Instant,
    ) -> CacheLookup {
        let cached = match self.lookup(method, host, path, is_high_threat, now) {
            Some(c) => c,
            None => return CacheLookup::Miss,
        };
        // Check `If-None-Match` first — strong validator, takes
        // precedence over `If-Modified-Since` per RFC 9111.
        if let Some(inm) = req_headers.get("if-none-match")
            && let Some(cached_etag) = cached.headers.get("etag")
            && etag_matches(inm, cached_etag)
        {
            self.stats.not_modified.fetch_add(1, Ordering::Relaxed);
            return CacheLookup::NotModified {
                etag: Some(cached_etag.clone()),
                last_modified: cached.headers.get("last-modified").cloned(),
            };
        }
        // Fallback: `If-Modified-Since` against cached `Last-Modified`.
        // Compare as raw HTTP-date strings — anything that matches
        // exactly is safe (cache returned same Last-Modified). For
        // proper >= comparison we'd need an HTTP-date parser; skipped
        // for MVP since exact-match catches the common browser case
        // (browser sends back what we gave it).
        if req_headers.get("if-none-match").is_none()
            && let Some(ims) = req_headers.get("if-modified-since")
            && let Some(cached_lm) = cached.headers.get("last-modified")
            && ims.as_bytes() == cached_lm.as_bytes()
        {
            self.stats.not_modified.fetch_add(1, Ordering::Relaxed);
            return CacheLookup::NotModified {
                etag: None,
                last_modified: Some(cached_lm.clone()),
            };
        }
        CacheLookup::Hit(cached)
    }

    fn host_eligible(&self, host: &str) -> bool {
        // Per-host explicit disable (Phase 3Y.3) overrides the
        // allow-list — even if the host is otherwise eligible, an
        // operator can pin `enabled = false` to skip it.
        if let Some(s) = self.per_host.get(&host.to_ascii_lowercase())
            && s.enabled == Some(false)
        {
            return false;
        }
        match &self.allow_hosts {
            None => true,
            Some(list) => list.iter().any(|h| h.eq_ignore_ascii_case(host)),
        }
    }
}

/// Per RFC 9111 §3 the default cacheable statuses are 200, 203, 204,
/// 206, 300, 301, 308, 404, 405, 410, 414, 501. We narrow to the ones
/// edge proxies actually benefit from caching.
fn cacheable_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 200 | 203 | 204 | 301 | 308 | 404 | 410)
}

/// V233 — true when the REQUEST carried client credentials, i.e. an
/// `Authorization` header or any `Cookie` header. A response to such a
/// request is per-client private data: the cache key is only
/// `(method, host, path)` with no credential component, so storing it
/// would let one client's authenticated body be served to every other
/// client. Used by `is_cacheable_response` to refuse caching outright.
///
/// This is intentionally header-presence only — we don't try to parse
/// or weigh the credential. Any `Authorization`/`Cookie` on the request
/// means "do not cache", which is the safe default. The opposite
/// direction (response `Set-Cookie`) is handled separately below.
fn request_had_credentials(request_headers: &HeaderMap) -> bool {
    request_headers.contains_key(AUTHORIZATION) || request_headers.contains_key(COOKIE)
}

fn is_cacheable_response(
    status: StatusCode,
    headers: &HeaderMap,
    request_headers: &HeaderMap,
    body_len: usize,
    max_body_bytes: usize,
) -> bool {
    if !cacheable_status(status) {
        return false;
    }
    if body_len > max_body_bytes {
        return false;
    }
    // V233 — never cache a response to a credentialed request. The cache
    // key has no credential dimension, so a personalised body (e.g. a
    // logged-in `GET /account` 200) would otherwise be stored under the
    // bare `(GET, host, /account)` key and leaked to other clients. This
    // catches the common origin misconfig of omitting
    // `Cache-Control: private` on authenticated responses — we no longer
    // depend on the origin getting that header right.
    if request_had_credentials(request_headers) {
        return false;
    }
    if headers.contains_key("set-cookie") {
        // Caching a Set-Cookie would cross-pollinate auth state across
        // users — never safe even when the response otherwise qualifies.
        return false;
    }
    if let Some(cc) = headers.get("cache-control")
        && let Ok(cc_str) = cc.to_str()
    {
        let lower = cc_str.to_ascii_lowercase();
        if lower.contains("no-store") || lower.contains("private") {
            return false;
        }
        // `no-cache` requires revalidation per request — we honour it
        // by simply not storing (the response is still served fine).
        if lower.contains("no-cache") {
            return false;
        }
    }
    // Phase 3Y.4 — Vary header awareness.
    //
    // The Vary header means "this response is keyed by these request
    // headers". Without storing per-variant entries (e.g. one for
    // gzip clients + one for identity), serving a cached response to
    // a client whose Vary-fields don't match could return the wrong
    // body — e.g. gzipped bytes to a client that asked for identity.
    //
    // MVP correctness-first approach: don't cache responses with a
    // non-trivial Vary. Special-case `Vary: Accept-Encoding` (the
    // most common one, ~all CDN traffic) is allowed when the value
    // is exactly that — it's safe to serve to clients with the same
    // Accept-Encoding canonicalisation we already do upstream.
    //
    // Future (3Y.4.1) would store per-variant entries keyed on the
    // hashed Vary-field values; correct but more complex.
    if let Some(vary) = headers.get("vary")
        && let Ok(vary_str) = vary.to_str()
    {
        let trimmed = vary_str.trim();
        // `Vary: *` blocks all caching per RFC 9111 §4.1.
        if trimmed == "*" {
            return false;
        }
        // Anything other than the exact `Accept-Encoding` case is
        // unsafe to serve without per-variant storage.
        let only_accept_encoding = trimmed
            .split(',')
            .map(|s| s.trim())
            .all(|f| f.eq_ignore_ascii_case("accept-encoding"));
        if !only_accept_encoding {
            return false;
        }
        // Even for Accept-Encoding, we currently don't differentiate
        // variants — serving identity to a gzip-only client is fine
        // (just no compression) but the reverse (gzip to identity) is
        // broken. Conservative: skip until 3Y.4.1 lands per-variant.
        return false;
    }
    true
}

/// Parse `Cache-Control: max-age=NN` (or `s-maxage` which takes
/// precedence for shared caches). Returns None if no max-age directive
/// — caller falls back to the configured default TTL.
fn extract_max_age(headers: &HeaderMap) -> Option<Duration> {
    let cc = headers.get("cache-control")?.to_str().ok()?;
    let lower = cc.to_ascii_lowercase();
    let key = if lower.contains("s-maxage=") {
        "s-maxage="
    } else if lower.contains("max-age=") {
        "max-age="
    } else {
        return None;
    };
    let idx = lower.find(key)? + key.len();
    let tail = &lower[idx..];
    let end = tail
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(tail.len());
    let secs: u64 = tail[..end].parse().ok()?;
    Some(Duration::from_secs(secs))
}

/// Helper used by the proxy to map a cached entry into the response
/// shape callers expect. Kept on the cache module so the cache owns
/// its own serialisation invariants (e.g. stamping an X-Aegis-Cache
/// hit-marker header so observability dashboards can compute hit
/// ratio from access logs without reading our metrics endpoint).
pub fn stamp_cache_hit_header(headers: &mut HeaderMap) {
    headers.insert("x-aegis-cache", HeaderValue::from_static("hit"));
}

/// Phase 3Y.5b — generate a weak ETag from body bytes. SHA-256 is
/// already a dep (used in JA4 fingerprints), so no new deps. Truncate
/// to 12 hex chars — keeps the header short while still providing
/// 48 bits of collision resistance (plenty for cache-validation
/// purposes; we don't need cryptographic-strength uniqueness here).
fn auto_etag(body: &Bytes) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(body);
    let bytes = h.finalize();
    let mut hex = String::with_capacity(20);
    hex.push_str("W/\"");
    for b in &bytes[..6] {
        hex.push_str(&format!("{:02x}", b));
    }
    hex.push('"');
    hex
}

/// RFC 9110 §13.1.2 — `If-None-Match` matches when ANY of the
/// comma-separated client ETags equals the cached ETag (weak
/// validators compared by their opaque tag, prefix `W/` stripped).
/// Also handles the wildcard `*` which matches any current entry.
fn etag_matches(if_none_match: &HeaderValue, cached_etag: &HeaderValue) -> bool {
    let inm = match if_none_match.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cached = match cached_etag.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cached_opaque = strip_etag(cached);
    for candidate in inm.split(',') {
        let c = candidate.trim();
        if c == "*" {
            return true;
        }
        if strip_etag(c) == cached_opaque {
            return true;
        }
    }
    false
}

/// Normalise an ETag value for comparison: drop the `W/` weak prefix
/// (if any) and surrounding quotes. Both `W/"abc"` and `"abc"`
/// compare equal — matches what browsers send back.
fn strip_etag(raw: &str) -> &str {
    let s = raw.strip_prefix("W/").unwrap_or(raw);
    s.trim_matches('"')
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn cfg(enabled: bool) -> ResponseCacheConfig {
        ResponseCacheConfig {
            enabled,
            max_entries: 1024,
            default_ttl_secs: 60,
            max_body_bytes: 1024 * 1024,
            status_ttl_secs: std::collections::HashMap::new(),
            stale_if_error_secs: 0,
            hosts: vec![],
            per_host: vec![],
        }
    }

    fn hdr(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn disabled_never_hits() {
        let c = ResponseCache::new(&cfg(false));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    #[test]
    fn high_threat_forces_miss() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", true, now).is_none());
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_some());
    }

    #[test]
    fn tier_low_serves_full_ttl() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        // Right at store time — Low admits.
        assert!(
            c.lookup_tiered(&Method::GET, "x", "/", ThreatTier::Low, now)
                .is_some()
        );
        // Most of the way through TTL — Low still admits.
        let later = now + Duration::from_secs(50);
        assert!(
            c.lookup_tiered(&Method::GET, "x", "/", ThreatTier::Low, later)
                .is_some()
        );
        let s = c.stats();
        assert!(s.served_low >= 2);
    }

    #[test]
    fn tier_medium_requires_first_half_life() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        // Within first half of 60s TTL — Medium admits.
        let t_mid = now + Duration::from_secs(20);
        assert!(
            c.lookup_tiered(&Method::GET, "x", "/", ThreatTier::Medium, t_mid)
                .is_some()
        );
        // Past first half — Medium rejects but Low still accepts.
        let t_old = now + Duration::from_secs(45);
        assert!(
            c.lookup_tiered(&Method::GET, "x", "/", ThreatTier::Medium, t_old)
                .is_none()
        );
        assert!(
            c.lookup_tiered(&Method::GET, "x", "/", ThreatTier::Low, t_old)
                .is_some()
        );
        let s = c.stats();
        assert!(s.served_medium >= 1);
        assert!(s.served_low >= 1);
    }

    #[test]
    fn tier_high_forces_miss_and_increments_counters() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(
            c.lookup_tiered(&Method::GET, "x", "/", ThreatTier::High, now)
                .is_none()
        );
        let s = c.stats();
        assert_eq!(s.forced_miss_high, 1);
        // Legacy `skipped_high_threat` counter also bumps so dashboards
        // don't lose visibility.
        assert!(s.skipped_high_threat >= 1);
    }

    #[test]
    fn threat_tier_from_score_thresholds() {
        assert_eq!(ThreatTier::from_score(0.0), ThreatTier::Low);
        assert_eq!(ThreatTier::from_score(33.0), ThreatTier::Low);
        assert_eq!(ThreatTier::from_score(33.5), ThreatTier::Medium);
        assert_eq!(ThreatTier::from_score(66.0), ThreatTier::Medium);
        assert_eq!(ThreatTier::from_score(66.1), ThreatTier::High);
        assert_eq!(ThreatTier::from_score(100.0), ThreatTier::High);
    }

    #[test]
    fn host_allow_list_filters() {
        let mut cfg = cfg(true);
        cfg.hosts = vec!["allowed.example".to_string()];
        let c = ResponseCache::new(&cfg);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "denied.example",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        c.store(
            &Method::GET,
            "allowed.example",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(
            c.lookup(&Method::GET, "denied.example", "/", false, now)
                .is_none()
        );
        assert!(
            c.lookup(&Method::GET, "allowed.example", "/", false, now)
                .is_some()
        );
    }

    #[test]
    fn set_cookie_never_cached() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("set-cookie", "session=abc")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    // V233 — a response to a request that carried `Cookie` is per-client
    // private data and must NEVER be cached: the cache key is only
    // `(method, host, path)`, so a cached personalised body would be
    // served to other clients. Note the response below has NO
    // `Cache-Control: private` — that is exactly the origin misconfig
    // this guard defends against; the request `Cookie` alone blocks it.
    #[test]
    fn request_with_cookie_not_cached() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/account",
            StatusCode::OK,
            &HeaderMap::new(), // response headers — no `private`
            &hdr(&[("cookie", "session=loggedin")]), // request headers
            &Bytes::from_static(b"hello user-42"),
            now,
        );
        assert!(
            c.lookup(&Method::GET, "x", "/account", false, now)
                .is_none(),
            "response to a cookie-bearing request must not be cached"
        );
    }

    // V233 — same guard for the `Authorization` request header (Bearer
    // tokens, Basic auth, etc.). Without this, an authenticated API
    // response would be stored under the bare key and leaked.
    #[test]
    fn request_with_authorization_not_cached() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/api/me",
            StatusCode::OK,
            &HeaderMap::new(),
            &hdr(&[("authorization", "Bearer secret-token")]),
            &Bytes::from_static(b"private profile"),
            now,
        );
        assert!(
            c.lookup(&Method::GET, "x", "/api/me", false, now).is_none(),
            "response to an Authorization-bearing request must not be cached"
        );
    }

    // V233 — direct check on `is_cacheable_response`: credentialed
    // requests are reported non-cacheable, non-credentialed ones remain
    // cacheable (so the guard doesn't over-block ordinary traffic).
    #[test]
    fn is_cacheable_response_rejects_credentialed_requests() {
        let resp = HeaderMap::new();
        // Cookie on the request → not cacheable.
        assert!(!is_cacheable_response(
            StatusCode::OK,
            &resp,
            &hdr(&[("cookie", "a=b")]),
            2,
            1024,
        ));
        // Authorization on the request → not cacheable.
        assert!(!is_cacheable_response(
            StatusCode::OK,
            &resp,
            &hdr(&[("authorization", "Bearer t")]),
            2,
            1024,
        ));
        // No credentials → still cacheable (positive control).
        assert!(is_cacheable_response(
            StatusCode::OK,
            &resp,
            &HeaderMap::new(),
            2,
            1024,
        ));
    }

    #[test]
    fn cache_control_private_skipped() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("cache-control", "private, max-age=60")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    #[test]
    fn cache_control_no_store_skipped() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("cache-control", "no-store")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    #[test]
    fn post_never_cached() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::POST,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::POST, "x", "/", false, now).is_none());
    }

    #[test]
    fn max_age_honoured() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("cache-control", "max-age=2")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_some());
        let later = now + Duration::from_secs(5);
        assert!(c.lookup(&Method::GET, "x", "/", false, later).is_none());
    }

    #[test]
    fn s_maxage_takes_precedence() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("cache-control", "max-age=10000, s-maxage=2")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        // s-maxage (shared cache) wins → expires after 2s
        let later = now + Duration::from_secs(5);
        assert!(c.lookup(&Method::GET, "x", "/", false, later).is_none());
    }

    #[test]
    fn non_cacheable_status_skipped() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::SERVICE_UNAVAILABLE,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"down"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    #[test]
    fn body_size_limit_enforced() {
        let mut cfg = cfg(true);
        cfg.max_body_bytes = 10;
        let c = ResponseCache::new(&cfg);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"this body is longer than ten bytes"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    #[test]
    fn etag_matches_strong_quoted() {
        let cached = HeaderValue::from_static("\"abc123\"");
        assert!(etag_matches(
            &HeaderValue::from_static("\"abc123\""),
            &cached
        ));
        assert!(!etag_matches(&HeaderValue::from_static("\"def\""), &cached));
    }

    #[test]
    fn etag_matches_weak_validator() {
        let cached = HeaderValue::from_static("\"abc\"");
        // Browser sends back the weak form when origin used weak.
        assert!(etag_matches(
            &HeaderValue::from_static("W/\"abc\""),
            &cached
        ));
        let weak_cached = HeaderValue::from_static("W/\"x\"");
        assert!(etag_matches(
            &HeaderValue::from_static("W/\"x\""),
            &weak_cached
        ));
        assert!(etag_matches(
            &HeaderValue::from_static("\"x\""),
            &weak_cached
        ));
    }

    #[test]
    fn etag_matches_wildcard() {
        let cached = HeaderValue::from_static("\"any\"");
        assert!(etag_matches(&HeaderValue::from_static("*"), &cached));
    }

    #[test]
    fn etag_matches_comma_list() {
        let cached = HeaderValue::from_static("\"b\"");
        assert!(etag_matches(
            &HeaderValue::from_static("\"a\", \"b\", \"c\""),
            &cached
        ));
        assert!(!etag_matches(
            &HeaderValue::from_static("\"a\", \"c\""),
            &cached
        ));
    }

    #[test]
    fn lookup_conditional_returns_not_modified_on_etag_match() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("etag", "\"v1\""), ("content-type", "text/plain")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"hello"),
            now,
        );
        let mut req = HeaderMap::new();
        req.insert("if-none-match", HeaderValue::from_static("\"v1\""));
        match c.lookup_conditional(&Method::GET, "x", "/", false, &req, now) {
            CacheLookup::NotModified { etag, .. } => {
                assert_eq!(etag.unwrap().as_bytes(), b"\"v1\"");
            }
            other => panic!("expected NotModified, got {other:?}"),
        }
    }

    #[test]
    fn lookup_conditional_falls_through_when_etag_mismatch() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("etag", "\"v2\"")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"hello"),
            now,
        );
        let mut req = HeaderMap::new();
        req.insert("if-none-match", HeaderValue::from_static("\"v1\""));
        match c.lookup_conditional(&Method::GET, "x", "/", false, &req, now) {
            CacheLookup::Hit(_) => {}
            other => panic!("expected Hit (etag mismatch), got {other:?}"),
        }
    }

    #[test]
    fn lookup_conditional_if_modified_since_match() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("last-modified", "Wed, 21 Oct 2020 07:28:00 GMT")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"hello"),
            now,
        );
        let mut req = HeaderMap::new();
        req.insert(
            "if-modified-since",
            HeaderValue::from_static("Wed, 21 Oct 2020 07:28:00 GMT"),
        );
        match c.lookup_conditional(&Method::GET, "x", "/", false, &req, now) {
            CacheLookup::NotModified { last_modified, .. } => {
                assert!(last_modified.is_some());
            }
            other => panic!("expected NotModified, got {other:?}"),
        }
    }

    #[test]
    fn lookup_conditional_high_threat_still_miss() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("etag", "\"v1\"")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"hello"),
            now,
        );
        let mut req = HeaderMap::new();
        req.insert("if-none-match", HeaderValue::from_static("\"v1\""));
        // High-threat → Miss, no 304 leak.
        match c.lookup_conditional(&Method::GET, "x", "/", true, &req, now) {
            CacheLookup::Miss => {}
            other => panic!("expected Miss for high-threat, got {other:?}"),
        }
    }

    #[test]
    fn stale_if_error_serves_recently_expired() {
        let mut config = cfg(true);
        config.default_ttl_secs = 5;
        config.stale_if_error_secs = 60;
        let c = ResponseCache::new(&config);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"backup"),
            now,
        );
        // Past TTL but within stale window → stale-if-error returns it
        let later = now + Duration::from_secs(30);
        let stale = c.lookup_stale_if_error(&Method::GET, "x", "/", false, later);
        assert!(stale.is_some());
        assert_eq!(stale.unwrap().body.as_ref(), b"backup");
        // Beyond stale window → None
        let way_later = now + Duration::from_secs(120);
        assert!(
            c.lookup_stale_if_error(&Method::GET, "x", "/", false, way_later)
                .is_none()
        );
    }

    #[test]
    fn stale_if_error_disabled_returns_none() {
        let c = ResponseCache::new(&cfg(true)); // stale_if_error_secs = 0
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        let later = now + Duration::from_secs(120);
        assert!(
            c.lookup_stale_if_error(&Method::GET, "x", "/", false, later)
                .is_none()
        );
    }

    #[test]
    fn stale_if_error_blocks_high_threat() {
        let mut config = cfg(true);
        config.stale_if_error_secs = 60;
        let c = ResponseCache::new(&config);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        let later = now + Duration::from_secs(120);
        assert!(
            c.lookup_stale_if_error(&Method::GET, "x", "/", true, later)
                .is_none()
        );
    }

    #[test]
    fn per_status_ttl_applied_for_404() {
        let mut config = cfg(true);
        config.default_ttl_secs = 600;
        config.status_ttl_secs.insert(404, 5);
        let c = ResponseCache::new(&config);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/missing",
            StatusCode::NOT_FOUND,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"not found"),
            now,
        );
        // Within 5s TTL → still cached
        assert!(
            c.lookup(
                &Method::GET,
                "x",
                "/missing",
                false,
                now + Duration::from_secs(3)
            )
            .is_some()
        );
        // After 5s → expired
        assert!(
            c.lookup(
                &Method::GET,
                "x",
                "/missing",
                false,
                now + Duration::from_secs(10)
            )
            .is_none()
        );
    }

    #[test]
    fn per_status_ttl_does_not_override_max_age() {
        // RFC 9111: upstream's Cache-Control wins.
        let mut config = cfg(true);
        config.status_ttl_secs.insert(200, 5);
        let c = ResponseCache::new(&config);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("cache-control", "max-age=3600")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        // Upstream says 3600s — should survive past status-ttl 5s.
        assert!(
            c.lookup(
                &Method::GET,
                "x",
                "/",
                false,
                now + Duration::from_secs(100)
            )
            .is_some()
        );
    }

    #[test]
    fn auto_etag_generated_when_upstream_missing() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"hello world"),
            now,
        );
        let cached = c.lookup(&Method::GET, "x", "/", false, now).unwrap();
        let etag = cached.headers.get("etag").expect("auto-etag inserted");
        let s = etag.to_str().unwrap();
        // Weak prefix, quoted, 12 hex chars
        assert!(s.starts_with("W/\""));
        assert!(s.ends_with('"'));
        assert_eq!(s.len(), 16); // W/"xxxxxxxxxxxx"
    }

    #[test]
    fn upstream_etag_preserved_over_auto() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("etag", "\"upstream-v1\"")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"hello"),
            now,
        );
        let cached = c.lookup(&Method::GET, "x", "/", false, now).unwrap();
        let etag = cached.headers.get("etag").unwrap();
        assert_eq!(etag.as_bytes(), b"\"upstream-v1\"");
    }

    #[test]
    fn auto_etag_stable_for_same_body() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"identical"),
            now,
        );
        c.store(
            &Method::GET,
            "y",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"identical"),
            now,
        );
        let e1 = c.lookup(&Method::GET, "x", "/", false, now).unwrap();
        let e2 = c.lookup(&Method::GET, "y", "/", false, now).unwrap();
        assert_eq!(
            e1.headers.get("etag"),
            e2.headers.get("etag"),
            "same body → same auto-etag"
        );
    }

    #[test]
    fn auto_etag_enables_304_for_etag_less_origin() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        // Origin doesn't return ETag.
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"hello"),
            now,
        );
        // First lookup: full hit. Capture the auto-generated ETag.
        let cached = c.lookup(&Method::GET, "x", "/", false, now).unwrap();
        let auto_etag = cached.headers.get("etag").unwrap().clone();
        // Second request from a browser revalidating with that ETag.
        let mut req = HeaderMap::new();
        req.insert("if-none-match", auto_etag);
        match c.lookup_conditional(&Method::GET, "x", "/", false, &req, now) {
            CacheLookup::NotModified { etag: Some(_), .. } => {}
            other => panic!("expected NotModified via auto-etag, got {other:?}"),
        }
    }

    #[test]
    fn vary_header_blocks_caching() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("vary", "Accept-Language")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    #[test]
    fn vary_star_blocks_caching() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("vary", "*")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    #[test]
    fn vary_accept_encoding_currently_skipped_conservatively() {
        // MVP correctness — even Accept-Encoding-only Vary is skipped
        // until per-variant storage lands. Documents the conservative
        // behaviour as a test so 3Y.4.1 implementation has a clear
        // anchor for what to change.
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &hdr(&[("vary", "Accept-Encoding")]),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_none());
    }

    #[test]
    fn no_vary_still_cached() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert!(c.lookup(&Method::GET, "x", "/", false, now).is_some());
    }

    #[test]
    fn per_host_ttl_override_applied() {
        let mut config = cfg(true);
        config.default_ttl_secs = 100;
        config.per_host = vec![crate::config::PerHostCache {
            host: "shorty.example".to_string(),
            ttl_secs: Some(2),
            max_body_bytes: None,
            enabled: None,
        }];
        let c = ResponseCache::new(&config);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "shorty.example",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"x"),
            now,
        );
        assert!(
            c.lookup(&Method::GET, "shorty.example", "/", false, now)
                .is_some()
        );
        let later = now + Duration::from_secs(5);
        assert!(
            c.lookup(&Method::GET, "shorty.example", "/", false, later)
                .is_none(),
            "per-host TTL of 2s should have expired by t+5s"
        );
    }

    #[test]
    fn per_host_disabled_skips_cache() {
        let mut config = cfg(true);
        config.per_host = vec![crate::config::PerHostCache {
            host: "nocache.example".to_string(),
            ttl_secs: None,
            max_body_bytes: None,
            enabled: Some(false),
        }];
        let c = ResponseCache::new(&config);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "nocache.example",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"x"),
            now,
        );
        // store no-op'd because host's enabled=false. lookup misses.
        assert!(
            c.lookup(&Method::GET, "nocache.example", "/", false, now)
                .is_none()
        );
    }

    #[test]
    fn per_host_body_cap_enforced() {
        let mut config = cfg(true);
        config.max_body_bytes = 10_000;
        config.per_host = vec![crate::config::PerHostCache {
            host: "tiny.example".to_string(),
            ttl_secs: None,
            max_body_bytes: Some(5),
            enabled: None,
        }];
        let c = ResponseCache::new(&config);
        let now = Instant::now();
        c.store(
            &Method::GET,
            "tiny.example",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"longer than five"),
            now,
        );
        // Body 16 > host cap 5 → no store
        assert!(
            c.lookup(&Method::GET, "tiny.example", "/", false, now)
                .is_none()
        );
        // Body within cap → stored
        c.store(
            &Method::GET,
            "tiny.example",
            "/x",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"hi"),
            now,
        );
        assert!(
            c.lookup(&Method::GET, "tiny.example", "/x", false, now)
                .is_some()
        );
    }

    #[test]
    fn purge_all_clears_cache() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        for path in ["/", "/a", "/b"] {
            c.store(
                &Method::GET,
                "x",
                path,
                StatusCode::OK,
                &HeaderMap::new(),
                &HeaderMap::new(),
                &Bytes::from_static(b"ok"),
                now,
            );
        }
        assert_eq!(c.purge_all(), 3);
        assert!(c.lookup(&Method::GET, "x", "/a", false, now).is_none());
    }

    #[test]
    fn purge_host_only_removes_that_host() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "keep.example",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"keep"),
            now,
        );
        c.store(
            &Method::GET,
            "drop.example",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"drop"),
            now,
        );
        c.store(
            &Method::GET,
            "drop.example",
            "/a",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"drop"),
            now,
        );
        assert_eq!(c.purge_host("drop.example"), 2);
        assert!(
            c.lookup(&Method::GET, "keep.example", "/", false, now)
                .is_some()
        );
        assert!(
            c.lookup(&Method::GET, "drop.example", "/", false, now)
                .is_none()
        );
    }

    #[test]
    fn purge_path_prefix_removes_matching() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        for path in ["/api/v1/x", "/api/v1/y", "/api/v2/x", "/other"] {
            c.store(
                &Method::GET,
                "h",
                path,
                StatusCode::OK,
                &HeaderMap::new(),
                &HeaderMap::new(),
                &Bytes::from_static(b"ok"),
                now,
            );
        }
        assert_eq!(c.purge_path_prefix("/api/v1/"), 2);
        assert!(
            c.lookup(&Method::GET, "h", "/api/v1/x", false, now)
                .is_none()
        );
        assert!(
            c.lookup(&Method::GET, "h", "/api/v2/x", false, now)
                .is_some()
        );
        assert!(c.lookup(&Method::GET, "h", "/other", false, now).is_some());
    }

    #[test]
    fn purge_exact_removes_single() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        c.store(
            &Method::GET,
            "h",
            "/a",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        c.store(
            &Method::GET,
            "h",
            "/b",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        assert_eq!(c.purge_exact(&Method::GET, "h", "/a"), 1);
        assert!(c.lookup(&Method::GET, "h", "/a", false, now).is_none());
        assert!(c.lookup(&Method::GET, "h", "/b", false, now).is_some());
    }

    #[test]
    fn stats_tracked() {
        let c = ResponseCache::new(&cfg(true));
        let now = Instant::now();
        // miss
        let _ = c.lookup(&Method::GET, "x", "/", false, now);
        // store
        c.store(
            &Method::GET,
            "x",
            "/",
            StatusCode::OK,
            &HeaderMap::new(),
            &HeaderMap::new(),
            &Bytes::from_static(b"ok"),
            now,
        );
        // hit
        let _ = c.lookup(&Method::GET, "x", "/", false, now);
        // high-threat skip
        let _ = c.lookup(&Method::GET, "x", "/", true, now);
        let s = c.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 1);
        assert_eq!(s.stores, 1);
        assert_eq!(s.skipped_high_threat, 1);
    }
}
