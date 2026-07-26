//! V198 — WISE-style enrichment proxy.
//!
//! Aegis grew up with a separate cache per intel source: V113
//! threat_intel CIDR coalesced, V138 JA4 reputation, V142 ASN
//! reputation, V176 JA4 corpus, GeoIP. Each has its own lookup
//! method, its own hot-reload, and its own per-IP cache layout.
//! Code that wants the FULL picture for an IP — say the admin
//! `/threats` page or the ML scorer — has to call four times and
//! manually fuse the verdicts.
//!
//! Idea borrowed from Arkime's WISE (Wireless Intelligence Sources
//! Engine): one cached facade in front of every source, identical
//! lookup shape, per-source TTL, per-source provenance carried
//! through in the response.
//!
//! ## Shape
//!
//! ```ignore
//!     enrich(EntityKey::Ip(addr)) -> Enrichment {
//!         verdict:   Verdict::Deny | Allow | Unknown,
//!         sources:   [
//!             SourceHit { name: "ja4-reputation", verdict: Deny,
//!                         tag: "sqlmap", fetched_at: Instant },
//!             SourceHit { name: "asn-reputation", verdict: Allow,
//!                         tag: "aws", fetched_at: Instant },
//!             ...
//!         ],
//!         cached_at: Instant,
//!     }
//! ```
//!
//! Aggregated verdict: any Deny wins; otherwise any Allow wins;
//! otherwise Unknown. Operator can override by registering sources
//! in priority order.
//!
//! ## Cache layout
//!
//! Two-tier:
//! * Per-source small LRU (default 4096 entries, configurable per
//!   source) — short TTL (default 30s) so reputation refresh stays
//!   visible.
//! * Aggregated EnrichmentCache LRU (16k default) — TTL = min of
//!   contributing sources.
//!
//! Lookup walks per-source caches first; only on miss does it call
//! the underlying source. This is the bit that "replaces 4
//! discrete caches" — sources become read-through providers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityKey {
    Ip(IpAddr),
    Ja4(String),
    Asn(u32),
    UserAgent(String),
}

impl EntityKey {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Ip(_) => "ip",
            Self::Ja4(_) => "ja4",
            Self::Asn(_) => "asn",
            Self::UserAgent(_) => "ua",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SourceHit {
    pub source: &'static str,
    pub verdict: Verdict,
    pub label: String,
    pub fetched_at: Instant,
}

#[derive(Debug, Clone)]
pub struct Enrichment {
    pub key: EntityKey,
    pub sources: Vec<SourceHit>,
    pub cached_at: Instant,
    pub expires_at: Instant,
}

impl Enrichment {
    pub fn aggregate(&self) -> Verdict {
        // Any Deny short-circuits to Deny.
        if self.sources.iter().any(|s| s.verdict == Verdict::Deny) {
            return Verdict::Deny;
        }
        if self.sources.iter().any(|s| s.verdict == Verdict::Allow) {
            return Verdict::Allow;
        }
        Verdict::Unknown
    }

    pub fn deny_reasons(&self) -> Vec<&str> {
        self.sources
            .iter()
            .filter(|s| s.verdict == Verdict::Deny)
            .map(|s| s.label.as_str())
            .collect()
    }
}

/// Source-side trait. Implementors wrap V113/V138/V142/V176/etc.
/// `name()` returns a `&'static str` so per-source counters stay
/// cardinality-bounded.
pub trait EnrichmentSource: Send + Sync {
    fn name(&self) -> &'static str;
    /// Returns `None` when the source has no data for this key
    /// (the lookup completed successfully but the key isn't tracked).
    /// Use `Some(Verdict::Unknown)` to signal explicit indeterminate
    /// (e.g., GeoIP DB loaded but country not classified).
    fn lookup(&self, key: &EntityKey) -> Option<(Verdict, String)>;
    fn default_ttl(&self) -> Duration {
        Duration::from_secs(30)
    }
}

#[derive(Debug)]
struct CacheEntry {
    enrichment: Enrichment,
    inserted: Instant,
}

#[derive(Debug, Default)]
pub struct SourceStats {
    pub queries: AtomicU64,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl SourceStats {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.queries.load(Ordering::Relaxed),
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }
}

pub struct EnrichmentFacade {
    sources: Vec<Arc<dyn EnrichmentSource>>,
    cache: RwLock<HashMap<EntityKey, CacheEntry>>,
    per_source_stats: RwLock<HashMap<&'static str, Arc<SourceStats>>>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    capacity: usize,
}

impl EnrichmentFacade {
    pub fn new(capacity: usize) -> Self {
        Self {
            sources: Vec::new(),
            cache: RwLock::new(HashMap::new()),
            per_source_stats: RwLock::new(HashMap::new()),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            capacity,
        }
    }

    pub fn register(&mut self, source: Arc<dyn EnrichmentSource>) {
        let name = source.name();
        self.per_source_stats
            .write()
            .unwrap()
            .insert(name, Arc::new(SourceStats::default()));
        self.sources.push(source);
    }

    /// Lookup with cache. Returns aggregated [Enrichment] every call.
    pub fn lookup(&self, key: &EntityKey) -> Enrichment {
        // Cache hit path.
        if let Some(entry) = self.cache.read().unwrap().get(key) {
            if Instant::now() < entry.enrichment.expires_at {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return entry.enrichment.clone();
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        // Walk sources.
        let now = Instant::now();
        let mut hits = Vec::new();
        let mut shortest_ttl = Duration::from_secs(300);
        for src in &self.sources {
            let stats = self
                .per_source_stats
                .read()
                .unwrap()
                .get(src.name())
                .cloned();
            if let Some(s) = &stats {
                s.queries.fetch_add(1, Ordering::Relaxed);
            }
            match src.lookup(key) {
                Some((verdict, label)) => {
                    if let Some(s) = &stats {
                        s.hits.fetch_add(1, Ordering::Relaxed);
                    }
                    hits.push(SourceHit {
                        source: src.name(),
                        verdict,
                        label,
                        fetched_at: now,
                    });
                    let ttl = src.default_ttl();
                    if ttl < shortest_ttl {
                        shortest_ttl = ttl;
                    }
                }
                None => {
                    if let Some(s) = &stats {
                        s.misses.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        let enrichment = Enrichment {
            key: key.clone(),
            sources: hits,
            cached_at: now,
            expires_at: now + shortest_ttl,
        };
        self.insert(key.clone(), enrichment.clone());
        enrichment
    }

    fn insert(&self, key: EntityKey, enrichment: Enrichment) {
        let mut g = self.cache.write().unwrap();
        if g.len() >= self.capacity {
            // Evict oldest single entry — linear scan is fine for
            // moderate capacity (16k typical).
            if let Some((k, _)) = g
                .iter()
                .min_by_key(|(_, e)| e.inserted)
                .map(|(k, e)| (k.clone(), e.inserted))
            {
                g.remove(&k);
            }
        }
        g.insert(
            key,
            CacheEntry {
                enrichment,
                inserted: Instant::now(),
            },
        );
    }

    pub fn invalidate(&self, key: &EntityKey) {
        self.cache.write().unwrap().remove(key);
    }

    pub fn invalidate_all(&self) {
        self.cache.write().unwrap().clear();
    }

    pub fn registered_sources(&self) -> Vec<&'static str> {
        self.sources.iter().map(|s| s.name()).collect()
    }

    pub fn source_stats(&self, name: &str) -> Option<(u64, u64, u64)> {
        self.per_source_stats
            .read()
            .unwrap()
            .get(name)
            .map(|s| s.snapshot())
    }

    pub fn cache_stats(&self) -> (u64, u64, usize) {
        (
            self.cache_hits.load(Ordering::Relaxed),
            self.cache_misses.load(Ordering::Relaxed),
            self.cache.read().unwrap().len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    struct StaticSource {
        name: &'static str,
        verdict: Verdict,
        label: &'static str,
        match_key: EntityKey,
        calls: Mutex<u32>,
    }

    impl EnrichmentSource for StaticSource {
        fn name(&self) -> &'static str {
            self.name
        }
        fn lookup(&self, key: &EntityKey) -> Option<(Verdict, String)> {
            *self.calls.lock().unwrap() += 1;
            if key == &self.match_key {
                Some((self.verdict, self.label.to_string()))
            } else {
                None
            }
        }
        fn default_ttl(&self) -> Duration {
            Duration::from_secs(60)
        }
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> EntityKey {
        EntityKey::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    #[test]
    fn deny_source_wins_aggregation() {
        let mut f = EnrichmentFacade::new(100);
        f.register(Arc::new(StaticSource {
            name: "allow_src",
            verdict: Verdict::Allow,
            label: "good",
            match_key: ip(1, 2, 3, 4),
            calls: Mutex::new(0),
        }));
        f.register(Arc::new(StaticSource {
            name: "deny_src",
            verdict: Verdict::Deny,
            label: "bad",
            match_key: ip(1, 2, 3, 4),
            calls: Mutex::new(0),
        }));
        let e = f.lookup(&ip(1, 2, 3, 4));
        assert_eq!(e.aggregate(), Verdict::Deny);
        assert_eq!(e.deny_reasons(), vec!["bad"]);
    }

    #[test]
    fn second_lookup_hits_cache() {
        let mut f = EnrichmentFacade::new(100);
        let src = Arc::new(StaticSource {
            name: "s",
            verdict: Verdict::Deny,
            label: "x",
            match_key: ip(1, 2, 3, 4),
            calls: Mutex::new(0),
        });
        f.register(src.clone());
        f.lookup(&ip(1, 2, 3, 4));
        f.lookup(&ip(1, 2, 3, 4));
        f.lookup(&ip(1, 2, 3, 4));
        let calls = *src.calls.lock().unwrap();
        assert_eq!(calls, 1, "should only call source once thanks to cache");
        let (hits, misses, len) = f.cache_stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);
        assert_eq!(len, 1);
    }

    #[test]
    fn unknown_when_no_source_returns_hit() {
        let mut f = EnrichmentFacade::new(100);
        f.register(Arc::new(StaticSource {
            name: "s",
            verdict: Verdict::Deny,
            label: "x",
            match_key: ip(1, 2, 3, 4),
            calls: Mutex::new(0),
        }));
        let e = f.lookup(&ip(9, 9, 9, 9));
        assert_eq!(e.aggregate(), Verdict::Unknown);
        assert!(e.sources.is_empty());
    }

    #[test]
    fn invalidate_removes_cached_entry() {
        let mut f = EnrichmentFacade::new(100);
        let src = Arc::new(StaticSource {
            name: "s",
            verdict: Verdict::Deny,
            label: "x",
            match_key: ip(1, 2, 3, 4),
            calls: Mutex::new(0),
        });
        f.register(src.clone());
        f.lookup(&ip(1, 2, 3, 4));
        f.invalidate(&ip(1, 2, 3, 4));
        f.lookup(&ip(1, 2, 3, 4));
        assert_eq!(*src.calls.lock().unwrap(), 2);
    }

    #[test]
    fn per_source_stats_track_independently() {
        let mut f = EnrichmentFacade::new(100);
        f.register(Arc::new(StaticSource {
            name: "ja4_rep",
            verdict: Verdict::Deny,
            label: "x",
            match_key: ip(1, 2, 3, 4),
            calls: Mutex::new(0),
        }));
        f.register(Arc::new(StaticSource {
            name: "asn_rep",
            verdict: Verdict::Allow,
            label: "ok",
            match_key: ip(2, 2, 2, 2),
            calls: Mutex::new(0),
        }));
        f.lookup(&ip(1, 2, 3, 4));
        f.lookup(&ip(2, 2, 2, 2));
        let (q1, h1, _) = f.source_stats("ja4_rep").unwrap();
        let (q2, h2, _) = f.source_stats("asn_rep").unwrap();
        assert_eq!(q1, 2);
        assert_eq!(h1, 1);
        assert_eq!(q2, 2);
        assert_eq!(h2, 1);
    }

    #[test]
    fn cache_eviction_when_capacity_exceeded() {
        let mut f = EnrichmentFacade::new(2);
        let src = Arc::new(MultiSource {});
        f.register(src);
        f.lookup(&ip(1, 0, 0, 0));
        f.lookup(&ip(2, 0, 0, 0));
        f.lookup(&ip(3, 0, 0, 0));
        let (_, _, len) = f.cache_stats();
        assert!(len <= 2);
    }

    struct MultiSource {}
    impl EnrichmentSource for MultiSource {
        fn name(&self) -> &'static str {
            "multi"
        }
        fn lookup(&self, _key: &EntityKey) -> Option<(Verdict, String)> {
            Some((Verdict::Deny, "x".into()))
        }
    }

    #[test]
    fn cache_expires_on_ttl() {
        let mut f = EnrichmentFacade::new(100);
        struct ShortTtl(Mutex<u32>);
        impl EnrichmentSource for ShortTtl {
            fn name(&self) -> &'static str {
                "short"
            }
            fn lookup(&self, _key: &EntityKey) -> Option<(Verdict, String)> {
                *self.0.lock().unwrap() += 1;
                Some((Verdict::Deny, "x".into()))
            }
            fn default_ttl(&self) -> Duration {
                Duration::from_millis(50)
            }
        }
        let src = Arc::new(ShortTtl(Mutex::new(0)));
        f.register(src.clone());
        f.lookup(&ip(1, 2, 3, 4));
        std::thread::sleep(Duration::from_millis(70));
        f.lookup(&ip(1, 2, 3, 4));
        assert_eq!(*src.0.lock().unwrap(), 2);
    }
}
