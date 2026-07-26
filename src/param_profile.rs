//! V180 — open-appsec-style per-endpoint parameter profile learning.
//!
//! For each (host, endpoint, param_name) tuple we maintain rolling
//! stats: count, min/max length, mean ± stddev length, charset
//! histogram, Shannon entropy mean. After `learn_threshold`
//! observations the profile is "trained" and subsequent values are
//! scored against it.
//!
//! Anomaly axes:
//!
//! * Length outside [mean - 3σ, mean + 3σ]
//! * New characters never seen during learning
//! * Entropy spike (e.g., a parameter that was always integers
//!   suddenly carrying base64)
//!
//! Output: 0.0 (matches profile) to 1.0 (every axis flags).
//!
//! Stays per-process; no shared state needed since the learner
//! converges fast for moderately trafficked endpoints. Surfaced in
//! the V158 admin UI Endpoints tab so operators can see "param `id`
//! on POST /users is normally 6-8 char numeric; just saw 320 char
//! base64".

use dashmap::DashMap;
use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone)]
pub struct ParamProfile {
    pub samples: u32,
    pub min_len: u32,
    pub max_len: u32,
    pub mean_len: f32,
    pub m2_len: f32, // Welford accumulator for variance
    pub mean_entropy: f32,
    pub charset_mask: CharsetMask,
}

#[derive(Debug, Clone, Default, Copy)]
pub struct CharsetMask {
    pub digit: bool,
    pub lower_alpha: bool,
    pub upper_alpha: bool,
    pub dash_underscore: bool,
    pub punct: bool,
    pub whitespace: bool,
    pub non_ascii: bool,
    pub base64_pad: bool,
}

impl CharsetMask {
    pub fn observe(&mut self, value: &str) {
        for c in value.chars() {
            match c {
                '0'..='9' => self.digit = true,
                'a'..='z' => self.lower_alpha = true,
                'A'..='Z' => self.upper_alpha = true,
                '-' | '_' => self.dash_underscore = true,
                '=' => self.base64_pad = true,
                ' ' | '\t' | '\n' | '\r' => self.whitespace = true,
                c if c.is_ascii_punctuation() => self.punct = true,
                c if !c.is_ascii() => self.non_ascii = true,
                _ => {}
            }
        }
    }

    pub fn includes(&self, other: &CharsetMask) -> bool {
        (!other.digit || self.digit)
            && (!other.lower_alpha || self.lower_alpha)
            && (!other.upper_alpha || self.upper_alpha)
            && (!other.dash_underscore || self.dash_underscore)
            && (!other.punct || self.punct)
            && (!other.whitespace || self.whitespace)
            && (!other.non_ascii || self.non_ascii)
            && (!other.base64_pad || self.base64_pad)
    }
}

impl ParamProfile {
    fn empty() -> Self {
        Self {
            samples: 0,
            min_len: u32::MAX,
            max_len: 0,
            mean_len: 0.0,
            m2_len: 0.0,
            mean_entropy: 0.0,
            charset_mask: CharsetMask::default(),
        }
    }

    fn observe(&mut self, value: &str) {
        let len = value.chars().count() as u32;
        self.samples += 1;
        self.min_len = self.min_len.min(len);
        self.max_len = self.max_len.max(len);
        // Welford update for length mean/variance.
        let delta = len as f32 - self.mean_len;
        self.mean_len += delta / self.samples as f32;
        let delta2 = len as f32 - self.mean_len;
        self.m2_len += delta * delta2;
        // EWMA for entropy (simpler than full streaming variance).
        let h = shannon_entropy(value);
        self.mean_entropy = if self.samples == 1 {
            h
        } else {
            self.mean_entropy * 0.95 + h * 0.05
        };
        self.charset_mask.observe(value);
    }

    fn stddev_len(&self) -> f32 {
        if self.samples < 2 {
            return 0.0;
        }
        (self.m2_len / (self.samples - 1) as f32).sqrt()
    }

    /// Score a fresh observation against the trained profile.
    pub fn score(&self, value: &str) -> f32 {
        if self.samples == 0 {
            return 0.0;
        }
        let len = value.chars().count() as u32;
        let len_score = {
            let sd = self.stddev_len().max(1.0);
            let z = (len as f32 - self.mean_len).abs() / sd;
            (z / 3.0).clamp(0.0, 1.0)
        };
        let mut other_mask = CharsetMask::default();
        other_mask.observe(value);
        let charset_score = if self.charset_mask.includes(&other_mask) {
            0.0
        } else {
            1.0
        };
        let entropy_score = {
            let h = shannon_entropy(value);
            let delta = (h - self.mean_entropy).abs();
            (delta / 3.0).clamp(0.0, 1.0)
        };
        // Mean of three axes; deny when 2+ axes flag.
        (len_score + charset_score + entropy_score) / 3.0
    }
}

pub fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f32;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / total;
            -p * p.log2()
        })
        .sum()
}

/// Trait-object key used by HashMap lookups so that both the owned
/// [`ParamKey`] and the borrowed [`ParamKeyRef`] hash and compare the
/// same way without an allocation on the hot path.
///
/// The hash/eq implementations here are exactly equivalent to the
/// derived `Hash`/`PartialEq` impls a `(String, String, String)`
/// would have — Rust's `Hash` for `String` delegates to `&str`, so we
/// can express the same hash over `&str` slices.
pub trait ParamKeyLookup {
    fn host_str(&self) -> &str;
    fn endpoint_str(&self) -> &str;
    fn param_str(&self) -> &str;
}

impl Hash for dyn ParamKeyLookup + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Mirror the layout `#[derive(Hash)]` would produce for a
        // struct of three `String` fields: each field's `Hash`
        // implementation delegates to `str::hash` (length + bytes).
        self.host_str().hash(state);
        self.endpoint_str().hash(state);
        self.param_str().hash(state);
    }
}

impl PartialEq for dyn ParamKeyLookup + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.host_str() == other.host_str()
            && self.endpoint_str() == other.endpoint_str()
            && self.param_str() == other.param_str()
    }
}

impl Eq for dyn ParamKeyLookup + '_ {}

#[derive(Debug, Clone, Eq)]
pub struct ParamKey {
    pub host: String,
    pub endpoint: String,
    pub param: String,
}

impl ParamKeyLookup for ParamKey {
    #[inline]
    fn host_str(&self) -> &str {
        &self.host
    }
    #[inline]
    fn endpoint_str(&self) -> &str {
        &self.endpoint
    }
    #[inline]
    fn param_str(&self) -> &str {
        &self.param
    }
}

// Hand-implement Hash/PartialEq so they route through the trait-object
// path and therefore hash/compare identically to `ParamKeyRef`. Without
// this, the derive would produce the same byte sequence (each `String`'s
// `Hash` is `<str as Hash>`) but routing through one code path keeps
// it obviously consistent and makes the invariant testable.
impl Hash for ParamKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self as &dyn ParamKeyLookup).hash(state);
    }
}

impl PartialEq for ParamKey {
    fn eq(&self, other: &Self) -> bool {
        (self as &dyn ParamKeyLookup) == (other as &dyn ParamKeyLookup)
    }
}

// The Borrow impl is what makes `HashMap<ParamKey, V>::get(&dyn ParamKeyLookup)`
// work without allocating a temporary `ParamKey`. The contract requires
// that the borrowed form hash and compare the same as the owned form —
// guaranteed because both route through the trait-object impls above.
impl<'a> Borrow<dyn ParamKeyLookup + 'a> for ParamKey {
    fn borrow(&self) -> &(dyn ParamKeyLookup + 'a) {
        self
    }
}

/// Borrowed counterpart to [`ParamKey`]. Built on the request hot path
/// to do a HashMap lookup without three `String` allocations. Promoted
/// to an owned `ParamKey` via [`ParamKeyRef::to_owned`] only when we
/// actually need to insert (i.e., the first time we see this triple).
#[derive(Debug, Copy, Clone)]
pub struct ParamKeyRef<'a> {
    pub host: &'a str,
    pub endpoint: &'a str,
    pub param: &'a str,
}

impl<'a> ParamKeyRef<'a> {
    #[inline]
    pub fn new(host: &'a str, endpoint: &'a str, param: &'a str) -> Self {
        Self {
            host,
            endpoint,
            param,
        }
    }

    pub fn to_owned(&self) -> ParamKey {
        ParamKey {
            host: self.host.to_string(),
            endpoint: self.endpoint.to_string(),
            param: self.param.to_string(),
        }
    }
}

impl<'a> ParamKeyLookup for ParamKeyRef<'a> {
    #[inline]
    fn host_str(&self) -> &str {
        self.host
    }
    #[inline]
    fn endpoint_str(&self) -> &str {
        self.endpoint
    }
    #[inline]
    fn param_str(&self) -> &str {
        self.param
    }
}

pub struct ParamProfileStore {
    inner: DashMap<ParamKey, ParamProfile>,
    learn_threshold: u32,
    // Mirrors `inner.len()` so the request hot path can gate on
    // `is_empty()` with a single relaxed atomic load instead of
    // touching any DashMap shard. Incremented exactly once per new
    // key insertion; never decremented (the store is append-only).
    count: AtomicUsize,
}

impl ParamProfileStore {
    pub fn new(learn_threshold: u32) -> Self {
        Self {
            // V230 — boost shard concurrency. The map sees per-query-param
            // writes from many threads simultaneously; the default shard
            // count (16-64 depending on parallelism) thrashes locks under
            // load. 128 shards spreads contention 2-8x with negligible
            // memory overhead. V228 introduced the empty-gate AtomicBool
            // fast-path; this lifts the ceiling once the gate is open.
            inner: DashMap::with_shard_amount(128),
            learn_threshold,
            count: AtomicUsize::new(0),
        }
    }

    pub fn observe(&self, key: ParamKey, value: &str) {
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(key) {
            Entry::Occupied(mut occ) => {
                occ.get_mut().observe(value);
            }
            Entry::Vacant(vac) => {
                let mut profile = ParamProfile::empty();
                profile.observe(value);
                vac.insert(profile);
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Borrowed-key variant of [`Self::observe`]. Only allocates a
    /// `ParamKey` on first insert for this triple; subsequent
    /// observations hit the existing entry via the borrowed-key
    /// lookup path and skip the `String`-clone of the three name
    /// slices.
    pub fn observe_ref(&self, key: ParamKeyRef<'_>, value: &str) {
        // Fast path: entry exists — update in place, no owned-key
        // allocation. DashMap's `get_mut` only locks the relevant
        // shard, so concurrent writers to other shards proceed in
        // parallel.
        if let Some(mut p) = self.inner.get_mut(&key as &dyn ParamKeyLookup) {
            p.observe(value);
            return;
        }
        // Slow path: missing — allocate the owned key and insert via
        // `entry` so a concurrent inserter doesn't race us into a
        // duplicate. Bump `count` only when *we* are the inserter.
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(key.to_owned()) {
            Entry::Occupied(mut occ) => {
                occ.get_mut().observe(value);
            }
            Entry::Vacant(vac) => {
                let mut profile = ParamProfile::empty();
                profile.observe(value);
                vac.insert(profile);
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn score(&self, key: &ParamKey, value: &str) -> f32 {
        match self.inner.get(key) {
            Some(p) if p.samples >= self.learn_threshold => p.score(value),
            _ => 0.0, // still learning
        }
    }

    /// Borrowed-key variant of [`Self::score`]. Hot-path lookup that
    /// avoids `to_string()` on host/endpoint/param when the entry is
    /// missing or still warming up — i.e., the overwhelmingly common
    /// case for any param the store hasn't seen `learn_threshold`
    /// times yet.
    pub fn score_ref(&self, key: ParamKeyRef<'_>, value: &str) -> f32 {
        match self.inner.get(&key as &dyn ParamKeyLookup) {
            Some(p) if p.samples >= self.learn_threshold => p.score(value),
            _ => 0.0,
        }
    }

    pub fn snapshot(&self, key: &ParamKey) -> Option<ParamProfile> {
        self.inner.get(key).map(|r| r.clone())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Lock-free fast-path emptiness check. Reads a single atomic and
    /// never touches a DashMap shard, so the per-request hot path can
    /// gate on `if store.is_empty() { return }` without lock traffic
    /// when the store has never observed a parameter.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count.load(Ordering::Relaxed) == 0
    }

    /// Backward-compatible alias for [`Self::is_empty`]; both are now
    /// the lock-free atomic-backed fast path.
    #[inline]
    pub fn is_empty_hint(&self) -> bool {
        self.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn key(host: &str, endpoint: &str, param: &str) -> ParamKey {
        ParamKey {
            host: host.into(),
            endpoint: endpoint.into(),
            param: param.into(),
        }
    }

    fn hash_of<T: Hash + ?Sized>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }

    #[test]
    fn integer_profile_flags_base64() {
        let s = ParamProfileStore::new(20);
        let k = key("api", "/users", "id");
        for i in 0..50 {
            s.observe(k.clone(), &format!("{}", 1000 + i));
        }
        let normal = s.score(&k, "12345");
        let anomaly = s.score(&k, "ZGFuZ2Vyb3VzcGF5bG9hZA==");
        assert!(normal < 0.2, "normal scored {normal}");
        assert!(anomaly > 0.4, "anomaly scored {anomaly}");
    }

    #[test]
    fn untrained_profile_returns_zero() {
        let s = ParamProfileStore::new(20);
        let k = key("api", "/x", "q");
        s.observe(k.clone(), "hello");
        assert_eq!(s.score(&k, "completely different and long"), 0.0);
    }

    #[test]
    fn shannon_entropy_constant_is_zero() {
        assert_eq!(shannon_entropy("aaaaaa"), 0.0);
    }

    #[test]
    fn shannon_entropy_high_for_random() {
        let h = shannon_entropy("a1B!c2D@e3F#g4H$");
        assert!(h > 3.5);
    }

    #[test]
    fn charset_includes_subset() {
        let mut trained = CharsetMask::default();
        trained.observe("abcdef123");
        let mut probe = CharsetMask::default();
        probe.observe("a1");
        assert!(trained.includes(&probe));
        let mut probe2 = CharsetMask::default();
        probe2.observe("a1<");
        assert!(!trained.includes(&probe2));
    }

    #[test]
    fn param_key_ref_hashes_equal_to_owned() {
        // Borrow contract: ParamKeyRef must hash and compare exactly
        // like its ParamKey twin so HashMap lookups stay valid.
        let owned = key("api.example.com", "/v1/users", "id");
        let borrowed = ParamKeyRef {
            host: "api.example.com",
            endpoint: "/v1/users",
            param: "id",
        };
        let h_owned = hash_of(&owned as &dyn ParamKeyLookup);
        let h_borrowed = hash_of(&borrowed as &dyn ParamKeyLookup);
        assert_eq!(h_owned, h_borrowed, "hashes diverged");
        // Cross-equality via the trait object.
        assert!((&owned as &dyn ParamKeyLookup) == (&borrowed as &dyn ParamKeyLookup));
    }

    #[test]
    fn observe_ref_then_score_ref_round_trips() {
        let s = ParamProfileStore::new(20);
        let kref = ParamKeyRef::new("api", "/users", "id");
        for i in 0..40 {
            s.observe_ref(kref, &format!("{}", 100_000 + i));
        }
        // Score via both APIs — should land on the same profile.
        let owned = kref.to_owned();
        let via_ref = s.score_ref(kref, "<script>alert(1)</script>");
        let via_owned = s.score(&owned, "<script>alert(1)</script>");
        assert_eq!(via_ref, via_owned, "ref vs owned scoring diverged");
        assert!(via_ref > 0.0, "trained profile should flag XSS");
    }

    #[test]
    fn score_ref_misses_dont_grow_the_map() {
        // The whole point of `score_ref`: a lookup miss must NOT insert
        // anything, otherwise a flood of unique param names would
        // unbounded-grow the map.
        let s = ParamProfileStore::new(20);
        for i in 0..100 {
            let pname = format!("p{i}");
            let kref = ParamKeyRef::new("api", "/x", &pname);
            let _ = s.score_ref(kref, "v");
        }
        assert_eq!(s.len(), 0, "score_ref must not insert");
    }

    #[test]
    fn is_empty_hint_tracks_first_insert() {
        let s = ParamProfileStore::new(20);
        assert!(s.is_empty_hint());
        s.observe_ref(ParamKeyRef::new("api", "/x", "q"), "v");
        assert!(!s.is_empty_hint());
    }
}
