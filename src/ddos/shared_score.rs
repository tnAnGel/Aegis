//! V90 — Cluster-wide per-IP threat scorer backed by the Phase D
//! shared mmap arena.
//!
//! The existing [ThreatScorer](super::score::ThreatScorer) uses a
//! per-worker `DashMap<IpAddr, WindowStats>`. Under REUSEPORT
//! multi-process deployments this means a distributed attacker can
//! saturate worker A's view of an IP while worker B still sees a
//! clean score. V90 ships the data structures + atomic update
//! logic that lets all workers contribute to a SHARED per-IP
//! score table. V91 will wire this into the proxy as an opt-in
//! alongside the per-worker scorer.
//!
//! Architecture
//! ------------
//! * **IPv4**: backed by V88's [AtomicHashMap]. Key = u32
//!   (network-order IPv4 bytes), value = packed
//!   `(allowed, denied, challenged, last_secs)` into a single u64.
//!   Every counter update is a CAS loop: read packed u64, unpack,
//!   modify, re-pack, CAS. Lock-free across workers.
//!
//! * **IPv6**: AtomicHashMap is u32-keyed for now. V91+ can add a
//!   parallel `AtomicHashMap<u128, u64>` once we add a second slot
//!   layout to the arena. For V90 we fall back to a per-worker
//!   `DashMap<Ipv6Addr, WindowStats>` — same as today's scorer.
//!   This means IPv6 traffic still suffers from the per-worker
//!   fragmentation issue. IPv4 (the vast majority of production
//!   traffic) gets the cluster-wide treatment.
//!
//! Packed layout (u64 value)
//! -------------------------
//! ```text
//!   bit 63..48  allowed   (u16, saturates at 65535)
//!   bit 47..32  denied    (u16, saturates at 65535)
//!   bit 31..16  challenged (u16, saturates at 65535)
//!   bit 15..0   last_secs (u16, seconds since daemon-start epoch;
//!                          wraps every ~18 hours which is fine for
//!                          a 60-second sliding window check)
//! ```
//!
//! 65535 is plenty for the 60-second window. At sustained 1000 RPS
//! a single IP saturates the counter in ~65 seconds, which is past
//! the window roll anyway — saturation is a strictly bigger threat
//! signal than the actual count, so capping doesn't hide attackers.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use super::score::ThreatScore;
use crate::shared_state::hashmap128::AtomicHashMap128;
use crate::shared_state::{AtomicHashMap, HashMapError};

/// Per-IP score state packed into 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PackedScore {
    pub allowed: u16,
    pub denied: u16,
    pub challenged: u16,
    pub last_secs: u16,
}

impl PackedScore {
    #[inline]
    pub fn pack(&self) -> u64 {
        (self.allowed as u64) << 48
            | (self.denied as u64) << 32
            | (self.challenged as u64) << 16
            | (self.last_secs as u64)
    }

    #[inline]
    pub fn unpack(v: u64) -> Self {
        Self {
            allowed: ((v >> 48) & 0xFFFF) as u16,
            denied: ((v >> 32) & 0xFFFF) as u16,
            challenged: ((v >> 16) & 0xFFFF) as u16,
            last_secs: (v & 0xFFFF) as u16,
        }
    }

    /// True when the last update is outside the sliding window
    /// `window_secs` seconds before `now_secs`. Accounts for u16
    /// wrap: if `last_secs > now_secs`, the daemon-start epoch
    /// wrapped between the last update and now (~18h gap),
    /// so the entry is definitely stale.
    #[inline]
    pub fn is_stale(&self, now_secs: u16, window_secs: u16) -> bool {
        if self.last_secs > now_secs {
            // Wraparound — entry is from before the most recent
            // u16 wrap, so > 18h old.
            return true;
        }
        now_secs - self.last_secs > window_secs
    }
}

/// Cluster-wide per-IP threat scorer. Built on top of V88
/// [AtomicHashMap] for IPv4; falls back to per-worker DashMap for
/// IPv6 (V91+ adds shared IPv6 table).
pub struct SharedScorer {
    /// Sliding-window length. Counters reset when the window
    /// rolls (detected via `last_secs` drift > window).
    window: Duration,
    /// Reference epoch — daemon-start instant. `last_secs` field
    /// in PackedScore is `now.saturating_duration_since(epoch)
    /// .as_secs() as u16` so it wraps every ~18h. The window
    /// staleness check accounts for the wrap.
    epoch: Instant,
    /// Backing AtomicHashMap for IPv4 (cluster-wide).
    v4: Arc<AtomicHashMap>,
    /// V93 — cluster-wide IPv6 map. Same packed score layout as v4,
    /// u128-keyed via [AtomicHashMap128]. Every REUSEPORT worker
    /// attaches to the SAME bytes via the SHARED_SCORER_V6 named slot.
    v6: Arc<AtomicHashMap128>,
}

impl SharedScorer {
    /// Construct with already-allocated v4 + v6 maps (caller owns
    /// the arena lifecycle). `window` matches ThreatScorer's default
    /// (60s) for behaviour parity.
    pub fn new(v4_map: AtomicHashMap, v6_map: AtomicHashMap128, window: Duration) -> Self {
        Self {
            window,
            epoch: Instant::now(),
            v4: Arc::new(v4_map),
            v6: Arc::new(v6_map),
        }
    }

    /// Seconds since the daemon-start epoch, truncated to u16.
    #[inline]
    fn now_secs(&self, now: Instant) -> u16 {
        now.saturating_duration_since(self.epoch).as_secs() as u16
    }

    /// Atomically update the packed score for an IPv4 IP. The
    /// update closure receives the current PackedScore (or
    /// default for a fresh entry) and returns the new value;
    /// SharedScorer handles the CAS loop and window-roll detection.
    fn update_v4<F>(&self, ip: Ipv4Addr, now: Instant, mut update: F)
    where
        F: FnMut(&mut PackedScore),
    {
        let key = u32::from(ip);
        let now_s = self.now_secs(now);
        let window_s = self.window.as_secs() as u16;

        // Value-level CAS update. AtomicHashMap::update_with claims
        // the slot then loops compare_exchange on the packed value,
        // so the read→unpack→modify→repack happens INSIDE the CAS
        // attempt — concurrent workers can no longer lose increments
        // (the prior insert-based path swapped the value, dropping a
        // racing worker's count). The closure must be pure in its
        // input, so window-roll detection + last_secs are derived
        // from the freshly-read value on every retry.
        let _ = self.v4.update_with(key, |current| {
            let mut packed = PackedScore::unpack(current);
            if packed.is_stale(now_s, window_s) {
                // Window rolled — reset counters but keep last_secs.
                packed = PackedScore::default();
            }
            packed.last_secs = now_s;
            update(&mut packed);
            packed.pack()
        });
    }

    /// V93 — IPv6 mirror of update_v4. Same value-level CAS semantics:
    /// AtomicHashMap128::update_with claims the slot then loops
    /// compare_exchange on the packed value, so read → maybe-reset-on-
    /// window-roll → modify → repack is atomic per attempt and
    /// concurrent same-key updates never lose increments.
    fn update_v6<F>(&self, ip: Ipv6Addr, now: Instant, mut update: F)
    where
        F: FnMut(&mut PackedScore),
    {
        let key = u128::from(ip);
        let now_s = self.now_secs(now);
        let window_s = self.window.as_secs() as u16;
        let _ = self.v6.update_with(key, |current| {
            let mut packed = PackedScore::unpack(current);
            if packed.is_stale(now_s, window_s) {
                packed = PackedScore::default();
            }
            packed.last_secs = now_s;
            update(&mut packed);
            packed.pack()
        });
    }

    fn read_v6(&self, ip: Ipv6Addr, now: Instant) -> PackedScore {
        let key = u128::from(ip);
        let now_s = self.now_secs(now);
        let window_s = self.window.as_secs() as u16;
        let raw = self.v6.get(key).unwrap_or(0);
        let packed = PackedScore::unpack(raw);
        if packed.is_stale(now_s, window_s) {
            PackedScore::default()
        } else {
            packed
        }
    }

    /// Read the current packed score for an IPv4 IP without
    /// mutating. Returns default (all zeros) when the IP is
    /// absent.
    fn read_v4(&self, ip: Ipv4Addr, now: Instant) -> PackedScore {
        let key = u32::from(ip);
        let now_s = self.now_secs(now);
        let window_s = self.window.as_secs() as u16;
        let raw = self.v4.get(key).unwrap_or(0);
        let packed = PackedScore::unpack(raw);
        if packed.is_stale(now_s, window_s) {
            PackedScore::default()
        } else {
            packed
        }
    }

    pub fn record_allowed(&self, ip: IpAddr, now: Instant) {
        match ip {
            IpAddr::V4(v4) => self.update_v4(v4, now, |p| {
                p.allowed = p.allowed.saturating_add(1);
            }),
            IpAddr::V6(v6) => self.update_v6(v6, now, |p| {
                p.allowed = p.allowed.saturating_add(1);
            }),
        }
    }

    pub fn record_denied(&self, ip: IpAddr, now: Instant) {
        match ip {
            IpAddr::V4(v4) => self.update_v4(v4, now, |p| {
                p.denied = p.denied.saturating_add(1);
            }),
            IpAddr::V6(v6) => self.update_v6(v6, now, |p| {
                p.denied = p.denied.saturating_add(1);
            }),
        }
    }

    pub fn record_challenged(&self, ip: IpAddr, now: Instant) {
        match ip {
            IpAddr::V4(v4) => self.update_v4(v4, now, |p| {
                p.challenged = p.challenged.saturating_add(1);
            }),
            IpAddr::V6(v6) => self.update_v6(v6, now, |p| {
                p.challenged = p.challenged.saturating_add(1);
            }),
        }
    }

    /// Compute the 0..=100 threat score for an IP. Same weighting
    /// the existing ThreatScorer uses: denied = full weight,
    /// challenged = half. Returns zero score for unknown IPs and
    /// for IPs whose window rolled.
    pub fn score(&self, ip: IpAddr) -> ThreatScore {
        let packed = match ip {
            IpAddr::V4(v4) => self.read_v4(v4, Instant::now()),
            IpAddr::V6(v6) => self.read_v6(v6, Instant::now()),
        };
        let total =
            (packed.allowed as u64 + packed.denied as u64 + packed.challenged as u64) as f64;
        if total < 1.0 {
            return ThreatScore(0.0);
        }
        let weighted = packed.denied as f64 + (packed.challenged as f64) * 0.5;
        ThreatScore(((weighted / total) * 100.0).clamp(0.0, 100.0))
    }

    /// Cluster-wide live IPv4 entry count. O(arena_capacity)
    /// walk — admin frequency, not hot path.
    pub fn live_v4_count(&self) -> usize {
        self.v4.live_count()
    }

    /// Snapshot for /admin/threats. Returns up to `limit` entries
    /// sorted by score descending. IPv6 entries included from the
    /// per-worker DashMap (only this worker's view for V90).
    pub fn top(&self, limit: usize) -> Vec<(IpAddr, ThreatScore)> {
        let now = Instant::now();
        let mut all: Vec<(IpAddr, ThreatScore)> = Vec::new();

        for (key, val) in self.v4.snapshot() {
            let packed = PackedScore::unpack(val);
            let score = self.score_packed(&packed);
            if score.0 > 0.0 {
                all.push((IpAddr::V4(Ipv4Addr::from(key)), score));
            }
        }
        let now_s = self.now_secs(now);
        let window_s = self.window.as_secs() as u16;
        for (key, val) in self.v6.snapshot() {
            let packed = PackedScore::unpack(val);
            if packed.is_stale(now_s, window_s) {
                continue;
            }
            let score = self.score_packed(&packed);
            if score.0 > 0.0 {
                all.push((IpAddr::V6(Ipv6Addr::from(key)), score));
            }
        }
        all.sort_by(|a, b| {
            b.1.0
                .partial_cmp(&a.1.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        all.truncate(limit);
        all
    }

    #[inline]
    fn score_packed(&self, packed: &PackedScore) -> ThreatScore {
        let total =
            (packed.allowed as u64 + packed.denied as u64 + packed.challenged as u64) as f64;
        if total < 1.0 {
            return ThreatScore(0.0);
        }
        let weighted = packed.denied as f64 + (packed.challenged as f64) * 0.5;
        ThreatScore(((weighted / total) * 100.0).clamp(0.0, 100.0))
    }

    /// Cleanup of stale entries. Both v4 and v6 maps are now shared
    /// AtomicHashMap[128] inside the arena — stale entries are zeroed
    /// on next access via the window-roll check. Calling this also
    /// reclaims arena slots (tombstones) for any entry whose
    /// `last_secs` is older than `window * retain_factor` seconds.
    ///
    /// Returns the number of v4+v6 entries tombstoned. Operator-driven
    /// (admin endpoint) or background-task driven (aegis-pingora ticks
    /// it every minute). Cheap enough that a 256k-slot map walks in
    /// the low single-digit ms on commodity ARM/x86.
    pub fn cleanup_stale(&self, now: Instant) -> usize {
        self.compact(now, 5)
    }

    /// V94 — explicit compaction pass. Walks both shared maps and
    /// removes entries idle for more than `window * retain_factor`
    /// seconds. `retain_factor=1` is aggressive (matches the sliding-
    /// window staleness check exactly), `5` is the default cleanup
    /// behaviour (keeps a 5× window of recent-but-stale entries
    /// around in case of bursty same-IP traffic). Returns the count
    /// of (v4+v6) entries tombstoned.
    ///
    /// Concurrent record_* calls during compaction are safe: removing
    /// a slot just sets its state atomically to TOMBSTONE. A concurrent
    /// insert for the same key will re-probe and either claim a fresh
    /// slot in the probe chain or reuse the tombstone — either way the
    /// new counter values are correct (no torn updates).
    pub fn compact(&self, now: Instant, retain_factor: u16) -> usize {
        let now_s = self.now_secs(now);
        let window_s = self.window.as_secs() as u16;
        let retain_window = window_s.saturating_mul(retain_factor);
        let mut removed = 0usize;
        // IPv4
        for (key, val) in self.v4.snapshot() {
            let packed = PackedScore::unpack(val);
            if Self::idle_beyond(&packed, now_s, retain_window) && self.v4.remove(key).is_some() {
                removed += 1;
            }
        }
        // IPv6
        for (key, val) in self.v6.snapshot() {
            let packed = PackedScore::unpack(val);
            if Self::idle_beyond(&packed, now_s, retain_window) && self.v6.remove(key).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// True when `packed` hasn't been touched in `cutoff_secs` seconds.
    /// Mirrors PackedScore::is_stale wraparound handling.
    #[inline]
    fn idle_beyond(packed: &PackedScore, now_s: u16, cutoff_secs: u16) -> bool {
        if packed.last_secs > now_s {
            // u16 wrapped — entry is from before the most recent wrap,
            // so > ~18h old. Definitely past any sane cutoff.
            return true;
        }
        now_s - packed.last_secs > cutoff_secs
    }

    /// Allocate a new SharedScorer with an AtomicHashMap from the
    /// process-global arena. Returns Err if the arena failed to
    /// init, or if the requested capacity won't fit.
    ///
    /// V91 — uses the well-known SHARED_SCORER_V4 named slot so
    /// every REUSEPORT worker attaches to the SAME underlying
    /// hashmap bytes. First worker to call allocates; subsequent
    /// workers re-attach to the existing region.
    pub fn from_global_arena(
        capacity: usize,
        window: Duration,
    ) -> Result<Self, SharedScorerInitError> {
        let arena =
            crate::shared_state::global::arena().ok_or(SharedScorerInitError::ArenaUnavailable)?;
        let v4 = AtomicHashMap::new_named(
            arena,
            crate::shared_state::named::SHARED_SCORER_V4,
            capacity,
        )
        .map_err(SharedScorerInitError::ArenaAlloc)?;
        // V93 — second well-known slot for the u128-keyed IPv6 map.
        // Same capacity; IPv6 cardinality is comparable to v4 in
        // mixed-stack deployments.
        let v6 = AtomicHashMap128::new_named(
            arena,
            crate::shared_state::named::SHARED_SCORER_V6,
            capacity,
        )
        .map_err(SharedScorerInitError::ArenaAlloc)?;
        Ok(Self::new(v4, v6, window))
    }
}

/// Errors when wiring SharedScorer to the daemon's shared arena.
#[derive(Debug)]
pub enum SharedScorerInitError {
    /// Arena failed to init at startup (Linux without /dev/shm,
    /// macOS dev build). SharedScorer can't be used — fall back
    /// to the per-worker ThreatScorer.
    ArenaUnavailable,
    /// Arena is available but the requested capacity exceeds
    /// remaining space. Operator should grow
    /// AEGIS_SHARED_STATE_SIZE_MB.
    ArenaAlloc(crate::shared_state::ArenaError),
}

impl std::fmt::Display for SharedScorerInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArenaUnavailable => {
                write!(f, "SharedScorer: cluster arena not initialised")
            }
            Self::ArenaAlloc(e) => write!(f, "SharedScorer: arena alloc failed: {e}"),
        }
    }
}

impl std::error::Error for SharedScorerInitError {}

// Silence unused warnings on non-Linux where HashMapError isn't
// referenced from here (the platform stub uses a different type).
#[allow(dead_code)]
fn _touch_unused() {
    let _ = std::mem::size_of::<HashMapError>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_state::Arena;

    fn ipv4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn ipv6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn unique_name(prefix: &str) -> String {
        format!(
            "/aegis-scorer-{}-{}-{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }

    fn fresh_scorer(prefix: &str) -> (SharedScorer, String) {
        let name = unique_name(prefix);
        let arena = Arena::open_or_create(&name, 4 * 1024 * 1024).expect("arena");
        let v4 = AtomicHashMap::new(&arena, 1024).expect("v4 map");
        let v6 = AtomicHashMap128::new(&arena, 1024).expect("v6 map");
        (SharedScorer::new(v4, v6, Duration::from_secs(60)), name)
    }

    fn cleanup(name: &str) {
        #[cfg(target_os = "linux")]
        let _ = Arena::unlink(name);
        #[cfg(not(target_os = "linux"))]
        let _ = name;
    }

    #[test]
    fn packed_score_pack_unpack_roundtrip() {
        let s = PackedScore {
            allowed: 12345,
            denied: 678,
            challenged: 999,
            last_secs: 42,
        };
        let v = s.pack();
        let back = PackedScore::unpack(v);
        assert_eq!(back, s);
    }

    #[test]
    fn packed_score_is_stale_window() {
        let s = PackedScore {
            allowed: 1,
            denied: 0,
            challenged: 0,
            last_secs: 100,
        };
        assert!(!s.is_stale(110, 60), "10s inside 60s window — fresh");
        assert!(!s.is_stale(160, 60), "60s exactly at edge — still fresh");
        assert!(s.is_stale(170, 60), "70s past window — stale");
        // Wraparound — last_secs > now_secs
        assert!(s.is_stale(50, 60), "wraparound — last>now — stale");
    }

    #[test]
    fn empty_history_zero_score() {
        let (s, name) = fresh_scorer("empty");
        assert_eq!(s.score(ipv4("10.0.0.1")), ThreatScore(0.0));
        assert_eq!(s.score(ipv6("::1")), ThreatScore(0.0));
        cleanup(&name);
    }

    #[test]
    fn all_denied_full_score_ipv4() {
        let (s, name) = fresh_scorer("denied-v4");
        let now = Instant::now();
        for _ in 0..5 {
            s.record_denied(ipv4("10.0.0.2"), now);
        }
        assert_eq!(s.score(ipv4("10.0.0.2")), ThreatScore(100.0));
        cleanup(&name);
    }

    #[test]
    fn all_denied_full_score_ipv6() {
        let (s, name) = fresh_scorer("denied-v6");
        let now = Instant::now();
        for _ in 0..5 {
            s.record_denied(ipv6("2001:db8::1"), now);
        }
        assert_eq!(s.score(ipv6("2001:db8::1")), ThreatScore(100.0));
        cleanup(&name);
    }

    #[test]
    fn challenged_weighted_half() {
        let (s, name) = fresh_scorer("ch");
        let now = Instant::now();
        for _ in 0..10 {
            s.record_challenged(ipv4("10.0.0.3"), now);
        }
        assert_eq!(s.score(ipv4("10.0.0.3")), ThreatScore(50.0));
        cleanup(&name);
    }

    #[test]
    fn mixed_outcomes() {
        let (s, name) = fresh_scorer("mixed");
        let now = Instant::now();
        for _ in 0..7 {
            s.record_allowed(ipv4("10.0.0.4"), now);
        }
        for _ in 0..3 {
            s.record_denied(ipv4("10.0.0.4"), now);
        }
        // 3 denied of 10 → 30
        assert!((s.score(ipv4("10.0.0.4")).as_f64() - 30.0).abs() < 0.001);
        cleanup(&name);
    }

    #[test]
    fn top_sorts_by_score_desc() {
        let (s, name) = fresh_scorer("top");
        let now = Instant::now();
        s.record_allowed(ipv4("1.1.1.1"), now);
        s.record_denied(ipv4("2.2.2.2"), now);
        s.record_challenged(ipv4("3.3.3.3"), now);
        let top = s.top(3);
        assert_eq!(top[0].0, ipv4("2.2.2.2"));
        cleanup(&name);
    }

    #[test]
    fn compact_tombstones_idle_entries() {
        let (s, name) = fresh_scorer("compact");
        let now = Instant::now();
        // Fresh entry — should NOT be tombstoned by compact.
        s.record_denied(ipv4("10.0.0.1"), now);
        // Stale entry — fake `last_secs` from "the past" by recording
        // at an Instant 600s ago. We achieve this by directly poking
        // a packed value into the v4 map at an old `last_secs`.
        let stale = PackedScore {
            allowed: 0,
            denied: 5,
            challenged: 0,
            // 600s before our scorer's epoch view of "now". `now_secs`
            // for the just-constructed scorer is ~0, so last_secs=0
            // looks fresh; we need to call compact with a much-later
            // `now`. Use Duration::from_secs(600) past Instant.
            last_secs: 0,
        };
        let key_v4 = u32::from(std::net::Ipv4Addr::new(10, 0, 0, 99));
        s.v4.insert(key_v4, stale.pack()).unwrap();
        let key_v6 = u128::from(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99));
        s.v6.insert(key_v6, stale.pack()).unwrap();

        // Compact at +600s (10× the 60s window). 5× window = 300s
        // cutoff; the 600s-idle stale entries get removed, the fresh
        // entry (last_secs ~600) stays.
        s.record_denied(ipv4("10.0.0.1"), now + Duration::from_secs(600));
        let removed = s.compact(now + Duration::from_secs(600), 5);
        assert_eq!(removed, 2, "expected v4 + v6 stale entries removed");
        assert!(
            s.v4.get(u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1)))
                .is_some(),
            "fresh entry must survive"
        );
        assert_eq!(s.v4.get(key_v4), None, "stale v4 must be removed");
        assert_eq!(s.v6.get(key_v6), None, "stale v6 must be removed");
        cleanup(&name);
    }

    #[test]
    fn cluster_concurrent_record_distinct_ips() {
        use std::sync::Arc;
        use std::thread;
        let (s, name) = fresh_scorer("concurrent");
        let s = Arc::new(s);
        let mut handles = Vec::new();
        // 8 threads × 100 distinct IPs (so 800 unique) each
        // recording 5 denies — final score for each IP must be 100.
        for tid in 0..8u32 {
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                let now = Instant::now();
                for i in 0..100u32 {
                    let octet_a = ((tid * 100 + i) >> 8) as u8;
                    let octet_b = ((tid * 100 + i) & 0xFF) as u8;
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, octet_a, octet_b));
                    for _ in 0..5 {
                        s.record_denied(ip, now);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Spot-check a few — each IP should have score 100 (all denies)
        for tid in 0..8u32 {
            for i in [0, 50, 99].iter() {
                let octet_a = ((tid * 100 + i) >> 8) as u8;
                let octet_b = ((tid * 100 + i) & 0xFF) as u8;
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, octet_a, octet_b));
                assert_eq!(s.score(ip), ThreatScore(100.0), "tid={tid} i={i}");
            }
        }
        cleanup(&name);
    }

    #[test]
    fn cluster_concurrent_record_same_key_no_lost_updates() {
        // H7 regression: many threads hammering the SAME IP must not
        // lose increments. The old insert-based path swapped the value
        // (read→modify→swap), so a worker that read before another's
        // write would clobber that write. update_with CAS-loops the
        // packed value, so every record_* is reflected.
        use std::sync::Arc;
        use std::thread;
        let (s, name) = fresh_scorer("same-key");
        let s = Arc::new(s);

        let threads = 8u32;
        let per_thread = 1000u32;
        let now = Instant::now();

        // ---- IPv4 ----
        let ip4 = ipv4("203.0.113.7");
        let mut handles = Vec::new();
        for _ in 0..threads {
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                for _ in 0..per_thread {
                    s.record_denied(ip4, now);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 8000 denies, but the u16 counter saturates at 65535 — well
        // above 8000, so the exact total is observable with no loss.
        let packed4 = s.read_v4(
            match ip4 {
                IpAddr::V4(v) => v,
                _ => unreachable!(),
            },
            now,
        );
        assert_eq!(
            packed4.denied as u32,
            threads * per_thread,
            "v4: lost increments under same-key contention"
        );
        // All denies → full threat score.
        assert_eq!(s.score(ip4), ThreatScore(100.0));

        // ---- IPv6 ----
        let ip6 = ipv6("2001:db8::dead:beef");
        let mut handles = Vec::new();
        for _ in 0..threads {
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                for _ in 0..per_thread {
                    s.record_denied(ip6, now);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let packed6 = s.read_v6(
            match ip6 {
                IpAddr::V6(v) => v,
                _ => unreachable!(),
            },
            now,
        );
        assert_eq!(
            packed6.denied as u32,
            threads * per_thread,
            "v6: lost increments under same-key contention"
        );
        assert_eq!(s.score(ip6), ThreatScore(100.0));

        cleanup(&name);
    }
}
