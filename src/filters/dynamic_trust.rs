//! Reputation-driven dynamic trust promotion.
//!
//! Amplifies the value of `BypassMatcher` by auto-promoting IPs that
//! have demonstrated clean behaviour over a window. Production traffic
//! gets the bypass-fast-path automatically without operators having to
//! enumerate trusted sources.
//!
//! Algorithm:
//!   1. On every Allow response, increment `clean_count` for the IP.
//!   2. Once `clean_count >= min_clean_requests` AND the run started
//!      within `trust_window` AND there have been no denies in the
//!      same window → mark the IP as trusted for `trust_ttl_secs`.
//!   3. On any Deny / Challenge response → immediately demote, reset
//!      `clean_count`, and clear `trusted_until`. A single attack
//!      attempt cancels accumulated reputation.
//!   4. Trust expires automatically at `trusted_until`; the next
//!      request from the IP starts a fresh observation window.
//!
//! Safety properties:
//!   - **No false-trust amplification**: an attacker can't ride a
//!     trust window because the first attack demotes immediately.
//!     They'd need to send N legitimate requests *and* then attack
//!     within TTL to gain even one bypassed attack.
//!   - **Bounded memory**: capped by `max_trusted` LRU eviction.
//!   - **Off by default**: disabled until operator opts in. Keeps
//!     deployment-safe rollout.
//!
//! The integration in `ProxyHttpHandler` checks `is_trusted(ip)` in
//! the same conditional as `BypassMatcher::matches`. When trust hits,
//! the request skips the full filter pipeline exactly like a static
//! bypass IP would.

use std::{
    net::IpAddr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::config::DynamicTrustConfig;

#[derive(Debug, Clone, Copy)]
struct TrustEntry {
    /// Consecutive allowed responses seen for this IP since the last
    /// reset (any deny resets to 0).
    clean_count: u32,
    /// When the current "clean run" started — used to enforce that
    /// trust only triggers if N clean requests happened within a
    /// reasonable window (defeats slow drip attempts to accumulate
    /// reputation over weeks).
    run_started_at: Instant,
    /// Trust expires at this instant. `None` when not yet trusted.
    trusted_until: Option<Instant>,
    /// Last activity timestamp — used by the LRU evictor.
    last_seen: Instant,
}

pub struct DynamicTrust {
    enabled: bool,
    min_clean_requests: u32,
    trust_window: Duration,
    trust_ttl: Duration,
    max_trusted: usize,
    state: DashMap<IpAddr, TrustEntry>,
    /// Monotonic counter of "ips currently in trusted state" — used to
    /// trigger LRU eviction when over `max_trusted`. Approximate, not
    /// exact (single races allowed). Drives the slow-path cleanup.
    trusted_count: AtomicUsize,
    /// V230 — eviction deferral flag. Hot path sets this when the
    /// `trusted_count` crosses `max_trusted`; a background task (wired
    /// by the caller) checks it and runs `evict_lru` off the request
    /// path. Removes the O(N) full-shard scan from `observe_allowed`.
    needs_evict: AtomicBool,
    /// XDP handle used **only to REVOKE** kernel allow entries, never to
    /// add them. C2: earned dynamic trust is deliberately userspace-only
    /// (see `observe_allowed`), so promotion does NOT push to the kernel
    /// allow map. We still hold the handle so that revocation paths —
    /// `observe_denied`, `cleanup_stale`, `evict_lru` — can pop any IP
    /// from the kernel allow map (defensively cleaning operator entries
    /// or any pre-existing leaked grants), guaranteeing no kernel allow
    /// entry outlives its userspace lifetime.
    xdp: Option<std::sync::Arc<dyn crate::xdp::XdpHandle>>,
}

impl DynamicTrust {
    pub fn new(cfg: &DynamicTrustConfig) -> Self {
        // Env-var override path. Operators (and bench runs) can flip
        // dynamic trust on without editing config. The override only
        // *enables* — it never disables an already-enabled config
        // (so production deployments aren't accidentally weakened by
        // a stray env var).
        //   AEGIS_DYNAMIC_TRUST_ENABLE=1 — turn on
        //   AEGIS_DYNAMIC_TRUST_MIN=<n>  — override min_clean_requests
        //   AEGIS_DYNAMIC_TRUST_WIN=<s>  — override trust_window_secs
        //   AEGIS_DYNAMIC_TRUST_TTL=<s>  — override trust_ttl_secs
        let env_enabled = std::env::var("AEGIS_DYNAMIC_TRUST_ENABLE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let env_min: Option<u32> = std::env::var("AEGIS_DYNAMIC_TRUST_MIN")
            .ok()
            .and_then(|v| v.parse().ok());
        let env_win: Option<u64> = std::env::var("AEGIS_DYNAMIC_TRUST_WIN")
            .ok()
            .and_then(|v| v.parse().ok());
        let env_ttl: Option<u64> = std::env::var("AEGIS_DYNAMIC_TRUST_TTL")
            .ok()
            .and_then(|v| v.parse().ok());
        Self {
            enabled: cfg.enabled || env_enabled,
            min_clean_requests: env_min.unwrap_or(cfg.min_clean_requests).max(1),
            trust_window: Duration::from_secs(env_win.unwrap_or(cfg.trust_window_secs).max(1)),
            trust_ttl: Duration::from_secs(env_ttl.unwrap_or(cfg.trust_ttl_secs).max(1)),
            max_trusted: cfg.max_trusted.max(64),
            // V230 — wider shard fan-out (default is ~16 on most
            // CPUs). Each shard has its own RwLock; with 128 shards
            // the chance two concurrent writers hit the same shard
            // drops ~8×, cutting hot-path contention on the
            // observe_allowed write path. Memory cost is trivial
            // (an extra ~1.5 KiB of empty buckets).
            state: DashMap::with_shard_amount(128),
            trusted_count: AtomicUsize::new(0),
            needs_evict: AtomicBool::new(false),
            xdp: None,
        }
    }

    /// Wire the XDP handle so trust *revocation* can pop IPs from the
    /// kernel allow map. C2: promotion never pushes to the kernel (earned
    /// trust is userspace-only); the handle is used purely on the revoke
    /// paths so no kernel allow entry can outlive its userspace grant.
    /// Optional — when no XDP loaded (e.g. on macOS or with `--no-xdp`),
    /// dynamic_trust still works fully in userspace.
    pub fn with_xdp(mut self, xdp: std::sync::Arc<dyn crate::xdp::XdpHandle>) -> Self {
        self.xdp = Some(xdp);
        self
    }

    /// Cheap pre-check: returns true iff this IP currently holds an
    /// unexpired trust grant. Called on the hot path before each
    /// request — must be lookup-only (no inserts) to stay fast.
    pub fn is_trusted(&self, ip: IpAddr, now: Instant) -> bool {
        if !self.enabled {
            return false;
        }
        match self.state.get(&ip) {
            Some(entry) => entry.trusted_until.map(|t| t > now).unwrap_or(false),
            None => false,
        }
    }

    /// Called after a response that was Allowed (request passed all
    /// filters). Promotes the IP to trusted if its clean-run threshold
    /// is now met.
    ///
    /// Hot-path fast skip: when the IP is already trusted with at
    /// least `trust_ttl / 4` remaining, we don't bother taking the
    /// DashMap write lock. The trust grant is still fresh enough to
    /// survive several more requests without refresh, and skipping
    /// the lock removes a measurable cross-CPU bottleneck for
    /// high-RPS trusted clients.
    pub fn observe_allowed(&self, ip: IpAddr, now: Instant) {
        if !self.enabled {
            return;
        }
        // V230 — peek-then-write. Three fast paths short-circuit
        // before the heavy entry-construction + promotion block:
        //   (a) already trusted with > 25% TTL left → no work
        //   (b) warming up well below threshold → cheap get_mut
        //       update only, skip the promotion conditional
        //   (c) cold IP → fall through to the slow path
        // The first two paths avoid `entry().or_insert(...)` which
        // synthesises a default TrustEntry on every miss; that
        // construction (plus the unconditional write-lock upgrade)
        // is what dominated the hot path before.
        if let Some(entry) = self.state.get(&ip) {
            // (a) Trust refresh skip: still well within trust window.
            if let Some(trusted_until) = entry.trusted_until
                && trusted_until > now
            {
                let remaining = trusted_until.duration_since(now);
                if remaining * 4 > self.trust_ttl {
                    // Still well within trust window — no refresh
                    // needed. Last-seen drift is at most trust_ttl/4
                    // which is fine for the LRU evictor (it ages out
                    // at trust_ttl × 10).
                    return;
                }
            }
            // (b) Warming-up fast path: not trusted, well below
            // threshold, and the run window hasn't expired. A simple
            // counter bump is all we need — no promotion possible.
            let count = entry.clean_count;
            let run_started_at = entry.run_started_at;
            let not_trusted = entry.trusted_until.map(|t| t <= now).unwrap_or(true);
            // Release the read shard before requesting the write
            // shard — DashMap will deadlock if both are held on the
            // same shard.
            drop(entry);
            if not_trusted
                && count.saturating_add(1) < self.min_clean_requests
                && now.duration_since(run_started_at) <= self.trust_window
            {
                // Per-shard write lock, but no entry construction
                // and no promotion branch. Cheap.
                self.state.entry(ip).and_modify(|e| {
                    e.last_seen = now;
                    e.clean_count = e.clean_count.saturating_add(1);
                });
                return;
            }
        }
        // Slow path: needs full entry mutation (cold IP, near-threshold
        // increment, expired window restart, or trust refresh).
        let mut entry = self.state.entry(ip).or_insert(TrustEntry {
            clean_count: 0,
            run_started_at: now,
            trusted_until: None,
            last_seen: now,
        });
        entry.last_seen = now;
        entry.clean_count = entry.clean_count.saturating_add(1);

        // Restart the observation window if the existing run is older
        // than `trust_window`. Prevents an attacker from accumulating
        // trust by drip-feeding clean traffic over hours.
        if now.duration_since(entry.run_started_at) > self.trust_window {
            entry.run_started_at = now;
            entry.clean_count = 1;
            return;
        }

        if entry.clean_count >= self.min_clean_requests {
            let was_untrusted = entry.trusted_until.map(|t| t <= now).unwrap_or(true);
            entry.trusted_until = Some(now + self.trust_ttl);
            if was_untrusted {
                let count = self.trusted_count.fetch_add(1, Ordering::Relaxed);
                // C2 — Earned dynamic trust stays USERSPACE-only and is
                // deliberately NOT pushed into the kernel XDP allow map.
                //
                // The XDP allow map is a line-rate kernel fast-pass: a
                // matching packet skips the *entire* downstream pipeline
                // — deny list, rate limiting, SYN protection, and the AC
                // WAF scan. Promoting an earned-trust IP into it would
                // mean that, once reputation is gained, subsequent
                // requests can never be inspected again, so trust could
                // no longer self-correct: `observe_denied` (and the WAF)
                // would never see the traffic to revoke it, and an
                // attacker who built reputation then attacked would ride
                // the kernel bypass indefinitely.
                //
                // Keeping promotion userspace-only means `is_trusted`
                // still grants the bypass-fast-path in
                // `ProxyHttpHandler`, but the WAF and `observe_denied`
                // continue to run so a single bad request demotes the IP.
                // The kernel allow map is reserved exclusively for
                // operator-curated STATIC bypass entries.
                // V230 — defer LRU eviction to a background task.
                // Previously this ran an O(N) full-shard scan on the
                // request path whenever we crossed the cap; now we
                // just flag and let the caller's housekeeping loop
                // pick it up via `take_evict_request()`.
                if count + 1 > self.max_trusted {
                    self.needs_evict.store(true, Ordering::Relaxed);
                }
            }
        }
    }

    /// Called after a response that was Denied or Challenged. Any
    /// single bad request immediately revokes trust — accumulated
    /// reputation cannot shield even one attack attempt.
    pub fn observe_denied(&self, ip: IpAddr, now: Instant) {
        if !self.enabled {
            return;
        }
        // V230 — short-circuit on unseen IPs. The vast majority of
        // first-time attackers have never been observed at all (no
        // prior allowed request to build state), so there is nothing
        // to reset. `contains_key` takes a read shard lock; skipping
        // the otherwise-unconditional write shard lock removes a
        // per-deny cross-CPU bounce on attack traffic.
        if !self.state.contains_key(&ip) {
            return;
        }
        if let Some(mut entry) = self.state.get_mut(&ip) {
            let was_trusted = entry.trusted_until.map(|t| t > now).unwrap_or(false);
            entry.trusted_until = None;
            entry.clean_count = 0;
            entry.run_started_at = now;
            entry.last_seen = now;
            if was_trusted {
                self.trusted_count.fetch_sub(1, Ordering::Relaxed);
                // Phase 3X.3 — trust revoked → remove from kernel
                // allow set so the IP goes back to full XDP scrutiny.
                drop(entry);
                if let Some(xdp) = &self.xdp {
                    let _ = xdp.unallow(ip);
                }
            }
        }
    }

    /// Cleanup entries that haven't been seen recently (10× trust TTL).
    /// Background task calls this periodically; keeps memory bounded
    /// even for hosts that see millions of unique IPs.
    pub fn cleanup_stale(&self, now: Instant) {
        let stale_threshold = self.trust_ttl * 10;
        let mut evicted_trusted = 0;
        // C2 — collect IPs whose (currently-trusted) entry is being
        // dropped so we can mirror `observe_denied` and pop them from
        // the kernel XDP allow map. Without this, a TTL/staleness
        // eviction would leave a kernel allow entry alive after the
        // userspace grant is gone — a leaked kernel bypass. This also
        // defensively cleans any pre-existing leaked entries.
        let mut revoke: Vec<IpAddr> = Vec::new();
        self.state.retain(|ip, e| {
            let alive = now.duration_since(e.last_seen) < stale_threshold;
            if !alive {
                // Decrement the live-trusted gauge only for entries that
                // are *currently* within their TTL (matches the rest of
                // the accounting), but revoke the kernel allow entry for
                // ANY entry that was ever promoted — a TTL-expired-but-
                // not-yet-cleaned entry may still hold a leaked kernel
                // allow because the userspace TTL expiry never popped it.
                if e.trusted_until.map(|t| t > now).unwrap_or(false) {
                    evicted_trusted += 1;
                }
                if e.trusted_until.is_some() {
                    revoke.push(*ip);
                }
            }
            alive
        });
        if evicted_trusted > 0 {
            self.trusted_count
                .fetch_sub(evicted_trusted, Ordering::Relaxed);
        }
        if let Some(xdp) = &self.xdp {
            for ip in revoke {
                let _ = xdp.unallow(ip);
            }
        }
    }

    /// V230 — background-eviction entry point. Returns `true` and
    /// clears the flag if the hot path has signalled that we are over
    /// the `max_trusted` cap; the caller's housekeeping task then
    /// invokes `evict_lru` outside the request path. Returns `false`
    /// when no eviction is pending — keeps the polling loop cheap.
    pub fn take_evict_request(&self) -> bool {
        self.needs_evict.swap(false, Ordering::Relaxed)
    }

    /// V230 — public so the background housekeeping task can drive
    /// eviction. Synchronous callers should prefer `take_evict_request`
    /// + `evict_lru` to keep the O(N) scan off the hot path.
    pub fn evict_lru_now(&self, now: Instant) {
        self.evict_lru(now);
    }

    /// LRU eviction triggered when `trusted_count` exceeds `max_trusted`.
    /// Removes the single oldest-last-seen trusted entry. Cheap because
    /// it scans only enough to find one victim.
    fn evict_lru(&self, _now: Instant) {
        let mut oldest: Option<(IpAddr, Instant)> = None;
        for kv in self.state.iter() {
            if kv.value().trusted_until.is_some() {
                match oldest {
                    Some((_, t)) if t <= kv.value().last_seen => {}
                    _ => oldest = Some((*kv.key(), kv.value().last_seen)),
                }
            }
        }
        if let Some((ip, _)) = oldest
            && let Some(mut e) = self.state.get_mut(&ip)
            && e.trusted_until.is_some()
        {
            e.trusted_until = None;
            self.trusted_count.fetch_sub(1, Ordering::Relaxed);
            // C2 — mirror `observe_denied`: the userspace grant is gone,
            // so pop the IP from the kernel XDP allow map too. Drop the
            // write guard first to avoid holding the shard lock across
            // the xdp call. Without this an LRU eviction would leak a
            // kernel allow entry past its userspace lifetime.
            drop(e);
            if let Some(xdp) = &self.xdp {
                let _ = xdp.unallow(ip);
            }
        }
    }

    /// Diagnostic: number of currently-trusted IPs. Approximate (races
    /// between observe and cleanup can drift by single digits).
    pub fn trusted_count(&self) -> usize {
        self.trusted_count.load(Ordering::Relaxed)
    }

    /// Diagnostic for admin dashboards.
    pub fn snapshot(&self) -> Vec<(IpAddr, u32, bool)> {
        self.state
            .iter()
            .map(|kv| {
                (
                    *kv.key(),
                    kv.value().clean_count,
                    kv.value().trusted_until.is_some(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    /// Test double for `XdpHandle` that records how many times each
    /// allow/unallow operation is invoked. Used to assert that earned
    /// dynamic trust never touches the kernel allow map (C2), and that
    /// eviction/staleness paths do revoke leaked kernel entries.
    #[derive(Default)]
    struct CountingXdp {
        allow_v4: AtomicUsize,
        allow_v6: AtomicUsize,
        unallow: AtomicUsize,
    }

    impl crate::xdp::XdpHandle for CountingXdp {
        fn deny_v4(&self, _: Ipv4Addr) -> anyhow::Result<()> {
            Ok(())
        }
        fn deny_v6(&self, _: Ipv6Addr) -> anyhow::Result<()> {
            Ok(())
        }
        fn undeny(&self, _: IpAddr) -> anyhow::Result<()> {
            Ok(())
        }
        fn allow_v4(&self, _: Ipv4Addr) -> anyhow::Result<()> {
            self.allow_v4.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn allow_v6(&self, _: Ipv6Addr) -> anyhow::Result<()> {
            self.allow_v6.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn unallow(&self, _: IpAddr) -> anyhow::Result<()> {
            self.unallow.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn set_rate_config(&self, _: u64, _: u64, _: u64, _: bool) -> anyhow::Result<()> {
            Ok(())
        }
        fn counters(&self) -> anyhow::Result<crate::xdp::XdpCounters> {
            Ok(crate::xdp::XdpCounters::default())
        }
    }

    fn cfg(min: u32, win: u64, ttl: u64) -> DynamicTrustConfig {
        DynamicTrustConfig {
            enabled: true,
            min_clean_requests: min,
            trust_window_secs: win,
            trust_ttl_secs: ttl,
            max_trusted: 1024,
        }
    }

    #[test]
    fn disabled_never_trusts() {
        let c = DynamicTrustConfig {
            enabled: false,
            ..cfg(5, 60, 60)
        };
        let t = DynamicTrust::new(&c);
        let ip = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        for _ in 0..100 {
            t.observe_allowed(ip, now);
        }
        assert!(!t.is_trusted(ip, now));
    }

    #[test]
    fn promotes_after_threshold() {
        let t = DynamicTrust::new(&cfg(5, 60, 60));
        let ip = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        for _ in 0..4 {
            t.observe_allowed(ip, now);
            assert!(!t.is_trusted(ip, now), "must not trust before threshold");
        }
        t.observe_allowed(ip, now);
        assert!(t.is_trusted(ip, now), "must trust at exactly threshold");
    }

    #[test]
    fn single_deny_revokes_trust() {
        let t = DynamicTrust::new(&cfg(3, 60, 60));
        let ip = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        for _ in 0..3 {
            t.observe_allowed(ip, now);
        }
        assert!(t.is_trusted(ip, now));
        t.observe_denied(ip, now);
        assert!(!t.is_trusted(ip, now));
    }

    #[test]
    fn trust_expires_after_ttl() {
        let t = DynamicTrust::new(&cfg(2, 60, 5));
        let ip = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        t.observe_allowed(ip, now);
        t.observe_allowed(ip, now);
        assert!(t.is_trusted(ip, now));
        let later = now + Duration::from_secs(10);
        assert!(!t.is_trusted(ip, later));
    }

    #[test]
    fn slow_drip_does_not_promote_across_windows() {
        // Threshold 10, window 30s. Send 5 requests at t=0, then 5
        // more at t=60s (outside window) — must NOT trust because the
        // run resets when the window expires.
        let t = DynamicTrust::new(&cfg(10, 30, 60));
        let ip = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        for _ in 0..5 {
            t.observe_allowed(ip, now);
        }
        let later = now + Duration::from_secs(60);
        for _ in 0..4 {
            t.observe_allowed(ip, later);
        }
        // 4 < 10, even after window reset
        assert!(!t.is_trusted(ip, later));
    }

    #[test]
    fn after_demote_can_be_re_promoted() {
        let t = DynamicTrust::new(&cfg(3, 60, 60));
        let ip = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        for _ in 0..3 {
            t.observe_allowed(ip, now);
        }
        assert!(t.is_trusted(ip, now));
        t.observe_denied(ip, now);
        assert!(!t.is_trusted(ip, now));
        for _ in 0..3 {
            t.observe_allowed(ip, now);
        }
        assert!(t.is_trusted(ip, now));
    }

    #[test]
    fn cleanup_drops_stale_entries() {
        let t = DynamicTrust::new(&cfg(2, 60, 60));
        let ip = "9.9.9.9".parse().unwrap();
        let now = Instant::now();
        t.observe_allowed(ip, now);
        t.observe_allowed(ip, now);
        let later = now + Duration::from_secs(60 * 60); // far future
        t.cleanup_stale(later);
        assert!(!t.is_trusted(ip, later));
        assert_eq!(t.snapshot().len(), 0);
    }

    #[test]
    fn promotion_does_not_push_to_kernel_allow_map() {
        // C2 — earned dynamic trust must stay userspace-only: crossing
        // the promotion threshold must NOT invoke the XDP allow path,
        // otherwise the kernel fast-pass would skip the WAF and deny
        // checks and trust could never self-correct.
        let xdp = Arc::new(CountingXdp::default());
        let t = DynamicTrust::new(&cfg(3, 60, 60)).with_xdp(xdp.clone());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        for _ in 0..3 {
            t.observe_allowed(ip, now);
        }
        assert!(
            t.is_trusted(ip, now),
            "promotion still grants userspace trust"
        );
        assert_eq!(
            xdp.allow_v4.load(Ordering::Relaxed),
            0,
            "promotion must NOT call xdp.allow_v4"
        );
        assert_eq!(
            xdp.allow_v6.load(Ordering::Relaxed),
            0,
            "promotion must NOT call xdp.allow_v6"
        );

        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        for _ in 0..3 {
            t.observe_allowed(ip6, now);
        }
        assert!(t.is_trusted(ip6, now));
        assert_eq!(
            xdp.allow_v4.load(Ordering::Relaxed),
            0,
            "v6 promotion must NOT call xdp.allow_v4"
        );
        assert_eq!(
            xdp.allow_v6.load(Ordering::Relaxed),
            0,
            "v6 promotion must NOT call xdp.allow_v6"
        );
    }

    #[test]
    fn cleanup_stale_revokes_kernel_allow_entry() {
        // C2 — a TTL/staleness eviction of a trusted entry must pop the
        // IP from the kernel allow map so no kernel bypass outlives its
        // userspace grant.
        let xdp = Arc::new(CountingXdp::default());
        let t = DynamicTrust::new(&cfg(2, 60, 60)).with_xdp(xdp.clone());
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        let now = Instant::now();
        t.observe_allowed(ip, now);
        t.observe_allowed(ip, now);
        assert!(t.is_trusted(ip, now));
        let later = now + Duration::from_secs(60 * 60); // past 10× TTL
        t.cleanup_stale(later);
        assert_eq!(t.snapshot().len(), 0);
        assert_eq!(
            xdp.unallow.load(Ordering::Relaxed),
            1,
            "stale trusted entry must be revoked from the kernel allow map"
        );
    }

    #[test]
    fn evict_lru_revokes_kernel_allow_entry() {
        // C2 — LRU eviction of the oldest trusted entry must pop it from
        // the kernel allow map.
        let xdp = Arc::new(CountingXdp::default());
        let t = DynamicTrust::new(&cfg(2, 60, 60)).with_xdp(xdp.clone());
        let ip: IpAddr = "5.5.5.5".parse().unwrap();
        let now = Instant::now();
        t.observe_allowed(ip, now);
        t.observe_allowed(ip, now);
        assert!(t.is_trusted(ip, now));
        t.evict_lru_now(now);
        assert!(!t.is_trusted(ip, now), "LRU eviction clears the grant");
        assert_eq!(
            xdp.unallow.load(Ordering::Relaxed),
            1,
            "evicted trusted entry must be revoked from the kernel allow map"
        );
    }

    #[test]
    fn deny_revokes_kernel_allow_entry() {
        // Regression guard for the existing (correct) revoke-on-deny.
        let xdp = Arc::new(CountingXdp::default());
        let t = DynamicTrust::new(&cfg(2, 60, 60)).with_xdp(xdp.clone());
        let ip: IpAddr = "7.7.7.7".parse().unwrap();
        let now = Instant::now();
        t.observe_allowed(ip, now);
        t.observe_allowed(ip, now);
        assert!(t.is_trusted(ip, now));
        t.observe_denied(ip, now);
        assert!(!t.is_trusted(ip, now));
        assert_eq!(xdp.unallow.load(Ordering::Relaxed), 1);
    }
}
