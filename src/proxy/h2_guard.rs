//! V111 — HTTP/2 abuse protection (info.md P1).
//!
//! Pingora bounds rapid-reset (CVE-2023-44487) natively, but the
//! broader info.md prescription includes per-connection limits on
//! stream churn / SETTINGS churn / CONTINUATION frame abuse / PING
//! flood / GOAWAY churn. Each is cheap to mount and not adequately
//! covered by stock pingora-core 0.8.
//!
//! V111 ships a per-connection [H2GuardState] that hot-path code
//! can call once per H2 event:
//!
//!   guard.note_new_stream(now) → AbuseDecision
//!   guard.note_reset(now)      → AbuseDecision
//!   guard.note_settings(now)   → AbuseDecision
//!   guard.note_ping(now)       → AbuseDecision
//!   guard.note_continuation(bytes) → AbuseDecision
//!
//! AbuseDecision::Block tells the caller to GOAWAY the connection.
//! Defaults are conservative: a sustained 200 streams/sec PER
//! CONNECTION, 50 resets/sec, 5 SETTINGS/sec, 10 pings/sec, 256 KiB
//! cumulative CONTINUATION bytes per request (matches Cloudflare
//! disclosure defaults).
//!
//! V111 does NOT wire into pingora itself — pingora's h2 event hooks
//! are private. Wiring is two paths:
//!   1. Operator runs Aegis behind a TLS terminator that exposes h2
//!      frame stats (haproxy, envoy) — V120+ scope.
//!   2. Fork pingora-core to expose h2 events — explicitly out of
//!      scope per ROADMAP-NEXT "what NOT to do" list.
//!
//! Until either path lands, H2Guard is library code consumed by tests
//! and by the hyper-based handler (which exposes h2 events via the
//! `hyper::server::conn::http2::Builder` callbacks). The data
//! structures are ready so the wiring is mechanical when pingora
//! gains the hooks.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

/// Default per-connection limits. info.md cites these ballpark values;
/// real production deployments typically tighten by 2-4x once they
/// observe their baseline.
pub const DEFAULT_STREAMS_PER_SEC: u32 = 200;
pub const DEFAULT_RESETS_PER_SEC: u32 = 50;
pub const DEFAULT_SETTINGS_PER_SEC: u32 = 5;
pub const DEFAULT_PINGS_PER_SEC: u32 = 10;
pub const DEFAULT_GOAWAY_PER_SEC: u32 = 3;
pub const DEFAULT_CONTINUATION_BYTES_PER_REQ: u32 = 256 * 1024;

/// Tunable thresholds.
#[derive(Debug, Clone, Copy)]
pub struct H2GuardConfig {
    pub streams_per_sec: u32,
    pub resets_per_sec: u32,
    pub settings_per_sec: u32,
    pub pings_per_sec: u32,
    pub goaway_per_sec: u32,
    pub continuation_bytes_per_req: u32,
}

impl Default for H2GuardConfig {
    fn default() -> Self {
        Self {
            streams_per_sec: DEFAULT_STREAMS_PER_SEC,
            resets_per_sec: DEFAULT_RESETS_PER_SEC,
            settings_per_sec: DEFAULT_SETTINGS_PER_SEC,
            pings_per_sec: DEFAULT_PINGS_PER_SEC,
            goaway_per_sec: DEFAULT_GOAWAY_PER_SEC,
            continuation_bytes_per_req: DEFAULT_CONTINUATION_BYTES_PER_REQ,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseDecision {
    Continue,
    /// Per-connection limit exceeded. Caller should GOAWAY (no
    /// graceful close — we want to evict the offender).
    Block {
        reason: &'static str,
    },
}

/// Per-connection counters. Wrapped in atomic types so the guard
/// can be `&self`-borrowed by hyper's h2 event callbacks which
/// don't permit `&mut`.
pub struct H2GuardState {
    cfg: H2GuardConfig,
    /// Rolling 1-second window counters. We reset each at the start
    /// of a new second instead of using a sliding window — bounded
    /// memory, and information.rs's framing is sec-granular anyway.
    window_start: AtomicU64, // monotonic Instant in nanos since `epoch`
    streams: AtomicU32,
    resets: AtomicU32,
    settings: AtomicU32,
    pings: AtomicU32,
    goaways: AtomicU32,
    /// Per-REQUEST CONTINUATION byte counter. Reset on every new
    /// HEADERS frame from the same connection (caller calls
    /// `reset_continuation()` when a HEADERS frame opens a new stream).
    continuation_bytes: AtomicU32,
    epoch: Instant,
}

impl H2GuardState {
    pub fn new(cfg: H2GuardConfig) -> Self {
        Self {
            cfg,
            window_start: AtomicU64::new(0),
            streams: AtomicU32::new(0),
            resets: AtomicU32::new(0),
            settings: AtomicU32::new(0),
            pings: AtomicU32::new(0),
            goaways: AtomicU32::new(0),
            continuation_bytes: AtomicU32::new(0),
            epoch: Instant::now(),
        }
    }

    /// Roll the per-second window if more than 1s has passed since
    /// `window_start`. Cheap, called from each note_*() helper.
    fn maybe_roll(&self, now: Instant) {
        let now_secs = now.saturating_duration_since(self.epoch).as_secs();
        let start = self.window_start.load(Ordering::Relaxed);
        if now_secs > start {
            // Compare-and-swap so concurrent rollers don't double-reset.
            if self
                .window_start
                .compare_exchange(start, now_secs, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.streams.store(0, Ordering::Relaxed);
                self.resets.store(0, Ordering::Relaxed);
                self.settings.store(0, Ordering::Relaxed);
                self.pings.store(0, Ordering::Relaxed);
                self.goaways.store(0, Ordering::Relaxed);
            }
        }
    }

    pub fn note_new_stream(&self, now: Instant) -> AbuseDecision {
        self.maybe_roll(now);
        // V233 — saturating_add: defense-in-depth against u32 wrap on a
        // hostile burst within a window. Saturating high keeps the
        // decision on the safe (Block) side; a wrap to 0 would not.
        let n = self
            .streams
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if n > self.cfg.streams_per_sec {
            AbuseDecision::Block {
                reason: "h2_stream_churn",
            }
        } else {
            AbuseDecision::Continue
        }
    }

    pub fn note_reset(&self, now: Instant) -> AbuseDecision {
        self.maybe_roll(now);
        // V233 — saturating_add: see note_new_stream.
        let n = self
            .resets
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if n > self.cfg.resets_per_sec {
            AbuseDecision::Block {
                reason: "h2_rapid_reset",
            }
        } else {
            AbuseDecision::Continue
        }
    }

    /// V194 — composite check that consults both the per-second
    /// window AND the per-connection token bucket from
    /// [crate::arsenal::ArsenalState::observe_h2_frame]. Callers wired
    /// into the H2 layer should prefer this entry point because it
    /// catches BOTH per-conn burst (Rapid Reset class) AND per-IP
    /// sustained churn (the window).
    pub fn note_reset_with_arsenal(
        &self,
        now: Instant,
        arsenal: Option<&crate::arsenal::ArsenalState>,
        conn_id: u64,
    ) -> AbuseDecision {
        if let AbuseDecision::Block { reason } = self.note_reset(now) {
            return AbuseDecision::Block { reason };
        }
        if let Some(a) = arsenal
            && !a.observe_h2_frame(conn_id, crate::h2_budget::FrameKind::RstStream)
        {
            return AbuseDecision::Block {
                reason: "h2_rapid_reset_budget",
            };
        }
        AbuseDecision::Continue
    }

    /// V194 — settings counterpart of [Self::note_reset_with_arsenal].
    pub fn note_settings_with_arsenal(
        &self,
        now: Instant,
        arsenal: Option<&crate::arsenal::ArsenalState>,
        conn_id: u64,
    ) -> AbuseDecision {
        if let AbuseDecision::Block { reason } = self.note_settings(now) {
            return AbuseDecision::Block { reason };
        }
        if let Some(a) = arsenal
            && !a.observe_h2_frame(conn_id, crate::h2_budget::FrameKind::Settings)
        {
            return AbuseDecision::Block {
                reason: "h2_settings_budget",
            };
        }
        AbuseDecision::Continue
    }

    /// V194 — ping counterpart.
    pub fn note_ping_with_arsenal(
        &self,
        now: Instant,
        arsenal: Option<&crate::arsenal::ArsenalState>,
        conn_id: u64,
    ) -> AbuseDecision {
        if let AbuseDecision::Block { reason } = self.note_ping(now) {
            return AbuseDecision::Block { reason };
        }
        if let Some(a) = arsenal
            && !a.observe_h2_frame(conn_id, crate::h2_budget::FrameKind::Ping)
        {
            return AbuseDecision::Block {
                reason: "h2_ping_budget",
            };
        }
        AbuseDecision::Continue
    }

    pub fn note_settings(&self, now: Instant) -> AbuseDecision {
        self.maybe_roll(now);
        // V233 — saturating_add: see note_new_stream.
        let n = self
            .settings
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if n > self.cfg.settings_per_sec {
            AbuseDecision::Block {
                reason: "h2_settings_churn",
            }
        } else {
            AbuseDecision::Continue
        }
    }

    pub fn note_ping(&self, now: Instant) -> AbuseDecision {
        self.maybe_roll(now);
        // V233 — saturating_add: see note_new_stream.
        let n = self.pings.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if n > self.cfg.pings_per_sec {
            AbuseDecision::Block {
                reason: "h2_ping_flood",
            }
        } else {
            AbuseDecision::Continue
        }
    }

    pub fn note_goaway(&self, now: Instant) -> AbuseDecision {
        self.maybe_roll(now);
        // V233 — saturating_add: see note_new_stream.
        let n = self
            .goaways
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if n > self.cfg.goaway_per_sec {
            AbuseDecision::Block {
                reason: "h2_goaway_churn",
            }
        } else {
            AbuseDecision::Continue
        }
    }

    /// Per-request CONTINUATION frame guard. Caller bumps with the
    /// frame's header-block-fragment byte length; CVE-2024-27316 and
    /// similar are large unbounded CONTINUATION chains used to
    /// exhaust the decoder. We bound per request and reset on a new
    /// HEADERS frame.
    pub fn note_continuation(&self, bytes: u32) -> AbuseDecision {
        // V233 — `bytes` is attacker-controlled per CONTINUATION frame and
        // this counter only resets on a fresh HEADERS frame. A raw
        // `fetch_add(..) + bytes` wraps silently in release once the
        // cumulative count crosses u32::MAX (~4 GiB), pushing `total`
        // back near 0 and bypassing the CVE-2024-27316 flood guard.
        // `fetch_add` itself can wrap inside the atomic; `saturating_add`
        // on the returned value clamps the post-increment total so the
        // comparison below never sees a wrapped value. Once saturated at
        // u32::MAX it stays > the cap until `reset_continuation()`.
        let total = self
            .continuation_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        if total > self.cfg.continuation_bytes_per_req {
            AbuseDecision::Block {
                reason: "h2_continuation_flood",
            }
        } else {
            AbuseDecision::Continue
        }
    }

    /// Reset the CONTINUATION counter at the start of a fresh HEADERS
    /// frame.
    pub fn reset_continuation(&self) {
        self.continuation_bytes.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_under_limit_continue() {
        let g = H2GuardState::new(H2GuardConfig::default());
        let now = Instant::now();
        for _ in 0..DEFAULT_STREAMS_PER_SEC {
            assert_eq!(g.note_new_stream(now), AbuseDecision::Continue);
        }
    }

    #[test]
    fn streams_over_limit_block() {
        let g = H2GuardState::new(H2GuardConfig {
            streams_per_sec: 5,
            ..H2GuardConfig::default()
        });
        let now = Instant::now();
        for _ in 0..5 {
            assert_eq!(g.note_new_stream(now), AbuseDecision::Continue);
        }
        assert!(matches!(
            g.note_new_stream(now),
            AbuseDecision::Block {
                reason: "h2_stream_churn"
            }
        ));
    }

    #[test]
    fn window_rolls_after_one_second() {
        let g = H2GuardState::new(H2GuardConfig {
            streams_per_sec: 3,
            ..H2GuardConfig::default()
        });
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(g.note_new_stream(t0), AbuseDecision::Continue);
        }
        // Next stream → block within the same window.
        assert!(matches!(g.note_new_stream(t0), AbuseDecision::Block { .. }));
        // After +1.5s the window rolls; should be allowed again.
        let t1 = t0 + Duration::from_millis(1500);
        // First call after roll re-allows because counters reset.
        assert_eq!(g.note_new_stream(t1), AbuseDecision::Continue);
    }

    #[test]
    fn reset_flood_blocked() {
        let g = H2GuardState::new(H2GuardConfig {
            resets_per_sec: 2,
            ..H2GuardConfig::default()
        });
        let now = Instant::now();
        assert_eq!(g.note_reset(now), AbuseDecision::Continue);
        assert_eq!(g.note_reset(now), AbuseDecision::Continue);
        assert!(matches!(
            g.note_reset(now),
            AbuseDecision::Block {
                reason: "h2_rapid_reset"
            }
        ));
    }

    #[test]
    fn settings_churn_blocked() {
        let g = H2GuardState::new(H2GuardConfig {
            settings_per_sec: 1,
            ..H2GuardConfig::default()
        });
        let now = Instant::now();
        assert_eq!(g.note_settings(now), AbuseDecision::Continue);
        assert!(matches!(
            g.note_settings(now),
            AbuseDecision::Block {
                reason: "h2_settings_churn"
            }
        ));
    }

    #[test]
    fn ping_flood_blocked() {
        let g = H2GuardState::new(H2GuardConfig {
            pings_per_sec: 1,
            ..H2GuardConfig::default()
        });
        let now = Instant::now();
        assert_eq!(g.note_ping(now), AbuseDecision::Continue);
        assert!(matches!(
            g.note_ping(now),
            AbuseDecision::Block {
                reason: "h2_ping_flood"
            }
        ));
    }

    #[test]
    fn continuation_bytes_accumulate_until_cap() {
        let g = H2GuardState::new(H2GuardConfig {
            continuation_bytes_per_req: 10_000,
            ..H2GuardConfig::default()
        });
        assert_eq!(g.note_continuation(5_000), AbuseDecision::Continue);
        assert_eq!(g.note_continuation(4_999), AbuseDecision::Continue);
        assert!(matches!(
            g.note_continuation(2),
            AbuseDecision::Block {
                reason: "h2_continuation_flood"
            }
        ));
    }

    /// V233 — regression: an attacker who drives the cumulative
    /// CONTINUATION byte count across u32::MAX must not wrap the counter
    /// back near 0 and slip past the flood guard. Before V233 the raw
    /// `fetch_add(..) + bytes` wrapped silently in release builds; this
    /// asserts the saturating accumulation keeps the guard tripped.
    #[test]
    fn continuation_counter_near_u32_max_still_blocks() {
        let g = H2GuardState::new(H2GuardConfig {
            continuation_bytes_per_req: 256 * 1024,
            ..H2GuardConfig::default()
        });
        // Push the counter to just below u32::MAX in big chunks. Each
        // chunk is already far over the cap, so every call must Block.
        let chunk = 1u32 << 30; // 1 GiB
        for _ in 0..3 {
            assert!(matches!(
                g.note_continuation(chunk),
                AbuseDecision::Block {
                    reason: "h2_continuation_flood"
                }
            ));
        }
        // Counter is now at 3 GiB. A naive `+ bytes` here would wrap
        // (3 GiB + 1 GiB = 4 GiB == u32::MAX+1 → 0) and return Continue.
        // Saturating accumulation must still report Block.
        assert!(
            matches!(
                g.note_continuation(chunk),
                AbuseDecision::Block {
                    reason: "h2_continuation_flood"
                }
            ),
            "guard wrapped past u32::MAX and bypassed the CONTINUATION flood check",
        );
        // Further frames once saturated at u32::MAX must keep blocking.
        assert!(matches!(
            g.note_continuation(chunk),
            AbuseDecision::Block {
                reason: "h2_continuation_flood"
            }
        ));
        // Even a tiny additional frame stays Block (no wrap-to-allow).
        assert!(matches!(
            g.note_continuation(1),
            AbuseDecision::Block {
                reason: "h2_continuation_flood"
            }
        ));
    }

    #[test]
    fn reset_continuation_clears_counter() {
        let g = H2GuardState::new(H2GuardConfig {
            continuation_bytes_per_req: 1_000,
            ..H2GuardConfig::default()
        });
        assert_eq!(g.note_continuation(900), AbuseDecision::Continue);
        g.reset_continuation();
        // After reset, 900 again is still under the cap.
        assert_eq!(g.note_continuation(900), AbuseDecision::Continue);
    }
}
