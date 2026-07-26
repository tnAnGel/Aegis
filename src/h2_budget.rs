//! V182 — Tempesta-style HTTP/2 control-frame budgets.
//!
//! CVE-2023-44487 (Rapid Reset), CVE-2024-27316 (CONTINUATION flood),
//! and the broader "Made You Reset" / "Settings flood" / "Ping flood"
//! family all share a shape: the attacker abuses the cheapness of a
//! specific control frame from the server's perspective. The fix is
//! per-connection budgets enforced *before* the frame reaches the
//! HTTP/2 state machine.
//!
//! Our V111 H2Guard already tracks these counts at the hyper/h2
//! layer; this module factors out the *budget logic* into a tiny
//! state machine that the XDP fast-path can mirror for kernel-side
//! enforcement. Same accounting in two places, single source of
//! truth for thresholds.
//!
//! Frame budgets (defaults — operator-tunable via DSL):
//!
//! | Frame             | Burst | Refill / s | Justification |
//! |-------------------|------:|-----------:|---------------|
//! | RST_STREAM        |    50 |         20 | Rapid Reset   |
//! | SETTINGS          |    10 |          2 | Settings flood|
//! | PING              |    30 |         10 | Ping flood    |
//! | PRIORITY          |   100 |         50 | Priority churn|
//! | GOAWAY            |     3 |          1 | should be rare|
//! | CONTINUATION      |    50 |         20 | CONT flood    |
//!
//! Token-bucket per (conn_id, frame_kind). On bucket empty we return
//! [Verdict::Reject], the caller is responsible for closing the
//! stream / connection. No timers — refill is computed lazily on
//! consume.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

// V230 — FxHash for the per-(conn_id, FrameKind) bucket map. Keys are
// connection-local sequential stream/conn IDs combined with a small
// enum; none of them are attacker-controlled, so SipHash's DoS
// protection is wasted cost. FxHash is materially faster for small
// fixed-size integer-ish keys on the hot consume path.
use rustc_hash::FxHashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    RstStream,
    Settings,
    Ping,
    Priority,
    Goaway,
    Continuation,
}

impl FrameKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RstStream => "rst_stream",
            Self::Settings => "settings",
            Self::Ping => "ping",
            Self::Priority => "priority",
            Self::Goaway => "goaway",
            Self::Continuation => "continuation",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub burst: u32,
    pub refill_per_s: u32,
}

impl Budget {
    pub const fn default_for(kind: FrameKind) -> Self {
        match kind {
            FrameKind::RstStream => Budget {
                burst: 50,
                refill_per_s: 20,
            },
            FrameKind::Settings => Budget {
                burst: 10,
                refill_per_s: 2,
            },
            FrameKind::Ping => Budget {
                burst: 30,
                refill_per_s: 10,
            },
            FrameKind::Priority => Budget {
                burst: 100,
                refill_per_s: 50,
            },
            FrameKind::Goaway => Budget {
                burst: 3,
                refill_per_s: 1,
            },
            FrameKind::Continuation => Budget {
                burst: 50,
                refill_per_s: 20,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Reject,
}

#[derive(Debug)]
struct Bucket {
    tokens: f32,
    last: Instant,
}

impl Bucket {
    fn new(burst: u32) -> Self {
        Self {
            tokens: burst as f32,
            last: Instant::now(),
        }
    }

    fn consume(&mut self, b: Budget, now: Instant) -> Verdict {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f32();
        self.tokens = (self.tokens + elapsed * b.refill_per_s as f32).min(b.burst as f32);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Verdict::Allow
        } else {
            Verdict::Reject
        }
    }
}

pub struct H2BudgetTracker {
    // V230 — FxHashMap: key is (conn_id, FrameKind), both
    // connection-local. No need for SipHash's collision-resistance.
    inner: RwLock<FxHashMap<(u64, FrameKind), Bucket>>,
    overrides: HashMap<FrameKind, Budget>,
}

impl H2BudgetTracker {
    pub fn new() -> Self {
        Self {
            // V230 — FxHashMap::default() in place of HashMap::new().
            inner: RwLock::new(FxHashMap::default()),
            overrides: HashMap::new(),
        }
    }

    pub fn with_override(mut self, kind: FrameKind, budget: Budget) -> Self {
        self.overrides.insert(kind, budget);
        self
    }

    fn budget(&self, kind: FrameKind) -> Budget {
        self.overrides
            .get(&kind)
            .copied()
            .unwrap_or_else(|| Budget::default_for(kind))
    }

    pub fn consume(&self, conn_id: u64, kind: FrameKind) -> Verdict {
        let b = self.budget(kind);
        let mut g = self.inner.write().unwrap();
        let entry = g
            .entry((conn_id, kind))
            .or_insert_with(|| Bucket::new(b.burst));
        entry.consume(b, Instant::now())
    }

    /// Drop all state for a closed connection.
    pub fn drop_conn(&self, conn_id: u64) {
        let mut g = self.inner.write().unwrap();
        g.retain(|(c, _), _| *c != conn_id);
    }

    /// Drop idle conn state (older than `idle`). Background GC.
    pub fn gc(&self, idle: Duration) -> usize {
        let now = Instant::now();
        let mut g = self.inner.write().unwrap();
        let before = g.len();
        g.retain(|_, b| now.saturating_duration_since(b.last) < idle);
        before - g.len()
    }

    pub fn tracked_conns(&self) -> usize {
        let g = self.inner.read().unwrap();
        let mut set = std::collections::HashSet::new();
        for (c, _) in g.keys() {
            set.insert(*c);
        }
        set.len()
    }
}

impl Default for H2BudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rapid_reset_burst_blocked_after_budget() {
        let t = H2BudgetTracker::new();
        let mut allow = 0;
        let mut reject = 0;
        for _ in 0..200 {
            match t.consume(1, FrameKind::RstStream) {
                Verdict::Allow => allow += 1,
                Verdict::Reject => reject += 1,
            }
        }
        assert!((45..=55).contains(&allow), "got allow={allow}");
        assert!(reject >= 145);
    }

    #[test]
    fn settings_floods_clamped_tight() {
        let t = H2BudgetTracker::new();
        let mut allow = 0;
        for _ in 0..100 {
            if let Verdict::Allow = t.consume(2, FrameKind::Settings) {
                allow += 1;
            }
        }
        assert!(allow <= 12, "settings allowed {allow}");
    }

    #[test]
    fn budgets_are_per_connection() {
        let t = H2BudgetTracker::new();
        for _ in 0..50 {
            assert_eq!(t.consume(1, FrameKind::RstStream), Verdict::Allow);
        }
        assert_eq!(t.consume(1, FrameKind::RstStream), Verdict::Reject);
        // Different conn id keeps its own budget.
        assert_eq!(t.consume(2, FrameKind::RstStream), Verdict::Allow);
    }

    #[test]
    fn drop_conn_releases_state() {
        let t = H2BudgetTracker::new();
        t.consume(1, FrameKind::Ping);
        assert_eq!(t.tracked_conns(), 1);
        t.drop_conn(1);
        assert_eq!(t.tracked_conns(), 0);
    }

    #[test]
    fn override_replaces_default() {
        let t = H2BudgetTracker::new().with_override(
            FrameKind::Ping,
            Budget {
                burst: 2,
                refill_per_s: 0,
            },
        );
        assert_eq!(t.consume(1, FrameKind::Ping), Verdict::Allow);
        assert_eq!(t.consume(1, FrameKind::Ping), Verdict::Allow);
        assert_eq!(t.consume(1, FrameKind::Ping), Verdict::Reject);
    }
}
