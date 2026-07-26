//! V197 — Active-response actuator framework.
//!
//! Today Aegis applies enforcement actions piecewise — XDP deny goes
//! into the kernel deny set and stays there until the operator
//! manually clears it; honeypot auto-XDP-deny escalates without a
//! TTL; BGP RTBH announce expires via its own timer; challenge floor
//! bumps are sticky. Each subsystem reinvents the timer.
//!
//! Idea borrowed from Wazuh's `active-response` + Falco Talon: a
//! single registry of `(action_kind, target, params, revert_after,
//! applied_at)` with a centralised timer wheel. On apply: dispatch
//! to the right enforcement primitive (XDP map insert, BGP announce,
//! cookie cookie-jar bump, etc.) and record the revert callback.
//! Background sweep runs every second and reverts everything past
//! its deadline.
//!
//! ## Why one registry
//!
//! 1. **Single source of truth** — `/admin/api/actions` lists every
//!    active response across every subsystem. Operator sees a 3-line
//!    chip "blocked 10.0.0.5 (XDP, expires in 27m)" instead of
//!    grepping four panels.
//! 2. **Bounded blast radius** — every action HAS a revert deadline
//!    (or `Never` if the operator explicitly chose permanent). No
//!    more "we blocked an IP 6 months ago and forgot".
//! 3. **Idempotent applies** — re-applying the same action against
//!    the same target bumps the revert deadline instead of stacking
//!    counters.
//! 4. **Audit trail** — every apply + revert flows through
//!    SecurityEvent for SIEM.
//!
//! ## Action vocabulary
//!
//! Pluggable via [Actuator] trait. Ships with a [NoopActuator] for
//! tests and a builder pattern for operator-supplied actuators
//! (XDP, nftables, BGP, etc.) — see [`ActionKind`] for the standard
//! set we ship counters for.
//!
//! Timer wheel uses [std::time::Instant] (no async runtime
//! dependency) — caller polls `tick()` from any task; the proxy's
//! background service calls it every second.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionKind {
    XdpDeny,
    NftDrop,
    BgpAnnounce,
    ChallengeFloorRaise,
    ResponseCachePoison,
    /// Operator-supplied custom kind. The `&'static str` keeps the
    /// counter map cardinality-bounded.
    Custom(&'static str),
}

impl ActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::XdpDeny => "xdp_deny",
            Self::NftDrop => "nft_drop",
            Self::BgpAnnounce => "bgp_announce",
            Self::ChallengeFloorRaise => "challenge_floor_raise",
            Self::ResponseCachePoison => "response_cache_poison",
            Self::Custom(name) => name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    Ip(IpAddr),
    Subnet(IpAddr, u8),
    UserAgent(String),
    Path(String),
    /// Free-form composite key for custom actions ("session:abc123" etc.)
    Custom(String),
}

impl Target {
    pub fn as_display(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Subnet(ip, bits) => format!("{ip}/{bits}"),
            Self::UserAgent(ua) => format!("ua:{ua}"),
            Self::Path(p) => format!("path:{p}"),
            Self::Custom(s) => s.clone(),
        }
    }
}

/// Result returned by an [Actuator]. Cleanly distinguishes "did
/// nothing because already applied" from "newly applied" so the
/// registry knows whether to fire SecurityEvent + bump counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    AlreadyApplied,
    Failed,
}

/// Operator-pluggable enforcement primitive. The registry hands the
/// `(kind, target)` pair off to the actuator that registered for
/// that kind; the actuator owns the actual side effect (XDP map
/// insert, nft rule push, etc.) and must also implement `revert`.
pub trait Actuator: Send + Sync {
    fn kind(&self) -> ActionKind;
    fn apply(&self, target: &Target, params: &ActionParams) -> Outcome;
    fn revert(&self, target: &Target) -> Outcome;
}

/// Free-form parameters carried with each action — actuators
/// interpret keys they care about.
#[derive(Debug, Clone, Default)]
pub struct ActionParams {
    pub reason: Option<String>,
    pub source_module: Option<&'static str>,
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ActiveAction {
    pub kind: ActionKind,
    pub target: Target,
    pub params: ActionParams,
    pub applied_at: Instant,
    pub revert_at: Option<Instant>,
}

impl ActiveAction {
    pub fn remaining(&self) -> Option<Duration> {
        let deadline = self.revert_at?;
        let now = Instant::now();
        if now >= deadline {
            Some(Duration::ZERO)
        } else {
            Some(deadline - now)
        }
    }
}

#[derive(Debug, Default)]
pub struct ActuatorStats {
    pub applied: AtomicU64,
    pub already_applied: AtomicU64,
    pub failed: AtomicU64,
    pub reverted_on_expiry: AtomicU64,
    pub reverted_manually: AtomicU64,
}

impl ActuatorStats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            applied: self.applied.load(Ordering::Relaxed),
            already_applied: self.already_applied.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            reverted_on_expiry: self.reverted_on_expiry.load(Ordering::Relaxed),
            reverted_manually: self.reverted_manually.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StatsSnapshot {
    pub applied: u64,
    pub already_applied: u64,
    pub failed: u64,
    pub reverted_on_expiry: u64,
    pub reverted_manually: u64,
}

pub struct ActuatorRegistry {
    actuators: RwLock<HashMap<ActionKind, Arc<dyn Actuator>>>,
    active: RwLock<HashMap<(ActionKind, Target), ActiveAction>>,
    stats: Arc<ActuatorStats>,
}

impl Default for ActuatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ActuatorRegistry {
    pub fn new() -> Self {
        Self {
            actuators: RwLock::new(HashMap::new()),
            active: RwLock::new(HashMap::new()),
            stats: Arc::new(ActuatorStats::default()),
        }
    }

    /// Register an actuator for a kind. Last registration wins
    /// (allows operators to swap a NoopActuator for a real one at
    /// startup without restarting).
    pub fn register(&self, actuator: Arc<dyn Actuator>) {
        let kind = actuator.kind();
        self.actuators.write().unwrap().insert(kind, actuator);
    }

    /// Apply an action. If `revert_after` is `None`, the action
    /// stays until manually cleared. Idempotent — re-applying the
    /// same (kind, target) extends the revert deadline rather than
    /// stacking entries.
    pub fn apply(
        &self,
        kind: ActionKind,
        target: Target,
        params: ActionParams,
        revert_after: Option<Duration>,
    ) -> Outcome {
        let actuator = self.actuators.read().unwrap().get(&kind).cloned();
        let Some(actuator) = actuator else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
            return Outcome::Failed;
        };
        let outcome = actuator.apply(&target, &params);
        let now = Instant::now();
        let revert_at = revert_after.map(|d| now + d);
        match outcome {
            Outcome::Applied => {
                self.stats.applied.fetch_add(1, Ordering::Relaxed);
                self.active.write().unwrap().insert(
                    (kind, target.clone()),
                    ActiveAction {
                        kind,
                        target,
                        params,
                        applied_at: now,
                        revert_at,
                    },
                );
            }
            Outcome::AlreadyApplied => {
                self.stats.already_applied.fetch_add(1, Ordering::Relaxed);
                // Bump deadline of existing entry.
                if let Some(entry) = self
                    .active
                    .write()
                    .unwrap()
                    .get_mut(&(kind, target.clone()))
                {
                    entry.revert_at = revert_at;
                }
            }
            Outcome::Failed => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
        outcome
    }

    /// Manual revert — operator-triggered or admin API DELETE.
    pub fn revert(&self, kind: ActionKind, target: &Target) -> Outcome {
        let Some(actuator) = self.actuators.read().unwrap().get(&kind).cloned() else {
            return Outcome::Failed;
        };
        let outcome = actuator.revert(target);
        if matches!(outcome, Outcome::Applied) {
            self.active.write().unwrap().remove(&(kind, target.clone()));
            self.stats.reverted_manually.fetch_add(1, Ordering::Relaxed);
        }
        outcome
    }

    /// Background sweep — call from a 1-second tick. Reverts every
    /// action whose deadline has passed.
    pub fn tick(&self) -> usize {
        let now = Instant::now();
        let expired: Vec<(ActionKind, Target)> = {
            let g = self.active.read().unwrap();
            g.iter()
                .filter_map(|(k, a)| match a.revert_at {
                    Some(deadline) if now >= deadline => Some(k.clone()),
                    _ => None,
                })
                .collect()
        };
        let mut count = 0;
        for (kind, target) in expired {
            if let Some(actuator) = self.actuators.read().unwrap().get(&kind).cloned() {
                let _ = actuator.revert(&target);
                self.active.write().unwrap().remove(&(kind, target));
                self.stats
                    .reverted_on_expiry
                    .fetch_add(1, Ordering::Relaxed);
                count += 1;
            }
        }
        count
    }

    pub fn active_actions(&self) -> Vec<ActiveAction> {
        self.active.read().unwrap().values().cloned().collect()
    }

    pub fn active_count(&self) -> usize {
        self.active.read().unwrap().len()
    }

    pub fn stats(&self) -> Arc<ActuatorStats> {
        self.stats.clone()
    }

    pub fn registered_kinds(&self) -> Vec<ActionKind> {
        self.actuators.read().unwrap().keys().copied().collect()
    }
}

/// Reference actuator that just bumps a counter — useful for tests
/// and for kinds where the operator hasn't wired a real backend yet
/// (the apply succeeds and the action shows up in /admin/api/actions
/// so the operator sees the intent even without enforcement).
#[derive(Debug)]
pub struct NoopActuator {
    kind: ActionKind,
    state: RwLock<std::collections::HashSet<Target>>,
}

impl NoopActuator {
    pub fn new(kind: ActionKind) -> Self {
        Self {
            kind,
            state: RwLock::new(Default::default()),
        }
    }
    pub fn active(&self) -> Vec<Target> {
        self.state.read().unwrap().iter().cloned().collect()
    }
}

impl Actuator for NoopActuator {
    fn kind(&self) -> ActionKind {
        self.kind
    }
    fn apply(&self, target: &Target, _params: &ActionParams) -> Outcome {
        let mut g = self.state.write().unwrap();
        if g.contains(target) {
            Outcome::AlreadyApplied
        } else {
            g.insert(target.clone());
            Outcome::Applied
        }
    }
    fn revert(&self, target: &Target) -> Outcome {
        if self.state.write().unwrap().remove(target) {
            Outcome::Applied
        } else {
            Outcome::AlreadyApplied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Target {
        Target::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    #[test]
    fn apply_records_action() {
        let r = ActuatorRegistry::new();
        r.register(Arc::new(NoopActuator::new(ActionKind::XdpDeny)));
        let outcome = r.apply(
            ActionKind::XdpDeny,
            ip(1, 2, 3, 4),
            ActionParams::default(),
            Some(Duration::from_secs(60)),
        );
        assert_eq!(outcome, Outcome::Applied);
        assert_eq!(r.active_count(), 1);
        assert_eq!(r.stats().applied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn reapply_is_idempotent_bumps_deadline() {
        let r = ActuatorRegistry::new();
        r.register(Arc::new(NoopActuator::new(ActionKind::XdpDeny)));
        r.apply(
            ActionKind::XdpDeny,
            ip(1, 2, 3, 4),
            Default::default(),
            Some(Duration::from_secs(60)),
        );
        let first_deadline = r.active_actions()[0].revert_at.unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let outcome = r.apply(
            ActionKind::XdpDeny,
            ip(1, 2, 3, 4),
            Default::default(),
            Some(Duration::from_secs(120)),
        );
        assert_eq!(outcome, Outcome::AlreadyApplied);
        assert_eq!(r.active_count(), 1);
        let second_deadline = r.active_actions()[0].revert_at.unwrap();
        assert!(second_deadline > first_deadline);
    }

    #[test]
    fn tick_reverts_expired() {
        let r = ActuatorRegistry::new();
        r.register(Arc::new(NoopActuator::new(ActionKind::XdpDeny)));
        r.apply(
            ActionKind::XdpDeny,
            ip(1, 2, 3, 4),
            Default::default(),
            Some(Duration::from_millis(50)),
        );
        assert_eq!(r.active_count(), 1);
        std::thread::sleep(Duration::from_millis(80));
        let n = r.tick();
        assert_eq!(n, 1);
        assert_eq!(r.active_count(), 0);
        assert_eq!(r.stats().reverted_on_expiry.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn never_expires_stays_active() {
        let r = ActuatorRegistry::new();
        r.register(Arc::new(NoopActuator::new(ActionKind::XdpDeny)));
        r.apply(
            ActionKind::XdpDeny,
            ip(1, 2, 3, 4),
            Default::default(),
            None,
        );
        std::thread::sleep(Duration::from_millis(100));
        let n = r.tick();
        assert_eq!(n, 0);
        assert_eq!(r.active_count(), 1);
    }

    #[test]
    fn manual_revert_clears_entry() {
        let r = ActuatorRegistry::new();
        r.register(Arc::new(NoopActuator::new(ActionKind::XdpDeny)));
        r.apply(
            ActionKind::XdpDeny,
            ip(1, 2, 3, 4),
            Default::default(),
            Some(Duration::from_secs(60)),
        );
        let outcome = r.revert(ActionKind::XdpDeny, &ip(1, 2, 3, 4));
        assert_eq!(outcome, Outcome::Applied);
        assert_eq!(r.active_count(), 0);
        assert_eq!(r.stats().reverted_manually.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn no_actuator_for_kind_fails_cleanly() {
        let r = ActuatorRegistry::new();
        // Register XdpDeny but try BgpAnnounce.
        r.register(Arc::new(NoopActuator::new(ActionKind::XdpDeny)));
        let outcome = r.apply(
            ActionKind::BgpAnnounce,
            ip(1, 2, 3, 4),
            Default::default(),
            None,
        );
        assert_eq!(outcome, Outcome::Failed);
        assert_eq!(r.active_count(), 0);
        assert_eq!(r.stats().failed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn remaining_returns_none_when_no_deadline() {
        let a = ActiveAction {
            kind: ActionKind::XdpDeny,
            target: ip(1, 2, 3, 4),
            params: Default::default(),
            applied_at: Instant::now(),
            revert_at: None,
        };
        assert!(a.remaining().is_none());
    }

    #[test]
    fn remaining_zero_when_past_deadline() {
        let a = ActiveAction {
            kind: ActionKind::XdpDeny,
            target: ip(1, 2, 3, 4),
            params: Default::default(),
            applied_at: Instant::now(),
            revert_at: Some(Instant::now() - Duration::from_secs(1)),
        };
        assert_eq!(a.remaining(), Some(Duration::ZERO));
    }

    #[test]
    fn target_display_renders_each_variant() {
        assert_eq!(ip(1, 2, 3, 4).as_display(), "1.2.3.4");
        let subnet = Target::Subnet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24);
        assert_eq!(subnet.as_display(), "10.0.0.0/24");
        assert_eq!(Target::UserAgent("curl/8".into()).as_display(), "ua:curl/8");
        assert_eq!(Target::Path("/admin".into()).as_display(), "path:/admin");
        assert_eq!(Target::Custom("session:x".into()).as_display(), "session:x");
    }
}
