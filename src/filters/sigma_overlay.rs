//! V237 — per-rule enable/disable overlay for the bundled WAF/Sigma
//! corpus.
//!
//! The bundled corpus (`rules/sigma/sigma-webserver.toml`, ~562
//! [crate::config::WafRule] entries derived from SigmaHQ) is loaded
//! read-only via `waf.rule_files`. Operators need to silence individual
//! noisy rules without hand-editing (and clobbering) the auto-generated
//! TOML — so we keep a tiny *overlay* file that lists the rule IDs that
//! have been turned **off**.
//!
//! Same design as the honeypot / domain-policy overlays:
//!
//! * One JSON file (default `/var/lib/aegis/sigma-overlay.json`) so the
//!   React panel can toggle a rule and every pingora worker picks it up
//!   — cross-worker, no daemon reload.
//! * Atomic write (tmp + rename) so a worker never reads a half-written
//!   file.
//! * mtime-stamped: [`WafFilter`] stats the file on its existing rule
//!   hot-reload poll and rebuilds the compiled plan when it changes, so
//!   a toggle lands within the same SLA as a rule-file edit.
//!
//! The set is *deny-list* shaped (only disabled IDs are stored) so a
//! fresh install ships with every rule ON and the file is typically
//! empty / absent. Disabled rules are dropped at compile time in
//! [`crate::filters::waf::CompiledRules::build`], so the per-request
//! hot path pays **zero** cost for a disabled rule — exactly like a
//! rule with `mode = "disabled"`.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::RwLock,
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

pub const DEFAULT_OVERLAY_PATH: &str = "/var/lib/aegis/sigma-overlay.json";

/// On-disk shape. `disabled` is the set of WafRule IDs that the
/// operator has switched off. Everything not listed is enabled.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SigmaOverlayState {
    #[serde(default)]
    pub disabled: Vec<String>,
}

/// Live, disk-backed overlay. Cheap to clone-check: holds the disabled
/// set behind an `RwLock` and re-reads the file only when its mtime
/// changes.
pub struct SigmaOverlay {
    path: PathBuf,
    inner: RwLock<HashSet<String>>,
    last_mtime: RwLock<Option<SystemTime>>,
}

impl SigmaOverlay {
    /// Open (or create) the overlay file. A missing file is treated as
    /// "nothing disabled" and is **not** written eagerly — the common
    /// case is an empty overlay, so we avoid touching the disk until an
    /// operator actually disables a rule.
    pub fn open(path: PathBuf) -> Self {
        let (set, mtime) = load(&path);
        Self {
            path,
            inner: RwLock::new(set),
            last_mtime: RwLock::new(mtime),
        }
    }

    /// Open at the default path, honouring `AEGIS_SIGMA_OVERLAY` for
    /// tests / non-root installs.
    pub fn open_default() -> Self {
        let path = std::env::var("AEGIS_SIGMA_OVERLAY")
            .unwrap_or_else(|_| DEFAULT_OVERLAY_PATH.to_string());
        Self::open(PathBuf::from(path))
    }

    /// True iff `rule_id` is currently disabled. Acquires a read lock —
    /// only called at compile time (rule load / reload), never on the
    /// per-request hot path.
    pub fn is_disabled(&self, rule_id: &str) -> bool {
        self.inner.read().unwrap().contains(rule_id)
    }

    /// Snapshot of every disabled rule ID (for the admin "list" API).
    pub fn disabled_ids(&self) -> HashSet<String> {
        self.inner.read().unwrap().clone()
    }

    /// Re-read the overlay from disk iff its mtime changed. Returns
    /// true when the in-memory set was replaced (i.e. the caller should
    /// recompile its rule plan). Cheap no-op when unchanged.
    pub fn refresh(&self) -> bool {
        let current = fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        {
            let cached = self.last_mtime.read().unwrap();
            if *cached == current {
                return false;
            }
        }
        let (set, mtime) = load(&self.path);
        *self.inner.write().unwrap() = set;
        *self.last_mtime.write().unwrap() = mtime;
        true
    }

    /// Set the enabled state of one rule and persist atomically.
    /// `enabled = false` adds the ID to the deny-list; `true` removes
    /// it. No-op (no write) when the state already matches, so repeated
    /// toggles from the panel don't churn the file / mtime.
    pub fn set_enabled(&self, rule_id: &str, enabled: bool) -> anyhow::Result<()> {
        {
            let mut set = self.inner.write().unwrap();
            let changed = if enabled {
                set.remove(rule_id)
            } else {
                set.insert(rule_id.to_string())
            };
            if !changed {
                return Ok(());
            }
            persist(&self.path, &set)?;
        }
        // Refresh our cached mtime so our own write doesn't trigger a
        // redundant reload on the next refresh() poll.
        let mtime = fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        *self.last_mtime.write().unwrap() = mtime;
        Ok(())
    }
}

fn load(path: &Path) -> (HashSet<String>, Option<SystemTime>) {
    let mtime = fs::metadata(path).ok().and_then(|m| m.modified().ok());
    let set = match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<SigmaOverlayState>(&raw)
            .map(|s| s.disabled.into_iter().collect())
            .unwrap_or_default(),
        Err(_) => HashSet::new(),
    };
    (set, mtime)
}

fn persist(path: &Path, set: &HashSet<String>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).ok();
    }
    // Sort for deterministic, diff-friendly output.
    let mut disabled: Vec<String> = set.iter().cloned().collect();
    disabled.sort();
    let state = SigmaOverlayState { disabled };
    let raw = serde_json::to_string_pretty(&state)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, raw)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-sigma-overlay-{}-{}.json",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn fresh_overlay_disables_nothing() {
        let p = tmp();
        let o = SigmaOverlay::open(p.clone());
        assert!(!o.is_disabled("sigma_x__1"));
        assert!(o.disabled_ids().is_empty());
        // No eager write — a never-touched overlay leaves no file.
        assert!(!p.exists());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn toggle_off_then_on_persists() {
        let p = tmp();
        let o = SigmaOverlay::open(p.clone());
        o.set_enabled("sigma_x__1", false).unwrap();
        assert!(o.is_disabled("sigma_x__1"));
        assert!(p.exists());

        // Re-open from disk: state survives.
        let o2 = SigmaOverlay::open(p.clone());
        assert!(o2.is_disabled("sigma_x__1"));

        o.set_enabled("sigma_x__1", true).unwrap();
        assert!(!o.is_disabled("sigma_x__1"));
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn no_op_toggle_does_not_write() {
        let p = tmp();
        let o = SigmaOverlay::open(p.clone());
        // Enabling an already-enabled rule writes nothing.
        o.set_enabled("sigma_x__1", true).unwrap();
        assert!(!p.exists());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn external_edit_picked_up_by_refresh() {
        let p = tmp();
        let o = SigmaOverlay::open(p.clone());
        assert!(!o.is_disabled("sigma_y__2"));
        // Simulate another worker writing the overlay.
        let mut set = HashSet::new();
        set.insert("sigma_y__2".to_string());
        persist(&p, &set).unwrap();
        // mtime changed → refresh returns true and picks up the edit.
        assert!(o.refresh());
        assert!(o.is_disabled("sigma_y__2"));
        // Idempotent: second refresh sees no change.
        assert!(!o.refresh());
        let _ = fs::remove_file(&p);
    }
}
