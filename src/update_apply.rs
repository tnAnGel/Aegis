//! V211 — Phase 3: apply-status JSON broker.
//!
//! The applier and the daemon don't share a process; they
//! communicate via an append-only status file (`apply-status.json`)
//! the daemon mtime-polls and serves to the panel. Each phase of an
//! update writes a [Phase] entry with timestamp + message; the panel
//! polls every 1s to stream the log.
//!
//! Layout:
//!
//! ```text
//! /var/lib/aegis/apply-status.json
//!   {
//!     "run_id": "2026-05-22T12-00-00_v0.2.0",
//!     "started_at_unix": 1716000000,
//!     "target_version": "v0.2.0",
//!     "previous_version": "v0.1.0",
//!     "snapshot_id": "2026-05-22T11-59-58_pre-update",
//!     "phases": [
//!       { "ts": 1716000001, "phase": "snapshot",     "msg": "saved 12 files" },
//!       { "ts": 1716000005, "phase": "download",     "msg": "fetched 12 MB" },
//!       { "ts": 1716000006, "phase": "verify",       "msg": "sha256 matched" },
//!       { "ts": 1716000007, "phase": "install",      "msg": "→ releases/v0.2.0/" },
//!       { "ts": 1716000007, "phase": "activate",     "msg": "current → v0.2.0" },
//!       { "ts": 1716000008, "phase": "restart",      "msg": "systemctl restart aegis-pingora.target" },
//!       { "ts": 1716000028, "phase": "health_probe", "msg": "ok after 20s" },
//!       { "ts": 1716000028, "phase": "complete",     "msg": "v0.1.0 → v0.2.0" }
//!     ],
//!     "outcome": "success" | "in_progress" | "reverted" | "failed"
//!   }
//! ```
//!
//! On failure the applier writes a `revert` phase and the new
//! `outcome` so the panel surfaces an actionable error.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const DEFAULT_STATUS_PATH: &str = "/var/lib/aegis/apply-status.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseKind {
    Init,
    Snapshot,
    Download,
    Verify,
    Install,
    Activate,
    Restart,
    HealthProbe,
    Complete,
    Revert,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    InProgress,
    Success,
    Reverted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseEntry {
    pub ts: u64,
    pub phase: PhaseKind,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyStatus {
    pub run_id: String,
    pub started_at_unix: u64,
    pub target_version: String,
    pub previous_version: Option<String>,
    pub snapshot_id: Option<String>,
    pub phases: Vec<PhaseEntry>,
    pub outcome: Outcome,
}

impl ApplyStatus {
    pub fn new(run_id: String, target_version: String, previous_version: Option<String>) -> Self {
        Self {
            started_at_unix: now(),
            run_id,
            target_version,
            previous_version,
            snapshot_id: None,
            phases: vec![PhaseEntry {
                ts: now(),
                phase: PhaseKind::Init,
                msg: "apply started".into(),
            }],
            outcome: Outcome::InProgress,
        }
    }
}

pub struct StatusWriter {
    path: PathBuf,
}

impl StatusWriter {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the initial status atomically (temp + rename).
    pub fn init(&self, status: &ApplyStatus) -> io::Result<()> {
        self.write_atomic(status)
    }

    /// Append a phase entry to the existing status file, atomically.
    pub fn phase(&self, phase: PhaseKind, msg: impl Into<String>) -> io::Result<()> {
        let mut s = self.load()?;
        s.phases.push(PhaseEntry {
            ts: now(),
            phase,
            msg: msg.into(),
        });
        self.write_atomic(&s)
    }

    pub fn set_snapshot_id(&self, id: impl Into<String>) -> io::Result<()> {
        let mut s = self.load()?;
        s.snapshot_id = Some(id.into());
        self.write_atomic(&s)
    }

    pub fn finish(&self, outcome: Outcome, msg: impl Into<String>) -> io::Result<()> {
        let mut s = self.load()?;
        s.outcome = outcome;
        let kind = match outcome {
            Outcome::Success => PhaseKind::Complete,
            Outcome::Reverted => PhaseKind::Revert,
            Outcome::Failed => PhaseKind::Failed,
            Outcome::InProgress => PhaseKind::Init,
        };
        s.phases.push(PhaseEntry {
            ts: now(),
            phase: kind,
            msg: msg.into(),
        });
        self.write_atomic(&s)
    }

    pub fn load(&self) -> io::Result<ApplyStatus> {
        let bytes = fs::read(&self.path)?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::other(format!("status json: {e}")))
    }

    fn write_atomic(&self, status: &ApplyStatus) -> io::Result<()> {
        let text = serde_json::to_string_pretty(status)
            .map_err(|e| io::Error::other(format!("encode status: {e}")))?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&tmp, text)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Reader half — daemon serves the latest status to the panel.
pub struct StatusReader {
    path: PathBuf,
}

impl StatusReader {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn read(&self) -> io::Result<Option<ApplyStatus>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.path)?;
        let s: ApplyStatus = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::other(format!("status json: {e}")))?;
        Ok(Some(s))
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aegis-apply-status-{}-{}.json",
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn init_then_phase_then_finish() {
        let path = temp_path();
        let w = StatusWriter::new(&path);
        let initial = ApplyStatus::new("run-1".into(), "v0.2.0".into(), Some("v0.1.0".into()));
        w.init(&initial).unwrap();
        w.phase(PhaseKind::Download, "12 MB").unwrap();
        w.phase(PhaseKind::Verify, "sha256 ok").unwrap();
        w.finish(Outcome::Success, "v0.1.0 → v0.2.0").unwrap();
        let r = StatusReader::new(&path).read().unwrap().unwrap();
        assert_eq!(r.outcome, Outcome::Success);
        let kinds: Vec<_> = r.phases.iter().map(|p| p.phase).collect();
        assert_eq!(
            kinds,
            vec![
                PhaseKind::Init,
                PhaseKind::Download,
                PhaseKind::Verify,
                PhaseKind::Complete
            ]
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn read_missing_returns_none() {
        let path = temp_path();
        let r = StatusReader::new(&path).read().unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn write_is_atomic_no_partial_files() {
        let path = temp_path();
        let w = StatusWriter::new(&path);
        let s = ApplyStatus::new("r".into(), "v1".into(), None);
        w.init(&s).unwrap();
        // The temp file should be cleaned up by rename().
        let parent = path.parent().unwrap();
        for e in fs::read_dir(parent).unwrap().flatten() {
            let name = e.file_name();
            let s = name.to_string_lossy();
            assert!(!s.contains("tmp.") || !s.contains("aegis-apply-status"));
        }
        fs::remove_file(&path).ok();
    }

    #[test]
    fn snapshot_id_set_via_writer() {
        let path = temp_path();
        let w = StatusWriter::new(&path);
        w.init(&ApplyStatus::new("r".into(), "v1".into(), None))
            .unwrap();
        w.set_snapshot_id("snap-abc").unwrap();
        let r = w.load().unwrap();
        assert_eq!(r.snapshot_id.as_deref(), Some("snap-abc"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn reverted_outcome_renders_revert_phase() {
        let path = temp_path();
        let w = StatusWriter::new(&path);
        w.init(&ApplyStatus::new(
            "r".into(),
            "v1".into(),
            Some("v0".into()),
        ))
        .unwrap();
        w.finish(Outcome::Reverted, "health probe failed → back to v0")
            .unwrap();
        let r = w.load().unwrap();
        assert_eq!(r.outcome, Outcome::Reverted);
        assert!(matches!(r.phases.last().unwrap().phase, PhaseKind::Revert));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn failed_outcome_renders_failed_phase() {
        let path = temp_path();
        let w = StatusWriter::new(&path);
        w.init(&ApplyStatus::new("r".into(), "v1".into(), None))
            .unwrap();
        w.finish(Outcome::Failed, "sha256 mismatch").unwrap();
        let r = w.load().unwrap();
        assert_eq!(r.outcome, Outcome::Failed);
        assert!(matches!(r.phases.last().unwrap().phase, PhaseKind::Failed));
        fs::remove_file(&path).ok();
    }
}
