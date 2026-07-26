//! V210 — Phase 2: releases/ directory layout + atomic symlink swap.
//!
//! ```text
//!   /var/lib/aegis/releases/v0.1.0/aegis-pingora
//!   /var/lib/aegis/releases/v0.2.0/aegis-pingora
//!   /var/lib/aegis/current -> releases/v0.2.0     ← atomic symlink
//!   /usr/local/bin/aegis-pingora -> /var/lib/aegis/current/aegis-pingora
//! ```
//!
//! The applier installs new releases under `releases/<version>/`,
//! then flips the `current` symlink via `rename()` — POSIX guarantees
//! atomic replacement of an existing symlink. The
//! `/usr/local/bin/aegis-pingora` symlink doesn't need to move:
//! it's a permanent indirection through `current`.
//!
//! Failure recovery: on health-probe failure post-apply the applier
//! restores `current` to the previous version and restarts.
//!
//! Old releases are GC'd after `keep_releases` (default 3) to bound
//! disk usage; the active release is always preserved regardless.

use std::fs;
use std::io;
use std::os::unix::fs::symlink as unix_symlink;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_RELEASES_ROOT: &str = "/var/lib/aegis/releases";
pub const DEFAULT_CURRENT_LINK: &str = "/var/lib/aegis/current";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseEntry {
    pub version: String,
    pub installed_at_unix: u64,
    pub binary_size: u64,
    pub is_current: bool,
}

pub struct ReleaseLayout {
    releases_root: PathBuf,
    current_link: PathBuf,
    keep_releases: usize,
}

impl ReleaseLayout {
    pub fn new(releases_root: impl Into<PathBuf>, current_link: impl Into<PathBuf>) -> Self {
        Self {
            releases_root: releases_root.into(),
            current_link: current_link.into(),
            keep_releases: 3,
        }
    }

    pub fn with_keep_releases(mut self, n: usize) -> Self {
        self.keep_releases = n.max(1);
        self
    }

    pub fn releases_root(&self) -> &Path {
        &self.releases_root
    }

    pub fn current_link(&self) -> &Path {
        &self.current_link
    }

    pub fn release_dir(&self, version: &str) -> PathBuf {
        self.releases_root.join(version)
    }

    pub fn ensure_root(&self) -> io::Result<()> {
        fs::create_dir_all(&self.releases_root)?;
        Ok(())
    }

    /// Install a binary blob into `releases/<version>/<bin_name>`.
    /// Atomic: writes to a staging name first, then renames.
    pub fn install_binary(
        &self,
        version: &str,
        bin_name: &str,
        bytes: &[u8],
    ) -> io::Result<PathBuf> {
        self.ensure_root()?;
        let dir = self.release_dir(version);
        fs::create_dir_all(&dir)?;
        let final_path = dir.join(bin_name);
        let staging = dir.join(format!(".{bin_name}.staging"));
        fs::write(&staging, bytes)?;
        let mut perms = fs::metadata(&staging)?.permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        fs::set_permissions(&staging, perms)?;
        fs::rename(&staging, &final_path)?;
        Ok(final_path)
    }

    /// Activate `version` by atomically swinging the `current`
    /// symlink. Returns the *previous* version if any (so the
    /// applier knows what to revert to on health-check failure).
    pub fn activate(&self, version: &str) -> io::Result<Option<String>> {
        let target = self.release_dir(version);
        if !target.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("release {version} not installed"),
            ));
        }
        let previous = self.current_version().ok();
        let temp_link = self
            .current_link
            .with_extension(format!("swap-{}", std::process::id()));
        // Remove any prior temp link from a crashed run.
        let _ = fs::remove_file(&temp_link);
        unix_symlink(&target, &temp_link)?;
        fs::rename(&temp_link, &self.current_link)?;
        Ok(previous)
    }

    pub fn current_version(&self) -> io::Result<String> {
        let target = fs::read_link(&self.current_link)?;
        target
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| io::Error::other("current symlink has no version basename"))
    }

    pub fn list(&self) -> io::Result<Vec<ReleaseEntry>> {
        if !self.releases_root.exists() {
            return Ok(Vec::new());
        }
        let current = self.current_version().ok();
        let mut out = Vec::new();
        for e in fs::read_dir(&self.releases_root)? {
            let e = e?;
            if !e.file_type()?.is_dir() {
                continue;
            }
            let version = e.file_name().to_string_lossy().to_string();
            let dir = e.path();
            let installed_at = fs::metadata(&dir)
                .and_then(|m| m.modified())
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            let mut binary_size = 0;
            if let Ok(entries) = fs::read_dir(&dir) {
                for f in entries.flatten() {
                    if let Ok(m) = f.metadata()
                        && m.is_file()
                    {
                        binary_size += m.len();
                    }
                }
            }
            out.push(ReleaseEntry {
                is_current: current.as_deref() == Some(version.as_str()),
                version,
                installed_at_unix: installed_at,
                binary_size,
            });
        }
        out.sort_by(|a, b| b.installed_at_unix.cmp(&a.installed_at_unix));
        Ok(out)
    }

    /// Drop oldest non-current releases beyond `keep_releases`.
    /// Returns the number of releases removed.
    pub fn gc(&self) -> io::Result<usize> {
        let entries = self.list()?;
        if entries.len() <= self.keep_releases {
            return Ok(0);
        }
        let mut dropped = 0;
        let mut keep_remaining = self.keep_releases;
        // First pass: count current (always kept) toward the budget.
        let has_current = entries.iter().any(|e| e.is_current);
        if has_current && keep_remaining > 0 {
            keep_remaining -= 1;
        }
        let mut non_current: Vec<_> = entries.into_iter().filter(|e| !e.is_current).collect();
        // Sorted newest-first; preserve `keep_remaining` newest, drop the rest.
        non_current.drain(..keep_remaining.min(non_current.len()));
        for stale in non_current {
            let path = self.release_dir(&stale.version);
            let _ = fs::remove_dir_all(&path);
            dropped += 1;
        }
        Ok(dropped)
    }

    pub fn delete(&self, version: &str) -> io::Result<()> {
        if let Ok(cur) = self.current_version()
            && cur == version
        {
            return Err(io::Error::other(format!(
                "cannot delete active version {version} — activate another first"
            )));
        }
        fs::remove_dir_all(self.release_dir(version))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_layout() -> (PathBuf, ReleaseLayout) {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("aegis-layout-{pid}-{nanos}"));
        fs::create_dir_all(&root).unwrap();
        let layout = ReleaseLayout::new(root.join("releases"), root.join("current"));
        (root, layout)
    }

    #[test]
    fn install_and_activate_round_trip() {
        let (_root, layout) = temp_layout();
        layout
            .install_binary("v0.1.0", "aegis-pingora", b"binary_bytes")
            .unwrap();
        layout.activate("v0.1.0").unwrap();
        let cur = layout.current_version().unwrap();
        assert_eq!(cur, "v0.1.0");
    }

    #[test]
    fn activate_returns_previous() {
        let (_root, layout) = temp_layout();
        layout.install_binary("v0.1.0", "bin", b"a").unwrap();
        layout.install_binary("v0.2.0", "bin", b"b").unwrap();
        let prev = layout.activate("v0.1.0").unwrap();
        assert!(prev.is_none());
        let prev2 = layout.activate("v0.2.0").unwrap();
        assert_eq!(prev2, Some("v0.1.0".into()));
    }

    #[test]
    fn activate_unknown_version_errors() {
        let (_root, layout) = temp_layout();
        let err = layout.activate("v9.9.9").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn list_marks_current_release() {
        let (_root, layout) = temp_layout();
        layout.install_binary("v0.1.0", "bin", b"a").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        layout.install_binary("v0.2.0", "bin", b"b").unwrap();
        layout.activate("v0.2.0").unwrap();
        let entries = layout.list().unwrap();
        assert_eq!(entries.len(), 2);
        let cur = entries.iter().find(|e| e.is_current).unwrap();
        assert_eq!(cur.version, "v0.2.0");
    }

    #[test]
    fn gc_preserves_current_and_keep_count() {
        let (_root, layout) = temp_layout();
        let layout = layout.with_keep_releases(2);
        for v in ["v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0"] {
            layout.install_binary(v, "bin", b"x").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        layout.activate("v0.2.0").unwrap();
        let dropped = layout.gc().unwrap();
        let remaining = layout.list().unwrap();
        // Keep 2 newest + current = 3 max; here current is v0.2.0
        // (older), so result is current + 1 newest (v0.4.0).
        assert!(
            remaining.iter().any(|e| e.version == "v0.2.0"),
            "current must survive"
        );
        assert!(dropped >= 1);
        assert!(remaining.len() <= 2);
    }

    #[test]
    fn delete_refuses_active_version() {
        let (_root, layout) = temp_layout();
        layout.install_binary("v0.1.0", "bin", b"x").unwrap();
        layout.activate("v0.1.0").unwrap();
        let err = layout.delete("v0.1.0").unwrap_err();
        assert!(err.to_string().contains("cannot delete active"));
    }

    #[test]
    fn delete_allows_inactive_version() {
        let (_root, layout) = temp_layout();
        layout.install_binary("v0.1.0", "bin", b"x").unwrap();
        layout.install_binary("v0.2.0", "bin", b"y").unwrap();
        layout.activate("v0.2.0").unwrap();
        layout.delete("v0.1.0").unwrap();
        let remaining = layout.list().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].version, "v0.2.0");
    }

    #[test]
    fn install_binary_is_atomic_when_replaced() {
        let (_root, layout) = temp_layout();
        layout.install_binary("v0.1.0", "bin", b"old").unwrap();
        layout.install_binary("v0.1.0", "bin", b"new").unwrap();
        let bytes = fs::read(layout.release_dir("v0.1.0").join("bin")).unwrap();
        assert_eq!(bytes, b"new");
        // Staging file shouldn't remain.
        assert!(!layout.release_dir("v0.1.0").join(".bin.staging").exists());
    }

    #[test]
    fn binary_is_executable_after_install() {
        let (_root, layout) = temp_layout();
        let path = layout.install_binary("v0.1.0", "bin", b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111);
    }

    #[test]
    fn activate_twice_to_same_version_idempotent() {
        let (_root, layout) = temp_layout();
        layout.install_binary("v0.1.0", "bin", b"x").unwrap();
        layout.activate("v0.1.0").unwrap();
        layout.activate("v0.1.0").unwrap();
        assert_eq!(layout.current_version().unwrap(), "v0.1.0");
    }
}
