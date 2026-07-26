//! V232 — runtime worker-topology introspection for the admin panel.
//!
//! The Workers page in the web UI shows the operator how the proxy is
//! laid out across the box: how many `aegis-pingora` worker processes
//! are running, how many runtime threads each carries, per-worker RAM
//! and lifetime-average CPU, and whether the layout matches the host's
//! core count.
//!
//! ## Why this lives in a module, not the hot path
//!
//! Nothing here runs per-request. `host_info()` + `enumerate_workers()`
//! are called only by the `/admin/api/topology` handler, i.e. on a
//! dashboard refresh (a few times a minute at most). They read `/proc`,
//! which is cheap but not free, so they stay well off the data path.
//!
//! ## The desired-count knob
//!
//! Worker *count* is a systemd-instance decision — the running daemon
//! cannot spawn or kill its own siblings (that needs `systemctl` +
//! root). So the panel records the operator's *intent* into a small
//! JSON state file ([`DesiredTopology`]); `install.sh::resolve_workers`
//! reads it on the next deploy/reconcile. This mirrors nginx, where
//! changing `worker_processes` also needs a reload — the daemon never
//! rescales itself live.

use std::path::Path;

/// Default location of the desired-topology state file. The admin
/// process has `ReadWritePaths=/var/lib/aegis` in its systemd unit.
pub const DEFAULT_TOPOLOGY_PATH: &str = "/var/lib/aegis/topology.json";

/// Host-level facts: core count, CPU model string, load average.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostInfo {
    /// Logical CPU count as the runtime sees it (respects cgroup
    /// quotas via `available_parallelism`).
    pub cpu_count: usize,
    /// Best-effort CPU model string from `/proc/cpuinfo`. `"unknown"`
    /// when the field is absent (common on some aarch64 kernels).
    pub cpu_model: String,
    /// 1 / 5 / 15-minute load average from `/proc/loadavg`.
    pub load_avg: [f64; 3],
}

/// One live `aegis-pingora` worker process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkerProc {
    pub pid: u32,
    /// systemd instance index from `AEGIS_PINGORA_INSTANCE` in the
    /// process environment. `None` for a standalone (non-systemd) run.
    pub instance: Option<u32>,
    /// Resident set size in MiB.
    pub rss_mb: u64,
    /// OS thread count (`/proc/<pid>/stat` field 20).
    pub threads: u32,
    /// Seconds since the process started.
    pub uptime_secs: u64,
    /// Lifetime-average CPU usage, percent of one core. `(utime +
    /// stime) / uptime`. A worker pinned 1:1 to a core and fully
    /// saturated reads ~100; idle reads ~0.
    pub cpu_pct_avg: f32,
}

/// Operator-recorded desired worker count. Persisted to
/// [`DEFAULT_TOPOLOGY_PATH`]; consumed by `install.sh` on the next
/// deploy. `"auto"` means "match the host core count".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DesiredTopology {
    /// `"auto"` or a positive integer rendered as a string (kept as a
    /// string so the JSON shape is stable if we later add `"auto-2"`
    /// style expressions).
    #[serde(default = "default_workers")]
    pub workers: String,
}

fn default_workers() -> String {
    "auto".to_string()
}

impl Default for DesiredTopology {
    fn default() -> Self {
        Self {
            workers: default_workers(),
        }
    }
}

impl DesiredTopology {
    /// Resolve the desired count against the host. `"auto"` → core
    /// count; an explicit number is clamped to `1..=4096`; anything
    /// unparseable falls back to the core count.
    pub fn effective(&self, host: &HostInfo) -> usize {
        if self.workers.eq_ignore_ascii_case("auto") {
            return host.cpu_count.max(1);
        }
        self.workers
            .trim()
            .parse::<usize>()
            .ok()
            .map(|n| n.clamp(1, 4096))
            .unwrap_or_else(|| host.cpu_count.max(1))
    }
}

/// Box-wide online CPU count, **affinity-agnostic**.
///
/// We must NOT use `std::thread::available_parallelism()` here: it is
/// scoped to the calling process's CPU-affinity mask. Every
/// `aegis-pingora` worker is pinned 1:1 to a single core (systemd
/// `CPUAffinity=%i`), so `available_parallelism()` inside a worker
/// reports `1` — which would make the topology dashboard think a
/// 16-core box has 1 core and flag the layout as "oversubscribed".
/// `sysconf(_SC_NPROCESSORS_ONLN)` reports the system-wide online
/// count regardless of the caller's affinity.
fn host_cpu_count() -> usize {
    let v = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if v >= 1 {
        return v as usize;
    }
    // Fallback: count `processor` lines in /proc/cpuinfo.
    let n = std::fs::read_to_string("/proc/cpuinfo")
        .map(|raw| raw.lines().filter(|l| l.starts_with("processor")).count())
        .unwrap_or(0);
    if n >= 1 {
        return n;
    }
    // Last resort (no /proc, no sysconf): affinity-scoped count.
    std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
}

/// Read host CPU facts. All fields degrade gracefully — on a platform
/// without `/proc` (e.g. macOS dev builds) the model is `"unknown"`
/// and the load average is zeroed, but `cpu_count` still works.
pub fn host_info() -> HostInfo {
    let cpu_count = host_cpu_count();

    let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|raw| {
            raw.lines().find_map(|l| {
                // x86 exposes "model name"; many aarch64 kernels
                // only expose "Processor" or nothing useful.
                let (k, v) = l.split_once(':')?;
                let k = k.trim();
                if k == "model name" || k == "Processor" || k == "Model" {
                    Some(v.trim().to_string())
                } else {
                    None
                }
            })
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let load_avg = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|raw| {
            let mut it = raw.split_whitespace();
            [
                it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0),
                it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0),
                it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0),
            ]
        })
        .unwrap_or([0.0, 0.0, 0.0]);

    HostInfo {
        cpu_count,
        cpu_model,
        load_avg,
    }
}

/// Clock ticks per second (`_SC_CLK_TCK`, almost always 100).
fn clk_tck() -> u64 {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as u64 } else { 100 }
}

/// Page size in bytes (`_SC_PAGESIZE`).
fn page_size() -> u64 {
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 { v as u64 } else { 4096 }
}

/// System uptime in seconds, from `/proc/uptime`.
fn system_uptime_secs() -> f64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|raw| raw.split_whitespace().next().map(|s| s.to_string()))
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0)
}

/// Enumerate every live `aegis-pingora` worker process by scanning
/// `/proc`. Returns an empty vec on a platform without `/proc`, or
/// when the scanning process lacks permission — callers must treat an
/// empty result as "unknown", not "zero workers".
pub fn enumerate_workers() -> Vec<WorkerProc> {
    let hz = clk_tck();
    let page = page_size();
    let sys_uptime = system_uptime_secs();

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };

        // `comm` is the process name, truncated to 15 bytes by the
        // kernel. "aegis-pingora" is 13 bytes, so an exact match is
        // safe.
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim() != "aegis-pingora" {
            continue;
        }

        let Some(w) = read_worker(pid, hz, page, sys_uptime) else {
            continue;
        };
        out.push(w);
    }
    // Stable order: by instance index when known, else by pid.
    out.sort_by_key(|w| (w.instance.unwrap_or(u32::MAX), w.pid));
    out
}

/// Parse a single worker's `/proc` entries. `None` when the process
/// disappeared mid-scan or its stat line is malformed.
fn read_worker(pid: u32, hz: u64, page: u64, sys_uptime: f64) -> Option<WorkerProc> {
    // /proc/<pid>/stat — field layout (1-indexed):
    //   14 utime, 15 stime, 20 num_threads, 22 starttime.
    // The comm field (2) can contain spaces/parens, so split on the
    // LAST ')' and index the remainder.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rparen = stat.rfind(')')?;
    let rest: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
    // After ')' the slice starts at field 3 (state), so field N is at
    // index N-3.
    let utime: u64 = rest.get(14 - 3)?.parse().ok()?;
    let stime: u64 = rest.get(15 - 3)?.parse().ok()?;
    let threads: u32 = rest.get(20 - 3)?.parse().ok()?;
    let starttime: u64 = rest.get(22 - 3)?.parse().ok()?;

    let start_secs = starttime as f64 / hz as f64;
    let uptime_secs = (sys_uptime - start_secs).max(0.0);

    let cpu_secs = (utime + stime) as f64 / hz as f64;
    let cpu_pct_avg = if uptime_secs > 0.5 {
        (cpu_secs / uptime_secs * 100.0) as f32
    } else {
        0.0
    };

    // /proc/<pid>/statm — field 2 is resident pages.
    let rss_mb = std::fs::read_to_string(format!("/proc/{pid}/statm"))
        .ok()
        .and_then(|raw| raw.split_whitespace().nth(1).map(|s| s.to_string()))
        .and_then(|s| s.parse::<u64>().ok())
        .map(|pages| pages * page / (1024 * 1024))
        .unwrap_or(0);

    let instance = read_instance_env(pid);

    Some(WorkerProc {
        pid,
        instance,
        rss_mb,
        threads,
        uptime_secs: uptime_secs as u64,
        cpu_pct_avg,
    })
}

/// Pull `AEGIS_PINGORA_INSTANCE` out of a worker's `/proc/<pid>/environ`
/// (NUL-separated `KEY=VALUE` records). `None` for standalone runs or
/// when the environ is unreadable (cross-user).
fn read_instance_env(pid: u32) -> Option<u32> {
    let raw = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    for kv in raw.split(|&b| b == 0) {
        let kv = std::str::from_utf8(kv).ok()?;
        if let Some(v) = kv.strip_prefix("AEGIS_PINGORA_INSTANCE=") {
            return v.trim().parse().ok();
        }
    }
    None
}

/// Read the desired-topology state file. Missing/corrupt file →
/// `Default` (`"auto"`).
pub fn read_desired(path: &Path) -> DesiredTopology {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Persist the desired-topology state file atomically (temp + rename)
/// so a concurrent reader never sees a half-written file.
pub fn write_desired(path: &Path, desired: &DesiredTopology) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }
    let tmp = path.with_extension("json.tmp");
    let raw = serde_json::to_string_pretty(desired)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, raw)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_info_reports_cpu_count() {
        let h = host_info();
        assert!(h.cpu_count >= 1);
    }

    #[test]
    fn desired_auto_resolves_to_core_count() {
        let host = HostInfo {
            cpu_count: 16,
            cpu_model: "test".into(),
            load_avg: [0.0; 3],
        };
        let d = DesiredTopology {
            workers: "auto".into(),
        };
        assert_eq!(d.effective(&host), 16);
    }

    #[test]
    fn desired_explicit_number_wins() {
        let host = HostInfo {
            cpu_count: 16,
            cpu_model: "t".into(),
            load_avg: [0.0; 3],
        };
        let d = DesiredTopology {
            workers: "8".into(),
        };
        assert_eq!(d.effective(&host), 8);
    }

    #[test]
    fn desired_clamps_and_falls_back() {
        let host = HostInfo {
            cpu_count: 4,
            cpu_model: "t".into(),
            load_avg: [0.0; 3],
        };
        // 0 clamps up to 1.
        assert_eq!(
            DesiredTopology {
                workers: "0".into()
            }
            .effective(&host),
            1
        );
        // Garbage falls back to the core count.
        assert_eq!(
            DesiredTopology {
                workers: "xyz".into()
            }
            .effective(&host),
            4,
        );
        // Absurdly large clamps to 4096.
        assert_eq!(
            DesiredTopology {
                workers: "999999".into()
            }
            .effective(&host),
            4096,
        );
    }

    #[test]
    fn desired_roundtrips_through_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("aegis-topo-test-{}.json", std::process::id()));
        let d = DesiredTopology {
            workers: "12".into(),
        };
        write_desired(&path, &d).unwrap();
        let back = read_desired(&path);
        assert_eq!(back.workers, "12");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_desired_missing_file_is_auto() {
        let d = read_desired(Path::new("/nonexistent/aegis/topology.json"));
        assert_eq!(d.workers, "auto");
    }

    #[test]
    fn enumerate_workers_never_panics() {
        // On CI / macOS there may be no /proc and no aegis-pingora
        // processes — the call must simply return (possibly empty).
        let _ = enumerate_workers();
    }
}
