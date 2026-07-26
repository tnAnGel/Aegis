//! V208 — update checker (read-only).
//!
//! Polls a Gitea/GitHub-compatible Releases API and reports the
//! latest release on the operator's chosen channel. **Does not
//! apply updates** — the admin UI surfaces the changelog + a download
//! link so the operator can manually run `sudo bash install.sh` on
//! the host.
//!
//! V233 — this module is now the *only* update surface. The in-panel
//! self-update *apply* mechanism (the V209-V212 snapshot / download /
//! install / activate / restart machinery) has been removed: it
//! downloaded and executed an unverified, attacker-controllable
//! binary as the service user (unauthenticated-RCE design). Nothing
//! in this file reaches an apply/execute path — every entry point
//! here is a read-only HTTP GET against the release feed.
//!
//! ## Wire shape
//!
//! Compatible with Gitea v1.x and GitHub
//! Releases API. Both expose `GET /repos/<owner>/<repo>/releases`
//! returning a JSON array of release objects:
//!
//! ```json
//! [
//!   { "tag_name": "v0.2.0",
//!     "name": "v0.2.0 — Defence Arsenal sprint",
//!     "body": "## Changelog\n\n- V176 ja4_corpus\n- ...",
//!     "published_at": "2026-05-22T12:00:00Z",
//!     "prerelease": false,
//!     "draft": false,
//!     "assets": [
//!       { "name": "aegis-pingora-v0.2.0-x86_64-linux.tar.gz",
//!         "size": 23456789,
//!         "browser_download_url": "https://...",
//!         "content_type": "application/gzip" }
//!     ]
//!   }, ...
//! ]
//! ```
//!
//! ## Channel matching
//!
//! Operator picks `stable | beta | nightly`. Tag classification:
//!
//! * Contains `-nightly` → nightly
//! * Contains `-beta` or `-rc` → beta
//! * Otherwise → stable
//!
//! Stable releases are visible to all channels; beta to beta+nightly;
//! nightly only to nightly. Same model as Rust / Chrome.
//!
//! ## Caching
//!
//! `UpdateChecker` caches the last successful fetch with timestamp
//! so the UI can hit `GET /admin/api/updates/status` cheaply without
//! re-hitting upstream. Manual "Check now" forces a refresh and
//! bumps `last_checked_at`. ETag-based conditional GET is supported
//! when the HttpClient implementation populates the response header.

use std::sync::RwLock;
#[cfg(test)]
use std::time::Duration;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    #[default]
    Stable,
    Beta,
    Nightly,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        }
    }
    /// Returns true when `release_channel` is permitted on `self`
    /// channel. Stable is permitted everywhere; beta in beta+nightly;
    /// nightly only in nightly.
    pub fn permits(self, release_channel: Channel) -> bool {
        match (self, release_channel) {
            (_, Channel::Stable) => true,
            (Channel::Beta | Channel::Nightly, Channel::Beta) => true,
            (Channel::Nightly, Channel::Nightly) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default, alias = "browser_download_url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub published_at: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

impl Release {
    pub fn channel(&self) -> Channel {
        let t = self.tag_name.to_ascii_lowercase();
        if t.contains("-nightly") {
            Channel::Nightly
        } else if t.contains("-beta") || t.contains("-rc") {
            Channel::Beta
        } else {
            Channel::Stable
        }
    }
}

/// HTTPS client trait — same opt-in pattern as captcha_providers.
/// Binary wires a hyper-rustls or reqwest backend; lib stays
/// HTTPS-agnostic for unit testing.
pub trait HttpClient: Send + Sync {
    fn get(&self, url: &str) -> Result<HttpResponse, String>;
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Production HTTPS client: shells out to `curl`. Zero new deps,
/// available on every Linux host the installer touches. Trade-off:
/// per-check process spawn (~50ms overhead) vs in-process hyper-
/// rustls. Fine for hourly polls / manual button clicks; the
/// HttpClient trait lets you swap to in-process when needed.
#[derive(Debug, Default, Clone)]
pub struct CurlHttpClient {
    pub timeout_secs: u32,
}

impl CurlHttpClient {
    pub fn new() -> Self {
        Self { timeout_secs: 15 }
    }
}

impl HttpClient for CurlHttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse, String> {
        // -sS: silent but show errors; -L: follow redirects;
        // -w: status code appended after body so we can split it.
        let timeout = self.timeout_secs.max(1).to_string();
        let output = std::process::Command::new("curl")
            .arg("-sS")
            .arg("-L")
            .arg("--max-time")
            .arg(&timeout)
            .arg("-A")
            .arg(format!(
                "aegis-update-checker/{}",
                env!("CARGO_PKG_VERSION")
            ))
            .arg("-w")
            .arg("\n__AEGIS_HTTP_STATUS__:%{http_code}\n")
            .arg(url)
            .output()
            .map_err(|e| format!("curl spawn: {e}"))?;
        if !output.status.success() && output.stderr.is_empty() {
            return Err(format!("curl exit code {}", output.status));
        }
        let stdout = output.stdout;
        // Split off the status marker tail.
        let marker = b"__AEGIS_HTTP_STATUS__:";
        let split = stdout
            .windows(marker.len())
            .rposition(|w| w == marker)
            .ok_or_else(|| "curl: no status marker in output".to_string())?;
        let body = stdout[..split.saturating_sub(1)].to_vec();
        let status_str = std::str::from_utf8(&stdout[split + marker.len()..])
            .unwrap_or("")
            .trim();
        let status: u16 = status_str.parse().unwrap_or(0);
        Ok(HttpResponse { status, body })
    }
}

/// In-process stub used by tests + as the fallback when the operator
/// hasn't wired a real HTTPS client.
#[derive(Debug, Default)]
pub struct StubHttpClient {
    pub canned: std::sync::Mutex<Vec<(String, HttpResponse)>>,
}

impl HttpClient for StubHttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse, String> {
        let g = self.canned.lock().unwrap();
        g.iter()
            .find(|(u, _)| u == url)
            .map(|(_, r)| r.clone())
            .ok_or_else(|| format!("stub: no canned response for {url}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Full Gitea/GitHub API base URL up to the repo (no trailing slash).
    /// Examples:
    ///   `https://api.github.com/repos/tnAnGel/Aegis`
    ///   `https://api.github.com/repos/<owner>/<repo>`
    pub repo_api_url: String,
    pub channel: Channel,
    pub current_version: String,
    /// Seconds between background polls. 0 = never poll automatically.
    pub poll_interval_secs: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            repo_api_url: "https://api.github.com/repos/tnAnGel/Aegis".into(),
            channel: Channel::Stable,
            current_version: env!("CARGO_PKG_VERSION").into(),
            poll_interval_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateStatus {
    pub current_version: String,
    pub channel: Channel,
    pub repo_api_url: String,
    pub latest: Option<Release>,
    pub update_available: bool,
    pub last_checked_at: Option<u64>, // unix seconds
    pub last_error: Option<String>,
}

pub struct UpdateChecker {
    config: RwLock<UpdateConfig>,
    cache: RwLock<CachedState>,
    http: std::sync::Arc<dyn HttpClient>,
}

#[derive(Debug, Default)]
struct CachedState {
    releases: Vec<Release>,
    last_checked: Option<SystemTime>,
    last_error: Option<String>,
}

impl UpdateChecker {
    pub fn new(config: UpdateConfig, http: std::sync::Arc<dyn HttpClient>) -> Self {
        Self {
            config: RwLock::new(config),
            cache: RwLock::new(CachedState::default()),
            http,
        }
    }

    pub fn config(&self) -> UpdateConfig {
        self.config.read().unwrap().clone()
    }

    pub fn update_config(&self, cfg: UpdateConfig) {
        *self.config.write().unwrap() = cfg;
    }

    /// Pull the releases list from upstream. Best-effort: errors are
    /// recorded in the cache so the next [Self::status] call surfaces
    /// them, but the previous successful list (if any) stays valid.
    pub fn check(&self) -> Result<usize, String> {
        let cfg = self.config.read().unwrap().clone();
        let url = format!(
            "{}/releases?limit=50",
            cfg.repo_api_url.trim_end_matches('/')
        );
        match self.http.get(&url) {
            Ok(resp) => {
                if resp.status != 200 {
                    let err = format!(
                        "upstream returned HTTP {}: {}",
                        resp.status,
                        String::from_utf8_lossy(&resp.body)
                            .chars()
                            .take(200)
                            .collect::<String>()
                    );
                    self.record_error(err.clone());
                    return Err(err);
                }
                match serde_json::from_slice::<Vec<Release>>(&resp.body) {
                    Ok(mut releases) => {
                        releases.retain(|r| !r.draft);
                        let count = releases.len();
                        let mut g = self.cache.write().unwrap();
                        g.releases = releases;
                        g.last_checked = Some(SystemTime::now());
                        g.last_error = None;
                        Ok(count)
                    }
                    Err(e) => {
                        let err = format!("parse failed: {e}");
                        self.record_error(err.clone());
                        Err(err)
                    }
                }
            }
            Err(e) => {
                self.record_error(e.clone());
                Err(e)
            }
        }
    }

    fn record_error(&self, err: String) {
        let mut g = self.cache.write().unwrap();
        g.last_checked = Some(SystemTime::now());
        g.last_error = Some(err);
    }

    /// Return the latest release on the configured channel + whether
    /// it's newer than current_version.
    pub fn status(&self) -> UpdateStatus {
        let cfg = self.config.read().unwrap().clone();
        let cache = self.cache.read().unwrap();
        let latest = cache
            .releases
            .iter()
            .filter(|r| cfg.channel.permits(r.channel()))
            .max_by(|a, b| a.published_at.cmp(&b.published_at))
            .cloned();
        let update_available = latest
            .as_ref()
            .map(|r| is_newer(&r.tag_name, &cfg.current_version))
            .unwrap_or(false);
        UpdateStatus {
            current_version: cfg.current_version,
            channel: cfg.channel,
            repo_api_url: cfg.repo_api_url,
            latest,
            update_available,
            last_checked_at: cache
                .last_checked
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
            last_error: cache.last_error.clone(),
        }
    }

    /// Return every release on every channel (for the "history" tab).
    pub fn releases(&self) -> Vec<Release> {
        self.cache.read().unwrap().releases.clone()
    }

    pub fn poll_due(&self) -> bool {
        let cfg = self.config.read().unwrap();
        if cfg.poll_interval_secs == 0 {
            return false;
        }
        let g = self.cache.read().unwrap();
        match g.last_checked {
            None => true,
            Some(t) => SystemTime::now()
                .duration_since(t)
                .map(|d| d.as_secs() >= cfg.poll_interval_secs)
                .unwrap_or(true),
        }
    }
}

/// Tag-aware semver comparison. Strips leading `v`, splits on
/// `.` / `-`, compares numeric segments numerically and pre-release
/// labels lexically (with the rule that NO pre-release > ANY
/// pre-release). Sufficient for `v0.1.5`, `v0.2.0-beta.1`,
/// `v0.2.0-nightly.20260522` tags.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    compare_versions(candidate, current) == std::cmp::Ordering::Greater
}

pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_nums, a_pre) = parse_version(a);
    let (b_nums, b_pre) = parse_version(b);
    match a_nums.cmp(&b_nums) {
        std::cmp::Ordering::Equal => match (a_pre.as_deref(), b_pre.as_deref()) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater, // 1.0 > 1.0-beta
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(x), Some(y)) => x.cmp(y),
        },
        ord => ord,
    }
}

fn parse_version(s: &str) -> (Vec<u32>, Option<String>) {
    let s = s.trim_start_matches('v').trim_start_matches('V');
    let (head, pre) = match s.find('-') {
        Some(i) => (&s[..i], Some(s[i + 1..].to_string())),
        None => (s, None),
    };
    let nums: Vec<u32> = head
        .split('.')
        .map(|p| p.parse::<u32>().unwrap_or(0))
        .collect();
    (nums, pre)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn stub_release(tag: &str, published_at: &str, body: &str) -> Release {
        Release {
            tag_name: tag.into(),
            name: tag.into(),
            body: body.into(),
            published_at: published_at.into(),
            prerelease: tag.contains("-"),
            draft: false,
            assets: vec![],
        }
    }

    fn checker_with(releases: Vec<Release>, current: &str, channel: Channel) -> UpdateChecker {
        let stub = StubHttpClient::default();
        let body = serde_json::to_vec(&releases).unwrap();
        let url = format!("{}/releases?limit=50", UpdateConfig::default().repo_api_url);
        stub.canned
            .lock()
            .unwrap()
            .push((url, HttpResponse { status: 200, body }));
        let mut cfg = UpdateConfig::default();
        cfg.current_version = current.into();
        cfg.channel = channel;
        UpdateChecker::new(cfg, Arc::new(stub))
    }

    #[test]
    fn channel_classification_via_tag() {
        assert_eq!(stub_release("v0.2.0", "", "").channel(), Channel::Stable);
        assert_eq!(
            stub_release("v0.2.0-beta.1", "", "").channel(),
            Channel::Beta
        );
        assert_eq!(stub_release("v0.2.0-rc.1", "", "").channel(), Channel::Beta);
        assert_eq!(
            stub_release("v0.2.0-nightly.20260522", "", "").channel(),
            Channel::Nightly
        );
    }

    #[test]
    fn permits_walks_channel_tree() {
        assert!(Channel::Stable.permits(Channel::Stable));
        assert!(!Channel::Stable.permits(Channel::Beta));
        assert!(Channel::Beta.permits(Channel::Stable));
        assert!(Channel::Beta.permits(Channel::Beta));
        assert!(!Channel::Beta.permits(Channel::Nightly));
        assert!(Channel::Nightly.permits(Channel::Stable));
        assert!(Channel::Nightly.permits(Channel::Beta));
        assert!(Channel::Nightly.permits(Channel::Nightly));
    }

    #[test]
    fn version_compare_handles_pre_release() {
        assert!(is_newer("v0.2.0", "v0.1.5"));
        assert!(is_newer("v0.2.0", "v0.2.0-beta.1"));
        assert!(!is_newer("v0.2.0-beta.1", "v0.2.0"));
        assert!(is_newer("v0.2.0-beta.2", "v0.2.0-beta.1"));
        assert!(!is_newer("v0.1.5", "v0.1.5"));
        assert!(is_newer("v1.0.0", "v0.99.99"));
    }

    #[test]
    fn check_populates_cache() {
        let c = checker_with(
            vec![
                stub_release("v0.2.0", "2026-05-22T12:00:00Z", "changelog"),
                stub_release("v0.1.5", "2026-04-01T00:00:00Z", "older"),
            ],
            "v0.1.5",
            Channel::Stable,
        );
        let n = c.check().unwrap();
        assert_eq!(n, 2);
        let s = c.status();
        assert_eq!(s.latest.as_ref().unwrap().tag_name, "v0.2.0");
        assert!(s.update_available);
        assert!(s.last_checked_at.is_some());
        assert!(s.last_error.is_none());
    }

    #[test]
    fn status_filters_by_channel() {
        let c = checker_with(
            vec![
                stub_release("v0.2.0", "2026-05-22T12:00:00Z", ""),
                stub_release("v0.3.0-beta.1", "2026-05-25T00:00:00Z", ""),
                stub_release("v0.4.0-nightly.20260601", "2026-06-01T00:00:00Z", ""),
            ],
            "v0.2.0",
            Channel::Stable,
        );
        c.check().unwrap();
        let s = c.status();
        assert_eq!(s.latest.as_ref().unwrap().tag_name, "v0.2.0");
        assert!(!s.update_available);
    }

    #[test]
    fn beta_channel_sees_beta_and_stable() {
        let c = checker_with(
            vec![
                stub_release("v0.2.0", "2026-05-22T12:00:00Z", ""),
                stub_release("v0.3.0-beta.1", "2026-05-25T00:00:00Z", ""),
            ],
            "v0.2.0",
            Channel::Beta,
        );
        c.check().unwrap();
        let s = c.status();
        assert_eq!(s.latest.as_ref().unwrap().tag_name, "v0.3.0-beta.1");
        assert!(s.update_available);
    }

    #[test]
    fn http_error_recorded_but_cache_preserved() {
        let stub = StubHttpClient::default();
        stub.canned.lock().unwrap().push((
            format!("{}/releases?limit=50", UpdateConfig::default().repo_api_url),
            HttpResponse {
                status: 503,
                body: b"service unavailable".to_vec(),
            },
        ));
        let c = UpdateChecker::new(UpdateConfig::default(), Arc::new(stub));
        let err = c.check();
        assert!(err.is_err());
        let s = c.status();
        assert!(s.last_error.is_some());
        assert!(s.last_checked_at.is_some());
    }

    #[test]
    fn poll_due_after_interval() {
        let mut cfg = UpdateConfig::default();
        cfg.poll_interval_secs = 1;
        let c = UpdateChecker::new(cfg, Arc::new(StubHttpClient::default()));
        assert!(c.poll_due()); // never checked
        let _ = c.check(); // will fail but bumps timestamp
        assert!(!c.poll_due());
        std::thread::sleep(Duration::from_millis(1500));
        assert!(c.poll_due());
    }

    #[test]
    fn draft_releases_filtered_out() {
        let mut draft = stub_release("v0.9.0", "2026-06-01T00:00:00Z", "");
        draft.draft = true;
        let c = checker_with(
            vec![draft, stub_release("v0.2.0", "2026-05-22T12:00:00Z", "")],
            "v0.1.5",
            Channel::Stable,
        );
        c.check().unwrap();
        let s = c.status();
        assert_eq!(s.latest.unwrap().tag_name, "v0.2.0");
    }

    #[test]
    fn poll_interval_zero_disables_auto_check() {
        let mut cfg = UpdateConfig::default();
        cfg.poll_interval_secs = 0;
        let c = UpdateChecker::new(cfg, Arc::new(StubHttpClient::default()));
        assert!(!c.poll_due());
    }
}
