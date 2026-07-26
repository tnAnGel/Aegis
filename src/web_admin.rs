//! Persistent admin credentials + session store for the web panel.
//!
//! State lives in a single JSON file (default `/var/lib/aegis/web.json`)
//! so the CLI (`aegis web reset-admin`, `aegis web stop`, …) and the
//! running daemon share one source of truth. The daemon stats the file
//! on every authenticated request and reloads when mtime changes — that
//! makes CLI mutations effective immediately without a SIGHUP.
//!
//! Password storage is argon2id with a per-record salt. Session tokens
//! are 256 random bits, base64 url-safe encoded, with a server-side TTL.
//!
//! Note: this is **separate** from the static `token <role> <value>;`
//! entries in the DSL config. Those still grant CLI / curl access to
//! `/admin/reload`, `/admin/health` etc. — useful for `systemctl
//! reload` and ops automation. The session token here only governs the
//! React panel (`/admin/ui` + `/admin/api/*`).

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

// V233 — constant-time comparator for session tokens. Session-token
// equality used to go through `String ==` (short-circuits on first
// mismatching byte), which is a remote timing oracle that lets an
// attacker recover the 256-bit token byte-by-byte and hijack the panel.
use crate::admin_auth::constant_time_eq;

pub const DEFAULT_EMAIL: &str = "admin@local.lcl";
pub const DEFAULT_PASSWORD: &str = "adminPassw0rd";
pub const DEFAULT_STATE_PATH: &str = "/var/lib/aegis/web.json";

/// How long a session token stays valid. Kept short-ish so a leaked
/// localStorage value doesn't have an unlimited window.
const SESSION_TTL_SECS: u64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAdminFile {
    /// When false the web panel is hard-disabled — `/admin/ui*` and
    /// `/admin/api/*` both return 503 regardless of auth. The plain
    /// `/admin/*` endpoints (reload, health, threats, …) still work
    /// so `systemctl reload aegis` doesn't break.
    pub enabled: bool,
    pub email: String,
    /// PHC-string argon2id hash of the password.
    pub password_hash: String,
    /// `true` until the user changes both email and password away from
    /// the installer defaults. React shows a red banner forcing the
    /// change while this is set.
    pub must_change: bool,
    /// Active sessions. We prune expired entries on every save.
    #[serde(default)]
    pub sessions: Vec<Session>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
}

impl Default for WebAdminFile {
    fn default() -> Self {
        let hash = hash_password(DEFAULT_PASSWORD).expect("hash default password");
        Self {
            enabled: true,
            email: DEFAULT_EMAIL.to_string(),
            password_hash: hash,
            must_change: true,
            sessions: Vec::new(),
        }
    }
}

/// In-memory cache plus the source-of-truth path. All public methods
/// re-read the file when its mtime has changed, so CLI edits made by a
/// different process win without an explicit reload signal.
pub struct WebAdminStore {
    path: PathBuf,
    inner: Mutex<Cached>,
}

struct Cached {
    file: WebAdminFile,
    mtime: Option<SystemTime>,
}

impl WebAdminStore {
    /// Open the store at `path`. If the file doesn't exist, provision a
    /// FRESH admin (`admin@local.lcl`, `must_change = true`) with a
    /// RANDOMLY-GENERATED strong password — the plaintext is emitted once
    /// via `tracing::warn!` and never persisted in the clear. We do NOT
    /// ship the well-known static default anymore (M8). An already-present
    /// file (existing deployments) is loaded verbatim and never migrated.
    /// Parent directory is created if missing.
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).ok();
        }
        let file = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str(&raw)?
        } else {
            // First run: generate a unique random password instead of the
            // static DEFAULT_PASSWORD, hash it, and surface the plaintext
            // exactly once so the operator can perform the first login.
            let pwd = generate_password();
            let f = WebAdminFile {
                enabled: true,
                email: DEFAULT_EMAIL.to_string(),
                password_hash: hash_password(&pwd)?,
                must_change: true,
                sessions: Vec::new(),
            };
            write_atomic(&path, &f)?;
            tracing::warn!("Generated initial admin password: {pwd} — change it on first login");
            f
        };
        let mtime = fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        Ok(Self {
            path,
            inner: Mutex::new(Cached { file, mtime }),
        })
    }

    fn refresh(&self) {
        let mut guard = self.inner.lock().unwrap();
        let current_mtime = fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        if current_mtime != guard.mtime
            && let Ok(raw) = fs::read_to_string(&self.path)
            && let Ok(file) = serde_json::from_str::<WebAdminFile>(&raw)
        {
            guard.file = file;
            guard.mtime = current_mtime;
        }
    }

    fn write(&self, file: &WebAdminFile) -> anyhow::Result<()> {
        write_atomic(&self.path, file)?;
        let mut guard = self.inner.lock().unwrap();
        guard.file = file.clone();
        guard.mtime = fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.refresh();
        self.inner.lock().unwrap().file.enabled
    }

    pub fn snapshot(&self) -> WebAdminFile {
        self.refresh();
        self.inner.lock().unwrap().file.clone()
    }

    /// Verify a (email, password) pair and, on success, issue a fresh
    /// session token. Returns the new token + the current
    /// `must_change` flag.
    pub fn login(&self, email: &str, password: &str) -> Option<(String, bool)> {
        self.refresh();
        let mut file = self.inner.lock().unwrap().file.clone();
        if !file.enabled {
            return None;
        }
        if !email.eq_ignore_ascii_case(&file.email) {
            return None;
        }
        let parsed = PasswordHash::new(&file.password_hash).ok()?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
        {
            return None;
        }
        let token = new_session_token();
        let now = now_unix();
        file.sessions.retain(|s| s.expires_at > now);
        file.sessions.push(Session {
            token: token.clone(),
            issued_at: now,
            expires_at: now + SESSION_TTL_SECS,
        });
        self.write(&file).ok()?;
        Some((token, file.must_change))
    }

    /// Returns `(email, must_change)` for a valid session token.
    pub fn validate(&self, token: &str) -> Option<(String, bool)> {
        self.refresh();
        let file = self.inner.lock().unwrap().file.clone();
        if !file.enabled {
            return None;
        }
        let now = now_unix();
        // V233 — constant-time token compare (no `String ==` short-circuit).
        file.sessions
            .iter()
            .find(|s| s.expires_at > now && constant_time_eq(s.token.as_bytes(), token.as_bytes()))
            .map(|_| (file.email.clone(), file.must_change))
    }

    pub fn logout(&self, token: &str) {
        self.refresh();
        let mut file = self.inner.lock().unwrap().file.clone();
        // V233 — constant-time token compare (no `String !=` short-circuit).
        file.sessions
            .retain(|s| !constant_time_eq(s.token.as_bytes(), token.as_bytes()));
        let _ = self.write(&file);
    }

    /// Replace email + password atomically. Verifies the old password
    /// first. Clears `must_change` and invalidates all other sessions
    /// (the one performing the change is reissued and returned).
    pub fn change_credentials(
        &self,
        current_token: &str,
        current_password: &str,
        new_email: &str,
        new_password: &str,
    ) -> Result<String, String> {
        self.refresh();
        let mut file = self.inner.lock().unwrap().file.clone();
        if !file.enabled {
            return Err("web panel is disabled".into());
        }
        // V233 — constant-time token compare (no `String ==` short-circuit).
        let now = now_unix();
        if !file.sessions.iter().any(|s| {
            s.expires_at > now && constant_time_eq(s.token.as_bytes(), current_token.as_bytes())
        }) {
            return Err("session expired".into());
        }
        let parsed = PasswordHash::new(&file.password_hash).map_err(|e| e.to_string())?;
        Argon2::default()
            .verify_password(current_password.as_bytes(), &parsed)
            .map_err(|_| "current password incorrect".to_string())?;
        validate_email(new_email)?;
        validate_password(new_password)?;
        file.email = new_email.trim().to_string();
        file.password_hash = hash_password(new_password).map_err(|e| e.to_string())?;
        file.must_change = false;
        let new_token = new_session_token();
        let now = now_unix();
        file.sessions = vec![Session {
            token: new_token.clone(),
            issued_at: now,
            expires_at: now + SESSION_TTL_SECS,
        }];
        self.write(&file).map_err(|e| e.to_string())?;
        Ok(new_token)
    }

    /// CLI: reset password to a freshly-generated random string and
    /// mark must_change so the next login re-prompts. Returns the new
    /// plain-text password — meant to be printed once to stdout.
    pub fn reset_admin(&self) -> anyhow::Result<String> {
        self.refresh();
        let mut file = self.inner.lock().unwrap().file.clone();
        let new_pwd = generate_password();
        file.password_hash = hash_password(&new_pwd)?;
        file.must_change = true;
        file.sessions.clear();
        // Reset email too so a fully-locked-out operator can get back
        // in with predictable creds.
        file.email = DEFAULT_EMAIL.to_string();
        self.write(&file)?;
        Ok(new_pwd)
    }

    pub fn set_enabled(&self, enabled: bool) -> anyhow::Result<()> {
        self.refresh();
        let mut file = self.inner.lock().unwrap().file.clone();
        file.enabled = enabled;
        if !enabled {
            // Wipe sessions so re-enabling forces a fresh login.
            file.sessions.clear();
        }
        self.write(&file)
    }
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?
        .to_string();
    Ok(hash)
}

fn new_session_token() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn generate_password() -> String {
    // 18 url-safe chars = ~108 bits of entropy. Printable, no
    // ambiguity, safe to read aloud and to embed in shell commands.
    let mut buf = [0u8; 14];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn validate_email(email: &str) -> Result<(), String> {
    let trimmed = email.trim();
    if trimmed.is_empty() || trimmed.len() > 254 {
        return Err("email must be 1..=254 chars".into());
    }
    if !trimmed.contains('@') {
        return Err("email must contain '@'".into());
    }
    Ok(())
}

fn validate_password(pwd: &str) -> Result<(), String> {
    if pwd.len() < 8 {
        return Err("password must be at least 8 chars".into());
    }
    if pwd.len() > 256 {
        return Err("password too long (max 256 chars)".into());
    }
    Ok(())
}

fn write_atomic(path: &Path, file: &WebAdminFile) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let raw = serde_json::to_string_pretty(file)?;
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
            "aegis-web-{}-{}.json",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// Open a fresh store and return a known password to log in with.
    /// First-run provisioning now mints a *random* password that's only
    /// logged, not returned — so for tests we immediately `reset_admin()`
    /// (which uses `DEFAULT_EMAIL` and hands back the new plaintext) to
    /// get a usable, deterministic-for-this-process credential.
    fn open_with_known_pwd(p: &Path) -> (WebAdminStore, String) {
        let s = WebAdminStore::open(p.to_path_buf()).unwrap();
        let pwd = s.reset_admin().unwrap();
        (s, pwd)
    }

    #[test]
    fn first_run_provisions_random_password_not_static_default() {
        let p = tmp();
        let s = WebAdminStore::open(p.clone()).unwrap();
        let snap = s.snapshot();
        assert_eq!(snap.email, DEFAULT_EMAIL);
        assert!(snap.must_change);
        // The shipped static default must NOT work on a fresh install.
        assert!(
            s.login(DEFAULT_EMAIL, DEFAULT_PASSWORD).is_none(),
            "static default password must not provision fresh installs (M8)"
        );
        // And the stored hash must not be a hash of the static default.
        let parsed = PasswordHash::new(&snap.password_hash).unwrap();
        assert!(
            Argon2::default()
                .verify_password(DEFAULT_PASSWORD.as_bytes(), &parsed)
                .is_err(),
            "fresh install must not hash the well-known DEFAULT_PASSWORD"
        );
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn existing_file_is_loaded_verbatim_not_migrated() {
        // Simulate an already-provisioned deployment whose password is the
        // legacy static default. open() must load it unchanged.
        let p = tmp();
        let existing = WebAdminFile {
            enabled: true,
            email: DEFAULT_EMAIL.to_string(),
            password_hash: hash_password(DEFAULT_PASSWORD).unwrap(),
            must_change: true,
            sessions: Vec::new(),
        };
        write_atomic(&p, &existing).unwrap();
        let s = WebAdminStore::open(p.clone()).unwrap();
        // Existing creds keep working — no migration / rewrite.
        assert!(
            s.login(DEFAULT_EMAIL, DEFAULT_PASSWORD).is_some(),
            "existing deployments must keep working unchanged"
        );
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn provisioned_login_must_change_and_validate() {
        let p = tmp();
        let (s, pwd) = open_with_known_pwd(&p);
        let (token, must_change) = s.login(DEFAULT_EMAIL, &pwd).unwrap();
        assert!(must_change);
        assert!(s.validate(&token).is_some());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn wrong_password_rejected() {
        let p = tmp();
        let (s, pwd) = open_with_known_pwd(&p);
        assert!(s.login(DEFAULT_EMAIL, "nope").is_none());
        assert!(s.login("nope@x", &pwd).is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn change_credentials_clears_must_change_and_old_sessions() {
        let p = tmp();
        let (s, pwd) = open_with_known_pwd(&p);
        let (t1, _) = s.login(DEFAULT_EMAIL, &pwd).unwrap();
        let new_token = s
            .change_credentials(&t1, &pwd, "ops@example.com", "newPassw0rd!")
            .unwrap();
        assert!(s.validate(&t1).is_none(), "old session should be invalid");
        assert!(s.validate(&new_token).is_some());
        let snap = s.snapshot();
        assert_eq!(snap.email, "ops@example.com");
        assert!(!snap.must_change);
        // Old password no longer works.
        assert!(s.login(DEFAULT_EMAIL, &pwd).is_none());
        assert!(s.login("ops@example.com", "newPassw0rd!").is_some());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn reset_admin_returns_usable_password() {
        let p = tmp();
        let s = WebAdminStore::open(p.clone()).unwrap();
        let new_pwd = s.reset_admin().unwrap();
        assert!(s.login(DEFAULT_EMAIL, &new_pwd).is_some());
        assert!(s.snapshot().must_change);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn disable_blocks_login_and_validate() {
        let p = tmp();
        let (s, pwd) = open_with_known_pwd(&p);
        let (t, _) = s.login(DEFAULT_EMAIL, &pwd).unwrap();
        s.set_enabled(false).unwrap();
        assert!(s.login(DEFAULT_EMAIL, &pwd).is_none());
        assert!(s.validate(&t).is_none());
        s.set_enabled(true).unwrap();
        // Sessions were wiped on disable, so the old token still fails.
        assert!(s.validate(&t).is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn external_mtime_change_is_picked_up() {
        let p = tmp();
        let s = WebAdminStore::open(p.clone()).unwrap();
        // Mutate the file directly to simulate the CLI in another
        // process.
        std::thread::sleep(Duration::from_millis(20));
        let mut snap = s.snapshot();
        snap.enabled = false;
        write_atomic(&p, &snap).unwrap();
        assert!(!s.enabled());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn password_min_length_enforced() {
        let p = tmp();
        let (s, pwd) = open_with_known_pwd(&p);
        let (t, _) = s.login(DEFAULT_EMAIL, &pwd).unwrap();
        let err = s.change_credentials(&t, &pwd, "a@b", "short").unwrap_err();
        assert!(err.contains("at least 8"));
        let _ = fs::remove_file(&p);
    }
}
