//! V184 — Beelzebub-style YAML honeypot service descriptors.
//!
//! Operator declares honeypot endpoints in YAML rather than embedding
//! them in DSL or Rust. Each descriptor binds a path pattern to a
//! deterministic multi-turn engagement script: trigger phrase →
//! response. State machine per (IP, descriptor) so probing tools
//! that follow links naturally engage the next turn.
//!
//! Example:
//!
//! ```yaml
//! - name: fake-phpmyadmin
//!   path: /phpmyadmin/*
//!   turns:
//!     - on: login_view
//!       response:
//!         status: 200
//!         headers:
//!           server: "Apache/2.4.41"
//!         body: "<title>phpMyAdmin login</title>…"
//!     - on: login_submit
//!       trigger_body_contains: "pma_password="
//!       response:
//!         status: 200
//!         body: "<title>Login error</title>…"
//!     - on: brute_attempt
//!       trigger_body_contains: "pma_password="
//!       repeat_after_ms: 800       # slow-replay tarpit
//!       response:
//!         status: 429
//!         body: "Too many requests"
//! ```
//!
//! The state machine advances on each turn, scoped per (IP,
//! descriptor_name). When the script ends we stay on the last turn
//! (so further requests get the final response — useful for tarpit
//! endings). State expires after `session_ttl` of inactivity.

// V230 — switched session map from `RwLock<HashMap>` to sharded
// `DashMap` so the per-request `step()` hot path no longer serializes
// every request through a single writer lock. Matches the convention
// used across the codebase (filters/rate_limit, ddos/score, etc.).
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Descriptor {
    pub name: String,
    pub path_pattern: String,
    pub turns: Vec<Turn>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Turn {
    pub label: String,
    pub trigger_body_contains: Option<String>,
    pub repeat_after_ms: Option<u32>,
    pub response: TurnResponse,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TurnResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug)]
struct SessionState {
    next_turn: usize,
    last_seen: Instant,
}

pub struct YamlHoneypotEngine {
    descriptors: Vec<Descriptor>,
    // V230 — keyed by `(IpAddr, descriptor_index)` instead of
    // `(IpAddr, String)`. Both fields are `Copy`, so per-request
    // lookups in `step()` no longer allocate. The descriptor index
    // is stable for the engine's lifetime (descriptors are set at
    // construction and never mutated).
    sessions: DashMap<(IpAddr, usize), SessionState>,
    session_ttl: Duration,
}

impl YamlHoneypotEngine {
    pub fn new(descriptors: Vec<Descriptor>) -> Self {
        Self {
            descriptors,
            // V230 — 128 shards (matches scenarios/rate_limit/ddos
            // for the high-concurrency hot path).
            sessions: DashMap::with_shard_amount(128),
            session_ttl: Duration::from_secs(900),
        }
    }

    pub fn with_session_ttl(mut self, ttl: Duration) -> Self {
        self.session_ttl = ttl;
        self
    }

    /// Match request → descriptor by path. Returns None if no
    /// descriptor's pattern matches. First match wins (operator
    /// orders the list).
    pub fn match_descriptor(&self, path: &str) -> Option<&Descriptor> {
        self.descriptors
            .iter()
            .find(|d| match_path(&d.path_pattern, path))
    }

    /// Advance state for (ip, descriptor) and return the response for
    /// the current turn. Optional body lets a turn require a body
    /// substring before counting as triggered.
    ///
    /// V230 — hot path: keyed lookup uses `(IpAddr, usize)` (both
    /// `Copy`) so no `String` is allocated per request. The DashMap
    /// guard is dropped before we return the `&Turn` borrowed from
    /// the (immutable) descriptors vector.
    pub fn step(&self, ip: IpAddr, descriptor_name: &str, body: &str) -> Option<&Turn> {
        // Descriptor index doubles as both the session key suffix and
        // the array index for the returned turn — single scan.
        let (descriptor_idx, descriptor) = self
            .descriptors
            .iter()
            .enumerate()
            .find(|(_, d)| d.name == descriptor_name)?;
        let key = (ip, descriptor_idx);
        let now = Instant::now();
        // Scoped block: release the shard guard before we return a
        // borrow into `self.descriptors` (separate field — no aliasing
        // — but keeps the lock held no longer than necessary).
        let idx = {
            let mut entry = self.sessions.entry(key).or_insert(SessionState {
                next_turn: 0,
                last_seen: now,
            });
            entry.last_seen = now;
            let idx = entry
                .next_turn
                .min(descriptor.turns.len().saturating_sub(1));
            // Compute trigger against the *current* turn before deciding
            // whether to advance. Borrow `turn` only briefly here.
            let triggered = match &descriptor.turns[idx].trigger_body_contains {
                Some(needle) => body.contains(needle),
                None => true,
            };
            if triggered && entry.next_turn + 1 < descriptor.turns.len() {
                entry.next_turn += 1;
            }
            idx
        };
        Some(&descriptor.turns[idx])
    }

    // V230 — background path only. Verified callers (admin/timer)
    // never invoke this from the per-request hot path. `DashMap::retain`
    // briefly locks each shard in turn rather than the whole map, so
    // GC no longer freezes concurrent `step()` calls globally.
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let before = self.sessions.len();
        self.sessions
            .retain(|_, s| now.saturating_duration_since(s.last_seen) < self.session_ttl);
        before - self.sessions.len()
    }

    pub fn descriptors(&self) -> &[Descriptor] {
        &self.descriptors
    }

    // V230 — `DashMap::len` is lock-free per shard; safe for the
    // admin stats endpoint at any frequency.
    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }
}

fn match_path(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        path == prefix || path.starts_with(&format!("{prefix}/"))
    } else if let Some(suffix) = pattern.strip_prefix("*/") {
        path.ends_with(&format!("/{suffix}")) || path == suffix
    } else {
        pattern == path
    }
}

/// Minimal YAML parser tailored to the descriptor schema. Avoids a
/// full serde_yaml dep — we accept a strict subset (one list of
/// mappings, mapping values are scalars or one level of nested
/// mapping). Returns descriptors in source order.
///
/// For richer YAML the operator can swap in serde_yaml at the call
/// site; this is the zero-dep fallback.
pub fn parse_descriptors(yaml: &str) -> Result<Vec<Descriptor>, String> {
    let mut out: Vec<Descriptor> = Vec::new();
    let mut current: Option<Descriptor> = None;
    let mut current_turn: Option<Turn> = None;
    let mut current_response: Option<TurnResponse> = None;
    let mut in_headers = false;
    let mut current_section: Option<&'static str> = None;
    for raw in yaml.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if trimmed.starts_with("- ") && indent == 0 {
            if let Some(d) = current.take() {
                let mut d = d;
                if let Some(mut t) = current_turn.take() {
                    if let Some(r) = current_response.take() {
                        t.response = r;
                    }
                    d.turns.push(t);
                }
                out.push(d);
            }
            current = Some(Descriptor {
                name: String::new(),
                path_pattern: String::new(),
                turns: Vec::new(),
            });
            let rest = trimmed.trim_start_matches("- ");
            apply_kv(
                &mut current,
                &mut current_turn,
                &mut current_response,
                &mut in_headers,
                &mut current_section,
                indent,
                rest,
            )?;
            continue;
        }
        if trimmed.starts_with("- ") && indent > 0 {
            // New turn within current descriptor.
            if let Some(mut t) = current_turn.take() {
                if let Some(r) = current_response.take() {
                    t.response = r;
                }
                if let Some(d) = current.as_mut() {
                    d.turns.push(t);
                }
            }
            current_turn = Some(Turn {
                label: String::new(),
                trigger_body_contains: None,
                repeat_after_ms: None,
                response: TurnResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: String::new(),
                },
            });
            let rest = trimmed.trim_start_matches("- ");
            apply_kv(
                &mut current,
                &mut current_turn,
                &mut current_response,
                &mut in_headers,
                &mut current_section,
                indent,
                rest,
            )?;
            continue;
        }
        apply_kv(
            &mut current,
            &mut current_turn,
            &mut current_response,
            &mut in_headers,
            &mut current_section,
            indent,
            trimmed,
        )?;
    }
    if let Some(mut d) = current {
        if let Some(mut t) = current_turn.take() {
            if let Some(r) = current_response.take() {
                t.response = r;
            }
            d.turns.push(t);
        }
        out.push(d);
    }
    Ok(out)
}

fn apply_kv(
    current: &mut Option<Descriptor>,
    current_turn: &mut Option<Turn>,
    current_response: &mut Option<TurnResponse>,
    in_headers: &mut bool,
    current_section: &mut Option<&'static str>,
    _indent: usize,
    rest: &str,
) -> Result<(), String> {
    let (k, v) = match rest.split_once(':') {
        Some((k, v)) => (k.trim(), v.trim()),
        None => return Ok(()),
    };
    let val = strip_quotes(v);
    match k {
        "name" => {
            if let Some(t) = current_turn.as_mut() {
                t.label = val.to_string();
            } else if let Some(d) = current.as_mut() {
                d.name = val.to_string();
            }
            *current_section = None;
            *in_headers = false;
        }
        "path" => {
            if let Some(d) = current.as_mut() {
                d.path_pattern = val.to_string();
            }
        }
        "on" => {
            if let Some(t) = current_turn.as_mut() {
                t.label = val.to_string();
            }
        }
        "trigger_body_contains" => {
            if let Some(t) = current_turn.as_mut() {
                t.trigger_body_contains = Some(val.to_string());
            }
        }
        "repeat_after_ms" => {
            if let Some(t) = current_turn.as_mut()
                && let Ok(n) = val.parse::<u32>()
            {
                t.repeat_after_ms = Some(n);
            }
        }
        "response" => {
            *current_response = Some(TurnResponse {
                status: 200,
                headers: Vec::new(),
                body: String::new(),
            });
            *current_section = Some("response");
            *in_headers = false;
        }
        "status" => {
            if let Some(r) = current_response.as_mut()
                && let Ok(n) = val.parse::<u16>()
            {
                r.status = n;
            }
        }
        "body" => {
            if let Some(r) = current_response.as_mut() {
                r.body = val.to_string();
            }
        }
        "headers" => {
            *in_headers = true;
        }
        "turns" => {
            *current_section = Some("turns");
        }
        _ if *in_headers && current_response.is_some() => {
            if let Some(r) = current_response.as_mut() {
                r.headers.push((k.to_string(), val.to_string()));
            }
        }
        _ => {}
    }
    Ok(())
}

fn strip_quotes(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn descriptor() -> Descriptor {
        Descriptor {
            name: "fake-pma".into(),
            path_pattern: "/phpmyadmin/*".into(),
            turns: vec![
                Turn {
                    label: "view".into(),
                    trigger_body_contains: None,
                    repeat_after_ms: None,
                    response: TurnResponse {
                        status: 200,
                        headers: vec![],
                        body: "view".into(),
                    },
                },
                Turn {
                    label: "submit".into(),
                    trigger_body_contains: Some("pma_password=".into()),
                    repeat_after_ms: None,
                    response: TurnResponse {
                        status: 200,
                        headers: vec![],
                        body: "submit".into(),
                    },
                },
                Turn {
                    label: "deny".into(),
                    trigger_body_contains: None,
                    repeat_after_ms: Some(800),
                    response: TurnResponse {
                        status: 429,
                        headers: vec![],
                        body: "deny".into(),
                    },
                },
            ],
        }
    }

    #[test]
    fn match_descriptor_prefix() {
        let e = YamlHoneypotEngine::new(vec![descriptor()]);
        assert!(e.match_descriptor("/phpmyadmin/index.php").is_some());
        assert!(e.match_descriptor("/other").is_none());
    }

    #[test]
    fn state_advances_on_each_step() {
        let e = YamlHoneypotEngine::new(vec![descriptor()]);
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let t1 = e.step(ip, "fake-pma", "").unwrap();
        assert_eq!(t1.label, "view");
        // Submit needs body trigger; without it we stay on submit.
        let t2 = e.step(ip, "fake-pma", "").unwrap();
        assert_eq!(t2.label, "submit");
        let t3 = e.step(ip, "fake-pma", "user=a&pma_password=b").unwrap();
        assert_eq!(t3.label, "submit");
        let t4 = e.step(ip, "fake-pma", "").unwrap();
        assert_eq!(t4.label, "deny");
        let t5 = e.step(ip, "fake-pma", "").unwrap();
        assert_eq!(t5.label, "deny");
    }

    #[test]
    fn parser_round_trips_basic_descriptor() {
        let yaml = "- name: x\n  path: /a/*\n  turns:\n    - on: hello\n      response:\n        status: 418\n        body: teapot\n";
        let ds = parse_descriptors(yaml).unwrap();
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].name, "x");
        assert_eq!(ds[0].path_pattern, "/a/*");
        assert_eq!(ds[0].turns.len(), 1);
        assert_eq!(ds[0].turns[0].response.status, 418);
        assert_eq!(ds[0].turns[0].response.body, "teapot");
    }

    #[test]
    fn parser_handles_headers_and_triggers() {
        let yaml = "- name: y\n  path: /b\n  turns:\n    - on: post\n      trigger_body_contains: password=\n      response:\n        status: 200\n        headers:\n          server: Apache/2.4\n        body: ok\n";
        let ds = parse_descriptors(yaml).unwrap();
        let t = &ds[0].turns[0];
        assert_eq!(t.trigger_body_contains.as_deref(), Some("password="));
        assert_eq!(
            t.response.headers,
            vec![("server".to_string(), "Apache/2.4".to_string())]
        );
    }

    #[test]
    fn gc_drops_idle_sessions() {
        let e =
            YamlHoneypotEngine::new(vec![descriptor()]).with_session_ttl(Duration::from_millis(50));
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        e.step(ip, "fake-pma", "");
        assert_eq!(e.sessions(), 1);
        std::thread::sleep(Duration::from_millis(120));
        e.gc();
        assert_eq!(e.sessions(), 0);
    }
}
