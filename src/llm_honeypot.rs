//! V183 — Galah-style LLM honeypot with semantic-hash response cache.
//!
//! Galah (`0x4D31/galah`) demonstrated that an LLM can synthesise
//! contextually-plausible HTTP responses on demand — making a honeypot
//! that looks like a real WordPress / phpMyAdmin / git-config to the
//! attacker without operator-authored fixtures. The trick that makes
//! it production-viable: **semantic-hash cache** so the same scanner
//! sees consistent responses across retries (otherwise the attacker
//! fingerprints the LLM by response variance).
//!
//! This module is the cache + decision layer. The actual LLM call
//! lives behind a [LlmClient] trait so operators can wire whichever
//! provider (OpenAI, Anthropic, vLLM, Ollama, llama.cpp).
//!
//! ## Flow
//!
//! 1. Honeypot route hit → compute [SemanticKey] from request shape.
//! 2. Cache lookup. Hit → return cached response immediately.
//! 3. Cache miss → call LlmClient::synthesise() with the request
//!    context. Cache + return.
//!
//! ## Semantic key
//!
//! Designed so cosmetic variation (query value, request id, timestamp)
//! collapses to the same key but a *different attack technique* gets
//! a fresh synthesis:
//!
//!     SemanticKey = sha1(
//!       method ||
//!       path_template ||             // V119 generalised path
//!       header_name_set ||           // sorted header names
//!       body_shape(body)             // top-level JSON keys / form
//!     )
//!
//! Without a real semantic-hash you'd get either: (a) cache thrash
//! (every request a miss → LLM cost explosion) or (b) over-cached
//! responses that all look identical (attacker fingerprints LLM).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticKey(pub [u8; 20]);

impl SemanticKey {
    pub fn compute(
        method: &str,
        path_template: &str,
        header_names: &[&str],
        body_shape: &str,
    ) -> Self {
        // FNV-1a 160 → 20 bytes. Avoids sha1 dep; cryptographic
        // strength not required (cache keying only).
        let mut state: [u64; 3] = [0xcbf29ce484222325, 0x100000001b3, 0xdeadbeefcafebabe];
        fn mix(state: &mut [u64; 3], bytes: &[u8]) {
            for &b in bytes {
                state[0] ^= b as u64;
                state[0] = state[0].wrapping_mul(0x100000001b3);
                state[1] = state[1].rotate_left(7) ^ state[0];
                state[2] = state[2].wrapping_add(state[1]);
            }
        }
        mix(&mut state, method.as_bytes());
        mix(&mut state, b"|");
        mix(&mut state, path_template.as_bytes());
        mix(&mut state, b"|");
        let mut sorted = header_names.to_vec();
        sorted.sort();
        for h in &sorted {
            mix(&mut state, h.as_bytes());
            mix(&mut state, b",");
        }
        mix(&mut state, b"|");
        mix(&mut state, body_shape.as_bytes());
        let mut out = [0u8; 20];
        out[..8].copy_from_slice(&state[0].to_le_bytes());
        out[8..16].copy_from_slice(&state[1].to_le_bytes());
        out[16..].copy_from_slice(&state[2].to_le_bytes()[..4]);
        Self(out)
    }
}

#[derive(Debug, Clone)]
pub struct SynthResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Minimal trait the operator implements (or wires through the
/// HttpPoster pattern). Default stub returns a generic 404 so the
/// module compiles without an LLM dep.
pub trait LlmClient: Send + Sync {
    fn synthesise(&self, ctx: &RequestContext<'_>) -> SynthResponse;
}

#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body_preview: &'a str,
}

#[derive(Default)]
pub struct StubLlm;

impl LlmClient for StubLlm {
    fn synthesise(&self, ctx: &RequestContext<'_>) -> SynthResponse {
        let body = format!(
            "<!doctype html><html><head><title>Index of {p}</title></head>\
             <body><h1>Index of {p}</h1><pre>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</pre></body></html>",
            p = html_escape(ctx.path)
        );
        SynthResponse {
            status: 200,
            headers: vec![
                ("server".into(), "Apache/2.4.41 (Ubuntu)".into()),
                ("content-type".into(), "text/html; charset=UTF-8".into()),
            ],
            body: body.into_bytes(),
        }
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[derive(Debug, Clone)]
struct Entry {
    response: SynthResponse,
    inserted: Instant,
}

pub struct LlmHoneypot {
    cache: RwLock<HashMap<SemanticKey, Entry>>,
    ttl: Duration,
    capacity: usize,
    client: std::sync::Arc<dyn LlmClient>,
    stats: RwLock<Stats>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl LlmHoneypot {
    pub fn new(client: std::sync::Arc<dyn LlmClient>, ttl: Duration, capacity: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl,
            capacity,
            client,
            stats: RwLock::new(Stats::default()),
        }
    }

    pub fn respond(&self, ctx: &RequestContext<'_>, key: SemanticKey) -> SynthResponse {
        if let Some(e) = self.lookup(&key) {
            self.stats.write().unwrap().hits += 1;
            return e;
        }
        self.stats.write().unwrap().misses += 1;
        let resp = self.client.synthesise(ctx);
        self.insert(key, resp.clone());
        resp
    }

    fn lookup(&self, key: &SemanticKey) -> Option<SynthResponse> {
        let g = self.cache.read().unwrap();
        let e = g.get(key)?;
        if e.inserted.elapsed() > self.ttl {
            None
        } else {
            Some(e.response.clone())
        }
    }

    fn insert(&self, key: SemanticKey, response: SynthResponse) {
        let mut g = self.cache.write().unwrap();
        if g.len() >= self.capacity {
            // Evict oldest. Single linear scan is fine — capacity
            // typically a few thousand entries.
            if let Some((k, _)) = g
                .iter()
                .min_by_key(|(_, e)| e.inserted)
                .map(|(k, v)| (k.clone(), v.clone()))
            {
                g.remove(&k);
                self.stats.write().unwrap().evictions += 1;
            }
        }
        g.insert(
            key,
            Entry {
                response,
                inserted: Instant::now(),
            },
        );
    }

    pub fn stats(&self) -> Stats {
        *self.stats.read().unwrap()
    }

    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Helper to compute body shape for [SemanticKey]. For JSON we return
/// the sorted top-level keys; for forms the param names; otherwise
/// the empty string. Cheap, deterministic.
pub fn body_shape(body: &str, content_type: &str) -> String {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("application/json") {
        if let Some(start) = body.find('{') {
            let mut keys: Vec<&str> = body[start..]
                .split(',')
                .filter_map(|seg| {
                    let q1 = seg.find('"')?;
                    let rest = &seg[q1 + 1..];
                    let q2 = rest.find('"')?;
                    Some(&rest[..q2])
                })
                .collect();
            keys.sort();
            keys.dedup();
            return keys.join(",");
        }
    }
    if ct.contains("application/x-www-form-urlencoded") {
        let mut names: Vec<&str> = body
            .split('&')
            .filter_map(|kv| kv.split('=').next())
            .collect();
        names.sort();
        names.dedup();
        return names.join(",");
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn semantic_key_stable_across_value_changes() {
        let k1 = SemanticKey::compute("GET", "/admin/:id", &["host", "user-agent"], "");
        let k2 = SemanticKey::compute("GET", "/admin/:id", &["user-agent", "host"], "");
        assert_eq!(k1, k2, "header order must not affect key");
    }

    #[test]
    fn semantic_key_changes_on_method() {
        let k1 = SemanticKey::compute("GET", "/x", &["host"], "");
        let k2 = SemanticKey::compute("POST", "/x", &["host"], "");
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_hit_returns_same_response() {
        let hp = LlmHoneypot::new(Arc::new(StubLlm), Duration::from_secs(60), 100);
        let key = SemanticKey::compute("GET", "/x", &["host"], "");
        let ctx = RequestContext {
            method: "GET",
            path: "/x",
            headers: vec![("host", "evil.test")],
            body_preview: "",
        };
        let a = hp.respond(&ctx, key.clone());
        let b = hp.respond(&ctx, key);
        assert_eq!(a.body, b.body);
        let s = hp.stats();
        assert_eq!(s.misses, 1);
        assert_eq!(s.hits, 1);
    }

    #[test]
    fn cache_evicts_at_capacity() {
        let hp = LlmHoneypot::new(Arc::new(StubLlm), Duration::from_secs(60), 2);
        let ctx = RequestContext {
            method: "GET",
            path: "/x",
            headers: vec![],
            body_preview: "",
        };
        hp.respond(&ctx, SemanticKey([1; 20]));
        hp.respond(&ctx, SemanticKey([2; 20]));
        hp.respond(&ctx, SemanticKey([3; 20]));
        assert!(hp.len() <= 2);
        assert!(hp.stats().evictions >= 1);
    }

    #[test]
    fn body_shape_normalises_json() {
        let s = body_shape(r#"{"b":1,"a":2}"#, "application/json");
        assert_eq!(s, "a,b");
    }

    #[test]
    fn body_shape_normalises_form() {
        let s = body_shape("user=root&pass=x", "application/x-www-form-urlencoded");
        assert_eq!(s, "pass,user");
    }

    #[test]
    fn stub_renders_index_of() {
        let stub = StubLlm;
        let ctx = RequestContext {
            method: "GET",
            path: "/.git/",
            headers: vec![],
            body_preview: "",
        };
        let r = stub.synthesise(&ctx);
        assert_eq!(r.status, 200);
        assert!(String::from_utf8_lossy(&r.body).contains("Index of /.git/"));
    }
}
