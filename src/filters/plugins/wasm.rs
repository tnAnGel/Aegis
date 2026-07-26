//! WebAssembly plugin filter (wasmi, pure-Rust interpreter).
//!
//! Plugin ABI (kept deliberately small to avoid the cost of WIT
//! tooling): the module imports
//!
//!   aegis_log(ptr: i32, len: i32) -> ()
//!
//! and exports
//!
//!   aegis_alloc(size: i32) -> i32
//!   aegis_check(req_ptr: i32, req_len: i32) -> i64
//!
//! `aegis_check` reads `req_len` UTF-8 bytes of JSON at `req_ptr`,
//! writes its response as JSON into memory it owns, and returns the
//! pointer in the high 32 bits and the length in the low 32 bits of
//! the i64. A zero result is treated as "allow".
//!
//! Why wasmi over wasmtime? Pure Rust, no LLVM / cranelift in the
//! dependency tree, ~500 KB compiled. We trade some throughput for a
//! lean dep footprint; filter checks are µs-scale either way.

use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::UNIX_EPOCH,
};

use serde::Serialize;
use wasmi::{Caller, Config, Engine, Linker, Memory, Module, Store};

use crate::{
    filters::{FilterAction, TrafficFilter, plugins::PluginResponse},
    proxy::request_context::RequestContext,
};

pub struct WasmPlugin {
    name: String,
    path: PathBuf,
    engine: Engine,
    state: Mutex<WasmState>,
    mtime_secs: AtomicU64,
    /// V229 — throttle for the per-request `maybe_reload` stat. Same
    /// motivation as the Lua plugin: eliminate the per-request statx
    /// syscall the previous impl issued on every filter check.
    last_reload_micros: AtomicU64,
    reload_start: std::time::Instant,
}

const WASM_RELOAD_INTERVAL_MICROS: u64 = 1_000_000;

/// V233 — upper bound on a single guest-supplied length passed to a
/// host function (`aegis_log` payload, `aegis_check` response). The
/// length the guest hands us is an unvalidated `i32`; a hostile or
/// buggy module can pass `i32::MAX` (~2 GiB) and, before any wasmi
/// bounds check runs, trigger a host-side `vec!` of that size. Under
/// `panic = "abort"` an allocation failure kills the whole worker.
/// We clamp to this constant — and further to the guest's actual
/// linear-memory size — so we never allocate more than is plausible
/// or even addressable.
const MAX_GUEST_BUF_BYTES: usize = 64 * 1024;

struct WasmState {
    module: Module,
    failed: bool,
    /// V230 — scratch buffer reused across calls for the JSON request
    /// payload. Lives behind the same mutex that serialises invocation,
    /// so reuse is free. Replaces the per-request `Vec<u8>` allocation
    /// from `serde_json::to_vec` which showed up as a hot allocator
    /// site under load.
    req_scratch: Vec<u8>,
}

// Host state attached to the wasmi Store. The plugin's memory export
// is fetched per-call (it's stable within a module instance) and the
// log buffer collects bytes the plugin sends via aegis_log.
struct HostCtx {
    log_buf: Vec<u8>,
}

impl WasmPlugin {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("wasm-plugin")
            .to_string();
        let mut config = Config::default();
        // wasmi's fuel metering is the practical instruction budget
        // — bumped to 10M per call which is plenty for a filter
        // decision but bounds the worst case.
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let bytes = std::fs::read(path)?;
        let module = Module::new(&engine, &bytes[..])?;
        let mtime_secs = file_mtime(path);
        Ok(Self {
            name,
            path: path.to_path_buf(),
            engine,
            state: Mutex::new(WasmState {
                module,
                failed: false,
                // V230 — pre-size to the typical payload (most
                // requests serialise into 1–4 KB of JSON).
                req_scratch: Vec::with_capacity(2048),
            }),
            mtime_secs: AtomicU64::new(mtime_secs),
            last_reload_micros: AtomicU64::new(0),
            reload_start: std::time::Instant::now(),
        })
    }

    fn maybe_reload(&self) {
        // V229 — throttle to once per second; see lua.rs for context.
        let now_micros = self.reload_start.elapsed().as_micros() as u64;
        let last = self.last_reload_micros.load(Ordering::Relaxed);
        if now_micros.saturating_sub(last) < WASM_RELOAD_INTERVAL_MICROS {
            return;
        }
        self.last_reload_micros.store(now_micros, Ordering::Relaxed);

        let on_disk = file_mtime(&self.path);
        let cached = self.mtime_secs.load(Ordering::Relaxed);
        if on_disk == cached {
            return;
        }
        match std::fs::read(&self.path)
            .map_err(anyhow::Error::from)
            .and_then(|b| Module::new(&self.engine, &b[..]).map_err(anyhow::Error::from))
        {
            Ok(module) => {
                if let Ok(mut guard) = self.state.lock() {
                    guard.module = module;
                    guard.failed = false;
                    // V230 — scratch buffer survives the reload so we
                    // don't pay the realloc again post-swap.
                }
                self.mtime_secs.store(on_disk, Ordering::Relaxed);
                tracing::info!(
                    target: "aegis::plugin",
                    plugin = %self.name,
                    "wasm plugin reloaded"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "aegis::plugin",
                    plugin = %self.name,
                    error = %e,
                    "wasm plugin reload failed — keeping previous version"
                );
                if let Ok(mut guard) = self.state.lock() {
                    guard.failed = true;
                }
                self.mtime_secs.store(on_disk, Ordering::Relaxed);
            }
        }
    }

    fn call(&self, ctx: &RequestContext) -> Option<PluginResponse> {
        // V230 — serialise the request inside the mutex into a scratch
        // buffer kept on the WasmState. Saves both the per-request
        // `PluginRequest` materialisation (string clones for every
        // header + fingerprint) and the per-request `Vec<u8>` from
        // `serde_json::to_vec`. The buffer is cleared, not freed, so
        // its capacity tracks the steady-state payload size. We move
        // the populated buffer out of the guard (leaving an empty
        // `Vec` behind) before releasing the mutex; a `ScratchReturn`
        // RAII guard puts it back on every exit path.
        let (req_bytes, module) = {
            let mut guard = self.state.lock().ok()?;
            if guard.failed {
                return None;
            }
            guard.req_scratch.clear();
            let borrowed = BorrowedRequest::from_ctx(ctx);
            if let Err(e) = serde_json::to_writer(&mut guard.req_scratch, &borrowed) {
                tracing::warn!(target: "aegis::plugin", plugin = %self.name, error = %e, "wasm: request serialise failed");
                return None;
            }
            (std::mem::take(&mut guard.req_scratch), guard.module.clone())
        };
        let scratch = ScratchReturn {
            state: &self.state,
            buf: req_bytes,
        };
        let req_bytes: &[u8] = &scratch.buf;

        let mut store = Store::new(
            &self.engine,
            HostCtx {
                log_buf: Vec::new(),
            },
        );
        // 10M fuel covers comfortable plugin logic (~10ms cap).
        store.set_fuel(10_000_000).ok()?;

        let mut linker = Linker::<HostCtx>::new(&self.engine);
        // aegis_log(ptr, len)
        if let Err(e) = linker.func_wrap(
            "env",
            "aegis_log",
            |mut caller: Caller<'_, HostCtx>, ptr: i32, len: i32| {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return,
                };
                // V233 — clamp the guest-supplied length BEFORE
                // allocating: first to MAX_GUEST_BUF_BYTES, then to the
                // guest's actual linear-memory size so we never reserve
                // more than the module could possibly address. The
                // wasmi `mem.read` below stays bounds-checked and will
                // still reject an out-of-range `ptr`.
                let n = (len.max(0) as usize)
                    .min(MAX_GUEST_BUF_BYTES)
                    .min(mem.data_size(&caller));
                let mut buf = vec![0u8; n];
                if mem.read(&caller, ptr as usize, &mut buf).is_ok() {
                    if let Ok(s) = std::str::from_utf8(&buf) {
                        tracing::info!(target: "aegis::plugin", "{s}");
                    }
                    caller.data_mut().log_buf.extend_from_slice(&buf);
                }
            },
        ) {
            tracing::warn!(target: "aegis::plugin", plugin = %self.name, error = %e, "wasm: link aegis_log failed");
            return None;
        }

        let instance = match linker
            .instantiate(&mut store, &module)
            .and_then(|pre| pre.start(&mut store))
        {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(target: "aegis::plugin", plugin = %self.name, error = %e, "wasm: instantiate failed");
                return None;
            }
        };
        let memory: Memory = instance.get_memory(&store, "memory")?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, "aegis_alloc")
            .ok()?;
        let check = instance
            .get_typed_func::<(i32, i32), i64>(&store, "aegis_check")
            .ok()?;

        // Allocate request buffer in plugin memory, copy bytes in.
        let req_ptr = match alloc.call(&mut store, req_bytes.len() as i32) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(target: "aegis::plugin", plugin = %self.name, error = %e, "wasm: aegis_alloc failed");
                return None;
            }
        };
        if let Err(e) = memory.write(&mut store, req_ptr as usize, req_bytes) {
            tracing::warn!(target: "aegis::plugin", plugin = %self.name, error = %e, "wasm: write request failed");
            return None;
        }

        let packed = match check.call(&mut store, (req_ptr, req_bytes.len() as i32)) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "aegis::plugin", plugin = %self.name, error = %e, "wasm: aegis_check trapped");
                return None;
            }
        };
        if packed == 0 {
            return Some(PluginResponse {
                action: "allow".into(),
                ..Default::default()
            });
        }
        let resp_ptr = ((packed as u64) >> 32) as i32;
        let resp_len = ((packed as u64) & 0xffff_ffff) as i32;
        // V233 — same guest-controlled-length hazard as aegis_log: the
        // low 32 bits of the packed return value are fully attacker
        // controlled. Clamp before the `vec!` so a bogus length can't
        // drive a multi-GiB host allocation. `memory.read` stays
        // bounds-checked for the pointer.
        let n = (resp_len.max(0) as usize)
            .min(MAX_GUEST_BUF_BYTES)
            .min(memory.data_size(&store));
        let mut buf = vec![0u8; n];
        if memory.read(&store, resp_ptr as usize, &mut buf).is_err() {
            tracing::warn!(target: "aegis::plugin", plugin = %self.name, "wasm: bad response pointer");
            return None;
        }
        match serde_json::from_slice::<PluginResponse>(&buf) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(target: "aegis::plugin", plugin = %self.name, error = %e, "wasm: response JSON parse failed");
                None
            }
        }
    }
}

impl TrafficFilter for WasmPlugin {
    fn name(&self) -> &'static str {
        "wasm_plugin"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        self.maybe_reload();
        // V230 — pass the context straight through; the wasm path
        // builds the JSON payload directly from it.
        match self.call(ctx) {
            Some(resp) => resp.into_action(&self.name),
            None => FilterAction::Allow,
        }
    }
}

/// V230 — RAII guard that returns the JSON scratch buffer to the
/// plugin state on drop, even on the early-return paths. Keeping the
/// allocation alive across calls is the whole point of the scratch
/// pattern; losing it on a guest trap would defeat the optimisation.
struct ScratchReturn<'a> {
    state: &'a Mutex<WasmState>,
    buf: Vec<u8>,
}

impl Drop for ScratchReturn<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.state.lock() {
            // A concurrent call may have raced past us and returned
            // its own buffer first; keep whichever has the bigger
            // capacity so the steady-state allocation only ever
            // grows. The losing buffer is freed when this scope ends.
            let taken = std::mem::take(&mut self.buf);
            if guard.req_scratch.capacity() < taken.capacity() {
                guard.req_scratch = taken;
            }
        }
    }
}

/// V230 — borrowing serialise wrapper. Matches the wire shape of the
/// public [`crate::filters::plugins::PluginRequest`] (and the field
/// names plugins already key on) but holds `&str` slices into the
/// `RequestContext` so `serde_json::to_writer` copies bytes once,
/// straight into the scratch buffer.
#[derive(Serialize)]
struct BorrowedRequest<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    user_agent: &'a str,
    client_ip: String,
    ja4: &'a str,
    ja4h: &'a str,
    ja4t: &'a str,
    ja4l: &'a str,
    h2fp: &'a str,
    h3fp: &'a str,
    mtls_fp: &'a str,
    headers: BorrowedHeaders<'a>,
}

struct BorrowedHeaders<'a>(&'a http::HeaderMap);

impl Serialize for BorrowedHeaders<'_> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = ser.serialize_seq(Some(self.0.len()))?;
        for (n, v) in self.0.iter() {
            if let Ok(vs) = v.to_str() {
                seq.serialize_element(&(n.as_str(), vs))?;
            }
        }
        seq.end()
    }
}

impl<'a> BorrowedRequest<'a> {
    fn from_ctx(ctx: &'a RequestContext) -> Self {
        let host = ctx
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        BorrowedRequest {
            method: ctx.method.as_str(),
            path: ctx.path.as_str(),
            host,
            user_agent: ctx.user_agent.as_deref().unwrap_or(""),
            // IpAddr -> String is unavoidable (no borrow available).
            client_ip: ctx.client_ip.to_string(),
            ja4: ctx.ja4.as_deref().unwrap_or(""),
            ja4h: ctx.ja4h().unwrap_or(""),
            ja4t: ctx.ja4t.as_deref().unwrap_or(""),
            ja4l: ctx.ja4l.as_deref().unwrap_or(""),
            h2fp: ctx.h2fp.as_deref().unwrap_or(""),
            h3fp: ctx.h3fp.as_deref().unwrap_or(""),
            mtls_fp: ctx.mtls_fp.as_deref().unwrap_or(""),
            headers: BorrowedHeaders(&ctx.headers),
        }
    }
}

fn file_mtime(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64 as TestSeq;

    static SEQ: TestSeq = TestSeq::new(0);

    fn tmp(bytes: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "aegis-wasm-{}-{}.wasm",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// Hand-rolled WAT module that always returns "deny". Built with
    /// `wat` crate at test time so we don't ship a binary fixture.
    fn deny_all_wasm() -> Vec<u8> {
        // Module that exports aegis_alloc + aegis_check + memory. Both
        // functions are trivial: aegis_alloc returns a fixed offset
        // (we pre-stage the response string starting at byte 0 with
        // length 51), aegis_check returns the packed ptr/len pointing
        // at it. Request bytes are ignored.
        let response = br#"{"action":"deny","reason":"wasm test","status":418}"#;
        let response_len = response.len() as u32;
        // Place response at offset 64 to leave room for request scratch.
        let response_offset: u32 = 64;
        let mut wat = String::new();
        wat.push_str("(module\n");
        wat.push_str("  (memory (export \"memory\") 1)\n");
        wat.push_str(&format!(
            "  (data (i32.const {response_offset}) \"{}\")\n",
            response
                .iter()
                .map(|b| format!("\\{b:02x}"))
                .collect::<String>()
        ));
        // aegis_alloc — just bump-allocate after the response data so
        // the host can write the request without trampling our reply.
        wat.push_str(&format!(
            "  (func (export \"aegis_alloc\") (param $sz i32) (result i32)\n    (i32.const {}))\n",
            response_offset + response_len + 8
        ));
        // aegis_check — return packed (offset << 32) | len.
        let packed = ((response_offset as u64) << 32) | (response_len as u64);
        let high = (packed >> 32) as u32;
        let low = packed as u32;
        wat.push_str(&format!(
            "  (func (export \"aegis_check\") (param i32 i32) (result i64)\n    (i64.or (i64.shl (i64.extend_i32_u (i32.const {high})) (i64.const 32)) (i64.extend_i32_u (i32.const {low}))))\n"
        ));
        wat.push_str(")\n");
        wat::parse_str(&wat).expect("wat parses")
    }

    fn allow_all_wasm() -> Vec<u8> {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "aegis_alloc") (param i32) (result i32)
                (i32.const 1024))
              (func (export "aegis_check") (param i32 i32) (result i64)
                (i64.const 0)))
        "#;
        wat::parse_str(wat).expect("wat parses")
    }

    #[test]
    fn deny_plugin_rejects_request() {
        let bytes = deny_all_wasm();
        let p = tmp(&bytes);
        let plugin = WasmPlugin::load(&p).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        match plugin.check(&ctx) {
            FilterAction::Deny { status, reason } => {
                assert_eq!(status, 418);
                assert_eq!(reason, "wasm test");
            }
            other => panic!("expected deny, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn allow_plugin_passes() {
        let bytes = allow_all_wasm();
        let p = tmp(&bytes);
        let plugin = WasmPlugin::load(&p).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        assert_eq!(plugin.check(&ctx), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn corrupt_wasm_fails_to_load() {
        let p = tmp(b"not really wasm");
        assert!(WasmPlugin::load(&p).is_err());
        let _ = std::fs::remove_file(&p);
    }

    /// V233 — a module that calls `aegis_log` with a hostile,
    /// near-`i32::MAX` length. Before the clamp this drove a ~2 GiB
    /// host-side `vec!` *before* wasmi's bounds check ran, which on a
    /// memory-constrained worker aborts the process (`panic = "abort"`).
    /// With the clamp the host allocates at most `MAX_GUEST_BUF_BYTES`
    /// (and here, the guest's 1-page / 64 KiB memory), the bounds-checked
    /// `mem.read` rejects the out-of-range pointer, and `aegis_check`
    /// returns 0 -> allow. The assertion is really "we got here without
    /// the worker dying".
    fn hostile_log_len_wasm() -> Vec<u8> {
        let wat = r#"
            (module
              (import "env" "aegis_log" (func $log (param i32 i32)))
              (memory (export "memory") 1)
              (func (export "aegis_alloc") (param i32) (result i32)
                (i32.const 1024))
              (func (export "aegis_check") (param i32 i32) (result i64)
                ;; aegis_log(ptr = 0, len = 0x7FFFFFFF)
                (call $log (i32.const 0) (i32.const 0x7FFFFFFF))
                (i64.const 0)))
        "#;
        wat::parse_str(wat).expect("wat parses")
    }

    #[test]
    fn hostile_log_length_does_not_crash_host() {
        let bytes = hostile_log_len_wasm();
        let p = tmp(&bytes);
        let plugin = WasmPlugin::load(&p).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        // No panic / abort: the guest-supplied 2 GiB length is clamped
        // before the host allocation. aegis_check returns 0 -> Allow.
        assert_eq!(plugin.check(&ctx), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }
}
