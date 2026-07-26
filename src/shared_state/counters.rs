//! Cluster-wide atomic counters backed by a shared mmap arena.
//!
//! V87 — first concrete consumer of the V86 [Arena](super::Arena).
//! Provides a fixed-size array of `AtomicU64` slots that any worker
//! can read or fetch_add. Used for any metric that needs to reflect
//! cluster-wide state (vs the current per-worker ShardedCounter,
//! which sums across CPUs WITHIN one process but loses cluster
//! aggregation in REUSEPORT N-process deployments).
//!
//! Typical use: registry-style numeric IDs (counter index) →
//! atomic value. Operators choose which counters to expose by
//! defining an enum of named indices. The array is fixed-size
//! at open time; growing requires recreating the arena (operator
//! task during deploy).
//!
//! V88+ will build the IP-keyed scorer hashmap on top of this same
//! arena. The counter array itself doesn't need a hashmap — slots
//! are accessed by integer index.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{Arena, ArenaError};

/// Fixed-size cluster-wide atomic counter table. All workers
/// access the same physical memory through `Arena`; fetch_add /
/// load operations are atomic across processes (POSIX shared
/// mmap atomics are coherent on Linux x86_64 + aarch64).
pub struct SharedCounters {
    /// Keep the arena reference alive for the counter table's
    /// lifetime. Arena holds the mmap; dropping it would unmap.
    _arena: Arena,
    /// Raw pointer to the AtomicU64 array inside the arena. Length
    /// stored separately because we erase the type to satisfy the
    /// `Sync` requirement (Arena is shared cross-thread).
    ptr: *const AtomicU64,
    len: usize,
}

// SAFETY: AtomicU64 is Sync; the pointer is to mmap'd memory whose
// lifetime is tied to the held `_arena` Arc. No Rust aliasing rules
// violated since all access goes through `&AtomicU64`.
unsafe impl Send for SharedCounters {}
unsafe impl Sync for SharedCounters {}

impl SharedCounters {
    /// Allocate a new counter table of `len` slots inside `arena`.
    /// Each slot is a u64 — total bytes = 8 * len. Returns an
    /// error if the arena doesn't have room.
    ///
    /// Slots are zero-initialised (mmap'd memory starts zero).
    pub fn new(arena: &Arena, len: usize) -> Result<Self, ArenaError> {
        let (_, ptr) = arena.alloc_slice::<AtomicU64>(len)?;
        Ok(Self {
            _arena: arena.clone(),
            ptr: ptr as *const AtomicU64,
            len,
        })
    }

    /// Number of counter slots.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrow a slot. Returns `None` if `idx` is out of bounds.
    pub fn get(&self, idx: usize) -> Option<&AtomicU64> {
        if idx >= self.len {
            return None;
        }
        // SAFETY: bounds checked above. ptr is valid for self.len
        // entries (alloc_slice guaranteed it) for the lifetime of
        // self._arena.
        Some(unsafe { &*self.ptr.add(idx) })
    }

    /// Convenience: atomic fetch_add on a slot. Returns the
    /// previous value. Saturating-style: silently no-op (returns 0)
    /// on out-of-bounds idx to avoid panicking the caller on a
    /// stale ordinal.
    pub fn add(&self, idx: usize, delta: u64) -> u64 {
        self.get(idx)
            .map(|c| c.fetch_add(delta, Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Atomic load of a slot. Returns 0 on out-of-bounds idx.
    pub fn load(&self, idx: usize) -> u64 {
        self.get(idx)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Snapshot all slots into an owned Vec — used by /metrics
    /// renderers. Per-slot atomic load; the snapshot is not
    /// atomic across slots (different slots may have been bumped
    /// between reads), but for monotonic counters this is fine.
    pub fn snapshot(&self) -> Vec<u64> {
        // SAFETY: ptr is valid for self.len entries.
        let slice = unsafe { std::slice::from_raw_parts(self.ptr, self.len) };
        slice.iter().map(|c| c.load(Ordering::Relaxed)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn unique_name(prefix: &str) -> String {
        format!(
            "/aegis-test-{}-{}-{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn unique_name(prefix: &str) -> String {
        format!("/aegis-stub-{prefix}")
    }

    #[test]
    fn counters_basic_add_load() {
        let name = unique_name("counters-basic");
        let arena = Arena::open_or_create(&name, 64 * 1024).expect("arena open");
        let counters = SharedCounters::new(&arena, 16).expect("counters new");
        assert_eq!(counters.len(), 16);
        assert_eq!(counters.load(0), 0);
        let prev = counters.add(0, 5);
        assert_eq!(prev, 0);
        assert_eq!(counters.load(0), 5);
        counters.add(0, 7);
        assert_eq!(counters.load(0), 12);
        // Out-of-bounds — no panic
        assert_eq!(counters.load(999), 0);
        assert_eq!(counters.add(999, 100), 0);
        #[cfg(target_os = "linux")]
        let _ = Arena::unlink(&name);
    }

    #[test]
    fn counters_snapshot() {
        let name = unique_name("counters-snap");
        let arena = Arena::open_or_create(&name, 64 * 1024).expect("arena open");
        let counters = SharedCounters::new(&arena, 8).expect("counters new");
        counters.add(0, 100);
        counters.add(3, 200);
        counters.add(7, 42);
        let snap = counters.snapshot();
        assert_eq!(snap.len(), 8);
        assert_eq!(snap[0], 100);
        assert_eq!(snap[1], 0);
        assert_eq!(snap[3], 200);
        assert_eq!(snap[7], 42);
        #[cfg(target_os = "linux")]
        let _ = Arena::unlink(&name);
    }

    #[test]
    fn counters_concurrent_add() {
        use std::sync::Arc;
        use std::thread;
        let name = unique_name("counters-concurrent");
        let arena = Arena::open_or_create(&name, 64 * 1024).expect("arena open");
        let counters = Arc::new(SharedCounters::new(&arena, 4).expect("counters new"));

        // 8 threads × 10_000 fetch_add on slot 0 — expect total
        // load = 80_000 exactly (proves atomics work).
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = Arc::clone(&counters);
            handles.push(thread::spawn(move || {
                for _ in 0..10_000 {
                    c.add(0, 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(counters.load(0), 80_000);
        #[cfg(target_os = "linux")]
        let _ = Arena::unlink(&name);
    }
}
