//! Cross-process shared-state arena for the Phase D
//! [shared mmap state plane](../../AEGIS-X-ROADMAP.md).
//!
//! Multi-process REUSEPORT (V71+) gives each pingora worker its own
//! address space. Per-worker `DashMap` instances for ThreatScorer /
//! DynamicTrust / AnomalyDetector therefore see only one quarter of
//! the cluster's traffic — a distributed attacker can saturate
//! worker A's view of an IP while worker B still sees a clean score.
//!
//! Phase D fixes this by allocating a single shared anonymous-mmap
//! arena (`shm_open` + `mmap(MAP_SHARED)`) that every worker opens
//! at startup. Lock-free hashmaps inside the arena (open-addressing
//! + CAS) let any worker read/write any per-IP counter, so the
//! cluster sees a unified score.
//!
//! V86 ships the foundation: arena open/create, bump allocator,
//! atomic-backed primitives. V87+ migrate the existing scorer /
//! trust / anomaly state to use it. Crates like `shared_memory` /
//! `raw-sync` would have worked, but the contract here is small
//! enough to avoid a new dependency — `libc::shm_open` + `mmap` are
//! sufficient and let us audit every syscall.
//!
//! Safety invariants:
//!   * Arena name must be unique per cluster (default `/aegis-state`)
//!   * Workers MUST agree on size at open time; first one wins, rest
//!     are checked
//!   * Bump allocator never frees individual allocations (compaction
//!     happens by recycling the whole arena on operator request)
//!   * All shared state must be `#[repr(C)]` + `Sync` + `Pod`-like;
//!     no Rust-side smart pointers (Arc/Box) — those reference the
//!     allocating process's heap

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

/// Linux-only for now. The cross-process shared-state arena uses
/// `shm_open` + `mmap(MAP_SHARED)` which are POSIX but only worth
/// the integration effort on the platform we deploy to.
#[cfg(target_os = "linux")]
pub mod arena_linux;

/// V87 — cluster-wide atomic counter primitive built on the
/// Arena foundation. Generic enough to be re-used by metrics +
/// scorer + any other "I need an aggregate u64 across N workers"
/// scenario.
pub mod counters;

/// V88 — lock-free open-addressing hashmap (u32 key, u64 value)
/// inside the Arena. Foundation for V89 ThreatScorer migration:
/// cluster-wide per-IP score table that all REUSEPORT workers
/// read and write to atomically.
pub mod hashmap;
pub mod hashmap128;

/// V89 — process-global access to the arena + counters. Lazy
/// init at daemon startup; hot-path code reaches counters via
/// `crate::shared_state::cluster_counter(IDX)` without plumbing.
pub mod global;

pub use counters::SharedCounters;
pub use hashmap::{AtomicHashMap, HashMapError};

/// Platform-neutral facade. On Linux, delegates to `arena_linux`.
/// On other platforms, returns a no-op stub so the rest of the
/// codebase compiles without `#[cfg]` everywhere.
#[cfg(target_os = "linux")]
pub use arena_linux::{Arena, ArenaError};

#[cfg(not(target_os = "linux"))]
pub use stub::{Arena, ArenaError};

#[cfg(not(target_os = "linux"))]
mod stub;

/// Well-known allocation IDs. Workers use [BumpAllocator::alloc_named]
/// to claim or attach to a fixed-purpose region. First-creator
/// allocates and stores the offset in `named_offsets[ID]`;
/// subsequent joiners CAS-fail the claim, read the stored offset,
/// and attach to the same physical bytes.
pub mod named {
    /// V91 — SharedScorer IPv4 AtomicHashMap allocation.
    pub const SHARED_SCORER_V4: usize = 0;
    /// V93 — SharedScorer IPv6 AtomicHashMap128 allocation.
    pub const SHARED_SCORER_V6: usize = 1;
    /// V94+ reserved slots. Bump NAMED_SLOTS when adding.
    pub const NAMED_SLOTS: usize = 16;
}

/// A bump allocator inside the shared arena. Each `alloc()` call
/// atomically advances the head pointer; never reclaims space. Used
/// for fixed-size shared-state structures (counter slabs, hashmap
/// bucket arrays) that live for the daemon's lifetime.
///
/// Returns a byte offset into the arena. Callers cast to their typed
/// view via `arena.slice_at::<T>(offset)`. Alignment is rounded up
/// to `T`'s alignment automatically.
///
/// Named allocations (V91): well-known purposes (e.g.
/// SHARED_SCORER_V4) use [Self::alloc_named] which stores the
/// offset in a small per-purpose registry inside the header,
/// so cross-process joiners attach to the SAME physical bytes
/// rather than each allocating their own copy.
#[repr(C)]
pub struct BumpAllocator {
    /// Atomic offset into the arena (in bytes). Starts at
    /// `size_of::<BumpAllocator>()` so we don't overwrite our own
    /// header.
    head: AtomicU64,
    /// Maximum offset (exclusive). Stored so alloc fast-paths can
    /// check capacity without consulting the Arena struct.
    capacity: u64,
    /// V91 — well-known offsets keyed by `named::*` index. 0
    /// means unclaimed; first-creator CAS's its offset in here.
    /// Sized at compile-time via `named::NAMED_SLOTS`.
    named_offsets: [AtomicU64; named::NAMED_SLOTS],
}

impl BumpAllocator {
    /// Initialise a freshly-mapped arena. Called by the first
    /// process that creates the segment; subsequent openers see the
    /// already-initialised header.
    pub fn init(&self, capacity: u64) {
        self.head.store(
            std::mem::size_of::<BumpAllocator>() as u64,
            Ordering::Relaxed,
        );
        // Capacity is stored once; future opens validate against
        // the same value (handled at the Arena layer).
        unsafe {
            // SAFETY: capacity is read by Arena::open with the same
            // alignment guarantee. AtomicU64 is sufficient on every
            // platform we target (Linux x86_64 + aarch64).
            (&self.capacity as *const u64 as *mut u64).write(capacity);
        }
        // named_offsets are zero-initialised by mmap; no explicit
        // store needed.
    }

    /// Claim or attach to a well-known allocation. Used by V91+
    /// to ensure all REUSEPORT workers share the SAME underlying
    /// bytes for a given purpose (e.g. SharedScorer's hashmap)
    /// rather than each bump-allocating their own region.
    ///
    /// Semantics:
    ///   1. Read named_offsets[name_id]. If non-zero, return it
    ///      (joiner path — attach to existing allocation).
    ///   2. Otherwise alloc(size, align) and CAS-store into
    ///      named_offsets[name_id]. If the CAS races and another
    ///      worker won, our alloc is wasted (small) and we attach
    ///      to the winner's offset instead.
    ///
    /// Returns the offset to use for the typed view.
    pub fn alloc_named(&self, name_id: usize, size: u64, align: u64) -> Option<u64> {
        if name_id >= named::NAMED_SLOTS {
            return None;
        }
        // Fast path: already claimed.
        let existing = self.named_offsets[name_id].load(Ordering::Acquire);
        if existing != 0 {
            return Some(existing);
        }
        // Slow path: try to claim. Allocate, then CAS-store.
        let our_offset = self.alloc(size, align)?;
        match self.named_offsets[name_id].compare_exchange(
            0,
            our_offset,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Some(our_offset),
            Err(winner_offset) => {
                // Lost the race. Our bump-allocated region is now
                // orphaned (~1MB of slack in the typical case), but
                // the winner's offset is the one everyone agrees on.
                // For SharedScorer this happens at most once across
                // worker startup — bounded waste.
                Some(winner_offset)
            }
        }
    }

    /// Allocate `size` bytes aligned to `align`. Returns the byte
    /// offset inside the arena. `None` means out-of-space.
    pub fn alloc(&self, size: u64, align: u64) -> Option<u64> {
        debug_assert!(align.is_power_of_two(), "align must be a power of two");
        let mask = align - 1;
        loop {
            let cur = self.head.load(Ordering::Acquire);
            let aligned = (cur + mask) & !mask;
            let next = aligned.checked_add(size)?;
            if next > self.capacity {
                return None;
            }
            // CAS: if no other allocator raced us, claim the slot.
            // On contention, loop with the fresh `head` value.
            match self
                .head
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(aligned),
                Err(_) => continue,
            }
        }
    }

    /// Bytes currently allocated. Cheap atomic load; safe to call
    /// from any thread.
    pub fn used(&self) -> u64 {
        self.head
            .load(Ordering::Relaxed)
            .saturating_sub(std::mem::size_of::<BumpAllocator>() as u64)
    }

    /// Total capacity in bytes.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Free space in bytes.
    pub fn free(&self) -> u64 {
        self.capacity
            .saturating_sub(self.head.load(Ordering::Relaxed))
    }
}

// `io_err` (Linux-only helper) now lives in `arena_linux.rs` — the
// stub impl doesn't surface raw errno values so it doesn't need a
// shared helper here.

#[cfg(test)]
mod tests {
    use super::*;

    /// Bump allocator unit test using a stack-allocated header. Does
    /// not touch the mmap layer — just validates the alloc/align
    /// logic that runs INSIDE the arena.
    #[test]
    fn bump_alloc_basic() {
        // Use Box<[u8]> as a stand-in for the arena memory. The
        // BumpAllocator header lives at offset 0; we'd never do
        // this for real (the header lives in the mmap'd region),
        // but for unit-testing the alloc math it's equivalent.
        let mut backing = vec![0u8; 4096].into_boxed_slice();
        let ptr = backing.as_mut_ptr() as *mut BumpAllocator;
        // SAFETY: BumpAllocator is #[repr(C)] with two u64 fields,
        // boxed slice is well-aligned for u64, no aliasing because
        // we're the sole owner.
        let alloc = unsafe { &*ptr };
        alloc.init(4096);

        // First alloc — should land right after the header.
        let header_size = std::mem::size_of::<BumpAllocator>() as u64;
        let a = alloc.alloc(64, 8).expect("alloc 64 bytes");
        assert_eq!(a, header_size); // first slot after header
        let b = alloc.alloc(32, 8).expect("alloc 32 bytes");
        assert_eq!(b, header_size + 64);
        let c = alloc.alloc(16, 16).expect("alloc 16 aligned to 16");
        // c must be 16-byte aligned. header_size + 64 + 32 = header + 96.
        // If header_size = 16 (two u64s), then 16 + 96 = 112, already aligned 16.
        assert_eq!(c % 16, 0);

        assert!(alloc.used() >= 64 + 32 + 16);
        assert!(alloc.free() < 4096);
    }

    #[test]
    fn bump_alloc_oom_returns_none() {
        // BumpAllocator header is now ~16 + 16*8 = 144 bytes (V91
        // added the named_offsets registry). Size the backing
        // generously and OOM with a request bigger than capacity.
        let mut backing = vec![0u8; 512].into_boxed_slice();
        let ptr = backing.as_mut_ptr() as *mut BumpAllocator;
        let alloc = unsafe { &*ptr };
        alloc.init(512);

        let _ = alloc.alloc(300, 8).expect("first alloc fits");
        // 512 - header - 300 ≈ 68 bytes left. 100 bytes OOMs.
        assert!(alloc.alloc(100, 8).is_none(), "alloc must OOM");
    }

    #[test]
    fn bump_alloc_concurrent_cas() {
        use std::sync::Arc;
        use std::thread;

        // 64 KiB arena, 8 threads each allocating 100×8-byte slots.
        // Expect all allocations to succeed (8 × 100 × 8 = 6400 bytes
        // total + header). Check that all returned offsets are unique
        // (proves CAS correctly serialises concurrent bumps).
        let backing = Arc::new(std::sync::Mutex::new(vec![0u8; 65536]));
        let ptr = backing.lock().unwrap().as_mut_ptr() as usize;
        // SAFETY: pointer escapes the lock scope but only as usize;
        // no concurrent mutation of the Vec itself, only of its
        // contents (the atomic header) which is what we're testing.
        let alloc_ptr = ptr as *mut BumpAllocator;
        // SAFETY: header lives at offset 0 of the backing buffer,
        // single owner during the test.
        let alloc = unsafe { &*alloc_ptr };
        alloc.init(65536);

        let mut handles = Vec::new();
        let results: Arc<std::sync::Mutex<Vec<u64>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        for _ in 0..8 {
            let r = Arc::clone(&results);
            let p = alloc_ptr as usize;
            handles.push(thread::spawn(move || {
                // SAFETY: header outlives the thread by construction
                let a = unsafe { &*(p as *const BumpAllocator) };
                let mut mine = Vec::new();
                for _ in 0..100 {
                    if let Some(off) = a.alloc(8, 8) {
                        mine.push(off);
                    }
                }
                r.lock().unwrap().extend(mine);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let mut offsets = results.lock().unwrap().clone();
        offsets.sort_unstable();
        offsets.dedup();
        // After dedup, count must equal original count (no
        // duplicate offsets from concurrent CAS).
        assert_eq!(offsets.len(), 800, "all 800 offsets must be unique");
    }
}
