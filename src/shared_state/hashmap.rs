//! Lock-free open-addressing hashmap inside a [shared mmap arena](super::Arena).
//!
//! V88 — the primitive that V89 will use to migrate ThreatScorer's
//! per-IP `DashMap<IpAddr, WindowStats>` to a cluster-wide shared
//! table. Designed for cross-process atomic access with no locks at
//! all on the read or insert paths.
//!
//! Design constraints
//! ------------------
//! * Fixed capacity — the arena's bump allocator can't grow tables
//!   so we pre-size at open time. Operators choose capacity based on
//!   expected unique-key cardinality (~100k IPs/day → 256k slots).
//! * Open addressing with linear probing. Collisions resolved by
//!   walking adjacent slots until empty/match found. Bounded by
//!   max probe distance (default 64); past that the insert fails.
//! * Atomic state packed into the key word (bits 62-63), so each
//!   slot is exactly 16 bytes (2× AtomicU64) — cache-line-aligned
//!   pairs fit in a single 64-byte cache line.
//! * Tombstones on remove so probe sequences don't break. Periodic
//!   compaction (V90 work) reclaims them.
//! * **u32 keys only.** IPv4 addresses fit, IPv6 will be addressed
//!   in V89+ via a separate map (or extended slot layout).
//!
//! Operations and their costs
//! --------------------------
//!   lookup(key)          : O(probe distance) atomic loads, no CAS
//!   insert_or_update     : O(probe distance) atomic loads + 1 CAS
//!   remove(key)          : O(probe distance) atomic loads + 1 store
//!   iter (rare; admin)   : O(capacity) atomic loads
//!
//! Memory layout for N slots: N × 16 bytes. 256k slots = 4 MiB.
//!
//! Safety
//! ------
//! All access is via atomic operations. The slot array's lifetime is
//! tied to the held Arena Arc; dropping the Arena would unmap the
//! backing memory, which is why AtomicHashMap clones the Arc into
//! its own field.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{Arena, ArenaError};

/// State bits packed into the high two bits of the key atomic.
/// Layout: `bits 0..32 = key (u32)`, `bits 62..64 = state`.
/// Bits 32..62 reserved (currently zero, V89+ may use for
/// per-slot generation counter to detect ABA in tombstone reuse).
const STATE_EMPTY: u64 = 0b00 << 62;
const STATE_OCCUPIED: u64 = 0b01 << 62;
const STATE_TOMBSTONE: u64 = 0b10 << 62;
const STATE_MASK: u64 = 0b11 << 62;
const KEY_MASK: u64 = 0x0000_0000_FFFF_FFFF;

/// Maximum linear probe distance. Bounded so a pathological
/// (full-table) insert can't loop forever. Reasonable upper bound
/// for fill < 75% with a good hash.
const MAX_PROBE: usize = 64;

#[repr(C)]
struct AtomicSlot {
    key_state: AtomicU64,
    value: AtomicU64,
}

/// Lock-free open-addressing hashmap for `(u32 key, u64 value)`.
/// Backed by an array of AtomicSlot inside an Arena.
pub struct AtomicHashMap {
    _arena: Arena,
    ptr: *const AtomicSlot,
    capacity: usize,
}

// SAFETY: AtomicSlot fields are AtomicU64 (Sync); ptr references
// arena-backed memory whose lifetime is tied to the Arc'd Arena.
unsafe impl Send for AtomicHashMap {}
unsafe impl Sync for AtomicHashMap {}

impl AtomicHashMap {
    /// Allocate a new hashmap with `capacity` slots inside `arena`.
    /// Capacity should be ~2x expected key count for good probe
    /// distance (fill factor < 50%). Must be a power of two for
    /// the modulo-by-mask optimisation in `index_for`.
    ///
    /// NB: this allocates a FRESH region — each call consumes
    /// `capacity * 16` bytes from the arena. For cross-process
    /// shared tables (typical V91+ use), see [Self::new_named]
    /// which CAS-claims a well-known offset so all workers attach
    /// to the same physical bytes.
    pub fn new(arena: &Arena, capacity: usize) -> Result<Self, ArenaError> {
        assert!(
            capacity.is_power_of_two(),
            "AtomicHashMap capacity must be a power of two"
        );
        let (_, ptr) = arena.alloc_slice::<AtomicSlot>(capacity)?;
        Ok(Self {
            _arena: arena.clone(),
            ptr: ptr as *const AtomicSlot,
            capacity,
        })
    }

    /// V91 — open the well-known shared hashmap for `name_id`.
    /// First worker to call allocates and CAS-claims the offset;
    /// subsequent workers attach to the same physical bytes
    /// without re-allocating. All workers see the same `(key,value)`
    /// inserts because they're hitting the same atomic slots.
    pub fn new_named(arena: &Arena, name_id: usize, capacity: usize) -> Result<Self, ArenaError> {
        assert!(
            capacity.is_power_of_two(),
            "AtomicHashMap capacity must be a power of two"
        );
        let (_, ptr) = arena.alloc_named_slice::<AtomicSlot>(name_id, capacity)?;
        Ok(Self {
            _arena: arena.clone(),
            ptr: ptr as *const AtomicSlot,
            capacity,
        })
    }

    /// Mix function. FNV-1a is dead simple, low collision rate for
    /// u32 keys, no external crate. For IP addresses the entropy is
    /// fine (the lower octets vary). If we ever need a stronger
    /// hash, swap for wyhash or aHash (both pure-Rust).
    #[inline]
    fn hash(key: u32) -> usize {
        const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
        const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
        let mut h = FNV_OFFSET;
        for b in key.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h as usize
    }

    /// Map a hash to a slot index. Capacity is power-of-two so
    /// modulo becomes a single AND with the capacity mask.
    #[inline]
    fn index_for(&self, hash: usize) -> usize {
        hash & (self.capacity - 1)
    }

    /// SAFETY: caller guarantees `idx < self.capacity`.
    #[inline]
    unsafe fn slot(&self, idx: usize) -> &AtomicSlot {
        unsafe { &*self.ptr.add(idx) }
    }

    /// Lookup the value for `key`. Returns `None` if absent.
    /// Linear-probes from the hash-derived index, bailing on empty.
    /// Tombstones are skipped (their original key may have been
    /// evicted but the probe sequence continues past them).
    pub fn get(&self, key: u32) -> Option<u64> {
        let start = self.index_for(Self::hash(key));
        for i in 0..MAX_PROBE {
            let idx = (start + i) & (self.capacity - 1);
            // SAFETY: idx is in-range by construction.
            let slot = unsafe { self.slot(idx) };
            let ks = slot.key_state.load(Ordering::Acquire);
            let state = ks & STATE_MASK;
            if state == STATE_EMPTY {
                return None; // hit an empty slot → key isn't in the map
            }
            if state == STATE_OCCUPIED && (ks & KEY_MASK) == key as u64 {
                return Some(slot.value.load(Ordering::Acquire));
            }
            // Tombstone or different key → continue probing.
        }
        None
    }

    /// Insert (or update) `key → value`. Returns the previous
    /// value if the key was already present, `None` on first
    /// insert. Returns `Err(Full)` only if every slot in the
    /// MAX_PROBE window is occupied by some other key — basically
    /// only when the table is wildly over capacity.
    pub fn insert(&self, key: u32, value: u64) -> Result<Option<u64>, HashMapError> {
        let start = self.index_for(Self::hash(key));
        for i in 0..MAX_PROBE {
            let idx = (start + i) & (self.capacity - 1);
            let slot = unsafe { self.slot(idx) };
            let ks = slot.key_state.load(Ordering::Acquire);
            let state = ks & STATE_MASK;

            if state == STATE_OCCUPIED && (ks & KEY_MASK) == key as u64 {
                // Existing key — just update value, return previous.
                let prev = slot.value.swap(value, Ordering::AcqRel);
                return Ok(Some(prev));
            }
            if state == STATE_EMPTY || state == STATE_TOMBSTONE {
                // Try to claim this slot via CAS. If another writer
                // grabbed it first we loop and re-probe.
                let new_ks = STATE_OCCUPIED | (key as u64 & KEY_MASK);
                match slot.key_state.compare_exchange(
                    ks,
                    new_ks,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // We own the slot now; safe to write value.
                        slot.value.store(value, Ordering::Release);
                        return Ok(None);
                    }
                    Err(_) => {
                        // Lost the race. Re-read state and decide:
                        // if the winner inserted OUR key, update.
                        let cur_ks = slot.key_state.load(Ordering::Acquire);
                        if cur_ks & STATE_MASK == STATE_OCCUPIED && cur_ks & KEY_MASK == key as u64
                        {
                            let prev = slot.value.swap(value, Ordering::AcqRel);
                            return Ok(Some(prev));
                        }
                        // Winner inserted DIFFERENT key — keep probing.
                        continue;
                    }
                }
            }
            // Occupied by different key — continue.
        }
        Err(HashMapError::ProbeExhausted)
    }

    /// Atomically read-modify-write the value for `key`. The closure
    /// `f` is given the current value (0 for a fresh entry) and
    /// returns the new value; the write is published via a value-level
    /// `compare_exchange` so concurrent updates to the SAME key never
    /// lose increments. `f` may be called more than once if another
    /// writer wins the race — keep it pure/idempotent w.r.t. its input.
    ///
    /// Unlike [Self::insert] (which `swap`s the value and so drops a
    /// concurrent reader-then-writer's increment), this is the correct
    /// primitive for counters: locate/claim the slot, then loop
    /// `value.compare_exchange(old, f(old))` until it succeeds.
    /// Returns the value that was stored on the winning CAS.
    pub fn update_with<F>(&self, key: u32, mut f: F) -> Result<u64, HashMapError>
    where
        F: FnMut(u64) -> u64,
    {
        let start = self.index_for(Self::hash(key));
        for i in 0..MAX_PROBE {
            let idx = (start + i) & (self.capacity - 1);
            // SAFETY: idx is in-range by construction.
            let slot = unsafe { self.slot(idx) };
            let ks = slot.key_state.load(Ordering::Acquire);
            let state = ks & STATE_MASK;

            if state == STATE_OCCUPIED && (ks & KEY_MASK) == key as u64 {
                // Existing key — CAS-loop on the value.
                return Ok(Self::cas_value(slot, &mut f));
            }
            if state == STATE_EMPTY || state == STATE_TOMBSTONE {
                // Try to claim this slot via CAS on key_state. The
                // value of a fresh/tombstoned slot is logically 0 for
                // our purposes — we store f(0) once we own it.
                let new_ks = STATE_OCCUPIED | (key as u64 & KEY_MASK);
                match slot.key_state.compare_exchange(
                    ks,
                    new_ks,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // We own the slot. A tombstoned slot may carry
                        // a stale value from its previous occupant, so
                        // start the count from 0 rather than that value.
                        let new_val = f(0);
                        slot.value.store(new_val, Ordering::Release);
                        return Ok(new_val);
                    }
                    Err(_) => {
                        // Lost the race. If the winner claimed OUR key,
                        // CAS-loop on its value; otherwise keep probing.
                        let cur_ks = slot.key_state.load(Ordering::Acquire);
                        if cur_ks & STATE_MASK == STATE_OCCUPIED && cur_ks & KEY_MASK == key as u64
                        {
                            return Ok(Self::cas_value(slot, &mut f));
                        }
                        continue;
                    }
                }
            }
            // Occupied by different key — continue probing.
        }
        Err(HashMapError::ProbeExhausted)
    }

    /// Lock-free value CAS loop for an already-claimed OCCUPIED slot.
    /// Loops `value.compare_exchange(old, f(old))` until it wins,
    /// returning the value it stored.
    #[inline]
    fn cas_value<F>(slot: &AtomicSlot, f: &mut F) -> u64
    where
        F: FnMut(u64) -> u64,
    {
        let mut old = slot.value.load(Ordering::Acquire);
        loop {
            let new = f(old);
            match slot
                .value
                .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return new,
                Err(actual) => old = actual,
            }
        }
    }

    /// Remove `key` by marking its slot as a tombstone. Returns
    /// the previous value if present. Probe sequences past this
    /// slot still work because tombstone != empty.
    pub fn remove(&self, key: u32) -> Option<u64> {
        let start = self.index_for(Self::hash(key));
        for i in 0..MAX_PROBE {
            let idx = (start + i) & (self.capacity - 1);
            let slot = unsafe { self.slot(idx) };
            let ks = slot.key_state.load(Ordering::Acquire);
            let state = ks & STATE_MASK;
            if state == STATE_EMPTY {
                return None;
            }
            if state == STATE_OCCUPIED && (ks & KEY_MASK) == key as u64 {
                let prev = slot.value.load(Ordering::Acquire);
                // Best-effort: mark tombstone. If a concurrent writer
                // already updated the value or reused the slot, we
                // still mark — the tombstone semantics just need
                // "key was here, now isn't". Future inserts treat
                // tombstone as reusable.
                let tomb = STATE_TOMBSTONE | (key as u64 & KEY_MASK);
                slot.key_state.store(tomb, Ordering::Release);
                return Some(prev);
            }
        }
        None
    }

    /// Number of slots (capacity, not live entries).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Approximate live entry count. O(capacity) walk; intended
    /// for admin/metrics, NOT the hot path.
    pub fn live_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.capacity {
            let slot = unsafe { self.slot(i) };
            let ks = slot.key_state.load(Ordering::Relaxed);
            if ks & STATE_MASK == STATE_OCCUPIED {
                n += 1;
            }
        }
        n
    }

    /// Iterate live (key, value) pairs. O(capacity); admin-only.
    pub fn snapshot(&self) -> Vec<(u32, u64)> {
        let mut out = Vec::new();
        for i in 0..self.capacity {
            let slot = unsafe { self.slot(i) };
            let ks = slot.key_state.load(Ordering::Acquire);
            if ks & STATE_MASK == STATE_OCCUPIED {
                let key = (ks & KEY_MASK) as u32;
                let val = slot.value.load(Ordering::Acquire);
                out.push((key, val));
            }
        }
        out
    }
}

/// Errors returned by `AtomicHashMap` mutation paths.
#[derive(Debug, PartialEq, Eq)]
pub enum HashMapError {
    /// MAX_PROBE consecutive slots are occupied by other keys.
    /// Indicates table is too small for live cardinality —
    /// operator should grow `capacity`.
    ProbeExhausted,
}

impl std::fmt::Display for HashMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProbeExhausted => write!(
                f,
                "AtomicHashMap: probe exhausted (table too small for live key count)"
            ),
        }
    }
}

impl std::error::Error for HashMapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn unique_name(prefix: &str) -> String {
        format!(
            "/aegis-hm-{}-{}-{}",
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
        format!("/aegis-hm-stub-{prefix}")
    }

    fn open_map(prefix: &str, capacity: usize) -> (AtomicHashMap, String) {
        let name = unique_name(prefix);
        let arena = Arena::open_or_create(&name, 1024 * 1024).expect("arena");
        let map = AtomicHashMap::new(&arena, capacity).expect("hashmap");
        (map, name)
    }

    fn cleanup(name: &str) {
        #[cfg(target_os = "linux")]
        let _ = Arena::unlink(name);
        #[cfg(not(target_os = "linux"))]
        let _ = name;
    }

    #[test]
    fn insert_get_remove_basic() {
        let (m, name) = open_map("basic", 64);
        assert_eq!(m.get(42), None);
        assert_eq!(m.insert(42, 100).unwrap(), None);
        assert_eq!(m.get(42), Some(100));
        // Update
        assert_eq!(m.insert(42, 200).unwrap(), Some(100));
        assert_eq!(m.get(42), Some(200));
        // Remove
        assert_eq!(m.remove(42), Some(200));
        assert_eq!(m.get(42), None);
        cleanup(&name);
    }

    #[test]
    fn collision_via_linear_probe() {
        // Tiny table → frequent collisions → exercises probe path
        let (m, name) = open_map("collide", 16);
        for i in 1..=8u32 {
            assert_eq!(m.insert(i, (i as u64) * 10).unwrap(), None);
        }
        // All keys must still be retrievable despite collisions
        for i in 1..=8u32 {
            assert_eq!(m.get(i), Some((i as u64) * 10));
        }
        assert_eq!(m.live_count(), 8);
        cleanup(&name);
    }

    #[test]
    fn tombstone_doesnt_break_probe() {
        let (m, name) = open_map("tomb", 16);
        // Insert several
        for i in 1..=5u32 {
            m.insert(i, i as u64).unwrap();
        }
        // Remove middle
        m.remove(3);
        // Subsequent keys still findable (probe walks past tombstone)
        assert_eq!(m.get(4), Some(4));
        assert_eq!(m.get(5), Some(5));
        // Slot is reusable
        m.insert(99, 999).unwrap();
        assert_eq!(m.get(99), Some(999));
        cleanup(&name);
    }

    #[test]
    fn snapshot_returns_live_entries() {
        let (m, name) = open_map("snap", 32);
        m.insert(1, 10).unwrap();
        m.insert(2, 20).unwrap();
        m.insert(3, 30).unwrap();
        m.remove(2);
        let mut snap = m.snapshot();
        snap.sort();
        assert_eq!(snap, vec![(1, 10), (3, 30)]);
        cleanup(&name);
    }

    #[test]
    fn concurrent_insert_distinct_keys() {
        use std::sync::Arc;
        use std::thread;
        // 8 threads × 1000 distinct keys = 8000 inserts. Capacity
        // 16k so fill = 50% (good probe behaviour).
        let (m, name) = open_map("concurrent", 16384);
        let m = Arc::new(m);
        let mut handles = Vec::new();
        for tid in 0..8u32 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for i in 0..1000u32 {
                    let key = tid * 1000 + i;
                    m.insert(key, (key as u64) * 7).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Verify every key reads back its value
        for tid in 0..8u32 {
            for i in 0..1000u32 {
                let key = tid * 1000 + i;
                assert_eq!(m.get(key), Some((key as u64) * 7), "key {key}");
            }
        }
        assert_eq!(m.live_count(), 8000);
        cleanup(&name);
    }

    #[test]
    fn concurrent_insert_same_key_one_winner() {
        use std::sync::Arc;
        use std::thread;
        // 8 threads each insert the same key with different values.
        // Last-writer-wins semantics — final value must be ONE of
        // the inserted values, not garbage.
        let (m, name) = open_map("same-key", 64);
        let m = Arc::new(m);
        let mut handles = Vec::new();
        for tid in 0..8u64 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    m.insert(42, tid * 1_000_000).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let v = m.get(42).expect("key 42 must be present");
        // Value must be one of: 0, 1M, 2M, ..., 7M
        assert!(v % 1_000_000 == 0 && v <= 7_000_000, "got {v}");
        // Only one slot consumed
        assert_eq!(m.live_count(), 1);
        cleanup(&name);
    }

    #[test]
    fn update_with_basic() {
        let (m, name) = open_map("update-basic", 64);
        // Fresh key — closure sees 0, stores f(0).
        assert_eq!(m.update_with(7, |v| v + 10).unwrap(), 10);
        assert_eq!(m.get(7), Some(10));
        // Existing key — closure sees current value.
        assert_eq!(m.update_with(7, |v| v + 5).unwrap(), 15);
        assert_eq!(m.get(7), Some(15));
        assert_eq!(m.live_count(), 1);
        cleanup(&name);
    }

    #[test]
    fn update_with_reuses_tombstone_from_zero() {
        let (m, name) = open_map("update-tomb", 16);
        m.insert(5, 999).unwrap();
        m.remove(5);
        // Re-claiming a tombstoned slot must start the count at 0,
        // not the dead occupant's value.
        assert_eq!(m.update_with(5, |v| v + 1).unwrap(), 1);
        assert_eq!(m.get(5), Some(1));
        cleanup(&name);
    }

    #[test]
    fn concurrent_update_with_same_key_no_lost_updates() {
        use std::sync::Arc;
        use std::thread;
        // 8 threads × 1000 increments of the SAME key. A swap-based
        // RMW would lose updates here; the value-level CAS must not.
        let (m, name) = open_map("update-same", 64);
        let m = Arc::new(m);
        let mut handles = Vec::new();
        for _ in 0..8u32 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    m.update_with(42, |v| v + 1).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.get(42), Some(8000), "lost increments under contention");
        assert_eq!(m.live_count(), 1);
        cleanup(&name);
    }
}
