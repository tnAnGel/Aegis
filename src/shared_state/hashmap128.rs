//! V93 — u128-keyed lock-free open-addressing hashmap in a shared arena.
//!
//! Parallel to [super::hashmap::AtomicHashMap] (which is u32-keyed for
//! IPv4) — this one stores u128 keys so IPv6 addresses can participate
//! in cluster-wide threat scoring without falling back to the per-worker
//! DashMap that V90 introduced as a stopgap.
//!
//! Layout per slot: 32 bytes = 4 × AtomicU64.
//!   * `state`   — bits 62-63 hold {EMPTY, RESERVED, OCCUPIED, TOMBSTONE}.
//!     RESERVED is the in-flight insert state (writer owns the slot
//!     but hasn't published key/value yet).
//!   * `key_hi`  — high 64 bits of the u128 key.
//!   * `key_lo`  — low 64 bits.
//!   * `value`   — 64-bit payload (PackedScore for IPv6 scoring).
//!
//! Insert protocol:
//!   1. Probe; if slot is EMPTY or TOMBSTONE, CAS state → RESERVED.
//!   2. Owner stores key_hi, key_lo, value.
//!   3. Owner releases state → OCCUPIED. Readers ignore RESERVED.
//!
//! Reader protocol (acquire ordering throughout):
//!   1. Load state. EMPTY → key absent.
//!   2. RESERVED or different-key OCCUPIED → continue probing.
//!   3. OCCUPIED + key matches → load value, re-check state (still
//!      OCCUPIED with same key); return value.
//!
//! No ABA hazard for the value alone — slot keys are only rewritten
//! after going through TOMBSTONE → RESERVED → OCCUPIED, so a reader
//! that saw OCCUPIED+matching-key sees consistent payload as long as
//! its post-load state re-check still matches.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{Arena, ArenaError};

const STATE_EMPTY: u64 = 0b00 << 62;
const STATE_RESERVED: u64 = 0b11 << 62;
const STATE_OCCUPIED: u64 = 0b01 << 62;
const STATE_TOMBSTONE: u64 = 0b10 << 62;
const STATE_MASK: u64 = 0b11 << 62;

const MAX_PROBE: usize = 64;

#[repr(C)]
struct Slot128 {
    state: AtomicU64,
    key_hi: AtomicU64,
    key_lo: AtomicU64,
    value: AtomicU64,
}

pub struct AtomicHashMap128 {
    _arena: Arena,
    ptr: *const Slot128,
    capacity: usize,
}

unsafe impl Send for AtomicHashMap128 {}
unsafe impl Sync for AtomicHashMap128 {}

#[derive(Debug, PartialEq, Eq)]
pub enum HashMapError {
    ProbeExhausted,
}

impl std::fmt::Display for HashMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProbeExhausted => write!(
                f,
                "AtomicHashMap128: probe exhausted (table too small for live key count)"
            ),
        }
    }
}

impl std::error::Error for HashMapError {}

impl AtomicHashMap128 {
    /// Fresh allocation. Caller picks `capacity` (must be power of two).
    /// Each slot is 32 bytes — 65536 slots = 2 MiB.
    pub fn new(arena: &Arena, capacity: usize) -> Result<Self, ArenaError> {
        assert!(
            capacity.is_power_of_two(),
            "AtomicHashMap128 capacity must be a power of two"
        );
        let (_, ptr) = arena.alloc_slice::<Slot128>(capacity)?;
        Ok(Self {
            _arena: arena.clone(),
            ptr: ptr as *const Slot128,
            capacity,
        })
    }

    /// Well-known shared allocation (CAS-claim at `name_id`). First
    /// worker allocates; others attach to the same bytes.
    pub fn new_named(arena: &Arena, name_id: usize, capacity: usize) -> Result<Self, ArenaError> {
        assert!(
            capacity.is_power_of_two(),
            "AtomicHashMap128 capacity must be a power of two"
        );
        let (_, ptr) = arena.alloc_named_slice::<Slot128>(name_id, capacity)?;
        Ok(Self {
            _arena: arena.clone(),
            ptr: ptr as *const Slot128,
            capacity,
        })
    }

    /// 64-bit mix of the u128 key. FNV-1a over the 16 LE bytes —
    /// same family as [super::hashmap::AtomicHashMap] for consistency.
    /// IPv6 entropy is concentrated in the lower 64 bits for most
    /// real traffic, so feeding both halves keeps high-prefix collisions
    /// from collapsing.
    #[inline]
    fn hash(key: u128) -> usize {
        const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
        const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
        let mut h = FNV_OFFSET;
        for b in key.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h as usize
    }

    #[inline]
    fn index_for(&self, hash: usize) -> usize {
        hash & (self.capacity - 1)
    }

    /// SAFETY: caller guarantees `idx < self.capacity`.
    #[inline]
    unsafe fn slot(&self, idx: usize) -> &Slot128 {
        unsafe { &*self.ptr.add(idx) }
    }

    pub fn get(&self, key: u128) -> Option<u64> {
        let (hi, lo) = ((key >> 64) as u64, key as u64);
        let start = self.index_for(Self::hash(key));
        for i in 0..MAX_PROBE {
            let idx = (start + i) & (self.capacity - 1);
            let slot = unsafe { self.slot(idx) };
            let st = slot.state.load(Ordering::Acquire) & STATE_MASK;
            if st == STATE_EMPTY {
                return None;
            }
            if st == STATE_OCCUPIED {
                let k_hi = slot.key_hi.load(Ordering::Acquire);
                let k_lo = slot.key_lo.load(Ordering::Acquire);
                if k_hi == hi && k_lo == lo {
                    let val = slot.value.load(Ordering::Acquire);
                    // Re-check state to defend against the slot being
                    // tombstoned + re-claimed for a different key
                    // between our key load and value load.
                    let st2 = slot.state.load(Ordering::Acquire) & STATE_MASK;
                    if st2 == STATE_OCCUPIED {
                        return Some(val);
                    }
                }
            }
            // RESERVED, TOMBSTONE, or wrong-key OCCUPIED → keep probing.
        }
        None
    }

    pub fn insert(&self, key: u128, value: u64) -> Result<Option<u64>, HashMapError> {
        let (hi, lo) = ((key >> 64) as u64, key as u64);
        let start = self.index_for(Self::hash(key));
        for i in 0..MAX_PROBE {
            let idx = (start + i) & (self.capacity - 1);
            let slot = unsafe { self.slot(idx) };
            let st_raw = slot.state.load(Ordering::Acquire);
            let st = st_raw & STATE_MASK;

            if st == STATE_OCCUPIED {
                let k_hi = slot.key_hi.load(Ordering::Acquire);
                let k_lo = slot.key_lo.load(Ordering::Acquire);
                if k_hi == hi && k_lo == lo {
                    let prev = slot.value.swap(value, Ordering::AcqRel);
                    return Ok(Some(prev));
                }
                continue;
            }
            if st == STATE_EMPTY || st == STATE_TOMBSTONE {
                // Claim slot via state CAS.
                match slot.state.compare_exchange(
                    st_raw,
                    STATE_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        slot.key_hi.store(hi, Ordering::Release);
                        slot.key_lo.store(lo, Ordering::Release);
                        slot.value.store(value, Ordering::Release);
                        slot.state.store(STATE_OCCUPIED, Ordering::Release);
                        return Ok(None);
                    }
                    Err(_) => continue,
                }
            }
            // RESERVED — another writer is mid-insert. Keep probing;
            // our target key may live further down the chain.
        }
        Err(HashMapError::ProbeExhausted)
    }

    /// Atomically read-modify-write the value for `key`. The closure
    /// `f` receives the current value (0 for a fresh entry) and returns
    /// the new value; the write to an existing slot is published via a
    /// value-level `compare_exchange` so concurrent updates to the SAME
    /// key never lose increments. `f` may be called more than once if a
    /// CAS loses the race.
    ///
    /// Unlike [Self::insert] (which `swap`s the value, dropping a
    /// concurrent reader-then-writer's increment), this is the correct
    /// primitive for counters.
    pub fn update_with<F>(&self, key: u128, mut f: F) -> Result<u64, HashMapError>
    where
        F: FnMut(u64) -> u64,
    {
        let (hi, lo) = ((key >> 64) as u64, key as u64);
        let start = self.index_for(Self::hash(key));
        for i in 0..MAX_PROBE {
            let idx = (start + i) & (self.capacity - 1);
            let slot = unsafe { self.slot(idx) };
            let st_raw = slot.state.load(Ordering::Acquire);
            let st = st_raw & STATE_MASK;

            if st == STATE_OCCUPIED {
                let k_hi = slot.key_hi.load(Ordering::Acquire);
                let k_lo = slot.key_lo.load(Ordering::Acquire);
                if k_hi == hi && k_lo == lo {
                    // Existing key — CAS-loop on the value.
                    return Ok(Self::cas_value(slot, &mut f));
                }
                continue;
            }
            if st == STATE_EMPTY || st == STATE_TOMBSTONE {
                // Claim slot via state CAS, then publish key + f(0).
                match slot.state.compare_exchange(
                    st_raw,
                    STATE_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // Fresh/tombstoned slot: count starts at 0.
                        let new_val = f(0);
                        slot.key_hi.store(hi, Ordering::Release);
                        slot.key_lo.store(lo, Ordering::Release);
                        slot.value.store(new_val, Ordering::Release);
                        slot.state.store(STATE_OCCUPIED, Ordering::Release);
                        return Ok(new_val);
                    }
                    Err(_) => continue,
                }
            }
            // RESERVED — another writer mid-insert. Keep probing; our
            // target key may live further down the chain.
        }
        Err(HashMapError::ProbeExhausted)
    }

    /// Lock-free value CAS loop for an already-published OCCUPIED slot.
    /// Loops `value.compare_exchange(old, f(old))` until it wins,
    /// returning the value it stored.
    #[inline]
    fn cas_value<F>(slot: &Slot128, f: &mut F) -> u64
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

    pub fn remove(&self, key: u128) -> Option<u64> {
        let (hi, lo) = ((key >> 64) as u64, key as u64);
        let start = self.index_for(Self::hash(key));
        for i in 0..MAX_PROBE {
            let idx = (start + i) & (self.capacity - 1);
            let slot = unsafe { self.slot(idx) };
            let st = slot.state.load(Ordering::Acquire) & STATE_MASK;
            if st == STATE_EMPTY {
                return None;
            }
            if st == STATE_OCCUPIED {
                let k_hi = slot.key_hi.load(Ordering::Acquire);
                let k_lo = slot.key_lo.load(Ordering::Acquire);
                if k_hi == hi && k_lo == lo {
                    let prev = slot.value.load(Ordering::Acquire);
                    slot.state.store(STATE_TOMBSTONE, Ordering::Release);
                    return Some(prev);
                }
            }
        }
        None
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn live_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.capacity {
            let slot = unsafe { self.slot(i) };
            if slot.state.load(Ordering::Relaxed) & STATE_MASK == STATE_OCCUPIED {
                n += 1;
            }
        }
        n
    }

    pub fn snapshot(&self) -> Vec<(u128, u64)> {
        let mut out = Vec::new();
        for i in 0..self.capacity {
            let slot = unsafe { self.slot(i) };
            if slot.state.load(Ordering::Acquire) & STATE_MASK != STATE_OCCUPIED {
                continue;
            }
            let hi = slot.key_hi.load(Ordering::Acquire);
            let lo = slot.key_lo.load(Ordering::Acquire);
            let val = slot.value.load(Ordering::Acquire);
            if slot.state.load(Ordering::Acquire) & STATE_MASK == STATE_OCCUPIED {
                out.push(((hi as u128) << 64 | lo as u128, val));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn unique_name(prefix: &str) -> String {
        format!(
            "/aegis-hm128-{}-{}-{}",
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
        format!("/aegis-hm128-stub-{prefix}")
    }

    fn open_map(prefix: &str, capacity: usize) -> (AtomicHashMap128, String) {
        let name = unique_name(prefix);
        let arena = Arena::open_or_create(&name, 4 * 1024 * 1024).expect("arena");
        let map = AtomicHashMap128::new(&arena, capacity).expect("hashmap128");
        (map, name)
    }

    fn cleanup(name: &str) {
        #[cfg(target_os = "linux")]
        let _ = Arena::unlink(name);
        #[cfg(not(target_os = "linux"))]
        let _ = name;
    }

    #[test]
    fn insert_get_remove_basic_u128() {
        let (m, name) = open_map("basic", 64);
        let k: u128 = (0x2001_0db8_0000_0000u128 << 64) | 0x0000_0000_0000_0001;
        assert_eq!(m.get(k), None);
        assert_eq!(m.insert(k, 100).unwrap(), None);
        assert_eq!(m.get(k), Some(100));
        assert_eq!(m.insert(k, 200).unwrap(), Some(100));
        assert_eq!(m.get(k), Some(200));
        assert_eq!(m.remove(k), Some(200));
        assert_eq!(m.get(k), None);
        cleanup(&name);
    }

    #[test]
    fn distinct_keys_no_collision_collapse() {
        let (m, name) = open_map("distinct", 256);
        // Keys differ only in the low 64 bits — must remain distinct.
        for i in 0..50u128 {
            let k = (0xdead_beefu128 << 64) | i;
            m.insert(k, (i as u64) * 13).unwrap();
        }
        for i in 0..50u128 {
            let k = (0xdead_beefu128 << 64) | i;
            assert_eq!(m.get(k), Some((i as u64) * 13), "key i={i}");
        }
        assert_eq!(m.live_count(), 50);
        cleanup(&name);
    }

    #[test]
    fn snapshot_returns_live_u128_entries() {
        let (m, name) = open_map("snap", 32);
        let k1: u128 = 0xaa;
        let k2: u128 = 0xbb;
        let k3: u128 = 0xcc;
        m.insert(k1, 10).unwrap();
        m.insert(k2, 20).unwrap();
        m.insert(k3, 30).unwrap();
        m.remove(k2);
        let mut snap = m.snapshot();
        snap.sort();
        assert_eq!(snap, vec![(k1, 10), (k3, 30)]);
        cleanup(&name);
    }

    #[test]
    fn concurrent_insert_distinct_u128_keys() {
        use std::sync::Arc;
        use std::thread;
        let (m, name) = open_map("concurrent", 16384);
        let m = Arc::new(m);
        let mut handles = Vec::new();
        for tid in 0..8u128 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for i in 0..500u128 {
                    let key = (tid << 64) | i;
                    m.insert(key, ((tid as u64) * 1000) + (i as u64)).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        for tid in 0..8u128 {
            for i in 0..500u128 {
                let key = (tid << 64) | i;
                let expect = ((tid as u64) * 1000) + (i as u64);
                assert_eq!(m.get(key), Some(expect), "tid={tid} i={i}");
            }
        }
        assert_eq!(m.live_count(), 4000);
        cleanup(&name);
    }

    #[test]
    fn update_with_basic_u128() {
        let (m, name) = open_map("update-basic", 64);
        let k: u128 = (0x2001_0db8u128 << 64) | 0x42;
        // Fresh key — closure sees 0.
        assert_eq!(m.update_with(k, |v| v + 10).unwrap(), 10);
        assert_eq!(m.get(k), Some(10));
        // Existing key.
        assert_eq!(m.update_with(k, |v| v + 5).unwrap(), 15);
        assert_eq!(m.get(k), Some(15));
        assert_eq!(m.live_count(), 1);
        cleanup(&name);
    }

    #[test]
    fn update_with_reuses_tombstone_from_zero_u128() {
        let (m, name) = open_map("update-tomb", 16);
        let k: u128 = 0xfeed;
        m.insert(k, 999).unwrap();
        m.remove(k);
        // Re-claiming a tombstoned slot starts the count at 0.
        assert_eq!(m.update_with(k, |v| v + 1).unwrap(), 1);
        assert_eq!(m.get(k), Some(1));
        cleanup(&name);
    }

    #[test]
    fn concurrent_update_with_same_key_no_lost_updates_u128() {
        use std::sync::Arc;
        use std::thread;
        // 8 threads × 1000 increments of the SAME u128 key.
        let (m, name) = open_map("update-same", 64);
        let m = Arc::new(m);
        let k: u128 = (0xdead_beefu128 << 64) | 0x1234;
        let mut handles = Vec::new();
        for _ in 0..8u32 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    m.update_with(k, |v| v + 1).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.get(k), Some(8000), "lost increments under contention");
        assert_eq!(m.live_count(), 1);
        cleanup(&name);
    }
}
