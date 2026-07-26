//! Cache-line-padded sharded counter — eliminates cross-CPU cache-line
//! contention on the metrics fast path.
//!
//! Multiple CPUs `fetch_add`ing the same `AtomicU64` ping-pong the
//! cache line between cores on every increment. On a 10-core ARM64
//! at 100k+ RPS this is measurably hot in profile. Splitting the
//! counter into a per-CPU array (each padded to its own cache line)
//! turns every write into a local-cache hit; reads sum across the
//! array, which is rare relative to writes.
//!
//! Drop-in API mirror of `AtomicU64`'s `fetch_add` + `load` so it
//! plugs into the existing `RuntimeMetrics` fields without callers
//! needing to change.

use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

/// One slot, padded to 64 bytes (ARM64 + most x86_64 cache line size)
/// so two adjacent slots don't share a cache line.
#[repr(align(64))]
struct Padded(AtomicU64);

pub struct ShardedCounter {
    shards: Box<[Padded]>,
}

impl Default for ShardedCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardedCounter {
    pub fn new() -> Self {
        let n = num_shards();
        let shards: Vec<Padded> = (0..n).map(|_| Padded(AtomicU64::new(0))).collect();
        Self {
            shards: shards.into_boxed_slice(),
        }
    }

    /// Increment by `delta`. Routes to this thread's pinned shard so
    /// concurrent writers from different threads touch different
    /// cache lines. Returns the previous value in that *single shard*
    /// (not the total — preserves AtomicU64::fetch_add signature for
    /// drop-in compatibility; callers that need the total should call
    /// `load()` instead).
    #[inline(always)]
    pub fn fetch_add(&self, delta: u64, order: Ordering) -> u64 {
        let idx = shard_idx(self.shards.len());
        self.shards[idx].0.fetch_add(delta, order)
    }

    /// Total across every shard. Linear in shard count (~num_cpus),
    /// negligible relative to read frequency (metrics dashboards).
    #[inline]
    pub fn load(&self, order: Ordering) -> u64 {
        let mut total: u64 = 0;
        for s in &*self.shards {
            total = total.wrapping_add(s.0.load(order));
        }
        total
    }
}

/// Number of shards — one per CPU when detectable, else 8 (safe
/// default that scales to small machines without wasting memory on
/// huge ones). Capped at 64 so the read-sum stays cheap even on
/// hyperscale boxes.
fn num_shards() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .clamp(1, 64)
}

/// Each thread is pinned to one shard on first access, distributed
/// round-robin across the global pool. After the first call the
/// lookup is a single TLS read with no atomics.
#[inline]
fn shard_idx(n: usize) -> usize {
    thread_local! {
        static MY_SHARD: Cell<Option<usize>> = const { Cell::new(None) };
    }
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    MY_SHARD.with(|c| {
        if let Some(v) = c.get() {
            return v;
        }
        let v = NEXT.fetch_add(1, Ordering::Relaxed) % n.max(1);
        c.set(Some(v));
        v
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn increments_sum_correctly_across_threads() {
        let c = Arc::new(ShardedCounter::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = c.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..10_000 {
                    c.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.load(Ordering::Relaxed), 80_000);
    }

    #[test]
    fn zero_when_untouched() {
        let c = ShardedCounter::new();
        assert_eq!(c.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn default_works() {
        let c = ShardedCounter::default();
        c.fetch_add(42, Ordering::Relaxed);
        assert_eq!(c.load(Ordering::Relaxed), 42);
    }
}
