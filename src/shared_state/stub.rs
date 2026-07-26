//! Stub implementation for non-Linux platforms. shm_open + mmap
//! semantics are POSIX-flavoured but the deployment target is
//! Linux; on macOS / Windows we provide a single-process-only
//! arena (effectively just a Box-backed buffer) so the rest of
//! the codebase compiles and unit tests can run.
//!
//! In particular: this stub does NOT share state across processes.
//! If you try to spin up REUSEPORT workers on macOS expecting
//! Phase D's shared scorer state, you'll get four independent
//! per-process arenas — same as before Phase D. Production runs
//! on Linux where the real impl kicks in.

use std::sync::atomic::Ordering;

use super::BumpAllocator;

#[derive(Debug)]
pub enum ArenaError {
    Unsupported,
    OutOfSpace { requested: u64, free: u64 },
}

impl std::fmt::Display for ArenaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "shared_state arena: stub (Linux-only)"),
            Self::OutOfSpace { requested, free } => write!(
                f,
                "shared_state arena: out of space — requested {requested}, free {free}"
            ),
        }
    }
}

impl std::error::Error for ArenaError {}

pub struct Arena {
    inner: std::sync::Arc<ArenaInner>,
}

struct ArenaInner {
    buffer: Box<[u8]>,
    size: u64,
    name: String,
}

impl Arena {
    pub fn open_or_create(name: &str, size: u64) -> Result<Self, ArenaError> {
        // Non-Linux: just back the arena with a heap-allocated
        // buffer. Single-process-only (no cross-worker sharing).
        let mut buffer = vec![0u8; size as usize].into_boxed_slice();
        // Initialise the header in-place.
        let ptr = buffer.as_mut_ptr() as *mut BumpAllocator;
        // SAFETY: header lives at offset 0, BumpAllocator is repr(C).
        unsafe { (&*ptr).init(size) };
        Ok(Self {
            inner: std::sync::Arc::new(ArenaInner {
                buffer,
                size,
                name: name.to_string(),
            }),
        })
    }

    pub fn header(&self) -> &BumpAllocator {
        // SAFETY: header lives at offset 0 of the backing buffer.
        unsafe { &*(self.inner.buffer.as_ptr() as *const BumpAllocator) }
    }

    /// # Safety
    /// See `arena_linux::Arena::slice_at` — same contract.
    pub unsafe fn slice_at<T>(&self, offset: u64, _len: usize) -> *mut T {
        unsafe { self.inner.buffer.as_ptr().add(offset as usize) as *mut T }
    }

    pub fn alloc_slice<T: Sized>(&self, len: usize) -> Result<(u64, *mut T), ArenaError> {
        let size = (std::mem::size_of::<T>() * len) as u64;
        let align = std::mem::align_of::<T>() as u64;
        let offset = self
            .header()
            .alloc(size, align)
            .ok_or_else(|| ArenaError::OutOfSpace {
                requested: size,
                free: self.header().free(),
            })?;
        let ptr = unsafe { self.slice_at::<T>(offset, len) };
        Ok((offset, ptr))
    }

    /// V91 — named alloc. On non-Linux single-process stub the
    /// distinction is meaningless (no cross-process attach), but
    /// we still honour the named_offsets registry for API parity
    /// so library code compiles unchanged.
    pub fn alloc_named_slice<T: Sized>(
        &self,
        name_id: usize,
        len: usize,
    ) -> Result<(u64, *mut T), ArenaError> {
        let size = (std::mem::size_of::<T>() * len) as u64;
        let align = std::mem::align_of::<T>() as u64;
        let offset = self
            .header()
            .alloc_named(name_id, size, align)
            .ok_or_else(|| ArenaError::OutOfSpace {
                requested: size,
                free: self.header().free(),
            })?;
        let ptr = unsafe { self.slice_at::<T>(offset, len) };
        Ok((offset, ptr))
    }

    pub fn size(&self) -> u64 {
        self.inner.size
    }

    pub fn used(&self) -> u64 {
        self.header().used()
    }

    pub fn created_by_us(&self) -> bool {
        // On non-Linux there's no concept of cross-process sharing,
        // so every open is "creator".
        true
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn unlink(_name: &str) -> Result<(), ArenaError> {
        // No persistent state on stub — nothing to unlink.
        Ok(())
    }
}

impl Clone for Arena {
    fn clone(&self) -> Self {
        Self {
            inner: std::sync::Arc::clone(&self.inner),
        }
    }
}

// Silence unused-import warnings in the cfg-gated module.
#[allow(dead_code)]
fn _touch_ordering() {
    let _ = Ordering::Relaxed;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_alloc_works() {
        let a = Arena::open_or_create("/test", 4096).expect("stub open");
        assert!(a.created_by_us());
        let (_, ptr) = a.alloc_slice::<u64>(10).expect("alloc 10 u64s");
        // SAFETY: just-allocated, len matches request
        let s = unsafe { std::slice::from_raw_parts_mut(ptr, 10) };
        s[0] = 42;
        assert_eq!(s[0], 42);
    }
}
