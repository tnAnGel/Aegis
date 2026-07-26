//! Linux-only cross-process shared memory arena via POSIX
//! `shm_open(3)` + `mmap(2)`. Workers open the same named segment
//! at startup; first one to call `open_or_create` initialises the
//! header, the rest validate the size matches and re-attach.
//!
//! The arena is named (typically `/aegis-state`); operators can run
//! multiple unrelated aegis clusters on the same host with distinct
//! names, and the kernel cleans up the segment on host reboot
//! (POSIX shm lives in `/dev/shm` on Linux, lost on power cycle).

#[cfg(test)]
use std::sync::atomic::Ordering;
use std::{ffi::CString, io};

use super::BumpAllocator;

/// Convert an `io::Error` into our `ArenaError` while preserving
/// the underlying errno. Linux-only — the stub impl uses different
/// error variants.
fn io_err(ctx: &'static str, e: io::Error) -> ArenaError {
    ArenaError::Io {
        ctx,
        errno: e.raw_os_error().unwrap_or(0),
        msg: e.to_string(),
    }
}

/// Errors returned by Arena operations. Carries the underlying
/// errno when the syscall layer surfaced one — operators can grep
/// for ENOSPC / EACCES / EINVAL to triage.
#[derive(Debug)]
pub enum ArenaError {
    /// Raw syscall error (shm_open, mmap, ftruncate, etc.).
    Io {
        ctx: &'static str,
        errno: i32,
        msg: String,
    },
    /// Two workers tried to open the same arena with different
    /// sizes. The first wins; subsequent attempts must match.
    SizeMismatch { requested: u64, existing: u64 },
    /// The name passed to shm_open was empty or contained an
    /// embedded NUL — shm_open would reject it anyway.
    InvalidName,
    /// Bump allocator returned None when sizing a typed view.
    OutOfSpace { requested: u64, free: u64 },
}

impl std::fmt::Display for ArenaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { ctx, errno, msg } => {
                write!(f, "shared_state arena: {ctx} failed (errno {errno}): {msg}")
            }
            Self::SizeMismatch {
                requested,
                existing,
            } => write!(
                f,
                "shared_state arena: size mismatch — requested {requested}, existing {existing}"
            ),
            Self::InvalidName => write!(f, "shared_state arena: invalid name"),
            Self::OutOfSpace { requested, free } => write!(
                f,
                "shared_state arena: out of space — requested {requested}, free {free}"
            ),
        }
    }
}

impl std::error::Error for ArenaError {}

/// Handle to a mmap'd shared-state region. Cloneable references
/// the same underlying memory (refcount via Arc).
pub struct Arena {
    inner: std::sync::Arc<ArenaInner>,
}

struct ArenaInner {
    /// Pointer to the start of the mapped region. Lives until
    /// `Drop` calls `munmap`.
    ptr: *mut u8,
    /// Total mapped size in bytes (header + payload).
    size: u64,
    /// shm_open'd file descriptor — kept open so /dev/shm/<name>
    /// stays available for sibling workers. Closed on Drop.
    fd: i32,
    /// Whether THIS process created the segment (vs joined an
    /// existing one). The creator owns the responsibility of
    /// shm_unlink on shutdown (operator-controlled).
    created: bool,
    /// Cached name for diagnostics / shm_unlink.
    name: String,
}

// SAFETY: the underlying mapping is process-shared and the BumpAllocator
// header uses atomics. All access through this Arena goes via &self,
// no Rust aliasing rules violated.
unsafe impl Send for ArenaInner {}
unsafe impl Sync for ArenaInner {}

impl Drop for ArenaInner {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size as usize);
            libc::close(self.fd);
        }
        // We intentionally do NOT shm_unlink on Drop — the segment
        // should survive an individual worker exit (siblings still
        // hold their own mappings). Operators can run
        // `aegis shared-state unlink <name>` for explicit cleanup
        // (planned for V90).
    }
}

impl Arena {
    /// Open the named segment if it exists, otherwise create it.
    /// `size` includes the BumpAllocator header. Suggested minimum:
    /// 4 MiB (covers ~100k IP entries + bucket arrays for the V87
    /// ThreatScorer migration).
    ///
    /// `name` follows POSIX shm conventions — must start with `/`.
    /// Default for the cluster: `/aegis-state`.
    pub fn open_or_create(name: &str, size: u64) -> Result<Self, ArenaError> {
        if name.is_empty() || name.as_bytes().contains(&0) {
            return Err(ArenaError::InvalidName);
        }
        let cname = CString::new(name).map_err(|_| ArenaError::InvalidName)?;
        // Round up to page size to avoid mmap partial-page edge
        // cases. Linux usually 4 KiB; query at runtime via sysconf.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let aligned_size = (size + page_size - 1) & !(page_size - 1);

        // O_RDWR | O_CREAT — created if missing. Mode 0600 so only
        // root (and the aegis user via fs-group) can read/write.
        // Use O_EXCL first to detect creation, fall back to plain
        // open if the segment already exists.
        let (fd, created) = unsafe {
            let fd = libc::shm_open(
                cname.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            );
            if fd >= 0 {
                (fd, true)
            } else {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EEXIST) {
                    let fd2 = libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0o600);
                    if fd2 < 0 {
                        return Err(io_err("shm_open existing", io::Error::last_os_error()));
                    }
                    (fd2, false)
                } else {
                    return Err(io_err("shm_open create", e));
                }
            }
        };

        // Size the segment. ftruncate is a no-op if already sized.
        // If sizes mismatch we still ftruncate to the requested
        // size — but it's typically a config-mismatch bug; surface
        // via a warning at the caller layer.
        let existing_size = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut st) < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(io_err("fstat", e));
            }
            st.st_size as u64
        };
        if created || existing_size == 0 {
            if unsafe { libc::ftruncate(fd, aligned_size as libc::off_t) } < 0 {
                let e = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(io_err("ftruncate", e));
            }
        } else if existing_size != aligned_size {
            // Joining a sibling that allocated a different size —
            // surface as SizeMismatch but keep the existing layout
            // (don't ftruncate-down which would corrupt data).
            unsafe { libc::close(fd) };
            return Err(ArenaError::SizeMismatch {
                requested: aligned_size,
                existing: existing_size,
            });
        }

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(io_err("mmap", e));
        }

        let arena = Arena {
            inner: std::sync::Arc::new(ArenaInner {
                ptr: ptr as *mut u8,
                size: aligned_size,
                fd,
                created,
                name: name.to_string(),
            }),
        };

        // Initialise the bump allocator header. Creator runs `init`;
        // joiners trust the existing one. The init is idempotent
        // for our case (zeroed memory → head=0, then init sets it),
        // but doing it twice would reset the head — so we only
        // init on creation.
        if created {
            // SAFETY: arena.ptr is valid, aligned, big enough for
            // BumpAllocator (verified by size > sizeof header).
            assert!(
                aligned_size >= std::mem::size_of::<BumpAllocator>() as u64,
                "arena size must accommodate the header"
            );
            arena.header().init(aligned_size);
        }
        Ok(arena)
    }

    /// Reference to the bump allocator at offset 0.
    pub fn header(&self) -> &BumpAllocator {
        // SAFETY: header lives at offset 0, init guaranteed size,
        // BumpAllocator uses atomics so concurrent access is safe.
        unsafe { &*(self.inner.ptr as *const BumpAllocator) }
    }

    /// Borrow a typed slice at the given offset. Caller is
    /// responsible for ensuring `T` is `Pod` + `Send + Sync` and
    /// that the offset / length were obtained from a previous
    /// `alloc` call.
    ///
    /// # Safety
    /// The caller must guarantee:
    ///   * `offset + size_of::<T>() * len <= arena_size`
    ///   * `T` is repr(C) with no padding holes (use `bytemuck`
    ///     or hand-validate)
    ///   * No other code mutates the same region without going
    ///     through atomic types (the whole point of this module)
    pub unsafe fn slice_at<T>(&self, offset: u64, _len: usize) -> *mut T {
        // SAFETY: byte offset add — caller guarantees in range.
        unsafe { self.inner.ptr.add(offset as usize) as *mut T }
    }

    /// Allocate a typed slice via the bump allocator and return
    /// its (offset, pointer). Convenience wrapper around
    /// `header().alloc(size, align)` + `slice_at`.
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
        // SAFETY: offset + size <= capacity (alloc guaranteed it),
        // T's alignment is satisfied (alloc rounded up).
        let ptr = unsafe { self.slice_at::<T>(offset, len) };
        Ok((offset, ptr))
    }

    /// V91 — allocate (or attach to) a well-known typed slice.
    /// Cross-process safe: first-creator allocates + CAS's the
    /// offset; joiners read the offset and return a pointer to
    /// the SAME physical bytes. Use for any structure that must
    /// be shared across REUSEPORT workers (SharedScorer's
    /// hashmap, V92+ structures).
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

    /// Total mapped bytes.
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    /// Bytes consumed by allocations so far.
    pub fn used(&self) -> u64 {
        self.header().used()
    }

    /// Whether this process originally created the segment (as
    /// opposed to joining a sibling's).
    pub fn created_by_us(&self) -> bool {
        self.inner.created
    }

    /// Name passed at open time.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Unlink the segment from /dev/shm. After unlink, existing
    /// mappings keep working until all processes close their fds,
    /// but no new workers can attach. Used by operator tooling
    /// (planned: `aegis shared-state unlink <name>`).
    pub fn unlink(name: &str) -> Result<(), ArenaError> {
        let cname = CString::new(name).map_err(|_| ArenaError::InvalidName)?;
        let rc = unsafe { libc::shm_unlink(cname.as_ptr()) };
        if rc < 0 {
            return Err(io_err("shm_unlink", io::Error::last_os_error()));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a unique-per-test arena name so parallel
    /// tests don't collide.
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

    #[test]
    fn arena_open_create_init() {
        let name = unique_name("create");
        let a = Arena::open_or_create(&name, 64 * 1024).expect("open_or_create");
        assert!(a.created_by_us(), "first open must report created=true");
        assert!(a.size() >= 64 * 1024);
        assert_eq!(a.used(), 0);
        assert_eq!(a.name(), name);
        // Cleanup
        let _ = Arena::unlink(&name);
    }

    #[test]
    fn arena_alloc_slice_atomic_u64() {
        use std::sync::atomic::AtomicU64;
        let name = unique_name("alloc");
        let a = Arena::open_or_create(&name, 64 * 1024).expect("open_or_create");

        // Allocate space for 100 AtomicU64s
        let (offset, ptr) = a.alloc_slice::<AtomicU64>(100).expect("alloc_slice");
        assert!(offset >= std::mem::size_of::<BumpAllocator>() as u64);
        // SAFETY: ptr was returned by alloc_slice with len=100.
        let slice = unsafe { std::slice::from_raw_parts(ptr, 100) };
        // First-touch — should be zeroed by mmap.
        for a in slice.iter().take(10) {
            assert_eq!(a.load(Ordering::Relaxed), 0);
        }
        // Bump one of them, read back.
        slice[5].store(42, Ordering::Relaxed);
        assert_eq!(slice[5].load(Ordering::Relaxed), 42);

        let _ = Arena::unlink(&name);
    }

    #[test]
    fn arena_second_open_joins_existing() {
        let name = unique_name("join");
        let a1 = Arena::open_or_create(&name, 32 * 1024).expect("first open");
        assert!(a1.created_by_us());
        // Second open from same process — should report created=false
        let a2 = Arena::open_or_create(&name, 32 * 1024).expect("second open");
        assert!(!a2.created_by_us(), "second open must report created=false");
        assert_eq!(a1.size(), a2.size());
        let _ = Arena::unlink(&name);
    }

    #[test]
    fn arena_size_mismatch_rejected() {
        let name = unique_name("size");
        let _a1 = Arena::open_or_create(&name, 16 * 1024).expect("first open");
        // Second open with different size — should error
        let r = Arena::open_or_create(&name, 64 * 1024);
        assert!(matches!(r, Err(ArenaError::SizeMismatch { .. })));
        let _ = Arena::unlink(&name);
    }

    #[test]
    fn arena_clone_shares_underlying() {
        let name = unique_name("clone");
        let a = Arena::open_or_create(&name, 32 * 1024).expect("open");
        let b = a.clone();
        let (off, _) = a.alloc_slice::<u64>(10).unwrap();
        // b sees the same head pointer because it's the SAME mmap
        assert_eq!(b.used(), a.used());
        assert!(off >= std::mem::size_of::<BumpAllocator>() as u64);
        let _ = Arena::unlink(&name);
    }
}
