//! Types shared between the userspace loader and the in-kernel BPF
//! program. Kept `no_std` so the BPF crate (target `bpfel-unknown-none`)
//! can depend on it without pulling libstd.

#![cfg_attr(not(feature = "std"), no_std)]

/// BPF map names, agreed on between userspace and kernel side.
pub mod maps {
    /// `HashMap<u32, u8>` — keys are IPv4 source addresses in network
    /// byte order, value is a placeholder (1). Packets matching this
    /// set get XDP_DROP'd at line rate.
    pub const DENY_V4: &str = "AEGIS_DENY_V4";
    /// `HashMap<[u8; 16], u8>` — keys are IPv6 source addresses.
    pub const DENY_V6: &str = "AEGIS_DENY_V6";

    /// `HashMap<u32, u8>` — allow-list for IPv4. Hits bypass the
    /// deny + rate-limit checks. When `RATE_CFG[allow_only]` is set,
    /// non-listed addresses are XDP_DROP'd ("whitelist mode").
    pub const ALLOW_V4: &str = "AEGIS_ALLOW_V4";
    /// `HashMap<[u8; 16], u8>` — allow-list for IPv6.
    pub const ALLOW_V6: &str = "AEGIS_ALLOW_V6";

    /// `HashMap<u32, RateBucket>` — per-IPv4 token-bucket-ish state for
    /// the kernel rate limiter. Userspace never writes to this; it's
    /// owned by the BPF program.
    pub const RATE_V4: &str = "AEGIS_RATE_V4";

    /// `HashMap<u32, RateBucket>` — separate state for TCP-SYN counts
    /// so a real SYN flood can't burn the general rate budget that
    /// also serves ICMP / UDP / established TCP traffic.
    pub const SYN_V4: &str = "AEGIS_SYN_V4";

    /// `Array<u64>` of action counters; see counter_idx.
    pub const COUNTERS: &str = "AEGIS_COUNTERS";

    /// `Array<u64>` config registers, written by userspace; see rate_cfg_idx.
    pub const RATE_CFG: &str = "AEGIS_RATE_CFG";

    /// `HashMap<Ja4tKey, Ja4tSynFingerprint>` — captured JA4T inputs
    /// (window, MSS, wscale, options-order) for each new IPv4 SYN.
    /// Keyed on (src_ip_be, src_port_be) — matches what userspace
    /// has after `accept()` returns the peer socket.
    pub const JA4T_V4: &str = "AEGIS_JA4T_V4";
}

/// Indices into the `COUNTERS` array.
pub mod counter_idx {
    pub const PASS: u32 = 0;
    pub const DROP_DENY: u32 = 1;
    pub const DROP_RATE: u32 = 2;
    pub const DROP_ALLOWONLY: u32 = 3;
    pub const DROP_SYN: u32 = 4;
    /// Phase 3X — XDP inline WAF dropped a packet whose HTTP request
    /// line started with a known scanner path prefix (e.g. /wp-admin/,
    /// /.env, /etc/passwd-style traversal).
    pub const DROP_WAF: u32 = 5;
    /// Phase A.1 — allow-list hit. Distinct from PASS so operators can
    /// measure the share of traffic taking the userspace-bound
    /// fast-path (trusted IPs that skip the rate-limit + WAF checks).
    /// Sharded across CPUs via the PerCpuArray backing the map, so
    /// the increment is uncontended at line rate.
    pub const FAST_PASS: u32 = 6;
    pub const LEN: u32 = 7;
}

/// Indices into the `RATE_CFG` array.
pub mod rate_cfg_idx {
    pub const WINDOW_NS: u32 = 0;
    pub const BURST: u32 = 1;
    pub const ALLOW_ONLY: u32 = 2;
    /// Per-IP TCP SYN burst within WINDOW_NS. 0 = SYN guard disabled.
    pub const SYN_BURST: u32 = 3;
    pub const LEN: u32 = 4;
}

/// Per-IP rate-limit state kept inside the kernel map. `count` resets
/// to 1 whenever `bpf_ktime_get_ns() - window_start_ns >= window_ns`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RateBucket {
    pub count: u32,
    pub _pad: u32,
    pub window_start_ns: u64,
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for RateBucket {}

/// Composite key for the JA4T capture map: source-IPv4 + source-port,
/// both stored in network byte order (matches what userspace gets from
/// the `SocketAddr` after accept and what XDP sees on the wire — no
/// conversion needed on either side).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Ja4tKey {
    /// IPv4 source, big-endian.
    pub src_ip_be: u32,
    /// TCP source port, big-endian.
    pub src_port_be: u16,
    pub _pad: u16,
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for Ja4tKey {}

/// Maximum TCP options recorded per SYN. The TCP header allows up to
/// 40 bytes of options; capping at 16 distinct option kinds in arrival
/// order covers every real-world stack (Linux: 4-7 options, Windows:
/// 3-6, macOS: 3-6) while keeping the BPF verifier loop bound small.
pub const JA4T_MAX_OPTIONS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Ja4tSynFingerprint {
    /// Advertised TCP window from the SYN (host byte order — userspace
    /// reads it directly into the JA4T `window` field).
    pub window: u16,
    /// MSS option value, 0 if MSS option wasn't present.
    pub mss: u16,
    /// Window scale shift count, 0xff if WSCALE wasn't present.
    pub wscale: u8,
    /// Number of valid entries in `options`.
    pub options_count: u8,
    pub _pad: u16,
    /// TCP option kinds in the order they appeared in the SYN.
    /// Unused trailing slots are zero. NOP (1) entries are kept
    /// because their position is part of the fingerprint.
    pub options: [u8; JA4T_MAX_OPTIONS],
    /// `bpf_ktime_get_ns()` at capture — userspace uses it to age
    /// entries out of the map (the BPF program never evicts itself).
    pub captured_at_ns: u64,
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for Ja4tSynFingerprint {}
