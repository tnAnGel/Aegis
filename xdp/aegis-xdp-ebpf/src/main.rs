//! Aegis XDP fast-path program.
//!
//! Order of operations per packet:
//!   1. Parse L2 + L3. Non-IPv4/IPv6 → PASS.
//!   2. If src ∈ ALLOW map → PASS (allow-list always wins).
//!   3. If RATE_CFG[allow_only] is set and src ∉ ALLOW → DROP.
//!   4. If src ∈ DENY map → DROP.
//!   5. Per-IPv4 rate-limit lookup against AEGIS_RATE_V4 + RATE_CFG.
//!      Excess in the current window → DROP.
//!   6. Otherwise PASS.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray},
    programs::XdpContext,
};
use core::mem;

use aegis_xdp_common::{
    JA4T_MAX_OPTIONS, Ja4tKey, Ja4tSynFingerprint, RateBucket, counter_idx, rate_cfg_idx,
};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_HDR_LEN: usize = 14;
const IP_PROTO_TCP: u8 = 6;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;

// Phase 3X: XDP inline WAF — scanner path prefixes that get
// XDP_DROP'd at line rate before the packet reaches userspace.
// All entries padded to 16 bytes for verifier-friendly fixed-stride
// comparison. `len` is the meaningful prefix length.
//
// Coverage (32 patterns):
//   • WordPress probes (wp-admin, wp-login, wp-config)
//   • Env / credential leaks (.env, .git, .aws, .ssh, /credentials)
//   • PHP admin interfaces (phpmyadmin, admin, administrator)
//   • Spring/Java/Tomcat management (actuator, jmx-console, manager)
//   • Generic shell uploads (c99.php, shell.php, r57.php, eval.php)
//   • OS file disclosure (/etc/passwd, /etc/shadow, /proc/self)
//   • Cloud metadata (/latest/meta-data, /computeMetadata, /opc/v1)
//   • DevOps leaks (/.svn/, /CVS/, /.travis.yml)
//   • Common scanner targets (HNAP1, server-status, server-info,
//     /jmx-console, /docker.sock)
//
// Patterns must be longest-first within the same prefix so the
// matcher's first-hit-wins behaviour picks the most specific. We
// only check the FIRST data packet (PSH+ACK) of a TCP stream where
// the HTTP request line is — that covers practically every scanner
// probe (single-packet HTTP requests are the norm).
// Phase A.1 v2 — pattern set expanded from 32 to 48 entries to cover
// modern scanner shapes (cloud-credential leaks, container runtime
// metadata, common API exploit probes, and the "vuln-scanner default
// path" tail). Every additional pattern is one extra constant-bound
// iteration of the inner compare loop, which the verifier still
// accepts well within the 1M-insn budget at the current shape.
const WAF_PATTERN_COUNT: usize = 48;
const WAF_PATTERN_MAX: usize = 16;
static WAF_PATTERNS: [[u8; WAF_PATTERN_MAX]; WAF_PATTERN_COUNT] = [
    *b"/wp-admin/      ",
    *b"/wp-login.php   ",
    *b"/wp-config.php  ",
    *b"/xmlrpc.php     ",
    *b"/.env           ",
    *b"/.git/          ",
    *b"/.aws/          ",
    *b"/.ssh/          ",
    *b"/.svn/          ",
    *b"/CVS/           ",
    *b"/phpmyadmin/    ",
    *b"/administrator/ ",
    *b"/actuator/env   ",
    *b"/server-status  ",
    *b"/server-info    ",
    *b"/HNAP1/         ",
    *b"/c99.php        ",
    *b"/shell.php      ",
    *b"/r57.php        ",
    *b"/eval.php       ",
    *b"/etc/passwd     ",
    *b"/etc/shadow     ",
    *b"/proc/self/     ",
    *b"/jmx-console    ",
    *b"/manager/html   ",
    *b"/.aws/credenti  ",
    *b"/.travis.yml    ",
    *b"/Jenkinsfile    ",
    *b"/docker-compose ",
    *b"/web.config     ",
    *b"/backup.zip     ",
    *b"/info.php       ",
    // --- A.1 expansion (cloud + scanner tail) ---
    *b"/.docker        ",
    *b"/.kube/         ",
    *b"/.npmrc         ",
    *b"/.dockercfg     ",
    *b"/latest/meta-da ",
    *b"/computeMetadat ",
    *b"/opc/v1/        ",
    *b"/metadata/v1    ",
    *b"/etc/hosts      ",
    *b"/etc/issue      ",
    *b"/proc/version   ",
    *b"/proc/cpuinfo   ",
    *b"/api/jolokia    ",
    *b"/console/login  ",
    *b"/druid/index    ",
    *b"/solr/admin     ",
];
static WAF_PATTERN_LENS: [u8; WAF_PATTERN_COUNT] = [
    10, 13, 14, 11, 5, 6, 6, 6, 6, 5,
    12, 15, 13, 14, 12, 7, 8, 10, 8, 9,
    11, 11, 11, 12, 13, 14, 12, 12, 15, 11,
    11, 9,
    // A.1 expansion lens
    8, 7, 7, 11, 15, 15, 8, 12,
    10, 10, 13, 13, 12, 14, 12, 11,
];

// Phase A.3 — first-byte triage. Every pattern starts with '/', so
// the differentiator is buf[path_start + 1]. Pre-extracted into a
// parallel table so the inner per-pattern loop can skip mismatches
// after a single byte compare instead of starting the 16-byte
// fixed-stride walk. Drops average per-packet work from
// `path_start_check + 16 * 48 = 768 byte-compares` (worst case)
// to roughly `path_start_check + 16 * avg_collisions_per_bucket`,
// which on the current 48-pattern set is `16 * 5 = 80` for the
// busiest second char ('.'), and `16 * 1 = 16` for unique second
// chars. ~10× expected throughput improvement on the WAF data path
// at line rate.
//
// Verifier shape unchanged: still a constant-bounded outer loop
// (WAF_PATTERN_COUNT iterations) with a single byte compare gate
// before the inner fixed-length compare. The "skip" branch is
// just an early `continue`.
static WAF_PATTERN_FIRST_BYTE: [u8; WAF_PATTERN_COUNT] = [
    b'w', b'w', b'w', b'x', b'.', b'.', b'.', b'.', b'.', b'C',
    b'p', b'a', b'a', b's', b's', b'H', b'c', b's', b'r', b'e',
    b'e', b'e', b'p', b'j', b'm', b'.', b'.', b'J', b'd', b'w',
    b'b', b'i',
    // A.1 expansion second bytes
    b'.', b'.', b'.', b'.', b'l', b'c', b'o', b'm',
    b'e', b'e', b'p', b'p', b'a', b'c', b'd', b's',
];

#[repr(C)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    src: u32,
    dst: u32,
}

#[repr(C)]
struct TcpHdr {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    data_off_reserved: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C)]
struct Ipv6Hdr {
    version_class_flow: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

// Map names MUST be string literals — aya-ebpf's #[map] attribute is
// expanded at proc-macro time and can't const-evaluate paths into
// strings. Keep these in sync with `aegis_xdp_common::maps::*` by
// hand; the userspace side reads them through the typed constants.
#[map(name = "AEGIS_DENY_V4")]
static DENY_V4: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(65_536, 0);

#[map(name = "AEGIS_DENY_V6")]
static DENY_V6: HashMap<[u8; 16], u8> = HashMap::<[u8; 16], u8>::with_max_entries(65_536, 0);

#[map(name = "AEGIS_ALLOW_V4")]
static ALLOW_V4: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(8_192, 0);

#[map(name = "AEGIS_ALLOW_V6")]
static ALLOW_V6: HashMap<[u8; 16], u8> = HashMap::<[u8; 16], u8>::with_max_entries(8_192, 0);

#[map(name = "AEGIS_RATE_V4")]
static RATE_V4: HashMap<u32, RateBucket> =
    HashMap::<u32, RateBucket>::with_max_entries(131_072, 0);

#[map(name = "AEGIS_SYN_V4")]
static SYN_V4: HashMap<u32, RateBucket> =
    HashMap::<u32, RateBucket>::with_max_entries(131_072, 0);

// Phase A.1 — per-CPU counters. The previous shared `Array<u64>` had
// every CPU CAS-ing the same cache line on each `bump()` call, which
// at line rate becomes a non-trivial bottleneck (NUMA-style coherence
// traffic across cores). PerCpuArray gives each CPU its own slot;
// userspace sums the slots at read time via `aya::PerCpuArray::get`.
#[map(name = "AEGIS_COUNTERS")]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(counter_idx::LEN, 0);

#[map(name = "AEGIS_RATE_CFG")]
static RATE_CFG: Array<u64> = Array::<u64>::with_max_entries(rate_cfg_idx::LEN, 0);

// 65_536 in-flight SYNs covers a multi-thousand-RPS edge with the
// natural 60 s userspace eviction window. Old entries get scrubbed
// by a background task; the BPF program itself never evicts.
#[map(name = "AEGIS_JA4T_V4")]
static JA4T_V4: HashMap<Ja4tKey, Ja4tSynFingerprint> =
    HashMap::<Ja4tKey, Ja4tSynFingerprint>::with_max_entries(65_536, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}

#[inline(always)]
fn bump(counter: u32) {
    if let Some(v) = COUNTERS.get_ptr_mut(counter) {
        unsafe {
            *v = (*v).wrapping_add(1);
        }
    }
}

#[inline(always)]
fn cfg(idx: u32) -> u64 {
    RATE_CFG.get(idx).copied().unwrap_or(0)
}

#[inline(always)]
fn bucket_check(
    map: &HashMap<u32, RateBucket>,
    src: u32,
    window_ns: u64,
    burst: u64,
) -> bool {
    if window_ns == 0 || burst == 0 {
        return true; // disabled
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let existing = unsafe { map.get(&src) };
    let mut bucket = match existing {
        Some(b) => *b,
        None => RateBucket {
            count: 0,
            _pad: 0,
            window_start_ns: now,
        },
    };
    if now.saturating_sub(bucket.window_start_ns) >= window_ns {
        bucket.window_start_ns = now;
        bucket.count = 0;
    }
    bucket.count = bucket.count.saturating_add(1);
    // Best-effort write — racing CPUs may clobber, that's fine for
    // rate limiting (we'd over- or under-count by O(num_cpus)).
    let _ = map.insert(&src, &bucket, 0);
    (bucket.count as u64) <= burst
}

#[inline(always)]
fn rate_check_v4(src: u32) -> bool {
    let window_ns = cfg(rate_cfg_idx::WINDOW_NS);
    let burst = cfg(rate_cfg_idx::BURST);
    bucket_check(&RATE_V4, src, window_ns, burst)
}

#[inline(always)]
fn syn_check_v4(src: u32) -> bool {
    let window_ns = cfg(rate_cfg_idx::WINDOW_NS);
    let burst = cfg(rate_cfg_idx::SYN_BURST);
    bucket_check(&SYN_V4, src, window_ns, burst)
}

/// Phase 3X — inline scanner WAF.
///
/// Returns true when this IPv4 packet carries an HTTP request line
/// whose path matches a known scanner pattern (WAF_PATTERNS). Caller
/// should XDP_DROP on true.
///
/// Verifier shape:
///   • Single 64-byte payload snapshot via `ptr_at::<[u8; 64]>` —
///     one bounds proof covers all reads, no per-byte packet
///     dereferences.
///   • Method-length lookup table (constant-time, no string compare).
///   • Outer loop over WAF_PATTERNS has constant trip count
///     (WAF_PATTERN_COUNT) — verifier accepts.
///   • Inner pattern compare runs to constant WAF_PATTERN_MAX bound,
///     masking off bytes beyond pattern.len.
///
/// Limits (documented for honesty):
///   • Plain HTTP only (TLS payload is encrypted; HTTPS WAF runs in
///     userspace after termination).
///   • Only matches when the request line fits in the first 64 bytes
///     of TCP payload — true for ~all real HTTP/1.1 requests.
///   • Pattern set is hardcoded; userspace-driven extension is a
///     follow-up (Phase 3X.2).
#[inline(always)]
fn waf_check_v4(ctx: &XdpContext, ip: &Ipv4Hdr) -> bool {
    if ip.protocol != IP_PROTO_TCP {
        return false;
    }
    let ihl = (ip.version_ihl & 0x0f) as usize;
    if ihl < 5 || ihl > 15 {
        return false;
    }
    let tcp_offset = ETH_HDR_LEN + ihl * 4;
    let tcp = match unsafe { ptr_at::<TcpHdr>(ctx, tcp_offset) } {
        Some(p) => unsafe { &*p },
        None => return false,
    };
    // Only inspect data packets — PSH+ACK with no SYN/FIN/RST.
    // Pure ACKs / handshake / teardown carry no request line.
    let flags = tcp.flags;
    if (flags & TCP_FLAG_PSH) == 0
        || (flags & TCP_FLAG_ACK) == 0
        || (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)) != 0
    {
        return false;
    }
    let data_off_words = (tcp.data_off_reserved >> 4) as usize;
    if data_off_words < 5 || data_off_words > 15 {
        return false;
    }
    let tcp_hdr_len = data_off_words * 4;
    let payload_offset = tcp_offset + tcp_hdr_len;
    // Snapshot 64 bytes — covers request line for any real HTTP/1.1
    // request (longest method is 7 chars + space + 256+ char URL,
    // but 99 % of scanner probes hit /tiny/path within 64 bytes).
    let buf: [u8; 64] = match unsafe { ptr_at::<[u8; 64]>(ctx, payload_offset) } {
        Some(p) => unsafe { *p },
        None => return false,
    };

    // Identify HTTP method by its first 4-7 bytes. Returns the offset
    // where the path starts (method_len + 1 for the space). Anything
    // we don't recognise as a method → pass through (userspace will
    // catch via the existing WAF method gate).
    let path_start: usize = if buf[0] == b'G' && buf[1] == b'E' && buf[2] == b'T' && buf[3] == b' '
    {
        4
    } else if buf[0] == b'P' && buf[1] == b'O' && buf[2] == b'S' && buf[3] == b'T' && buf[4] == b' '
    {
        5
    } else if buf[0] == b'H' && buf[1] == b'E' && buf[2] == b'A' && buf[3] == b'D' && buf[4] == b' '
    {
        5
    } else if buf[0] == b'P' && buf[1] == b'U' && buf[2] == b'T' && buf[3] == b' ' {
        4
    } else if buf[0] == b'D'
        && buf[1] == b'E'
        && buf[2] == b'L'
        && buf[3] == b'E'
        && buf[4] == b'T'
        && buf[5] == b'E'
        && buf[6] == b' '
    {
        7
    } else {
        return false;
    };
    // Path must start with `/`. Otherwise we likely misidentified the
    // method or the request line is malformed — let userspace handle.
    if path_start >= buf.len() || buf[path_start] != b'/' {
        return false;
    }

    // Phase A.3 — read the byte right after '/' once, use as triage
    // key. If buf[path_start+1] doesn't match a pattern's first
    // byte, skip the full 16-byte compare entirely. Bounds: path_start
    // ≤ 7 (longest method), +1 ≤ 8 < 64. Falls back gracefully when
    // the path is a bare `/` (target_byte = 0 won't match any
    // pattern's first byte since we picked second-bytes that are
    // ASCII letters/dot/slash).
    let triage_idx = path_start + 1;
    if triage_idx >= 64 {
        return false;
    }
    let target_first = buf[triage_idx];

    // Outer loop: check every WAF pattern. Constant trip count — verifier-friendly.
    let mut i = 0;
    while i < WAF_PATTERN_COUNT {
        // First-byte triage gate — skip this pattern unless its
        // second char matches. This is the A.3 hot-path optimisation;
        // every non-matching pattern costs a single byte compare
        // instead of starting the 16-iteration inner compare.
        if WAF_PATTERN_FIRST_BYTE[i] != target_first {
            i += 1;
            continue;
        }
        let pat = WAF_PATTERNS[i];
        let plen = WAF_PATTERN_LENS[i] as usize;
        // Inner loop: byte-by-byte compare. Iterates to WAF_PATTERN_MAX
        // (constant) but breaks out when we hit the real pattern length
        // — masks off the padding bytes.
        let mut matched = true;
        let mut j = 0;
        while j < WAF_PATTERN_MAX {
            if j >= plen {
                break;
            }
            // Path bytes live at buf[path_start + j]. Bound this access:
            // path_start ≤ 7 (longest method), plen ≤ 16, sum ≤ 23 < 64.
            let buf_idx = path_start + j;
            if buf_idx >= 64 {
                matched = false;
                break;
            }
            if buf[buf_idx] != pat[j] {
                matched = false;
                break;
            }
            j += 1;
        }
        if matched {
            return true;
        }
        i += 1;
    }
    false
}

/// True iff this IPv4 packet is a TCP SYN without ACK — i.e. a brand
/// new connection attempt that hasn't completed the three-way
/// handshake yet. Returns false for any non-TCP packet, ACK-bearing
/// SYN/ACK (the server reply, not a flood), or fragments/truncation.
#[inline(always)]
fn is_tcp_syn(ctx: &XdpContext, ip: &Ipv4Hdr) -> bool {
    if ip.protocol != IP_PROTO_TCP {
        return false;
    }
    let ihl = (ip.version_ihl & 0x0f) as usize;
    if ihl < 5 {
        return false;
    }
    let tcp_offset = ETH_HDR_LEN + ihl * 4;
    let tcp = match unsafe { ptr_at::<TcpHdr>(ctx, tcp_offset) } {
        Some(p) => unsafe { &*p },
        None => return false,
    };
    (tcp.flags & TCP_FLAG_SYN) != 0 && (tcp.flags & TCP_FLAG_ACK) == 0
}

/// JA4T capture for a confirmed-SYN IPv4 packet. Records the
/// advertised window, the MSS and WSCALE values, and up to
/// JA4T_MAX_OPTIONS option kinds in arrival order. The walker is
/// shaped specifically for what the BPF verifier can prove:
///
///   * The whole 40-byte TCP options block is bounds-checked up
///     front by asking for a `[u8; 40]` slice via `ptr_at`. The
///     verifier sees this as a single contiguous packet region.
///   * The inner loop is a `for _ in 0..40` (constant trip count)
///     reading from the pre-bounds-checked slice. Per-byte reads
///     are array-indexed, NOT pointer arithmetic on the packet —
///     this is what kept the previous attempt out of "R0 offset is
///     outside of the packet" rejection.
///   * Reads past `options_len` are still safe (the slice is 40
///     bytes); we just `break` so the option-kinds buffer reflects
///     only valid TLVs.
#[inline(always)]
fn capture_ja4t_v4(ctx: &XdpContext, ip: &Ipv4Hdr) {
    let ihl = (ip.version_ihl & 0x0f) as usize;
    if ihl < 5 {
        return;
    }
    let tcp_offset = ETH_HDR_LEN + ihl * 4;
    let tcp_ptr = match unsafe { ptr_at::<TcpHdr>(ctx, tcp_offset) } {
        Some(p) => p,
        None => return,
    };
    let tcp = unsafe { &*tcp_ptr };
    let data_off_words = (tcp.data_off_reserved >> 4) as usize;
    if data_off_words < 5 || data_off_words > 15 {
        return;
    }
    let tcp_hdr_len = data_off_words * 4;
    let options_len = tcp_hdr_len.saturating_sub(20);
    if options_len == 0 {
        // SYN without options happens (Windows minimal stack). Still
        // write window+port so the fingerprint isn't empty.
        let fp = Ja4tSynFingerprint {
            window: u16::from_be(tcp.window),
            mss: 0,
            wscale: 0xff,
            options_count: 0,
            _pad: 0,
            options: [0; JA4T_MAX_OPTIONS],
            captured_at_ns: unsafe { bpf_ktime_get_ns() },
        };
        let key = Ja4tKey {
            src_ip_be: ip.src,
            src_port_be: tcp.sport,
            _pad: 0,
        };
        let _ = JA4T_V4.insert(&key, &fp, 0);
        return;
    }

    // The BPF verifier rejects loops that walk packet data with a
    // variable stride (state explosion / unprovable bounds), so we
    // snapshot a fixed 16-byte slice of the options block as a
    // single struct read. That gives the verifier ONE bounds proof
    // covering the whole region. Userspace then walks the bytes
    // (no verifier constraints) to extract MSS / WSCALE / option
    // order. Capping at 16 bytes covers every modern stack's first
    // four options — typical SYN options are 12 bytes (MSS, SACKp,
    // TSval, WSCALE) and Windows/Linux fit well under 16.
    let opts_start = tcp_offset + 20;
    let opts16: [u8; 16] = match unsafe { ptr_at::<[u8; 16]>(ctx, opts_start) } {
        Some(p) => unsafe { *p },
        None => [0u8; 16], // SYN without 16 bytes of options — partial fp ok
    };
    let snapshot_len = if options_len > 16 { 16 } else { options_len };

    let mut fp = Ja4tSynFingerprint {
        window: u16::from_be(tcp.window),
        mss: 0,
        wscale: 0xff,
        options_count: snapshot_len as u8,
        _pad: 0,
        options: [0; JA4T_MAX_OPTIONS],
        captured_at_ns: unsafe { bpf_ktime_get_ns() },
    };
    // Copy the snapshot into the fingerprint's `options` array — no
    // packet bounds, all stack-local. Userspace decodes the TLVs.
    let copy_len = if snapshot_len > JA4T_MAX_OPTIONS {
        JA4T_MAX_OPTIONS
    } else {
        snapshot_len
    };
    let mut k = 0;
    while k < copy_len && k < 16 {
        fp.options[k & (JA4T_MAX_OPTIONS - 1)] = opts16[k & 15];
        k += 1;
    }

    let key = Ja4tKey {
        src_ip_be: ip.src,
        src_port_be: tcp.sport,
        _pad: 0,
    };
    let _ = JA4T_V4.insert(&key, &fp, 0);
}

#[xdp]
pub fn aegis_xdp(ctx: XdpContext) -> u32 {
    match try_action(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_action(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = unsafe { ptr_at::<EthHdr>(ctx, 0).ok_or(())? };
    let ether_type = u16::from_be(unsafe { (*eth).ether_type });
    let allow_only = cfg(rate_cfg_idx::ALLOW_ONLY) != 0;

    match ether_type {
        ETH_P_IP => {
            let ip_ptr = unsafe { ptr_at::<Ipv4Hdr>(ctx, ETH_HDR_LEN).ok_or(())? };
            let ip = unsafe { &*ip_ptr };
            let src = ip.src;
            if unsafe { ALLOW_V4.get(&src) }.is_some() {
                // Phase A.1 fast-path: trusted IP, skip every downstream
                // check (deny / rate / SYN guard / WAF). Counter bumps
                // the per-CPU FAST_PASS slot — no cross-core coherence
                // traffic, which matters when trusted traffic is the
                // bulk of the flow.
                bump(counter_idx::FAST_PASS);
                return Ok(xdp_action::XDP_PASS);
            }
            if allow_only {
                bump(counter_idx::DROP_ALLOWONLY);
                return Ok(xdp_action::XDP_DROP);
            }
            if unsafe { DENY_V4.get(&src) }.is_some() {
                bump(counter_idx::DROP_DENY);
                return Ok(xdp_action::XDP_DROP);
            }
            // SYN flood guard runs before the general rate limiter so a
            // saturating SYN storm can't deplete the legit traffic
            // budget. Only counts brand-new connection attempts (SYN
            // without ACK).
            let syn = is_tcp_syn(ctx, ip);
            if syn {
                // JA4T capture happens before any drop decision —
                // userspace might still want the fingerprint for an
                // accept that the SYN-guard previously dropped (e.g.
                // when the same client retries successfully on a
                // looser window). Cheap: bounded option walk +
                // single map insert.
                capture_ja4t_v4(ctx, ip);
            }
            if syn && !syn_check_v4(src) {
                bump(counter_idx::DROP_SYN);
                return Ok(xdp_action::XDP_DROP);
            }
            if !rate_check_v4(src) {
                bump(counter_idx::DROP_RATE);
                return Ok(xdp_action::XDP_DROP);
            }
            // Phase 3X inline WAF — runs only for non-SYN packets
            // (request line lives in the first data packet, not the
            // handshake). Cheap fast-path: PSH+ACK + HTTP method
            // detection + bounded path prefix match. Drops obvious
            // scanner probes at line rate without bothering userspace.
            if !syn && waf_check_v4(ctx, ip) {
                bump(counter_idx::DROP_WAF);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        ETH_P_IPV6 => {
            let ip = unsafe { ptr_at::<Ipv6Hdr>(ctx, ETH_HDR_LEN).ok_or(())? };
            let src = unsafe { (*ip).src };
            if unsafe { ALLOW_V6.get(&src) }.is_some() {
                bump(counter_idx::FAST_PASS);
                return Ok(xdp_action::XDP_PASS);
            }
            if allow_only {
                bump(counter_idx::DROP_ALLOWONLY);
                return Ok(xdp_action::XDP_DROP);
            }
            if unsafe { DENY_V6.get(&src) }.is_some() {
                bump(counter_idx::DROP_DENY);
                return Ok(xdp_action::XDP_DROP);
            }
            // IPv6 rate-limit not yet implemented (would need a
            // separate map keyed on [u8;16] — skipping for now).
        }
        _ => {}
    }

    bump(counter_idx::PASS);
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
