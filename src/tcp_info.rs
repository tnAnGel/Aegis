//! Best-effort JA4T capture via Linux `TCP_INFO` getsockopt.
//!
//! True JA4T requires reading the SYN packet's TCP options (MSS,
//! window scale, options order). Linux doesn't expose those once the
//! connection is established — they're consumed by the kernel's
//! handshake state machine. What `TCP_INFO` *does* give us is the
//! negotiated MSS (`tcpi_snd_mss` / `tcpi_rcv_mss`) and a few other
//! fields, which is enough to produce a coarse-grained JA4T variant.
//!
//! For full-fidelity JA4T capture, an eBPF program at the XDP / TC
//! layer would intercept the SYN packet and write the options to a
//! BPF map keyed by 4-tuple. The XDP loader (`src/xdp.rs`) is already
//! plumbed; wiring the SYN capture is left as a follow-up — TCP_INFO
//! covers the most common operator needs (MSS-based botnet
//! distinction) without the additional kernel-program complexity.

#[cfg(target_os = "linux")]
use crate::ja4::{Ja4tInput, compute_ja4t};

/// Best-effort `JA4T` from `TCP_INFO` (Linux only). On every other
/// target it's a permanent None — the XDP-capture path is the
/// preferred source there too, this is just the local fallback.
#[cfg(not(target_os = "linux"))]
pub fn capture(_socket: &tokio::net::TcpStream) -> Option<String> {
    None
}

/// Try to fetch a full-fidelity JA4T from the XDP SYN capture, fall
/// back to TCP_INFO-derived best-effort. Operators who run the XDP
/// fast-path get window + options-order + MSS + WSCALE; operators
/// without XDP get an MSS+WSCALE-only fingerprint that still
/// distinguishes major OS families.
pub fn capture_with_xdp(
    socket: &tokio::net::TcpStream,
    peer_port: u16,
    xdp: &dyn crate::xdp::XdpHandle,
    peer_ip: std::net::IpAddr,
) -> Option<String> {
    if let std::net::IpAddr::V4(v4) = peer_ip
        && let Some(cap) = xdp.read_ja4t_v4(v4, peer_port)
    {
        // The eBPF program stashes the raw first-16-bytes of the
        // SYN options block in `cap.options` (BPF verifier rejects
        // packet-data loops with variable strides — we keep parsing
        // in userspace). Walk the TLV stream here to extract MSS,
        // WSCALE, and the option-kind sequence.
        let (option_kinds, mss, wscale) = parse_syn_options(&cap.options);
        let kinds_csv = option_kinds
            .iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
            .join(",");
        // MSS / WSCALE from the SYN parse beat any value the BPF
        // program might have already filled (it never does — the
        // simplified program only writes the snapshot). Fall back
        // to the BPF-recorded value if the userspace parse failed.
        let mss = if mss == 0 { cap.mss } else { mss };
        let wscale = wscale.unwrap_or(if cap.wscale == 0xff { 0 } else { cap.wscale });
        return Some(format!(
            "{}_{}_{}_{}",
            cap.window,
            if kinds_csv.is_empty() {
                "0".to_string()
            } else {
                kinds_csv
            },
            mss,
            wscale
        ));
    }
    // No XDP capture — fall back to the TCP_INFO best-effort path.
    capture(socket)
}

/// Walk the first up-to-16 bytes of a TCP SYN options block. Returns
/// `(kinds in arrival order, MSS or 0, WSCALE or None)`. Lives in
/// userspace so the BPF verifier never sees the loop.
fn parse_syn_options(snap: &[u8]) -> (Vec<u8>, u16, Option<u8>) {
    let mut kinds = Vec::new();
    let mut mss: u16 = 0;
    let mut wscale: Option<u8> = None;
    let mut i = 0;
    while i < snap.len() {
        let kind = snap[i];
        kinds.push(kind);
        match kind {
            0 => break, // EOL
            1 => {
                i += 1; // NOP
                continue;
            }
            _ => {
                if i + 1 >= snap.len() {
                    break;
                }
                let len = snap[i + 1] as usize;
                if len < 2 || i + len > snap.len() {
                    break;
                }
                if kind == 2 && len == 4 {
                    mss = ((snap[i + 2] as u16) << 8) | (snap[i + 3] as u16);
                } else if kind == 3 && len == 3 {
                    wscale = Some(snap[i + 2]);
                }
                i += len;
            }
        }
    }
    (kinds, mss, wscale)
}

/// Return the kernel-measured smoothed RTT in microseconds for this
/// TCP socket — populates the `client_to_server` half of JA4L. On
/// non-Linux returns 0 (caller will report the legacy single-value
/// form).
#[cfg(target_os = "linux")]
pub fn smoothed_rtt_us(socket: &tokio::net::TcpStream) -> u64 {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    #[repr(C)]
    struct TcpInfo {
        _pad_pre: [u8; 56],
        // tcpi_rtt is the smoothed RTT in microseconds, stored at
        // offset 56 in the standard Linux TCP_INFO struct.
        tcpi_rtt: u32,
        _pad_post: [u8; 200],
    }
    let mut info: TcpInfo = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<TcpInfo>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut TcpInfo).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return 0;
    }
    info.tcpi_rtt as u64
}

#[cfg(not(target_os = "linux"))]
pub fn smoothed_rtt_us(_socket: &tokio::net::TcpStream) -> u64 {
    0
}

/// Read TCP_INFO on `socket` and produce a JA4T-shaped string. Always
/// returns Some on Linux, None on every other OS. The "options" field
/// is left as `0` — operators who turn on the eBPF SYN capture will
/// see a populated value; everyone else gets a window/mss/wscale
/// hash that still distinguishes major OS families.
#[cfg(target_os = "linux")]
pub fn capture(socket: &tokio::net::TcpStream) -> Option<String> {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    // TCP_INFO definition (selected fields) — we mirror the kernel
    // layout but only read the fields we use. The struct grows over
    // time, so we ask for `size_of` bytes and accept a short read.
    #[repr(C)]
    struct TcpInfo {
        tcpi_state: u8,
        tcpi_ca_state: u8,
        tcpi_retransmits: u8,
        tcpi_probes: u8,
        tcpi_backoff: u8,
        tcpi_options: u8,
        tcpi_snd_rcv_wscale: u8,
        tcpi_delivery_rate_app_limited: u8,
        tcpi_rto: u32,
        tcpi_ato: u32,
        tcpi_snd_mss: u32,
        tcpi_rcv_mss: u32,
        _pad: [u8; 192],
    }
    // SAFETY: TcpInfo is repr(C) and all-numeric; zeroed bytes are a
    // valid TcpInfo and getsockopt overwrites the prefix it knows.
    let mut info: TcpInfo = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<TcpInfo>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut TcpInfo).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    let snd_wscale = info.tcpi_snd_rcv_wscale & 0x0f;
    let mss = (info.tcpi_snd_mss as u16).max(info.tcpi_rcv_mss as u16);
    // Default IPv4 window from MSS is 65535; we can't read the raw
    // SYN window from TCP_INFO, so report 0 (sentinel "not captured").
    let input = Ja4tInput {
        window: 0,
        options_order: String::new(),
        mss,
        wscale: snd_wscale,
    };
    Some(compute_ja4t(&input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_syn_options() {
        // Realistic Linux SYN: MSS(1460) + SACKp + TS + NOP + WSCALE(7)
        let snap = [
            2, 4, 0x05, 0xb4, // MSS = 1460
            4, 2, // SACK permitted (kind=4, len=2)
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // Timestamp (kind=8, len=10) — first 10 bytes
        ];
        let (kinds, mss, wscale) = parse_syn_options(&snap);
        assert_eq!(mss, 1460);
        assert_eq!(wscale, None); // didn't fit in the 16-byte window
        assert_eq!(kinds, vec![2, 4, 8]);
    }

    #[test]
    fn parses_short_options_block() {
        let snap = [
            2, 4, 0x05, 0xb4, // MSS = 1460
            1, 1, // two NOPs
            3, 3, 7, // WSCALE = 7
            0, // EOL
        ];
        let (kinds, mss, wscale) = parse_syn_options(&snap);
        assert_eq!(mss, 1460);
        assert_eq!(wscale, Some(7));
        assert_eq!(kinds, vec![2, 1, 1, 3, 0]);
    }

    #[test]
    fn handles_truncated_input() {
        // Single MSS kind byte but no length field → parser bails
        let snap = [2u8];
        let (kinds, mss, wscale) = parse_syn_options(&snap);
        assert_eq!(kinds, vec![2]);
        assert_eq!(mss, 0);
        assert_eq!(wscale, None);
    }
}
