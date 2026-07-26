//! PROXY protocol v1 (text) and v2 (binary) header parser.
//!
//! When Aegis runs behind a L4 load balancer (AWS NLB, HAProxy, IPVS-DR)
//! the TCP peer address is the LB, not the real client. The PROXY
//! protocol — defined by HAProxy — prepends the original src/dst tuple
//! to every connection so the backend can recover the real client IP.
//!
//! v1: ASCII line ending with `\r\n`, e.g.
//!     `PROXY TCP4 192.0.2.1 198.51.100.2 35692 80\r\n`
//!
//! v2: 12-byte magic + 4-byte header + variable-length address block.
//!
//! This module reads enough bytes to recover the real `IpAddr` and
//! returns the number of bytes consumed so the caller can slice them
//! off the connection (with `AsyncReadExt::read_exact`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow};

use crate::config::ProxyProtocolMode;

/// Outcome of a parse attempt — the recovered client IP plus the
/// number of bytes that belong to the PROXY header (caller must
/// consume them before reading the real payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub client_ip: IpAddr,
    pub consumed: usize,
}

const V2_MAGIC: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Parse a PROXY header from the prefix of `buf`. Returns Ok(Some(...))
/// when a full header is present, Ok(None) when more bytes are needed
/// to decide, and Err when bytes definitively don't match the
/// requested mode (caller should close the connection).
pub fn parse(buf: &[u8], mode: ProxyProtocolMode) -> Result<Option<Parsed>> {
    if mode == ProxyProtocolMode::Off {
        return Ok(Some(Parsed {
            client_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            consumed: 0,
        }));
    }

    if buf.len() >= V2_MAGIC.len() && buf.starts_with(&V2_MAGIC) {
        if mode == ProxyProtocolMode::V1 {
            return Err(anyhow!("v2 header but mode = v1"));
        }
        return parse_v2(buf);
    }

    if buf.starts_with(b"PROXY ") {
        if mode == ProxyProtocolMode::V2 {
            return Err(anyhow!("v1 header but mode = v2"));
        }
        return parse_v1(buf);
    }

    // Neither prefix yet — caller decides whether to wait for more
    // bytes or treat as protocol violation. For Auto/V1/V2 modes we
    // need at least 12 bytes to discriminate v2 magic, plus enough
    // for "PROXY ".
    if buf.len() < 16 {
        return Ok(None);
    }
    Err(anyhow!("connection does not begin with a PROXY header"))
}

fn parse_v1(buf: &[u8]) -> Result<Option<Parsed>> {
    let Some(end) = find_crlf(buf) else {
        if buf.len() > 108 {
            return Err(anyhow!("PROXY v1 header exceeds 108-byte limit"));
        }
        return Ok(None);
    };
    let line =
        std::str::from_utf8(&buf[..end]).map_err(|_| anyhow!("PROXY v1 header is not ASCII"))?;
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.len() < 2 || parts[0] != "PROXY" {
        return Err(anyhow!("malformed PROXY v1 header"));
    }
    let client_ip = match parts[1] {
        "TCP4" | "TCP6" => {
            if parts.len() < 6 {
                return Err(anyhow!("PROXY v1 TCP header missing fields"));
            }
            parts[2]
                .parse::<IpAddr>()
                .map_err(|_| anyhow!("PROXY v1 invalid client IP"))?
        }
        "UNKNOWN" => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        other => return Err(anyhow!("PROXY v1 unsupported family: {other}")),
    };
    Ok(Some(Parsed {
        client_ip,
        consumed: end + 2, // include the \r\n
    }))
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn parse_v2(buf: &[u8]) -> Result<Option<Parsed>> {
    if buf.len() < 16 {
        return Ok(None);
    }
    let ver_cmd = buf[12];
    let fam_proto = buf[13];
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let header_len = 16 + addr_len;
    if buf.len() < header_len {
        return Ok(None);
    }

    // Top nibble of byte 12 must be 2 (protocol version).
    if (ver_cmd >> 4) != 0x2 {
        return Err(anyhow!("PROXY v2 unsupported version"));
    }
    let command = ver_cmd & 0x0F;
    // command 0 = LOCAL (health check from the LB itself) → no real
    // client, just consume the bytes and signal "no override".
    if command == 0 {
        return Ok(Some(Parsed {
            client_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            consumed: header_len,
        }));
    }
    if command != 1 {
        return Err(anyhow!("PROXY v2 unknown command {command}"));
    }

    let family = fam_proto >> 4;
    let client_ip = match family {
        // 0 = AF_UNSPEC: header carries no addresses, treat as unknown.
        0 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        // 1 = AF_INET: 4 byte src + 4 byte dst + 2 byte sport + 2 byte dport
        1 => {
            if addr_len < 12 {
                return Err(anyhow!("PROXY v2 IPv4 addr block too short"));
            }
            let s = &buf[16..20];
            IpAddr::V4(Ipv4Addr::new(s[0], s[1], s[2], s[3]))
        }
        // 2 = AF_INET6: 16 byte src + 16 byte dst + 2 byte sport + 2 byte dport
        2 => {
            if addr_len < 36 {
                return Err(anyhow!("PROXY v2 IPv6 addr block too short"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[16..32]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        // 3 = AF_UNIX: ignore, no IP available.
        3 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        other => return Err(anyhow!("PROXY v2 unknown family {other}")),
    };

    Ok(Some(Parsed {
        client_ip,
        consumed: header_len,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_mode_returns_zero_consumed() {
        let p = parse(b"GET / HTTP/1.1", ProxyProtocolMode::Off)
            .unwrap()
            .unwrap();
        assert_eq!(p.consumed, 0);
    }

    #[test]
    fn v1_tcp4_round_trip() {
        let raw = b"PROXY TCP4 192.0.2.1 198.51.100.2 35692 80\r\nGET / HTTP/1.1";
        let p = parse(raw, ProxyProtocolMode::V1).unwrap().unwrap();
        assert_eq!(p.client_ip, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(&raw[p.consumed..p.consumed + 5], b"GET /");
    }

    #[test]
    fn v1_tcp6_round_trip() {
        let raw = b"PROXY TCP6 2001:db8::1 2001:db8::2 35692 443\r\n";
        let p = parse(raw, ProxyProtocolMode::Auto).unwrap().unwrap();
        assert_eq!(p.client_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(p.consumed, raw.len());
    }

    #[test]
    fn v1_unknown_family_is_unspecified() {
        let raw = b"PROXY UNKNOWN\r\n";
        let p = parse(raw, ProxyProtocolMode::V1).unwrap().unwrap();
        assert!(p.client_ip.is_unspecified());
    }

    #[test]
    fn v1_short_buffer_waits_for_more() {
        let raw = b"PROXY TCP4 192.0.2.1";
        let r = parse(raw, ProxyProtocolMode::V1).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn v1_mode_rejects_v2_magic() {
        let mut raw = V2_MAGIC.to_vec();
        raw.extend_from_slice(&[0x21, 0x11, 0, 12]);
        raw.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]);
        assert!(parse(&raw, ProxyProtocolMode::V1).is_err());
    }

    #[test]
    fn v2_ipv4_parses() {
        let mut raw = V2_MAGIC.to_vec();
        raw.push(0x21); // version 2, command PROXY (1)
        raw.push(0x11); // family AF_INET (1), proto STREAM (1)
        raw.extend_from_slice(&12u16.to_be_bytes());
        raw.extend_from_slice(&[10, 0, 0, 5]); // src
        raw.extend_from_slice(&[10, 0, 0, 1]); // dst
        raw.extend_from_slice(&44321u16.to_be_bytes()); // sport
        raw.extend_from_slice(&80u16.to_be_bytes()); // dport
        let p = parse(&raw, ProxyProtocolMode::V2).unwrap().unwrap();
        assert_eq!(p.client_ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(p.consumed, raw.len());
    }

    #[test]
    fn v2_ipv6_parses() {
        let mut raw = V2_MAGIC.to_vec();
        raw.push(0x21);
        raw.push(0x21); // AF_INET6 (2), STREAM (1)
        raw.extend_from_slice(&36u16.to_be_bytes());
        let src: Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        raw.extend_from_slice(&src.octets());
        raw.extend_from_slice(&dst.octets());
        raw.extend_from_slice(&12345u16.to_be_bytes());
        raw.extend_from_slice(&443u16.to_be_bytes());
        let p = parse(&raw, ProxyProtocolMode::Auto).unwrap().unwrap();
        assert_eq!(p.client_ip, IpAddr::V6(src));
    }

    #[test]
    fn v2_local_command_returns_unspecified() {
        let mut raw = V2_MAGIC.to_vec();
        raw.push(0x20); // version 2, command LOCAL (0)
        raw.push(0x00);
        raw.extend_from_slice(&0u16.to_be_bytes());
        let p = parse(&raw, ProxyProtocolMode::V2).unwrap().unwrap();
        assert!(p.client_ip.is_unspecified());
        assert_eq!(p.consumed, 16);
    }

    #[test]
    fn auto_mode_picks_either() {
        let v1 = b"PROXY TCP4 1.1.1.1 2.2.2.2 10 20\r\n";
        let p1 = parse(v1, ProxyProtocolMode::Auto).unwrap().unwrap();
        assert_eq!(p1.client_ip, "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn non_proxy_traffic_in_strict_mode_errors() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(parse(raw, ProxyProtocolMode::V1).is_err());
    }
}
