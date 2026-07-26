//! HTTP/2 "Akamai-style" fingerprint (h2fp).
//!
//! Captures the connection-level state every HTTP/2 client emits
//! during its initial handshake, before any application request:
//!
//! 1. **Connection preface** (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) —
//!    confirms HTTP/2; not part of the fingerprint itself.
//! 2. **SETTINGS frame** — comma-joined `setting_id:value` pairs in
//!    the order the client sent them.
//! 3. **WINDOW_UPDATE** — the connection-level increment (if any).
//! 4. **PRIORITY frames** — count, plus the first one's
//!    `stream:exclusive:dependency:weight` tuple.
//! 5. **Pseudo-header order** — the order `:method`, `:authority`,
//!    `:scheme`, `:path` appear in the first HEADERS frame.
//!
//! Wire format: `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO`. Chrome,
//! Firefox, Safari, curl, go-http, Python httpx all produce
//! distinctive values — most "JA3/JA4-as-Chrome" spoofers don't bother
//! matching the HTTP/2 layer because hyper/h2 implementations differ
//! at byte-granularity.
//!
//! We don't run a real HPACK decoder for the pseudo-header order.
//! Instead we scan the HEADERS frame payload for HPACK static-table
//! indices (1=:authority, 2=:method GET, 3=:method POST, 4=:path /,
//! 5=:path /index.html, 6=:scheme http, 7=:scheme https) — enough to
//! reconstruct the order for any well-formed request.

use std::io;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_TYPE_DATA: u8 = 0x00;
const FRAME_TYPE_HEADERS: u8 = 0x01;
const FRAME_TYPE_PRIORITY: u8 = 0x02;
const FRAME_TYPE_SETTINGS: u8 = 0x04;
const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x08;
const SETTINGS_ACK: u8 = 0x01;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H2Fingerprint {
    /// SETTINGS pairs in arrival order, formatted `id:value`.
    pub settings: Vec<(u16, u32)>,
    /// Connection-level WINDOW_UPDATE increment, if the client sent
    /// one before the first HEADERS frame.
    pub window_update: Option<u32>,
    /// PRIORITY frames issued before HEADERS — count + first tuple
    /// (`stream:exclusive:dependency:weight`).
    pub priority_count: u32,
    pub first_priority: Option<(u32, bool, u32, u8)>,
    /// Pseudo-header order from the first HEADERS frame, lowercase
    /// single-letter form (`m` = method, `a` = authority, `s` =
    /// scheme, `p` = path).
    pub pseudo_order: String,
}

impl H2Fingerprint {
    /// Canonical wire format. Designed to be human-readable and
    /// directly comparable to akamai_fingerprint values published
    /// by threat-intel feeds.
    pub fn full(&self) -> String {
        let settings = self
            .settings
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(";");
        let wu = self
            .window_update
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string());
        let prio = match self.first_priority {
            Some((s, e, d, w)) => {
                format!("{}:{s}:{}:{d}:{w}", self.priority_count, e as u8)
            }
            None => format!("{}", self.priority_count),
        };
        let pseudo = if self.pseudo_order.is_empty() {
            "0".to_string()
        } else {
            self.pseudo_order.clone()
        };
        format!("{settings}|{wu}|{prio}|{pseudo}")
    }
}

/// Parse a buffered prefix of an HTTP/2 connection. `buf` must start
/// at the client preface; we read forward through SETTINGS / WU /
/// PRIORITY frames until the first HEADERS frame, then stop. Returns
/// None for non-HTTP/2 traffic or truncated buffers (caller falls
/// through; we don't block the connection over a sniff miss).
pub fn parse_prefix(buf: &[u8]) -> Option<H2Fingerprint> {
    if buf.len() < HTTP2_PREFACE.len() || &buf[..HTTP2_PREFACE.len()] != HTTP2_PREFACE {
        return None;
    }
    let mut r = Reader::new(&buf[HTTP2_PREFACE.len()..]);
    let mut fp = H2Fingerprint::default();
    // Walk up to MAX_FRAMES frames. Real clients send 1 SETTINGS +
    // up to one WINDOW_UPDATE + up to a few PRIORITY before HEADERS.
    // 16 is comfortably above that.
    for _ in 0..16 {
        let Some(frame) = read_frame(&mut r) else {
            return Some(fp); // truncation OK — return what we have
        };
        match frame.ty {
            FRAME_TYPE_SETTINGS if (frame.flags & SETTINGS_ACK) == 0 => {
                // SETTINGS payload: repeated (u16 id, u32 value).
                let mut pr = Reader::new(frame.payload);
                while pr.remaining() >= 6 {
                    let id = pr.u16().unwrap_or(0);
                    let val = pr.u32().unwrap_or(0);
                    fp.settings.push((id, val));
                }
            }
            FRAME_TYPE_WINDOW_UPDATE if frame.stream_id == 0 && frame.payload.len() >= 4 => {
                let inc = u32::from_be_bytes([
                    frame.payload[0] & 0x7f,
                    frame.payload[1],
                    frame.payload[2],
                    frame.payload[3],
                ]);
                fp.window_update = Some(inc);
            }
            FRAME_TYPE_PRIORITY => {
                fp.priority_count = fp.priority_count.saturating_add(1);
                if fp.first_priority.is_none() && frame.payload.len() >= 5 {
                    let dep = u32::from_be_bytes([
                        frame.payload[0] & 0x7f,
                        frame.payload[1],
                        frame.payload[2],
                        frame.payload[3],
                    ]);
                    let exclusive = (frame.payload[0] & 0x80) != 0;
                    let weight = frame.payload[4];
                    fp.first_priority = Some((frame.stream_id, exclusive, dep, weight));
                }
            }
            FRAME_TYPE_HEADERS => {
                fp.pseudo_order = parse_pseudo_order(frame.payload, frame.flags);
                return Some(fp);
            }
            FRAME_TYPE_DATA => {
                // Out-of-spec — clients shouldn't DATA before HEADERS.
                // Stop early; what we have is the fingerprint.
                return Some(fp);
            }
            _ => { /* skip other frame types (e.g. PING, GOAWAY) */ }
        }
    }
    Some(fp)
}

/// Decode the HPACK byte stream just enough to extract the
/// pseudo-header arrival order. Static-table indices 1-7 cover all
/// the pseudo-headers a normal request emits (`:authority`,
/// `:method GET/POST`, `:path //index.html`, `:scheme http/https`);
/// anything else is treated as a regular header and ignored.
fn parse_pseudo_order(mut payload: &[u8], flags: u8) -> String {
    // PADDED flag: first byte is padding length.
    const FLAG_PADDED: u8 = 0x08;
    const FLAG_PRIORITY: u8 = 0x20;
    if (flags & FLAG_PADDED) != 0 {
        if payload.is_empty() {
            return String::new();
        }
        let pad = payload[0] as usize;
        payload = &payload[1..];
        if payload.len() < pad {
            return String::new();
        }
        payload = &payload[..payload.len() - pad];
    }
    // PRIORITY flag: 5-byte stream dependency + weight prefix.
    if (flags & FLAG_PRIORITY) != 0 {
        if payload.len() < 5 {
            return String::new();
        }
        payload = &payload[5..];
    }
    let mut order = String::new();
    let mut i = 0;
    while i < payload.len() && order.len() < 4 {
        let b = payload[i];
        // Each HPACK header-field representation starts with one of
        // these prefix patterns (RFC 7541 §6). We decode just enough
        // to skip past each field; we don't maintain a dynamic
        // table because we only need the pseudo-header order from
        // the *first* HEADERS frame.
        let (prefix_bits, name_index_opt, has_value) = match b {
            // Indexed Header Field (1xxxxxxx) — 7-bit prefix, no value
            v if v & 0x80 != 0 => (7u8, None, false),
            // Literal With Incremental Indexing (01xxxxxx) — 6-bit
            // prefix; index 0 means literal name follows.
            v if v & 0xc0 == 0x40 => (6, Some(v & 0x3f), true),
            // Dynamic Table Size Update (001xxxxx) — 5-bit prefix, no value
            v if v & 0xe0 == 0x20 => (5, None, false),
            // Literal Without Indexing (0000xxxx) — 4-bit prefix
            v if v & 0xf0 == 0x00 => (4, Some(v & 0x0f), true),
            // Literal Never Indexed (0001xxxx) — 4-bit prefix
            v if v & 0xf0 == 0x10 => (4, Some(v & 0x0f), true),
            _ => break,
        };
        // Decode the leading integer (prefix bits). For the
        // 7-bit-prefix (indexed) form this IS the static-table
        // index. For the literal forms it's the name index (0 →
        // literal name follows).
        let Some((int_value, consumed)) = decode_integer(&payload[i..], prefix_bits) else {
            break;
        };
        i += consumed;
        // Record pseudo-header order for known static-table indices.
        let idx_for_order = match (prefix_bits, name_index_opt) {
            (7, None) => Some(int_value), // indexed form: int_value IS the static index
            (_, Some(0)) => None,         // literal name follows — not pseudo-header
            (_, Some(_)) => Some(int_value), // literal with indexed name
            _ => None,
        };
        if let Some(idx) = idx_for_order {
            match idx {
                1 => push_unique(&mut order, 'a'),
                2 | 3 => push_unique(&mut order, 'm'),
                4 | 5 => push_unique(&mut order, 'p'),
                6 | 7 => push_unique(&mut order, 's'),
                _ => {}
            }
        }
        if has_value {
            // Literal name (when name_index == 0): length-prefixed
            // bytes immediately follow. We don't care about the
            // string contents; skip past name then value.
            if matches!(name_index_opt, Some(0)) {
                let Some((nlen, n_consumed)) = decode_integer(&payload[i..], 7) else {
                    break;
                };
                i += n_consumed;
                i += nlen as usize;
                if i > payload.len() {
                    break;
                }
            }
            // Value: 1-bit Huffman flag (high bit) + 7-bit integer
            // prefix length + length bytes of value data.
            let Some((vlen, v_consumed)) = decode_integer(&payload[i..], 7) else {
                break;
            };
            i += v_consumed;
            i += vlen as usize;
            if i > payload.len() {
                break;
            }
        }
    }
    order
}

/// Decode an HPACK integer (RFC 7541 §5.1). `prefix_bits` is the
/// number of bits the integer shares with the leading byte (4, 5,
/// 6, or 7). Returns `(value, bytes_consumed)`; None on
/// truncation or a malformed continuation that doesn't terminate.
fn decode_integer(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let mask: u8 = (1u16.wrapping_shl(prefix_bits as u32) - 1) as u8;
    let first = buf[0] & mask;
    if first < mask {
        // Single-byte form — the integer fits entirely in the
        // prefix.
        return Some((first as u64, 1));
    }
    // Multi-byte continuation. Each subsequent byte contributes
    // 7 bits (low 7) and signals "more bytes follow" via the high
    // bit. Spec caps the value at 2^32, so 5 continuation bytes
    // is the absolute max — we accept up to 6 for slack.
    let mut value: u64 = first as u64;
    let mut shift: u32 = 0;
    let mut i = 1;
    while i < buf.len() && i <= 7 {
        let b = buf[i];
        value = value.checked_add(((b & 0x7f) as u64).checked_shl(shift)?)?;
        i += 1;
        if (b & 0x80) == 0 {
            return Some((value, i));
        }
        shift += 7;
        // The integer can be up to 2^64 by construction here, but
        // realistic HPACK lengths fit in 32 bits — bail on
        // anything that exceeds 32-bit max.
        if value > u32::MAX as u64 {
            return None;
        }
    }
    None
}

fn push_unique(s: &mut String, c: char) {
    if !s.contains(c) {
        s.push(c);
    }
}

struct ParsedFrame<'a> {
    ty: u8,
    flags: u8,
    stream_id: u32,
    payload: &'a [u8],
}

fn read_frame<'a>(r: &mut Reader<'a>) -> Option<ParsedFrame<'a>> {
    if r.remaining() < 9 {
        return None;
    }
    let len = r.u24()? as usize;
    let ty = r.u8()?;
    let flags = r.u8()?;
    let raw_sid = r.u32()?;
    let stream_id = raw_sid & 0x7fff_ffff;
    let payload = r.take(len)?;
    Some(ParsedFrame {
        ty,
        flags,
        stream_id,
        payload,
    })
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.buf.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<u32> {
        let b = self.buf.get(self.pos..self.pos + 3)?;
        self.pos += 3;
        Some(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.buf.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
}

// ───────────────────────── buffered sniff stream ─────────────────────

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Adapter that buffers up to `buf_size` bytes from the underlying
/// stream on the way in, lets a sniff callback inspect them, then
/// replays the buffer transparently — downstream readers (hyper)
/// see an `AsyncRead` that yields the captured bytes followed by
/// whatever else arrives.
///
/// We use this to wrap the TLS-terminated stream so the HTTP/2 frame
/// parser can capture the connection preface + SETTINGS without
/// hyper losing those bytes.
pub struct SniffedStream<S> {
    inner: S,
    replay: Vec<u8>,
    replay_pos: usize,
}

impl<S> SniffedStream<S> {
    pub fn new(inner: S, captured: Vec<u8>) -> Self {
        Self {
            inner,
            replay: captured,
            replay_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SniffedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.replay_pos < self.replay.len() {
            let remaining = &self.replay[self.replay_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.replay_pos += n;
            // Free the captured buffer the instant the last byte is
            // replayed — for keep-alive HTTP/2 connections this saves
            // 2-8 KiB per connection that would otherwise sit around
            // for the lifetime of the connection.
            if self.replay_pos >= self.replay.len() {
                self.replay = Vec::new();
                self.replay_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SniffedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut out = vec![
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
            ty,
            flags,
        ];
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn chrome_like_preface() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(HTTP2_PREFACE);
        // SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
        // INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144
        let mut payload = Vec::new();
        for (id, val) in [(1u16, 65_536u32), (2, 0), (4, 6_291_456), (6, 262_144)] {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&val.to_be_bytes());
        }
        out.extend(frame(FRAME_TYPE_SETTINGS, 0, 0, &payload));
        // WINDOW_UPDATE on stream 0, +15663105
        let wu: u32 = 15_663_105;
        out.extend(frame(FRAME_TYPE_WINDOW_UPDATE, 0, 0, &wu.to_be_bytes()));
        // HEADERS: indexed :method GET (2), :scheme https (7),
        // :path / (4), :authority (1, literal value)
        let mut hdr = vec![
            0x80 | 2, // :method GET
            0x80 | 7, // :scheme https
            0x80 | 4, // :path /
            0x40 | 1, // :authority literal
            11,       // value length
        ];
        hdr.extend_from_slice(b"example.com");
        out.extend(frame(FRAME_TYPE_HEADERS, 0x04, 1, &hdr)); // END_HEADERS
        out
    }

    #[test]
    fn parses_chrome_like_preface() {
        let bytes = chrome_like_preface();
        let fp = parse_prefix(&bytes).expect("parses");
        assert_eq!(fp.settings.len(), 4);
        assert_eq!(fp.settings[0], (1, 65_536));
        assert_eq!(fp.window_update, Some(15_663_105));
        assert_eq!(
            fp.pseudo_order, "mspa",
            "expected `mspa`, got `{}`",
            fp.pseudo_order
        );
    }

    #[test]
    fn full_format_matches_akamai_shape() {
        let bytes = chrome_like_preface();
        let fp = parse_prefix(&bytes).unwrap();
        let s = fp.full();
        // Format: settings|wu|prio|pseudo
        let parts: Vec<&str> = s.split('|').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts[0].contains("1:65536"));
        assert_eq!(parts[1], "15663105");
        assert_eq!(parts[3], "mspa");
    }

    #[test]
    fn rejects_non_h2_buffer() {
        assert!(parse_prefix(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn truncated_after_settings_is_partial() {
        let mut out = Vec::new();
        out.extend_from_slice(HTTP2_PREFACE);
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&65_536u32.to_be_bytes());
        out.extend(frame(FRAME_TYPE_SETTINGS, 0, 0, &payload));
        let fp = parse_prefix(&out).unwrap();
        assert_eq!(fp.settings.len(), 1);
        assert!(fp.pseudo_order.is_empty());
    }

    #[test]
    fn hpack_integer_single_byte() {
        // 5-bit prefix, value 10 → single byte 0b000_01010
        assert_eq!(decode_integer(&[0x0a], 5), Some((10, 1)));
    }

    #[test]
    fn hpack_integer_multi_byte_spec_example() {
        // RFC 7541 §C.1.2 example: encode 1337 with 5-bit prefix
        // → 0b00011111, 0b10011010, 0b00001010 = 0x1f, 0x9a, 0x0a
        assert_eq!(decode_integer(&[0x1f, 0x9a, 0x0a], 5), Some((1337, 3)));
    }

    #[test]
    fn hpack_integer_truncated_is_none() {
        // Prefix says continuation but buffer cut off.
        assert!(decode_integer(&[0xff, 0x80], 7).is_none());
    }

    #[test]
    fn long_header_value_does_not_break_pseudo_walk() {
        // Build a HEADERS payload: :method GET (indexed) +
        // literal-name pseudo-header with a 300-byte value.
        let mut hdr = vec![0x82]; // :method GET
        // Literal without indexing, indexed name = 4 (:path /), then
        // a 300-byte value (HPACK length encoded as multi-byte).
        hdr.push(0x04); // 0000 0100 — literal without indexing, name index 4
        // Value length 300 with 7-bit prefix: 300 - 127 = 173,
        // → 0x7f, 0xad, 0x01
        hdr.push(0x7f);
        hdr.push((173 % 128) | 0x80);
        hdr.push(173 / 128);
        hdr.extend_from_slice(&vec![b'a'; 300]);
        // Then :authority indexed.
        hdr.push(0x81);
        let order = parse_pseudo_order(&hdr, 0);
        assert_eq!(order, "mpa", "expected `mpa`, got `{order}`");
    }

    #[test]
    fn settings_ack_is_ignored() {
        let mut out = Vec::new();
        out.extend_from_slice(HTTP2_PREFACE);
        out.extend(frame(FRAME_TYPE_SETTINGS, SETTINGS_ACK, 0, &[]));
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&65_536u32.to_be_bytes());
        out.extend(frame(FRAME_TYPE_SETTINGS, 0, 0, &payload));
        let fp = parse_prefix(&out).unwrap();
        // The ACK doesn't contribute settings; only the real frame.
        assert_eq!(fp.settings.len(), 1);
    }
}
