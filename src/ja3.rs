//! JA3 TLS Client Hello fingerprinting.
//!
//! Implements the canonical JA3 string defined by Salesforce
//! (https://github.com/salesforce/ja3):
//!
//! `SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat`
//!
//! Each field is a hyphen-separated list of decimal numbers. The MD5
//! hash of the final string is the JA3 fingerprint commonly published
//! by threat-intel feeds (abuse.ch, SSL Blacklist, etc.) so operators
//! can paste hashes straight into the deny list.
//!
//! GREASE values (RFC 8701) are excluded so genuine browsers — which
//! sprinkle randomised GREASE codepoints into ciphers/extensions —
//! produce a stable hash.

use md5::{Digest, Md5};

const TLS_HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;

/// Parse a TLS record + ClientHello prefix and compute the JA3 string
/// plus its MD5 hex digest. Returns None if `buf` doesn't carry a
/// well-formed ClientHello (truncated, wrong content type, etc.).
pub fn compute_ja3(buf: &[u8]) -> Option<(String, String)> {
    let mut r = Reader::new(buf);

    // TLS record header
    let content_type = r.u8()?;
    if content_type != TLS_HANDSHAKE {
        return None;
    }
    let _record_version = r.u16()?;
    let record_len = r.u16()? as usize;
    if r.remaining() < record_len {
        return None;
    }

    // Handshake header
    let hs_type = r.u8()?;
    if hs_type != CLIENT_HELLO {
        return None;
    }
    let hs_len = r.u24()? as usize;
    if hs_len > r.remaining() {
        return None;
    }
    let mut hs = Reader::new(r.take(hs_len)?);

    let client_version = hs.u16()?;
    hs.skip(32)?; // random

    let sid_len = hs.u8()? as usize;
    hs.skip(sid_len)?;

    let cipher_bytes_len = hs.u16()? as usize;
    let cipher_bytes = hs.take(cipher_bytes_len)?;
    let ciphers = parse_u16_list(cipher_bytes);

    let comp_len = hs.u8()? as usize;
    hs.skip(comp_len)?;

    // Some TLS 1.0 hellos omit the extensions block — that's fine, the
    // resulting JA3 string just has empty trailing fields.
    let (extensions, groups, point_formats) = if hs.remaining() >= 2 {
        let ext_len = hs.u16()? as usize;
        let ext_bytes = hs.take(ext_len)?;
        parse_extensions(ext_bytes)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

    let ja3 = format!(
        "{},{},{},{},{}",
        client_version,
        join_dash(&filter_grease(&ciphers)),
        join_dash(&filter_grease(&extensions)),
        join_dash(&filter_grease(&groups)),
        join_dash(&point_formats),
    );

    let mut hasher = Md5::new();
    hasher.update(ja3.as_bytes());
    let hash = hex(hasher.finalize().as_slice());
    Some((ja3, hash))
}

/// V51 — compute the canonical JA3 string + MD5 hash from
/// already-parsed pieces. Used by the pingora openssl TlsAccept
/// callback, which reads ClientHello data via `SSL_client_hello_*`
/// accessors rather than raw record bytes.
///
/// Arguments mirror the wire-format fields:
///   • `client_version` — TLS legacy version (0x0303 etc.)
///   • `ciphers` — offered cipher suite IDs (u16 list, wire order)
///   • `extension_types` — extension type IDs offered (wire order)
///   • `supported_groups` — TLS supported_groups (ext 10) values
///   • `ec_point_formats` — TLS ec_point_formats (ext 11) values
///     (single-byte each — caller widens to u16 for join uniformity)
///
///
/// GREASE values (RFC 8701) are filtered out of ciphers, extensions,
/// and supported_groups so browsers' randomised entries produce a
/// stable hash. ec_point_formats stays raw — matches the original
/// byte-parser version.
pub fn compute_ja3_from_parts(
    client_version: u16,
    ciphers: &[u16],
    extension_types: &[u16],
    supported_groups: &[u16],
    ec_point_formats: &[u16],
) -> (String, String) {
    let s = format!(
        "{},{},{},{},{}",
        client_version,
        join_dash(&filter_grease(ciphers)),
        join_dash(&filter_grease(extension_types)),
        join_dash(&filter_grease(supported_groups)),
        join_dash(ec_point_formats),
    );
    let mut hasher = Md5::new();
    hasher.update(s.as_bytes());
    (s, hex(hasher.finalize().as_slice()))
}

/// V56 — exposed so tests + cross-binary parity assertions can
/// pull the parts out of a wire buffer and feed them to
/// `compute_ja3_from_parts`. Not part of the operator surface;
/// kept `pub(crate)` to discourage accidental coupling.
#[cfg(test)]
pub(crate) fn parse_extensions_pub(bytes: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<u16>) {
    parse_extensions(bytes)
}

fn parse_extensions(bytes: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<u16>) {
    let mut r = Reader::new(bytes);
    let mut types = Vec::new();
    let mut supported_groups = Vec::new();
    let mut point_formats = Vec::new();
    while r.remaining() >= 4 {
        let Some(ty) = r.u16() else { break };
        let Some(len) = r.u16() else { break };
        let Some(data) = r.take(len as usize) else {
            break;
        };
        types.push(ty);
        match ty {
            EXT_SUPPORTED_GROUPS => {
                // supported_groups: u16 length prefix + list
                let mut inner = Reader::new(data);
                if let Some(l) = inner.u16()
                    && let Some(b) = inner.take(l as usize)
                {
                    supported_groups = parse_u16_list(b);
                }
            }
            EXT_EC_POINT_FORMATS => {
                // ec_point_formats: u8 length prefix + bytes (each u8)
                let mut inner = Reader::new(data);
                if let Some(l) = inner.u8()
                    && let Some(b) = inner.take(l as usize)
                {
                    point_formats = b.iter().map(|x| *x as u16).collect();
                }
            }
            _ => {}
        }
    }
    (types, supported_groups, point_formats)
}

fn parse_u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// GREASE codepoints (RFC 8701) — both nibbles of each byte equal,
/// low nibble is `a`. Browsers stuff random GREASE values into their
/// hellos to keep middleboxes honest; filtering them keeps JA3
/// fingerprints stable across browser sessions.
///
/// pub so other modules (ja4.rs's wire-format path uses a local copy
/// for a tiny dep-isolation win, but `compute_ja3_from_parts` callers
/// and the pingora openssl bridge in `proxy::pingora_tls` need the
/// public version too).
pub fn is_grease(v: u16) -> bool {
    let lo = (v & 0xff) as u8;
    let hi = (v >> 8) as u8;
    lo == hi && (lo & 0x0f) == 0x0a
}

fn filter_grease(input: &[u16]) -> Vec<u16> {
    input.iter().copied().filter(|v| !is_grease(*v)).collect()
}

fn join_dash(xs: &[u16]) -> String {
    let mut s = String::new();
    for (i, x) in xs.iter().enumerate() {
        if i > 0 {
            s.push('-');
        }
        s.push_str(&x.to_string());
    }
    s
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.remaining() < n {
            return None;
        }
        self.pos += n;
        Some(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but realistic ClientHello: TLS 1.2 record carrying a
    /// ClientHello with ClientVersion=0x0303 (TLS 1.2), two cipher
    /// suites (one of which is GREASE — must be stripped), one
    /// supported_groups extension with two curves, one ec_point_formats
    /// extension with one value.
    fn sample_client_hello() -> Vec<u8> {
        let mut hs = Vec::new();
        // ClientVersion: TLS 1.2
        hs.extend_from_slice(&0x0303u16.to_be_bytes());
        // Random
        hs.extend_from_slice(&[0u8; 32]);
        // SessionID
        hs.push(0);
        // Cipher suites: GREASE 0x0a0a + TLS_AES_128_GCM_SHA256 (0x1301)
        let ciphers: [u16; 2] = [0x0a0a, 0x1301];
        hs.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            hs.extend_from_slice(&c.to_be_bytes());
        }
        // Compression methods
        hs.push(1);
        hs.push(0);

        // Extensions
        let mut exts = Vec::new();
        // supported_groups (type 10): list of two groups (29=x25519, 23=secp256r1)
        let sg_inner: Vec<u8> = [29u16, 23u16]
            .iter()
            .flat_map(|x| x.to_be_bytes())
            .collect();
        let mut sg_ext = Vec::new();
        sg_ext.extend_from_slice(&(sg_inner.len() as u16).to_be_bytes());
        sg_ext.extend_from_slice(&sg_inner);
        exts.extend_from_slice(&10u16.to_be_bytes()); // type
        exts.extend_from_slice(&(sg_ext.len() as u16).to_be_bytes()); // len
        exts.extend_from_slice(&sg_ext);
        // ec_point_formats (type 11): one byte (0 = uncompressed)
        let mut pf_ext = vec![1u8, 0u8];
        let _ = &mut pf_ext;
        exts.extend_from_slice(&11u16.to_be_bytes());
        exts.extend_from_slice(&(pf_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&pf_ext);

        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);

        // Handshake wrapper: HandshakeType (1) + 24-bit length
        let mut handshake = vec![CLIENT_HELLO];
        let hs_len = hs.len() as u32;
        handshake.push(((hs_len >> 16) & 0xff) as u8);
        handshake.push(((hs_len >> 8) & 0xff) as u8);
        handshake.push((hs_len & 0xff) as u8);
        handshake.extend_from_slice(&hs);

        // TLS record header
        let mut record = vec![TLS_HANDSHAKE];
        record.extend_from_slice(&0x0301u16.to_be_bytes()); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn computes_ja3_string_and_hash() {
        let (ja3, hash) = compute_ja3(&sample_client_hello()).expect("parses");
        // ClientVersion=771, ciphers=4865 (GREASE stripped),
        // extensions=10-11, groups=29-23, point_formats=0
        assert_eq!(ja3, "771,4865,10-11,29-23,0");
        // Hash is the MD5 of that string.
        assert_eq!(hash.len(), 32);
        let expected = format!("{:x}", Md5::digest(ja3.as_bytes()));
        assert_eq!(hash, expected);
    }

    #[test]
    fn rejects_non_handshake_record() {
        let mut buf = sample_client_hello();
        buf[0] = 23; // application data — not handshake
        assert!(compute_ja3(&buf).is_none());
    }

    #[test]
    fn rejects_truncated_hello() {
        let buf = sample_client_hello();
        assert!(compute_ja3(&buf[..20]).is_none());
    }

    #[test]
    fn grease_values_filtered() {
        for v in [0x0a0a, 0x1a1a, 0x2a2a, 0xfafa] {
            assert!(is_grease(v), "{v:#06x} should be GREASE");
        }
        for v in [0x1301, 0x0303, 0x000a] {
            assert!(!is_grease(v), "{v:#06x} should NOT be GREASE");
        }
    }

    /// V56 — cross-binary parity: a JA3 string + MD5 computed from
    /// raw wire bytes (compute_ja3, used by hyper handler) MUST equal
    /// the JA3 computed from already-parsed fields (compute_ja3_from_parts,
    /// used by the pingora openssl TlsAccept callback). Same client
    /// → same fingerprint on both binaries.
    #[test]
    fn from_parts_matches_byte_parser() {
        let buf = sample_client_hello();
        let (ja3_bytes, hash_bytes) = compute_ja3(&buf).expect("byte parser");
        // Extract the same parts manually (this is what the openssl
        // TlsAccept callback gets via SSL_client_hello_* accessors).
        let mut r = Reader::new(&buf);
        // record header
        let _ct = r.u8().unwrap();
        let _rv = r.u16().unwrap();
        let _rl = r.u16().unwrap();
        // handshake header
        let _ht = r.u8().unwrap();
        let _hl = r.u24().unwrap();
        let client_version = r.u16().unwrap();
        r.skip(32).unwrap();
        let sid_len = r.u8().unwrap() as usize;
        r.skip(sid_len).unwrap();
        let cipher_len = r.u16().unwrap() as usize;
        let cipher_bytes = r.take(cipher_len).unwrap();
        let ciphers: Vec<u16> = parse_u16_list(cipher_bytes);
        let comp_len = r.u8().unwrap() as usize;
        r.skip(comp_len).unwrap();
        let ext_len = r.u16().unwrap() as usize;
        let ext_bytes = r.take(ext_len).unwrap();
        let (extensions, groups, ec_formats) = parse_extensions_pub(ext_bytes);
        let (ja3_parts, hash_parts) =
            compute_ja3_from_parts(client_version, &ciphers, &extensions, &groups, &ec_formats);
        assert_eq!(
            ja3_bytes, ja3_parts,
            "JA3 string drift between byte parser and from_parts"
        );
        assert_eq!(
            hash_bytes, hash_parts,
            "JA3 MD5 drift between byte parser and from_parts"
        );
    }

    #[test]
    fn from_parts_with_grease_filters_identically() {
        // Construct a ClientHello with GREASE codepoints in ciphers
        // and extensions — both compute paths must drop them.
        let ciphers_raw = vec![0x0a0au16, 0x1301, 0x1302, 0x2a2a];
        let exts_raw = vec![0x0a0au16, 0, 10, 11, 0xfafa];
        let groups = vec![29u16, 23];
        let ec = vec![0u16];
        let (s, _h) = compute_ja3_from_parts(0x0303, &ciphers_raw, &exts_raw, &groups, &ec);
        // After GREASE filter: ciphers = [4865, 4866], exts = [0, 10, 11]
        assert_eq!(s, "771,4865-4866,0-10-11,29-23,0");
    }
}
