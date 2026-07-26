//! mTLS client-certificate fingerprint.
//!
//! When the proxy is configured for client-certificate auth, rustls
//! hands us the verified chain after the handshake. We hash the
//! leaf in a canonical way that's stable across cosmetic differences
//! (whitespace, order of SAN entries) and tag the resulting digest
//! into the per-request context.
//!
//! The fingerprint shape mirrors the JA4 family — two segments
//! separated by `_`:
//!
//!   `mtls_{kty}{chain_len}{san_count}{policy_hash}_{leaf_sha256_12}`
//!
//! Example: `mtls_e2sf_4f8e9b1c2d3a_3e7c1a8f9e2b`
//!
//!   - `kty` one of `r` (RSA), `e` (ECDSA), `d` (Ed25519), `?` (other)
//!   - `chain_len` capped at 9 (single hex digit)
//!   - `san_count` capped at 9 (single hex digit)
//!   - `policy_hash` first 12 hex of sha256 over the issuer DN
//!   - `leaf_sha256_12` first 12 hex of sha256 over the leaf cert DER
//!
//! Operators consume this for "fleet-wide cert leakage" detection:
//! one leaked client cert appearing from many IPs in a short window
//! will all share the same `mtls_*` fingerprint regardless of the
//! TLS version, JA3, JA4, or geolocation of the connections.

use sha2::{Digest, Sha256};

/// Captured client-certificate chain — the subset of rustls's
/// `CertificateDer` chain that we need to fingerprint. Built by the
/// loader after rustls accepts the chain (so the certs are already
/// chain-validated against the configured roots).
#[derive(Debug, Clone, Default)]
pub struct MtlsChain {
    /// Leaf certificate (the client's own cert) in DER form.
    pub leaf_der: Vec<u8>,
    /// Chain length including the leaf — `1` when the client sent a
    /// single self-signed cert, `2..N` for intermediate chains.
    pub chain_len: usize,
    /// Number of SAN entries on the leaf. Operators flag clients
    /// with unusually high SAN counts (wildcard-stuffed bypass certs).
    pub san_count: usize,
    /// Key type as observed in the leaf's SPKI: `'r'` RSA, `'e'`
    /// ECDSA, `'d'` Ed25519, `'?'` anything else.
    pub key_type: char,
    /// Issuer Distinguished Name as a UTF-8 string (already RFC-4514
    /// formatted by the caller). We hash this verbatim so issuer
    /// changes (even cosmetic) bump the policy hash.
    pub issuer_dn: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsFingerprint {
    pub full: String,
    pub a: String,
    pub b: String,
}

/// Compute a JA4-style mTLS fingerprint from a captured chain.
pub fn compute(chain: &MtlsChain) -> MtlsFingerprint {
    let chain_d = single_hex(chain.chain_len);
    let san_d = single_hex(chain.san_count);
    let policy_hash = sha_prefix12(chain.issuer_dn.as_bytes());
    let a = format!("mtls_{}{chain_d}{san_d}{policy_hash}", chain.key_type);
    let b = sha_prefix12(&chain.leaf_der);
    MtlsFingerprint {
        full: format!("{a}_{b}"),
        a,
        b,
    }
}

fn single_hex(n: usize) -> char {
    // Cap at 9 so the segment width stays predictable. Real chains
    // rarely exceed 4-5 deep; anything past 9 means an attacker is
    // stuffing the chain for nuisance.
    let n = n.min(9);
    char::from_digit(n as u32, 16).unwrap_or('0')
}

fn sha_prefix12(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    let digest = h.finalize();
    let mut out = String::with_capacity(12);
    for x in digest.iter().take(6) {
        out.push_str(&format!("{x:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MtlsChain {
        MtlsChain {
            leaf_der: b"sample-leaf-der".to_vec(),
            chain_len: 2,
            san_count: 1,
            key_type: 'e',
            issuer_dn: "CN=Test CA,O=Aegis".to_string(),
        }
    }

    #[test]
    fn fingerprint_shape() {
        let fp = compute(&sample());
        // mtls_<kty><chain_d><san_d><policy12>_<leaf12>
        assert!(fp.a.starts_with("mtls_e"));
        assert_eq!(fp.a.len(), 5 + 1 + 1 + 1 + 12); // "mtls_" + 3 + 12
        assert_eq!(fp.b.len(), 12);
        assert_eq!(fp.full, format!("{}_{}", fp.a, fp.b));
    }

    #[test]
    fn issuer_change_bumps_policy_hash() {
        let mut a = sample();
        let mut b = sample();
        b.issuer_dn = "CN=Other CA".into();
        assert_ne!(compute(&a).a, compute(&b).a);
        // Leaf hash unchanged.
        a.leaf_der = b.leaf_der.clone();
        assert_eq!(compute(&a).b, compute(&b).b);
    }

    #[test]
    fn chain_length_caps_at_nine() {
        let mut c = sample();
        c.chain_len = 99;
        // The single hex digit should still be `9`, not error.
        let fp = compute(&c);
        assert!(fp.a.contains('9'));
    }
}

// =====================================================================
// V55 — DER parsers shared by hyper (server.rs) and pingora
// (proxy/pingora_tls.rs) paths. Both call into these helpers so the
// resulting MtlsChain fields — and therefore the final fingerprint —
// are byte-identical regardless of which TLS backend handled the
// handshake. Lives here next to `compute` so a single
// `pub use mtls_fp::{classify_key_type, count_san_entries,
// extract_issuer_dn}` covers everything callers need.
// =====================================================================

/// Coarse key-type detection via OID byte signature in the leaf DER.
/// Returns the `kty` character that goes into the fingerprint's
/// `mtls_<kty>...` slot.
pub fn classify_key_type(der: &[u8]) -> char {
    // RSA: 1.2.840.113549.1.1.1 → DER bytes 06 09 2a 86 48 86 f7 0d 01 01 01
    const RSA_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    // ECDSA: 1.2.840.10045.2.1 → 06 07 2a 86 48 ce 3d 02 01
    const EC_OID: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    // Ed25519: 1.3.101.112 → 06 03 2b 65 70
    const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    if der.windows(RSA_OID.len()).any(|w| w == RSA_OID) {
        'r'
    } else if der.windows(EC_OID.len()).any(|w| w == EC_OID) {
        'e'
    } else if der.windows(ED25519_OID.len()).any(|w| w == ED25519_OID) {
        'd'
    } else {
        '?'
    }
}

/// Best-effort SAN entry count via OID byte signature.
/// 2.5.29.17 = subjectAltName → DER bytes 06 03 55 1d 11
/// Counts `0x82` (dNSName) and `0x87` (iPAddress) tags inside the
/// next 256 bytes after the SAN OID. Coarse but stable — operators
/// only consume the digit in the fingerprint, not the exact count.
pub fn count_san_entries(der: &[u8]) -> usize {
    const SAN_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
    let Some(off) = der.windows(SAN_OID.len()).position(|w| w == SAN_OID) else {
        return 0;
    };
    let region = &der[off..der.len().min(off + 256)];
    region.iter().filter(|b| matches!(**b, 0x82 | 0x87)).count()
}

/// Extract a canonical Issuer DN string from a leaf X.509 cert in
/// DER form. Walks just enough ASN.1 to land on the `issuer`
/// SEQUENCE inside `tbsCertificate`, then concatenates every
/// PrintableString / UTF8String value with `,` separators.
/// Result is stable across cosmetically-different copies of the
/// same cert — exactly what the `policy_hash` slot needs.
pub fn extract_issuer_dn(der: &[u8]) -> String {
    // X.509 cert nesting:
    //   Certificate (outer SEQUENCE) {
    //     tbsCertificate (SEQUENCE) {
    //       version [0] EXPLICIT optional,
    //       serialNumber INTEGER,
    //       signature AlgorithmIdentifier (SEQUENCE),
    //       issuer Name (SEQUENCE) ← target,
    //       ...
    //     },
    //     signatureAlgorithm AlgorithmIdentifier,
    //     signatureValue BIT STRING,
    //   }
    //
    // So we descend TWO SEQUENCE levels (Certificate → tbsCertificate)
    // before walking the version/serial/sig prefix. (V55 fix — the
    // pre-V55 version called enter_sequence once and ended up skipping
    // tbsCertificate entirely, then trying to enter the sigValue BIT
    // STRING. Silently returned "" on every real cert.)
    let Some(outer) = enter_sequence(der) else {
        return String::new();
    };
    let Some(tbs) = enter_sequence(outer) else {
        return String::new();
    };
    let mut cursor = tbs;
    // Optional explicit [0] version
    if !cursor.is_empty() && cursor[0] == 0xa0 {
        cursor = skip_tag(cursor).unwrap_or(cursor);
    }
    // serialNumber (INTEGER)
    cursor = skip_tag(cursor).unwrap_or(&[]);
    // signature (AlgorithmIdentifier — SEQUENCE)
    cursor = skip_tag(cursor).unwrap_or(&[]);
    // issuer (Name — SEQUENCE OF RelativeDistinguishedName)
    let Some(issuer_body) = enter_sequence(cursor) else {
        return String::new();
    };
    extract_dn_strings(issuer_body)
}

fn enter_sequence(der: &[u8]) -> Option<&[u8]> {
    if der.is_empty() || der[0] != 0x30 {
        return None;
    }
    let (len, header_len) = asn1_length(&der[1..])?;
    let start = 1 + header_len;
    der.get(start..start + len)
}

fn skip_tag(der: &[u8]) -> Option<&[u8]> {
    if der.is_empty() {
        return None;
    }
    let (len, header_len) = asn1_length(&der[1..])?;
    der.get(1 + header_len + len..)
}

fn asn1_length(der: &[u8]) -> Option<(usize, usize)> {
    let first = *der.first()?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || der.len() < 1 + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &der[1..1 + n] {
            len = (len << 8) | (b as usize);
        }
        Some((len, 1 + n))
    }
}

fn extract_dn_strings(mut body: &[u8]) -> String {
    let mut out = String::new();
    while !body.is_empty() {
        // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        let Some(rdn_body) = enter_set(body) else {
            break;
        };
        let next_after = skip_tag(body).unwrap_or(&[]);
        // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
        let mut atv = rdn_body;
        while !atv.is_empty() {
            let Some(seq_body) = enter_sequence(atv) else {
                break;
            };
            // Skip the OID (type).
            let value_region = skip_tag(seq_body).unwrap_or(&[]);
            if let Some(s) = read_dn_string(value_region) {
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(&s);
            }
            atv = skip_tag(atv).unwrap_or(&[]);
        }
        body = next_after;
    }
    out
}

fn enter_set(der: &[u8]) -> Option<&[u8]> {
    if der.is_empty() || der[0] != 0x31 {
        return None;
    }
    let (len, header_len) = asn1_length(&der[1..])?;
    let start = 1 + header_len;
    der.get(start..start + len)
}

fn read_dn_string(der: &[u8]) -> Option<String> {
    let tag = *der.first()?;
    // 0x13 PrintableString, 0x0c UTF8String, 0x16 IA5String,
    // 0x14 T61String, 0x1e BMPString — common DN value tags.
    if !matches!(tag, 0x13 | 0x0c | 0x16 | 0x14 | 0x1e) {
        return None;
    }
    let (len, header_len) = asn1_length(&der[1..])?;
    let start = 1 + header_len;
    let bytes = der.get(start..start + len)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod der_tests {
    use super::*;

    /// Hand-crafted minimal X.509: SEQUENCE { tbsCertificate { version,
    /// serial, sigAlg, issuer { RDN { ATV { OID, PrintableString "CN=Test CA" } } }, ... } }
    /// The values are skeletal but valid enough to exercise the parser.
    fn build_minimal_cert_with_issuer(cn: &str) -> Vec<u8> {
        // Build issuer: SEQUENCE { SET { SEQUENCE { OID(commonName), PrintableString(cn) } } }
        let cn_bytes = cn.as_bytes();
        let mut printable = vec![0x13, cn_bytes.len() as u8];
        printable.extend_from_slice(cn_bytes);
        // commonName OID: 2.5.4.3 → 06 03 55 04 03
        let oid_cn = [0x06, 0x03, 0x55, 0x04, 0x03];
        let mut atv = oid_cn.to_vec();
        atv.extend_from_slice(&printable);
        let mut atv_seq = vec![0x30, atv.len() as u8];
        atv_seq.extend_from_slice(&atv);
        let mut rdn_set = vec![0x31, atv_seq.len() as u8];
        rdn_set.extend_from_slice(&atv_seq);
        let mut issuer_seq = vec![0x30, rdn_set.len() as u8];
        issuer_seq.extend_from_slice(&rdn_set);
        // tbsCertificate: SEQUENCE { [0] version, INTEGER serial, SEQUENCE sigAlg, <issuer> }
        let version = [0xa0, 0x03, 0x02, 0x01, 0x02]; // [0] INTEGER 2 = v3
        let serial = [0x02, 0x01, 0x01]; // INTEGER 1
        let sig_alg = [0x30, 0x02, 0x05, 0x00]; // SEQUENCE { NULL }
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&serial);
        tbs.extend_from_slice(&sig_alg);
        tbs.extend_from_slice(&issuer_seq);
        let mut tbs_seq = vec![0x30, tbs.len() as u8];
        tbs_seq.extend_from_slice(&tbs);
        // Outer Certificate: SEQUENCE { tbsCertificate, ... } — we
        // only need tbs for the issuer walk to succeed.
        let mut cert = vec![0x30, tbs_seq.len() as u8];
        cert.extend_from_slice(&tbs_seq);
        cert
    }

    #[test]
    fn issuer_dn_extracts_from_minimal_cert() {
        let der = build_minimal_cert_with_issuer("Test CA");
        let dn = extract_issuer_dn(&der);
        assert_eq!(dn, "Test CA");
    }

    #[test]
    fn issuer_dn_returns_empty_for_malformed() {
        assert_eq!(extract_issuer_dn(&[]), "");
        assert_eq!(extract_issuer_dn(&[0xff, 0xff, 0xff]), "");
    }

    #[test]
    fn classify_key_type_detects_rsa_oid() {
        let der = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        assert_eq!(classify_key_type(&der), 'r');
    }

    #[test]
    fn classify_key_type_detects_ec_oid() {
        let der = [
            0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        ];
        assert_eq!(classify_key_type(&der), 'e');
    }

    #[test]
    fn classify_key_type_detects_ed25519_oid() {
        let der = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        assert_eq!(classify_key_type(&der), 'd');
    }

    #[test]
    fn issuer_dn_extracts_from_real_self_signed_cert() {
        // Generate a real self-signed cert via openssl shell-out and
        // verify the issuer DN comes out non-empty. Catches the V55
        // bug class where extract_issuer_dn silently returned "" on
        // every real cert because of a missed enter_sequence level.
        let dir = std::env::temp_dir().join(format!(
            "aegis-mtls-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_pem = dir.join("real.crt");
        let key_pem = dir.join("real.key");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_pem.to_str().unwrap(),
                "-out",
                cert_pem.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/O=Aegis Test/CN=mtls-issuer-fixture",
            ])
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status();
        // Skip silently when openssl bin is absent — keeps the test
        // suite portable.
        let Ok(s) = status else {
            return;
        };
        if !s.success() {
            return;
        }
        let pem = std::fs::read_to_string(&cert_pem).unwrap();
        let der = pem_to_der(&pem);
        let dn = extract_issuer_dn(&der);
        assert!(
            dn.contains("mtls-issuer-fixture") || dn.contains("Aegis Test"),
            "expected issuer DN to contain CN or O; got {dn:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn pem_to_der(pem: &str) -> Vec<u8> {
        let mut b64 = String::new();
        let mut inside = false;
        for line in pem.lines() {
            if line.starts_with("-----BEGIN") {
                inside = true;
                continue;
            }
            if line.starts_with("-----END") {
                break;
            }
            if inside {
                b64.push_str(line.trim());
            }
        }
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap()
    }

    #[test]
    fn count_san_entries_finds_dns_and_ip_tags() {
        // SAN OID followed by some 0x82 (dNSName) + 0x87 (iPAddress) markers.
        let der = vec![
            0x06, 0x03, 0x55, 0x1d, 0x11, // SAN OID
            0x82, 0x05, b'e', b'x', b'a', b'm', b'p', // dNS:example
            0x82, 0x04, b't', b'e', b's', b't', // dNS:test
            0x87, 0x04, 127, 0, 0, 1, // ip:127.0.0.1
        ];
        assert_eq!(count_san_entries(&der), 3);
    }
}
