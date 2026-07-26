//! V155 — p0f-style passive OS / TCP-stack fingerprinting.
//!
//! JA4T (in `src/ja4.rs`) captures TCP SYN options but stops at
//! emitting the wire-shape hash. p0f (Marshall Beddoe / Michał
//! Zalewski, 2005) goes one step further: it classifies that wire
//! shape into a likely OS family (Linux 2.6, Windows 10, macOS,
//! iOS, Android) using a fingerprint database of known TCP-stack
//! defaults.
//!
//! Why both? JA4T tells you "two clients are the same TCP stack";
//! p0f tells you "this client claims to be Chrome on Windows in
//! its UA but its TCP stack is Linux", which is a strong proxy /
//! sandbox / scraper signal. The Rust `huginn-net` crate ships a
//! full p0f port; V155 ships a focused minimal subset that:
//!
//!   * Takes the SYN observations Aegis already captures (window
//!     size, MSS, window scale, options ordering) via [Ja4tSyn].
//!   * Reconstructs a p0f-style signature string.
//!   * Matches it against a small built-in database of canonical
//!     OS stacks.
//!   * Surfaces the result so [crate::fp_correlation] can flag
//!     UA-vs-stack disagreement (e.g., "Windows 10 UA but Linux
//!     TCP stack").
//!
//! The DB is intentionally small — operators with a richer p0f.fp
//! drop it in via [OsDatabase::load_file]. We don't bundle the full
//! p0f corpus because it adds 50KB to the binary and 99% of operators
//! only need the modern desktop / mobile clusters.

use std::collections::HashMap;

/// SYN-side observations the classifier consumes. Already captured
/// by `src/tcp_info.rs::capture_with_xdp` (eBPF preferred) and the
/// userspace TCP_INFO fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ja4tSyn {
    pub window: u16,
    pub mss: u16,
    pub wscale: u8,
    /// First-hop TTL the SYN landed at. p0f famously uses TTL as
    /// the primary OS divider: Linux defaults to 64, Windows to
    /// 128, BSD/macOS to 64, old Solaris to 255.
    pub ttl: u8,
    /// Option kinds in wire order (e.g., MSS=2, NOP=1, WSCALE=3,
    /// SACKOK=4, TS=8). Stored as up to 8 bytes; trailing zeros mean
    /// "no more options". p0f calls this the "olayout".
    pub options: [u8; 8],
}

impl Ja4tSyn {
    pub fn olayout_string(&self) -> String {
        let opts: Vec<String> = self
            .options
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| b.to_string())
            .collect();
        opts.join("-")
    }

    /// Build a p0f-style signature line for this SYN:
    ///   `<ttl>:<window>:<mss>:<wscale>:<olayout>`
    /// (The full p0f format has more fields — IP version, DF flag,
    /// quirks, payload class — we omit them to keep the matcher
    /// tight on the parts Aegis actually captures reliably.)
    pub fn signature(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            ttl_bucket(self.ttl),
            self.window,
            self.mss,
            self.wscale,
            self.olayout_string(),
        )
    }
}

/// p0f's first divider — round TTL to the nearest power-of-two-style
/// bucket because the value Aegis sees has been decremented by hops.
/// The bucket recovers the original SYN's TTL from the observed one:
/// 0..=32 → 32, 33..=64 → 64, 65..=128 → 128, 129.. → 255.
pub fn ttl_bucket(observed: u8) -> u8 {
    match observed {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

/// Coarse OS classification. Bucket fits the V137 fingerprint
/// correlator's needs (cross-check vs UA-claimed OS); finer-grained
/// (Linux 2.6 vs 3.10 vs 5.4) is rarely actionable for a security
/// proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsFamily {
    Linux,
    Windows,
    Macos,
    Bsd,
    Ios,
    Android,
    Unknown,
}

impl OsFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Bsd => "bsd",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Unknown => "unknown",
        }
    }
}

/// Static signature database. Keyed by p0f signature string; value
/// is the OS family that ships with that TCP stack default.
///
/// Built-in entries cover the modern desktop + mobile clusters as
/// of 2024. Sources: p0f-3.09b's p0f.fp, FoxIO JA4 cookbook
/// observations, and Wireshark capture comparisons across real
/// devices.
pub struct OsDatabase {
    entries: HashMap<String, OsFamily>,
}

impl Default for OsDatabase {
    fn default() -> Self {
        let mut entries: HashMap<String, OsFamily> = HashMap::new();
        // Format: ttl_bucket:window:mss:wscale:olayout

        // Linux 5.x+ desktop (most distros): TTL 64, win 64240 or
        // 65535, MSS 1460, wscale 7, options M-S-T-N-W (2,4,8,1,3).
        entries.insert("64:64240:1460:7:2-4-8-1-3".into(), OsFamily::Linux);
        entries.insert("64:65535:1460:7:2-4-8-1-3".into(), OsFamily::Linux);
        entries.insert("64:29200:1460:7:2-4-8-1-3".into(), OsFamily::Linux);

        // Windows 10 / 11: TTL 128, win 65535, MSS 1460, wscale 8,
        // options M-N-W-N-N-T-S (2,1,3,1,1,8,4).
        entries.insert("128:65535:1460:8:2-1-3-1-1-8-4".into(), OsFamily::Windows);
        entries.insert("128:64240:1460:8:2-1-3-1-1-8-4".into(), OsFamily::Windows);

        // macOS 13+ / Ventura+: TTL 64, win 65535, MSS 1460, wscale 6,
        // options M-N-W-N-N-T-S-E-O-O (Apple-specific MPTCP-aware
        // ordering with EOL padding). We match the common short form.
        entries.insert("64:65535:1460:6:2-1-3-1-1-8-4".into(), OsFamily::Macos);

        // iOS 16+: TTL 64, win 65535, MSS 1460, wscale 7. Similar
        // shape to macOS but historically wscale=7 vs 6.
        entries.insert("64:65535:1460:7:2-1-3-1-1-8-4".into(), OsFamily::Ios);

        // Android 12+: TTL 64, win 65535, MSS 1460, wscale 9 (newer
        // kernel default), options M-S-T-N-W like generic Linux but
        // higher wscale.
        entries.insert("64:65535:1460:9:2-4-8-1-3".into(), OsFamily::Android);
        entries.insert("64:65535:1460:8:2-4-8-1-3".into(), OsFamily::Android);

        // FreeBSD / pfSense: TTL 64, win 65535, MSS 1460, wscale 6,
        // options M-N-W-S-T (2,1,3,4,8) — distinctive ordering vs
        // Linux's M-S-T-N-W.
        entries.insert("64:65535:1460:6:2-1-3-4-8".into(), OsFamily::Bsd);

        Self { entries }
    }
}

impl OsDatabase {
    /// Construct empty (for tests / fully custom DBs).
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Load entries from a text file. Each line is
    /// `<signature> <os_family>`; comments (`#`) and blank lines
    /// ignored. Family names are case-insensitive.
    pub fn load_str(&mut self, contents: &str) -> usize {
        let mut added = 0;
        for raw in contents.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(sig), Some(os)) = (parts.next(), parts.next()) else {
                continue;
            };
            let fam = match os.to_ascii_lowercase().as_str() {
                "linux" => OsFamily::Linux,
                "windows" => OsFamily::Windows,
                "macos" | "mac" => OsFamily::Macos,
                "bsd" | "freebsd" => OsFamily::Bsd,
                "ios" => OsFamily::Ios,
                "android" => OsFamily::Android,
                // Skip unknown families — silent acceptance would
                // pollute the DB with noise from malformed lines.
                _ => continue,
            };
            self.entries.insert(sig.to_string(), fam);
            added += 1;
        }
        added
    }

    /// Match a signature to a family. Exact-match only; fuzzy
    /// matching (wildcards on window size, etc.) is out of scope —
    /// operators with richer needs vendor huginn-net or run p0f
    /// alongside Aegis and feed its verdict.
    pub fn classify(&self, sig: &str) -> OsFamily {
        self.entries.get(sig).copied().unwrap_or(OsFamily::Unknown)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One-stop classifier. Wraps a [Ja4tSyn] and an [OsDatabase].
pub fn classify_syn(syn: &Ja4tSyn, db: &OsDatabase) -> OsFamily {
    db.classify(&syn.signature())
}

/// V155 bridge into V137 fp_correlation: derive the OS family the
/// UA claims, so the correlator can fire on mismatches. Returns
/// `OsFamily::Unknown` when the UA shape doesn't resolve to a known
/// platform (curl, custom tools).
pub fn ua_os_family(ua: &str) -> OsFamily {
    let u = ua.to_ascii_lowercase();
    if u.contains("iphone") || u.contains("ipad") {
        return OsFamily::Ios;
    }
    if u.contains("android") {
        return OsFamily::Android;
    }
    if u.contains("windows") {
        return OsFamily::Windows;
    }
    if u.contains("mac os") || u.contains("macintosh") {
        return OsFamily::Macos;
    }
    if u.contains("linux") {
        return OsFamily::Linux;
    }
    if u.contains("freebsd") || u.contains("openbsd") {
        return OsFamily::Bsd;
    }
    OsFamily::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn(ttl: u8, win: u16, mss: u16, wscale: u8, opts: &[u8]) -> Ja4tSyn {
        let mut options = [0u8; 8];
        for (i, b) in opts.iter().take(8).enumerate() {
            options[i] = *b;
        }
        Ja4tSyn {
            ttl,
            window: win,
            mss,
            wscale,
            options,
        }
    }

    #[test]
    fn ttl_bucket_recovers_original() {
        assert_eq!(ttl_bucket(30), 32);
        assert_eq!(ttl_bucket(60), 64);
        assert_eq!(ttl_bucket(120), 128);
        assert_eq!(ttl_bucket(250), 255);
        assert_eq!(ttl_bucket(0), 32);
    }

    #[test]
    fn olayout_string_drops_trailing_zeros() {
        let s = syn(64, 65535, 1460, 7, &[2, 4, 8, 1, 3]);
        assert_eq!(s.olayout_string(), "2-4-8-1-3");
    }

    #[test]
    fn olayout_string_empty_when_no_options() {
        let s = syn(64, 65535, 1460, 7, &[]);
        assert_eq!(s.olayout_string(), "");
    }

    #[test]
    fn signature_format_matches_p0f_subset() {
        let s = syn(64, 64240, 1460, 7, &[2, 4, 8, 1, 3]);
        assert_eq!(s.signature(), "64:64240:1460:7:2-4-8-1-3");
    }

    #[test]
    fn default_db_classifies_linux_5x() {
        let db = OsDatabase::default();
        let s = syn(60, 64240, 1460, 7, &[2, 4, 8, 1, 3]);
        assert_eq!(classify_syn(&s, &db), OsFamily::Linux);
    }

    #[test]
    fn default_db_classifies_windows_10() {
        let db = OsDatabase::default();
        // Observed TTL after 8 hops → 120. Bucket to 128.
        let s = syn(120, 65535, 1460, 8, &[2, 1, 3, 1, 1, 8, 4]);
        assert_eq!(classify_syn(&s, &db), OsFamily::Windows);
    }

    #[test]
    fn default_db_classifies_macos() {
        let db = OsDatabase::default();
        let s = syn(64, 65535, 1460, 6, &[2, 1, 3, 1, 1, 8, 4]);
        assert_eq!(classify_syn(&s, &db), OsFamily::Macos);
    }

    #[test]
    fn default_db_classifies_ios() {
        let db = OsDatabase::default();
        let s = syn(64, 65535, 1460, 7, &[2, 1, 3, 1, 1, 8, 4]);
        assert_eq!(classify_syn(&s, &db), OsFamily::Ios);
    }

    #[test]
    fn default_db_classifies_android() {
        let db = OsDatabase::default();
        let s = syn(64, 65535, 1460, 9, &[2, 4, 8, 1, 3]);
        assert_eq!(classify_syn(&s, &db), OsFamily::Android);
    }

    #[test]
    fn default_db_classifies_freebsd() {
        let db = OsDatabase::default();
        let s = syn(64, 65535, 1460, 6, &[2, 1, 3, 4, 8]);
        assert_eq!(classify_syn(&s, &db), OsFamily::Bsd);
    }

    #[test]
    fn unknown_signature_returns_unknown() {
        let db = OsDatabase::default();
        let s = syn(64, 1234, 5678, 0, &[9, 9, 9]);
        assert_eq!(classify_syn(&s, &db), OsFamily::Unknown);
    }

    #[test]
    fn empty_db_classifies_nothing() {
        let db = OsDatabase::empty();
        let s = syn(64, 64240, 1460, 7, &[2, 4, 8, 1, 3]);
        assert_eq!(classify_syn(&s, &db), OsFamily::Unknown);
    }

    #[test]
    fn load_str_adds_custom_entries() {
        let mut db = OsDatabase::empty();
        let n = db.load_str(
            "\
# custom test corpus
64:99:99:9:1-2-3  linux
128:99:99:9:1-2-3  Windows
malformed line
0:0:0:0:0  ios
",
        );
        assert_eq!(n, 3);
        assert_eq!(db.classify("64:99:99:9:1-2-3"), OsFamily::Linux);
        assert_eq!(db.classify("128:99:99:9:1-2-3"), OsFamily::Windows);
        assert_eq!(db.classify("0:0:0:0:0"), OsFamily::Ios);
    }

    #[test]
    fn load_str_ignores_comments_and_blanks() {
        let mut db = OsDatabase::empty();
        db.load_str(
            "\
# header
\n\n
64:1:1:1:1 linux  # trailing comment
",
        );
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn ua_os_family_recognises_major_uas() {
        assert_eq!(
            ua_os_family("Mozilla/5.0 (Windows NT 10.0)"),
            OsFamily::Windows
        );
        assert_eq!(
            ua_os_family("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0)"),
            OsFamily::Macos
        );
        assert_eq!(
            ua_os_family("Mozilla/5.0 (X11; Linux x86_64)"),
            OsFamily::Linux
        );
        assert_eq!(
            ua_os_family("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
            OsFamily::Ios
        );
        assert_eq!(
            ua_os_family("Mozilla/5.0 (Linux; Android 14)"),
            OsFamily::Android
        );
        assert_eq!(ua_os_family("Mozilla/5.0 (FreeBSD)"), OsFamily::Bsd);
        assert_eq!(ua_os_family("curl/8.0"), OsFamily::Unknown);
    }

    #[test]
    fn ua_ios_check_wins_over_macos_string() {
        // iOS UAs literally contain "Mac OS X" (heritage); we must
        // detect iPhone/iPad first.
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)";
        assert_eq!(ua_os_family(ua), OsFamily::Ios);
    }

    #[test]
    fn os_family_as_str_round_trip() {
        for f in [
            OsFamily::Linux,
            OsFamily::Windows,
            OsFamily::Macos,
            OsFamily::Bsd,
            OsFamily::Ios,
            OsFamily::Android,
            OsFamily::Unknown,
        ] {
            assert!(!f.as_str().is_empty());
        }
    }
}
