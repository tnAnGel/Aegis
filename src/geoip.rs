//! GeoIP country lookup backed by a MaxMind .mmdb file.
//!
//! The free GeoLite2-Country database from MaxMind maps every routable
//! IPv4/IPv6 address to an ISO 3166-1 alpha-2 country code. Aegis uses
//! that mapping for two things:
//!
//! 1. Static deny list — drop traffic from countries you never serve.
//! 2. Attack-mode deny — only enforce the list when the anomaly detector
//!    flags the upstream as under attack, so legit minority-country
//!    traffic isn't punished during peacetime.
//!
//! The mmdb is mmap-loaded once at startup; lookups are zero-alloc.
//! Failed loads log a warning and fall through to a no-op handle — the
//! proxy keeps serving traffic if MaxMind data is missing or stale.

use std::{net::IpAddr, sync::Arc};

use anyhow::{Context, Result};
use maxminddb::{Reader, geoip2};

// Use the maxminddb-shipped geoip2 schema; it implements zero-copy
// `Deserialize` correctly across maxminddb's internal lifetime, which
// our hand-rolled struct couldn't (the borrow checker refused
// `'de: 'a` on a #[derive] without a bound on the impl).
type CountryRecord<'a> = geoip2::Country<'a>;
type AsnRecord<'a> = geoip2::Asn<'a>;

/// Platform-neutral facade — Linux, macOS, missing-database all share
/// the same call sites.
pub trait GeoIpLookup: Send + Sync {
    /// Return the ISO 3166-1 alpha-2 country code (uppercase) for `ip`,
    /// or None if the database doesn't have a mapping (private range,
    /// unallocated block, missing db).
    fn country(&self, ip: IpAddr) -> Option<String>;

    /// V144 — return the autonomous-system number (AS number) the IP
    /// is announced from, when an ASN database is loaded. Default
    /// impl returns None so existing impls don't need changes.
    /// Consumed by the V142 ASN reputation feed via the
    /// [GeoIpAsnLookup] adapter below.
    fn asn(&self, _ip: IpAddr) -> Option<u32> {
        None
    }
}

#[derive(Default)]
pub struct NoopGeoIp;

impl GeoIpLookup for NoopGeoIp {
    fn country(&self, _: IpAddr) -> Option<String> {
        None
    }
}

pub struct MaxMindGeoIp {
    reader: Arc<Reader<Vec<u8>>>,
    /// V144 — optional ASN database (GeoLite2-ASN). When set,
    /// [asn] returns the AS number for the given IP. Loaded
    /// separately because MaxMind ships country and ASN as
    /// two distinct .mmdb files.
    asn_reader: Option<Arc<Reader<Vec<u8>>>>,
}

impl MaxMindGeoIp {
    pub fn open(path: &str) -> Result<Self> {
        let reader = Reader::open_readfile(path)
            .with_context(|| format!("failed to open GeoIP database at {path}"))?;
        Ok(Self {
            reader: Arc::new(reader),
            asn_reader: None,
        })
    }

    /// V144 — attach a GeoLite2-ASN database. Returns Err if the file
    /// can't be opened (caller decides whether to fail-open or hard
    /// fail). Operator typically calls this right after [open].
    pub fn with_asn(mut self, path: &str) -> Result<Self> {
        let r = Reader::open_readfile(path)
            .with_context(|| format!("failed to open ASN database at {path}"))?;
        self.asn_reader = Some(Arc::new(r));
        Ok(self)
    }
}

impl GeoIpLookup for MaxMindGeoIp {
    fn country(&self, ip: IpAddr) -> Option<String> {
        let rec: CountryRecord = self.reader.lookup(ip).ok()?;
        rec.country
            .and_then(|c| c.iso_code)
            .map(|s| s.to_ascii_uppercase())
    }
    fn asn(&self, ip: IpAddr) -> Option<u32> {
        let r = self.asn_reader.as_ref()?;
        let rec: AsnRecord = r.lookup(ip).ok()?;
        rec.autonomous_system_number
    }
}

/// V144 — adapter that exposes a [GeoIpLookup]'s ASN method as the
/// [crate::asn_reputation::AsnLookup] trait so the V142 reputation
/// feed can use the same MaxMind database the proxy already opened.
///
/// Use:
///
///     let geoip: Arc<dyn GeoIpLookup> = ...; // already loaded
///     let asn_lookup = Arc::new(GeoIpAsnLookup::new(geoip.clone()));
///     let asn_rep = AsnReputation::new(paths, asn_lookup);
pub struct GeoIpAsnLookup {
    geoip: Arc<dyn GeoIpLookup>,
}

impl GeoIpAsnLookup {
    pub fn new(geoip: Arc<dyn GeoIpLookup>) -> Self {
        Self { geoip }
    }
}

impl crate::asn_reputation::AsnLookup for GeoIpAsnLookup {
    fn asn(&self, ip: IpAddr) -> Option<u32> {
        self.geoip.asn(ip)
    }
}

/// Build a `GeoIpLookup` from configuration. Missing path or load
/// failure produces a `NoopGeoIp` plus a warning log — never aborts
/// server startup.
pub fn load(path: Option<&str>) -> Arc<dyn GeoIpLookup> {
    load_with_asn(path, None)
}

/// Candidate locations for the bundled country database, in priority
/// order. Lets Aegis ship a working GeoIP out of the box: the repo
/// bundles a db-ip "IP to Country Lite" mmdb (CC-BY-4.0), install.sh
/// copies it to /var/lib/aegis/geoip, and this resolver finds it even
/// when no `[geoip] db_path` is configured. The update endpoint writes
/// the refreshed file to the same /var/lib location, which wins.
pub const BUNDLED_COUNTRY_DB_NAME: &str = "dbip-country-lite.mmdb";

pub fn default_country_db_path() -> Option<String> {
    const DIRS: [&str; 4] = [
        "/var/lib/aegis/geoip",
        "/etc/aegis/geoip",
        "/usr/local/src/aegis/data/geoip",
        "data/geoip",
    ];
    DIRS.iter()
        .map(|d| format!("{d}/{BUNDLED_COUNTRY_DB_NAME}"))
        .find(|p| std::path::Path::new(p).exists())
}

/// Resolve the country DB path the proxy should load: explicit config
/// wins, then the `AEGIS_GEOIP_PATH` env override, then the bundled
/// default. Returns None only when nothing is configured AND no bundled
/// file is present (→ NoopGeoIp).
pub fn resolve_country_db_path(configured: Option<&str>) -> Option<String> {
    if let Some(p) = configured
        && !p.is_empty()
    {
        return Some(p.to_string());
    }
    if let Ok(p) = std::env::var("AEGIS_GEOIP_PATH")
        && !p.is_empty()
    {
        return Some(p);
    }
    default_country_db_path()
}

/// V244 — bundled/seeded ASN database name (db-ip "IP to ASN Lite",
/// CC BY 4.0). install.sh + the feed-refresh job fetch it here.
pub const BUNDLED_ASN_DB_NAME: &str = "dbip-asn-lite.mmdb";

pub fn default_asn_db_path() -> Option<String> {
    const DIRS: [&str; 4] = [
        "/var/lib/aegis/geoip",
        "/etc/aegis/geoip",
        "/usr/local/src/aegis/data/geoip",
        "data/geoip",
    ];
    DIRS.iter()
        .map(|d| format!("{d}/{BUNDLED_ASN_DB_NAME}"))
        .find(|p| std::path::Path::new(p).exists())
}

/// V244 — resolve the ASN DB path the proxy should load: explicit config
/// wins, then the `AEGIS_ASN_PATH` env override, then the bundled/seeded
/// default. Mirrors [resolve_country_db_path] so AS-keyed reputation works
/// out of the box (the DSL config path leaves `cfg.geoip` as None). Returns
/// None only when nothing is configured AND no seeded file is present.
pub fn resolve_asn_db_path(configured: Option<&str>) -> Option<String> {
    if let Some(p) = configured
        && !p.is_empty()
    {
        return Some(p.to_string());
    }
    if let Ok(p) = std::env::var("AEGIS_ASN_PATH")
        && !p.is_empty()
    {
        return Some(p);
    }
    default_asn_db_path()
}

/// V144 — load both country and ASN databases. Either path can be
/// None / empty / missing without aborting startup; degraded
/// capabilities log a warning. The resulting handle's [GeoIpLookup::asn]
/// returns Some only when the ASN db loaded successfully.
pub fn load_with_asn(country_path: Option<&str>, asn_path: Option<&str>) -> Arc<dyn GeoIpLookup> {
    let country = match country_path {
        Some(p) if !p.is_empty() => Some(p),
        _ => None,
    };
    let asn = match asn_path {
        Some(p) if !p.is_empty() => Some(p),
        _ => None,
    };

    let Some(country) = country else {
        // No country DB. If only ASN was given, we still want to be
        // able to answer asn() — build a country-less Noop wrapper.
        if let Some(asn_path) = asn {
            if let Ok(asn_only) = AsnOnlyGeoIp::open(asn_path) {
                tracing::info!(path = asn_path, "GeoIP ASN-only database loaded");
                return Arc::new(asn_only);
            }
        }
        return Arc::new(NoopGeoIp);
    };

    match MaxMindGeoIp::open(country) {
        Ok(db) => {
            let db = match asn {
                Some(asn_path) => match db.with_asn(asn_path) {
                    Ok(d) => {
                        tracing::info!(
                            country_path = country,
                            asn_path,
                            "GeoIP country + ASN databases loaded"
                        );
                        d
                    }
                    Err(e) => {
                        tracing::warn!(
                            country_path = country,
                            asn_path,
                            error = %e,
                            "GeoIP ASN database unavailable; ASN reputation will only match CIDR entries"
                        );
                        MaxMindGeoIp::open(country).unwrap()
                    }
                },
                None => {
                    tracing::info!(path = country, "GeoIP country database loaded");
                    db
                }
            };
            Arc::new(db)
        }
        Err(e) => {
            tracing::warn!(path = country, error = %e, "GeoIP database unavailable; geo deny list ignored");
            Arc::new(NoopGeoIp)
        }
    }
}

/// V144 — ASN-only GeoIP handle for deployments that have an ASN
/// database but no country database. country() returns None; asn()
/// answers from the ASN reader.
pub struct AsnOnlyGeoIp {
    asn_reader: Arc<Reader<Vec<u8>>>,
}

impl AsnOnlyGeoIp {
    pub fn open(path: &str) -> Result<Self> {
        let r = Reader::open_readfile(path)
            .with_context(|| format!("failed to open ASN database at {path}"))?;
        Ok(Self {
            asn_reader: Arc::new(r),
        })
    }
}

impl GeoIpLookup for AsnOnlyGeoIp {
    fn country(&self, _: IpAddr) -> Option<String> {
        None
    }
    fn asn(&self, ip: IpAddr) -> Option<u32> {
        let rec: AsnRecord = self.asn_reader.lookup(ip).ok()?;
        rec.autonomous_system_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_returns_none() {
        let g = NoopGeoIp;
        assert!(g.country("1.1.1.1".parse().unwrap()).is_none());
        assert!(g.country("::1".parse().unwrap()).is_none());
    }

    #[test]
    fn missing_path_falls_through_to_noop() {
        let g = load(Some("/nonexistent.mmdb"));
        assert!(g.country("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn empty_path_falls_through_to_noop() {
        let g = load(Some(""));
        assert!(g.country("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn none_path_falls_through_to_noop() {
        let g = load(None);
        assert!(g.country("8.8.8.8".parse().unwrap()).is_none());
    }

    // ── V144 — ASN integration tests ──────────────────────────────

    #[test]
    fn default_asn_impl_returns_none() {
        // Trait default: any GeoIpLookup that doesn't override asn()
        // gives None. NoopGeoIp uses the default.
        let g = NoopGeoIp;
        assert!(g.asn("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn load_with_asn_missing_both_falls_through() {
        let g = load_with_asn(None, None);
        assert!(g.country("1.2.3.4".parse().unwrap()).is_none());
        assert!(g.asn("1.2.3.4".parse().unwrap()).is_none());
    }

    #[test]
    fn load_with_asn_missing_asn_keeps_country_path() {
        // We can't actually verify country lookup without a real .mmdb,
        // but we can verify the loader doesn't panic and returns a handle.
        let g = load_with_asn(
            Some("/nonexistent-country.mmdb"),
            Some("/nonexistent-asn.mmdb"),
        );
        assert!(g.country("8.8.8.8".parse().unwrap()).is_none());
        assert!(g.asn("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn geoip_asn_lookup_adapter_delegates() {
        use crate::asn_reputation::AsnLookup;
        struct FakeGeoIp;
        impl GeoIpLookup for FakeGeoIp {
            fn country(&self, _: IpAddr) -> Option<String> {
                None
            }
            fn asn(&self, _: IpAddr) -> Option<u32> {
                Some(13335)
            }
        }
        let g: Arc<dyn GeoIpLookup> = Arc::new(FakeGeoIp);
        let a = GeoIpAsnLookup::new(g);
        assert_eq!(a.asn("1.1.1.1".parse().unwrap()), Some(13335));
    }

    #[test]
    fn asn_only_handle_falls_through_country() {
        // Without a real DB we can only check the error path: opening
        // a nonexistent file returns Err, the load_with_asn() wrapper
        // returns NoopGeoIp.
        let r = AsnOnlyGeoIp::open("/nonexistent-asn.mmdb");
        assert!(r.is_err());
    }
}
