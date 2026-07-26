//! Userspace loader for the Aegis XDP fast-path.
//!
//! Maps the platform-neutral `XdpHandle` trait onto an aya-loaded BPF
//! program on Linux (when the `xdp` Cargo feature is enabled). On any
//! other platform every operation is a no-op so the rest of the code
//! doesn't need to branch on `cfg(target_os)`.

use std::net::IpAddr;

use anyhow::Result;

/// Sentinel embedded in the error returned by `load` when the eBPF program
/// is already attached to the NIC by a sibling SO_REUSEPORT worker (XDP is
/// single-owner per NIC). The caller matches on this to log the condition
/// as informational (this worker filters in userspace) rather than as a
/// load failure. The owning worker enforces the kernel maps for all traffic.
pub const XDP_ALREADY_OWNED_MARKER: &str = "xdp-already-owned-by-sibling-worker";

/// Public, platform-neutral facade. Allow/deny APIs mutate BPF
/// HashMaps; `set_rate_config` writes the kernel rate limiter
/// parameters; `counters` returns aggregated per-action drop counts.
#[allow(dead_code)]
pub trait XdpHandle: Send + Sync {
    fn deny_v4(&self, ip: std::net::Ipv4Addr) -> Result<()>;
    fn deny_v6(&self, ip: std::net::Ipv6Addr) -> Result<()>;
    fn undeny(&self, ip: IpAddr) -> Result<()>;

    fn allow_v4(&self, ip: std::net::Ipv4Addr) -> Result<()>;
    fn allow_v6(&self, ip: std::net::Ipv6Addr) -> Result<()>;
    fn unallow(&self, ip: IpAddr) -> Result<()>;

    /// Configure the in-kernel rate limiter, SYN-flood guard, and
    /// allow-only mode in one shot. `window_ns == 0 || burst == 0`
    /// disables the corresponding limiter. `syn_burst == 0` disables
    /// the dedicated SYN guard (general rate limiter still applies).
    /// `allow_only` switches into whitelist mode.
    fn set_rate_config(
        &self,
        window_ns: u64,
        burst: u64,
        syn_burst: u64,
        allow_only: bool,
    ) -> Result<()>;

    fn counters(&self) -> Result<XdpCounters>;

    /// Look up the JA4T SYN-capture for `(src_ip, src_port)`. Returns
    /// `Ok(Some(...))` when the BPF program saw a SYN with this
    /// 4-tuple and the entry is still in the map, `Ok(None)` for any
    /// "no capture" case (XDP off, IPv6, eviction). Never errors —
    /// callers treat absence as "fall back to TCP_INFO".
    fn read_ja4t_v4(&self, src_ip: std::net::Ipv4Addr, src_port: u16) -> Option<Ja4tCapture> {
        let _ = (src_ip, src_port);
        None
    }

    /// Sweep entries whose `captured_at_ns` is older than `max_age_ns`.
    /// The BPF program never evicts itself; userspace pages out old
    /// SYNs so the map doesn't fill with dead 4-tuples from port-scan
    /// bursts. Returns the number of entries removed. No-op when XDP
    /// isn't loaded.
    fn evict_ja4t_v4(&self, _max_age_ns: u64) -> Result<usize> {
        Ok(0)
    }
}

/// User-facing copy of the on-wire SYN fingerprint. We keep this
/// `Vec`-flavoured rather than mirroring the fixed-size BPF struct so
/// the rest of the codebase doesn't pull in the xdp-common crate.
#[derive(Debug, Clone)]
pub struct Ja4tCapture {
    pub window: u16,
    pub mss: u16,
    /// 0xff = WSCALE option wasn't present.
    pub wscale: u8,
    /// TCP option kinds in arrival order.
    pub options: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XdpCounters {
    pub pass: u64,
    pub drop_deny: u64,
    pub drop_rate: u64,
    pub drop_allowonly: u64,
    pub drop_syn: u64,
    /// Phase 3X — packets dropped by the inline kernel WAF because
    /// their HTTP request line matched a known scanner path prefix.
    /// These never reach userspace; serving them through XDP is
    /// effectively free (line rate).
    pub drop_waf: u64,
    /// Phase A.1 — packets that hit the allow-list and skipped every
    /// downstream check (deny / rate / SYN guard / WAF). Distinct from
    /// `pass` so operators can read the share of trusted-bypass
    /// traffic without subtracting other PASS sources. Sum of per-CPU
    /// counters; uncontended at the eBPF write side.
    pub fast_pass: u64,
}

pub struct NoopXdp;

impl XdpHandle for NoopXdp {
    fn deny_v4(&self, _: std::net::Ipv4Addr) -> Result<()> {
        Ok(())
    }
    fn deny_v6(&self, _: std::net::Ipv6Addr) -> Result<()> {
        Ok(())
    }
    fn undeny(&self, _: IpAddr) -> Result<()> {
        Ok(())
    }
    fn allow_v4(&self, _: std::net::Ipv4Addr) -> Result<()> {
        Ok(())
    }
    fn allow_v6(&self, _: std::net::Ipv6Addr) -> Result<()> {
        Ok(())
    }
    fn unallow(&self, _: IpAddr) -> Result<()> {
        Ok(())
    }
    fn set_rate_config(&self, _: u64, _: u64, _: u64, _: bool) -> Result<()> {
        Ok(())
    }
    fn counters(&self) -> Result<XdpCounters> {
        Ok(XdpCounters::default())
    }
}

/// Try to load the XDP program and attach it to `iface`. On non-Linux
/// platforms or when the `xdp` feature is disabled, returns `NoopXdp`.
pub fn load(_iface: &str, _bpf_obj: &std::path::Path) -> Result<Box<dyn XdpHandle>> {
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    {
        return linux::load_impl(_iface, _bpf_obj).map(|h| Box::new(h) as Box<dyn XdpHandle>);
    }
    #[cfg(not(all(target_os = "linux", feature = "xdp")))]
    {
        tracing::warn!(
            "XDP fast-path not available on this build (need target_os=linux + `xdp` feature)"
        );
        Ok(Box::new(NoopXdp))
    }
}

#[cfg(all(target_os = "linux", feature = "xdp"))]
mod linux {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::Path,
        sync::{Arc, Mutex},
    };

    use anyhow::{Context, Result};
    use aya::{
        Ebpf,
        maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray},
        programs::{Xdp, XdpFlags},
    };

    /// True when an attach error is EEXIST ("File exists") — i.e. a sibling
    /// worker already attached the program to this NIC. Walks the error
    /// source chain so we catch the io::Error regardless of wrapper depth.
    fn is_already_attached(err: &(dyn std::error::Error + 'static)) -> bool {
        let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
        while let Some(e) = cur {
            if let Some(io) = e.downcast_ref::<std::io::Error>() {
                if io.raw_os_error() == Some(17) {
                    return true;
                }
            }
            let s = e.to_string();
            if s.contains("File exists") || s.contains("os error 17") {
                return true;
            }
            cur = e.source();
        }
        false
    }

    use aegis_xdp_common::{
        Ja4tKey, Ja4tSynFingerprint, RateBucket, counter_idx, maps, rate_cfg_idx,
    };

    use super::{Ja4tCapture, XdpCounters, XdpHandle};

    pub struct LinuxXdp {
        // Held to keep the program loaded; dropping unloads it.
        _ebpf: Arc<Mutex<Ebpf>>,
        deny_v4: Arc<Mutex<BpfHashMap<MapData, u32, u8>>>,
        deny_v6: Arc<Mutex<BpfHashMap<MapData, [u8; 16], u8>>>,
        allow_v4: Arc<Mutex<BpfHashMap<MapData, u32, u8>>>,
        allow_v6: Arc<Mutex<BpfHashMap<MapData, [u8; 16], u8>>>,
        _rate_v4: Arc<Mutex<BpfHashMap<MapData, u32, RateBucket>>>,
        counters: Arc<Mutex<PerCpuArray<MapData, u64>>>,
        rate_cfg: Arc<Mutex<Array<MapData, u64>>>,
        ja4t_v4: Arc<Mutex<BpfHashMap<MapData, Ja4tKey, Ja4tSynFingerprint>>>,
        /// Cached value of `bpf_ktime_get_ns()` at load time, used to
        /// translate the kernel monotonic clock the BPF program
        /// stamps into something userspace can compare against
        /// `Instant::now`-style ages. Read via the kernel's
        /// `/proc/sys/kernel/random/boot_id`-adjacent clock —
        /// approximated below.
        loaded_at_ktime_ns: u64,
    }

    pub fn load_impl(iface: &str, bpf_obj: &Path) -> Result<LinuxXdp> {
        let mut ebpf = Ebpf::load_file(bpf_obj)
            .with_context(|| format!("failed to load XDP object at {}", bpf_obj.display()))?;

        let program: &mut Xdp = ebpf
            .program_mut("aegis_xdp")
            .context("BPF object is missing `aegis_xdp` program section")?
            .try_into()
            .context("loaded program is not an XDP program")?;
        program
            .load()
            .context("failed to load XDP program into kernel")?;
        // Phase A.1 — try native (DRV) mode first for line-rate
        // performance; fall back to SKB (generic) mode if the NIC's
        // driver can't host XDP natively. SKB mode is slower (packets
        // are reinjected after sk_buff allocation) but works on every
        // Linux NIC including virtio-net under hypervisors. Without
        // this fallback, deployments on cloud VMs without native
        // XDP support silently skip the kernel fast-path.
        // A NIC hosts exactly one XDP program, so with N SO_REUSEPORT worker
        // processes only one wins the attach; the rest get EEXIST. We surface
        // that as a distinct, recognisable error so the caller can log it as
        // an informational single-owner condition (this worker then filters
        // in userspace) rather than a scary failure. The owning worker's
        // program enforces the deny/allow maps at the NIC for ALL traffic.
        let attach_native = program.attach(iface, XdpFlags::default());
        if let Err(native_err) = attach_native {
            if is_already_attached(&native_err) {
                return Err(anyhow::anyhow!(super::XDP_ALREADY_OWNED_MARKER));
            }
            tracing::warn!(
                iface = %iface,
                error = %native_err,
                "XDP native attach failed, retrying in SKB (generic) mode"
            );
            match program.attach(iface, XdpFlags::SKB_MODE) {
                Ok(_) => tracing::info!(iface = %iface, "XDP attached in SKB mode"),
                Err(skb_err) if is_already_attached(&skb_err) => {
                    return Err(anyhow::anyhow!(super::XDP_ALREADY_OWNED_MARKER));
                }
                Err(skb_err) => {
                    return Err(anyhow::anyhow!(
                        "failed to attach XDP program to {iface} (tried both DRV and SKB modes): {skb_err}"
                    ));
                }
            }
        }

        let deny_v4: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(ebpf.take_map(maps::DENY_V4).context("DENY_V4 missing")?)?;
        let deny_v6: BpfHashMap<_, [u8; 16], u8> =
            BpfHashMap::try_from(ebpf.take_map(maps::DENY_V6).context("DENY_V6 missing")?)?;
        let allow_v4: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(ebpf.take_map(maps::ALLOW_V4).context("ALLOW_V4 missing")?)?;
        let allow_v6: BpfHashMap<_, [u8; 16], u8> =
            BpfHashMap::try_from(ebpf.take_map(maps::ALLOW_V6).context("ALLOW_V6 missing")?)?;
        let rate_v4: BpfHashMap<_, u32, RateBucket> =
            BpfHashMap::try_from(ebpf.take_map(maps::RATE_V4).context("RATE_V4 missing")?)?;
        let counters: PerCpuArray<_, u64> =
            PerCpuArray::try_from(ebpf.take_map(maps::COUNTERS).context("COUNTERS missing")?)?;
        let rate_cfg: Array<_, u64> =
            Array::try_from(ebpf.take_map(maps::RATE_CFG).context("RATE_CFG missing")?)?;
        let ja4t_v4: BpfHashMap<_, Ja4tKey, Ja4tSynFingerprint> =
            BpfHashMap::try_from(ebpf.take_map(maps::JA4T_V4).context("JA4T_V4 missing")?)?;

        tracing::info!(iface = %iface, "XDP fast-path attached");

        Ok(LinuxXdp {
            _ebpf: Arc::new(Mutex::new(ebpf)),
            deny_v4: Arc::new(Mutex::new(deny_v4)),
            deny_v6: Arc::new(Mutex::new(deny_v6)),
            allow_v4: Arc::new(Mutex::new(allow_v4)),
            allow_v6: Arc::new(Mutex::new(allow_v6)),
            _rate_v4: Arc::new(Mutex::new(rate_v4)),
            counters: Arc::new(Mutex::new(counters)),
            rate_cfg: Arc::new(Mutex::new(rate_cfg)),
            ja4t_v4: Arc::new(Mutex::new(ja4t_v4)),
            loaded_at_ktime_ns: read_ktime_ns(),
        })
    }

    /// Read CLOCK_MONOTONIC in ns — that's what `bpf_ktime_get_ns`
    /// reports inside the kernel, so we can compare timestamps the
    /// BPF program stamped without further translation.
    fn read_ktime_ns() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: timespec is a POD destination; CLOCK_MONOTONIC is
        // valid on every Linux we target.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        if rc != 0 {
            return 0;
        }
        (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
    }

    impl XdpHandle for LinuxXdp {
        fn deny_v4(&self, ip: Ipv4Addr) -> Result<()> {
            let key = u32::from(ip).to_be();
            self.deny_v4.lock().unwrap().insert(key, 1u8, 0)?;
            Ok(())
        }

        fn deny_v6(&self, ip: Ipv6Addr) -> Result<()> {
            let key = ip.octets();
            self.deny_v6.lock().unwrap().insert(key, 1u8, 0)?;
            Ok(())
        }

        fn undeny(&self, ip: IpAddr) -> Result<()> {
            match ip {
                IpAddr::V4(v4) => {
                    let key = u32::from(v4).to_be();
                    let _ = self.deny_v4.lock().unwrap().remove(&key);
                }
                IpAddr::V6(v6) => {
                    let key = v6.octets();
                    let _ = self.deny_v6.lock().unwrap().remove(&key);
                }
            }
            Ok(())
        }

        fn allow_v4(&self, ip: Ipv4Addr) -> Result<()> {
            let key = u32::from(ip).to_be();
            self.allow_v4.lock().unwrap().insert(key, 1u8, 0)?;
            Ok(())
        }

        fn allow_v6(&self, ip: Ipv6Addr) -> Result<()> {
            let key = ip.octets();
            self.allow_v6.lock().unwrap().insert(key, 1u8, 0)?;
            Ok(())
        }

        fn unallow(&self, ip: IpAddr) -> Result<()> {
            match ip {
                IpAddr::V4(v4) => {
                    let key = u32::from(v4).to_be();
                    let _ = self.allow_v4.lock().unwrap().remove(&key);
                }
                IpAddr::V6(v6) => {
                    let key = v6.octets();
                    let _ = self.allow_v6.lock().unwrap().remove(&key);
                }
            }
            Ok(())
        }

        fn set_rate_config(
            &self,
            window_ns: u64,
            burst: u64,
            syn_burst: u64,
            allow_only: bool,
        ) -> Result<()> {
            let mut cfg = self.rate_cfg.lock().unwrap();
            cfg.set(rate_cfg_idx::WINDOW_NS, window_ns, 0)?;
            cfg.set(rate_cfg_idx::BURST, burst, 0)?;
            cfg.set(rate_cfg_idx::ALLOW_ONLY, u64::from(allow_only), 0)?;
            cfg.set(rate_cfg_idx::SYN_BURST, syn_burst, 0)?;
            Ok(())
        }

        fn counters(&self) -> Result<XdpCounters> {
            let c = self.counters.lock().unwrap();
            // PerCpuArray::get returns one value per CPU — sum to get
            // the global counter. The aya `PerCpuValues` derefs to a
            // `[V]`, so `iter().copied().sum()` works directly.
            let sum = |idx: u32| -> u64 {
                c.get(&idx, 0)
                    .map(|vals| vals.iter().copied().sum::<u64>())
                    .unwrap_or(0)
            };
            Ok(XdpCounters {
                pass: sum(counter_idx::PASS),
                drop_deny: sum(counter_idx::DROP_DENY),
                drop_rate: sum(counter_idx::DROP_RATE),
                drop_allowonly: sum(counter_idx::DROP_ALLOWONLY),
                drop_syn: sum(counter_idx::DROP_SYN),
                drop_waf: sum(counter_idx::DROP_WAF),
                fast_pass: sum(counter_idx::FAST_PASS),
            })
        }

        fn read_ja4t_v4(&self, src_ip: Ipv4Addr, src_port: u16) -> Option<Ja4tCapture> {
            let key = Ja4tKey {
                src_ip_be: u32::from(src_ip).to_be(),
                src_port_be: src_port.to_be(),
                _pad: 0,
            };
            let fp = self.ja4t_v4.lock().ok()?.get(&key, 0).ok()?;
            // Convert fixed-size options buffer back to a Vec — only
            // the first `options_count` entries are meaningful.
            let n = (fp.options_count as usize).min(fp.options.len());
            let options = fp.options[..n].to_vec();
            Some(Ja4tCapture {
                window: fp.window,
                mss: fp.mss,
                wscale: fp.wscale,
                options,
            })
        }

        fn evict_ja4t_v4(&self, max_age_ns: u64) -> Result<usize> {
            let now = read_ktime_ns();
            let cutoff = now.saturating_sub(max_age_ns);
            let mut victims: Vec<Ja4tKey> = Vec::new();
            {
                let map = self.ja4t_v4.lock().unwrap();
                // `iter` yields (Result<Key>, Result<Value>) — best
                // effort: skip rows we can't read.
                for kv in map.iter() {
                    let Ok((k, v)) = kv else { continue };
                    if v.captured_at_ns < cutoff {
                        victims.push(k);
                    }
                }
            }
            let removed = {
                let mut map = self.ja4t_v4.lock().unwrap();
                let mut n = 0;
                for k in &victims {
                    if map.remove(k).is_ok() {
                        n += 1;
                    }
                }
                n
            };
            // Suppress unused-field warning when this code path is
            // exercised only on the real Linux build.
            let _ = self.loaded_at_ktime_ns;
            Ok(removed)
        }
    }
}

/// Mirror an `IpAclFilter`-style deny list into the XDP deny map.
/// Returns the number of entries successfully programmed.
pub fn sync_deny_list(handle: &dyn XdpHandle, deny: &[IpAddr]) -> usize {
    let mut programmed = 0;
    for ip in deny {
        let result = match ip {
            IpAddr::V4(v4) => handle.deny_v4(*v4),
            IpAddr::V6(v6) => handle.deny_v6(*v6),
        };
        match result {
            Ok(()) => programmed += 1,
            Err(e) => tracing::warn!(error = %e, %ip, "failed to insert into XDP deny map"),
        }
    }
    programmed
}

/// Same shape as `sync_deny_list` but targets the ALLOW maps.
pub fn sync_allow_list(handle: &dyn XdpHandle, allow: &[IpAddr]) -> usize {
    let mut programmed = 0;
    for ip in allow {
        let result = match ip {
            IpAddr::V4(v4) => handle.allow_v4(*v4),
            IpAddr::V6(v6) => handle.allow_v6(*v6),
        };
        match result {
            Ok(()) => programmed += 1,
            Err(e) => tracing::warn!(error = %e, %ip, "failed to insert into XDP allow map"),
        }
    }
    programmed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::Ipv4Addr,
        sync::{Arc, Mutex},
    };

    #[test]
    fn noop_handle_zero_counters() {
        let h = NoopXdp;
        assert_eq!(h.counters().unwrap(), XdpCounters::default());
        h.deny_v4(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        h.allow_v4(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        h.unallow(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).unwrap();
        h.set_rate_config(1_000_000_000, 100, 50, true).unwrap();
    }

    #[test]
    fn sync_lists_with_noop() {
        let h = NoopXdp;
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        assert_eq!(sync_deny_list(&h, &ips), 2);
        assert_eq!(sync_allow_list(&h, &ips), 2);
    }

    /// Recording handle covers both deny and allow paths so we can
    /// verify Reloader-style reconciliation does the right thing.
    #[derive(Default)]
    struct RecordingHandle {
        denied: Mutex<Vec<IpAddr>>,
        allowed: Mutex<Vec<IpAddr>>,
        undenied: Mutex<Vec<IpAddr>>,
        unallowed: Mutex<Vec<IpAddr>>,
        rate_cfg: Mutex<Option<(u64, u64, u64, bool)>>,
    }

    impl XdpHandle for RecordingHandle {
        fn deny_v4(&self, ip: std::net::Ipv4Addr) -> Result<()> {
            self.denied.lock().unwrap().push(IpAddr::V4(ip));
            Ok(())
        }
        fn deny_v6(&self, ip: std::net::Ipv6Addr) -> Result<()> {
            self.denied.lock().unwrap().push(IpAddr::V6(ip));
            Ok(())
        }
        fn undeny(&self, ip: IpAddr) -> Result<()> {
            self.undenied.lock().unwrap().push(ip);
            Ok(())
        }
        fn allow_v4(&self, ip: std::net::Ipv4Addr) -> Result<()> {
            self.allowed.lock().unwrap().push(IpAddr::V4(ip));
            Ok(())
        }
        fn allow_v6(&self, ip: std::net::Ipv6Addr) -> Result<()> {
            self.allowed.lock().unwrap().push(IpAddr::V6(ip));
            Ok(())
        }
        fn unallow(&self, ip: IpAddr) -> Result<()> {
            self.unallowed.lock().unwrap().push(ip);
            Ok(())
        }
        fn set_rate_config(
            &self,
            window_ns: u64,
            burst: u64,
            syn_burst: u64,
            allow_only: bool,
        ) -> Result<()> {
            *self.rate_cfg.lock().unwrap() = Some((window_ns, burst, syn_burst, allow_only));
            Ok(())
        }
        fn counters(&self) -> Result<XdpCounters> {
            Ok(XdpCounters::default())
        }
    }

    #[test]
    fn allow_list_diff_reconciles() {
        let h = Arc::new(RecordingHandle::default());
        let a: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let b: Vec<IpAddr> = vec!["10.0.0.2".parse().unwrap(), "10.0.0.3".parse().unwrap()];
        sync_allow_list(&*h, &a);

        let prev: std::collections::HashSet<IpAddr> = a.into_iter().collect();
        let next: std::collections::HashSet<IpAddr> = b.into_iter().collect();
        for r in prev.difference(&next) {
            h.unallow(*r).unwrap();
        }
        let added: Vec<IpAddr> = next.difference(&prev).copied().collect();
        sync_allow_list(&*h, &added);

        assert_eq!(h.allowed.lock().unwrap().len(), 3);
        assert_eq!(h.unallowed.lock().unwrap().len(), 1);
    }

    #[test]
    fn set_rate_config_stores_values() {
        let h = RecordingHandle::default();
        h.set_rate_config(1_000_000_000, 50, 25, true).unwrap();
        assert_eq!(
            *h.rate_cfg.lock().unwrap(),
            Some((1_000_000_000u64, 50u64, 25u64, true))
        );
    }
}
