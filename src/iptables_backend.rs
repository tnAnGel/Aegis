//! V130 — iptables backend (4th-tier fallback, Synapse parity).
//!
//! Completes the XDP → nftables → iptables → userspace fallback chain.
//! iptables is the pre-nftables Linux firewall (since 1998), still
//! shipped on legacy / embedded / minimal-container systems. Modern
//! distros default to nftables (≥3.13) so this tier only fires when
//! BOTH XDP and nftables are unavailable.
//!
//! Implementation mirrors V128 [nftables_backend]: implements
//! [XdpHandle] so it drops into the existing pipeline as a peer of
//! NoopXdp / NftablesXdp without touching the rest of the codebase.
//!
//! Per-deny / undeny shells out to `iptables -I AEGIS-DENY -s <ip>
//! -j DROP` / `iptables -D AEGIS-DENY -s <ip> -j DROP`. Two chains
//! (AEGIS-DENY-V4 in iptables, AEGIS-DENY-V6 in ip6tables) are jumped
//! to from INPUT.
//!
//! Counters parsed from `iptables -L AEGIS-DENY -nvx --line-numbers`.
//!
//! V130 is feature-complete but DOES NOT auto-install. Operator
//! explicitly opts in via `AEGIS_FW_BACKEND=iptables` or the
//! fallback chain in `open_with_fallback()`.

use std::{net::IpAddr, process::Command};

use anyhow::{Context, Result, anyhow};

use crate::xdp::{XdpCounters, XdpHandle};

pub struct IptablesXdp {
    chain_v4: String,
    chain_v6: String,
}

impl IptablesXdp {
    pub fn open() -> Result<Self> {
        Self::open_named("AEGIS-DENY-V4", "AEGIS-DENY-V6")
    }

    pub fn open_named(chain_v4: impl Into<String>, chain_v6: impl Into<String>) -> Result<Self> {
        let h = Self {
            chain_v4: chain_v4.into(),
            chain_v6: chain_v6.into(),
        };
        h.ensure_chain(false)?;
        h.ensure_chain(true)?;
        Ok(h)
    }

    fn iptables_bin(&self, v6: bool) -> &'static str {
        if v6 { "ip6tables" } else { "iptables" }
    }

    fn run(&self, v6: bool, args: &[&str]) -> Result<String> {
        let bin = self.iptables_bin(v6);
        let out = Command::new(bin)
            .args(args)
            .output()
            .with_context(|| format!("spawn {bin}"))?;
        if !out.status.success() {
            return Err(anyhow!(
                "{} {} failed: {}",
                bin,
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn chain(&self, v6: bool) -> &str {
        if v6 { &self.chain_v6 } else { &self.chain_v4 }
    }

    /// Idempotently create the chain + INPUT jump.
    fn ensure_chain(&self, v6: bool) -> Result<()> {
        let chain = self.chain(v6).to_string();
        // -N creates a chain; returns error if exists. Suppress that.
        let _ = self.run(v6, &["-N", &chain]);
        // -C checks; if absent (return non-zero), we insert the jump.
        let check = self.run(v6, &["-C", "INPUT", "-j", &chain]);
        if check.is_err() {
            self.run(v6, &["-I", "INPUT", "1", "-j", &chain])?;
        }
        Ok(())
    }

    fn add_deny(&self, v6: bool, ip: &str) -> Result<()> {
        let chain = self.chain(v6).to_string();
        // -C first to dedupe; only -I if absent.
        let check = self.run(v6, &["-C", &chain, "-s", ip, "-j", "DROP"]);
        if check.is_err() {
            self.run(v6, &["-I", &chain, "1", "-s", ip, "-j", "DROP"])?;
        }
        Ok(())
    }

    fn remove_deny(&self, v6: bool, ip: &str) -> Result<()> {
        let chain = self.chain(v6).to_string();
        // -D may need to repeat if multiple rules exist; iptables -D
        // removes ONE match. Single-shot is fine for our shape.
        self.run(v6, &["-D", &chain, "-s", ip, "-j", "DROP"])?;
        Ok(())
    }

    /// Parse `iptables -L <chain> -nvx` packet counters. Output:
    ///
    ///   Chain AEGIS-DENY-V4 (1 references)
    ///       pkts      bytes target     prot opt in     out     source   ...
    ///         42       2940 DROP       all  --  *      *       1.2.3.4  ...
    ///
    /// We sum the first numeric column across all rules.
    fn sum_counters(&self, v6: bool) -> u64 {
        let chain = self.chain(v6).to_string();
        let raw = match self.run(v6, &["-L", &chain, "-nvx"]) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let mut total = 0u64;
        for line in raw.lines().skip(2) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // First whitespace-separated token is the packet count.
            if let Some(first) = trimmed.split_whitespace().next()
                && let Ok(n) = first.parse::<u64>()
            {
                total = total.saturating_add(n);
            }
        }
        total
    }
}

impl XdpHandle for IptablesXdp {
    fn deny_v4(&self, ip: std::net::Ipv4Addr) -> Result<()> {
        self.add_deny(false, &ip.to_string())
    }
    fn deny_v6(&self, ip: std::net::Ipv6Addr) -> Result<()> {
        self.add_deny(true, &ip.to_string())
    }
    fn undeny(&self, ip: IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(v4) => self.remove_deny(false, &v4.to_string()),
            IpAddr::V6(v6) => self.remove_deny(true, &v6.to_string()),
        }
    }
    fn allow_v4(&self, _ip: std::net::Ipv4Addr) -> Result<()> {
        Err(anyhow!(
            "iptables backend: allow_v4 not implemented (deny-only)"
        ))
    }
    fn allow_v6(&self, _ip: std::net::Ipv6Addr) -> Result<()> {
        Err(anyhow!(
            "iptables backend: allow_v6 not implemented (deny-only)"
        ))
    }
    fn unallow(&self, _ip: IpAddr) -> Result<()> {
        Err(anyhow!(
            "iptables backend: unallow not implemented (deny-only)"
        ))
    }
    fn set_rate_config(
        &self,
        _window_ns: u64,
        _burst: u64,
        _syn_burst: u64,
        _allow_only: bool,
    ) -> Result<()> {
        // iptables has -m limit / -m hashlimit but per-IP shape
        // would require a different chain structure. Out of V130
        // scope; operator uses XDP for kernel rate limit or the
        // userspace RateLimitFilter.
        Err(anyhow!("iptables backend: set_rate_config not implemented"))
    }
    fn counters(&self) -> Result<XdpCounters> {
        Ok(XdpCounters {
            pass: 0,
            drop_deny: self.sum_counters(false) + self.sum_counters(true),
            drop_rate: 0,
            drop_allowonly: 0,
            drop_syn: 0,
            drop_waf: 0,
            fast_pass: 0,
        })
    }
}

/// V130 — full fallback chain: XDP → nftables → iptables → userspace.
/// V128 had XDP → nftables → userspace; this completes the picture.
///
/// Order:
///   1. nftables (V128) — modern Linux, default since 2014.
///   2. iptables (V130) — fallback for legacy / embedded.
///   3. NoopXdp — userspace-only IpAclFilter does the work.
///
/// eBPF XDP is wired in aegis-pingora.rs at a higher priority tier
/// ahead of nftables; this function is the post-XDP chain.
pub fn open_full_fallback() -> std::sync::Arc<dyn XdpHandle> {
    if let Ok(h) = crate::nftables_backend::NftablesXdp::open_default() {
        tracing::info!("firewall backend: nftables (inet table aegis)");
        return std::sync::Arc::new(h);
    }
    match IptablesXdp::open() {
        Ok(h) => {
            tracing::info!("firewall backend: iptables (legacy fallback)");
            std::sync::Arc::new(h)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "firewall backend: iptables unavailable too; userspace-only"
            );
            std::sync::Arc::new(crate::xdp::NoopXdp)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iptables_counter_output() {
        // Synthetic iptables -L -nvx output shape.
        let raw = "Chain AEGIS-DENY-V4 (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      42       2940 DROP       all  --  *      *       1.2.3.4              0.0.0.0/0
     100      10000 DROP       all  --  *      *       5.6.7.8              0.0.0.0/0
";
        let mut total = 0u64;
        for line in raw.lines().skip(2) {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(first) = t.split_whitespace().next()
                && let Ok(n) = first.parse::<u64>()
            {
                total += n;
            }
        }
        assert_eq!(total, 142);
    }

    #[test]
    fn iptables_not_on_path_returns_err() {
        let saved = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", "") };
        let r = IptablesXdp::open();
        if let Some(p) = saved {
            unsafe { std::env::set_var("PATH", p) };
        }
        assert!(r.is_err());
    }
}
