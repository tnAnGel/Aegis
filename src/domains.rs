use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::time;

use crate::metrics::RuntimeMetrics;

const DOMAINS_FILE: &str = "config/domains.toml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainStats {
    pub total_requests: u64,
    pub denied_requests: u64,
    pub challenged_requests: u64,
    pub last_seen_unix: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainRegistry {
    #[serde(default)]
    pub domains: BTreeMap<String, DomainStats>,
}

impl DomainRegistry {
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path).context("failed to read domains registry")?;
        toml::from_str(&raw).context("failed to parse domains registry")
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        let raw = toml::to_string_pretty(self).context("failed to serialize domains registry")?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, raw).context("failed to write domains registry")
    }

    /// Merge live counters from `RuntimeMetrics` into the registry,
    /// replacing previous totals with the snapshot value.
    pub fn apply_runtime(&mut self, metrics: &RuntimeMetrics) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for kv in metrics.domain.iter() {
            let counter = kv.value();
            let entry = self.domains.entry(kv.key().clone()).or_default();
            entry.total_requests = counter.total.load(Ordering::Relaxed);
            entry.denied_requests = counter.denied.load(Ordering::Relaxed);
            entry.challenged_requests = counter.challenged.load(Ordering::Relaxed);
            entry.last_seen_unix = Some(now);
        }
    }
}

fn registry_path() -> PathBuf {
    PathBuf::from(DOMAINS_FILE)
}

fn load_registry() -> Result<DomainRegistry> {
    DomainRegistry::load_from(&registry_path())
}

fn save_registry(reg: &DomainRegistry) -> Result<()> {
    reg.save_to(&registry_path())
}

pub fn add_domain(domain: &str) -> Result<()> {
    let mut reg = load_registry()?;
    reg.domains.entry(domain.to_string()).or_default();
    save_registry(&reg)?;
    println!("Domain added: {domain}");
    Ok(())
}

pub fn remove_domain(domain: &str) -> Result<()> {
    let mut reg = load_registry()?;
    if reg.domains.remove(domain).is_some() {
        save_registry(&reg)?;
        println!("Domain removed: {domain}");
    } else {
        println!("Domain not found: {domain}");
    }
    Ok(())
}

pub fn list_domains() -> Result<()> {
    let reg = load_registry()?;
    if reg.domains.is_empty() {
        println!("No domains configured");
        return Ok(());
    }
    for name in reg.domains.keys() {
        println!("{name}");
    }
    Ok(())
}

pub fn stats_domain(domain: &str) -> Result<()> {
    let reg = load_registry()?;
    match reg.domains.get(domain) {
        Some(stats) => {
            println!("domain={domain}");
            println!("total_requests={}", stats.total_requests);
            println!("denied_requests={}", stats.denied_requests);
            println!("challenged_requests={}", stats.challenged_requests);
            println!(
                "last_seen_unix={}",
                stats
                    .last_seen_unix
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            );
            Ok(())
        }
        None => {
            println!("Domain not found: {domain}");
            Ok(())
        }
    }
}

pub fn metrics_summary() -> Result<String> {
    let reg = load_registry()?;
    let domains = reg.domains.len();
    let total: u64 = reg.domains.values().map(|v| v.total_requests).sum();
    let denied: u64 = reg.domains.values().map(|v| v.denied_requests).sum();
    Ok(format!(
        "domains={domains} total_requests={total} denied_requests={denied}"
    ))
}

/// Background loop that flushes runtime metrics into the on-disk registry.
///
/// Called once at server start; cancellable by aborting the JoinHandle.
pub fn spawn_persister(
    metrics: Arc<RuntimeMetrics>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = time::interval(interval);
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let path = registry_path();
            let mut reg = DomainRegistry::load_from(&path).unwrap_or_default();
            reg.apply_runtime(&metrics);
            if let Err(e) = reg.save_to(&path) {
                tracing::warn!(error = %e, "failed to persist domain registry");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::RuntimeMetrics;
    use std::sync::atomic::Ordering;

    #[test]
    fn apply_runtime_populates_entries() {
        let metrics = RuntimeMetrics::default();
        metrics.observe_domain_outcome("api.example.com", true, false);
        metrics.observe_domain_outcome("api.example.com", false, false);
        metrics.observe_domain_outcome("api.example.com", false, true);

        let mut reg = DomainRegistry::default();
        reg.apply_runtime(&metrics);

        let stats = reg.domains.get("api.example.com").expect("present");
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.denied_requests, 1);
        assert_eq!(stats.challenged_requests, 1);
        assert!(stats.last_seen_unix.is_some());
    }

    #[test]
    fn round_trip_save_load() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("aegis-domains-{}.toml", std::process::id()));
        let mut reg = DomainRegistry::default();
        reg.domains.insert(
            "foo".to_string(),
            DomainStats {
                total_requests: 7,
                denied_requests: 2,
                challenged_requests: 1,
                last_seen_unix: Some(123),
            },
        );
        reg.save_to(&path).unwrap();
        let loaded = DomainRegistry::load_from(&path).unwrap();
        assert_eq!(loaded.domains.get("foo").unwrap().total_requests, 7);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn counters_are_relaxed_loaded() {
        let metrics = RuntimeMetrics::default();
        metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.requests_total.load(Ordering::Relaxed), 1);
    }
}
