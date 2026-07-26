use anyhow::Result;
use tracing_subscriber::{EnvFilter, fmt};

/// Initialize structured tracing logs.
// V230 — env-gate the JSON formatter (AEGIS_LOG_JSON=1) so the default uses the
// compact text formatter; JSON formatting is ~3-5x slower than compact on the
// hot path, so it is opt-in for log-aggregation deployments only.
pub fn init_logging(level: &str) -> Result<()> {
    let env = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("warn"));
    let use_json = std::env::var("AEGIS_LOG_JSON")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let builder = fmt().with_env_filter(env).with_target(false);
    if use_json {
        builder
            .json()
            .try_init()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    } else {
        builder
            .compact()
            .try_init()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    }
    Ok(())
}
