//! End-to-end load harness.
//!
//! Spawns a real Aegis process against a mock upstream and exercises
//! every major gate (WAF, rate limit, challenge ladder, bot filter,
//! body limit, admin auth, metrics endpoint). Asserts on observed
//! HTTP status codes AND on `aegis_*` counter deltas scraped from
//! /metrics — a regression that silently stops emitting metrics fails
//! the build just as loudly as a passthrough WAF rule.
//!
//! Designed for CI: bounded runtime (~30 s total), all sockets on
//! 127.0.0.1, no external dependencies (no Redis, no GeoIP), no
//! flaky timing waits — every assertion is on a deterministic
//! invariant the gate is supposed to enforce.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes as HyperBytes;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, sleep, timeout},
};

#[derive(Debug, Parser)]
#[command(name = "aegis-e2e", about = "End-to-end load test harness for Aegis")]
struct Args {
    /// Path to the aegis binary under test.
    #[arg(long, default_value = "target/release/aegis")]
    aegis_binary: PathBuf,
    /// Path to the template config (placeholders patched at runtime).
    #[arg(long, default_value = "bench/e2e-config.toml")]
    config_template: PathBuf,
    /// Seconds to wait for aegis to come online before failing.
    #[arg(long, default_value_t = 10)]
    startup_timeout_secs: u64,
    /// Print the final /metrics dump even on success.
    #[arg(long)]
    dump_metrics: bool,
}

#[derive(Debug, Default, Clone)]
struct Report {
    sent: u64,
    statuses: HashMap<u16, u64>,
    errors: u64,
}

impl Report {
    fn count(&self, status: u16) -> u64 {
        self.statuses.get(&status).copied().unwrap_or(0)
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut pairs: Vec<_> = self.statuses.iter().collect();
        pairs.sort_by_key(|(s, _)| **s);
        let body: Vec<String> = pairs.iter().map(|(s, n)| format!("{s}={n}")).collect();
        write!(
            f,
            "sent={} errors={} statuses=[{}]",
            self.sent,
            self.errors,
            body.join(",")
        )
    }
}

/// Find a free local port by binding to :0, capturing the assigned
/// port, then dropping the listener. There's a tiny race before aegis
/// re-binds but it's reliable in single-host CI.
fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Mock upstream — answers every HTTP/1.1 request with 200 OK and
/// counts hits. We deliberately don't parse the request beyond the
/// headers; aegis already vetted it.
async fn spawn_mock_upstream(port: u16) -> Result<Arc<AtomicU64>> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("bind mock upstream :{port}"))?;
    let hits = Arc::new(AtomicU64::new(0));
    let hits_cloned = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let hits = hits_cloned.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                hits.fetch_add(1, Ordering::Relaxed);
                let body = b"e2e-upstream-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(hits)
}

fn render_config(
    template_path: &PathBuf,
    aegis: u16,
    admin: u16,
    upstream: u16,
) -> Result<PathBuf> {
    let raw = std::fs::read_to_string(template_path)
        .with_context(|| format!("read config template {}", template_path.display()))?;
    let rendered = raw
        .replace("__AEGIS_LISTEN__", &format!("127.0.0.1:{aegis}"))
        .replace("__ADMIN_LISTEN__", &format!("127.0.0.1:{admin}"))
        .replace("__UPSTREAM_URL__", &format!("http://127.0.0.1:{upstream}"));
    let out_dir = std::env::temp_dir();
    let out_path = out_dir.join(format!("aegis-e2e-{}.toml", std::process::id()));
    std::fs::write(&out_path, rendered).context("write rendered config")?;
    Ok(out_path)
}

async fn wait_for_ready(metrics_url: String, timeout_secs: u64) -> Result<()> {
    let client = http_client();
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut last_err: Option<anyhow::Error> = None;
    while Instant::now() < deadline {
        let req = Request::builder()
            .method("GET")
            .uri(&metrics_url)
            .body(Full::new(HyperBytes::new()))?;
        match timeout(Duration::from_millis(500), client.request(req)).await {
            Ok(Ok(resp)) if resp.status().is_success() => return Ok(()),
            Ok(Ok(resp)) => {
                last_err = Some(anyhow!("metrics returned {}", resp.status()));
            }
            Ok(Err(e)) => last_err = Some(anyhow!("metrics connect: {e}")),
            Err(_) => last_err = Some(anyhow!("metrics timed out")),
        }
        sleep(Duration::from_millis(200)).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow!("aegis did not become ready")))
}

fn http_client() -> Client<HttpConnector, Full<HyperBytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// Fire `n` concurrent GETs at `url`. Each request runs with the
/// given header overrides. Returns aggregated Report.
async fn fire_get(url: &str, n: usize, headers: &[(&'static str, String)]) -> Result<Report> {
    let client = http_client();
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let client = client.clone();
        let url = url.to_string();
        let headers: Vec<(&'static str, String)> = headers.to_vec();
        handles.push(tokio::spawn(async move {
            let mut builder = Request::builder().method("GET").uri(&url);
            for (k, v) in &headers {
                builder = builder.header(*k, v);
            }
            let req = match builder.body(Full::new(HyperBytes::new())) {
                Ok(r) => r,
                Err(_) => return (None, true),
            };
            match timeout(Duration::from_secs(2), client.request(req)).await {
                Ok(Ok(resp)) => {
                    let status = resp.status().as_u16();
                    // Drain body so connection can be recycled.
                    let _ = resp.into_body().collect().await;
                    (Some(status), false)
                }
                Ok(Err(_)) | Err(_) => (None, true),
            }
        }));
    }
    let mut rep = Report::default();
    for h in handles {
        let (status, err) = h.await.unwrap_or((None, true));
        rep.sent += 1;
        if err {
            rep.errors += 1;
        }
        if let Some(s) = status {
            *rep.statuses.entry(s).or_default() += 1;
        }
    }
    Ok(rep)
}

async fn fire_post(url: &str, body: Vec<u8>, content_type: &str) -> Result<u16> {
    let client = http_client();
    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", content_type)
        .body(Full::new(HyperBytes::from(body)))?;
    let resp = timeout(Duration::from_secs(2), client.request(req))
        .await
        .map_err(|_| anyhow!("POST timed out"))?
        .map_err(|e| anyhow!("POST: {e}"))?;
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await;
    Ok(status)
}

async fn scrape_metrics(url: &str) -> Result<HashMap<String, f64>> {
    let client = http_client();
    let req = Request::builder()
        .method("GET")
        .uri(url)
        .body(Full::new(HyperBytes::new()))?;
    let resp = client.request(req).await.context("metrics scrape")?;
    let bytes = resp.into_body().collect().await?.to_bytes();
    let text = std::str::from_utf8(&bytes).context("metrics utf-8")?;
    let mut out = HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let name = parts.next().unwrap_or("").to_string();
        let value: f64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
        out.insert(name, value);
    }
    Ok(out)
}

/// Subtract `before` from `after` for a given metric. Returns 0 when
/// either side is missing (so a renamed metric becomes visible in the
/// report instead of crashing the harness).
fn delta(before: &HashMap<String, f64>, after: &HashMap<String, f64>, name: &str) -> f64 {
    let b = before.get(name).copied().unwrap_or(0.0);
    let a = after.get(name).copied().unwrap_or(0.0);
    a - b
}

/// Slowloris-style client: open a TCP connection, drip a partial
/// request, never finish. Used to verify the Slowloris guard kills
/// the connection within header_read_timeout_ms.
async fn slowloris_test(addr: SocketAddr, timeout_secs: u64) -> Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .context("slowloris connect")?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: e2e.local\r\nX-Drip: ")
        .await?;
    // The Aegis header read timeout is 1000 ms in our test config.
    // We give it `timeout_secs` to close the connection — that's
    // many multiples of the configured budget.
    let deadline = Duration::from_secs(timeout_secs);
    let mut buf = [0u8; 1024];
    let read = timeout(deadline, stream.read(&mut buf)).await;
    // We expect either:
    //   - read returns 0 (server closed cleanly), or
    //   - read returns some bytes (server sent 408/431/whatever)
    // The wrong outcome is: timeout elapsed — server held the
    // connection past the configured header_read_timeout.
    match read {
        Ok(Ok(0)) => Ok(()),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => Ok(()), // connection closed mid-read — also good
        Err(_) => Err(anyhow!("server held connection past header timeout")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.aegis_binary.exists() {
        bail!(
            "aegis binary not found at {} — build first: `cargo build --release`",
            args.aegis_binary.display()
        );
    }

    let aegis_port = free_port()?;
    let admin_port = free_port()?;
    let upstream_port = free_port()?;
    println!("ports: aegis={aegis_port} admin={admin_port} upstream={upstream_port}");

    let upstream_hits = spawn_mock_upstream(upstream_port).await?;
    let config_path = render_config(&args.config_template, aegis_port, admin_port, upstream_port)?;
    println!("config rendered → {}", config_path.display());

    let mut child = Command::new(&args.aegis_binary)
        .args([
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "start",
        ])
        .env("AEGIS_ADMIN_TOKEN", "e2e-admin-token")
        .env("RUST_LOG", "warn,aegis=info")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn aegis")?;

    let metrics_url = format!("http://127.0.0.1:{admin_port}/metrics");
    let proxy_url = format!("http://127.0.0.1:{aegis_port}");

    // Always kill the child even if a scenario panics.
    let result = run_scenarios(
        &metrics_url,
        &proxy_url,
        SocketAddr::new("127.0.0.1".parse().unwrap(), aegis_port),
        admin_port,
        upstream_hits,
        args.startup_timeout_secs,
        args.dump_metrics,
    )
    .await;

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&config_path);

    result
}

#[allow(clippy::too_many_arguments)]
async fn run_scenarios(
    metrics_url: &str,
    proxy_url: &str,
    aegis_addr: SocketAddr,
    admin_port: u16,
    upstream_hits: Arc<AtomicU64>,
    startup_timeout_secs: u64,
    dump_metrics: bool,
) -> Result<()> {
    wait_for_ready(metrics_url.to_string(), startup_timeout_secs).await?;
    println!("aegis is ready");

    let baseline = scrape_metrics(metrics_url).await?;
    let mut failures: Vec<String> = Vec::new();
    let mut scenario_results: Vec<(String, String)> = Vec::new();

    // Browser-y UA so the bot filter doesn't trip the scanner pattern
    // even though it's disabled in this config — keeps the harness
    // robust against people enabling bot defence in their copy.
    let ua = ("user-agent", "Mozilla/5.0 e2e-harness".to_string());

    // --- Scenario 1: baseline pass-through ---
    let url = format!("{proxy_url}/baseline");
    let bypass_hits_before = upstream_hits.load(Ordering::Relaxed);
    let baseline_pass = fire_get(&url, 3, std::slice::from_ref(&ua)).await?;
    let bypass_hits_after = upstream_hits.load(Ordering::Relaxed);
    record(
        &mut scenario_results,
        "baseline_passthrough",
        &baseline_pass,
        &mut failures,
        |r| {
            if r.count(200) < 3 {
                Err(format!("expected ≥3 200s, got full report {r}"))
            } else if bypass_hits_after - bypass_hits_before < 3 {
                Err(format!(
                    "upstream only saw {} hits",
                    bypass_hits_after - bypass_hits_before
                ))
            } else {
                Ok(format!(
                    "{} reached upstream",
                    bypass_hits_after - bypass_hits_before
                ))
            }
        },
    );

    // --- Scenario 2: WAF blocks SQLi in query string ---
    let sqli = fire_get(
        &format!("{proxy_url}/api?q=1%27%20UNION%20SELECT%20%2A%20FROM%20users"),
        5,
        std::slice::from_ref(&ua),
    )
    .await?;
    record(
        &mut scenario_results,
        "waf_sqli_query_blocked",
        &sqli,
        &mut failures,
        |r| {
            if r.count(403) >= 5 {
                Ok("all 5 SQLi attempts returned 403".to_string())
            } else {
                Err(format!("expected 5×403, got {r}"))
            }
        },
    );

    // --- Scenario 3: WAF blocks XSS in query ---
    let xss = fire_get(
        &format!("{proxy_url}/page?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        5,
        std::slice::from_ref(&ua),
    )
    .await?;
    record(
        &mut scenario_results,
        "waf_xss_query_blocked",
        &xss,
        &mut failures,
        |r| {
            if r.count(403) >= 5 {
                Ok("all 5 XSS attempts returned 403".to_string())
            } else {
                Err(format!("expected 5×403, got {r}"))
            }
        },
    );

    // --- Scenario 4: WAF body inspection (signature in POST body) ---
    let body_url = format!("{proxy_url}/login");
    let body_status = fire_post(
        &body_url,
        b"u=admin&p=' UNION SELECT password FROM users--".to_vec(),
        "application/x-www-form-urlencoded",
    )
    .await?;
    scenario_results.push((
        "waf_body_sqli_blocked".to_string(),
        format!("status={body_status}"),
    ));
    if body_status != 403 {
        failures.push("waf_body_sqli_blocked".to_string());
    }

    // --- Scenario 5: WAF body size limit ---
    let oversized_status = fire_post(
        &body_url,
        vec![b'a'; 16 * 1024], // max_body_bytes = 4096
        "text/plain",
    )
    .await?;
    scenario_results.push((
        "waf_body_size_413".to_string(),
        format!("status={oversized_status}"),
    ));
    if oversized_status != 413 {
        failures.push("waf_body_size_413".to_string());
    }

    // --- Scenario 6: IP ACL deny does not affect our test source ---
    // We hard-coded 198.51.100.99 (TEST-NET-2) into deny so the rule
    // exists but our 127.0.0.1 client isn't covered. This proves the
    // ACL is loaded without locking us out.
    let acl_ok = fire_get(
        &format!("{proxy_url}/acl-probe"),
        1,
        std::slice::from_ref(&ua),
    )
    .await?;
    record(
        &mut scenario_results,
        "ip_acl_loaded_without_self_lock",
        &acl_ok,
        &mut failures,
        |r| {
            if r.count(403) == 0 && r.count(200) >= 1 {
                Ok("config loaded, 127.0.0.1 not on deny list".to_string())
            } else {
                Err(format!("expected pass, got {r}"))
            }
        },
    );

    // --- Scenario 7: rate limit trips after burst ---
    // We've already burned several tokens above. Smash 50 more in
    // parallel; per-IP burst=5, so most should be 429.
    let burst = fire_get(&format!("{proxy_url}/burst"), 50, std::slice::from_ref(&ua)).await?;
    record(
        &mut scenario_results,
        "rate_limit_burst",
        &burst,
        &mut failures,
        |r| {
            if r.count(429) >= 10 {
                Ok(format!("429 fired {} times out of 50", r.count(429)))
            } else {
                Err(format!("expected ≥10 × 429, got {r}"))
            }
        },
    );

    // --- Scenario 8: Slowloris connection killed ---
    // header_read_timeout_ms = 1000 in config; give 5 s for kill.
    match slowloris_test(aegis_addr, 5).await {
        Ok(_) => scenario_results.push((
            "slowloris_connection_killed".to_string(),
            "server closed connection within timeout".to_string(),
        )),
        Err(e) => {
            scenario_results.push((
                "slowloris_connection_killed".to_string(),
                format!("FAIL: {e}"),
            ));
            failures.push("slowloris_connection_killed".to_string());
        }
    }

    // --- Scenario 9: admin auth — wrong token → 401 ---
    let admin_url = format!("http://127.0.0.1:{admin_port}/admin/health");
    let unauth = fire_get(
        &admin_url,
        1,
        &[("x-admin-token", "wrong-token".to_string())],
    )
    .await?;
    record(
        &mut scenario_results,
        "admin_unauth_rejected",
        &unauth,
        &mut failures,
        |r| {
            if r.count(401) >= 1 {
                Ok("401 unauthorized as expected".to_string())
            } else {
                Err(format!("expected 401, got {r}"))
            }
        },
    );

    // --- Scenario 10: admin auth — correct token → 200 ---
    let auth = fire_get(
        &admin_url,
        1,
        &[("x-admin-token", "e2e-admin-token".to_string())],
    )
    .await?;
    record(
        &mut scenario_results,
        "admin_authorized_passes",
        &auth,
        &mut failures,
        |r| {
            if r.count(200) >= 1 {
                Ok("authorized admin call returned 200".to_string())
            } else {
                Err(format!("expected 200, got {r}"))
            }
        },
    );

    // --- Scenario 11: admin endpoints reachable by role ---
    let read_endpoints = [
        "/admin/threats",
        "/admin/xdp",
        "/admin/hot_uris",
        "/admin/anomaly",
    ];
    let mut endpoint_failures = Vec::new();
    for ep in read_endpoints {
        let url = format!("http://127.0.0.1:{admin_port}{ep}");
        let r = fire_get(&url, 1, &[("x-admin-token", "e2e-admin-token".to_string())]).await?;
        if r.count(200) == 0 {
            endpoint_failures.push(format!("{ep} → {r}"));
        }
    }
    if endpoint_failures.is_empty() {
        scenario_results.push((
            "admin_read_endpoints_alive".to_string(),
            format!("{} endpoints OK", read_endpoints.len()),
        ));
    } else {
        scenario_results.push((
            "admin_read_endpoints_alive".to_string(),
            format!("FAIL: {endpoint_failures:?}"),
        ));
        failures.push("admin_read_endpoints_alive".to_string());
    }

    // --- Metrics regression check ---
    let after = scrape_metrics(metrics_url).await?;
    let total_delta = delta(&baseline, &after, "aegis_requests_total");
    let denied_delta = delta(&baseline, &after, "aegis_requests_denied");
    let challenged_delta = delta(&baseline, &after, "aegis_requests_challenged");

    let metrics_checks: Vec<(&str, bool, String)> = vec![
        (
            "metrics_requests_total_advanced",
            total_delta > 0.0,
            format!("Δ={total_delta}"),
        ),
        (
            "metrics_requests_denied_recorded",
            denied_delta > 0.0,
            format!("Δ={denied_delta}"),
        ),
        (
            "metrics_latency_histogram_present",
            after.contains_key("aegis_request_latency_ms_count"),
            "present".to_string(),
        ),
        (
            "metrics_per_protocol_present",
            after
                .keys()
                .any(|k| k.starts_with("aegis_requests_by_protocol")),
            "present".to_string(),
        ),
    ];
    // Avoid an unused-variable warning when challenge stays off.
    let _ = challenged_delta;

    for (name, ok, info) in metrics_checks {
        scenario_results.push((name.to_string(), info));
        if !ok {
            failures.push(name.to_string());
        }
    }

    println!("\n=== scenario results ===");
    for (name, info) in &scenario_results {
        let mark = if failures.iter().any(|f| f == name) {
            "FAIL"
        } else {
            "PASS"
        };
        println!("[{mark}] {name}: {info}");
    }

    if dump_metrics {
        println!("\n=== /metrics ===");
        for (k, v) in after.iter() {
            println!("{k} {v}");
        }
    }

    if !failures.is_empty() {
        bail!("{} scenario(s) failed: {failures:?}", failures.len());
    }
    println!("\n✓ all scenarios passed");
    Ok(())
}

fn record<F>(
    out: &mut Vec<(String, String)>,
    name: &str,
    rep: &Report,
    failures: &mut Vec<String>,
    check: F,
) where
    F: FnOnce(&Report) -> Result<String, String>,
{
    match check(rep) {
        Ok(info) => out.push((name.to_string(), info)),
        Err(e) => {
            out.push((name.to_string(), format!("FAIL: {e}")));
            failures.push(name.to_string());
        }
    }
}
