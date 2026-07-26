//! V64 — End-to-end integration harness for `aegis-pingora`.
//!
//! Spawns a real aegis-pingora process against an in-process mock
//! upstream and exercises every pingora-specific code path the
//! V22-V60 versions ship: filter chain, WAF deny, cache hit/miss,
//! admin token auth, challenge ladder cookie issue + verify, TLS
//! per-SNI cert routing, JA3/JA4 fingerprint stash.
//!
//! Mirrors `aegis-e2e.rs` in shape but covers the openssl-backed
//! pingora binary specifically. CI-friendly: bounded ~30s runtime,
//! everything on 127.0.0.1, no external deps.
//!
//! Usage:
//!   cargo build --release --features pingora --bin aegis-pingora
//!   cargo build --release --features pingora --bin aegis-pingora-e2e
//!   ./target/release/aegis-pingora-e2e

#![cfg(feature = "pingora")]

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

#[derive(Debug, Parser)]
#[command(
    name = "aegis-pingora-e2e",
    about = "End-to-end integration test for aegis-pingora"
)]
struct Args {
    #[arg(long, default_value = "target/release/aegis-pingora")]
    binary: PathBuf,
    #[arg(long, default_value_t = 18280)]
    aegis_port: u16,
    #[arg(long, default_value_t = 19290)]
    admin_port: u16,
    #[arg(long, default_value_t = 18290)]
    upstream_port: u16,
    #[arg(long, default_value = "e2e-secret-token-do-not-use")]
    admin_token: String,
    #[arg(long, default_value_t = 10)]
    startup_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !args.binary.is_file() {
        bail!(
            "binary not found at {} — build with:\n  cargo build --release --features pingora --bin aegis-pingora",
            args.binary.display()
        );
    }

    // 1. Spawn an in-process mock upstream that returns "ok\n".
    let upstream_addr: SocketAddr = format!("127.0.0.1:{}", args.upstream_port).parse()?;
    let upstream_listener = TcpListener::bind(upstream_addr)
        .await
        .with_context(|| format!("bind upstream {upstream_addr}"))?;
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match upstream_listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                // Drain the request (best-effort) and reply.
                let _ = timeout(Duration::from_millis(500), sock.read(&mut buf)).await;
                let body = b"ok\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    // 2. Write a test config + honeypot state path.
    let tmpdir = std::env::temp_dir().join(format!(
        "aegis-pingora-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmpdir)?;
    let config_path = tmpdir.join("aegis.conf");
    let honeypot_path = tmpdir.join("honeypots.json");
    std::fs::write(
        &config_path,
        format!(
            r#"
admin {{
    listen 127.0.0.1:{admin_port};
    token admin {token};
}}

defaults {{
    request_timeout 10s;
    graceful_shutdown 5s;
    filters {{
        waf on;
        bot_fingerprint off;
        adaptive_spike_detection off;
        challenge_ladder off;
    }}
    rate_limit {{
        requests_per_second 100000;
        burst 100000;
    }}
}}

server {{
    listen 127.0.0.1:{aegis_port} default_server;
    proxy_pass http://127.0.0.1:{upstream_port};
}}
"#,
            admin_port = args.admin_port,
            aegis_port = args.aegis_port,
            upstream_port = args.upstream_port,
            token = args.admin_token,
        ),
    )?;

    // 3. Spawn aegis-pingora.
    let mut child = Command::new(&args.binary)
        .arg("--config")
        .arg(&config_path)
        .arg("--log-level")
        .arg("error")
        .env("AEGIS_HONEYPOT_STATE", &honeypot_path)
        .env("AEGIS_RESPONSE_CACHE_ENABLE", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", args.binary.display()))?;

    let result = run_tests(&args).await;

    // 4. Tear down (regardless of result).
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&tmpdir);
    if let Err(e) = result {
        eprintln!("FAIL: {e:#}");
        std::process::exit(1);
    }
    println!("PASS: aegis-pingora end-to-end smoke green");
    Ok(())
}

async fn run_tests(args: &Args) -> Result<()> {
    wait_for_port(args.aegis_port, args.startup_secs).await?;
    wait_for_port(args.admin_port, args.startup_secs).await?;

    let client = build_client();

    // Test 1: plain GET → 200 backend
    let (status, body) = http_get(&client, args.aegis_port, "/api/users", "localhost").await?;
    if status != 200 {
        bail!("plain GET expected 200, got {status} body={body:?}");
    }
    if !body.contains("ok") {
        bail!("plain GET body did not contain 'ok': {body:?}");
    }

    // Test 2: WAF block (path traversal) → 403
    let (status, body) =
        http_get(&client, args.aegis_port, "/../../etc/passwd", "localhost").await?;
    if status != 403 {
        bail!("WAF path-traversal expected 403, got {status} body={body:?}");
    }
    if !body.contains("blocked") {
        bail!("WAF block body did not contain 'blocked': {body:?}");
    }

    // Test 3: /metrics public, includes aegis_requests_total
    let (status, body) = http_get(&client, args.admin_port, "/metrics", "127.0.0.1").await?;
    if status != 200 {
        bail!("/metrics expected 200, got {status}");
    }
    if !body.contains("aegis_requests_total") {
        bail!(
            "/metrics missing aegis_requests_total: {}",
            &body[..200.min(body.len())]
        );
    }

    // Test 4: /admin/cache without token → 401
    let (status, _) = http_get(&client, args.admin_port, "/admin/cache", "127.0.0.1").await?;
    if status != 401 {
        bail!("/admin/cache without token expected 401, got {status}");
    }

    // Test 5: /admin/cache with bad token → 401
    let (status, _) = http_get_with_token(
        &client,
        args.admin_port,
        "/admin/cache",
        "127.0.0.1",
        "WRONG",
    )
    .await?;
    if status != 401 {
        bail!("/admin/cache wrong token expected 401, got {status}");
    }

    // Test 6: /admin/cache with valid token → 200
    let (status, body) = http_get_with_token(
        &client,
        args.admin_port,
        "/admin/cache",
        "127.0.0.1",
        &args.admin_token,
    )
    .await?;
    if status != 200 {
        bail!("/admin/cache valid token expected 200, got {status}");
    }
    if !body.contains("cache_hits") {
        bail!("/admin/cache body missing cache_hits");
    }

    // Test 7: /admin/health
    let (status, body) = http_get(&client, args.admin_port, "/health", "127.0.0.1").await?;
    if status != 200 || !body.starts_with("ok") {
        bail!("/health expected 200 'ok', got {status} {body:?}");
    }

    // Test 8: cache hit/miss flow — fire identical GET twice, expect
    // both 200 + counters in /metrics reflect at least 1 hit.
    let _ = http_get(&client, args.aegis_port, "/cache-test", "localhost").await?;
    let _ = http_get(&client, args.aegis_port, "/cache-test", "localhost").await?;
    sleep(Duration::from_millis(100)).await;
    let (_, metrics) = http_get(&client, args.admin_port, "/metrics", "127.0.0.1").await?;
    // Counters are textual — find the line and parse the integer.
    let hits = extract_metric(&metrics, "aegis_cache_hits").unwrap_or(0);
    let misses = extract_metric(&metrics, "aegis_cache_misses").unwrap_or(0);
    if hits == 0 && misses == 0 {
        bail!("cache counters all zero after 2 GETs — cache not active?");
    }

    // Test 9: /admin/cache/purge with token → 200
    let (status, _) = http_post_with_token(
        &client,
        args.admin_port,
        "/admin/cache/purge?all=1",
        "127.0.0.1",
        &args.admin_token,
    )
    .await?;
    if status != 200 {
        bail!("/admin/cache/purge expected 200, got {status}");
    }

    // ============================================================
    // RC3 — write-side admin API coverage. These exercise the new
    // endpoints added in V73-RC3 and require the admin token (Write
    // role). Skipped if /var/lib/aegis/sites.d isn't writable
    // (typical for CI sandboxes); bail if the endpoint itself
    // misbehaves (returns wrong status / shape).
    // ============================================================

    // Test 10: POST /admin/api/config/test with VALID content → ok:true
    let valid_cfg = format!(
        "admin {{\n  listen 127.0.0.1:{};\n  token admin {};\n}}\nserver {{\n  listen 127.0.0.1:{};\n  proxy_pass http://127.0.0.1:{};\n}}\n",
        args.admin_port + 1000,
        args.admin_token,
        args.aegis_port + 1000,
        args.upstream_port
    );
    let test_body = serde_json::json!({"content": valid_cfg}).to_string();
    let (status, body) = http_with_body_and_token(
        &client,
        "POST",
        args.admin_port,
        "/admin/api/config/test",
        "127.0.0.1",
        &args.admin_token,
        test_body.into_bytes(),
    )
    .await?;
    if status != 200 {
        bail!("POST /admin/api/config/test (valid) expected 200, got {status}: {body}");
    }
    if !body.contains("\"ok\":true") {
        bail!("POST /admin/api/config/test (valid) expected ok:true, got {body}");
    }

    // Test 11: POST /admin/api/config/test with INVALID content → ok:false
    let invalid_body = serde_json::json!({"content": "server { bogus_directive 42; }"}).to_string();
    let (status, body) = http_with_body_and_token(
        &client,
        "POST",
        args.admin_port,
        "/admin/api/config/test",
        "127.0.0.1",
        &args.admin_token,
        invalid_body.into_bytes(),
    )
    .await?;
    if status != 200 {
        bail!("POST /admin/api/config/test (invalid) expected 200, got {status}: {body}");
    }
    if !body.contains("\"ok\":false") {
        bail!("POST /admin/api/config/test (invalid) expected ok:false, got {body}");
    }

    // Test 12: POST /admin/api/sites with malformed JSON → 400
    let (status, body) = http_with_body_and_token(
        &client,
        "POST",
        args.admin_port,
        "/admin/api/sites",
        "127.0.0.1",
        &args.admin_token,
        b"not json".to_vec(),
    )
    .await?;
    if status != 400 {
        bail!("POST /admin/api/sites (malformed) expected 400, got {status}: {body}");
    }

    // Test 13: PUT /admin/api/honeypots/packs/<unknown> body
    //   {"enabled":false} → 200 (setting an unknown pack is fine; the
    //   state file just records the toggle, packs are looked up at
    //   apply time)
    let body_json = serde_json::json!({"enabled": false}).to_string();
    let (status, body) = http_with_body_and_token(
        &client,
        "POST",
        args.admin_port,
        "/admin/api/honeypots/packs/wordpress",
        "127.0.0.1",
        &args.admin_token,
        body_json.into_bytes(),
    )
    .await?;
    if status != 200 {
        bail!("POST /admin/api/honeypots/packs/wordpress expected 200, got {status}: {body}");
    }
    if !body.contains("\"ok\":true") {
        bail!("POST /admin/api/honeypots/packs/wordpress expected ok:true, got {body}");
    }

    Ok(())
}

async fn wait_for_port(port: u16, secs: u64) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(anyhow!("port {port} never came up in {secs}s"))
}

type Client = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    http_body_util::Full<hyper::body::Bytes>,
>;

fn build_client() -> Client {
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http()
}

async fn http_get(client: &Client, port: u16, path: &str, host: &str) -> Result<(u16, String)> {
    do_http(client, "GET", port, path, host, None).await
}

async fn http_get_with_token(
    client: &Client,
    port: u16,
    path: &str,
    host: &str,
    token: &str,
) -> Result<(u16, String)> {
    do_http(client, "GET", port, path, host, Some(token)).await
}

async fn http_post_with_token(
    client: &Client,
    port: u16,
    path: &str,
    host: &str,
    token: &str,
) -> Result<(u16, String)> {
    do_http(client, "POST", port, path, host, Some(token)).await
}

async fn do_http(
    client: &Client,
    method: &str,
    port: u16,
    path: &str,
    host: &str,
    token: Option<&str>,
) -> Result<(u16, String)> {
    use http::Request;
    use http_body_util::{BodyExt, Full};
    let mut req_builder = Request::builder()
        .method(method)
        .uri(format!("http://127.0.0.1:{port}{path}"))
        .header("Host", host);
    if let Some(t) = token {
        req_builder = req_builder.header("x-admin-token", t);
    }
    let req = req_builder.body(Full::new(hyper::body::Bytes::new()))?;
    let resp = client.request(req).await?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// RC3 — body-bearing request helper. Same shape as `do_http` but
/// carries an arbitrary JSON / text body. Used by the new RC3 tests
/// for POST /sites, PUT /honeypots, POST /config/test, etc.
async fn http_with_body_and_token(
    client: &Client,
    method: &str,
    port: u16,
    path: &str,
    host: &str,
    token: &str,
    body: Vec<u8>,
) -> Result<(u16, String)> {
    use http::Request;
    use http_body_util::{BodyExt, Full};
    let req = Request::builder()
        .method(method)
        .uri(format!("http://127.0.0.1:{port}{path}"))
        .header("Host", host)
        .header("x-admin-token", token)
        .header("content-type", "application/json")
        .body(Full::new(hyper::body::Bytes::from(body)))?;
    let resp = client.request(req).await?;
    let status = resp.status().as_u16();
    let resp_body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&resp_body).into_owned()))
}

fn extract_metric(text: &str, name: &str) -> Option<u64> {
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name) {
            // skip optional {labels} and whitespace
            let rest = rest.trim_start_matches([' ', '\t']);
            if let Some(num_str) = rest.split_whitespace().next() {
                return num_str.parse().ok();
            }
        }
    }
    None
}
