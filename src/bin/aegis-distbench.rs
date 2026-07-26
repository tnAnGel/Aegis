//! V105 — distributed-attacker bench client.
//!
//! Pingora's TCP accept reports the peer address from `accept()` — i.e.
//! whatever the connecting client bind'd as its source IP. By aliasing
//! loopback to 127.0.0.2 .. 127.0.0.{N+1} on the test host and binding
//! each connection to a distinct alias, we can simulate N attackers
//! against a single Aegis instance WITHOUT needing PROXY protocol
//! support on the listener (pingora-core 0.8 has none).
//!
//! Output: total RPS, status-code distribution, sample of `/admin/threats`
//! after the run so the operator can verify cluster-wide aggregation.
//!
//! Pre-requisites on Linux:
//!   for i in $(seq 2 N); do sudo ip addr add 127.0.0.$i/8 dev lo; done
//!
//! Usage:
//!   aegis-distbench --target http://127.0.0.1/ --sources 50 \
//!     --requests-per-source 200 --concurrency-per-source 4

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::Parser;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use tokio::sync::Mutex;

#[derive(Debug, Parser)]
#[command(
    name = "aegis-distbench",
    about = "Distributed-attacker simulator for Aegis"
)]
struct Args {
    /// Target URL — protocol://host:port/path. Path doesn't matter
    /// to the bench; just used to construct each request.
    #[arg(long)]
    target: String,
    /// Number of distinct source IPs (127.0.0.2 .. 127.0.0.{2+N-1}).
    /// Operator must alias these on the loopback before running.
    #[arg(long, default_value_t = 50)]
    sources: u32,
    /// Requests each source will send.
    #[arg(long, default_value_t = 200)]
    requests_per_source: u32,
    /// In-flight requests per source.
    #[arg(long, default_value_t = 4)]
    concurrency_per_source: u32,
    /// Optional custom path to GET; otherwise probes `/?q=union+select`
    /// (will hit WAF if enabled). Useful for cache-warm vs attack tests.
    #[arg(long, default_value = "/?q=union+select+1")]
    path: String,
    /// Optional bench timeout (seconds). Aborts if run exceeds this.
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,
}

#[derive(Default, Clone, Copy)]
struct Stats {
    total: u64,
    ok: u64,
    forbidden: u64,
    errors: u64,
    bytes: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let url: hyper::Uri = args.target.parse()?;
    let host = url.host().unwrap_or("127.0.0.1").to_string();
    let port = url.port_u16().unwrap_or(80);
    let target_addr = SocketAddr::new(
        host.parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port,
    );
    eprintln!(
        "aegis-distbench: target={} sources={} reqs/src={} c/src={}",
        args.target, args.sources, args.requests_per_source, args.concurrency_per_source
    );

    let stats = Arc::new(Mutex::new(Stats::default()));
    let start = Instant::now();
    let mut handles = Vec::new();

    for sid in 0..args.sources {
        // 127.0.0.2 + sid → spread across loopback aliases.
        let src_octet = 2u8.saturating_add(sid as u8);
        let src_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, src_octet));
        let stats = Arc::clone(&stats);
        let path = args.path.clone();
        let host = host.clone();
        let target = target_addr;
        let rps = args.requests_per_source;
        let conc = args.concurrency_per_source;
        let handle = tokio::spawn(async move {
            run_source(src_ip, target, &host, &path, rps, conc, stats).await
        });
        handles.push(handle);
    }

    // Hard timeout safety net.
    let timeout = Duration::from_secs(args.timeout_secs);
    let _ = tokio::time::timeout(timeout, async {
        for h in handles {
            let _ = h.await;
        }
    })
    .await;

    let elapsed = start.elapsed();
    let s = *stats.lock().await;
    let rps = s.total as f64 / elapsed.as_secs_f64();
    println!(
        "\n=== aegis-distbench result ===\n\
         elapsed:        {:.2}s\n\
         total requests: {}\n\
         200 OK:         {}\n\
         403 forbidden:  {}\n\
         errors:         {}\n\
         total RPS:      {:>10.0}\n\
         bytes received: {}\n",
        elapsed.as_secs_f64(),
        s.total,
        s.ok,
        s.forbidden,
        s.errors,
        rps,
        s.bytes
    );
    Ok(())
}

async fn run_source(
    src_ip: IpAddr,
    target: SocketAddr,
    host_header: &str,
    path: &str,
    requests: u32,
    concurrency: u32,
    stats: Arc<Mutex<Stats>>,
) {
    // Each "source" gets its own hyper client whose HttpConnector
    // binds outgoing TCP to the source IP. This is the lever that
    // makes Aegis's per-IP scorer see distinct attackers.
    let mut connector = HttpConnector::new();
    connector.set_local_address(Some(src_ip));
    connector.set_nodelay(true);
    let client: Client<HttpConnector, Empty<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(concurrency as usize)
        .build(connector);

    let uri: hyper::Uri = format!("http://{}:{}{}", target.ip(), target.port(), path)
        .parse()
        .unwrap();
    let host_header = host_header.to_string();

    let in_flight = Arc::new(tokio::sync::Semaphore::new(concurrency as usize));
    let mut spawned = Vec::new();

    for _ in 0..requests {
        let permit = in_flight.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let uri = uri.clone();
        let host_header = host_header.clone();
        let stats = Arc::clone(&stats);
        spawned.push(tokio::spawn(async move {
            let _p = permit;
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", host_header)
                .header("user-agent", "aegis-distbench/0.1")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let outcome = client.request(req).await;
            let mut s = stats.lock().await;
            s.total += 1;
            match outcome {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 {
                        s.ok += 1;
                    } else if status == 403 {
                        s.forbidden += 1;
                    }
                    // Drain body (refcount) and count bytes.
                    drop(s);
                    if let Ok(b) = resp.into_body().collect().await {
                        let bytes = b.to_bytes();
                        let mut s = stats.lock().await;
                        s.bytes += bytes.len() as u64;
                    }
                }
                Err(_) => {
                    s.errors += 1;
                }
            }
        }));
    }
    for h in spawned {
        let _ = h.await;
    }
}
