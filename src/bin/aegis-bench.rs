use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::Parser;
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use tokio::sync::Mutex;

#[derive(Debug, Parser)]
#[command(
    name = "aegis-bench",
    about = "HTTP load benchmark tool for Aegis/nginx"
)]
struct Args {
    #[arg(long)]
    url: String,
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,
    #[arg(long, default_value_t = 200)]
    concurrency: usize,
    #[arg(long, default_value_t = 0)]
    rps: u64,
    #[arg(long, default_value_t = 3000)]
    timeout_ms: u64,
    #[arg(long, default_value = "GET")]
    method: String,
}

#[derive(Default, Clone)]
struct Stats {
    total: u64,
    ok: u64,
    errors: u64,
    timeouts: u64,
    status_2xx: u64,
    status_3xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    latencies_ms: Vec<f64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let stats = Arc::new(Mutex::new(Stats::default()));

    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.duration_secs);

    let rate_per_worker = if args.rps > 0 {
        Some(args.rps as f64 / args.concurrency as f64)
    } else {
        None
    };

    let mut tasks = Vec::with_capacity(args.concurrency);
    for _ in 0..args.concurrency {
        let client = client.clone();
        let stats = Arc::clone(&stats);
        let url = args.url.clone();
        let method = args.method.clone();
        let timeout = Duration::from_millis(args.timeout_ms);

        tasks.push(tokio::spawn(async move {
            let mut next_tick = Instant::now();
            while Instant::now() < deadline {
                if let Some(rate) = rate_per_worker
                    && rate > 0.0
                {
                    let interval = Duration::from_secs_f64(1.0 / rate);
                    let now = Instant::now();
                    if now < next_tick {
                        tokio::time::sleep(next_tick - now).await;
                    }
                    next_tick += interval;
                }

                let req = match Request::builder()
                    .method(method.as_str())
                    .uri(url.as_str())
                    .body(Empty::new())
                {
                    Ok(r) => r,
                    Err(_) => {
                        let mut s = stats.lock().await;
                        s.errors += 1;
                        s.total += 1;
                        continue;
                    }
                };

                let begin = Instant::now();
                let resp = tokio::time::timeout(timeout, client.request(req)).await;
                let elapsed = begin.elapsed().as_secs_f64() * 1000.0;

                let mut s = stats.lock().await;
                s.total += 1;
                s.latencies_ms.push(elapsed);

                match resp {
                    Ok(Ok(res)) => {
                        let status = res.status().as_u16();
                        let _ = res.into_body().collect().await;
                        s.ok += 1;
                        match status {
                            200..=299 => s.status_2xx += 1,
                            300..=399 => s.status_3xx += 1,
                            400..=499 => s.status_4xx += 1,
                            _ => s.status_5xx += 1,
                        }
                    }
                    Ok(Err(_)) => s.errors += 1,
                    Err(_) => {
                        s.timeouts += 1;
                        s.errors += 1;
                    }
                }
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let mut final_stats = stats.lock().await.clone();
    final_stats
        .latencies_ms
        .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let p50 = percentile(&final_stats.latencies_ms, 50.0);
    let p95 = percentile(&final_stats.latencies_ms, 95.0);
    let p99 = percentile(&final_stats.latencies_ms, 99.0);
    let achieved_rps = if elapsed > 0.0 {
        final_stats.total as f64 / elapsed
    } else {
        0.0
    };
    let err_rate = if final_stats.total > 0 {
        (final_stats.errors as f64 / final_stats.total as f64) * 100.0
    } else {
        0.0
    };

    println!("target_url={}", args.url);
    println!("duration_secs={}", args.duration_secs);
    println!("concurrency={}", args.concurrency);
    println!("requested_rps={}", args.rps);
    println!("total_requests={}", final_stats.total);
    println!("achieved_rps={:.2}", achieved_rps);
    println!("ok={}", final_stats.ok);
    println!("errors={}", final_stats.errors);
    println!("timeouts={}", final_stats.timeouts);
    println!("error_rate_pct={:.2}", err_rate);
    println!("status_2xx={}", final_stats.status_2xx);
    println!("status_3xx={}", final_stats.status_3xx);
    println!("status_4xx={}", final_stats.status_4xx);
    println!("status_5xx={}", final_stats.status_5xx);
    println!("latency_ms_p50={:.2}", p50);
    println!("latency_ms_p95={:.2}", p95);
    println!("latency_ms_p99={:.2}", p99);

    Ok(())
}

fn percentile(data: &[f64], p: f64) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let rank = (p / 100.0) * (data.len() as f64 - 1.0);
    data[rank.round() as usize]
}
