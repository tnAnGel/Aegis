//! End-to-end integration tests for the Aegis proxy handler.
//!
//! Each test spins up a real upstream on a free TCP port (one tokio
//! task per test) and drives `ProxyHttpHandler::handle_collected`
//! directly. That exercises the full pipeline — distributed checks,
//! WAF, bot, adaptive, rate-limit, challenge, upstream forward — on
//! actual sockets, without needing to boot the public listeners.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use aegis::{
    config::{
        AdaptiveConfig, BotConfig, ChallengeConfig, DefaultAction, RateLimitConfig, WafConfig,
        WafRule,
    },
    ddos::score::ThreatScorer,
    filters::{
        SharedFilter, adaptive::AdaptiveFilter, bot::BotFilter, challenge::ChallengeFilter,
        engine::FilterEngine, ip_acl::IpAclFilter, rate_limit::RateLimitFilter, waf::WafFilter,
    },
    metrics::RuntimeMetrics,
    proxy::{
        http::ProxyHttpHandler,
        upstream::{Upstream, UpstreamRouter},
    },
};

static TEST_HONEYPOT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Spawn a one-shot HTTP/1.1 upstream that responds to every request
/// with `200 OK` + the given body. Returns the bound address so the
/// test can wire it into the upstream router.
async fn spawn_mock_upstream(body: &'static str) -> (SocketAddr, Arc<AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let hits = Arc::new(AtomicU32::new(0));
    let hits_cloned = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let hits = hits_cloned.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                // Read at least the request line + headers; we don't
                // bother parsing — the proxy already validated them.
                let _ = stream.read(&mut buf).await;
                hits.fetch_add(1, Ordering::Relaxed);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, hits)
}

/// Build a handler whose pipeline matches a sensible default
/// production config but with all the knobs we need for assertions
/// dialled to predictable values.
fn build_handler(
    upstream_addr: SocketAddr,
    ip_deny: Vec<&str>,
    waf_enabled: bool,
    waf_rules: Vec<WafRule>,
    rate_burst: u64,
    challenge_enabled: bool,
) -> ProxyHttpHandler {
    let default_upstream = Upstream::from_url(&format!("http://{upstream_addr}")).unwrap();
    let router = Arc::new(UpstreamRouter {
        default_upstream,
        domain_upstreams: HashMap::new(),
    });
    let challenge_cfg = ChallengeConfig {
        enabled: challenge_enabled,
        token_ttl_secs: 60,
        hmac_secret: "integration-secret".to_string(),
        captcha_site_key: None,
        captcha_secret: None,
        fp_ttl_secs: 86_400,
        cookie_secure: false,
    };
    let waf_cfg = WafConfig {
        enabled: waf_enabled,
        custom_rules: waf_rules,
        max_body_bytes: Some(1024),
        rule_files: vec![],
        disable_signatures: vec![],
        ..Default::default()
    };
    let bot_cfg = BotConfig {
        enabled: false,
        challenge_score: 60,
        deny_score: 90,
        penalty_seconds: 60,
    };
    let adaptive_cfg = AdaptiveConfig {
        enabled: false,
        suspicious_rps_threshold: 1000,
        penalty_seconds: 10,
        exempt_paths: Vec::new(),
    };
    let ip_deny_strings: Vec<String> = ip_deny.iter().map(|s| s.to_string()).collect();
    let ip_allow_strings: Vec<String> = vec![];
    let challenge = Arc::new(ChallengeFilter::new(&challenge_cfg));
    let filters: Vec<SharedFilter> = vec![
        SharedFilter::IpAcl(Arc::new(IpAclFilter::new(
            &ip_deny_strings,
            &ip_allow_strings,
        ))),
        SharedFilter::Waf(Arc::new(WafFilter::new(&waf_cfg))),
        SharedFilter::Bot(Arc::new(BotFilter::new(&bot_cfg))),
        SharedFilter::Adaptive(Arc::new(AdaptiveFilter::new(&adaptive_cfg))),
        SharedFilter::Challenge(challenge.clone()),
        SharedFilter::RateLimit(Arc::new(RateLimitFilter::new(
            true,
            0,
            rate_burst,
            HashMap::new(),
        ))),
    ];
    let engine = Arc::new(FilterEngine::new(filters, DefaultAction::Allow));
    let metrics = Arc::new(RuntimeMetrics::default());
    let scorer = Arc::new(ThreatScorer::default());

    let rate_cfg = RateLimitConfig {
        enabled: false, // distributed rate limit off — only local bucket in pipeline
        requests_per_second: 0,
        burst: rate_burst,
        subnet_buckets: false,
        subnet_24_multiplier: 8,
        subnet_16_multiplier: 64,
        uri_budgets: vec![],
        hot_uri_rps_threshold: 0,
    };

    ProxyHttpHandler::new(
        router.clone(),
        engine,
        metrics,
        scorer,
        challenge_cfg,
        challenge,
        bot_cfg,
        rate_cfg,
        &waf_cfg,
        &aegis::config::GraphqlConfig::default(),
        &aegis::config::BypassConfig::default(),
        Arc::new(aegis::proxy::health::UpstreamHealth::new(router.clone())),
        Arc::new(aegis::state::fingerprint::FingerprintCache::new()),
        Arc::new(
            aegis::honeypot::HoneypotStore::open(std::env::temp_dir().join(format!(
                "aegis-int-honeypots-{}-{}.json",
                std::process::id(),
                TEST_HONEYPOT_SEQ.fetch_add(1, Ordering::Relaxed)
            )))
            .unwrap(),
        ),
        Arc::new(aegis::xdp::NoopXdp),
        None,
        Arc::new(aegis::geoip::NoopGeoIp),
        None,
        Arc::new(aegis::anomaly::AnomalyDetector::new(
            aegis::anomaly::AnomalyConfig::default(),
        )),
        None,
        30_000,
        aegis::config::UpstreamProtocol::default(),
        vec![],
        &aegis::config::DynamicTrustConfig::default(),
        &aegis::config::ResponseCacheConfig::default(),
    )
}

async fn read_body(
    response: Response<impl http_body::Body<Data = Bytes, Error = hyper::Error>>,
) -> Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

fn req(path: &str) -> (http::request::Parts, Bytes) {
    let r: Request<()> = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("host", "example.test")
        .body(())
        .unwrap();
    let (parts, _) = r.into_parts();
    (parts, Bytes::new())
}

#[tokio::test]
async fn upstream_passthrough_returns_body() {
    let (addr, hits) = spawn_mock_upstream("hello from upstream").await;
    let h = build_handler(addr, vec![], false, vec![], 100, false);
    let (parts, body) = req("/hello");
    let resp = h
        .handle_collected("1.1.1.1".parse().unwrap(), 0, parts, body)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    assert_eq!(body, Bytes::from("hello from upstream"));
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn waf_sqli_signature_blocks_before_upstream() {
    let (addr, hits) = spawn_mock_upstream("never").await;
    let h = build_handler(addr, vec![], true, vec![], 100, false);
    // URL-encoded "1' UNION SELECT * FROM users"; canonicalisation in
    // the WAF decodes it back before signature matching.
    let (parts, body) = req("/api?q=1%27%20UNION%20SELECT%20%2A%20FROM%20users");
    let resp = h
        .handle_collected("1.1.1.1".parse().unwrap(), 0, parts, body)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = read_body(resp).await;
    assert!(String::from_utf8_lossy(&body).contains("sqli"));
    assert_eq!(hits.load(Ordering::Relaxed), 0, "upstream must not be hit");
}

#[tokio::test]
async fn ip_acl_deny_short_circuits() {
    let (addr, hits) = spawn_mock_upstream("never").await;
    let h = build_handler(addr, vec!["10.0.0.5"], false, vec![], 100, false);
    let (parts, body) = req("/anything");
    let resp = h
        .handle_collected("10.0.0.5".parse().unwrap(), 0, parts, body)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn rate_limit_returns_429_after_burst() {
    let (addr, _) = spawn_mock_upstream("ok").await;
    let h = build_handler(addr, vec![], false, vec![], 2, false);
    let ip: IpAddr = "2.2.2.2".parse().unwrap();

    // burst = 2 → first two requests pass
    for _ in 0..2 {
        let (parts, body) = req("/");
        let resp = h.handle_collected(ip, 0, parts, body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let (parts, body) = req("/");
    let resp = h.handle_collected(ip, 0, parts, body).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn challenge_ladder_emits_set_cookie_and_step_header() {
    let (addr, _) = spawn_mock_upstream("ok").await;
    let h = build_handler(addr, vec![], false, vec![], 100, true);
    let (parts, body) = req("/desired-page");
    let resp = h
        .handle_collected("3.3.3.3".parse().unwrap(), 0, parts, body)
        .await;
    // First attempt on the ladder = 307 redirect.
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(resp.headers().get("location").unwrap(), "/desired-page");
    assert_eq!(resp.headers().get("x-aegis-step").unwrap(), "headers");
    let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie.starts_with("aegis_token="));
    assert!(cookie.contains("HttpOnly"));
}

#[tokio::test]
async fn challenge_cookie_round_trip_passes_to_upstream() {
    let (addr, hits) = spawn_mock_upstream("welcome").await;
    let h = build_handler(addr, vec![], false, vec![], 100, true);
    let ip: IpAddr = "4.4.4.4".parse().unwrap();

    // First request: get challenge + cookie.
    let (parts, body) = req("/");
    let first = h.handle_collected(ip, 0, parts, body).await;
    let cookie_value = first
        .headers()
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .next()
                .and_then(|kv| kv.split_once('='))
                .map(|(_, v)| v.to_string())
        })
        .expect("cookie set");

    // Second request: replay the cookie, expect upstream pass-through.
    let r: Request<()> = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "example.test")
        .header("cookie", format!("aegis_token={cookie_value}"))
        .body(())
        .unwrap();
    let (parts2, _) = r.into_parts();
    let second = h.handle_collected(ip, 0, parts2, Bytes::new()).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(read_body(second).await, Bytes::from("welcome"));
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn waf_body_inspection_catches_signature_in_payload() {
    let (addr, hits) = spawn_mock_upstream("never").await;
    let h = build_handler(addr, vec![], true, vec![], 100, false);
    let r: Request<()> = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header("host", "example.test")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(())
        .unwrap();
    let (parts, _) = r.into_parts();
    let body = Bytes::from("u=admin&p=' UNION SELECT password FROM users--");
    let resp = h
        .handle_collected("5.5.5.5".parse().unwrap(), 0, parts, body)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn waf_body_size_limit_returns_413() {
    let (addr, hits) = spawn_mock_upstream("never").await;
    let h = build_handler(addr, vec![], true, vec![], 100, false);
    let r: Request<()> = Request::builder()
        .method(Method::POST)
        .uri("/upload")
        .header("host", "example.test")
        .body(())
        .unwrap();
    let (parts, _) = r.into_parts();
    let body = Bytes::from(vec![b'a'; 4096]); // max_body_bytes = 1024
    let resp = h
        .handle_collected("6.6.6.6".parse().unwrap(), 0, parts, body)
        .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn upstream_unavailable_returns_502() {
    // Bind a listener to grab a port then drop it — connections fail.
    let dead_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    // Tiny delay to make sure the OS released the port.
    tokio::time::sleep(Duration::from_millis(10)).await;
    let dead: SocketAddr = format!("127.0.0.1:{dead_port}").parse().unwrap();
    let h = build_handler(dead, vec![], false, vec![], 100, false);
    let (parts, body) = req("/");
    let resp = h
        .handle_collected("7.7.7.7".parse().unwrap(), 0, parts, body)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn fingerprint_cookie_short_circuits_challenge() {
    // After a JS challenge, the verify endpoint stamps both
    // aegis_token + aegis_fp. The long-lived aegis_fp alone is enough
    // to bypass the challenge ladder on subsequent requests.
    let (addr, hits) = spawn_mock_upstream("welcome").await;
    let h = build_handler(addr, vec![], false, vec![], 100, true);
    let ip: IpAddr = "9.9.9.9".parse().unwrap();

    // Step 1: trigger challenge, capture token from Set-Cookie.
    let (parts, body) = req("/");
    let first = h.handle_collected(ip, 0, parts, body).await;
    let token_value = first
        .headers()
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .next()
                .and_then(|kv| kv.split_once('='))
                .map(|(_, v)| v.to_string())
        })
        .expect("token cookie");

    // Step 2: simulate the JS-challenge POST to /__aegis/verify with
    // a fingerprint, observe both cookies.
    let verify_uri = format!(
        "/__aegis/verify?t={}&r=/&fp=abc12345",
        urlencoding::encode(&token_value)
    );
    let r: Request<()> = Request::builder()
        .method(Method::GET)
        .uri(&verify_uri)
        .header("host", "example.test")
        .body(())
        .unwrap();
    let (vparts, _) = r.into_parts();
    let verify_resp = h.handle_collected(ip, 0, vparts, Bytes::new()).await;
    // Two Set-Cookie headers expected: aegis_token + aegis_fp.
    let cookies: Vec<String> = verify_resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();
    assert!(cookies.iter().any(|c| c.starts_with("aegis_token=")));
    let fp_cookie = cookies
        .iter()
        .find(|c| c.starts_with("aegis_fp="))
        .expect("fp cookie set after JS verify");
    let fp_value = fp_cookie
        .strip_prefix("aegis_fp=")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Step 3: a fresh client that only carries the fp cookie should
    // bypass the challenge ladder entirely.
    let r: Request<()> = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "example.test")
        .header("cookie", format!("aegis_fp={fp_value}"))
        .body(())
        .unwrap();
    let (parts3, _) = r.into_parts();
    let resp = h.handle_collected(ip, 0, parts3, Bytes::new()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(read_body(resp).await, Bytes::from("welcome"));
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn verify_endpoint_with_invalid_token_rejects() {
    let (addr, hits) = spawn_mock_upstream("ok").await;
    let h = build_handler(addr, vec![], false, vec![], 100, true);
    let r: Request<()> = Request::builder()
        .method(Method::GET)
        .uri("/__aegis/verify?t=not-a-real-token&r=/")
        .header("host", "example.test")
        .body(())
        .unwrap();
    let (parts, _) = r.into_parts();
    let resp = h
        .handle_collected("8.8.8.8".parse().unwrap(), 0, parts, Bytes::new())
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::Relaxed), 0);
}
