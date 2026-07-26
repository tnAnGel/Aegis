//! HTTP/3 over QUIC listener.
//!
//! Wires quinn's UDP-based QUIC endpoint to the shared `ProxyHttpHandler`
//! so that filter pipeline, rate limits, challenge ladder and metrics
//! work uniformly across h1, h2 and h3.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use http::{Request, Response};
use http_body_util::BodyExt;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig, crypto::rustls::QuicServerConfig};
use rustls::ServerConfig as RustlsServerConfig;
use tokio::sync::{RwLock, Semaphore};

use crate::{
    config::SniEntry,
    proxy::http::{ProxyHttpHandler, RespBody},
    tls_sni::SniResolver,
};

// V233 — HTTP/3 / QUIC resource-exhaustion bounds.
//
// The QUIC path previously had no ceiling on memory or task count:
// a slow-loris stream could pin a task forever, and connections /
// streams were spawned unboundedly. These three constants close that
// gap. Values are deliberately conservative — h3 is a sidecar listener,
// not the primary ingress.

/// V233 — wall-clock budget a single h3 request body gets to fully
/// arrive. Mirrors the h1/h2 `body_read_timeout_ms` config default
/// (30s). The h3 listener clones `ProxyHttpHandler` but does not
/// expose the private `body_read_timeout_ms` field, and the task
/// brief forbids editing `http.rs`, so we pin the documented default
/// here. A stream dripping one byte per RTT is aborted at this bound
/// instead of holding a task (and up to `max_body_bytes` of buffer)
/// indefinitely.
const H3_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// V233 — maximum number of in-flight request-stream tasks per QUIC
/// connection. A permit is acquired before each stream task is
/// spawned and released when it finishes; this caps both task count
/// and aggregate body buffering (≤ 256 × `max_body_bytes`) per peer.
const H3_MAX_STREAMS_PER_CONN: usize = 256;

/// V233 — process-wide ceiling on concurrent h3 request-stream tasks
/// across every connection. Bounds total QUIC-path memory regardless
/// of how many connections a flood opens. 256 conns × 256 streams is
/// the per-conn product; the global cap keeps the real total far
/// below that worst case.
const H3_MAX_STREAMS_GLOBAL: usize = 4096;

/// V233 — `quinn` transport cap on concurrently-open bidirectional
/// streams the peer may have outstanding. Backs the per-conn task
/// semaphore at the protocol layer so a peer cannot even open more
/// streams than we will service.
const H3_MAX_CONCURRENT_BIDI: u32 = 256;

/// V233 — companion cap for unidirectional streams (h3 control /
/// QPACK encoder/decoder streams need only a handful).
const H3_MAX_CONCURRENT_UNI: u32 = 16;

/// Build a quinn endpoint with HTTP/3 ALPN and the shared SNI-aware
/// TLS resolver — the same certs userland h1/h2 receives.
pub fn build_endpoint(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    sni: &[SniEntry],
) -> Result<Endpoint> {
    let resolver =
        SniResolver::build(cert_path, key_path, sni).context("SNI resolver setup failed for h3")?;
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // M10 — disable QUIC 0-RTT early data. 0-RTT (TLS 1.3 early data,
    // RFC 8446 §8 / RFC 9001 §9.2) is inherently replayable: an attacker
    // who captures the encrypted early-data flight can resend it, and the
    // server has no transport-level guarantee it is seen only once.
    // AEGIS forwards request bodies to the origin with no anti-replay
    // dedup, so accepting 0-RTT would let a captured request be replayed
    // through the proxy. For a security proxy the safe default is to
    // refuse early data entirely; setting this to 0 forces every request
    // onto a fully-handshaked (1-RTT) connection. (If 0-RTT is ever
    // wanted as an opt-in, it belongs behind a config toggle in
    // config.rs — see integration_needed.)
    tls.max_early_data_size = 0;

    let quic_crypto =
        QuicServerConfig::try_from(tls).context("rustls config is not QUIC-compatible")?;
    let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));

    // V233 — bound concurrent QUIC streams at the transport layer.
    // Without this `quinn` lets a peer open an effectively unlimited
    // number of bidi streams, each able to buffer up to
    // `max_body_bytes` in the request handler. Capping bidi streams
    // here backs the per-connection task semaphore in
    // `serve_connection`: a peer cannot open more streams than we
    // will service. Uni streams only carry h3 control / QPACK, so a
    // small cap is plenty.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(H3_MAX_CONCURRENT_BIDI.into());
    transport.max_concurrent_uni_streams(H3_MAX_CONCURRENT_UNI.into());
    server_config.transport_config(Arc::new(transport));

    // H3 multi-process — bind the UDP socket with SO_REUSEPORT so every
    // SO_REUSEPORT worker PROCESS can share :443/udp. `Endpoint::server`
    // binds a plain socket without REUSEPORT, so with N worker processes
    // only the first bound and the rest died with EADDRINUSE ("failed to
    // bind QUIC endpoint"). We build the socket ourselves, set REUSEPORT,
    // then hand it to quinn via `Endpoint::new`.
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("create QUIC UDP socket")?;
    sock.set_reuse_address(true).ok();
    sock.set_reuse_port(true)
        .context("set SO_REUSEPORT on QUIC socket")?;
    sock.set_nonblocking(true).ok();
    sock.bind(&addr.into())
        .with_context(|| format!("bind QUIC UDP socket {addr}"))?;
    let udp: std::net::UdpSocket = sock.into();
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        udp,
        Arc::new(quinn::TokioRuntime),
    )
    .context("failed to create QUIC endpoint")?;
    Ok(endpoint)
}

/// Spawn the h3 accept loop. The returned `JoinHandle` runs until the
/// endpoint is closed; cancelling the future aborts new connection
/// processing but does not actively close existing streams.
pub fn spawn_server(
    endpoint: Endpoint,
    handler: Arc<RwLock<ProxyHttpHandler>>,
    fingerprints: Arc<crate::state::fingerprint::FingerprintCache>,
) -> tokio::task::JoinHandle<()> {
    // V233 — process-wide ceiling on concurrent h3 stream tasks,
    // created once per listener and shared by every connection. The
    // accept loop itself stays unbounded (a refused connection is
    // cheap — it never reaches the request handler), but each stream
    // task must hold both this global permit and a per-connection
    // permit before it can buffer a request body. That bounds total
    // QUIC-path memory no matter how many connections a flood opens.
    let global_streams = Arc::new(Semaphore::new(H3_MAX_STREAMS_GLOBAL));
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let handler = handler.clone();
            let fingerprints = fingerprints.clone();
            let global_streams = global_streams.clone();
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!(error = %e, "h3 connection refused during handshake");
                        return;
                    }
                };
                let remote = connection.remote_address();
                // H3 fingerprint. quinn-0.11 doesn't expose the raw
                // Initial-packet bytes or the peer's individual
                // transport parameter values, so we hash the small
                // set of *stable* signals it does surface:
                //
                //   - ALPN string (from rustls HandshakeData)
                //   - max_datagram_size (derived from the peer's
                //     advertised max_udp_payload_size — fixed for
                //     the lifetime of the connection)
                //
                // Coarser than a true JA4Q would be, but distinguishes
                // major QUIC stacks (chromium / firefox / cronet /
                // quiche / msquic) reliably — operators consume the
                // hash, not the components.
                let alpn = connection
                    .handshake_data()
                    .and_then(|hd| {
                        hd.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                            .and_then(|h| h.protocol.clone())
                    })
                    .and_then(|p| String::from_utf8(p).ok())
                    .unwrap_or_default();
                let max_dgram = connection.max_datagram_size().unwrap_or(0) as u64;
                let cap = crate::h3_fp::H3Capture {
                    // CAVEAT: quinn 0.11 does not expose the
                    // negotiated QUIC version through any public
                    // accessor — neither `Connection::version()`
                    // nor `HandshakeData` carry it. quinn negotiates
                    // RFC 9000 (version 1) exclusively by default
                    // unless an operator manually calls
                    // `TransportConfig::version()` to advertise
                    // alternates. We hard-code the default here so
                    // the fingerprint format stays JA4Q-compatible;
                    // promote this to a real read once quinn merges
                    // a Connection version getter.
                    // See: https://github.com/quinn-rs/quinn/issues/
                    version: 0x0000_0001,
                    alpn,
                    params: vec![(0x03, max_dgram)],
                };
                let h3fp = crate::h3_fp::compute(&cap).full;
                fingerprints.record_h3fp(remote.ip(), remote.port(), h3fp);
                let h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(
                    connection,
                ))
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!(error = %e, "h3 negotiation failed");
                        return;
                    }
                };
                serve_connection(h3_conn, remote, handler, global_streams).await;
            });
        }
    })
}

async fn serve_connection(
    mut conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
    remote: SocketAddr,
    handler: Arc<RwLock<ProxyHttpHandler>>,
    global_streams: Arc<Semaphore>,
) {
    // V233 — per-connection ceiling on concurrent stream tasks. quinn's
    // transport-level `max_concurrent_bidi_streams` already caps how
    // many streams a peer may open, but this guards the spawn site
    // directly: a permit is held for the whole lifetime of each stream
    // task, so an abusive peer cannot accumulate more in-flight request
    // handlers (and their body buffers) than this on a single
    // connection.
    let conn_streams = Arc::new(Semaphore::new(H3_MAX_STREAMS_PER_CONN));
    loop {
        match conn.accept().await {
            Ok(Some(resolver)) => {
                let handler = handler.clone();
                // V233 — acquire a global then a per-connection permit
                // *before* spawning. `acquire_owned` on these
                // never-closed semaphores only fails if the semaphore
                // is closed, which we never do — hence the defensive
                // `else { break }`. Holding both permits inside the
                // task means they release exactly when the stream task
                // ends (success, error or panic via drop).
                let Ok(global_permit) = global_streams.clone().acquire_owned().await else {
                    break;
                };
                let Ok(conn_permit) = conn_streams.clone().acquire_owned().await else {
                    break;
                };
                tokio::spawn(async move {
                    // Permits live for the whole task; drop releases
                    // them. Bound to `_` names so they are not dropped
                    // early by the compiler.
                    let _global_permit = global_permit;
                    let _conn_permit = conn_permit;
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(error = %e, "h3 stream resolve failed");
                            return;
                        }
                    };
                    if let Err(e) = handle_stream(req, stream, remote, handler).await {
                        tracing::debug!(error = %e, "h3 stream handling error");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(error = %e, "h3 connection error");
                break;
            }
        }
    }
}

async fn handle_stream<S>(
    req: Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    remote: SocketAddr,
    handler: Arc<RwLock<ProxyHttpHandler>>,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (parts, _) = req.into_parts();

    // Cap drain at the WAF body limit + a small slack so inspect_body
    // still sees the overflow and returns 413 cleanly instead of us
    // silently truncating.
    let (handler_clone, max) = {
        let h = handler.read().await.for_h3();
        let max = h.max_body_bytes().saturating_add(1);
        (h, max)
    };

    let mut body = BytesMut::new();
    let mut overflow = false;
    // V233 — slow-loris (R-U-Dead-Yet) guard. The whole body must
    // arrive within H3_BODY_READ_TIMEOUT; otherwise the stream is
    // aborted. Without this a peer dripping one byte per RTT pins this
    // task forever — `recv_data()` itself has no deadline. The budget
    // wraps the *entire* drain loop (not each chunk) so it mirrors the
    // h1/h2 path, which times out `body.collect()` as a unit. On
    // timeout we return an error: `handle_stream`'s caller logs it and
    // the stream/task is dropped, releasing its semaphore permits.
    let drain = async {
        while let Some(chunk) = stream.recv_data().await? {
            if body.len() + chunk.remaining() > max {
                overflow = true;
                break;
            }
            body.extend_from_slice(chunk_to_bytes(chunk).as_ref());
        }
        Ok::<(), anyhow::Error>(())
    };
    match tokio::time::timeout(H3_BODY_READ_TIMEOUT, drain).await {
        Ok(inner) => inner?,
        Err(_) => {
            anyhow::bail!(
                "h3 body read timeout after {}s",
                H3_BODY_READ_TIMEOUT.as_secs()
            );
        }
    }
    if overflow {
        // Pad to one byte past the limit so WafFilter::inspect_body
        // returns 413; saves us from synthesizing the response here.
        body.resize(max, 0);
    }
    let body = body.freeze();

    let response = handler_clone
        .handle_collected(remote.ip(), remote.port(), parts, body)
        .await;
    send_response(&mut stream, response).await
}

fn chunk_to_bytes<B: bytes::Buf>(mut buf: B) -> Bytes {
    let mut out = BytesMut::with_capacity(buf.remaining());
    while buf.has_remaining() {
        let c = buf.chunk();
        out.extend_from_slice(c);
        let n = c.len();
        buf.advance(n);
    }
    out.freeze()
}

async fn send_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    response: Response<RespBody>,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (parts, mut body) = response.into_parts();
    let head = Response::from_parts(parts, ());
    stream.send_response(head).await?;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            stream.send_data(data).await?;
        }
    }
    stream.finish().await?;
    Ok(())
}

// V233 — the QUIC-facing functions (build_endpoint / spawn_server /
// serve_connection / handle_stream) all require a live quinn endpoint
// or h3 stream and so cannot be exercised in a plain unit test. What
// *is* testable in isolation is the resource-limit machinery the V233
// fix introduced: the limit constants and the two primitives it relies
// on — `tokio::time::timeout` (slow-loris body guard) and
// `Semaphore` permit accounting (per-conn / global stream caps).
#[cfg(test)]
mod tests {
    use super::*;

    /// V233 — the limit constants must stay internally consistent:
    /// non-zero, and the per-connection stream cap must not exceed the
    /// transport-level bidi-stream cap (the transport cap is the
    /// protocol-layer backstop for the task semaphore).
    #[test]
    fn v233_limit_constants_are_sane() {
        assert!(
            H3_BODY_READ_TIMEOUT.as_secs() > 0,
            "body timeout must be set"
        );
        assert!(H3_MAX_STREAMS_PER_CONN > 0, "per-conn cap must be set");
        assert!(H3_MAX_STREAMS_GLOBAL > 0, "global cap must be set");
        assert!(H3_MAX_CONCURRENT_BIDI > 0, "bidi cap must be set");
        assert!(H3_MAX_CONCURRENT_UNI > 0, "uni cap must be set");
        // The per-connection task semaphore must never let a peer run
        // more stream tasks than quinn will allow it to open.
        assert!(
            H3_MAX_STREAMS_PER_CONN as u64 <= u64::from(H3_MAX_CONCURRENT_BIDI),
            "per-conn task cap must not exceed transport bidi cap"
        );
        // The global cap is a process-wide ceiling; it should be at
        // least one connection's worth so a single peer is not starved.
        assert!(
            H3_MAX_STREAMS_GLOBAL >= H3_MAX_STREAMS_PER_CONN,
            "global cap must admit at least one full connection"
        );
    }

    /// V233 — exercises the exact `tokio::time::timeout` wrapper the
    /// body-drain loop uses: a never-completing "drain" must yield the
    /// timeout (`Err`) branch rather than hanging the task.
    #[tokio::test(start_paused = true)]
    async fn v233_slow_drain_hits_timeout() {
        let slow_drain = async {
            // A slow-loris client: nothing ever arrives.
            std::future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };
        let res = tokio::time::timeout(H3_BODY_READ_TIMEOUT, slow_drain).await;
        assert!(res.is_err(), "a stalled body drain must time out");
    }

    /// V233 — a drain that finishes before the deadline passes through
    /// the `Ok` branch unharmed (the timeout must not penalise
    /// well-behaved clients).
    #[tokio::test(start_paused = true)]
    async fn v233_prompt_drain_passes_through() {
        let prompt_drain = async { Ok::<(), anyhow::Error>(()) };
        let res = tokio::time::timeout(H3_BODY_READ_TIMEOUT, prompt_drain).await;
        assert!(res.is_ok(), "a completed drain must not be timed out");
        assert!(res.unwrap().is_ok(), "inner drain result must survive");
    }

    /// V233 — the per-connection `Semaphore` caps in-flight stream
    /// tasks: once `H3_MAX_STREAMS_PER_CONN` permits are held, the
    /// next acquire cannot succeed until one is released — exactly the
    /// backpressure `serve_connection` relies on.
    #[tokio::test]
    async fn v233_stream_semaphore_caps_concurrency() {
        let sem = Arc::new(Semaphore::new(H3_MAX_STREAMS_PER_CONN));
        // Drain every permit, as a connection at full stream capacity.
        let mut held = Vec::with_capacity(H3_MAX_STREAMS_PER_CONN);
        for _ in 0..H3_MAX_STREAMS_PER_CONN {
            held.push(sem.clone().acquire_owned().await.expect("permit"));
        }
        assert_eq!(sem.available_permits(), 0, "all permits must be in use");
        // With zero permits free, a further spawn must not proceed.
        assert!(
            sem.clone().try_acquire_owned().is_err(),
            "over-cap stream acquire must fail while connection is saturated"
        );
        // A finished stream task releases its permit; the next can run.
        drop(held.pop());
        let next = sem.clone().try_acquire_owned();
        assert!(next.is_ok(), "a freed permit must admit the next stream");
    }
}
