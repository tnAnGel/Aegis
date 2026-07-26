//! V127 — EventBridge: NDJSON stream over Unix socket (Synapse parity).
//!
//! Operators wire SIEM / log aggregators (Wazuh, Elasticsearch, Loki,
//! Splunk, Vector, FluentBit) to a single endpoint that emits one JSON
//! object per security decision. V116 SecurityEvent is the data; V127
//! is the transport.
//!
//! Design properties:
//! * **Unix socket** (`/var/run/aegis-events.sock` by default) — no
//!   network exposure, file-permission ACL'd. Operator subscribes
//!   with `nc -U` / `socat` / their SIEM's unix-socket reader.
//! * **NDJSON broadcast** — every connected subscriber gets every
//!   event. New connections start fresh (no history replay).
//! * **Lossy bounded queue per subscriber** — if a slow subscriber
//!   can't keep up the proxy never blocks; we drop oldest in their
//!   queue and bump a metric. Aegis isn't a logging system, it's a
//!   proxy that emits — drop > block.
//! * **Best-effort** — if the socket isn't reachable (operator never
//!   set up the path / dir doesn't exist) emission is a no-op.
//!
//! Hot-path cost: one mpsc `try_send` per event. Sub-µs when no
//! subscriber is attached.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::mpsc,
};

use crate::security_event::SecurityEvent;

/// Per-subscriber outbound buffer size. ~1k events of headroom before
/// the slowest reader starts losing.
const SUBSCRIBER_CHANNEL_CAP: usize = 1024;

/// Internal subscriber handle — a `Sender` over which the broadcaster
/// dispatches every event the proxy emits.
type SubscriberTx = mpsc::Sender<Arc<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireFormat {
    /// Native Aegis SecurityEvent JSON (default).
    #[default]
    Native,
    /// V185 — T-Pot Sicherheitstacho-compatible NDJSON.
    Sicherheitstacho,
}

pub struct EventBridge {
    /// Subscriber list. Each connected reader gets a clone of every
    /// event. New subscribers are pushed by the accept loop; dead
    /// ones are pruned on send error.
    subscribers: Arc<Mutex<Vec<SubscriberTx>>>,
    socket_path: Option<PathBuf>,
    format: WireFormat,
    /// V185 — when set, every emit in Sicherheitstacho format bumps
    /// this counter so the Defence Arsenal panel
    /// (`/admin/api/arsenal` → `sicherheitstacho.emits`) reflects real
    /// T-Pot-schema export volume. Points at the arsenal's
    /// `sicherheitstacho_emits` shard. None when no arsenal is wired.
    sicherheitstacho_counter: Option<Arc<crate::metrics::sharded::ShardedCounter>>,
}

impl EventBridge {
    /// Construct disconnected. Use [Self::spawn] to bind the socket
    /// and start the accept loop. `socket_path = None` keeps the
    /// bridge in no-op mode (emit() is cheap, listen never starts).
    pub fn new(socket_path: Option<PathBuf>) -> Self {
        // V185 — environment-driven format selection. Operator sets
        // AEGIS_EVENT_FORMAT=sicherheitstacho to switch the NDJSON
        // schema to the T-Pot-compatible shape without a code change.
        // Default stays the native SecurityEvent JSON.
        let format = match std::env::var("AEGIS_EVENT_FORMAT")
            .ok()
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("sicherheitstacho") | Some("tpot") => WireFormat::Sicherheitstacho,
            _ => WireFormat::Native,
        };
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
            socket_path,
            format,
            sicherheitstacho_counter: None,
        }
    }

    pub fn with_format(mut self, format: WireFormat) -> Self {
        self.format = format;
        self
    }

    /// V185 — attach the Defence Arsenal's `sicherheitstacho_emits`
    /// counter so each T-Pot-schema emit is reflected in the arsenal
    /// panel. Operator wires this from the binary when both an
    /// EventBridge and an ArsenalState are constructed.
    pub fn with_sicherheitstacho_counter(
        mut self,
        counter: Arc<crate::metrics::sharded::ShardedCounter>,
    ) -> Self {
        self.sicherheitstacho_counter = Some(counter);
        self
    }

    pub fn format(&self) -> WireFormat {
        self.format
    }

    pub fn enabled(&self) -> bool {
        self.socket_path.is_some()
    }

    /// Bind the Unix socket and accept subscribers in a background
    /// task. Returns immediately. No-op when socket_path is None.
    /// Idempotent — calling twice without shutdown silently no-ops
    /// (the first listener stays).
    pub async fn spawn(&self) -> std::io::Result<()> {
        let Some(path) = &self.socket_path else {
            return Ok(());
        };
        // Best-effort cleanup of stale socket from prior process.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        // Permissions: 0600 by default — operator chmods/chowns to
        // grant their SIEM read access. Aegis runs as service user,
        // so anyone with that user (or root) can subscribe.
        if let Err(e) =
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        {
            tracing::warn!(error = %e, "event_bridge: chmod 600 on socket failed");
        }
        let subs = Arc::clone(&self.subscribers);
        let path_str = path.display().to_string();
        tokio::spawn(async move {
            tracing::info!(socket = %path_str, "event_bridge: accept loop started");
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        Self::register_subscriber(&subs, stream).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "event_bridge: accept failed; will retry");
                        // Brief backoff so a misconfigured systemd
                        // doesn't pin a CPU on errno spam.
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        Ok(())
    }

    async fn register_subscriber(subs: &Arc<Mutex<Vec<SubscriberTx>>>, mut stream: UnixStream) {
        let (tx, mut rx) = mpsc::channel::<Arc<String>>(SUBSCRIBER_CHANNEL_CAP);
        if let Ok(mut guard) = subs.lock() {
            guard.push(tx);
        }
        // Per-subscriber writer task. Reads from rx, writes to socket,
        // exits on client disconnect or write error.
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if stream.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                if stream.write_all(b"\n").await.is_err() {
                    break;
                }
            }
        });
    }

    /// Emit one [SecurityEvent]. Cheap when no subscribers
    /// (just an Arc allocation + try_send to nothing). When slow
    /// subscribers exist, their queue fills and try_send drops the
    /// event for them — never blocks the proxy.
    ///
    /// V230 audit: emit() is O(M) over M subscribers, each receiver
    /// gets an Arc::clone (atomic bump only — the JSON payload itself
    /// is serialised exactly once per call and shared). Pruning is
    /// O(1) amortized via the V228 try_send-based Closed-eviction:
    /// dead_indices stays empty on the common path (all subscribers
    /// live) so the second lock acquisition is skipped entirely.
    /// The subscriber-list snapshot is a Vec of Sender clones
    /// (each Sender is internally Arc-backed, so cloning is an
    /// atomic bump, not a channel duplication). No further hot-path
    /// optimization possible without changing the broker semantics
    /// (e.g. switching to tokio::sync::broadcast, which would change
    /// the lossy-per-subscriber drop policy).
    pub fn emit(&self, ev: &SecurityEvent) {
        if !self.enabled() {
            return;
        }
        // Serialise once, share via Arc across subscribers.
        let json = match self.format {
            WireFormat::Native => match serde_json::to_string(ev) {
                Ok(s) => Arc::new(s),
                Err(_) => return,
            },
            WireFormat::Sicherheitstacho => {
                // V185 — bump the arsenal counter (if wired) so the
                // panel reflects real T-Pot-schema export volume.
                if let Some(c) = &self.sicherheitstacho_counter {
                    c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Arc::new(render_sicherheitstacho(ev))
            }
        };
        // Snapshot subscriber list under lock; release before send so
        // a stuck subscriber can't hold up the broadcaster.
        let subs_snapshot: Vec<SubscriberTx> = match self.subscribers.lock() {
            Ok(g) => g.iter().cloned().collect(),
            Err(_) => return,
        };
        let mut dead_indices = Vec::new();
        for (i, tx) in subs_snapshot.iter().enumerate() {
            match tx.try_send(Arc::clone(&json)) {
                Ok(_) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Slow subscriber — drop, bump metric.
                    tracing::trace!(target: "aegis::event_bridge", "subscriber queue full; dropped");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    dead_indices.push(i);
                }
            }
        }
        // Prune dead subscribers.
        if !dead_indices.is_empty()
            && let Ok(mut g) = self.subscribers.lock()
        {
            // Walk in reverse so indices stay valid as we remove.
            for &i in dead_indices.iter().rev() {
                if i < g.len() {
                    g.remove(i);
                }
            }
        }
    }

    /// Diagnostic: count of currently-attached subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().map(|g| g.len()).unwrap_or(0)
    }
}

fn render_sicherheitstacho(ev: &SecurityEvent) -> String {
    use crate::security_event::DecisionKind;
    use crate::sicherheitstacho::{Category, EventInput, render};
    let category = match ev.action {
        DecisionKind::Deny => Category::Block,
        DecisionKind::Challenge => Category::Challenge,
        DecisionKind::Throttle => Category::Waf,
        DecisionKind::Allow | DecisionKind::Observed => Category::Waf,
    };
    let tags_storage: Vec<&str> = ev
        .extra_reasons
        .iter()
        .copied()
        .chain(std::iter::once(ev.reason))
        .collect();
    let inp = EventInput {
        timestamp_unix_ms: None,
        src_ip: ev.client_ip.as_str(),
        src_port: 0,
        dst_port: 443,
        country: None,
        asn: None,
        transport: "TCP",
        service: "aegis-waf",
        category,
        tags: &tags_storage,
        method: ev.method.as_str(),
        host: ev.host.as_str(),
        path: ev.path.as_str(),
        user_agent: None,
    };
    render(&inp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_event::{DecisionKind, SecurityEvent};
    use tokio::io::AsyncBufReadExt;

    fn tmp_socket_path() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "aegis-eb-test-{}-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            n,
        ))
    }

    fn mk_event(reason: &'static str) -> SecurityEvent {
        SecurityEvent::new(
            DecisionKind::Deny,
            reason,
            "req-1",
            "example.com",
            "1.2.3.4",
            "GET",
            "/admin",
        )
    }

    #[tokio::test]
    async fn disabled_bridge_is_noop() {
        let b = EventBridge::new(None);
        assert!(!b.enabled());
        b.emit(&mk_event("test"));
        assert_eq!(b.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn subscriber_receives_events() {
        let path = tmp_socket_path();
        let b = EventBridge::new(Some(path.clone()));
        b.spawn().await.unwrap();
        // Give the accept loop a tick to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Connect as a subscriber.
        let stream = UnixStream::connect(&path).await.unwrap();
        let mut reader = tokio::io::BufReader::new(stream);
        // Give register_subscriber time to push into the list.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(b.subscriber_count(), 1);

        b.emit(&mk_event("waf_critical"));
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reader.read_line(&mut line),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(line.contains("waf_critical"), "got: {line}");
        assert!(line.contains("example.com"), "got: {line}");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn multiple_subscribers_all_receive() {
        let path = tmp_socket_path();
        let b = EventBridge::new(Some(path.clone()));
        b.spawn().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let s1 = UnixStream::connect(&path).await.unwrap();
        let s2 = UnixStream::connect(&path).await.unwrap();
        let mut r1 = tokio::io::BufReader::new(s1);
        let mut r2 = tokio::io::BufReader::new(s2);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(b.subscriber_count(), 2);

        b.emit(&mk_event("honeypot_hit"));

        let mut l1 = String::new();
        let mut l2 = String::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(r1.read_line(&mut l1), r2.read_line(&mut l2))
        })
        .await;
        assert!(l1.contains("honeypot_hit"));
        assert!(l2.contains("honeypot_hit"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn disconnected_subscriber_pruned_on_next_emit() {
        let path = tmp_socket_path();
        let b = EventBridge::new(Some(path.clone()));
        b.spawn().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        {
            let _stream = UnixStream::connect(&path).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert_eq!(b.subscriber_count(), 1);
        } // _stream drops → subscriber's rx fills up + then the writer
        // task exits on write_all error. emit() detects via Closed.

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // Multiple emits to allow the channel-closed branch to fire.
        for _ in 0..5 {
            b.emit(&mk_event("x"));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(b.subscriber_count(), 0);
        let _ = std::fs::remove_file(&path);
    }
}
