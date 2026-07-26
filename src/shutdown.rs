use tokio::signal;

/// V20 — Wait for any process termination signal.
///
/// Listens for both SIGINT (Ctrl+C, dev usage) and SIGTERM (the
/// signal systemd sends on `systemctl stop`). Earlier code only
/// handled Ctrl+C, so `systemctl stop aegis` skipped the drain
/// loop and dropped in-flight connections.
///
/// On non-unix targets, falls back to ctrl_c only.
pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal as unix_signal};
        // SIGTERM is the standard "please exit cleanly" signal that
        // systemd / docker / k8s send first. We ALSO listen for
        // SIGINT (Ctrl+C) for interactive runs.
        let mut sigterm = match unix_signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not install SIGTERM handler — falling back to ctrl_c only");
                let _ = signal::ctrl_c().await;
                return;
            }
        };
        let mut sigint = match unix_signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => {
                let _ = sigterm.recv().await;
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received — initiating graceful drain");
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received — initiating graceful drain");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}
