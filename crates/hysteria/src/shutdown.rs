use hysteria_cli::Result;
use std::future::Future;

/// Registers SIGTERM before startup and also handles Ctrl+C for Unix foreground and service processes.
#[cfg(unix)]
pub(crate) fn signal() -> Result<impl Future<Output = ()> + Send> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    })
}

/// Preserves console Ctrl+C shutdown on platforms without Unix signals.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Keep one fallible startup contract on every platform.
pub(crate) fn signal() -> Result<impl Future<Output = ()> + Send> {
    Ok(async {
        let _ = tokio::signal::ctrl_c().await;
    })
}
