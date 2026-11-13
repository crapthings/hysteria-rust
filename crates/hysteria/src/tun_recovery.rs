//! Explicit recovery of private macOS TUN route receipts.
use crate::{CliError, Result};
use std::path::Path;

/// Inspect a journal or explicitly recover only routes whose recorded ownership is still valid.
/// # Errors
/// Rejects unsafe files, active leases, uncertain ownership and route-operation failures.
pub fn recover(path: &Path, apply: bool) -> Result<serde_json::Value> {
    #[cfg(target_os = "macos")]
    {
        crate::macos_route_journal::recover(path, apply)
            .map_err(|error| CliError::new(format!("TUN route recovery not confirmed: {error}")))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, apply);
        Err(CliError::new(
            "route journal recovery currently requires macOS",
        ))
    }
}
