//! Utility functions for the testkit.
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current time in seconds since the UNIX epoch.
///
/// # Panics
///
/// Panics if the system clock is set before the UNIX epoch.
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}
