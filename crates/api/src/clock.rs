//! This side's clock: the enclave's own, which timesync keeps.

use std::time::{SystemTime, UNIX_EPOCH};

/// Now, in unix seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
