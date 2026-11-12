//! How large a decoded picture may be: the host's to set — the execution
//! worker's `picture-long-side` and `picture-short-side` settings — and
//! [`PictureBounds::DEFAULT`] where it does not. Read once at boot, the same
//! for every round the worker runs.

use serde::{Deserialize, Serialize};

/// The largest picture a decode gives, whichever way it is turned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PictureBounds {
    /// The longer side at most, in pixels.
    pub long: u32,
    /// The shorter side at most, in pixels.
    pub short: u32,
}

impl PictureBounds {
    /// 1920 pixels each way: as long as the page asks the camera for, either
    /// way it is turned, and room for a square picture to a model of that
    /// side.
    pub const DEFAULT: Self = Self {
        long: 1920,
        short: 1920,
    };

    /// The most pixels a picture within them has.
    pub fn pixels(&self) -> u64 {
        u64::from(self.long) * u64::from(self.short)
    }
}
