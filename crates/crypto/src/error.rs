//! Error for crypto operations. Intentionally opaque (just a message):
//! seal / open / recipient failures carry no domain meaning for callers
//! (they all map to infra errors), and naming the failing step leaks
//! nothing useful. Consumers convert into their own error — `broker-
//! client`'s `BridgeError`, `api`'s `RunError`.

use std::fmt;

#[derive(Debug, Clone)]
pub struct CryptoError(String);

impl CryptoError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CryptoError {}
