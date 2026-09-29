//! Where api dials its legs: the hatch, and its three fleet peers.
//!
//! Each leg is dialed at the host — `vsock://2:PORT`. The hatch is the host's
//! own process; for a peer, a relay the host runs carries the connection on to
//! the peer's guest. So the host decides where every dial lands whatever the
//! image says, and a port written into the measured command line bound
//! nothing. What decides whether api talks to a peer is the one measurement it
//! pins for that leg (`crate::endorsement`), checked in the handshake before a
//! byte of a request is sent; a port that leads anywhere else ends as a refused
//! leg and a false field in the health answer. The hatch is believed in
//! nothing: what it hands back is checked where it arrives — an endorsement
//! against the root compiled in, an artifact against its digest.
//!
//! So the ports are the launch's, not the image's: two releases can run side by
//! side on one host, each api's legs reaching its own peers and a hatch of its
//! own or a shared one, and neither measurement carries the host's port plan.
//! They arrive through QEMU's fw_cfg, one entry per leg under
//! `opt/com.enclavid/`, each a decimal port. Only the number is the host's —
//! the destination is always the host, fixed here — and nothing read there
//! reaches the environment, so every other setting stays on the measured
//! command line.
//!
//! The dev build dials over TCP and reads whole addresses from its environment.

use safe_logger::{debug, reason, safe};

/// Each leg's address, in the form `fleet_transport` and `hatch_client` dial.
pub struct Legs {
    pub hatch: String,
    pub storage: String,
    pub compile_worker: String,
    pub execution_worker: String,
}

#[cfg(feature = "vsock")]
pub fn load() -> Legs {
    Legs {
        hatch: from_launch("hatch-port"),
        storage: from_launch("storage-port"),
        compile_worker: from_launch("compile-worker-port"),
        execution_worker: from_launch("execution-worker-port"),
    }
}

#[cfg(not(feature = "vsock"))]
pub fn load() -> Legs {
    Legs {
        hatch: from_env("ENCLAVID_ADDRESS_OUT"),
        storage: from_env("ENCLAVID_STORAGE_ADDR"),
        compile_worker: from_env("ENCLAVID_COMPILE_WORKER_ADDR"),
        execution_worker: from_env("ENCLAVID_EXECUTION_WORKER_ADDR"),
    }
}

/// Where the kernel's fw_cfg driver shows this project's entries, by name.
#[cfg(feature = "vsock")]
const FW_CFG: &str = "/sys/firmware/qemu_fw_cfg/by_name/opt/com.enclavid";

/// Ten digits is every `u32`. One byte more is read, so an entry that is longer
/// is seen to be longer rather than cut to fit.
#[cfg(any(feature = "vsock", test))]
const MAX_PORT_DIGITS: usize = 10;

#[cfg(feature = "vsock")]
fn from_launch(name: &'static str) -> String {
    use std::io::Read;

    let mut raw = Vec::new();
    let read = std::fs::File::open(format!("{FW_CFG}/{name}/raw"))
        .and_then(|f| f.take(MAX_PORT_DIGITS as u64 + 1).read_to_end(&mut raw));
    let port = match read {
        Ok(_) => port(&raw).or_else(|| {
            debug!("not a port: {:?}", String::from_utf8_lossy(&raw));
            None
        }),
        Err(e) => {
            debug!("{e}");
            None
        }
    };
    let Some(port) = port else {
        safe_logger::error_and_panic!(
            "api: this launch gave no port, or not a port, as fw_cfg opt/com.enclavid/{}. \
             Stopping.",
            safe(&name, reason!("an entry name fixed in this image")),
            reason!("a constant naming an entry the host itself supplies")
        )
    };
    format!("vsock://2:{port}")
}

/// A port as the host writes one: decimal digits and nothing else, and neither
/// 0 nor the kernel's wildcard `VMADDR_PORT_ANY` (`u32::MAX`).
#[cfg(any(feature = "vsock", test))]
fn port(raw: &[u8]) -> Option<u32> {
    if raw.is_empty() || raw.len() > MAX_PORT_DIGITS || !raw.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let port: u32 = std::str::from_utf8(raw).ok()?.parse().ok()?;
    (port != 0 && port != u32::MAX).then_some(port)
}

#[cfg(not(feature = "vsock"))]
fn from_env(key: &'static str) -> String {
    std::env::var(key).unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "api: {} is not set. Stopping.",
            safe(&key, reason!("a configuration key named in this image")),
            reason!("a constant naming a configuration key the host itself supplied")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::port;

    #[test]
    fn a_port_is_digits_and_nothing_else() {
        assert_eq!(port(b"8001"), Some(8001));
        assert_eq!(port(b"4294967294"), Some(u32::MAX - 1));
        for refused in [
            &b""[..],
            b"0",
            b"4294967295",
            b"4294967296",
            b"99999999999",
            b"+8001",
            b"-1",
            b" 8001",
            b"8001\n",
            b"8001\0",
            b"0x1f41",
        ] {
            assert_eq!(
                port(refused),
                None,
                "{:?}",
                String::from_utf8_lossy(refused)
            );
        }
    }
}
