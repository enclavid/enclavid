//! Where a role binary reads its configuration from.
//!
//! Two sources, chosen at compile time, because they are the same fact about a
//! build: in a guest nothing fills an environment. There is no shell and no
//! service manager, and PID 1 runs the role binary straight from its inittab.
//! The kernel command line is the only channel in.
//!
//! It could be read less directly: the kernel hands init any unrecognised
//! `key=value` parameter as an environment variable, so a guest is not strictly
//! environment-less. Reading `/proc/cmdline` here instead does not avoid the
//! compile-time split or the name transposition — the kernel would deliver
//! `enclavid.address_out`, not `ENCLAVID_ADDRESS_OUT`, so both are needed
//! either way. What it does avoid is depending on PID 1 to pass its environment
//! on, and on the kernel's cap of a few dozen such variables.
//!
//! That channel is MEASURED. Which makes it the right place for values that say
//! what an image *is* — the fixed ports it speaks on, the host CID it reaches —
//! and the wrong place for anything that differs per machine, since a
//! machine-specific value would fragment the measurement into one per
//! deployment and end reproducibility. It is also the wrong place for a secret:
//! the command line is not confidential, and a secret compiled into every
//! deployment is not a secret.
//!
//! Keys are the environment names transposed: `ENCLAVID_ADDRESS_OUT` is read
//! from `enclavid.address_out=` on the command line. One name per value, so a
//! reader looking at either source recognises the other.

/// The command line, read once. `/proc` is mounted by PID 1 before the role
/// binary runs.
#[cfg(feature = "guest")]
fn cmdline() -> &'static str {
    use std::sync::OnceLock;
    static CMDLINE: OnceLock<String> = OnceLock::new();
    CMDLINE.get_or_init(|| {
        std::fs::read_to_string("/proc/cmdline")
            .expect("/proc/cmdline unreadable — is /proc mounted?")
    })
}

/// `ENCLAVID_ADDRESS_OUT` → `enclavid.address_out`.
#[cfg(feature = "guest")]
fn cmdline_key(env_key: &str) -> String {
    match env_key.split_once('_') {
        Some((prefix, rest)) => format!("{}.{}", prefix.to_lowercase(), rest.to_lowercase()),
        None => env_key.to_lowercase(),
    }
}

/// Look a value up without deciding what a missing one means.
#[cfg(feature = "guest")]
pub fn optional(env_key: &str) -> Option<String> {
    let prefix = format!("{}=", cmdline_key(env_key));
    cmdline()
        .split_ascii_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
        .map(str::to_string)
}

#[cfg(not(feature = "guest"))]
pub fn optional(env_key: &str) -> Option<String> {
    std::env::var(env_key).ok()
}

/// A value this build cannot run without. The message names both spellings, so
/// it reads the same whether the reader is looking at a shell or a boot line.
pub fn required(env_key: &str, what: &str) -> String {
    optional(env_key).unwrap_or_else(|| {
        panic!(
            "{env_key} is not set ({what}). In a guest this comes from the measured \
             kernel command line; elsewhere from the environment."
        )
    })
}

/// A value with a compiled-in fallback. Anything reached this way is absent
/// from a guest's command line unless that image chooses to set it — which is
/// what keeps availability tuning from fragmenting the measurement.
pub fn or_default<T: std::str::FromStr>(env_key: &str, fallback: T) -> T {
    optional(env_key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

#[cfg(all(test, feature = "guest"))]
mod tests {
    use super::cmdline_key;

    #[test]
    fn env_names_transpose_to_command_line_names() {
        assert_eq!(cmdline_key("ENCLAVID_ADDRESS_OUT"), "enclavid.address_out");
        assert_eq!(
            cmdline_key("ENCLAVID_EXECUTION_WORKER_ADDR"),
            "enclavid.execution_worker_addr"
        );
    }
}
