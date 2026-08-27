//! Where this process reads its configuration from.
//!
//! Two sources, chosen at compile time by the same feature that selects the
//! guest transport, because they are the same fact about a build: a guest has
//! no environment. PID 1 runs `/bin/app` directly and sets nothing, so the
//! kernel command line is the only channel into it.
//!
//! That channel is MEASURED. Which makes it the right place for values that say
//! what this image *is* — the fixed vsock ports it speaks on, the host CID it
//! reaches — and the wrong place for anything that differs per machine, since a
//! machine-specific value would fragment the measurement into one per
//! deployment and end reproducibility. It is also the wrong place for a secret:
//! the command line is not confidential, and a secret compiled into every
//! deployment is not a secret.
//!
//! Keys are the environment names transposed: `ENCLAVID_ADDRESS_OUT` is read
//! from `enclavid.address_out=` on the command line. One name per value, so a
//! reader looking at either source recognises the other.

/// The command line, read once. `/proc` is mounted by PID 1 before `/bin/app`.
#[cfg(feature = "vsock")]
fn cmdline() -> &'static str {
    use std::sync::OnceLock;
    static CMDLINE: OnceLock<String> = OnceLock::new();
    CMDLINE.get_or_init(|| {
        std::fs::read_to_string("/proc/cmdline")
            .expect("/proc/cmdline unreadable — is /proc mounted?")
    })
}

/// `ENCLAVID_ADDRESS_OUT` → `enclavid.address_out`.
#[cfg(feature = "vsock")]
fn cmdline_key(env_key: &str) -> String {
    match env_key.split_once('_') {
        Some((prefix, rest)) => format!("{}.{}", prefix.to_lowercase(), rest.to_lowercase()),
        None => env_key.to_lowercase(),
    }
}

/// Look a value up without deciding what a missing one means.
#[cfg(feature = "vsock")]
pub fn optional(env_key: &str) -> Option<String> {
    let prefix = format!("{}=", cmdline_key(env_key));
    cmdline()
        .split_ascii_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
        .map(str::to_string)
}

#[cfg(not(feature = "vsock"))]
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

#[cfg(all(test, feature = "vsock"))]
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
