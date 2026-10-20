//! What the host decides about api at launch, outside its measurement
//! (`fleet_transport::launch`): how long a session lives, how long and how
//! often api waits on its legs and on the hatch, how many pulls one consumer
//! may have under way at once, and how it holds up its own end of each leg.
//!
//! None of them reaches the terms between applicant, consumer and policy, and
//! none opens anything to the host. The host splices the hatch's leg, so how
//! long api waits on the hatch was the host's to stall already; a leg is dialed
//! at the host; and a session's lifetime is swept on the host's clock. The framing
//! that keeps a round's sizes constant on a leg is the contract's, above the
//! connection these set. Read once, before api talks to anything.

use std::time::Duration;

use engine_rpc::{DEFAULT_CALLBACK_REQUEST_BUFFER, LegSettings};
use fleet_transport::launch::{LaunchError, Settings as Launch};
use safe_logger::{reason, safe};

use crate::fleet::Dial;

/// How long a session lives, unless the host says otherwise
/// (`session-ttl-secs`): an ABSOLUTE TTL, its deadline `created_at + ttl` set
/// once at create, after which the storage-CVM's sweeper removes the session —
/// abandoned or completed-and-pulled. A week is a generous window for the
/// consumer to pull disclosures after completion.
const DEFAULT_SESSION_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// api's settings, as the host gave them or as this build defaults them.
pub struct Settings {
    pub session_ttl_secs: u64,
    /// How each fleet leg is dialed: one attempt's bound (`leg-dial-secs`) and
    /// the longest wait between attempts (`leg-retry-max-secs`).
    pub leg_dial: Dial,
    /// How long the hatch has to answer a pull (`pull-deadline-secs`), and how
    /// long a pull waits for its consumer's turn.
    pub pull_deadline: Duration,
    /// Registry requests one consumer may have under way at once
    /// (`registry-requests-per-consumer`).
    pub registry_requests_per_consumer: usize,
    /// How long the hatch has to answer an authorization
    /// (`authorize-deadline-secs`).
    pub authorize_deadline: Duration,
    /// How long the hatch has to answer one relayed KBS leg
    /// (`kbs-deadline-secs`).
    pub kbs_deadline: Duration,
    /// How many of a round's callbacks may wait for its server
    /// (`callback-request-buffer`).
    pub callback_request_buffer: usize,
    /// This end of every fleet leg (`leg-timeout-secs`, `leg-max-ports`,
    /// `leg-chunk-bytes`, `leg-receive-bytes`).
    pub leg: LegSettings,
    /// How long a listener waits after an accept this process could not
    /// complete (`accept-retry-ms`).
    pub accept_retry: Duration,
}

/// The host's settings for api, or no boot: a key api does not know, one given
/// twice, or a value that is not a number above zero stops it rather than
/// falling back to a default — a zero TTL would sweep every session as it is
/// made, and a zero deadline would fail every call it bounds. The leg's port
/// limit and chunk are held to what chmux runs with ([`LegSettings::refusal`]).
pub fn load() -> Settings {
    let mut launch = Launch::load("api").unwrap_or_else(|e| refused(e));
    let leg = LegSettings::default();
    let settings = Settings {
        session_ttl_secs: number(&mut launch, "session-ttl-secs", DEFAULT_SESSION_TTL_SECS),
        leg_dial: Dial {
            within: secs(
                &mut launch,
                "leg-dial-secs",
                crate::fleet::DEFAULT_ATTEMPT_TIMEOUT,
            ),
            retry_max: secs(
                &mut launch,
                "leg-retry-max-secs",
                crate::fleet::DEFAULT_RETRY_MAX,
            ),
        },
        pull_deadline: secs(
            &mut launch,
            "pull-deadline-secs",
            hatch_client::DEFAULT_PULL_DEADLINE,
        ),
        registry_requests_per_consumer: number(
            &mut launch,
            "registry-requests-per-consumer",
            crate::turns::DEFAULT_REGISTRY_REQUESTS_PER_CONSUMER,
        ),
        authorize_deadline: secs(
            &mut launch,
            "authorize-deadline-secs",
            hatch_client::DEFAULT_AUTHORIZE_DEADLINE,
        ),
        kbs_deadline: secs(
            &mut launch,
            "kbs-deadline-secs",
            hatch_client::DEFAULT_RELAY_DEADLINE,
        ),
        callback_request_buffer: number(
            &mut launch,
            "callback-request-buffer",
            DEFAULT_CALLBACK_REQUEST_BUFFER,
        ),
        leg: LegSettings {
            timeout: secs(&mut launch, "leg-timeout-secs", leg.timeout),
            max_ports: parsed(&mut launch, "leg-max-ports", leg.max_ports),
            chunk_bytes: parsed(&mut launch, "leg-chunk-bytes", leg.chunk_bytes),
            receive_bytes: parsed(&mut launch, "leg-receive-bytes", leg.receive_bytes),
        },
        accept_retry: Duration::from_millis(number(
            &mut launch,
            "accept-retry-ms",
            u64::try_from(fleet_transport::DEFAULT_ACCEPT_RETRY.as_millis()).unwrap_or(u64::MAX),
        )),
    };
    launch.finish().unwrap_or_else(|e| refused(e));
    if let Some(refusal) = settings.leg.refusal() {
        safe_logger::error_and_panic!(
            "api: {} cannot hold a leg up. Stopping.",
            safe(
                &refusal,
                reason!("a constant naming which of this role's settings")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        );
    }
    settings
}

/// A setting above zero.
fn number<T>(launch: &mut Launch, key: &'static str, default: T) -> T
where
    T: std::str::FromStr + PartialEq + From<u8>,
{
    let value = parsed(launch, key, default);
    if value == T::from(0) {
        safe_logger::error_and_panic!(
            "api: the setting {} is not a number above zero. Stopping.",
            safe(
                &key,
                reason!("a constant naming one of this role's settings")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        );
    }
    value
}

/// A setting in whole seconds, above zero.
fn secs(launch: &mut Launch, key: &'static str, default: Duration) -> Duration {
    Duration::from_secs(number(launch, key, default.as_secs()))
}

/// A setting that may be any number, zero included: `default` when the host
/// gave none, and no boot when it gave one that does not parse.
fn parsed<T: std::str::FromStr>(launch: &mut Launch, key: &'static str, default: T) -> T {
    match launch.take(key) {
        None => default,
        Some(value) => value.parse().unwrap_or_else(|_| {
            safe_logger::error_and_panic!(
                "api: the setting {} does not parse. Stopping.",
                safe(
                    &key,
                    reason!("a constant naming one of this role's settings")
                ),
                reason!("a constant, emitted once at boot before any request exists")
            )
        }),
    }
}

fn refused(e: LaunchError) -> ! {
    safe_logger::error_and_panic!(
        "api: {}. Stopping.",
        e,
        reason!("a constant, emitted once at boot before any request exists")
    )
}
