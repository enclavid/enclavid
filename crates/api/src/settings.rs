//! What the host decides about api at launch, outside its measurement
//! (`fleet_transport::launch`): how long a session lives, how long and how
//! often api waits on its legs and on the hatch, and how it holds up its own
//! end of each leg.
//!
//! None of them reaches the terms between applicant, consumer and policy, and
//! none opens anything to the host. The hatch is the host's own process, so how
//! long api waits on it was the host's to decide already; a leg is dialed at
//! the host; and a session's lifetime is swept on the host's clock. The framing
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

/// How often api asks the hatch whether this guest can still reach it, unless
/// the host says otherwise (`hatch-probe-secs`).
///
/// A clock, not a reaction: it runs at this rate whether or not anyone is being
/// verified, which is exactly what keeps the bit from reporting session
/// activity. The host choosing the rate changes nothing about that — it is one
/// rate for the life of the guest. Ten seconds because it is the same order as
/// chmux's own keepalive on the fleet legs, so every field of the answer ages at
/// one rate and a host polling it needs one cadence in mind rather than three.
const DEFAULT_HATCH_PROBE: Duration = Duration::from_secs(10);

/// How long one probe waits before calling it a miss, unless the host says
/// otherwise (`hatch-probe-deadline-secs`).
///
/// Shorter than the interval, and the boot refuses one that is not, so a
/// stalled hatch cannot make probes overlap: at most one is ever in flight, and
/// the bit is never older than one interval plus this.
const DEFAULT_HATCH_PROBE_DEADLINE: Duration = Duration::from_secs(5);

/// api's settings, as the host gave them or as this build defaults them.
pub struct Settings {
    pub session_ttl_secs: u64,
    /// How each fleet leg is dialed: one attempt's bound (`leg-dial-secs`) and
    /// the longest wait between attempts (`leg-retry-max-secs`).
    pub leg_dial: Dial,
    /// How long the hatch has to answer a pull (`pull-deadline-secs`).
    pub pull_deadline: Duration,
    /// How long the hatch has to answer an authorization
    /// (`authorize-deadline-secs`).
    pub authorize_deadline: Duration,
    /// How long the hatch has to answer one relayed KBS leg
    /// (`kbs-deadline-secs`).
    pub kbs_deadline: Duration,
    /// How long the hatch has to answer a certificate request
    /// (`vcek-deadline-secs`).
    pub vcek_deadline: Duration,
    /// How many times a failed certificate request is tried again before the
    /// guest stops (`vcek-retries`, `crate::endorsement::DEFAULT_VCEK_RETRIES`).
    /// Zero is a choice: the first failure stops it.
    pub vcek_retries: usize,
    /// How often the hatch bit is probed (`hatch-probe-secs`).
    pub hatch_probe: Duration,
    /// How long one probe waits (`hatch-probe-deadline-secs`).
    pub hatch_probe_deadline: Duration,
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
/// made, and a zero deadline would fail every call it bounds. `vcek-retries`
/// may be zero, and the leg's port limit and chunk are held to what chmux runs
/// with ([`LegSettings::refusal`]).
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
        vcek_deadline: secs(
            &mut launch,
            "vcek-deadline-secs",
            hatch_client::DEFAULT_VCEK_DEADLINE,
        ),
        vcek_retries: parsed(
            &mut launch,
            "vcek-retries",
            crate::endorsement::DEFAULT_VCEK_RETRIES,
        ),
        hatch_probe: secs(&mut launch, "hatch-probe-secs", DEFAULT_HATCH_PROBE),
        hatch_probe_deadline: secs(
            &mut launch,
            "hatch-probe-deadline-secs",
            DEFAULT_HATCH_PROBE_DEADLINE,
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
    if settings.hatch_probe_deadline >= settings.hatch_probe {
        safe_logger::error_and_panic!(
            "api: a hatch probe must end before the next one starts — its deadline under \
             its period. Stopping.",
            reason!("a constant, emitted once at boot before any request exists")
        );
    }
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
