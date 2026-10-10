//! What the host decides about this worker at launch, outside its measurement
//! (`fleet_transport::launch`): how many rounds it runs and how much each may
//! hold, how long it waits on what, and how it holds up its own end of its legs.
//!
//! None of them reaches what a round discloses or how its traffic is shaped for
//! the host: the framing that holds a round's sizes constant, the policy's state
//! cap and the consent limits are the build's (`engine_types::limits`). These
//! are the service's capacity. The round's memory max and fuel are the two whose
//! value a round can cross, and what the host learns from choosing them is set
//! out there.

use std::time::Duration;

use engine_executor::DEFAULT_ROUND_FUEL;
use engine_executor::admission::{
    DEFAULT_BASE_RESERVE_BYTES, DEFAULT_BUNDLE_CACHE_ENTRIES, DEFAULT_CAPACITY_WAIT_SECS,
    DEFAULT_ROUND_HEADROOM_BYTES, DEFAULT_ROUND_MAX_BYTES, DEFAULT_WAITING_PER_CHILD,
};
use engine_rpc::{
    DEFAULT_BUNDLE_STREAM_DEADLINE, DEFAULT_BUNDLE_STREAM_IDLE, DEFAULT_CALLBACK_REQUEST_BUFFER,
    DEFAULT_REQUEST_BUFFER, LegSettings, MAX_BUNDLE_META_BYTES, MAX_CWASM_BYTES,
};
use engine_supervisor::{ChildTimes, DEFAULT_CHILD_MAX_TASKS};
use fleet_transport::DEFAULT_ACCEPT_RETRY;
use fleet_transport::launch::{LaunchError, Settings as Launch};
use safe_logger::{reason, safe};

use crate::bundles::{MAX_IDLE, fill_charge};

/// Wall-clock limit on ONE round in the child (the `round-deadline-secs`
/// setting; enforced by the [`engine_supervisor::ChildRunner`]). A child that
/// WEDGES rather than crashes — an escaped payload that keeps its remoc reactor
/// answering keepalives while parking the `run`, or a hung upstream callback —
/// would otherwise hold its child-slot permit forever and, after `max_children`
/// such rounds, starve the WHOLE worker (the exact whole-worker blast radius this
/// split exists to bound; remoc has a dead-transport timeout but NO per-request
/// deadline). On expiry the runner kills the child and we surface
/// `ExecError::Unknown` so api returns 5xx and the applicant retries against
/// intact api-side state. Not `Policy`, even though a hanging policy is one way to
/// reach this: a spawn failure arrives the same way and is ours, and this side
/// cannot tell them apart.
/// Generous so no legitimately slow round (ML inference, OCR) is false-killed.
const DEFAULT_ROUND_DEADLINE_SECS: u64 = 120;

/// Default L1 (memfd cwasm-cache) RAM budget (the `bundle-cache-bytes`
/// setting). The cache is weighed by what
/// an entry RETAINS, so this is a BYTE limit, not an entry count: each cwasm is
/// ~10-15 MiB of memfd RAM, so an entry-count cap would nominally admit >100 GB,
/// and an authenticated consumer minting many distinct `composition_key`s could
/// OOM the supervisor (crashing every concurrent in-flight round). 4 GiB holds
/// two compositions carrying a gigabyte of data each beside about a hundred
/// ordinary ones. It is reserved whole out of this guest's memory before
/// the round children's total is set (see `children_total`), so a larger cache is
/// a smaller total. It holds the fills streaming into the cache as well as its
/// entries: a fill reserves what it will hold out of it before its first byte.
///
/// A byte budget alone is not the whole bound, because an entry costs a DESCRIPTOR
/// as well as RAM and a degenerate cwasm costs no RAM at all. What closes that is
/// [`engine_executor::admission`]: entries are charged a floor derived from this
/// number and the entry count (`bundle-cache-entries`), and a bundle that is not a
/// composition never becomes one. And an entry is charged its metadata as well as
/// its cwasm (see [`crate::bundles::entry_charge`]), so what an entry also keeps
/// is inside this limit rather than beside it.
///
/// The cache is also where a round's cwasm is when the round runs: the child maps
/// the entry's memfd rather than a copy of it, and the entry stays in the budget
/// until that child has exited (see [`crate::bundles`]). So the budget is what the
/// bundles in use can take together, and a budget that cannot hold a fill of the
/// largest bundle could never run that bundle — the worker does not boot with
/// one (see [`fill_charge`]); about 1.6 GiB is the least it takes.
const DEFAULT_BUNDLE_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// How many round children may run at once unless the host says otherwise
/// (the `max-children` setting). A count, not a memory figure:
/// what the children take in memory the kernel holds them to, and what the count
/// bounds is what memory does not — how many rounds share the guest's CPUs,
/// the descriptors and tasks each slot holds, and the share of this process each
/// child is reserved (`supervisor_per_child`), which comes out of the
/// children's total before any child runs.
///
/// Twelve, because twelve rounds on the guest's eight CPUs are already one and
/// a half to each, beside the supervisor's own work. Against a 10 GiB guest, which its kernel reports as 9000 MiB, that
/// leaves the children about 3.8 GiB at the other defaults — room for eleven
/// rounds at the headroom beside one at its max with some 2 GiB to spare, so
/// one round growing to its max does not by itself reach the total and take a
/// neighbour with it. An availability setting: a guest whose kernel reports
/// below about 5.4 GiB does not boot with it, and below about 6.5 GiB the count
/// is more than the memory holds at the headroom, so rounds past what it holds
/// answer busy.
const DEFAULT_MAX_CHILDREN: usize = 12;

// The default cache holds a fill of the largest bundle the execute hop accepts.
const _: () = assert!(
    fill_charge(MAX_CWASM_BYTES, MAX_BUNDLE_META_BYTES) <= DEFAULT_BUNDLE_CACHE_BYTES,
    "the default cache has no room for the largest bundle"
);

/// The worker's settings, as the host gave them or as this build defaults them.
pub(crate) struct Settings {
    pub(crate) max_children: usize,
    pub(crate) waiting_per_child: usize,
    pub(crate) bundle_cache_bytes: u64,
    /// How many entries the cache may hold (`bundle-cache-entries`,
    /// [`DEFAULT_BUNDLE_CACHE_ENTRIES`]).
    pub(crate) bundle_cache_entries: u64,
    /// How long an entry no round has used stays (`bundle-idle-secs`, at most
    /// and by default [`MAX_IDLE`]).
    pub(crate) bundle_idle: Duration,
    pub(crate) base_reserve: u64,
    pub(crate) round_max: u64,
    pub(crate) round_headroom: u64,
    pub(crate) round_deadline: Duration,
    pub(crate) round_fuel: u64,
    pub(crate) capacity_wait: Duration,
    pub(crate) bundle_stream: Duration,
    pub(crate) bundle_stream_idle: Duration,
    /// How many tasks one child may have alive (`child-max-tasks`,
    /// [`DEFAULT_CHILD_MAX_TASKS`]).
    pub(crate) child_max_tasks: u64,
    /// How long the runner waits on a child where the round's deadline does not
    /// reach (`child-exit-wait-secs`, `child-connect-secs`, `room-poll-ms`).
    pub(crate) child_times: ChildTimes,
    /// How many of api's requests may wait on its connection
    /// (`request-buffer`, [`DEFAULT_REQUEST_BUFFER`]).
    pub(crate) request_buffer: usize,
    /// How many of a child's callbacks may wait on the relay
    /// (`callback-request-buffer`, [`DEFAULT_CALLBACK_REQUEST_BUFFER`]).
    pub(crate) callback_request_buffer: usize,
    /// This end of api's legs (`leg-timeout-secs`, `leg-max-ports`,
    /// `leg-chunk-bytes`, `leg-receive-bytes`).
    pub(crate) leg: LegSettings,
    /// How long a listener waits after an accept this process could not
    /// complete (`accept-retry-ms`, [`DEFAULT_ACCEPT_RETRY`]).
    pub(crate) accept_retry: Duration,
}

/// The host's settings for this guest, read once — every round it runs has the
/// same ones — or no boot. A key the worker does not know, one given twice, a
/// value that does not parse, or a value with which the worker could run
/// nothing stops it rather than falling back to a default: a value the host
/// wrote and got wrong is not a request for the default.
///
/// What is checked here is what each value means alone or beside another
/// setting. What the guest's memory holds of them is checked where the memory
/// is read.
pub(crate) fn load() -> Settings {
    let mut launch = Launch::load("execution-worker").unwrap_or_else(|e| refused(e));
    let leg = LegSettings::default();
    let child_times = ChildTimes::default();
    let settings = Settings {
        max_children: setting(&mut launch, "max-children", DEFAULT_MAX_CHILDREN),
        waiting_per_child: setting(&mut launch, "waiting-per-child", DEFAULT_WAITING_PER_CHILD),
        bundle_cache_bytes: setting(
            &mut launch,
            "bundle-cache-bytes",
            DEFAULT_BUNDLE_CACHE_BYTES,
        ),
        bundle_cache_entries: setting(
            &mut launch,
            "bundle-cache-entries",
            DEFAULT_BUNDLE_CACHE_ENTRIES,
        ),
        bundle_idle: secs(&mut launch, "bundle-idle-secs", MAX_IDLE),
        base_reserve: setting(
            &mut launch,
            "base-reserve-bytes",
            DEFAULT_BASE_RESERVE_BYTES,
        ),
        round_max: setting(&mut launch, "round-max-bytes", DEFAULT_ROUND_MAX_BYTES),
        round_headroom: setting(
            &mut launch,
            "round-headroom-bytes",
            DEFAULT_ROUND_HEADROOM_BYTES,
        ),
        round_deadline: secs(
            &mut launch,
            "round-deadline-secs",
            Duration::from_secs(DEFAULT_ROUND_DEADLINE_SECS),
        ),
        round_fuel: setting(&mut launch, "round-fuel", DEFAULT_ROUND_FUEL),
        capacity_wait: secs(
            &mut launch,
            "capacity-wait-secs",
            Duration::from_secs(DEFAULT_CAPACITY_WAIT_SECS),
        ),
        bundle_stream: secs(
            &mut launch,
            "bundle-stream-secs",
            DEFAULT_BUNDLE_STREAM_DEADLINE,
        ),
        bundle_stream_idle: secs(
            &mut launch,
            "bundle-stream-idle-secs",
            DEFAULT_BUNDLE_STREAM_IDLE,
        ),
        child_max_tasks: setting(&mut launch, "child-max-tasks", DEFAULT_CHILD_MAX_TASKS),
        child_times: ChildTimes {
            exit_wait: secs(&mut launch, "child-exit-wait-secs", child_times.exit_wait),
            connect: secs(&mut launch, "child-connect-secs", child_times.connect),
            room_poll: millis(&mut launch, "room-poll-ms", child_times.room_poll),
        },
        request_buffer: setting(&mut launch, "request-buffer", DEFAULT_REQUEST_BUFFER),
        callback_request_buffer: setting(
            &mut launch,
            "callback-request-buffer",
            DEFAULT_CALLBACK_REQUEST_BUFFER,
        ),
        leg: LegSettings {
            timeout: secs(&mut launch, "leg-timeout-secs", leg.timeout),
            max_ports: setting(&mut launch, "leg-max-ports", leg.max_ports),
            chunk_bytes: setting(&mut launch, "leg-chunk-bytes", leg.chunk_bytes),
            receive_bytes: setting(&mut launch, "leg-receive-bytes", leg.receive_bytes),
        },
        accept_retry: millis(&mut launch, "accept-retry-ms", DEFAULT_ACCEPT_RETRY),
    };
    launch.finish().unwrap_or_else(|e| refused(e));
    settings.check();
    settings
}

impl Settings {
    fn check(&self) {
        // Counts and times that leave the worker nothing to run with. Zero
        // waiting rounds and a zero capacity wait are not among them: those
        // answer busy sooner, which is a choice.
        if self.max_children == 0
            || self.bundle_cache_entries == 0
            || self.round_deadline.is_zero()
            || self.round_fuel == 0
            || self.bundle_stream.is_zero()
            || self.bundle_stream_idle.is_zero()
            || self.child_max_tasks == 0
            || self.child_times.exit_wait.is_zero()
            || self.child_times.connect.is_zero()
            || self.child_times.room_poll.is_zero()
            || self.request_buffer == 0
            || self.callback_request_buffer == 0
            || self.accept_retry.is_zero()
        {
            safe_logger::error_and_panic!(
                "execution-worker: a child bound, a cache entry count, a round deadline, \
                 round fuel, a bundle stream deadline or idle limit, a child task cap, a \
                 child exit wait, handshake or room poll time, a request buffer or an accept \
                 retry of zero runs nothing; each must be above it. Stopping.",
                reason!("a constant, emitted once at boot before any request exists")
            );
        }

        // How soon an unused composition goes is the host's to choose; how long
        // it may stay is the build's.
        if self.bundle_idle.is_zero() || self.bundle_idle > MAX_IDLE {
            safe_logger::error_and_panic!(
                "execution-worker: a bundle idle time of {}s must be above zero and at most \
                 {}s. Stopping.",
                safe(
                    &self.bundle_idle.as_secs(),
                    reason!("the host's own setting, or this build's default")
                ),
                safe(
                    &MAX_IDLE.as_secs(),
                    reason!("a constant of the measured build")
                ),
                reason!("a constant, emitted once at boot before any request exists")
            );
        }

        if let Some(refusal) = self.leg.refusal() {
            safe_logger::error_and_panic!(
                "execution-worker: {} cannot hold a leg up. Stopping.",
                safe(
                    &refusal,
                    reason!("a constant naming which of this role's settings")
                ),
                reason!("a constant, emitted once at boot before any request exists")
            );
        }

        // A round runs its cwasm from the cache, so a cache that cannot take the
        // largest bundle could never run it.
        let largest_fill = fill_charge(MAX_CWASM_BYTES, MAX_BUNDLE_META_BYTES);
        if self.bundle_cache_bytes < largest_fill {
            safe_logger::error_and_panic!(
                "execution-worker: a {} MiB bundle cache cannot hold the {} MiB the largest \
                 bundle takes while it streams in, and a round runs its bundle from the \
                 cache. Give the cache at least that. Stopping.",
                safe(
                    &(self.bundle_cache_bytes >> 20),
                    reason!("the host's own setting, or this build's default")
                ),
                safe(
                    &largest_fill.div_ceil(1 << 20),
                    reason!("derived from constants of the measured build")
                ),
                reason!("a constant, emitted once at boot before any request exists")
            );
        }

        // The room a child needs to start must be above zero — there is nothing
        // to divide by below otherwise — and within a round's max, or no child
        // could ever start.
        if self.round_headroom == 0 || self.round_headroom > self.round_max {
            safe_logger::error_and_panic!(
                "execution-worker: a {} MiB round headroom must be above zero and within \
                 the {} MiB round max. Stopping.",
                safe(
                    &(self.round_headroom >> 20),
                    reason!("the host's own setting, or this build's default")
                ),
                safe(
                    &(self.round_max >> 20),
                    reason!("the host's own setting, or this build's default")
                ),
                reason!("a constant, emitted once at boot before any request exists")
            );
        }
    }
}

/// The setting `key` the host gave at launch: `default` when it gave none, and
/// no boot when it gave one that does not parse.
fn setting<T: std::str::FromStr>(launch: &mut Launch, key: &'static str, default: T) -> T {
    match launch.take(key) {
        None => default,
        Some(value) => value.parse().unwrap_or_else(|_| {
            safe_logger::error_and_panic!(
                "execution-worker: the setting {} does not parse. Stopping.",
                safe(
                    &key,
                    reason!("a constant naming one of this role's settings")
                ),
                reason!("a constant, emitted once at boot before any request exists")
            )
        }),
    }
}

/// A setting given in whole seconds.
fn secs(launch: &mut Launch, key: &'static str, default: Duration) -> Duration {
    Duration::from_secs(setting(launch, key, default.as_secs()))
}

/// A setting given in milliseconds.
fn millis(launch: &mut Launch, key: &'static str, default: Duration) -> Duration {
    let default = u64::try_from(default.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(setting(launch, key, default))
}

/// The host's launch settings could not be taken as given.
fn refused(e: LaunchError) -> ! {
    safe_logger::error_and_panic!(
        "execution-worker: {}. Stopping.",
        e,
        reason!("a constant, emitted once at boot before any request exists")
    )
}

#[cfg(test)]
mod tests {
    use engine_executor::admission::{
        DEFAULT_BASE_RESERVE_BYTES, DEFAULT_ROUND_HEADROOM_BYTES, DEFAULT_ROUND_MAX_BYTES,
        DEFAULT_WAITING_PER_CHILD, children_total,
    };

    use super::{DEFAULT_BUNDLE_CACHE_BYTES, DEFAULT_MAX_CHILDREN};

    /// The default child bound against the guest it was chosen for: a 10 GiB
    /// launch, which its kernel reports as 9000 MiB. Every round but one at the
    /// headroom and that one at its max fit the children's total, so one round
    /// growing to its max does not by itself reach the total.
    #[test]
    fn the_default_bound_fits_a_10_gib_guest() {
        const REPORTED: u64 = 9000 * 1024 * 1024;
        let total = children_total(
            REPORTED,
            DEFAULT_BUNDLE_CACHE_BYTES,
            DEFAULT_BASE_RESERVE_BYTES,
            DEFAULT_MAX_CHILDREN as u64,
            DEFAULT_WAITING_PER_CHILD,
        );
        assert!(
            total
                >= DEFAULT_ROUND_MAX_BYTES
                    + (DEFAULT_MAX_CHILDREN as u64 - 1) * DEFAULT_ROUND_HEADROOM_BYTES,
            "{} MiB for the children",
            total >> 20
        );
    }
}
