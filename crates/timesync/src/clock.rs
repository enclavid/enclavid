//! The kernel clock: what the algorithm steers, and the two facts about it this
//! process checks rather than assumes — which clocksource it reads, and that it
//! starts no earlier than this build.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use clock_steering::unix::UnixClock;
use clock_steering::{Clock as _, LeapIndicator, TimeOffset};
use ntp_proto::{NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp};
use safe_logger::{info, reason};

/// Seconds from the NTP era to the Unix epoch.
const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

/// The earliest the clock may read when the keeper starts: 2026-10-11, a day
/// this tree existed on.
///
/// The clock starts at whatever the host's emulated RTC said, and it is the
/// clock the key exchange checks certificates against. A host that started it
/// years back could present a certificate that was valid then and whose key has
/// since leaked; with this, only certificates still valid after this date are.
const NOT_BEFORE: i64 = 1_791_676_800;

/// Where the kernel names the clocksource it reads time from.
const CLOCKSOURCE: &str = "/sys/devices/system/clocksource/clocksource0/current_clocksource";

/// Where the kernel names every clocksource it could move to.
const AVAILABLE: &str = "/sys/devices/system/clocksource/clocksource0/available_clocksource";

/// Whether the TSC is the only clocksource the kernel has. The kernel leaves the
/// TSC at run time when anything marks it unstable, and the guest's timers stop
/// with whatever it moves to — the checks on which clocksource it reads among
/// them, so they cannot be what catches that. What does is there being nothing
/// to move to, which the measured kernel and command line arrange; this checks
/// they did.
pub fn only_tsc() -> std::io::Result<bool> {
    Ok(std::fs::read_to_string(AVAILABLE)?.trim_ascii() == "tsc")
}

/// CLOCK_REALTIME, as the synchronisation algorithm steers it. Nothing here
/// decides anything: ntp-proto decides what to change and when, and this hands
/// it to the kernel.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock;

const CLOCK: UnixClock = UnixClock::CLOCK_REALTIME;

/// Set once the algorithm first reports a known leap state — the moment it
/// clears the kernel's "unsynchronised" bit, and the keeper tells dinit it has
/// started.
static SYNCHRONISED: AtomicBool = AtomicBool::new(false);

/// The leap state the algorithm last set, which is also whether it left the
/// kernel calling its clock synchronised. `None` until it first sets one.
static LEAP: Mutex<Option<LeapIndicator>> = Mutex::new(None);

fn to_ntp(ts: clock_steering::Timestamp) -> NtpTimestamp {
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        EPOCH_OFFSET.wrapping_add(ts.seconds as _),
        ts.nanos,
    )
}

impl NtpClock for SystemClock {
    type Error = clock_steering::unix::Error;

    fn now(&self) -> Result<NtpTimestamp, Self::Error> {
        CLOCK.now().map(to_ntp)
    }

    fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error> {
        CLOCK.set_frequency(freq * 1e6).map(to_ntp)
    }

    fn get_frequency(&self) -> Result<f64, Self::Error> {
        CLOCK.get_frequency().map(|ppm| ppm * 1e-6)
    }

    fn step_clock(&self, offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
        let (seconds, nanos) = offset.as_seconds_nanos();
        let stepped = CLOCK.step_clock(TimeOffset {
            seconds: seconds as _,
            nanos,
        })?;
        // A step makes the kernel call its clock unsynchronised, with an error
        // of 16 s (`ntp_clear`). The algorithm writes a new error estimate
        // straight after, but sets the leap state only when the servers agree
        // on one; so the state it last set goes back here, or a step taken
        // while they disagree would leave every role's guard reading an
        // unsynchronised clock until the next agreement.
        let leap = *LEAP.lock().expect("the lock is never held across a panic");
        if let Some(leap) = leap {
            CLOCK.set_leap_seconds(leap)?;
        }
        Ok(to_ntp(stepped))
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        CLOCK.disable_kernel_ntp_algorithm()
    }

    fn error_estimate_update(
        &self,
        est_error: NtpDuration,
        max_error: NtpDuration,
    ) -> Result<(), Self::Error> {
        CLOCK.error_estimate_update(
            std::time::Duration::from_secs_f64(est_error.to_seconds()),
            std::time::Duration::from_secs_f64(max_error.to_seconds()),
        )
    }

    fn status_update(&self, leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
        let leap = match leap_status {
            NtpLeapIndicator::NoWarning => LeapIndicator::NoWarning,
            NtpLeapIndicator::Leap61 => LeapIndicator::Leap61,
            NtpLeapIndicator::Leap59 => LeapIndicator::Leap59,
            NtpLeapIndicator::Unknown | NtpLeapIndicator::Unsynchronized => LeapIndicator::Unknown,
        };
        CLOCK.set_leap_seconds(leap)?;
        *LEAP.lock().expect("the lock is never held across a panic") = Some(leap);
        if leap != LeapIndicator::Unknown && !SYNCHRONISED.swap(true, Ordering::Relaxed) {
            info!(
                "timesync: the clock is synchronised",
                reason!("a constant, emitted once per boot")
            );
            crate::ready::notify();
        }
        Ok(())
    }
}

/// Which clocksource the kernel reads time from, through a descriptor opened
/// once: the keeper asks again every second, by then from under a syscall
/// filter that lets it open nothing.
///
/// The answer has to be the TSC. Secure TSC is what makes the TSC the guest's
/// own: the host fixed its rate at launch, in the measurement, and cannot move
/// it after. Every other clocksource a guest can have is a device the host
/// emulates. The command line asks for the TSC, but the kernel leaves it — after
/// boot too — when it judges the TSC unstable, and part of what it judges by is
/// what the host tells it. So this is checked, not assumed: once before the
/// clock is trusted, and again for as long as it is kept.
pub struct Clocksource(std::fs::File);

impl Clocksource {
    pub fn open() -> std::io::Result<Self> {
        std::fs::File::open(CLOCKSOURCE).map(Clocksource)
    }

    /// Whether it is the TSC now. Read from the start every time: sysfs
    /// renders the attribute afresh for a read at offset 0.
    pub fn is_tsc(&self) -> std::io::Result<bool> {
        let mut name = [0u8; 32];
        let n = std::os::unix::fs::FileExt::read_at(&self.0, &mut name, 0)?;
        Ok(name[..n].trim_ascii() == b"tsc")
    }
}

/// Move the clock forward to [`NOT_BEFORE`] if it reads earlier. Whether it
/// had to.
pub fn raise_to_floor() -> Result<bool, clock_steering::unix::Error> {
    let now = CLOCK.now()?;
    let behind = NOT_BEFORE - now.seconds;
    if behind <= 0 {
        return Ok(false);
    }
    CLOCK.step_clock(TimeOffset {
        seconds: behind as _,
        nanos: 0,
    })?;
    Ok(true)
}
