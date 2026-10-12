//! What the rest of the guest reads of the clock the keeper keeps — whether the
//! kernel still vouches for it — and the guard every role runs on it.
//!
//! The keeper (this crate's binary) writes into the kernel, each time enough
//! servers agree, how far off the clock may be (`maxerror`), and clears the
//! kernel's "unsynchronised" bit. Left alone, the kernel adds 500 µs to that
//! figure every second (`kernel/time/ntp.c`, `MAXFREQ`), and past 16 s sets the
//! bit again. So any process can tell, without asking the keeper and without
//! privilege, how long it has been since the clock was last kept: a keeper that
//! died, hung, or lost its servers shows up as a growing `maxerror`.
//!
//! [`guard`] turns that into the role ending. The guest's PID 1 ends the guest
//! when its application ends (image/init/services), so a role on a clock nobody
//! keeps does not go on serving on it.

use std::time::Duration;

use safe_logger::{error, reason};

/// How far off the kernel may say its clock could be before a role stops
/// trusting it: 2 s.
///
/// A kept clock reads tens of milliseconds. The kernel's own growth takes it
/// from there to here in a little over an hour without an update, and the
/// keeper's longest wait between asking a server is some seventeen minutes.
///
/// The keeper holds itself to the same figure: once it has first set the
/// clock, a step larger than this ends it, since that step would show the clock
/// had been further off than every role took it to be.
pub const MAX_ERROR: Duration = Duration::from_secs(2);

/// How often [`guard`] asks.
const EVERY: Duration = Duration::from_secs(10);

/// How long [`guard`] waits before it asks again about a clock it found
/// wanting, and ends the role only if it still is.
const AGAIN: Duration = Duration::from_secs(1);

/// Why the clock is not trusted, in words of this crate's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Untrusted {
    /// The kernel calls its clock unsynchronised: nobody synchronised it, or
    /// nobody has updated it for long enough that the kernel stopped calling it
    /// synchronised.
    Unsynchronised,
    /// The kernel's error estimate is past [`MAX_ERROR`]: the clock was kept,
    /// and has not been for too long.
    Drifted,
    /// The kernel could not be asked.
    Unreadable(std::io::ErrorKind),
}

impl std::fmt::Display for Untrusted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Untrusted::Unsynchronised => f.write_str("the kernel calls its clock unsynchronised"),
            Untrusted::Drifted => f.write_str(
                "the clock has not been kept for long enough that it may be off by more than 2 s",
            ),
            Untrusted::Unreadable(kind) => {
                write!(f, "the kernel's clock status could not be read ({kind:?})")
            }
        }
    }
}

// Every arm writes a literal or the name of an `ErrorKind`, a fieldless enum.
impl safe_logger::SafeToLog for Untrusted {}

/// Whether the kernel vouches for its clock now.
pub fn check() -> Result<(), Untrusted> {
    let (status, max_error) = kernel_clock()?;
    judge(status, max_error)
}

/// The judgement, apart from the asking: the kernel's status bits and its error
/// estimate in microseconds.
fn judge(status: i32, max_error_us: i64) -> Result<(), Untrusted> {
    const STA_UNSYNC: i32 = 0x0040;
    if status & STA_UNSYNC != 0 {
        return Err(Untrusted::Unsynchronised);
    }
    if max_error_us < 0 || max_error_us as u128 > MAX_ERROR.as_micros() {
        return Err(Untrusted::Drifted);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn kernel_clock() -> Result<(i32, i64), Untrusted> {
    // SAFETY: an all-zero `timex` is a valid value (every field an integer),
    // and `modes = 0` asks only to read, which needs no privilege.
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: `timex` is a live, writable `timex` for the whole call.
    if unsafe { libc::adjtimex(&mut timex) } == -1 {
        return Err(Untrusted::Unreadable(
            std::io::Error::last_os_error().kind(),
        ));
    }
    Ok((timex.status, timex.maxerror as i64))
}

#[cfg(not(target_os = "linux"))]
fn kernel_clock() -> Result<(i32, i64), Untrusted> {
    Err(Untrusted::Unreadable(std::io::ErrorKind::Unsupported))
}

/// End the process unless the kernel vouches for its clock — now, and then
/// every ten seconds for as long as the process lives.
///
/// For a role's measured build, called first thing in `main`: by then the
/// keeper has synchronised the clock (dinit starts no role before), so a first
/// check that fails means something is already wrong. Off a guest there is no
/// keeper, and nothing should call this.
///
/// It ends the process with `exit`, not a panic: a panic on the guard's thread
/// would end that thread, and the role would go on serving on the clock it had
/// just found wanting.
pub fn guard() {
    if let Err(why) = check_twice() {
        end(why);
    }
    std::thread::Builder::new()
        .name("trusted-time".into())
        .spawn(|| {
            loop {
                std::thread::sleep(EVERY);
                if let Err(why) = check_twice() {
                    end(why);
                }
            }
        })
        .expect("a thread starts at boot");
}

/// [`check`], and when it fails, again [`AGAIN`] later: only the second answer
/// counts. When the keeper steps the clock, the kernel calls it unsynchronised,
/// with an error of 16 s, for the moment until the keeper restores both; a read
/// that lands in that moment is no reason to end a role. What [`guard`] is for
/// — a clock nobody keeps — lasts far longer than a second.
fn check_twice() -> Result<(), Untrusted> {
    check().or_else(|_| {
        std::thread::sleep(AGAIN);
        check()
    })
}

fn end(why: Untrusted) -> ! {
    error!(
        "trusted-time: {}; ending, and the guest with it",
        why,
        reason!("emitted once, as the guest stops")
    );
    std::process::exit(70)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STA_UNSYNC: i32 = 0x0040;
    const STA_PLL: i32 = 0x0001;

    #[test]
    fn a_kept_clock_is_trusted() {
        assert_eq!(judge(0, 25_000), Ok(()));
        assert_eq!(judge(STA_PLL, 2_000_000), Ok(()));
    }

    #[test]
    fn an_unsynchronised_clock_is_not() {
        assert_eq!(judge(STA_UNSYNC, 0), Err(Untrusted::Unsynchronised));
    }

    #[test]
    fn a_clock_kept_too_long_ago_is_not() {
        assert_eq!(judge(0, 2_000_001), Err(Untrusted::Drifted));
        assert_eq!(judge(0, -1), Err(Untrusted::Drifted));
    }
}
