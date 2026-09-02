//! The descriptor itself: opening it, and the one place bytes go out of it.
//!
//! The whole module is behind the `device` feature. A package that does not ask
//! for it gets no descriptor, no `emit`, and — the part that is checked by the
//! compiler rather than by a reviewer — no [`crate::info!`] to reach them with.

use std::sync::{Mutex, OnceLock};

/// Config key naming the device to write to. Absent means no output — the
/// ordinary case off a guest, where stderr already goes somewhere a developer
/// can read.
pub const DEVICE_KEY: &str = "ENCLAVID_LOG_DEVICE";

/// The opened device, if one was named.
///
/// The `Mutex` is what keeps two threads from splicing bytes into one line. It
/// is taken around a single `write` and nothing else — no formatting, no
/// foreign `Display` — so nothing under it can panic and it can never be
/// poisoned. That is the whole reason `logger::render` builds the line first.
///
/// No `unsafe impl Send`/`Sync` is needed: a `RawFd` is an `i32`.
static DEVICE: OnceLock<Mutex<Device>> = OnceLock::new();

struct Device {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
}

/// Set by [`crate::install_contained`]: this process has no outward tier of its
/// own, so an outward line is dropped rather than sent somewhere else.
///
/// It exists for the build where the feature is on and the posture is contained
/// anyway — which a whole-workspace build produces, since features unify across
/// one cargo invocation. Where each package is built on its own, as the image
/// does, a contained process has no `emit` compiled at all and this flag is
/// never read.
static CONTAINED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// See [`CONTAINED`]. Called by [`crate::install_contained`], which lives
/// outside this module because it must exist without the feature.
pub(crate) fn mark_contained() {
    CONTAINED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Write one rendered line out. The only place in the crate that touches the
/// descriptor.
///
/// Three cases, and the third is the one worth naming.
///
/// With a device, the bytes go to it. With no [`DEVICE_KEY`] they fall back to
/// stderr — a developer's terminal, and the `debug` image, whose command line
/// puts a real console on the port. On a production guest the device is always
/// named, so that fallback never runs there.
///
/// Under [`crate::install_contained`] they are DROPPED. The fallback would be
/// wrong there, and quietly: a line written as an [`crate::info!`], carrying a
/// [`crate::reason!`] that says why the HOST may see it, would end up on stderr
/// instead — a different destination with a different argument behind it. A
/// process with no outward tier should emit nothing outward, not something
/// sideways.
pub(crate) fn emit(line: &[u8]) {
    match DEVICE.get() {
        // `into_inner` rather than `unwrap`: poisoning cannot happen, because
        // nothing under this lock can panic — and if that ever stopped being
        // true, an `unwrap` would panic on the channel that reports panics.
        Some(device) => device.lock().unwrap_or_else(|e| e.into_inner()).write(line),
        None if CONTAINED.load(std::sync::atomic::Ordering::Relaxed) => {}
        None => {
            use std::io::Write;

            let _ = std::io::stderr().write_all(line);
        }
    }
}

/// Stand the channel up for a process that MAY speak to the host: take the
/// global logger slot, open the device, set the threshold.
///
/// Call it first in `main`, before anything that could want to say something.
/// Absent [`DEVICE_KEY`] leaves the descriptor unopened — that is a developer's
/// box, where stderr is already readable — but the slot is claimed either way,
/// because that half is about the `log` facade and not about any device.
///
/// Its counterpart is [`crate::install_contained`], and choosing between them is
/// the process saying which of the two it is. A role that serves the outside
/// world picks this one; a disposable child that holds a round's plaintext picks
/// the other — and, because that one is not behind the `device` feature, can be
/// built with no way to reach this function at all.
///
/// The threshold is set here and nowhere else, because it is configuration and
/// not an invariant: it belongs to starting the application, in one place, from
/// one source. The slot claim is the opposite — it is welded to
/// `DeviceLogger::claim` as well, so that it holds even for a process that never
/// calls either installer. The consequence is worth knowing: an OUTWARD line
/// emitted before this runs is dropped by `log`'s gate, which is shut until
/// opened. `debug!` does not go through that gate and works regardless.
///
/// A device that is named but cannot be opened ends the process, as does a
/// threshold that is named but cannot be read. There is no sensible way to
/// report either failure, which is precisely why they must not be survivable: a
/// role that was told to be observable and is not would run silently, and that
/// is the state this whole crate exists to remove.
pub fn install() {
    crate::logger::claim_the_global_slot();
    open_device();
    crate::logger::set_threshold_from_config();
}

#[cfg(target_os = "linux")]
fn open_device() {
    let Ok(device) = std::env::var(DEVICE_KEY) else {
        return;
    };
    let fd = unsafe {
        libc::open(
            std::ffi::CString::new(device)
                .expect("device path")
                .as_ptr(),
            // O_NOCTTY: a serial port is a terminal, and a session leader that
            // opens one without this adopts it as its controlling terminal.
            // That would give the far end — the host — a way to deliver
            // SIGINT/SIGQUIT/SIGHUP into this process group, turning a
            // write-only disclosure into something with a direction back.
            libc::O_WRONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        // Before the device exists there is nowhere to say why.
        std::process::exit(70);
    }
    let _ = DEVICE.set(Mutex::new(Device { fd }));
}

/// Off Linux there is no guest and no device: leave stdio alone so a developer
/// keeps their terminal.
#[cfg(not(target_os = "linux"))]
fn open_device() {}

#[cfg(target_os = "linux")]
impl Device {
    fn write(&self, line: &[u8]) {
        // Non-blocking, and a short write is not retried: a full device must
        // never stall the role, and losing the tail of a line under pressure is
        // the cheaper failure. The lock above is what keeps that loss confined
        // to one line instead of splicing two together.
        unsafe { libc::write(self.fd, line.as_ptr() as *const libc::c_void, line.len()) };
    }
}

#[cfg(not(target_os = "linux"))]
impl Device {
    fn write(&self, _line: &[u8]) {}
}
