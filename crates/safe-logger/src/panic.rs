//! What a crash says, and how much of it.
//!
//! Behind the `device` feature, because what it says goes on the channel. A
//! contained process leaves the default hook in place: it writes to stderr,
//! which is where everything else that process says already goes.

/// Report panics on the channel, with or without naming where.
///
/// A panic's default hook writes to stderr, which on a guest is discarded, so
/// without this a crash is silent. The payload never travels either way:
/// `unwrap` on an arbitrary error formats that error, and what an error quotes
/// is not knowable from here.
///
/// `with_location` decides between `panic at <file>:<line>` and a bare
/// `panicked`, and the split follows who can steer the choice of site.
///
/// `file:line` is a constant of the measured image, so the strings are fixed
/// and public; what a reader learns is WHICH of them was reached, and that is
/// selected by control flow. In a role whose code is the measured code — api,
/// storage, the compile worker — the only party that could aim that selection
/// at a secret is whoever wrote the role, and rewriting the role changes the
/// measurement. There the location is free and worth having.
///
/// The execution worker is the exception and the reason this is a parameter: it
/// runs the consumer's policy, adversary-chosen wasm that executes inside the
/// measured image without altering it. A site reached because of what the
/// policy did is a site the policy chose. It passes `cfg!(feature = "debug")` —
/// off in the measured build, on in a debug one, which is a different
/// measurement no consumer pins and which already puts the whole kernel log on
/// the same port. Withholding a location there would cost diagnosis and protect
/// nothing.
///
/// Separate from [`crate::install`] so each name is true, and safe to forget: a
/// role that omits this call says less, never more.
#[cfg(target_os = "linux")]
pub fn install_panic(with_location: bool) {
    std::panic::set_hook(Box::new(move |info| {
        if !with_location {
            crate::error!(
                "panicked",
                crate::reason!("a constant; the payload is never rendered")
            );
            return;
        }
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        crate::error!(
            "panic at {}",
            crate::safe(
                &at,
                crate::reason!(
                    "a file:line fixed by the measured image; the role that executes the \
                     consumer's policy passes with_location = false, so no site here sits on a \
                     branch the policy selected"
                )
            ),
            crate::reason!("emitted only on a crash, which is not a per-session event")
        );
    }));
}

/// Off Linux the default hook already prints where a developer can read it.
#[cfg(not(target_os = "linux"))]
pub fn install_panic(_with_location: bool) {}
