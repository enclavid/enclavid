//! Who says a value may be disclosed, and how they say it.
//!
//! Nothing here writes anything. This is only the discipline: the wrapper a
//! value must be in to appear on a line, the function that makes one, and the
//! trait the macros bound on.

use enclavid_boundary::Reason;

/// A value the author has examined and vouched for. The only thing a log line
/// can carry.
///
/// There is no counterpart. Whether a value may be disclosed is knowable only
/// where it came from — an error's `Display` chain runs through types nobody
/// here wrote, and one link that renders the frame it failed to decode turns a
/// diagnostic into a disclosure. Working that out took an audit one full pass
/// per interpolated error in this tree, and two of the answers held only by way
/// of a default in someone else's crate.
///
/// So the rule is not "hide what you did not check" but "say only what you
/// did". Anything you cannot vouch for goes to `debug!`, which never leaves the
/// TEE at all — same visibility as a redaction, one mechanism instead of two,
/// and a production line with no `<redacted>` in it saying nothing.
pub struct Safe<'a, T: ?Sized>(&'a T);

/// Vouch for one value, with the reason it may be disclosed.
///
/// The reason belongs HERE and not on the line, because a line has several
/// values and they are safe for different reasons — or not all safe at all. One
/// reason covering a whole line has to be a claim about all of them at once,
/// and the way that fails is not that someone lies but that the sentence is
/// true of one value and false of the next:
///
/// ```ignore
/// reason!("the address and limits come from the measured command line")
/// //       ^ true of the address        ^ false of the limits, which are
/// //                                      compiled-in defaults
/// ```
///
/// That was the commonest finding of an audit of these sites. Bound to one
/// value, the sentence has nothing to be loose about.
pub fn safe<'a, T: ?Sized>(value: &'a T, _why: Reason) -> Safe<'a, T> {
    Safe(value)
}

/// What the log macros accept as an argument.
///
/// Two kinds of implementor, and a reviewer needs to know both exist — reading
/// only this crate would otherwise leave them thinking every value on the port
/// was vouched by a human at the site.
///
/// [`Safe`] is the per-SITE half: a value someone examined there, because
/// whether it may be disclosed depends on where it came from.
///
/// The per-TYPE half is for an error whose `Display` and `Debug` are a closed
/// vocabulary — safe always, so it says so once, next to those impls. One type
/// does today: `fleet_transport::LegFailure`, which carries only fieldless
/// variants and a `std::io::ErrorKind`. Grep `impl.*SafeToLog` across the
/// workspace to find them; there is no other way to enumerate this half, and
/// each one is a value that reaches the host with no `safe(..)` at the log
/// site.
///
/// The trait is deliberately not sealed, and the orphan rule is what keeps that
/// safe: an impl must live in the crate that owns the type, so no crate can
/// vouch for `rustls::Error`, `anyhow::Error`, or any other chain running
/// through types nobody here wrote (`E0117`). A type-wide vouch is therefore
/// always written by the author of the vocabulary it covers.
pub trait SafeToLog {}

impl<T: ?Sized> SafeToLog for Safe<'_, T> {}

/// Refuses anything that is not [`SafeToLog`]. The whole type check, in one
/// place.
#[doc(hidden)]
pub fn vouched<T: SafeToLog>(value: T) -> T {
    value
}

impl<T: std::fmt::Display + ?Sized> std::fmt::Display for Safe<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: std::fmt::Debug + ?Sized> std::fmt::Debug for Safe<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
