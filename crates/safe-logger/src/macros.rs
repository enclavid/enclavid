//! The six macros. Everything a caller of this crate writes is here.
//!
//! `#[macro_export]` puts them at the crate root regardless of which file they
//! sit in, so this module exists only to keep them together for reading.
//!
//! The outward five — [`info!`], [`warn!`], [`error!`], `__line!` and
//! [`error_and_panic!`] — are behind the `device` feature. In a package that
//! did not ask for it they do not exist, and writing one is
//! `cannot find macro `info` in crate `safe_logger``. That error is the point:
//! a process with no channel to the host should not be able to compile a line
//! addressed to it. [`debug!`] and [`trace!`] are unconditional — they go to
//! stderr, which never leaves the TEE.

/// Log one line to the host, with the reason it carries no hidden bandwidth.
///
/// Named `info!` rather than `log!` for two reasons: it is the word every Rust
/// programmer already reads, and `log!` would collide with the `log` crate this
/// one depends on.
///
/// ```ignore
/// info!("api: alive", reason!("a constant"));
/// info!(
///     "api: listening on vsock://*:{}",
///     safe(&port, reason!("on the measured command line")),
///     reason!("a constant, emitted once at boot"),
/// );
/// ```
///
/// **Two refusals, both by the compiler, and between them nothing unvouched can
/// get out.** An argument that is not [`crate::SafeToLog`] does not compile. A
/// name captured inside the format string does not resolve, because the literal
/// reaches `format_args!` through `concat!` and so carries this crate's span
/// rather than the caller's — see the crate docs.
///
/// A named argument (`info!("{x}", x = ..)`) does not work either, for the same
/// reason and by the same error. Pass values positionally.
///
/// Two reasons per line, because there are two questions. Each value carries its
/// own, written where someone knows the answer. The line carries one for its
/// constant text and for whether the line APPEARING says anything.
#[cfg(feature = "device")]
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => { $crate::__line!($crate::Level::Info, $($arg)+) };
}

/// [`info!`], marked as something that went wrong but is being handled.
#[cfg(feature = "device")]
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => { $crate::__line!($crate::Level::Warn, $($arg)+) };
}

/// [`info!`], marked as something that went wrong and is not being handled.
#[cfg(feature = "device")]
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => { $crate::__line!($crate::Level::Error, $($arg)+) };
}

/// The shared body: wrap every argument, refuse a capture, hand the line to the
/// device sink.
///
/// A muncher, because the reason sits last and the arguments before it are
/// variadic — `$(, $arg:expr)* , $reason:expr` is ambiguous to `macro_rules!`,
/// which cannot tell the final argument from the reason. `@a` walks the tokens
/// into an accumulator, wrapping each argument, until one expression is left.
///
/// The whole thing expands at the CALL SITE, which is what makes the record
/// honest: `log`'s own `module_path!()` and `loc()` land in the caller's crate
/// and report it, rather than reporting this crate's internals as they would if
/// a function of ours sat in between. That is also why there is no
/// `#[track_caller]` anywhere — nothing to see through.
#[doc(hidden)]
#[cfg(feature = "device")]
#[macro_export]
macro_rules! __line {
    // Only the reason is left. The optional trailing comma is what a multi-line
    // call is naturally written with; without it this rule fails to match and
    // the error names an internal meta-variable.
    (@a $lvl:expr, [$($acc:tt)*] $reason:expr $(,)?) => {{
        // The reason is a compile-time marker: `Reason` is a ZST whose field is
        // private, so this binding is what forces a `reason!(..)` at the site.
        // It carries nothing to run and nothing to print.
        let _: $crate::Reason = $reason;
        $crate::__log::log!(
            logger: $crate::DeviceLogger::claim(),
            $lvl,
            $($acc)*
        );
    }};
    // One argument: wrapped, so anything that is not `safe(..)` fails to build.
    (@a $lvl:expr, [$($acc:tt)*] $e:expr, $($rest:tt)+) => {
        $crate::__line!(@a $lvl, [$($acc)* , $crate::vouched($e)] $($rest)+)
    };
    // `concat!` is what refuses an inline capture, and rustc's own name
    // resolution is what does the refusing — see the crate docs.
    ($lvl:expr, $fmt:literal $(, $($rest:tt)+)?) => {
        $crate::__line!(@a $lvl, [concat!($fmt)] $($($rest)+)?)
    };
}

/// Say why on the channel, then stop the process. [`crate::error!`] and a panic
/// in one, for a failure the guest cannot continue past.
///
/// ```ignore
/// let addr = std::env::var(KEY).unwrap_or_else(|e| {
///     debug!("{e}");
///     safe_logger::error_and_panic!(
///         "api: ENCLAVID_STORAGE_ADDR is not set. Stopping.",
///         reason!("a constant naming a configuration key the host itself supplied"),
///     )
/// });
/// ```
///
/// It exists because a bare `expect` is MUTE on a guest. Its message goes into
/// the panic payload, and [`crate::install_panic`] never forwards a payload —
/// deliberately, since a payload can carry anything. So the operator gets
/// `panic at main.rs:158` and no reason, for exactly the class of failure where
/// the reason is the whole point: a role that will not start.
///
/// The panic is kept rather than replaced by `exit`, because the two carry
/// different halves. The [`crate::error!`] says WHAT is wrong; the panic hook
/// adds WHERE. An exit code would carry neither: nothing reads it on a guest,
/// where PID 1 powers the machine off when the application ends either way. An
/// exit code earns its keep only before the channel exists — which is why
/// `device::open_device` still uses one.
///
/// The cause, if there is one, belongs in a [`crate::debug!`] beside the call.
/// It cannot come in here: this line is vouched and a cause is not.
///
/// The expansion diverges, so it type-checks anywhere a value is expected —
/// `unwrap_or_else`, a `match` arm, the tail of a function.
///
/// Named for what it does rather than for a severity. `panic!` was the first
/// choice and is the wrong one twice over: it would stop `grep panic!` from
/// meaning the language's, blinding any analysis that counts them, and a macro
/// of that name shadows the prelude's in whichever module imports it. `fatal!`
/// would grep cleanly but names a level this crate does not have — the ladder
/// here is a CHANNEL, not a severity. This says the two things it does, in the
/// order it does them.
#[cfg(feature = "device")]
#[macro_export]
macro_rules! error_and_panic {
    ($($arg:tt)+) => {{
        $crate::error!($($arg)+);
        // The payload never leaves a guest; the hook's `file:line` does. On a
        // developer's box `install_panic` is a no-op and the default hook prints
        // this, by which point the `error!` above has already said more.
        ::std::panic!("stopping — see the preceding line");
    }};
}

/// Say something on the way to a developer, never to the host.
///
/// Goes to stderr, which a production guest discards — and under a build
/// without `debug` the call is not compiled at all, so the strings are not in
/// the binary and nothing runs. That second half is why this needs no reason:
/// there is nothing to disclose, by construction rather than by a console
/// setting being right.
///
/// The level here says which CHANNEL, not how bad it is: `Debug` and `Trace` do
/// not leave the TEE, `Info` and above do. That is not what a level means
/// anywhere else in Rust, which is why it is said twice.
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! debug {
    // Not through `log::log!`, unlike the outward macros. That form tests
    // `max_level()`, which starts shut and is opened only by an installer — so a
    // process that never installs would silently lose every `debug!`, including
    // one written on the way to deciding whether to install. Nothing here leaves
    // the TEE, so there is no gate worth having and no reason to owe anything to
    // start-up order.
    //
    // `file!()`/`line!()` are the call site's own, resolved where this expands —
    // the same answer `log`'s `loc()` would give, without the machinery.
    ($($arg:tt)*) => {
        $crate::__log_private(
            $crate::Level::Debug,
            format_args!($($arg)*),
            file!(),
            line!(),
        )
    };
}

#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! debug {
    // Dead by the language rather than by the optimiser: `if false` is a
    // constant condition, so the branch never runs in any profile, and the
    // format string is dropped as unreferenced in a release build.
    //
    // Kept instead of expanding to nothing because a binding used ONLY by a
    // `debug!` would otherwise read as unused. Measured on this tree: an empty
    // expansion raises 26 warnings in api and 7 in storage, most of them the
    // `e` in a `map_err` closure whose detail now goes here.
    ($($arg:tt)*) => {{
        if false {
            let _ = format_args!($($arg)*);
        }
    }};
}

/// [`debug!`], for the noisier half of the private channel.
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::__log_private(
            $crate::Level::Trace,
            format_args!($($arg)*),
            file!(),
            line!(),
        )
    };
}

#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {{
        if false {
            let _ = format_args!($($arg)*);
        }
    }};
}
