//! `timesync` — keeps the guest's clock, beneath the application.
//!
//! On SEV-SNP the host sets a guest's wall clock: it is whatever the emulated
//! RTC says at boot. Secure TSC makes the guest's own counter something the host
//! cannot move, so elapsed time is the guest's — but where the calendar STARTS
//! is still the host's word. This takes the calendar from NTS servers instead,
//! end to end: the key exchange is TLS that ends in this process, every time
//! packet is authenticated with the keys it agreed, and the clock moves only
//! when [`servers::AGREEING`] servers, each of a different operator, agree.
//!
//! dinit runs it in every role, before the application
//! (`image/init/services/common/timesync`):
//!
//!   1. it writes a line to the pipe dinit gives it when the kernel's clock is
//!      first synchronised, and dinit, counting it started only then, starts
//!      the application;
//!   2. it goes on keeping the clock for as long as the guest runs;
//!   3. when it cannot — the kernel left the TSC, a step too large to be the
//!      clock's fault, a fault of its own — it ends, and dinit turns its ending
//!      into the guest's.
//!
//! Nothing in the application has to know any of this: it reads the system
//! clock, and the system clock is kept. What it does check is that the clock
//! still is — the kernel's error estimate grows by itself while nobody updates
//! it, and every role runs this crate's library guard on that (src/lib.rs).

mod clock;
mod lock;
mod ready;
mod servers;
mod source;
mod system;

use std::process::ExitCode;
use std::time::Duration;

use safe_logger::{debug, info, reason};
use tokio::sync::mpsc;

/// How often the keeper checks the kernel is still reading time from the TSC.
const CLOCKSOURCE_CHECK: Duration = Duration::from_secs(1);

/// How many requests the sources may queue for the system.
const REQUEST_BUFFER: usize = 64;

fn main() -> ExitCode {
    // Panic locations are on: this binary is the measured code, and it holds no
    // session's data, only time.
    safe_logger::install();
    safe_logger::install_panic(true);
    // A panic anywhere — in a task as much as here — ends the keeper, and dinit
    // turns that into the guest's end. Without this a panicking task would end
    // only itself, and the clock would quietly stop being kept.
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        std::process::exit(70);
    }));

    if let Err(why) = ready::adopt() {
        safe_logger::error_and_panic!(
            "timesync: could not take dinit's pipe ({}). Stopping.",
            safe_logger::safe(&why, reason!("a constant from this crate")),
            reason!("emitted once, as the keeper stops")
        );
    }

    let clocksource = clock::Clocksource::open().unwrap_or_else(|e| {
        debug!("timesync: {e}");
        safe_logger::error_and_panic!(
            "timesync: could not open which clocksource the kernel uses. Stopping.",
            reason!("a constant")
        )
    });
    check_clocksource(&clocksource);
    match clock::only_tsc() {
        Ok(true) => {}
        Ok(false) => safe_logger::error_and_panic!(
            "timesync: the kernel has a clocksource other than the TSC to move to, which the \
             host could stop with every timer here. Stopping.",
            reason!("a constant, emitted once, as the guest stops")
        ),
        Err(e) => {
            debug!("timesync: {e}");
            safe_logger::error_and_panic!(
                "timesync: could not read which clocksources the kernel has. Stopping.",
                reason!("a constant, emitted once, as the guest stops")
            )
        }
    }
    match clock::raise_to_floor() {
        Ok(true) => info!(
            "timesync: the clock started earlier than this build allows; moved forward to its floor",
            reason!("a constant, emitted at most once per boot")
        ),
        Ok(false) => {}
        Err(e) => {
            debug!("timesync: {e:?}");
            safe_logger::error_and_panic!(
                "timesync: could not set the clock. Stopping.",
                reason!("a constant")
            )
        }
    }

    // The process's TLS provider, chosen once: the same `ring` the rest of the
    // workspace uses.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let roots = servers::roots();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            debug!("timesync: {e}");
            safe_logger::error_and_panic!(
                "timesync: could not start its runtime. Stopping.",
                reason!("a constant")
            )
        });

    // Everything it will use is open; nothing from the network has been read.
    if let Err(why) = lock::lock() {
        safe_logger::error_and_panic!(
            "timesync: could not lock itself ({}). Stopping.",
            safe_logger::safe(&why, reason!("a constant from this crate")),
            reason!("emitted once, as the keeper stops")
        );
    }

    runtime.block_on(async {
        let (requests, received) = mpsc::channel(REQUEST_BUFFER);
        for server in servers::all() {
            tokio::spawn(source::keep(server, roots.clone(), requests.clone()));
        }
        drop(requests);
        tokio::select! {
            () = system::run(received) => {}
            () = watch_clocksource(&clocksource) => {}
        }
    });
    safe_logger::error_and_panic!(
        "timesync: the keeper stopped. Stopping.",
        reason!("a constant")
    )
}

/// End the keeper unless the kernel reads time from the TSC — see
/// [`clock::Clocksource`] for why it might not.
fn check_clocksource(clocksource: &clock::Clocksource) {
    match clocksource.is_tsc() {
        Ok(true) => {}
        Ok(false) => safe_logger::error_and_panic!(
            "timesync: the kernel is not reading time from the TSC, so the host could move \
             the clock under it. Stopping.",
            reason!("a constant, emitted once, as the guest stops")
        ),
        Err(e) => {
            debug!("timesync: {e}");
            safe_logger::error_and_panic!(
                "timesync: could not read which clocksource the kernel uses. Stopping.",
                reason!("a constant, emitted once, as the guest stops")
            )
        }
    }
}

/// Check, for as long as the clock is kept, that the kernel still reads it
/// from the TSC. A second line, not the first: this wakes by the guest's own
/// timers, which run on whatever clocksource the kernel reads, so a move to one
/// the host stops would stop this too. The first is that there is nothing to
/// move to ([`clock::only_tsc`]).
async fn watch_clocksource(clocksource: &clock::Clocksource) {
    let mut every = tokio::time::interval(CLOCKSOURCE_CHECK);
    loop {
        every.tick().await;
        check_clocksource(clocksource);
    }
}
