//! The WASI a round is served.
//!
//! Its time is a value OF THE ROUND, fixed before the policy runs. Nothing the
//! component does reads a clock of the world while it runs.
//!
//! * Time is read once, when the round starts, to the whole second. The wall
//!   clock shows that second for the whole round. The monotonic clock starts
//!   there and moves only to a deadline the round set itself: asked about in
//!   any way — waited on, polled, checked for readiness — a deadline moves the
//!   clock to where it lies and is ready at once. So nothing can be timed and a
//!   wait never waits. A program only ever finds the clock further on than it
//!   expected, never short of a deadline it asked about.
//! * Randomness is fresh for every round, from this CVM's kernel generator:
//!   wasmtime-wasi's own, which seeds each context from it. It is derived from
//!   nothing api holds. What a round drew reaches anyone only once the round is
//!   committed, so running again a round nobody saw reveals nothing, and a
//!   draw fixed by the session would hand the same challenge to whoever starts
//!   the session over.
//! * The rest is what toolchains' runtimes import and a round has no use for,
//!   served by wasmtime-wasi from a context left empty: no environment, no
//!   arguments, no working directory, stdin at its end, stdout and stderr
//!   writing nowhere, a filesystem with nothing opened. Sockets are not linked;
//!   a composition importing them is refused at compile.
//!
//! Plugins fused into the composition share the store, so they read the same.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWrite;
use wasmtime::component::{HasData, HasSelf, Linker, Resource, ResourceTable};
use wasmtime_wasi::cli::{IsTerminal, StdoutStream, WasiCli, WasiCliView};
use wasmtime_wasi::filesystem::{WasiFilesystem, WasiFilesystemView};
use wasmtime_wasi::p2::bindings::{cli, clocks, filesystem, random};
use wasmtime_wasi::p2::{DynPollable, Pollable, subscribe};
use wasmtime_wasi::random::WasiRandom;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_io::bindings::wasi::io;
use wasmtime_wasi_io::bytes::Bytes;
use wasmtime_wasi_io::streams::{OutputStream, StreamError};

use crate::state::HostState;

/// The most one `get-random-bytes` or `get-insecure-random-bytes` hands out.
/// Past it the call traps, rather than the round's memory running out on a
/// length the component chose.
const MAX_RANDOM_BYTES: u64 = 1024 * 1024;

/// The most one write to stdout or stderr may carry, which is also the most
/// `write-zeroes` builds before it is discarded. Past it the call traps.
const MAX_WRITE_BYTES: usize = 64 * 1024;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// stdout and stderr: what is written goes nowhere.
///
/// wasmtime-wasi's own sink does that too, but grants a write of any length,
/// and `write-zeroes` builds the zeros on the host before discarding them — so
/// a length the component chose would panic the host or run it out of memory.
/// This one grants [`MAX_WRITE_BYTES`] at a time.
struct Nowhere;

impl IsTerminal for Nowhere {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for Nowhere {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(Nowhere)
    }

    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        std::io::empty().async_stream()
    }
}

#[wasmtime_wasi::async_trait]
impl OutputStream for Nowhere {
    fn write(&mut self, _bytes: Bytes) -> Result<(), StreamError> {
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StreamError> {
        Ok(())
    }

    fn check_write(&mut self) -> Result<usize, StreamError> {
        Ok(MAX_WRITE_BYTES)
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for Nowhere {
    async fn ready(&mut self) {}
}

/// The round's clocks, and the WASI context its random streams and the rest
/// are served from.
pub struct Round {
    /// When the round started, in whole seconds since the Unix epoch.
    secs: u64,
    /// The monotonic clock in nanoseconds: `secs` when the round starts, moved
    /// only by a deadline asked about.
    now: Arc<AtomicU64>,
    wasi: WasiCtx,
}

/// A `pollable` of the monotonic clock: the instant it lies at, and the clock it
/// moves there.
struct Deadline {
    at: u64,
    now: Arc<AtomicU64>,
}

impl Round {
    /// A round starting now.
    pub fn starting_now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        Self::at(secs)
    }

    fn at(secs: u64) -> Self {
        let wasi = WasiCtx::builder()
            .stdout(Nowhere)
            .stderr(Nowhere)
            .max_random_size(MAX_RANDOM_BYTES)
            .build();
        Self {
            secs,
            now: Arc::new(AtomicU64::new(secs.saturating_mul(NANOS_PER_SEC))),
            wasi,
        }
    }

    fn now(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }

    fn deadline(
        &self,
        at: u64,
        table: &mut ResourceTable,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        let deadline = table.push(Deadline {
            at,
            now: self.now.clone(),
        })?;
        subscribe(table, deadline)
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for Deadline {
    async fn ready(&mut self) {
        self.now.fetch_max(self.at, Ordering::Relaxed);
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.round.wasi,
            table: &mut self.table,
        }
    }
}

impl clocks::wall_clock::Host for HostState {
    fn now(&mut self) -> wasmtime::Result<clocks::wall_clock::Datetime> {
        Ok(clocks::wall_clock::Datetime {
            seconds: self.round.secs,
            nanoseconds: 0,
        })
    }

    fn resolution(&mut self) -> wasmtime::Result<clocks::wall_clock::Datetime> {
        Ok(clocks::wall_clock::Datetime {
            seconds: 1,
            nanoseconds: 0,
        })
    }
}

impl clocks::monotonic_clock::Host for HostState {
    fn now(&mut self) -> wasmtime::Result<clocks::monotonic_clock::Instant> {
        Ok(self.round.now())
    }

    fn resolution(&mut self) -> wasmtime::Result<clocks::monotonic_clock::Duration> {
        Ok(1)
    }

    fn subscribe_instant(
        &mut self,
        when: clocks::monotonic_clock::Instant,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        self.round.deadline(when, &mut self.table)
    }

    fn subscribe_duration(
        &mut self,
        when: clocks::monotonic_clock::Duration,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        let at = self.round.now().saturating_add(when);
        self.round.deadline(at, &mut self.table)
    }
}

/// `wasi:io`'s host is the round's resource table itself.
struct Io;

impl HasData for Io {
    type Data<'a> = &'a mut ResourceTable;
}

/// Link the WASI a round is served. Nothing of `wasi:sockets` or `wasi:http`.
pub(crate) fn add_to_linker(linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
    let l = linker;
    io::error::add_to_linker::<_, Io>(l, |s| &mut s.table)?;
    io::poll::add_to_linker::<_, Io>(l, |s| &mut s.table)?;
    io::streams::add_to_linker::<_, Io>(l, |s| &mut s.table)?;
    clocks::wall_clock::add_to_linker::<_, HasSelf<HostState>>(l, |s| s)?;
    clocks::monotonic_clock::add_to_linker::<_, HasSelf<HostState>>(l, |s| s)?;
    random::random::add_to_linker::<_, WasiRandom>(l, |s| s.round.wasi.random())?;
    random::insecure::add_to_linker::<_, WasiRandom>(l, |s| s.round.wasi.random())?;
    random::insecure_seed::add_to_linker::<_, WasiRandom>(l, |s| s.round.wasi.random())?;
    filesystem::types::add_to_linker::<_, WasiFilesystem>(l, HostState::filesystem)?;
    filesystem::preopens::add_to_linker::<_, WasiFilesystem>(l, HostState::filesystem)?;
    cli::environment::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::exit::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::stdin::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::stdout::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::stderr::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::terminal_input::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::terminal_output::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::terminal_stdin::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::terminal_stdout::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    cli::terminal_stderr::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime_wasi::p2::bindings::random::random::Host as _;

    const START: u64 = 1_760_000_000;

    #[test]
    fn the_clocks_start_at_the_rounds_second() {
        let round = Round::at(START);
        assert_eq!(round.secs, START);
        assert_eq!(round.now(), START * NANOS_PER_SEC);
    }

    #[tokio::test]
    async fn a_deadline_asked_about_moves_the_clock_to_it_and_never_back() {
        let round = Round::at(START);
        let start = round.now();
        let deadline = |at| Deadline {
            at,
            now: round.now.clone(),
        };
        deadline(start + 1_000).ready().await;
        assert_eq!(round.now(), start + 1_000);
        deadline(start + 10).ready().await;
        assert_eq!(round.now(), start + 1_000, "a deadline behind leaves it");
    }

    /// Two rounds started in the same second draw apart: nothing they share
    /// decides what they draw.
    #[test]
    fn every_round_draws_afresh() {
        let draw = || Round::at(START).wasi.random().get_random_bytes(64).unwrap();
        assert_ne!(draw(), draw());
    }

    #[test]
    fn a_write_past_the_permit_traps_without_building_it() {
        let mut out = Nowhere.p2_stream();
        assert!(out.write_zeroes(MAX_WRITE_BYTES).is_ok());
        assert!(out.write_zeroes(usize::MAX).is_err());
    }

    #[test]
    fn a_draw_past_the_bound_traps() {
        let mut round = Round::at(START);
        let random = round.wasi.random();
        assert_eq!(
            random.get_random_bytes(MAX_RANDOM_BYTES).unwrap().len(),
            1024 * 1024
        );
        assert!(random.get_random_bytes(MAX_RANDOM_BYTES + 1).is_err());
    }
}
