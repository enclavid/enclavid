//! The WASI a round is served.
//!
//! Its time and its randomness are values OF THE ROUND, fixed before the policy
//! runs, so a round is a function of its state, its event, its time and its
//! seed. Nothing the component does reads the world while it runs.
//!
//! * Time is read once, when the round starts, to the whole second. The wall
//!   clock shows that second for the whole round. The monotonic clock starts
//!   there and moves only to a deadline the round set itself: asked about in
//!   any way — waited on, polled, checked for readiness — a deadline moves the
//!   clock to where it lies and is ready at once. So nothing can be timed and a
//!   wait never waits. A program only ever finds the clock further on than it
//!   expected, never short of a deadline it asked about.
//! * Randomness is one stream, `StdRng` seeded with what api derived for this
//!   session and round, so a round run again draws the same bytes, whoever
//!   makes it run again.
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

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use wasmtime::component::{HasData, HasSelf, Linker, Resource, ResourceTable};
use wasmtime_wasi::cli::{WasiCli, WasiCliView};
use wasmtime_wasi::filesystem::{WasiFilesystem, WasiFilesystemView};
use wasmtime_wasi::p2::bindings::{cli, clocks, filesystem, random};
use wasmtime_wasi::p2::{DynPollable, Pollable, subscribe};
use wasmtime_wasi::random::WasiRandom;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_io::bindings::wasi::io;

use crate::state::HostState;

/// The most one `get-random-bytes` or `get-insecure-random-bytes` hands out.
/// Past it the call traps, rather than the round's memory running out on a
/// length the component chose.
const MAX_RANDOM_BYTES: u64 = 1024 * 1024;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// The round's clocks, and the WASI context its random stream and the rest are
/// served from.
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
    /// A round starting now, drawing from `seed`.
    pub fn starting_now(seed: [u8; 32]) -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        Self::at(secs, seed)
    }

    fn at(secs: u64, seed: [u8; 32]) -> Self {
        let mut random = StdRng::from_seed(seed);
        let insecure = StdRng::from_rng(&mut random);
        let insecure_seed: u128 = random.random();
        let wasi = WasiCtx::builder()
            .secure_random(random)
            .insecure_random(insecure)
            .insecure_random_seed(insecure_seed)
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
        let round = Round::at(START, [0; 32]);
        assert_eq!(round.secs, START);
        assert_eq!(round.now(), START * NANOS_PER_SEC);
    }

    #[tokio::test]
    async fn a_deadline_asked_about_moves_the_clock_to_it_and_never_back() {
        let round = Round::at(START, [0; 32]);
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

    #[test]
    fn one_seed_draws_the_same_bytes_and_another_does_not() {
        let draw = |seed| {
            Round::at(START, seed)
                .wasi
                .random()
                .get_random_bytes(64)
                .unwrap()
        };
        assert_eq!(draw([1; 32]), draw([1; 32]));
        assert_ne!(draw([1; 32]), draw([2; 32]));
    }

    #[test]
    fn a_draw_past_the_bound_traps() {
        let mut round = Round::at(START, [0; 32]);
        let random = round.wasi.random();
        assert_eq!(
            random.get_random_bytes(MAX_RANDOM_BYTES).unwrap().len(),
            1024 * 1024
        );
        assert!(random.get_random_bytes(MAX_RANDOM_BYTES + 1).is_err());
    }
}
