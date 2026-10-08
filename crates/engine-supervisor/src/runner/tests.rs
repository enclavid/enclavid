// Admission: when a request is let in, when it is turned away, and that every
// path out of `run` gives back what it took. Platform-neutral — none of these
// spawns a child that gets as far as speaking.

use super::*;

const WAIT: Duration = Duration::from_secs(10);

/// A runner of one slot whose child binary does not exist, so a request that IS
/// admitted fails at spawn and one that is not fails before it.
fn runner(wait: Option<Duration>) -> ChildRunner {
    runner_of("/nonexistent/enclavid-child", wait)
}

fn runner_of(exe: &str, wait: Option<Duration>) -> ChildRunner {
    ChildRunner::new(
        RunnerConfig {
            exe: exe.into(),
            max_children: 1,
            deadline: Duration::from_secs(120),
            admission_wait: wait,
            times: ChildTimes::default(),
        },
        None,
    )
}

/// How long the runners here let an answer wait for why its child ended.
fn exit_wait() -> Duration {
    ChildTimes::default().exit_wait
}

/// Take the runner's one slot from outside, the way a running child holds it.
fn hold(runner: &ChildRunner) -> OwnedSemaphorePermit {
    runner
        .slots
        .clone()
        .try_acquire_owned()
        .expect("the runner's one slot is free")
}

/// Wait — on no timer, which a paused clock would fire early — for every
/// slot of `runner` to be given back.
async fn every_slot_comes_back(runner: &ChildRunner, slots: u32) {
    let _all = runner
        .slots
        .clone()
        .acquire_many_owned(slots)
        .await
        .expect("the runner is open");
}

#[tokio::test(start_paused = true)]
async fn a_full_runner_answers_busy_at_the_end_of_its_wait() {
    let runner = runner(Some(WAIT));
    let _held = hold(&runner);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        runner.admit().await,
        Err(SupervisorError::Busy(w)) if w == WAIT
    ));
    assert!(started.elapsed() >= WAIT);
}

#[tokio::test(start_paused = true)]
async fn a_slot_freed_within_the_wait_is_taken() {
    let runner = runner(Some(WAIT));
    let held = hold(&runner);
    tokio::spawn(async move {
        tokio::time::sleep(WAIT / 2).await;
        drop(held);
    });
    assert!(runner.admit().await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn without_a_wait_a_full_runner_keeps_waiting() {
    let runner = runner(None);
    let _held = hold(&runner);
    assert!(
        tokio::time::timeout(WAIT * 100, runner.admit())
            .await
            .is_err()
    );
}

/// Admission comes before spawn: the binary does not exist, and the answer is
/// still `Busy` rather than a failed spawn.
#[tokio::test(start_paused = true)]
async fn a_request_not_admitted_spawns_nothing() {
    let runner = runner(Some(WAIT));
    let _held = hold(&runner);
    let out = runner.run(None, (), |_: ()| async {}).await;
    assert!(matches!(out, Err(SupervisorError::Busy(_))));
}

/// The wait that timed out left the queue: once the holder lets go, the slot
/// is free and the next request is served at once.
#[tokio::test(start_paused = true)]
async fn a_request_not_admitted_takes_no_slot() {
    let runner = runner(Some(WAIT));
    let held = hold(&runner);
    assert!(matches!(
        runner.admit().await,
        Err(SupervisorError::Busy(_))
    ));
    drop(held);
    assert_eq!(runner.slots.available_permits(), 1);
    let started = tokio::time::Instant::now();
    let _slot = runner.admit().await.expect("a free slot is taken");
    assert_eq!(started.elapsed(), Duration::ZERO);
}

/// The early return on a failed spawn gives the slot back.
#[tokio::test(start_paused = true)]
async fn a_failed_spawn_returns_its_slot() {
    let runner = runner(Some(WAIT));
    let out = runner.run(None, (), |_: ()| async {}).await;
    assert!(matches!(out, Err(SupervisorError::Spawn(_))));
    every_slot_comes_back(&runner, 1).await;
}

/// A request dropped while it waits for admission holds nothing afterwards.
#[tokio::test(start_paused = true)]
async fn a_request_cancelled_while_waiting_holds_nothing() {
    let runner = runner(Some(WAIT));
    let held = hold(&runner);
    assert!(
        tokio::time::timeout(WAIT / 2, runner.run(None, (), |_: ()| async {}))
            .await
            .is_err()
    );
    drop(held);
    assert_eq!(runner.slots.available_permits(), 1);
}

/// A request dropped AFTER admission, with its child alive and mid-handshake,
/// gives its slot back too. `cat` reads the handshake and never answers it,
/// which is a child that took its slot and will not say anything.
#[tokio::test(start_paused = true)]
async fn a_request_cancelled_after_admission_returns_its_slot() {
    let runner = runner_of("/bin/cat", Some(WAIT));
    assert!(
        tokio::time::timeout(WAIT / 2, runner.run(None, (), |_: ()| async {}))
            .await
            .is_err()
    );
    every_slot_comes_back(&runner, 1).await;
}

/// The same child left to the handshake's own bound: the request fails — at
/// the bound, or sooner where the filter ends `cat` first — and the slot comes
/// back with it.
#[tokio::test(start_paused = true)]
async fn a_child_that_never_connects_returns_its_slot() {
    let runner = runner_of("/bin/cat", Some(WAIT));
    let out = runner.run(None, (), |_: ()| async {}).await;
    assert!(matches!(
        out,
        Err(SupervisorError::Handshake(_) | SupervisorError::Spawn(_))
    ));
    every_slot_comes_back(&runner, 1).await;
}

/// What a child of `runner` holds while it runs `sleep`, which never goes by
/// itself, with `kept` as the caller's `keep`; and the exit cause its release
/// settles.
async fn sleeping(runner: &ChildRunner, kept: &Arc<()>) -> (Held, oneshot::Receiver<ExitCause>) {
    let slot = runner.admit().await.expect("a free slot");
    let process = tokio::process::Command::new("/bin/sleep")
        .arg("1000")
        .kill_on_drop(true)
        .spawn()
        .expect("sleep spawns");
    let (cause, settled) = oneshot::channel();
    let held = Held {
        process,
        cause: Some(cause),
        kept: Box::new(kept.clone()),
        group: None,
        slot,
    };
    (held, settled)
}

/// The slot, and what was kept, are held until the child has exited — not
/// when it was told to go — and a runner without cgroups attributes nothing
/// about how it went.
#[tokio::test(start_paused = true)]
async fn a_slot_is_held_until_its_child_has_exited() {
    use rustix::process::{Pid, Signal, kill_process};

    let runner = runner(None);
    let kept = Arc::new(());
    let (held, settled) = sleeping(&runner, &kept).await;
    let pid = held
        .process
        .id()
        .and_then(|id| Pid::from_raw(id.cast_signed()));
    let release = tokio::spawn(held.release());
    tokio::time::sleep(WAIT).await;
    assert_eq!(runner.slots.available_permits(), 0);
    assert_eq!(Arc::strong_count(&kept), 2);

    kill_process(pid.expect("sleep is running"), Signal::KILL).expect("kill sleep");
    release.await.expect("the release finishes");
    assert_eq!(runner.slots.available_permits(), 1);
    assert_eq!(Arc::strong_count(&kept), 1);
    assert_eq!(settled.await, Ok(ExitCause::Unattributed));
}

/// A dropped child is killed then and there: `sleep` never goes by itself, so
/// only the kill gives its slot back. Real time: a paused clock would run the
/// bound out at once.
#[tokio::test]
async fn a_dropped_child_is_killed_at_once() {
    let runner = runner(None);
    let kept = Arc::new(());
    let (held, _settled) = sleeping(&runner, &kept).await;
    drop(Child(Some(held)));
    tokio::time::timeout(Duration::from_secs(10), every_slot_comes_back(&runner, 1))
        .await
        .expect("the slot comes back once the killed child is gone");
    assert_eq!(Arc::strong_count(&kept), 1);
}

/// The answer does not wait on a release that will not settle: past the exit
/// wait, an exit attributes nothing.
#[tokio::test(start_paused = true)]
async fn an_exit_is_waited_for_no_longer_than_the_exit_wait() {
    let (_unsettled, rx) = oneshot::channel();
    let started = tokio::time::Instant::now();
    let exit = Exit {
        cause: rx,
        within: exit_wait(),
    };
    assert_eq!(exit.cause().await, ExitCause::Unattributed);
    assert_eq!(started.elapsed(), exit_wait());
    assert_eq!(
        Exit::known(ExitCause::OutgrewItsMax).cause().await,
        ExitCause::OutgrewItsMax
    );
}
