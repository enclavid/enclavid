// Admission: when a request is let in, when it is turned away, and that every
// path out of `run` gives back what it took — the coprocess beside a child
// included. Platform-neutral — none of these spawns a child that gets as far
// as speaking.

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
            coprocess: None,
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
    let out = runner.run(&[], (), |_: (), _| async {}).await;
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
    let out = runner.run(&[], (), |_: (), _| async {}).await;
    assert!(matches!(out, Err(SupervisorError::Spawn(_))));
    every_slot_comes_back(&runner, 1).await;
}

/// A request dropped while it waits for admission holds nothing afterwards.
#[tokio::test(start_paused = true)]
async fn a_request_cancelled_while_waiting_holds_nothing() {
    let runner = runner(Some(WAIT));
    let held = hold(&runner);
    assert!(
        tokio::time::timeout(WAIT / 2, runner.run(&[], (), |_: (), _| async {}))
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
        tokio::time::timeout(WAIT / 2, runner.run(&[], (), |_: (), _| async {}))
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
    let out = runner.run(&[], (), |_: (), _| async {}).await;
    assert!(matches!(
        out,
        Err(SupervisorError::Handshake(_) | SupervisorError::Spawn(_))
    ));
    every_slot_comes_back(&runner, 1).await;
}

/// `sleep`, which never goes by itself.
fn sleep() -> tokio::process::Child {
    tokio::process::Command::new("/bin/sleep")
        .arg("1000")
        .kill_on_drop(true)
        .spawn()
        .expect("sleep spawns")
}

/// Its pid, while it is running.
fn pid_of(process: &tokio::process::Child) -> rustix::process::Pid {
    process
        .id()
        .and_then(|id| rustix::process::Pid::from_raw(id.cast_signed()))
        .expect("the process is running")
}

/// What a child of `runner` holds while it runs `sleep`, with `kept` as the
/// caller's `keep`; and the exit cause its release settles.
async fn sleeping(runner: &ChildRunner, kept: &Arc<()>) -> (Held, oneshot::Receiver<ExitCause>) {
    let slot = runner.admit().await.expect("a free slot");
    let (cause, settled) = oneshot::channel();
    let held = Held {
        process: sleep(),
        coprocesses: Arc::default(),
        cause: Some(cause),
        kept: Box::new(kept.clone()),
        group: None,
        slot,
    };
    (held, settled)
}

/// How many coprocesses the runners here let one child have.
const MAX_COPROCESSES: usize = 2;

/// The child's coprocesses as a runner of `exe` hands them out, beside `held`.
fn coprocess_of(held: &Held, exe: Option<&str>) -> Coprocess {
    Coprocess {
        config: exe.map(|exe| CoprocessConfig {
            exe: exe.into(),
            max: MAX_COPROCESSES,
        }),
        cgroups: None,
        group: None,
        state: Arc::clone(&held.coprocesses),
    }
}

/// `process` kept beside `held` as a started coprocess, with `kept` for it.
fn beside(held: &Held, process: tokio::process::Child, kept: &Arc<()>) {
    lock(&held.coprocesses).started.push(Started {
        process,
        kept: Box::new(kept.clone()),
    });
}

/// One end of a socket pair, as the coprocess is given; the other end, which
/// the child would hold.
fn socket() -> (OwnedFd, std::os::unix::net::UnixStream) {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
    (OwnedFd::from(theirs), ours)
}

/// The slot, and what was kept, are held until the child has exited — not
/// when it was told to go — and a runner without cgroups attributes nothing
/// about how it went.
#[tokio::test(start_paused = true)]
async fn a_slot_is_held_until_its_child_has_exited() {
    use rustix::process::{Signal, kill_process};

    let runner = runner(None);
    let kept = Arc::new(());
    let (held, settled) = sleeping(&runner, &kept).await;
    let pid = pid_of(&held.process);
    let release = tokio::spawn(held.release());
    tokio::time::sleep(WAIT).await;
    assert_eq!(runner.slots.available_permits(), 0);
    assert_eq!(Arc::strong_count(&kept), 2);

    kill_process(pid, Signal::KILL).expect("kill sleep");
    release.await.expect("the release finishes");
    assert_eq!(runner.slots.available_permits(), 1);
    assert_eq!(Arc::strong_count(&kept), 1);
    assert_eq!(settled.await, Ok(ExitCause::Unattributed));
}

/// A coprocess outliving its child keeps the child's slot, and what was kept
/// for the coprocess, until it has exited too.
#[tokio::test(start_paused = true)]
async fn a_slot_is_held_until_the_coprocess_has_exited_too() {
    use rustix::process::{Signal, kill_process};

    let runner = runner(None);
    let (kept, coprocess_kept) = (Arc::new(()), Arc::new(()));
    let (held, _settled) = sleeping(&runner, &kept).await;
    let coprocess = sleep();
    let (child_pid, coprocess_pid) = (pid_of(&held.process), pid_of(&coprocess));
    beside(&held, coprocess, &coprocess_kept);
    let release = tokio::spawn(held.release());

    kill_process(child_pid, Signal::KILL).expect("kill the child");
    tokio::time::sleep(WAIT).await;
    assert_eq!(runner.slots.available_permits(), 0);
    assert_eq!(Arc::strong_count(&coprocess_kept), 2);

    kill_process(coprocess_pid, Signal::KILL).expect("kill the coprocess");
    release.await.expect("the release finishes");
    assert_eq!(runner.slots.available_permits(), 1);
    assert_eq!(Arc::strong_count(&coprocess_kept), 1);
    assert_eq!(Arc::strong_count(&kept), 1);
}

/// A dropped child takes its coprocesses with it: none goes by itself, so only
/// the kill gives the slot back. Real time, as for the child alone.
#[tokio::test]
async fn the_coprocesses_are_killed_with_their_child() {
    let runner = runner(None);
    let (kept, coprocess_kept) = (Arc::new(()), Arc::new(()));
    let (held, _settled) = sleeping(&runner, &kept).await;
    let (first, second) = (sleep(), sleep());
    let pids = [pid_of(&first), pid_of(&second)];
    beside(&held, first, &coprocess_kept);
    beside(&held, second, &coprocess_kept);
    drop(Child(Some(held)));
    tokio::time::timeout(Duration::from_secs(10), every_slot_comes_back(&runner, 1))
        .await
        .expect("the slot comes back once the child and its coprocesses are gone");
    assert_eq!(Arc::strong_count(&coprocess_kept), 1);
    for pid in pids {
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "a coprocess outlived its child"
        );
    }
}

/// A child has no more coprocesses than the runner lets it: past the max,
/// none starts.
#[tokio::test]
async fn a_child_has_no_more_coprocesses_than_its_max() {
    let runner = runner(None);
    let kept = Arc::new(());
    let (held, _settled) = sleeping(&runner, &kept).await;
    let coprocesses = coprocess_of(&held, Some("/bin/cat"));
    let mut ours = Vec::new();
    for _ in 0..MAX_COPROCESSES {
        let (theirs, our) = socket();
        ours.push(our);
        coprocesses
            .start(theirs, &[], ())
            .expect("a coprocess within the max starts");
    }
    let (theirs, _ours) = socket();
    assert!(matches!(
        coprocesses.start(theirs, &[], ()),
        Err(CoprocessError::TooMany(MAX_COPROCESSES))
    ));
    assert_eq!(lock(&held.coprocesses).started.len(), MAX_COPROCESSES);
}

/// A coprocess started through the handle is the one the child's kill
/// reaches.
#[tokio::test]
async fn a_started_coprocess_is_killed_with_its_child() {
    let runner = runner(None);
    let (kept, coprocess_kept) = (Arc::new(()), Arc::new(()));
    let (held, _settled) = sleeping(&runner, &kept).await;
    // `cat` on a socket this test keeps open goes only when killed — or, on
    // Linux, when the coprocess's filters end it first; either way it is gone
    // before the slot comes back.
    let (theirs, _ours) = socket();
    coprocess_of(&held, Some("/bin/cat"))
        .start(theirs, &[], coprocess_kept.clone())
        .expect("the coprocess starts");
    let coprocess_pid = pid_of(
        &lock(&held.coprocesses)
            .started
            .first()
            .expect("the started coprocess is kept beside the child")
            .process,
    );
    drop(Child(Some(held)));
    tokio::time::timeout(Duration::from_secs(10), every_slot_comes_back(&runner, 1))
        .await
        .expect("the slot comes back once the child and its coprocess are gone");
    assert_eq!(Arc::strong_count(&coprocess_kept), 1);
    assert!(rustix::process::test_kill_process(coprocess_pid).is_err());
}

/// Once its child is being ended, no coprocess starts beside it: one started
/// then would outlive the kill.
#[tokio::test]
async fn no_coprocess_starts_beside_an_ended_child() {
    let runner = runner(None);
    let kept = Arc::new(());
    let (mut held, _settled) = sleeping(&runner, &kept).await;
    let coprocess = coprocess_of(&held, Some("/bin/cat"));
    held.kill();
    let (theirs, _ours) = socket();
    assert!(matches!(
        coprocess.start(theirs, &[], ()),
        Err(CoprocessError::ChildEnded)
    ));
    assert!(lock(&held.coprocesses).started.is_empty());
}

/// A runner given no coprocess binary starts no coprocess.
#[tokio::test]
async fn a_runner_without_a_coprocess_binary_starts_none() {
    let runner = runner(None);
    let kept = Arc::new(());
    let (held, _settled) = sleeping(&runner, &kept).await;
    let (theirs, _ours) = socket();
    assert!(matches!(
        coprocess_of(&held, None).start(theirs, &[], ()),
        Err(CoprocessError::NoBinary)
    ));
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
