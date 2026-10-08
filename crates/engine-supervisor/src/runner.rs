//! Running each request in a child of its own: admission, the request's
//! deadline, and the release that gives its place back once the child is gone.

#[cfg(test)]
mod tests;

use std::future::Future;
use std::io;
use std::os::fd::BorrowedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use remoc::RemoteSend;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

use crate::cgroup::{Cgroups, ChildGroup, ExitCause};
use crate::spawn::{SpawnError, connect, inherited_len, spawn_child};

/// How long a runner waits on a child at the steps a request's own deadline does
/// not cover, as the role's launch settings give them or as [`Default`] has
/// them. Waits on this guest's own processes: how long they take is a matter of
/// its load, and none of them is a term of what a round discloses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildTimes {
    /// How long an answer's [`Exit::cause`] waits for the release — the child
    /// killed and gone, its group empty — to read how the child ended. Five
    /// seconds by default.
    pub exit_wait: Duration,
    /// Bound on the child's handshake — spawn, remoc hello, its service client.
    /// Milliseconds for a child that works; this keeps one that connects and
    /// never sends its client from holding its slot forever, so every child is
    /// killed within a bounded time of taking one. Untrusted work runs only
    /// after the handshake, under the request's deadline. Thirty seconds by
    /// default.
    pub connect: Duration,
    /// How often a request admitted to a slot reads whether there is room for
    /// its child, while the runner's admission wait lasts. Only a runner with
    /// [`Cgroups`] reads it. 50 ms by default.
    pub room_poll: Duration,
}

impl Default for ChildTimes {
    fn default() -> Self {
        Self {
            exit_wait: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            room_poll: Duration::from_millis(50),
        }
    }
}

/// What a [`ChildRunner`] runs and the bounds it runs it under.
#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// The child binary.
    pub exe: PathBuf,
    /// How many children may be alive at once — one process each.
    pub max_children: usize,
    /// The per-request wall-clock ceiling.
    pub deadline: Duration,
    /// How long `run` waits to be admitted — a slot, and room for its child —
    /// before answering [`SupervisorError::Busy`]; `None` waits for as long as
    /// that takes.
    pub admission_wait: Option<Duration>,
    /// How long the runner waits on a child where `deadline` does not reach.
    pub times: ChildTimes,
}

/// A failure of the SUPERVISOR itself — distinct from the domain call's own error
/// (which the caller's closure returns and maps). Kept separate so a per-request
/// wall-clock deadline (a real availability control) is never confused with a
/// domain compile/run failure.
///
/// Each variant's text carries the error under it, as remoc's own do, so one
/// logged line says the whole of it.
#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    /// Not admitted — a slot, and room for the child — within the runner's
    /// admission wait. Nothing was spawned: the caller answers with its own
    /// retryable "busy", and the request can be made again as it was.
    #[error("no child was admitted within {0:?}")]
    Busy(Duration),
    /// Whether there is room for one more child could not be read.
    #[error("read the children's memory: {0}")]
    Room(io::Error),
    /// The child's own group could not be made.
    #[error("make the child's group: {0}")]
    Group(io::Error),
    /// The child could not be started, or did not hand over its client.
    #[error("start the child: {0}")]
    Spawn(SpawnError),
    /// The child did not finish its handshake within [`ChildTimes::connect`] —
    /// it was killed.
    #[error("the child's handshake exceeded {0:?} (killed)")]
    Handshake(Duration),
    /// The child did not finish the request within the runner's deadline — it
    /// was killed. The caller maps this to its own 5xx-class domain error so the
    /// request fails safe (and, for a keyless worker, is retryable).
    #[error("child exceeded its {0:?} deadline (killed)")]
    Deadline(Duration),
}

/// Runs each request in a fresh disposable child process: bounds how many are
/// alive at once, enforces a per-request wall-clock deadline and, if given one,
/// a deadline on admission. On Linux every child it spawns runs under the
/// syscall filters. Share it behind an `Arc` to serve concurrently.
#[derive(Debug)]
pub struct ChildRunner {
    exe: PathBuf,
    /// One permit per child alive, held from admission until the child and
    /// everything in its group are gone.
    slots: Arc<Semaphore>,
    deadline: Duration,
    admission_wait: Option<Duration>,
    /// The kernel's hold on the children's memory, when this runner has one.
    /// Shared with the blocking thread each child's group is made on.
    cgroups: Option<Arc<Cgroups>>,
    times: ChildTimes,
}

/// How a request's child ended, settled once the child and everything in its
/// group are gone. Returned beside the request's answer, which does not wait
/// for it.
#[derive(Debug)]
pub struct Exit {
    cause: oneshot::Receiver<ExitCause>,
    /// The runner's [`ChildTimes::exit_wait`].
    within: Duration,
}

impl Exit {
    /// Why the child ended, waited for no longer than [`ChildTimes::exit_wait`]:
    /// a release that has not settled by then is answered
    /// [`ExitCause::Unattributed`] here, and goes on holding its slot until it
    /// does. A runner without [`Cgroups`] attributes nothing.
    pub async fn cause(self) -> ExitCause {
        match tokio::time::timeout(self.within, self.cause).await {
            Ok(Ok(cause)) => cause,
            _ => ExitCause::Unattributed,
        }
    }

    /// An exit already settled at `cause` — what a caller's own tests need to
    /// drive the mapping it makes of one.
    #[doc(hidden)]
    pub fn known(cause: ExitCause) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(cause);
        Self {
            cause: rx,
            within: ChildTimes::default().exit_wait,
        }
    }
}

/// A running child. Dropping it is how it ends, and every way out of
/// [`ChildRunner::run`] does — an answer, an error, a cancelled request, a
/// panic in the caller's closure: the child and everything in its group are
/// killed at once, and the release lets go of what it [`Held`] once they are
/// gone.
///
/// The kill is the drop's own work. Waiting for the kernel is not something a
/// drop can do, so that part goes to a task.
struct Child(Option<Held>);

/// What a child holds, in the order it is let go of: its fields drop in
/// declaration order once the child is gone.
struct Held {
    process: tokio::process::Child,
    /// Settled by the release; the answer's [`Exit`] reads it.
    cause: Option<oneshot::Sender<ExitCause>>,
    /// The caller's `keep`: what the child maps, so not before it is gone.
    #[allow(dead_code, reason = "held for its drop")]
    kept: Box<dyn Send>,
    /// The child's own group, when the runner has [`Cgroups`]; its drop
    /// removes it.
    group: Option<ChildGroup>,
    /// Last: a slot comes back only once everything above is let go of.
    #[allow(dead_code, reason = "held for its drop")]
    slot: OwnedSemaphorePermit,
}

impl Drop for Child {
    fn drop(&mut self) {
        let Some(mut held) = self.0.take() else {
            return;
        };
        held.kill();
        // Outside a runtime is the process going away: there is nothing to wait
        // with, and what the child held drops here.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(held.release());
        }
    }
}

impl Held {
    /// Kill the child, and everything else in its group, now.
    fn kill(&mut self) {
        let _ = self.process.start_kill();
        if let Some(group) = &self.group {
            group.kill();
        }
    }

    /// Wait for the killed child to exit and its group to empty, settle why it
    /// ended, and let go of what it held.
    ///
    /// Without a bound: a killed child keeps its memory until it is gone, and
    /// one in uninterruptible sleep — likely under memory pressure — can take a
    /// while. A child or group that will not go keeps its slot and what was
    /// kept for it, because it keeps its memory.
    async fn release(mut self) {
        let _ = self.process.wait().await;
        let cause = match &self.group {
            Some(group) => {
                group.emptied().await;
                group.exit_cause()
            }
            None => ExitCause::Unattributed,
        };
        #[cfg(feature = "debug")]
        if let Some(group) = &self.group {
            safe_logger::debug!(
                "child: peak {:?} KiB, {:?}",
                group.peak().map(|bytes| bytes >> 10),
                cause
            );
        }
        if let Some(settled) = self.cause.take() {
            let _ = settled.send(cause);
        }
        // Off the runtime: the group's drop reclaims what the child left
        // charged, which can be a great many kernel objects.
        let _ = tokio::task::spawn_blocking(move || drop(self)).await;
    }
}

impl ChildRunner {
    /// A runner of `config`. `cgroups` is the kernel's hold on the children's
    /// memory, built for `config.max_children`, or `None` for a runner without
    /// one: with it, each child gets a group and an identity of its own.
    pub fn new(config: RunnerConfig, cgroups: Option<Cgroups>) -> Self {
        Self {
            exe: config.exe,
            slots: Arc::new(Semaphore::new(config.max_children)),
            deadline: config.deadline,
            admission_wait: config.admission_wait,
            cgroups: cgroups.map(Arc::new),
            times: config.times,
        }
    }

    /// Admission for one child: a slot, and — for a runner with [`Cgroups`] —
    /// room for the child in the children's total and in the guest. Both are
    /// waited for within ONE admission wait, if the runner has one, and past it
    /// the answer is [`SupervisorError::Busy`]: a request that was not admitted
    /// spawns nothing. Without one, as long as it takes.
    ///
    /// A wait that ends unanswered leaves the queue with nothing held: tokio drops
    /// an abandoned acquire's place, so a timed-out request takes no slot from
    /// whoever is behind it. Room is read rather than waited on — every
    /// [`ChildTimes::room_poll`] — and is a gate, not a reservation: see
    /// [`Cgroups::room`].
    async fn admit(&self) -> Result<OwnedSemaphorePermit, SupervisorError> {
        let until = self
            .admission_wait
            .map(|wait| tokio::time::Instant::now() + wait);
        let slot = self.slots.clone().acquire_owned();
        let slot = match until {
            Some(until) => tokio::time::timeout_at(until, slot)
                .await
                .map_err(|_| self.busy())?,
            None => slot.await,
        }
        .expect("a runner never closes its slots");
        if let Some(cgroups) = &self.cgroups {
            loop {
                let room = cgroups.room().map_err(SupervisorError::Room)?;
                if room {
                    break;
                }
                let now = tokio::time::Instant::now();
                if until.is_some_and(|until| now >= until) {
                    return Err(self.busy());
                }
                let next = now + self.times.room_poll;
                tokio::time::sleep_until(until.map_or(next, |until| until.min(next))).await;
            }
        }
        Ok(slot)
    }

    fn busy(&self) -> SupervisorError {
        SupervisorError::Busy(self.admission_wait.unwrap_or_default())
    }

    /// Spawn a fresh child, hand its service client `Cli` to `f`, and drive `f`
    /// under the request's deadline. The answer comes back beside the child's
    /// [`Exit`], which a caller reads only when the answer leaves it asking how
    /// the child died; the release runs off the request's path.
    ///
    /// `f` does the domain work — `prime` then `run`, or `compile` — and its
    /// result is returned as it is. A [`SupervisorError`] is the runner's own:
    /// not admitted in time, a failed spawn, or the deadline elapsing on a
    /// wedged child, one that keeps its connection alive while parking the
    /// call. However the call ends — an answer, an error, the caller dropping
    /// it — the child is killed then: whatever it had to say, it has said.
    ///
    /// `inherit` goes to the child at [`INHERITED_FD`](crate::INHERITED_FD)
    /// (see [`spawn_and_connect`](crate::spawn_and_connect)), read only up to
    /// the spawn. `keep` is what must outlive the child — what it maps through
    /// that descriptor — and is let go of once the child has exited and its
    /// group is empty, which can be well after this call returns.
    pub async fn run<Cli, F, Fut, T, K>(
        &self,
        inherit: Option<BorrowedFd<'_>>,
        keep: K,
        f: F,
    ) -> Result<(T, Exit), SupervisorError>
    where
        Cli: RemoteSend,
        F: FnOnce(Cli) -> Fut,
        Fut: Future<Output = T>,
        K: Send + 'static,
    {
        let slot = self.admit().await?;
        // A group and an identity made for this child alone, when the runner
        // holds its children's memory. On a blocking thread, as is the group's
        // removal: making and removing a group wait on one kernel lock over
        // every group in the guest.
        let (group, placement) = match &self.cgroups {
            Some(cgroups) => {
                let (cgroups, inherited) = (Arc::clone(cgroups), inherited_len(inherit));
                let (group, placement) =
                    tokio::task::spawn_blocking(move || cgroups.new_child(inherited))
                        .await
                        .map_err(io::Error::other)
                        .and_then(std::convert::identity)
                        .map_err(SupervisorError::Group)?;
                (Some(group), Some(placement))
            }
            None => (None, None),
        };
        // Always filtered. The filter is a confidentiality control, and the host
        // provisions this process's settings, so it is not one of them: turning
        // it off is a rebuild and a new measurement.
        let (process, sup_end) = match spawn_child(&self.exe, inherit, true, placement) {
            Ok(spawned) => spawned,
            Err(e) => {
                // Nothing ever ran in the group: it goes as it came.
                if let Some(group) = group {
                    let _ = tokio::task::spawn_blocking(move || drop(group)).await;
                }
                return Err(SupervisorError::Spawn(e));
            }
        };
        let (cause, settled) = oneshot::channel();
        // Dropped on every way out of this call, which is what ends the child.
        let _child = Child(Some(Held {
            process,
            cause: Some(cause),
            kept: Box::new(keep),
            group,
            slot,
        }));

        // The deadline covers `f` alone; the handshake has its own bound.
        let client = tokio::time::timeout(self.times.connect, connect::<Cli>(sup_end))
            .await
            .map_err(|_elapsed| SupervisorError::Handshake(self.times.connect))?
            .map_err(SupervisorError::Spawn)?;
        let answer = tokio::time::timeout(self.deadline, f(client))
            .await
            .map_err(|_elapsed| SupervisorError::Deadline(self.deadline))?;
        let exit = Exit {
            cause: settled,
            within: self.times.exit_wait,
        };
        Ok((answer, exit))
    }
}
