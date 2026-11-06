//! What the children take in memory, held by the kernel rather than reserved.
//!
//! A child is given memory as it touches it. The kernel's memory controller
//! holds every child of a runner together to one total: a control group
//! `children/` with the total as its limit, built once at boot
//! ([`Cgroups::create`]). Inside it each child has a group of its own, held to
//! the limits the child starts with ([`GroupLimits`]): its work — the child's
//! own process and the coprocesses of every kind it cannot do without
//! ([`CoprocessKind`]) — to one limit, and inside the work each of those to a
//! part of its own; beside the work, each expendable kind to a part of its
//! own. What a process maps of the supervisor's memory counts against its part
//! and the work as what it holds does. The kernel does not refuse memory at a
//! limit, it kills, and whom it picks is set by each process's score
//! ([`oom_score_adj`]). What it records about the kills is what
//! [`ExitCause`] reads.
//!
//! Nothing a child had is handed to the next. Each child gets a group made for
//! it ([`ChildGroup`]) and removed once it is empty, and an identity no other
//! child of this boot has had or will have ([`CHILD_UID_BASE`]). So whatever a
//! child leaves behind under its identity — anything the kernel keeps for an
//! identity past its processes — no later round can reach. The supervisor
//! itself stays in the root group, which has no limit, so a kill at the total
//! never takes the process every round depends on.

use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::runner::CoprocessKind;

/// A child group's `memory.peak`, where a build keeps one.
#[cfg(feature = "debug")]
type Peak = std::fs::File;
#[cfg(not(feature = "debug"))]
type Peak = ();

/// The first child's identity: the `n`-th child of this boot runs as this
/// plus `n`, user and group alike, and no identity is used twice in a boot.
///
/// No account database names these — the image has none — and that is fine:
/// the kernel compares numbers. What matters is that none is root and no two
/// children share one. Against another identity, a child cannot signal the
/// supervisor or a sibling, cannot read or change their resource limits, and
/// cannot open their ptrace-gated `/proc` entries — `/proc/<pid>/fd` among
/// them, through which a root child could reopen any descriptor the supervisor
/// holds, every cached composition's cwasm included, because reading another
/// process's descriptors needs only the READ ptrace mode and Yama gates only
/// ATTACH. The entries the kernel serves to anyone — a sibling's `status`, its
/// `cgroup`, the `oom_score_adj` the supervisor gave it — are hidden by
/// `/proc`'s `hidepid=invisible`, which the worker's own `proc` service mounts
/// it with and [`Cgroups::create`] checks: each identity sees only its own. It cannot write a cgroup file, all
/// of which are root's, so it cannot move itself out of its group or raise its
/// own max, and it cannot even look inside `children/`, which only root may
/// enter; it cannot raise a hard limit; and it cannot open `/proc/kmsg`.
///
/// Never reused, so what outlives a child's processes under its identity — the
/// child's syscall filter allows it nothing of the kind, and this does not rest
/// on that — belongs to an identity no later child has.
///
/// What the identity does NOT take away is the child's own inherited cwasm: the
/// memfd it reopens through `/proc/self/fd/N` was created world-readable, and
/// the kernel lets any process reach its own descriptors whatever its identity.
pub(crate) const CHILD_UID_BASE: u32 = 65_536;

/// How many tasks one child may have alive at once ([`ChildLimits::tasks`])
/// unless the host says otherwise (each worker's `child-max-tasks` setting).
///
/// An executor child runs a current-thread runtime plus the few blocking-pool
/// threads remoc decodes a large item on, so an honest child is nowhere near
/// this.
pub const DEFAULT_CHILD_MAX_TASKS: u64 = 64;

/// Where the cgroup v2 hierarchy is mounted: each worker's `cgroup` service
/// (image/init/services) mounts it there before the supervisor starts. The children's group is `children/`
/// directly below it.
#[cfg(all(target_os = "linux", feature = "guest-hardening"))]
const ROOT: &std::ffi::CStr = c"/sys/fs/cgroup";

/// What the children may hold: memory, in bytes, and tasks.
#[derive(Clone, Copy, Debug)]
pub struct ChildLimits {
    /// Every child together: the children's group's `memory.max`. Set once at
    /// boot and never lowered — the kernel meets a lowered limit by reclaiming
    /// and then killing until usage fits.
    pub total: u64,
    /// The most any of a child's [`GroupLimits`] is set to.
    pub max: u64,
    /// What must be free before a child is started, in the children's total and
    /// in the guest's available memory alike. A gate read before each spawn, not
    /// a reservation: several children can pass on the same reading.
    pub headroom: u64,
    /// How many tasks — threads count — one child may have alive at once, held
    /// by `RLIMIT_NPROC` on its identity ([`DEFAULT_CHILD_MAX_TASKS`]).
    ///
    /// What it bounds is a child an escape turns into native code: each task is
    /// a PID out of the guest's, and a few children creating threads without end
    /// would leave the supervisor none to start the next child with. Each
    /// coprocess beside a child has the same cap under its own identity. Boot
    /// checks that the most processes a runner holds at once, each at this cap,
    /// still leave half the guest's PIDs. Too few, and an honest child cannot
    /// start its runtime — its rounds fail, and nothing else does.
    pub tasks: u64,
}

/// What one child's group is held to, set as the child starts: budgets, each
/// held to the runner's [`ChildLimits::max`]. What a process maps of the
/// supervisor's memory — the descriptors it inherits — comes off its part's
/// and, for a process of the work, off the work's, from its start until the
/// group goes: its pages are charged where the supervisor wrote them, so this
/// is what counts them against the group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupLimits {
    /// The child's work: its own process and every coprocess of a kind it
    /// cannot do without, together.
    pub max: u64,
    /// The child's own process.
    pub child: u64,
    /// Each kind of coprocess, in the order of the runner's
    /// [`CoprocessKind`]s; a kind given none is held to the work's alone, or
    /// to nothing of its own if it is expendable.
    pub kinds: Vec<u64>,
}

/// Why a child's life ended, as far as the kernel's record of it can say. Read
/// once the child's group is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitCause {
    /// Killed at a limit of its own — its part's, or its work's — while the
    /// children's total was never reached during its life. The kernel's
    /// record reads the same for one other end: a child whose work reached a
    /// limit unkilled, and that was later killed because the whole guest ran
    /// short.
    OutgrewItsMax,
    /// Anything else — it exited, its runner killed it, it was the one the
    /// kernel picked when the total or the guest ran short, or a kill whose
    /// cause the record does not settle.
    Unattributed,
}

/// What is left of a child's limits as its processes start, each less what
/// the processes started so far map of the supervisor's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Left {
    /// The work's.
    work: u64,
    /// The child's part's.
    child: u64,
    /// Each kind's part's, in the runner's order.
    kinds: Vec<u64>,
}

/// The children's group, built at boot, and the count every child's group and
/// identity are numbered by.
#[derive(Debug)]
pub struct Cgroups {
    limits: ChildLimits,
    group: PathBuf,
    /// How many children this boot has made. Only ever goes up.
    made: AtomicU64,
}

/// One child's own group, made for it before its spawn and removed as it
/// drops: the group and its work, with no process of their own; inside the
/// work the child's part, [`CHILD_PART`], and a part for each kind of
/// coprocess it cannot do without; beside the work a part for each
/// expendable kind. Each kind's part is named after it.
pub(crate) struct ChildGroup {
    path: PathBuf,
    /// The kinds' parts, in the runner's order.
    kinds: Vec<PathBuf>,
    /// The children's group's `memory.events.local`, where a kill at the total
    /// is counted.
    total_events: PathBuf,
    /// How often the children's total had been reached when this child was
    /// made: [`ExitCause`] asks whether that moved during its life.
    total_oom_before: u64,
    /// What the group's drop asks the kernel to reclaim before the group goes:
    /// the most it could have left charged.
    reclaim: u64,
    #[cfg_attr(not(feature = "debug"), allow(dead_code))]
    peak: Peak,
}

/// The child's own part of its work.
pub(crate) const CHILD_PART: &str = "child";

/// The child's work in its group.
pub(crate) const WORK: &str = "work";

/// Where `kind`'s part lies in the group at `group`: in the work, unless the
/// kind is expendable.
fn part(group: &Path, kind: &CoprocessKind) -> PathBuf {
    if kind.expendable {
        group.join(kind.name)
    } else {
        group.join(WORK).join(kind.name)
    }
}

/// What a child is given before its exec, besides its fds: its group, its
/// out-of-memory score, its identity and its task cap. Built in the parent, so
/// the post-fork code allocates nothing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct Placement {
    /// The `cgroup.procs` of the part of the child's group it runs in, written
    /// `0` — the writer itself — first. `None` places the identity alone.
    /// Opened for this spawn: it closes at the child's exec and with the spawn
    /// in the parent.
    pub(crate) procs: Option<OwnedFd>,
    /// The decimal text written to `/proc/self/oom_score_adj`.
    pub(crate) oom_score_adj: Vec<u8>,
    /// User and group id alike.
    pub(crate) uid: u32,
    /// `RLIMIT_NPROC`, soft and hard.
    pub(crate) tasks: u64,
}

/// The two counters a child's exit cause is read from, as `memory.events.local`
/// reports them for one group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Counters {
    /// Times this group's own limit was reached and the kernel went to kill.
    oom: u64,
    /// Processes in this group the kernel killed for memory, wherever the
    /// limit was.
    oom_kill: u64,
}

impl Cgroups {
    /// Build the children's group for a runner that holds at most `processes`
    /// at once — its children, and the coprocesses each may have beside it — at
    /// `limits`, or `None` where this build does not hold its children to their
    /// memory.
    ///
    /// Under `guest-hardening` — the feature the measured image builds with — it
    /// never returns `None`: it builds the group or stops the boot, naming the
    /// step that failed on the log device. It checks before it builds: what is
    /// mounted is cgroup v2 with the memory controller, this process sits at the
    /// root, `processes` at their task cap leave half the guest's PIDs, the
    /// kernel log is closed to every reader without CAP_SYSLOG and `/dev/kmsg`
    /// to every reader at all, `/proc` shows no process another's entries
    /// unless it may trace it, and the limits hold one child at its max with at
    /// least one task. Then it builds the group, and scores this process
    /// `-1000`, the one score the kernel never kills at: every process of a
    /// child's group is scored above it, so a kill for the whole guest takes
    /// one of theirs before the process they all depend on.
    /// `children/` must not exist yet: this process runs once per boot, so a
    /// group already there was built by something else, with limits this
    /// process did not set.
    ///
    /// Elsewhere it is `None`: a developer's machine has no cgroup v2 root this
    /// process may build under, and making one needs root.
    pub fn create(limits: ChildLimits, processes: usize) -> Option<Self> {
        #[cfg(all(target_os = "linux", feature = "guest-hardening"))]
        {
            use safe_logger::{debug, error_and_panic, reason, safe};

            match Self::build(limits, processes) {
                Ok(cgroups) => Some(cgroups),
                Err((step, e)) => {
                    debug!("{e}");
                    error_and_panic!(
                        "engine-supervisor: cannot hold the round children to their memory — {} \
                         failed. The measured image boots this role's kernel with the memory \
                         controller, mounts cgroup v2 and shuts the kernel log; a guest without \
                         them is mis-provisioned. Stopping.",
                        safe(
                            &step,
                            reason!("a constant naming a step of this build's own boot")
                        ),
                        reason!("a constant, emitted once at boot before any request exists"),
                    );
                }
            }
        }
        #[cfg(not(all(target_os = "linux", feature = "guest-hardening")))]
        {
            let _ = (limits, processes);
            None
        }
    }

    #[cfg(all(target_os = "linux", feature = "guest-hardening"))]
    fn build(limits: ChildLimits, processes: usize) -> Result<Self, (&'static str, io::Error)> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::DirBuilderExt;

        fn at<T>(step: &'static str, r: io::Result<T>) -> Result<T, (&'static str, io::Error)> {
            r.map_err(|e| (step, e))
        }
        fn refused(step: &'static str) -> (&'static str, io::Error) {
            (step, io::Error::other(step))
        }

        if processes == 0 || limits.max > limits.total || limits.tasks == 0 {
            return Err(refused(
                "checking the limits hold one child at its max, with a task to run in",
            ));
        }

        let fs = at(
            "reading what is mounted at /sys/fs/cgroup",
            rustix::fs::statfs(ROOT).map_err(io::Error::from),
        )?;
        // `f_type` is signed on glibc and unsigned on musl; the magic is `c_long`.
        if fs.f_type as i64 != libc::CGROUP2_SUPER_MAGIC {
            return Err(refused("finding cgroup v2 mounted at /sys/fs/cgroup"));
        }
        let root = Path::new(std::ffi::OsStr::from_bytes(ROOT.to_bytes()));
        let controllers = at(
            "reading the available controllers",
            std::fs::read_to_string(root.join("cgroup.controllers")),
        )?;
        if !controllers.split_ascii_whitespace().any(|c| c == "memory") {
            return Err(refused("finding the memory controller"));
        }
        let own = at(
            "reading this process's group",
            std::fs::read_to_string("/proc/self/cgroup"),
        )?;
        if own != "0::/\n" {
            return Err(refused("finding this process at the root group"));
        }
        let pid_max = at(
            "reading the guest's PID bound",
            std::fs::read_to_string("/proc/sys/kernel/pid_max"),
        )?;
        let pid_max = pid_max
            .trim()
            .parse::<u64>()
            .map_err(|_| refused("reading the guest's PID bound"))?;
        if (processes as u64).saturating_mul(limits.tasks) > pid_max / 2 {
            return Err(refused(
                "fitting every process's task cap within half the guest's PIDs",
            ));
        }
        // With the kernel log open to reading — and it is, to any identity,
        // unless the command line shuts it — a child could read the kernel's
        // report of a sibling's out-of-memory kill. `/proc/kmsg` asks for
        // CAP_SYSLOG whatever is set; the other two doors are the measured
        // command line's to shut: `/dev/kmsg`, shut and locked shut, and
        // `syslog(2)`, restricted to a holder of CAP_SYSLOG. The child's
        // syscall filter refuses `syslog` as well; this is the kernel's
        // refusal beside it.
        let devkmsg = at(
            "reading the kernel log's access",
            std::fs::read_to_string("/proc/sys/kernel/printk_devkmsg"),
        )?;
        let restricted = at(
            "reading the kernel log's access",
            std::fs::read_to_string("/proc/sys/kernel/dmesg_restrict"),
        )?;
        if devkmsg.trim() != "off" || restricted.trim() != "1" {
            return Err(refused("finding the kernel log closed to every reader"));
        }

        // `/proc` shows a process's entries only to those that may trace it,
        // so a child sees its own and none of its siblings' — not even the
        // `status`, `cgroup` and `oom_score_adj` the kernel otherwise serves
        // to anyone, which would say which other rounds are running and how
        // large each one's composition is. This process reads only its own.
        // The worker's `proc` service mounts it so; this process has no right
        // to mount, and checks.
        let mounts = at(
            "reading what is mounted at /proc",
            std::fs::read_to_string("/proc/self/mountinfo"),
        )?;
        if !proc_hides_entries(&mounts) {
            return Err(refused("finding /proc mounted hidepid=invisible"));
        }

        at(
            "enabling the memory controller below the root",
            write(&root.join("cgroup.subtree_control"), "+memory"),
        )?;
        // The group every child of the runner lives under. It holds no process
        // itself — the kernel allows controllers below a group only when it
        // does not. Root's alone to enter: a child has no business reading its
        // siblings' memory and kill counts.
        let group = root.join("children");
        at(
            "creating the children's group",
            std::fs::DirBuilder::new().mode(0o700).create(&group),
        )?;
        at(
            "enabling the memory controller below the children's group",
            write(&group.join("cgroup.subtree_control"), "+memory"),
        )?;
        // `memory.oom.group` stays 0 here: set on this group, one child past
        // the total would take every child with it.
        at(
            "setting the children's total",
            write(&group.join("memory.max"), &limits.total.to_string()),
        )?;
        // Last for every kill: each child's process and coprocess is scored
        // above this one. A child inherits the score at its fork and writes
        // its own before its exec, or does not exec.
        at(
            "scoring this process last for the kernel's kills",
            write(Path::new("/proc/self/oom_score_adj"), "-1000"),
        )?;

        Ok(Self {
            limits,
            group,
            made: AtomicU64::new(0),
        })
    }

    /// Whether one more child may start: see [`room_for_one_more`]. Read fresh
    /// on every call, so a caller polls it.
    pub(crate) fn room(&self) -> io::Result<bool> {
        let children = std::fs::read_to_string(self.group.join("memory.current"))?;
        let children = children
            .trim()
            .parse::<u64>()
            .map_err(|_| io::Error::other("memory.current is not a number"))?;
        let available = mem_available(&std::fs::read_to_string("/proc/meminfo")?)
            .ok_or_else(|| io::Error::other("/proc/meminfo has no MemAvailable"))?;
        Ok(room_for_one_more(
            children,
            self.limits.total,
            available,
            self.limits.headroom,
        ))
    }

    /// What is left of `limits`, each held to the runner's max, once the child
    /// maps its `inherited` bytes of the supervisor's: off its part and off
    /// the work. `None` where that leaves either nothing — the child would map
    /// more than its limits hold.
    pub(crate) fn left(&self, limits: &GroupLimits, inherited: u64) -> Option<Left> {
        let held = |limit: u64| limit.min(self.limits.max);
        let after = |limit: u64| held(limit).checked_sub(inherited).filter(|&left| left > 0);
        Some(Left {
            work: after(limits.max)?,
            child: after(limits.child)?,
            kinds: limits.kinds.iter().map(|&limit| held(limit)).collect(),
        })
    }

    /// Make the next child's group at `left` — the group, its work with the
    /// child's part and a part for each of `kinds` it cannot do without, and
    /// beside the work a part for each expendable kind — and what the child is
    /// given before its exec to enter its part under its own identity and
    /// score ([`oom_score_adj`]).
    ///
    /// Fails once this boot has run through every identity it may give, rather
    /// than give one twice.
    pub(crate) fn new_child(
        &self,
        left: &Left,
        kinds: &[CoprocessKind],
    ) -> io::Result<(ChildGroup, Placement)> {
        let n = self.made.fetch_add(1, Ordering::Relaxed);
        let uid = child_uid(n)
            .ok_or_else(|| io::Error::other("every child identity of this boot is used"))?;
        let total_events = self.group.join("memory.events.local");
        let total_oom_before = read_counters(&total_events)?.oom;

        let path = self.group.join(format!("c{n}"));
        let work = path.join(WORK);
        let child = work.join(CHILD_PART);
        let parts: Vec<PathBuf> = kinds.iter().map(|kind| part(&path, kind)).collect();
        let made = (|| -> io::Result<(OwnedFd, Peak)> {
            // Neither the group nor the work holds a process itself: the
            // kernel allows controllers below a group only when it does not.
            // Their `memory.oom.group` stays 0, so a kill at the work's limit
            // takes one part's processes, not the work's every one.
            std::fs::create_dir(&path)?;
            write(&path.join("cgroup.subtree_control"), "+memory")?;
            std::fs::create_dir(&work)?;
            write(&work.join("memory.max"), &left.work.to_string())?;
            write(&work.join("cgroup.subtree_control"), "+memory")?;
            std::fs::create_dir(&child)?;
            write(&child.join("memory.max"), &left.child.to_string())?;
            // A kill in the child's part takes everything in it.
            write(&child.join("memory.oom.group"), "1")?;
            for (k, (part, kind)) in parts.iter().zip(kinds).enumerate() {
                std::fs::create_dir(part)?;
                if let Some(limit) = left.kinds.get(k) {
                    write(&part.join("memory.max"), &limit.to_string())?;
                }
                // A kill in the part of a kind the child cannot do without
                // takes every process of it; in an expendable kind's, the one
                // the kernel picks, alone.
                if !kind.expendable {
                    write(&part.join("memory.oom.group"), "1")?;
                }
            }
            let procs = std::fs::OpenOptions::new()
                .write(true)
                .open(child.join("cgroup.procs"))?;
            #[cfg(feature = "debug")]
            let peak = std::fs::File::open(path.join("memory.peak"))?;
            #[cfg(not(feature = "debug"))]
            let peak = ();
            Ok((OwnedFd::from(procs), peak))
        })();
        let (procs, peak) = match made {
            Ok(made) => made,
            Err(e) => {
                for part in &parts {
                    let _ = std::fs::remove_dir(part);
                }
                let _ = std::fs::remove_dir(&child);
                let _ = std::fs::remove_dir(&work);
                let _ = std::fs::remove_dir(&path);
                return Err(e);
            }
        };

        let expendable_room = parts
            .iter()
            .zip(kinds)
            .enumerate()
            .filter(|(_, (_, kind))| kind.expendable)
            .map(|(k, _)| left.kinds.get(k).copied().unwrap_or(self.limits.max))
            .fold(0, u64::saturating_add);
        let group = ChildGroup {
            path,
            kinds: parts,
            total_events,
            total_oom_before,
            reclaim: left.work.saturating_add(expendable_room),
            peak,
        };
        let placement = Placement {
            procs: Some(procs),
            oom_score_adj: oom_score_adj(false).to_string().into_bytes(),
            uid,
            tasks: self.limits.tasks,
        };
        Ok((group, placement))
    }

    /// What the `k`-th of the runner's kinds, `kind`, a coprocess started
    /// beside a child, is given before its exec: its kind's part of the
    /// child's group at `group`, so it is held to its part's limit — and the
    /// work's, for a kind the child cannot do without — and killed with the
    /// group; its score ([`oom_score_adj`]); and an identity of its own.
    /// Numbered by the same count as every child's, so it is no child's and
    /// no other coprocess's: against it the child can neither signal nor trace
    /// the coprocess, nor the coprocess the child.
    ///
    /// What it maps of the supervisor's, its `inherited` bytes, comes off its
    /// part's limit and, in the work, off the work's, before it starts: from
    /// `left`, which keeps what is left. A limit lowered below what its part
    /// already holds is met by the kernel as one reached: it kills there
    /// before the write returns, and a limit left with nothing ends all of it.
    pub(crate) fn coprocess(
        &self,
        group: &Path,
        k: usize,
        kind: &CoprocessKind,
        inherited: u64,
        left: &mut Left,
    ) -> io::Result<Placement> {
        let n = self.made.fetch_add(1, Ordering::Relaxed);
        let uid = child_uid(n)
            .ok_or_else(|| io::Error::other("every child identity of this boot is used"))?;
        let part = part(group, kind);
        if inherited > 0 {
            if let Some(limit) = left.kinds.get_mut(k) {
                *limit = limit.saturating_sub(inherited);
                write(&part.join("memory.max"), &limit.to_string())?;
            }
            if !kind.expendable {
                left.work = left.work.saturating_sub(inherited);
                write(&group.join(WORK).join("memory.max"), &left.work.to_string())?;
            }
        }
        let procs = std::fs::OpenOptions::new()
            .write(true)
            .open(part.join("cgroup.procs"))?;
        Ok(Placement {
            procs: Some(OwnedFd::from(procs)),
            oom_score_adj: oom_score_adj(kind.expendable).to_string().into_bytes(),
            uid,
            tasks: self.limits.tasks,
        })
    }
}

impl ChildGroup {
    /// The group's directory, whose parts the coprocesses started beside the
    /// child join.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Kill everything in the group. The kernel delivers `SIGKILL` to every task
    /// in it and to any task forked into it while it does. Best effort: a
    /// failure here is followed by the wait for the group to empty.
    pub(crate) fn kill(&self) {
        let _ = write(&self.path.join("cgroup.kill"), "1");
    }

    /// Returns once the group holds no process. No upper bound: a group that
    /// does not empty keeps its slot, because what is in it keeps its memory.
    pub(crate) async fn emptied(&self) {
        let events = self.path.join("cgroup.events");
        let mut pause = std::time::Duration::from_millis(1);
        loop {
            let text = std::fs::read_to_string(&events).ok();
            if text.as_deref().and_then(populated) == Some(false) {
                return;
            }
            tokio::time::sleep(pause).await;
            pause = (pause * 2).min(std::time::Duration::from_millis(100));
        }
    }

    /// Why the child ended. Only meaningful once the group is empty: the
    /// kernel counts a kill before it sends it. A record that cannot be read
    /// attributes nothing.
    pub(crate) fn exit_cause(&self) -> ExitCause {
        let work = self.path.join(WORK);
        let read = || -> io::Result<Record> {
            Ok(Record {
                child: read_counters(&work.join(CHILD_PART).join("memory.events.local"))?,
                work: read_counters(&work.join("memory.events.local"))?,
                total_oom_before: self.total_oom_before,
                total_oom_after: read_counters(&self.total_events)?.oom,
            })
        };
        read().map_or(ExitCause::Unattributed, |record| record.cause())
    }

    /// The highest the group reached, in bytes.
    #[cfg(feature = "debug")]
    pub(crate) fn peak(&self) -> Option<u64> {
        use std::os::unix::fs::FileExt;
        let mut buf = [0u8; 32];
        let n = self.peak.read_at(&mut buf, 0).ok()?;
        std::str::from_utf8(&buf[..n]).ok()?.trim().parse().ok()
    }
}

/// Remove the group. Only an empty group can go; one dropped while something
/// is still in it stays where it is.
///
/// What a child caused that outlives it — the cache entries of every path it
/// looked up, for one — stays charged to its group until something reclaims
/// it, and counts against the total [`Cgroups::room`] reads; a group removed
/// with charges still on it lingers in the kernel until they go. So they are
/// reclaimed first. Best effort, and blocking: reclaiming is the kernel's work
/// done on the dropping thread.
impl Drop for ChildGroup {
    fn drop(&mut self) {
        let _ = write(&self.path.join("memory.reclaim"), &self.reclaim.to_string());
        for part in &self.kinds {
            let _ = std::fs::remove_dir(part);
        }
        let work = self.path.join(WORK);
        let _ = std::fs::remove_dir(work.join(CHILD_PART));
        let _ = std::fs::remove_dir(&work);
        let _ = std::fs::remove_dir(&self.path);
        #[cfg(feature = "debug")]
        self.log_removal();
    }
}

impl ChildGroup {
    /// Whether the group is gone, and what the kernel counts under `children`
    /// after it: `nr_dying_descendants` is the removed groups it still holds.
    #[cfg(feature = "debug")]
    fn log_removal(&self) {
        let stat = self
            .path
            .parent()
            .and_then(|children| std::fs::read_to_string(children.join("cgroup.stat")).ok())
            .unwrap_or_default();
        let state = if self.path.exists() {
            "left behind"
        } else {
            "removed"
        };
        safe_logger::debug!(
            "child group {state}; children: {}",
            stat.split_whitespace().collect::<Vec<_>>().join(" ")
        );
    }
}

/// The identity of the `n`-th child of this boot, or `None` once they run out.
/// The kernel's last valid id is one below `-1`.
fn child_uid(n: u64) -> Option<u32> {
    let uid = u64::from(CHILD_UID_BASE).checked_add(n)?;
    u32::try_from(uid).ok().filter(|&uid| uid != u32::MAX)
}

/// Write `value` to a file that exists. Never creates or truncates: every file
/// this writes is a control file of the kernel's, and a path that is not one
/// should fail rather than become a regular file.
fn write(path: &Path, value: &str) -> io::Result<()> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .write_all(value.as_bytes())
}

/// Whether one more child may start: the children together still have
/// `headroom` under their `total`, AND the guest has `headroom` available.
///
/// The second half is not implied by the first. The root group — the
/// supervisor, its cache and the bundles streaming into it — has no limit, and
/// what it reserves at boot is a count and not a hold. A guest short of memory
/// everywhere ends in a kill the kernel picks from the whole guest, and a child
/// started into that is one more thing for it to pick.
///
/// A gate, not a reservation: several children can pass at once on the same
/// reading, before any of them has grown. The kernel's limits are what hold;
/// this turns most of an overload into a refusal before anything starts.
pub(crate) fn room_for_one_more(children: u64, total: u64, available: u64, headroom: u64) -> bool {
    children
        .checked_add(headroom)
        .is_some_and(|needed| needed <= total)
        && available >= headroom
}

/// A group's `memory.events.local`.
fn read_counters(path: &Path) -> io::Result<Counters> {
    counters(&std::fs::read_to_string(path)?)
        .ok_or_else(|| io::Error::other("memory.events.local is not as expected"))
}

/// `oom` and `oom_kill` out of a `memory.events.local`, which reads one
/// `name value` pair per line.
fn counters(text: &str) -> Option<Counters> {
    let mut oom = None;
    let mut oom_kill = None;
    for line in text.lines() {
        let mut words = line.split_ascii_whitespace();
        match (words.next(), words.next().map(str::parse::<u64>)) {
            (Some("oom"), Some(Ok(v))) => oom = Some(v),
            (Some("oom_kill"), Some(Ok(v))) => oom_kill = Some(v),
            _ => {}
        }
    }
    Some(Counters {
        oom: oom?,
        oom_kill: oom_kill?,
    })
}

/// The `populated` line of a `cgroup.events`.
fn populated(text: &str) -> Option<bool> {
    match text
        .lines()
        .find_map(|line| line.strip_prefix("populated "))?
        .trim()
    {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// Whether `/proc` shows each process's entries only to those that may trace
/// it, by `/proc/self/mountinfo`: the mount on top at `/proc` is procfs, and
/// every procfs mounted anywhere — each an instance with options of its own —
/// has `hidepid=invisible` and no `gid=`, the group that option would let see
/// everything. A line is the mount's own fields, ` - `, then the filesystem
/// type, the source and the superblock's options; the mount point is the fifth
/// field, escaped, so it holds no space.
#[cfg_attr(
    not(all(target_os = "linux", feature = "guest-hardening")),
    allow(dead_code)
)]
fn proc_hides_entries(mountinfo: &str) -> bool {
    let mounts = || {
        mountinfo.lines().filter_map(|line| {
            let (mount, superblock) = line.split_once(" - ")?;
            let point = mount.split(' ').nth(4)?;
            let mut fields = superblock.split(' ');
            let (kind, _source, options) = (fields.next()?, fields.next()?, fields.next()?);
            Some((point, kind, options))
        })
    };
    let hides = |options: &str| {
        options.split(',').any(|o| o == "hidepid=invisible")
            && !options.split(',').any(|o| o.starts_with("gid="))
    };
    mounts()
        .rev()
        .find(|&(point, _, _)| point == "/proc")
        .is_some_and(|(_, kind, _)| kind == "proc")
        && mounts()
            .filter(|&(_, kind, _)| kind == "proc")
            .all(|(_, _, options)| hides(options))
}

/// `MemAvailable` out of `/proc/meminfo`, in bytes.
fn mem_available(meminfo: &str) -> Option<u64> {
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    kib.checked_mul(1024)
}

/// What the kernel counted in a child's work over its life, read once the
/// group is empty: each counter started at zero with its group.
struct Record {
    /// The child's own part.
    child: Counters,
    /// The work: its `oom` is its limit reached.
    work: Counters,
    /// The children's total reached, as many times as when the child was made.
    total_oom_before: u64,
    /// And as many times once the group was empty.
    total_oom_after: u64,
}

impl Record {
    /// Why the child ended, by what was counted where: its own where it was
    /// killed at its part's limit or at its work's — the limit reached there,
    /// and the kernel killing it — and the children's total never reached
    /// meanwhile.
    ///
    /// All of that, because each part alone admits an innocent child. A kill
    /// at the total raises the victim's `oom_kill` and the children's `oom`,
    /// not the part's or the work's `oom`. A limit can be reached with nothing
    /// killed, when memory came free in time, and the child then be the victim
    /// of a kill at the total, which the total's count tells. The one case this
    /// still calls the child's own is a work that reached a limit unkilled and
    /// was later the victim of a kill for the whole guest, which raises no
    /// group's `oom`. What is in the work is the child's and what it cannot do
    /// without, so the kernel's pick inside it — by what each process has
    /// resident — needs no more telling apart. An expendable coprocess has its
    /// part beside the work, and nothing it holds reaches the work's limit.
    fn cause(&self) -> ExitCause {
        let own_limit = self.child.oom > 0 || self.work.oom > 0;
        if self.total_oom_after == self.total_oom_before && own_limit && self.child.oom_kill > 0 {
            ExitCause::OutgrewItsMax
        } else {
            ExitCause::Unattributed
        }
    }
}

/// The `oom_score_adj` of a process of a child's group: [`EXPENDABLE_SCORE`]
/// for a coprocess of an expendable kind, `0` — the kernel's own — for the
/// child and every other coprocess.
///
/// Where the children's total or the whole guest runs short, the kernel picks
/// the victim by what each process has resident — its pages, page tables —
/// plus its score in thousandths of that limit: a score of 1000 adds a whole
/// limit, so it takes an expendable coprocess before any other process of any
/// child. Inside a work, the rest are compared by what they have resident,
/// which counts what they map of the supervisor's — a child's cwasm, a model's
/// files — though their group is not charged for it: the pick in a work ends
/// the work's own either way.
///
/// No other process of a group is scored below `0`: the guest's own
/// long-running processes keep the kernel's `0`, and a child's process scored
/// below them could see them killed first in a kill for the whole guest. The
/// supervisor alone is scored `-1000` ([`Cgroups::create`]), the one score
/// the kernel never kills at — never a child's process: a group whose every
/// process is unchosen leaves the charge that reached the limit waiting for
/// good. Written before the identity changes, by a holder of
/// CAP_SYS_RESOURCE, so it is also the floor the process cannot lower itself
/// below.
fn oom_score_adj(expendable: bool) -> i32 {
    if expendable { EXPENDABLE_SCORE } else { 0 }
}

/// The score of a coprocess of an expendable kind: the most there is.
const EXPENDABLE_SCORE: i32 = 1000;

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn counted(oom: u64, oom_kill: u64) -> Counters {
        Counters { oom, oom_kill }
    }

    #[test]
    fn room_needs_the_total_and_the_guest_both() {
        assert!(room_for_one_more(
            100 * MIB,
            512 * MIB,
            1024 * MIB,
            128 * MIB
        ));
        // the total is short
        assert!(!room_for_one_more(
            400 * MIB,
            512 * MIB,
            1024 * MIB,
            128 * MIB
        ));
        // the guest is short
        assert!(!room_for_one_more(0, 512 * MIB, 64 * MIB, 128 * MIB));
        // exactly enough of both
        assert!(room_for_one_more(
            384 * MIB,
            512 * MIB,
            128 * MIB,
            128 * MIB
        ));
        // a reading at the top of the range is no room, rather than wrapping
        assert!(!room_for_one_more(u64::MAX, u64::MAX, u64::MAX, 1));
    }

    /// Every child of a boot gets an identity of its own, never root, never
    /// `-1`, and none at all once they run out.
    #[test]
    fn identities_are_never_given_twice() {
        assert_eq!(child_uid(0), Some(CHILD_UID_BASE));
        assert_eq!(child_uid(1), Some(CHILD_UID_BASE + 1));
        let last = u64::from(u32::MAX - 1 - CHILD_UID_BASE);
        assert_eq!(child_uid(last), Some(u32::MAX - 1));
        assert_eq!(child_uid(last + 1), None);
        assert_eq!(child_uid(u64::MAX), None);
    }

    /// The kernel's own format for `memory.events.local`.
    #[test]
    fn counters_read_the_kernels_format() {
        let text = "low 0\nhigh 0\nmax 12\noom 3\noom_kill 2\noom_group_kill 1\n";
        assert_eq!(counters(text), Some(counted(3, 2)));
        assert_eq!(counters(""), None);
        assert_eq!(counters("oom 1\n"), None);
        assert_eq!(counters("oom x\noom_kill 1\n"), None);
    }

    #[test]
    fn proc_mounted_hidepid_invisible_hides_entries() {
        let mountinfo = "\
22 1 0:20 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible
23 1 0:21 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
";
        assert!(proc_hides_entries(mountinfo));
    }

    #[test]
    fn proc_mounted_plain_does_not() {
        let mountinfo = "22 1 0:20 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";
        assert!(!proc_hides_entries(mountinfo));
    }

    #[test]
    fn the_mount_on_top_is_the_one_that_counts() {
        // Hidden first, then mounted over without it.
        let mountinfo = "\
22 1 0:20 / /proc rw,relatime - proc proc rw,hidepid=invisible
30 22 0:25 / /proc rw,relatime - proc proc rw
";
        assert!(!proc_hides_entries(mountinfo));
        // Optional fields before the separator do not shift the rest.
        let shared = "22 1 0:20 / /proc rw shared:1 master:2 - proc proc rw,hidepid=invisible\n";
        assert!(proc_hides_entries(shared));
    }

    #[test]
    fn a_group_let_see_everything_does_not() {
        let mountinfo = "22 1 0:20 / /proc rw - proc proc rw,gid=65536,hidepid=invisible\n";
        assert!(!proc_hides_entries(mountinfo));
    }

    #[test]
    fn a_second_procfs_without_it_does_not() {
        // Each procfs is its own instance: one elsewhere, mounted plain, shows
        // every entry whatever /proc does.
        let mountinfo = "\
22 1 0:20 / /proc rw - proc proc rw,hidepid=invisible
40 25 0:30 / /run/proc rw - proc proc rw
";
        assert!(!proc_hides_entries(mountinfo));
    }

    #[test]
    fn something_else_at_proc_does_not() {
        let mountinfo = "22 1 0:20 / /proc rw - tmpfs tmpfs rw,hidepid=invisible\n";
        assert!(!proc_hides_entries(mountinfo));
        assert!(!proc_hides_entries(""));
    }

    /// A work's record: the child's part, the work, and the children's total
    /// reached `before` and `after`.
    fn record(child: Counters, work: Counters, before: u64, after: u64) -> Record {
        Record {
            child,
            work,
            total_oom_before: before,
            total_oom_after: after,
        }
    }

    const NONE: Counters = Counters {
        oom: 0,
        oom_kill: 0,
    };

    /// Killed at its own part's limit, or at its work's: its own. A kill in a
    /// part whose processes go together counts its victim twice, once picked
    /// and once with the rest.
    #[test]
    fn a_kill_at_a_limit_of_its_own_is_its_own() {
        assert_eq!(
            record(counted(1, 2), NONE, 5, 5).cause(),
            ExitCause::OutgrewItsMax
        );
        assert_eq!(
            record(counted(0, 2), counted(1, 0), 5, 5).cause(),
            ExitCause::OutgrewItsMax
        );
    }

    #[test]
    fn the_victim_of_a_kill_at_the_total_is_not() {
        let at_total = record(counted(0, 1), NONE, 5, 6);
        assert_eq!(at_total.cause(), ExitCause::Unattributed);
        let reached_then = record(counted(1, 1), NONE, 5, 6);
        assert_eq!(reached_then.cause(), ExitCause::Unattributed);
    }

    #[test]
    fn a_limit_reached_without_a_kill_is_not() {
        let unkilled = record(counted(1, 0), counted(1, 0), 5, 5);
        assert_eq!(unkilled.cause(), ExitCause::Unattributed);
        assert_eq!(record(NONE, NONE, 5, 5).cause(), ExitCause::Unattributed);
    }

    /// A runner whose groups are held to `max` at most.
    fn cgroups(max: u64) -> Cgroups {
        Cgroups {
            limits: ChildLimits {
                total: 4 * max,
                max,
                headroom: MIB,
                tasks: DEFAULT_CHILD_MAX_TASKS,
            },
            group: PathBuf::new(),
            made: AtomicU64::new(0),
        }
    }

    /// What the child maps comes off its part and its work, each first held
    /// to the runner's max; a child that would map all of either has nothing
    /// to run with.
    #[test]
    fn what_the_child_maps_comes_off_its_part_and_its_work() {
        let limits = GroupLimits {
            max: 384 * MIB,
            child: 512 * MIB,
            kinds: vec![256 * MIB, 1024 * MIB],
        };
        assert_eq!(
            cgroups(384 * MIB).left(&limits, 15 * MIB),
            Some(Left {
                work: 369 * MIB,
                child: 369 * MIB,
                kinds: vec![256 * MIB, 384 * MIB],
            })
        );
        assert_eq!(cgroups(384 * MIB).left(&limits, 384 * MIB), None);
        let small_child = GroupLimits {
            child: 15 * MIB,
            ..limits
        };
        assert_eq!(cgroups(384 * MIB).left(&small_child, 15 * MIB), None);
    }

    /// The kernel takes an expendable coprocess before anything else; the rest
    /// keep its own score.
    #[test]
    fn an_expendable_kind_is_scored_first_and_the_rest_as_the_kernel_does() {
        assert_eq!(oom_score_adj(true), 1000);
        assert_eq!(oom_score_adj(false), 0);
    }

    #[test]
    fn meminfo_and_events_read_the_kernels_format() {
        let meminfo = "MemTotal:        7720960 kB\nMemFree:         1234 kB\n\
                       MemAvailable:    2097152 kB\nBuffers:            0 kB\n";
        assert_eq!(mem_available(meminfo), Some(2048 * MIB));
        assert_eq!(mem_available("MemTotal: 1 kB\n"), None);
        assert_eq!(populated("populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(populated("populated 1\nfrozen 0\n"), Some(true));
        assert_eq!(populated("frozen 0\n"), None);
    }
}
