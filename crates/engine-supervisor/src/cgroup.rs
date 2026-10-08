//! What the children take in memory, held by the kernel rather than reserved.
//!
//! A child is given memory as it touches it. The kernel's memory controller
//! holds every child of a runner together to one total, and each alone to a max:
//! a control group `children/` with the total as its limit, built once at boot
//! ([`Cgroups::create`]), and inside it a group of the child's own with the max
//! as its limit. A child past its max, or the one the kernel picks when the
//! total is reached, is killed with everything in its group — the kernel does
//! not refuse memory at a limit, it kills. What it records about that kill is
//! what [`ExitCause`] reads.
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
/// `cgroup`, the `oom_score_adj` the supervisor gave it — are hidden by the
/// remount of `/proc` with `hidepid=invisible` at boot ([`Cgroups::create`]),
/// which leaves each identity only its own. It cannot write a cgroup file, all
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

/// Where the cgroup v2 hierarchy is mounted: each worker's inittab mounts it
/// there before the supervisor starts. The children's group is `children/`
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
    /// One child alone: its own group's `memory.max`.
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
    /// would leave the supervisor none to start the next child with. Boot checks
    /// that the most children a runner runs at once, each at this cap, still
    /// leave half the guest's PIDs. Too few, and an honest child cannot start
    /// its runtime — its rounds fail, and nothing else does.
    pub tasks: u64,
}

/// Why a child's life ended, as far as the kernel's record of it can say. Read
/// once the child's group is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitCause {
    /// Killed at its own max, while the children's total was never reached
    /// during its life. The kernel's record reads the same for one other end: a
    /// child that reached its max without being killed there, and was later
    /// killed because the whole guest ran short.
    OutgrewItsMax,
    /// Anything else — it exited, its runner killed it, it was the one the
    /// kernel picked when the total or the guest ran short, or a kill whose
    /// cause the record does not settle.
    Unattributed,
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
/// drops.
pub(crate) struct ChildGroup {
    path: PathBuf,
    /// The children's group's `memory.events.local`, where a kill at the total
    /// is counted.
    total_events: PathBuf,
    /// How often the children's total had been reached when this child was
    /// made: [`ExitCause`] asks whether that moved during its life.
    total_oom_before: u64,
    /// What the group's drop asks the kernel to reclaim before the group goes:
    /// the child's max, which is the most it could have left charged.
    max: u64,
    #[cfg_attr(not(feature = "debug"), allow(dead_code))]
    peak: Peak,
}

/// What a child is given before its exec, besides its fds: its group, its
/// out-of-memory score, its identity and its task cap. Built in the parent, so
/// the post-fork code allocates nothing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct Placement {
    /// The child's group's `cgroup.procs`, written `0` — the writer itself —
    /// first. `None` places the identity alone. Opened for this spawn: it closes
    /// at the child's exec and with the spawn in the parent.
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
    /// Build the children's group for a runner that runs at most `children` at
    /// once, at `limits`, or `None` where this build does not hold its children
    /// to their memory.
    ///
    /// Under `guest-hardening` — the feature the measured image builds with — it
    /// never returns `None`: it builds the group or stops the boot, naming the
    /// step that failed on the log device. It checks before it builds: what is
    /// mounted is cgroup v2 with the memory controller, this process sits at the
    /// root, `children` at their task cap leave half the guest's PIDs, the
    /// kernel log is closed to every reader without CAP_SYSLOG and `/dev/kmsg`
    /// to every reader at all, and the limits hold one child at its max with at
    /// least one task. Then it remounts `/proc` so that no process sees
    /// another's entries unless it may trace it, and builds the group.
    /// `children/` must not exist yet: this process runs once per boot, so a
    /// group already there was built by something else, with limits this
    /// process did not set.
    ///
    /// Elsewhere it is `None`: a developer's machine has no cgroup v2 root this
    /// process may build under, and making one needs root.
    pub fn create(limits: ChildLimits, children: usize) -> Option<Self> {
        #[cfg(all(target_os = "linux", feature = "guest-hardening"))]
        {
            use safe_logger::{debug, error_and_panic, reason, safe};

            match Self::build(limits, children) {
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
            let _ = (limits, children);
            None
        }
    }

    #[cfg(all(target_os = "linux", feature = "guest-hardening"))]
    fn build(limits: ChildLimits, children: usize) -> Result<Self, (&'static str, io::Error)> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::DirBuilderExt;

        fn at<T>(step: &'static str, r: io::Result<T>) -> Result<T, (&'static str, io::Error)> {
            r.map_err(|e| (step, e))
        }
        fn refused(step: &'static str) -> (&'static str, io::Error) {
            (step, io::Error::other(step))
        }

        if children == 0 || limits.max > limits.total || limits.tasks == 0 {
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
        if (children as u64).saturating_mul(limits.tasks) > pid_max / 2 {
            return Err(refused(
                "fitting every child's task cap within half the guest's PIDs",
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
        // large each one's composition is. Root loses nothing. Set here
        // because PID 1's inittab cannot say it: busybox init hands any line
        // holding `=` to a shell, and the image has none. A remount names the
        // mount's flags afresh, so the inittab's are repeated.
        {
            use rustix::mount::{MountFlags, mount_remount};
            at(
                "hiding each process's /proc entries from the others",
                mount_remount(
                    c"/proc",
                    MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                    c"hidepid=invisible",
                )
                .map_err(io::Error::from),
            )?;
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

    /// Make the next child's group, at the child's max, and what the child is
    /// given before its exec to enter it under its own identity. `inherited` is
    /// the length of what it maps from the supervisor's memory; see
    /// [`oom_score_adj`].
    ///
    /// Fails once this boot has run through every identity it may give, rather
    /// than give one twice.
    pub(crate) fn new_child(&self, inherited: u64) -> io::Result<(ChildGroup, Placement)> {
        let n = self.made.fetch_add(1, Ordering::Relaxed);
        let uid = child_uid(n)
            .ok_or_else(|| io::Error::other("every child identity of this boot is used"))?;
        let total_events = self.group.join("memory.events.local");
        let total_oom_before = read_counters(&total_events)?.oom;

        let path = self.group.join(format!("c{n}"));
        std::fs::create_dir(&path)?;
        let made = (|| -> io::Result<(OwnedFd, Peak)> {
            write(&path.join("memory.max"), &self.limits.max.to_string())?;
            // A kill in this group takes everything in it, never one task of
            // several.
            write(&path.join("memory.oom.group"), "1")?;
            let procs = std::fs::OpenOptions::new()
                .write(true)
                .open(path.join("cgroup.procs"))?;
            #[cfg(feature = "debug")]
            let peak = std::fs::File::open(path.join("memory.peak"))?;
            #[cfg(not(feature = "debug"))]
            let peak = ();
            Ok((OwnedFd::from(procs), peak))
        })();
        let (procs, peak) = match made {
            Ok(made) => made,
            Err(e) => {
                let _ = std::fs::remove_dir(&path);
                return Err(e);
            }
        };

        let group = ChildGroup {
            path,
            total_events,
            total_oom_before,
            max: self.limits.max,
            peak,
        };
        let placement = Placement {
            procs: Some(procs),
            oom_score_adj: oom_score_adj(inherited, self.limits.total)
                .to_string()
                .into_bytes(),
            uid,
            tasks: self.limits.tasks,
        };
        Ok((group, placement))
    }
}

impl ChildGroup {
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
        let own = read_counters(&self.path.join("memory.events.local"));
        let total = read_counters(&self.total_events);
        match (own, total) {
            (Ok(own), Ok(total)) if outgrew_max(own, self.total_oom_before, total.oom) => {
                ExitCause::OutgrewItsMax
            }
            _ => ExitCause::Unattributed,
        }
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
        let _ = write(&self.path.join("memory.reclaim"), &self.max.to_string());
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

/// Killed at its own max and at no other limit: the child's group reached its
/// own limit, the kernel killed in it, and the children's group never reached
/// the total meanwhile — its `oom` still where it was when the child was made.
/// The child's own counters started at zero with its group.
///
/// All three, because each alone admits an innocent child. A kill at the total
/// raises the victim's `oom_kill` and the children's `oom`, not the child's
/// `oom`. A group can reach its limit with nothing killed, when memory came
/// free in time, and then be the victim of a kill at the total. The one case
/// this still calls the child's own is a group that reached its limit unkilled
/// and was later the victim of a kill for the whole guest, which raises no
/// group's `oom`.
fn outgrew_max(own: Counters, total_oom_before: u64, total_oom_after: u64) -> bool {
    own.oom > 0 && own.oom_kill > 0 && total_oom_after == total_oom_before
}

/// A child's `oom_score_adj`: `1000` less its `inherited` bytes in thousandths
/// of the children's `total`, never below `0`.
///
/// The kernel picks the victim of a kill at the total by what each process
/// maps — resident pages, page tables — plus this score in thousandths of the
/// total. A child maps its cwasm, and the cwasm is not charged to the child:
/// the supervisor wrote it, so its pages count in the root group. An honest
/// round with a large cwasm would otherwise outscore a hostile one holding more
/// memory of its own, and killing it would free only what is its own. Taking
/// the inherited bytes back out of the score, in the score's own unit, leaves
/// what the child holds. It over-corrects for cwasm pages the child never
/// touched, in the direction of sparing large compositions — and a consumer
/// can buy that: a cwasm padded with bytes its rounds never touch has the
/// padding taken off their score all the same, up to the cwasm bound, so the
/// kernel can pass over such a round at the total and kill an honest one
/// holding less. What that costs is availability, not confidentiality: the
/// round killed instead is answered as unattributed, and its retry runs.
///
/// Never negative, so a kill for the whole guest — which scores in thousandths
/// of the guest's memory instead — still takes a child before the supervisor,
/// whose score is `0`. Never `-1000`: a process there is never chosen, and a
/// group whose every process is unchosen leaves the charge that reached the
/// limit waiting for good. Written as root before the identity changes, so it
/// is also the floor the child cannot lower itself below.
fn oom_score_adj(inherited: u64, total: u64) -> i32 {
    1000 - inherited
        .saturating_mul(1000)
        .div_ceil(total.max(1))
        .min(1000) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn own(oom: u64, oom_kill: u64) -> Counters {
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
        assert_eq!(counters(text), Some(own(3, 2)));
        assert_eq!(counters(""), None);
        assert_eq!(counters("oom 1\n"), None);
        assert_eq!(counters("oom x\noom_kill 1\n"), None);
    }

    #[test]
    fn a_kill_at_its_own_max_is_its_own() {
        assert!(outgrew_max(own(1, 1), 5, 5));
    }

    #[test]
    fn the_victim_of_a_kill_at_the_total_is_not() {
        assert!(!outgrew_max(own(0, 1), 5, 6));
    }

    #[test]
    fn its_max_reached_while_the_total_was_is_not() {
        assert!(!outgrew_max(own(1, 1), 5, 6));
    }

    #[test]
    fn its_max_reached_without_a_kill_is_not() {
        assert!(!outgrew_max(own(1, 0), 5, 5));
    }

    #[test]
    fn the_score_takes_out_what_the_child_maps_from_the_supervisor() {
        let total = 2048 * MIB;
        assert_eq!(oom_score_adj(0, total), 1000);
        assert_eq!(oom_score_adj(12 * MIB, total), 994);
        assert_eq!(oom_score_adj(total, total), 0);
        assert_eq!(oom_score_adj(2 * total, total), 0);
        assert_eq!(oom_score_adj(1, 0), 0);
        assert_eq!(oom_score_adj(u64::MAX, total), 0);
        // the largest cwasm the contract carries against the smallest total a
        // runner boots with stays well clear of the supervisor's 0
        assert_eq!(oom_score_adj(256 * MIB, 384 * MIB), 333);
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
