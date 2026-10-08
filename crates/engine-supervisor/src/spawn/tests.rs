// What a spawned child is left holding: only the descriptor it is handed, and
// — for a placed child — an identity of its own. Changing identity takes root,
// so those tests run where the tests do as root — a Linux build machine — and
// say they tested nothing anywhere else. What they cover is the one assumption
// the identity rests on that no other test reaches: the child still opens and
// maps the cwasm it inherits.

use rustix::fs::{MemfdFlags, Mode, OFlags, memfd_create, open};
use rustix::mm::{MapFlags, ProtFlags, mmap};
use rustix::process::{Pid, WaitOptions, geteuid, waitpid};
use rustix::thread::{Gid, Uid, set_thread_groups, set_thread_res_gid, set_thread_res_uid};

use super::*;
use crate::cgroup::{CHILD_UID_BASE, DEFAULT_CHILD_MAX_TASKS};

fn root() -> bool {
    let root = geteuid().is_root();
    if !root {
        eprintln!("not root, so no identity can be changed here — skipping");
    }
    root
}

/// The executor child reopens its inherited cwasm through `/proc/self/fd/N`
/// and maps it executable. Under an identity of its own that must still work
/// for a memfd root created, and root's own `/proc` entries must be out of
/// reach. Run without an exec, where the kernel is stricter still: a process
/// that changed identity is not dumpable until it execs, so its `/proc/self`
/// is root's.
#[test]
fn an_identity_of_its_own_still_maps_the_cwasm_it_was_handed() {
    const MAPPED: i32 = 0;
    const CANNOT_CHANGE_IDENTITY: i32 = 2;
    const NO_REOPEN: i32 = 3;
    const NO_MAP: i32 = 4;
    const WRONG_BYTES: i32 = 5;
    const STILL_ROOT: i32 = 6;

    if !root() {
        return;
    }
    // A root-created memfd, as the worker stages a cwasm.
    let memfd =
        memfd_create(c"enclavid-identity-probe", MemfdFlags::CLOEXEC).expect("memfd_create");
    let page = [0x5au8; 4096];
    let written = rustix::io::write(&memfd, &page).expect("write the memfd");
    assert_eq!(written, page.len());
    let path =
        std::ffi::CString::new(format!("/proc/self/fd/{}", memfd.as_raw_fd())).expect("no NUL");

    // SAFETY: the child of this multi-threaded harness makes only single system
    // calls over data built before the fork — rustix's take a `&CStr` path as
    // it is and allocate nothing — and `_exit`s without returning into the
    // harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let code = (|| {
            let (uid, gid) = (Uid::from_raw(CHILD_UID_BASE), Gid::from_raw(CHILD_UID_BASE));
            if set_thread_groups(&[]).is_err()
                || set_thread_res_gid(gid, gid, gid).is_err()
                || set_thread_res_uid(uid, uid, uid).is_err()
            {
                return CANNOT_CHANGE_IDENTITY;
            }
            let flags = OFlags::RDONLY | OFlags::CLOEXEC;
            let Ok(reopened) = open(path.as_c_str(), flags, Mode::empty()) else {
                return NO_REOPEN;
            };
            let exec = ProtFlags::READ | ProtFlags::EXEC;
            // SAFETY: a new private mapping of a file nothing writes again, read
            // once below while the child lives.
            let mapped = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    page.len(),
                    exec,
                    MapFlags::PRIVATE,
                    &reopened,
                    0,
                )
            };
            let Ok(map) = mapped else {
                return NO_MAP;
            };
            // SAFETY: `map` is `page.len()` readable bytes.
            if unsafe { map.cast::<u8>().read() } != 0x5a {
                return WRONG_BYTES;
            }
            if open(c"/proc/1/environ", OFlags::RDONLY, Mode::empty()).is_ok() {
                return STILL_ROOT;
            }
            MAPPED
        })();
        // SAFETY: see the fork.
        unsafe { libc::_exit(code) }
    }
    drop(memfd);
    let (_, status) = waitpid(Pid::from_raw(pid), WaitOptions::empty())
        .expect("wait for the probe")
        .expect("the probe has ended");
    match status.exit_status().expect("the probe exited") {
        MAPPED => {}
        CANNOT_CHANGE_IDENTITY => {
            eprintln!("this environment cannot take on another identity — skipping")
        }
        NO_REOPEN => panic!("the child cannot reopen its inherited cwasm"),
        NO_MAP => panic!("the child cannot map its inherited cwasm executable"),
        WRONG_BYTES => panic!("the child mapped something other than its cwasm"),
        STILL_ROOT => panic!("the child still reaches root's /proc entries"),
        other => panic!("the probe exited with unexpected code {other}"),
    }
}

/// What a placement leaves a real exec'd child with: its own identity and
/// no supplementary groups, the score, and limits it cannot raise.
#[tokio::test]
async fn a_placed_child_runs_under_its_own_identity() {
    if !root() {
        return;
    }
    let uid = CHILD_UID_BASE + 1;
    let placement = Placement {
        procs: None,
        oom_score_adj: b"500".to_vec(),
        uid,
        tasks: DEFAULT_CHILD_MAX_TASKS,
    };
    let (mut child, sup_end) =
        spawn_child(Path::new("/bin/cat"), None, false, Some(placement)).expect("cat spawns");
    let pid = child.id().expect("cat is running");
    let read = |file: &str| {
        std::fs::read_to_string(format!("/proc/{pid}/{file}")).expect("a /proc file of cat's")
    };

    let status = read("status");
    let ids = format!("\t{uid}\t{uid}\t{uid}\t{uid}");
    assert!(
        status.lines().any(|l| l == format!("Uid:{ids}")),
        "{status}"
    );
    assert!(
        status.lines().any(|l| l == format!("Gid:{ids}")),
        "{status}"
    );
    assert!(
        status.lines().any(|l| l.trim_end() == "Groups:"),
        "{status}"
    );
    assert_eq!(read("oom_score_adj"), "500\n");
    let limits = read("limits");
    let limit = |name: &str| {
        limits
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|rest| rest.split_whitespace().take(2).collect::<Vec<_>>())
    };
    let tasks = DEFAULT_CHILD_MAX_TASKS.to_string();
    assert_eq!(
        limit("Max processes"),
        Some(vec![tasks.as_str(), tasks.as_str()])
    );
    assert_eq!(limit("Max core file size"), Some(vec!["0", "0"]));

    // End of its input: `cat` goes by itself.
    drop(sup_end);
    assert!(child.wait().await.expect("cat is reaped").success());
}

/// Only what a child is handed survives its exec. A descriptor this process
/// holds without CLOEXEC — as a vsock connection is between its accept and the
/// flag set after it — is closed in the child; the one handed over is there.
/// Read from outside, through the child's `/proc` entry, once the spawn has
/// returned — which it does only after the exec.
#[tokio::test]
async fn only_the_handed_descriptor_survives_the_exec() {
    use std::os::fd::AsFd;

    // Taken first, so neither descriptor below can be the inherited number.
    let _low = open(
        c"/dev/null",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open /dev/null");
    let stray = open(c"/dev/null", OFlags::RDONLY, Mode::empty()).expect("open a stray");
    let handed = open(
        c"/dev/null",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open one to hand over");
    let stray_fd = stray.as_raw_fd();
    assert_ne!(stray_fd, INHERITED_FD);

    // `cat` waits on its input, the socketpair, and opens nothing of its own.
    let (mut child, sup_end) =
        spawn_child(Path::new("/bin/cat"), Some(handed.as_fd()), false, None).expect("cat spawns");
    let pid = child.id().expect("cat is running");
    let holds = |fd: RawFd| Path::new(&format!("/proc/{pid}/fd/{fd}")).exists();
    let (inherited, strayed) = (holds(INHERITED_FD), holds(stray_fd));

    // End of its input: `cat` goes by itself.
    drop(sup_end);
    assert!(child.wait().await.expect("cat is reaped").success());
    assert!(inherited, "the handed descriptor is not at {INHERITED_FD}");
    assert!(
        !strayed,
        "the stray descriptor {stray_fd} survived the exec"
    );
}
