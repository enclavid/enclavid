//! The parent half — spawn, harden, bound, kill, release — behind the
//! `parent` feature; the crate's documentation says what each piece is.

mod cgroup;
mod preconditions;
mod runner;
#[cfg(target_os = "linux")]
mod seccomp;
mod spawn;

pub use cgroup::{Cgroups, ChildLimits, DEFAULT_CHILD_MAX_TASKS, ExitCause, GroupLimits};
pub use preconditions::{physical_memory, require_fd_budget, require_ptrace_scope};
pub use runner::{
    ChildRunner, ChildTimes, Coprocess, CoprocessConfig, CoprocessError, CoprocessKind, Exit,
    RunnerConfig, SupervisorError,
};
pub use spawn::{SpawnError, spawn_and_connect, spawn_coprocess};
