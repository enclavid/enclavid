//! Telling dinit the clock is synchronised.
//!
//! dinit starts the keeper with the write end of a pipe and puts its descriptor
//! in [`VARIABLE`] (`ready-notification = pipevar:READY_FD` in its service
//! file). It counts the keeper started when a line arrives there, and only then
//! starts the application, which depends on the keeper.

use std::io::Write;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Mutex;

/// Where dinit names the pipe's descriptor; the service file names the same.
const VARIABLE: &str = "READY_FD";

/// The pipe, from adoption until the line is written.
static PIPE: Mutex<Option<std::fs::File>> = Mutex::new(None);

/// Take the pipe [`VARIABLE`] names. Unset, the keeper was started other than
/// by dinit, and there is nothing to tell. Set, it has to name a pipe past
/// stdio: anything else is a service file and a keeper that disagree, which
/// would otherwise only show as dinit's start timing out.
pub fn adopt() -> Result<(), &'static str> {
    let Some(value) = std::env::var_os(VARIABLE) else {
        return Ok(());
    };
    let fd = value
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
        // 0 to 2 are stdio, the console the keeper shares with dinit.
        .filter(|fd| *fd > 2)
        .ok_or("READY_FD does not name a descriptor past stdio")?;
    // The kernel names what each open descriptor is under /proc/self/fd; a
    // pipe reads `pipe:[<inode>]`, and a descriptor that is not open is absent.
    let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .map_err(|_| "READY_FD names a descriptor that is not open")?;
    if !target.to_str().is_some_and(|t| t.starts_with("pipe:")) {
        return Err("READY_FD names a descriptor that is not a pipe");
    }
    // SAFETY: the descriptor is an open pipe, dinit passed it for this alone,
    // and the keeper adopts it once, here, before anything else could take it.
    let pipe = unsafe { std::fs::File::from_raw_fd(fd) };
    *PIPE.lock().expect("the lock is never held across a panic") = Some(pipe);
    Ok(())
}

/// Write the line, once, and close the pipe. Later calls find it gone.
pub fn notify() {
    let pipe = PIPE
        .lock()
        .expect("the lock is never held across a panic")
        .take();
    if let Some(mut pipe) = pipe {
        // dinit reads this as the start completing; if the write fails, dinit
        // never hears it, the start times out, and the guest ends — which is
        // the right outcome for a keeper that cannot say it is ready.
        let _ = pipe.write_all(b"\n");
    }
}
