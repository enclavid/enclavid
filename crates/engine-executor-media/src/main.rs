//! The coprocess the applicant's capture is decoded in: one a capture, a photo
//! or a video.
//!
//! On fd 0 is the socket whose other end the round holds. The round sends the
//! capture first — a JPEG, or a WebM of VP8 frames: the applicant's upload —
//! and the coprocess narrows itself to what a decode needs before it parses a
//! byte of it: read and write on that socket, memory that is never executable,
//! and an exit, with no clock to time anything by. Then it reads what the
//! capture holds — a photo's size, a video's frames as its container lists
//! them — and answers the round's requests for regions of its pictures one at
//! a time, decoding a picture when a region of it is first asked for, until
//! the round lets go of the socket or a failure ends it.
//!
//! What it makes of the bytes crosses as a fixed failure code, never in
//! libvpx's or the JPEG decoder's words.

mod photo;
mod picture;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
#[cfg(feature = "video")]
mod video;

use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, RawFd};

use coprocess_channel::{receive, send};
use enclavid_media::protocol::{
    Failure, Kind, MAX_REQUEST_BYTES, Opened, PictureBounds, Region, Request, Response,
};

type Stop = Box<dyn std::error::Error>;

/// The capture being decoded.
enum Capture {
    Photo(photo::Photo),
    #[cfg(feature = "video")]
    Video(Box<video::Video>),
}

impl Capture {
    /// Open `bytes` as a capture of `kind`, its pictures held to `bounds`. A
    /// build without `video` opens no video: it is not one it decodes.
    fn open(kind: Kind, bytes: Vec<u8>, bounds: PictureBounds) -> Result<Self, Failure> {
        Ok(match kind {
            Kind::Photo => Capture::Photo(photo::Photo::open(bytes, bounds)?),
            #[cfg(feature = "video")]
            Kind::Video => Capture::Video(Box::new(video::Video::open(bytes, bounds)?)),
            #[cfg(not(feature = "video"))]
            Kind::Video => return Err(Failure::NotMedia),
        })
    }

    /// What its open tells the round.
    fn opened(&self) -> Opened {
        match self {
            Capture::Photo(photo) => Opened::Photo(photo.size),
            #[cfg(feature = "video")]
            Capture::Video(video) => Opened::Video {
                size: video.size,
                frames: video.frames(),
            },
        }
    }

    fn region(&mut self, frame: u32, region: &Region) -> Result<Vec<u8>, Failure> {
        match self {
            Capture::Photo(photo) => photo.region(frame, region),
            #[cfg(feature = "video")]
            Capture::Video(video) => video.region(frame, region),
        }
    }

    fn end(self) {
        #[cfg(feature = "video")]
        if let Capture::Video(video) = self {
            video.end();
        }
    }
}

fn main() {
    let code = match serve() {
        Ok(()) => 0,
        Err(_) => 1,
    };
    // Straight out, past the runtime's teardown: it frees the signal stack
    // with a call the narrowed filter does not have.
    // SAFETY: ends the process; nothing of it runs after.
    unsafe { libc::_exit(code) }
}

fn serve() -> Result<(), Stop> {
    // Read and written as a file, with read(2) and write(2): a socket type
    // reads through recvfrom, which neither filter has. Never closed: the
    // narrowed filter has no `close`, nor the `fcntl` a debug build checks a
    // descriptor with before it closes one; `_exit` closes it.
    let mut socket = ManuallyDrop::new(File::from(std::io::stdin().as_fd().try_clone_to_owned()?));
    // The keys every map's hasher is seeded from, read now: the first read
    // asks the kernel for randomness, which the narrowed filter does not
    // have, and the demuxer makes its maps after it.
    let _ = std::collections::hash_map::RandomState::new();
    let socket = &mut *socket;
    let first: Option<Request> = receive(socket, MAX_REQUEST_BYTES)?;
    narrow(socket.as_raw_fd())?;
    let Some(Request::Open {
        kind,
        bytes,
        bounds,
    }) = first
    else {
        send(socket, &Response::Failed(Failure::OutOfTurn))?;
        return Ok(());
    };
    let mut capture = match Capture::open(kind, bytes.into_vec(), bounds) {
        Ok(capture) => capture,
        Err(failure) => {
            send(socket, &Response::Failed(failure))?;
            return Ok(());
        }
    };
    send(socket, &Response::Opened(capture.opened()))?;
    while let Some(request) = receive::<Request>(socket, MAX_REQUEST_BYTES)? {
        let Request::Region { frame, region } = request else {
            send(socket, &Response::Failed(Failure::OutOfTurn))?;
            break;
        };
        match capture.region(frame, &region) {
            Ok(rgb) => send(socket, &Response::Pixels(rgb))?,
            Err(failure) => {
                send(socket, &Response::Failed(failure))?;
                // A picture that does not decode is answered, and the next
                // request read: another may. Any other failure ends the
                // coprocess.
                if failure != Failure::Corrupt {
                    break;
                }
            }
        }
    }
    capture.end();
    Ok(())
}

/// Before a byte of the capture is parsed, the coprocess keeps only what a
/// decode needs: read and write on `socket`, memory as its allocator asks for
/// it — private, anonymous, read and written, never executed — and its exit.
/// On top of the filter it was started under, which can only be narrowed, any
/// other call ends it — whatever the applicant's bytes have made of the
/// demuxer, libvpx or the JPEG decoder.
#[cfg(target_os = "linux")]
fn narrow(socket: RawFd) -> Result<(), Stop> {
    narrow_to(&filter(socket)?)
}

/// Take the time-stamp counter, then install `filter` over every thread: with
/// no call that tells the time, the counter is the one clock left.
#[cfg(target_os = "linux")]
fn narrow_to(filter: &seccompiler::BpfProgram) -> Result<(), Stop> {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: changes nothing but whether this process may read the counter.
    if unsafe { libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    seccompiler::apply_filter_all_threads(filter)?;
    Ok(())
}

/// The filter [`narrow`] installs. The allocator was measured mapping memory
/// with these protections and flags alone, and calling no `madvise`; `mremap`,
/// reasoned, is glibc's `realloc` of a block it mapped on its own.
#[cfg(target_os = "linux")]
fn filter(socket: RawFd) -> Result<seccompiler::BpfProgram, Stop> {
    use std::collections::BTreeMap;

    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    #[cfg(target_arch = "x86_64")]
    const ARCH: TargetArch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    const ARCH: TargetArch = TargetArch::aarch64;

    let socket = u64::try_from(socket)?;
    let arg = |index, value| {
        SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
    };
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(
        libc::SYS_read,
        vec![SeccompRule::new(vec![arg(0, socket)?])?],
    );
    rules.insert(
        libc::SYS_write,
        vec![SeccompRule::new(vec![arg(0, socket)?])?],
    );
    rules.insert(
        libc::SYS_mmap,
        vec![SeccompRule::new(vec![
            arg(2, (libc::PROT_READ | libc::PROT_WRITE) as u64)?,
            arg(3, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64)?,
        ])?],
    );
    rules.insert(
        libc::SYS_mremap,
        vec![SeccompRule::new(vec![arg(
            3,
            libc::MREMAP_MAYMOVE as u64,
        )?])?],
    );
    for sys in [
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        rules.insert(sys, Vec::new());
    }
    Ok(SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        ARCH,
    )?
    .try_into()?)
}

#[cfg(not(target_os = "linux"))]
fn narrow(_: RawFd) -> Result<(), Stop> {
    Ok(())
}
