//! A cwasm on its way into the cache: an [`Incoming`] written as its stream
//! arrives, then sealed and checked in one step, after which it is a [`Cwasm`] —
//! the only form an L1 entry holds.
//!
//! A file rather than bytes in this process's heap, because a round runs in a
//! child process, which cannot see this one's heap. A file it can be handed, and
//! `deserialize_file` maps it: every child of one composition shares the same
//! pages, this process holds them once inside the cache's budget, and nothing is
//! copied per round.

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd};

use engine_executor::admission::is_precompiled_component;

/// A cwasm being written as its stream arrives: read by nothing, sealed by
/// nothing yet, and freed when dropped — which is all a refused or abandoned
/// fill does with it.
///
/// On the Linux CVM a `memfd`: RAM-backed (never touches disk), nameless and
/// CLOEXEC, so no child inherits it but the one the runner hands it to on purpose,
/// and only once it is a [`Cwasm`]. On a developer's macOS an unlinked tmpfile,
/// with the same anonymous, fd-only, refcounted lifetime and no seals.
pub(crate) struct Incoming {
    #[cfg(target_os = "linux")]
    file: memfd::Memfd,
    #[cfg(not(target_os = "linux"))]
    file: File,
}

/// A cwasm that arrived whole, sealed so that nothing can change it, and found
/// to be a wasmtime-serialized component. What an L1 entry holds, and what each
/// round's child is handed by fd.
pub(crate) struct Cwasm {
    file: File,
}

/// Why an [`Incoming`] did not become a [`Cwasm`].
#[derive(Debug)]
pub(crate) enum Refused {
    /// Sealing it or reading it back failed: this worker's trouble, not the
    /// bytes'.
    Failed(String),
    /// It arrived whole and is not a wasmtime-serialized component.
    NotAComponent,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(why) => write!(f, "cwasm not kept: {why}"),
            Self::NotAComponent => f.write_str("refused: not a wasmtime-serialized component"),
        }
    }
}

impl Incoming {
    /// An empty file to write a cwasm into.
    #[cfg(target_os = "linux")]
    pub(crate) fn new() -> Result<Self, String> {
        let file = memfd::MemfdOptions::default()
            .close_on_exec(true)
            .allow_sealing(true)
            .create("enclavid-cwasm")
            .map_err(|e| format!("memfd_create: {e}"))?;
        Ok(Self { file })
    }
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn new() -> Result<Self, String> {
        let file = tempfile::tempfile().map_err(|e| format!("tempfile: {e}"))?;
        Ok(Self { file })
    }

    /// The file the stream is written into.
    #[cfg(target_os = "linux")]
    pub(crate) fn writer(&self) -> &File {
        self.file.as_file()
    }
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn writer(&self) -> &File {
        &self.file
    }

    /// End the writing, and keep what was written only if it is a component.
    ///
    /// Sealed first, then checked. The seals are what make it safe to share:
    /// once its bytes cannot change, a child an escape has turned into native
    /// code cannot alter the code pages the next rounds of this composition
    /// will map, and nothing can change what the check is about to read.
    pub(crate) fn finish(self) -> Result<Cwasm, Refused> {
        let sealed = self.seal()?;
        if sealed.is_component()? {
            Ok(Cwasm { file: sealed.0 })
        } else {
            Err(Refused::NotAComponent)
        }
    }

    /// Seal against writes, growth, shrinking and further seals.
    #[cfg(target_os = "linux")]
    fn seal(self) -> Result<Sealed, Refused> {
        self.file
            .add_seals(&[
                memfd::FileSeal::SealShrink,
                memfd::FileSeal::SealGrow,
                memfd::FileSeal::SealWrite,
                memfd::FileSeal::SealSeal,
            ])
            .map_err(|e| Refused::Failed(format!("seal: {e}")))?;
        Ok(Sealed(self.file.into_file()))
    }
    /// The developer's tmpfile has no seals; that path never runs on the CVM.
    #[cfg(not(target_os = "linux"))]
    fn seal(self) -> Result<Sealed, Refused> {
        Ok(Sealed(self.file))
    }
}

/// An [`Incoming`] once sealed, before it is checked. Private, so that the
/// mapping [`Sealed::is_component`] reads through is made of a sealed file and
/// nothing else.
struct Sealed(File);

impl Sealed {
    /// Its length: its own, read after the seals, so the length any mapping of
    /// it will ever have.
    fn len(&self) -> Result<usize, Refused> {
        let len = self
            .0
            .metadata()
            .map_err(|e| Refused::Failed(format!("read its length: {e}")))?
            .len();
        usize::try_from(len)
            .map_err(|_| Refused::Failed("a cwasm past this platform's address space".into()))
    }

    /// Whether it reads as a serialized component.
    ///
    /// Over a read-only mapping, so the check reads the pages the file already
    /// holds and copies none of them — see [`is_precompiled_component`] for why
    /// it is handed a slice and not the file.
    #[cfg(target_os = "linux")]
    fn is_component(&self) -> Result<bool, Refused> {
        use rustix::mm::{MapFlags, ProtFlags, mmap};

        let len = self.len()?;
        // A mapping cannot be empty, and an empty file is no component.
        if len == 0 {
            return Ok(false);
        }
        // SAFETY: a `Sealed` holds a file sealed against writes, growth,
        // shrinking and further seals, so while the mapping lives nothing
        // anywhere can change its bytes or its length: the view below never
        // sees a byte move and never reaches past the end. `len` is that length.
        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                ProtFlags::READ,
                MapFlags::SHARED,
                &self.0,
                0,
            )
        }
        .map_err(|e| Refused::Failed(format!("map: {e}")))?;
        let mapping = Mapping { ptr, len };
        // SAFETY: `ptr` maps `len` readable bytes that cannot change (above), and
        // the view is not used past `mapping`, which unmaps them when it drops.
        let view = unsafe { std::slice::from_raw_parts(mapping.ptr.cast::<u8>(), len) };
        Ok(is_precompiled_component(view))
    }

    /// The developer's tmpfile has no seals, so nothing would hold a mapping's
    /// bytes still. The check reads one copy instead, scrubbed on drop.
    #[cfg(not(target_os = "linux"))]
    fn is_component(&self) -> Result<bool, Refused> {
        use std::os::unix::fs::FileExt;

        let mut copy = zeroize::Zeroizing::new(vec![0u8; self.len()?]);
        self.0
            .read_exact_at(&mut copy, 0)
            .map_err(|e| Refused::Failed(format!("read back: {e}")))?;
        Ok(is_precompiled_component(&copy))
    }
}

/// [`Sealed::is_component`]'s mapping, unmapped when dropped, so no way out of
/// the check leaves one behind.
#[cfg(target_os = "linux")]
struct Mapping {
    ptr: *mut std::ffi::c_void,
    len: usize,
}

#[cfg(target_os = "linux")]
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the mapping `is_component` made, unmapped once, with nothing
        // borrowing it any longer.
        let _ = unsafe { rustix::mm::munmap(self.ptr, self.len) };
    }
}

impl Cwasm {
    /// The path a round's child opens this cwasm by: the fd the runner installs
    /// it on in the child ([`engine_supervisor::INHERITED_FD`]), through
    /// `/proc/self/fd` on Linux and `/dev/fd` on macOS. `deserialize_file` maps
    /// what it opens.
    pub(crate) fn path_in_child() -> String {
        #[cfg(target_os = "linux")]
        const FD_DIR: &str = "/proc/self/fd";
        #[cfg(not(target_os = "linux"))]
        const FD_DIR: &str = "/dev/fd";
        format!("{FD_DIR}/{}", engine_supervisor::INHERITED_FD)
    }

    /// A `Cwasm` the tests make without a stream: what the cache does with an
    /// entry does not depend on what its file holds.
    #[cfg(test)]
    pub(crate) fn unchecked(file: File) -> Self {
        Self { file }
    }
}

impl AsFd for Cwasm {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{Incoming, Refused};

    fn incoming(bytes: &[u8]) -> Incoming {
        let incoming = Incoming::new().expect("an incoming file");
        let mut w = incoming.writer();
        w.write_all(bytes).expect("an incoming file takes writes");
        incoming
    }

    /// Bytes that arrived whole are still refused if they are not a component —
    /// read off the sealed file, the way a cache fill reads them.
    #[test]
    fn what_arrived_is_refused_if_not_a_component() {
        let bytes = b"\0asm\x01\0\0\0 and nothing wasmtime serialized";
        assert!(matches!(
            incoming(bytes).finish(),
            Err(Refused::NotAComponent)
        ));
    }

    /// Nothing at all is no component either, and is refused before anything
    /// tries to map it.
    #[test]
    fn nothing_is_not_a_component() {
        assert!(matches!(
            incoming(b"").finish(),
            Err(Refused::NotAComponent)
        ));
    }

    /// Once sealed, the file the children map cannot change under them — nor
    /// under the check about to read it: no write, and no length but its own.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_sealed_file_refuses_change() {
        let Ok(sealed) = incoming(b"cwasm").seal() else {
            panic!("the incoming file seals");
        };
        let mut f = sealed.0;
        assert!(f.write_all(b"more").is_err());
        assert!(f.set_len(1).is_err(), "a sealed file shrank");
        assert!(f.set_len(1 << 20).is_err(), "a sealed file grew");
    }
}
