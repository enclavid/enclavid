//! A composition's model files in the L1 — its models' graphs and data files:
//! each made empty with its entry, filled the first time a round of the
//! composition runs a model of it, and sealed — then mapped by the process of
//! every model of it a round starts, and copied by no one.
//!
//! No round's child is handed a model file: the process a model runs in is,
//! once its files are filled and sealed, and only that model's — through
//! descriptors opened for reading alone as the process starts, so a process an
//! escape has turned into native code cannot write what the next rounds will
//! map.

use std::fs::File;
use std::io::{Seek, SeekFrom};

use engine_types::composition::ModelFile;
use tokio::sync::Mutex;

/// One model file of an entry.
pub(crate) struct ModelFileSlot {
    /// What the composition's bundle says the file is: what a fill is held to.
    pub(crate) declared: ModelFile,
    /// The file, written by its fill.
    #[cfg(target_os = "linux")]
    file: memfd::Memfd,
    #[cfg(not(target_os = "linux"))]
    file: File,
    /// Whether the file is whole and sealed. Held by the one round that fills
    /// it, so every other round that runs a model of it waits for that fill.
    pub(crate) filled: Mutex<bool>,
}

impl ModelFileSlot {
    /// An empty file for `declared`.
    #[cfg(target_os = "linux")]
    pub(crate) fn new(declared: ModelFile) -> Result<Self, String> {
        let file = memfd::MemfdOptions::default()
            .close_on_exec(true)
            .allow_sealing(true)
            .create("enclavid-model-file")
            .map_err(|e| format!("memfd_create: {e}"))?;
        Ok(Self {
            declared,
            file,
            filled: Mutex::new(false),
        })
    }
    /// The developer's tmpfile, which nothing seals. That path never runs on
    /// the CVM.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn new(declared: ModelFile) -> Result<Self, String> {
        let file = tempfile::tempfile().map_err(|e| format!("tempfile: {e}"))?;
        Ok(Self {
            declared,
            file,
            filled: Mutex::new(false),
        })
    }

    /// The file a fill writes into, emptied first: a fill that broke off part
    /// way leaves bytes no later fill may follow.
    pub(crate) fn writer(&self) -> Result<&File, String> {
        let mut file = self.file();
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .map_err(|e| format!("empty the model file: {e}"))?;
        Ok(file)
    }

    #[cfg(target_os = "linux")]
    fn file(&self) -> &File {
        self.file.as_file()
    }
    #[cfg(not(target_os = "linux"))]
    fn file(&self) -> &File {
        &self.file
    }

    /// Seal against writes, growth, shrinking and further seals.
    #[cfg(target_os = "linux")]
    pub(crate) fn seal(&self) -> Result<(), String> {
        self.file
            .add_seals(&[
                memfd::FileSeal::SealShrink,
                memfd::FileSeal::SealGrow,
                memfd::FileSeal::SealWrite,
                memfd::FileSeal::SealSeal,
            ])
            .map_err(|e| format!("seal the model file: {e}"))
    }
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn seal(&self) -> Result<(), String> {
        Ok(())
    }

    /// A new descriptor of the file, for reading: what a model's process is
    /// handed. A write through it fails, and so does a writable mapping of it.
    #[cfg(target_os = "linux")]
    pub(crate) fn reader(&self) -> Result<File, String> {
        use std::os::fd::AsRawFd;

        File::open(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
            .map_err(|e| format!("open the model file for reading: {e}"))
    }
    /// The developer's tmpfile: the same open file again.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn reader(&self) -> Result<File, String> {
        self.file
            .try_clone()
            .map_err(|e| format!("a second descriptor of the model file: {e}"))
    }
}
