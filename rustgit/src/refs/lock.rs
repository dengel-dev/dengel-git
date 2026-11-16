//! Ref lock file primitive: `<ref-path>.lock`, created with exclusive-
//! create semantics (Rust's `OpenOptions::create_new`, which maps to
//! O_EXCL on Unix - refuses if the file already exists rather than
//! truncating it).
//!
//! PRIOR-KNOWLEDGE DISCLOSURE (per CLAUDE.md, maximum weight in this
//! spike): the `<ref>.lock` naming convention itself is documented
//! (git-check-ref-format.adoc / gitprotocol-common.adoc: refnames
//! "cannot end with the sequence `.lock`" - the rule only makes sense
//! if this convention exists), but the operational mechanics
//! (exclusive-create, atomic rename-over-target on commit, refusing
//! rather than auto-cleaning a stale lock) are NOT documented anywhere
//! found in this checkout. Verified directly against real git before
//! writing this (see NOTES-03.md): created a stale `<ref>.lock` by
//! hand, ran real `git update-ref` against it, and got "cannot lock
//! ref '...': Unable to create '....lock': File exists" (exit 128) -
//! confirms exclusive-create semantics and confirms git refuses rather
//! than auto-removing a stale lock. This module matches that observed
//! behaviour, not a remembered description of it.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::checkpoint::checkpoint;

#[derive(Debug)]
pub enum LockError {
    AlreadyLocked { path: PathBuf },
    Io(std::io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::AlreadyLocked { path } => {
                write!(f, "Unable to create '{}': File exists.", path.display())
            }
            LockError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}
impl std::error::Error for LockError {}

pub struct RefLock {
    pub target_path: PathBuf,
    pub lock_path: PathBuf,
    file: Option<File>,
}

impl RefLock {
    /// Acquire the lock for `target_path` (the real ref file path).
    /// Fails with AlreadyLocked if `<target_path>.lock` already exists
    /// - matches observed real-git behaviour (see module doc comment).
    pub fn acquire(target_path: &Path) -> Result<Self, LockError> {
        let lock_path = lock_path_for(target_path);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(LockError::Io)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL semantics
            .open(&lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    LockError::AlreadyLocked {
                        path: lock_path.clone(),
                    }
                } else {
                    LockError::Io(e)
                }
            })?;
        checkpoint("after_lock");
        Ok(RefLock {
            target_path: target_path.to_path_buf(),
            lock_path,
            file: Some(file),
        })
    }

    /// Write `content` into the (already-locked) temp file. Does not
    /// commit - call `commit()` to make it visible.
    pub fn write_content(&mut self, content: &[u8]) -> std::io::Result<()> {
        let file = self.file.as_mut().expect("lock file already consumed");
        file.write_all(content)?;
        file.sync_all()?; // fsync before rename - see NOTES-03.md durability discussion
        checkpoint("after_tempfile_write");
        Ok(())
    }

    /// Atomically rename the lock file over the target path, making
    /// the new content visible. Consumes the lock (no further use).
    pub fn commit(mut self) -> std::io::Result<()> {
        drop(self.file.take()); // close before rename (required on some platforms, harmless on all)
        checkpoint("before_rename");
        fs::rename(&self.lock_path, &self.target_path)?;
        checkpoint("after_rename_before_unlock");
        // Nothing left to unlock - the rename consumed the lock file
        // itself, which IS the unlock (matches real git: there is no
        // separate "unlock" step after a successful commit rename).
        std::mem::forget(self); // skip Drop's cleanup-on-abort path
        Ok(())
    }

    /// Delete the target ref file entirely (for a `delete` operation)
    /// and release the lock. The lock file itself is removed, not
    /// renamed over the target (there is nothing to rename - the
    /// target should no longer exist).
    pub fn commit_delete(mut self) -> std::io::Result<()> {
        drop(self.file.take());
        checkpoint("before_delete");
        if self.target_path.exists() {
            fs::remove_file(&self.target_path)?;
        }
        fs::remove_file(&self.lock_path)?;
        checkpoint("after_delete");
        std::mem::forget(self);
        Ok(())
    }

    /// Release the lock without making any change (transaction
    /// aborted). Safe to call even if a write already happened via
    /// write_content - the lock file (temp) is simply discarded.
    pub fn abort(mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.lock_path);
        std::mem::forget(self);
    }
}

impl Drop for RefLock {
    /// Safety net: if a RefLock is dropped without an explicit
    /// commit/commit_delete/abort (e.g. an early return via `?`), the
    /// lock file must not be left stranded - clean it up here. This is
    /// NOT how a real crash would behave (a real SIGKILL skips Drop
    /// entirely, which is exactly why R3 has to test via actual
    /// process kill rather than relying on this safety net).
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.lock_path);
    }
}

pub fn lock_path_for(target_path: &Path) -> PathBuf {
    let mut s = target_path.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}
