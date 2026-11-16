//! Instrumented pause points for the ref-transaction path, used by
//! spike 03's harness for BOTH deterministic interleaving (R2) and
//! crash injection (R3). The harness configures each ref-writer
//! process through environment variables.
//!
//! Protocol (all via a directory named by RUSTGIT_CHECKPOINT_DIR, or
//! REFSTORE_HARNESS_CHECKPOINT_DIR - see below):
//! - On reaching checkpoint `name`, write an empty marker file
//!   `<dir>/at_<name>` (lets the harness observe "the writer reached
//!   this point" without a shared IPC channel - just a file it can
//!   poll for).
//! - If RUSTGIT_CRASH_AT == name, print "CRASH_POINT:<name>" to
//!   stderr, flush, then block forever. The harness watches for that
//!   line and SIGKILLs this process - a true hard-kill at exactly this
//!   logical point, not a voluntary exit (which would run Drop code
//!   the real crash we're simulating wouldn't).
//! - If a file `<dir>/wait_<name>` exists, block until
//!   `<dir>/release_<name>` appears (polled) - lets a test force two
//!   writers into a specific interleaving without crashing either one.
//!
//! Also answers to REFSTORE_HARNESS_CHECKPOINT_DIR / _CRASH_AT (the
//! generic env var names used by the standalone git-refstore-harness
//! crate this protocol was extracted into) - kept as aliases so
//! ref-writer can be driven by either this repo's own spike 03 tests
//! or the extracted, implementation-agnostic harness without
//! duplicating the binary. See NOTES-03.md's upstream-contribution
//! section.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

fn env_first(names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| std::env::var(n).ok())
}

fn checkpoint_dir() -> Option<PathBuf> {
    env_first(&["RUSTGIT_CHECKPOINT_DIR", "REFSTORE_HARNESS_CHECKPOINT_DIR"]).map(PathBuf::from)
}

pub fn checkpoint(name: &str) {
    let Some(dir) = checkpoint_dir() else { return };

    let marker = dir.join(format!("at_{}", name));
    let _ = std::fs::write(&marker, b"");

    if env_first(&["RUSTGIT_CRASH_AT", "REFSTORE_HARNESS_CRASH_AT"]).as_deref() == Some(name) {
        eprintln!("CRASH_POINT:{}", name);
        let _ = std::io::stderr().flush();
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    let wait_file = dir.join(format!("wait_{}", name));
    if wait_file.exists() {
        let release_file = dir.join(format!("release_{}", name));
        while !release_file.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
