//! Standalone binary that executes ONE ref transaction against a
//! given repo, then exits. Exists so the test harness can spawn it as
//! a real OS process and SIGKILL it (R3) or race it against another
//! instance / real git (R2) - a library function call can't be
//! killed mid-execution the way a real crash needs to be.
//!
//! Usage: ref-writer <git-dir> <stdin-script-file>
//! Env vars (all optional, read by src/refs/checkpoint.rs):
//!   RUSTGIT_CHECKPOINT_DIR - directory for pause/crash coordination
//!   RUSTGIT_CRASH_AT       - checkpoint name to block at (for SIGKILL)
//!
//! Exit codes: 0 = transaction committed, 1 = transaction rejected
//! (prints the reason to stderr), 2 = usage/io error.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: ref-writer <git-dir> <stdin-script-file>");
        return ExitCode::from(2);
    }
    let git_dir = PathBuf::from(&args[1]);
    let script_path = &args[2];

    let script = match std::fs::read_to_string(script_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read script file {}: {}", script_path, e);
            return ExitCode::from(2);
        }
    };

    let ops = match rustgit::refs::stdin_format::parse_script(&script) {
        Ok(ops) => ops,
        Err(e) => {
            eprintln!("failed to parse script: {}", e);
            return ExitCode::from(2);
        }
    };

    match rustgit::refs::transaction::execute_transaction(&git_dir, &ops) {
        Ok(()) => {
            println!("OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("REJECTED: {}", e);
            ExitCode::from(1)
        }
    }
}
