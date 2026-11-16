// Differential harness for spike 03 (ref transactions). Oracle: real
// `git update-ref --stdin` on an identical repo copy, real `git
// for-each-ref` / `git symbolic-ref` for state comparison, real
// `git fsck` / `git refs verify` for consistency validation.
//
// SAFETY: every function here operates on a caller-supplied scratch
// repo path. Nothing in this file ever touches the actual rustgit
// spike repo. See NOTES-03.md's "Harness/scope decisions" note.
//
// This file is #[path]-included into multiple test binaries (R1's
// refs_differential.rs, R2's refs_r2_differential.rs, and more to
// come) - each binary legitimately uses only a subset of these
// helpers, which triggers cross-binary dead-code warnings without
// this allow.
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Create a fresh scratch git repo under the system temp dir, seeded
/// with `initial_refs` (refname, oid) pairs written directly as loose
/// files (bypassing update-ref entirely for setup, so the fixture's
/// starting state is unambiguous and not itself dependent on the code
/// under test).
pub fn make_scratch_repo(name: &str, initial_refs: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rustgit-refs-{}-{}", std::process::id(), name));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("failed to create scratch repo dir");
    let init = Command::new("git")
        .current_dir(&dir)
        .args([
            "init",
            "-q",
            "--object-format=sha1",
            "--initial-branch=main",
        ])
        .output()
        .expect("git init failed");
    assert!(
        init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // A repo needs at least one real object for oids to resolve
    // against something git itself would consider valid - commit once
    // so HEAD and the initial refs can point at a real commit.
    //
    // FIXED author/committer date (not just identity): commit oids
    // embed the timestamp, so two separately-created "identical"
    // commits get DIFFERENT oids unless the date is pinned too. This
    // was a real bug caught by the first R1 run: seed_commit_oid()
    // computed from a throwaway probe repo, then reused as an
    // "initial ref" value in a DIFFERENT freshly-made repo, pointed at
    // an oid that didn't actually exist there - git correctly rejected
    // it ("nonexistent object"), which looked like a transaction-logic
    // bug until traced back to this harness issue. See NOTES-03.md.
    std::fs::write(dir.join("seed.txt"), b"seed\n").unwrap();
    Command::new("git")
        .current_dir(&dir)
        .arg("add")
        .arg("seed.txt")
        .output()
        .unwrap();
    let commit = Command::new("git")
        .current_dir(&dir)
        .args([
            "-c",
            "user.email=spike@example.com",
            "-c",
            "user.name=spike",
            "-c",
            "commit.gpgSign=false",
        ])
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00+0000")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00+0000")
        .arg("commit")
        .arg("-q")
        .arg("-m")
        .arg("seed")
        .output()
        .expect("git commit failed");
    assert!(
        commit.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let git_dir = dir.join(".git");
    for (refname, oid) in initial_refs {
        let path = git_dir.join(refname);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{}\n", oid)).unwrap();
    }

    dir
}

/// The seed commit's oid - deterministic (fixed author/committer date
/// in make_scratch_repo) and therefore identical across every scratch
/// repo this harness creates, so it's safe to use as a hardcoded
/// constant rather than re-derived per repo instance (see
/// make_scratch_repo's doc comment for why re-deriving per instance
/// was itself a bug caught by the first R1 run).
pub const SEED_OID: &str = "2d9355e12197a8962da4308f175d4ace563a76e6";

/// A SECOND deterministic, real object (a commit, parented on
/// SEED_OID, fixed timestamp) - present in every scratch repo's object
/// database via ensure_second_object(), but not pointed at by any ref.
/// Needed for R2 race scenarios that need two distinct real oids to
/// race between (since transaction.rs validates new-oid existence -
/// see R1's finding - an arbitrary fake oid won't pass).
pub const SEED_OID_2: &str = "63bddf3dd5df4aee5ae51de3a85d2e9e930ea6b7";

/// Write SEED_OID_2's commit object into `repo`'s object database
/// (via `git commit-tree`, which creates the object WITHOUT moving
/// any ref) so it's a valid update/create target without disturbing
/// whatever refs the test set up.
pub fn ensure_second_object(repo: &Path) {
    std::fs::write(repo.join("second.txt"), b"second\n").unwrap();
    Command::new("git")
        .current_dir(repo)
        .arg("add")
        .arg("second.txt")
        .output()
        .unwrap();
    let tree = Command::new("git")
        .current_dir(repo)
        .arg("write-tree")
        .output()
        .unwrap();
    let tree_oid = String::from_utf8_lossy(&tree.stdout).trim().to_string();
    let commit = Command::new("git")
        .current_dir(repo)
        .args([
            "-c",
            "user.email=spike@example.com",
            "-c",
            "user.name=spike",
        ])
        .env("GIT_AUTHOR_DATE", "2026-01-02T00:00:00+0000")
        .env("GIT_COMMITTER_DATE", "2026-01-02T00:00:00+0000")
        .arg("commit-tree")
        .arg(&tree_oid)
        .arg("-p")
        .arg(SEED_OID)
        .arg("-m")
        .arg("second")
        .output()
        .unwrap();
    let oid = String::from_utf8_lossy(&commit.stdout).trim().to_string();
    assert_eq!(
        oid, SEED_OID_2,
        "SEED_OID_2 drifted from the hardcoded constant - regenerate it"
    );
    // commit-tree doesn't touch the index/working tree state
    // meaningfully for our purposes, but reset the index so
    // subsequent `git` inspection commands (status, fsck) see a clean
    // working tree rather than a staged-but-uncommitted second.txt.
    Command::new("git")
        .current_dir(repo)
        .arg("reset")
        .arg("-q")
        .output()
        .unwrap();
}

/// Cross-check that SEED_OID actually matches what this checkout's
/// git produces for the fixed-timestamp seed commit - guards against
/// silent drift if git's commit-object format or hashing ever changes
/// in a way that would shift the oid.
pub fn seed_commit_oid(repo: &Path) -> String {
    let out = Command::new("git")
        .current_dir(repo)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .unwrap();
    let oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        oid, SEED_OID,
        "seed commit oid drifted from the hardcoded constant - regenerate SEED_OID"
    );
    oid
}

pub struct RunResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Oracle: run real `git update-ref --stdin` with `script` as input.
pub fn run_real_update_ref(repo: &Path, script: &str) -> RunResult {
    let mut child = Command::new("git")
        .current_dir(repo)
        .arg("update-ref")
        .arg("--stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn git update-ref --stdin");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    RunResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Run OUR implementation via the ref-writer binary (a real spawned
/// process, not a library call - needed for R2/R3's process-level
/// racing/crash-injection, and used uniformly here too so R1's own
/// harness exercises the exact same code path).
pub fn run_ref_writer(repo: &Path, script: &str) -> RunResult {
    run_ref_writer_with_env(repo, script, &[])
}

pub fn run_ref_writer_with_env(repo: &Path, script: &str, env: &[(&str, &str)]) -> RunResult {
    let script_file = script_file(script);

    let git_dir = repo.join(".git");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ref-writer"));
    cmd.arg(&git_dir).arg(script_file.path());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("failed to run ref-writer");
    RunResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn script_file(script: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create ref script");
    file.write_all(script.as_bytes()).expect("write ref script");
    file
}

/// Full ref state, normalized for comparison: every ref's (name, oid,
/// type) plus HEAD's symref target (or resolved oid if detached).
pub fn dump_ref_state(repo: &Path) -> String {
    let refs = Command::new("git")
        .current_dir(repo)
        .arg("for-each-ref")
        .arg("--format=%(refname) %(objectname) %(objecttype)")
        .output()
        .expect("git for-each-ref failed");
    assert!(refs.status.success());
    let mut lines: Vec<String> = String::from_utf8_lossy(&refs.stdout)
        .lines()
        .map(String::from)
        .collect();
    lines.sort();

    let head = Command::new("git")
        .current_dir(repo)
        .arg("symbolic-ref")
        .arg("-q")
        .arg("HEAD")
        .output()
        .unwrap();
    let head_line = if head.status.success() {
        format!("HEAD -> {}", String::from_utf8_lossy(&head.stdout).trim())
    } else {
        "HEAD -> (detached or invalid)".to_string()
    };

    format!("{}\n{}", head_line, lines.join("\n"))
}

/// State validation: git fsck clean, git refs verify clean, no stray
/// .lock files anywhere under .git/refs or on packed-refs.
pub fn validate_state(repo: &Path) -> Result<(), String> {
    validate_state_impl(repo, true)
}

/// Same as validate_state, but tolerates "dangling <type> <oid>"
/// fsck warnings - legitimate for race-scenario fixtures where a
/// LOSING writer's candidate object is expected to end up unreferenced
/// by design (see r2_same_ref_race_stress_real_concurrency: whichever
/// writer doesn't win leaves its own commit-tree object dangling -
/// that's the fixture working as intended, not corruption). Still
/// rejects any OTHER fsck warning, and still requires refs verify and
/// stray-lock checks to pass.
pub fn validate_state_allow_dangling(repo: &Path) -> Result<(), String> {
    validate_state_impl(repo, false)
}

fn validate_state_impl(repo: &Path, strict_fsck_stdout: bool) -> Result<(), String> {
    let fsck = Command::new("git")
        .current_dir(repo)
        .arg("fsck")
        .arg("--no-progress")
        .output()
        .unwrap();
    if !fsck.status.success() {
        return Err(format!(
            "git fsck failed: {}",
            String::from_utf8_lossy(&fsck.stderr)
        ));
    }
    let fsck_stdout = String::from_utf8_lossy(&fsck.stdout);
    let unexpected: Vec<&str> = fsck_stdout
        .lines()
        .filter(|line| !(!strict_fsck_stdout && line.starts_with("dangling ")))
        .collect();
    if !unexpected.is_empty() {
        return Err(format!("git fsck reported warnings: {:?}", unexpected));
    }

    verify_ref_store(repo)?;

    let git_dir = repo.join(".git");
    let stray_locks = find_stray_locks(&git_dir);
    if !stray_locks.is_empty() {
        return Err(format!("stray .lock files found: {:?}", stray_locks));
    }

    Ok(())
}

pub fn verify_ref_store(repo: &Path) -> Result<(), String> {
    let verify = Command::new("git")
        .current_dir(repo)
        .env("LC_ALL", "C")
        .args(["refs", "verify", "--strict"])
        .output()
        .map_err(|error| error.to_string())?;
    let stderr = String::from_utf8_lossy(&verify.stderr);
    // Git 2.43 lacks this supplemental check. The harness still uses
    // fsck and stock Git's ref readback on those installations.
    if verify.status.success() || stderr.contains("'refs' is not a git command") {
        Ok(())
    } else {
        Err(format!("git refs verify --strict failed: {stderr}"))
    }
}

fn find_stray_locks(git_dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let refs_dir = git_dir.join("refs");
    if refs_dir.exists() {
        walk_for_locks(&refs_dir, &mut found);
    }
    let packed_lock = git_dir.join("packed-refs.lock");
    if packed_lock.exists() {
        found.push(packed_lock);
    }
    let head_lock = git_dir.join("HEAD.lock");
    if head_lock.exists() {
        found.push(head_lock);
    }
    found
}

// --- R2/R3 deterministic-interleaving support (checkpoint protocol,
// see src/refs/checkpoint.rs's doc comment for the file-based
// coordination scheme this drives from the test side). ---

use std::process::Child;
use std::time::{Duration, Instant};

pub fn make_checkpoint_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rustgit-checkpoint-{}-{}",
        std::process::id(),
        name
    ));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("failed to create checkpoint dir");
    dir
}

/// Arm a wait-point BEFORE spawning the writer that will hit it - the
/// marker file must already exist when the writer's code calls
/// checkpoint(name), or it will race straight through instead of
/// pausing.
pub fn arm_wait(checkpoint_dir: &Path, name: &str) {
    std::fs::write(checkpoint_dir.join(format!("wait_{}", name)), b"").unwrap();
}

/// Block (with a timeout, so a bug can't hang the whole test suite)
/// until the writer signals it reached `name`.
pub fn wait_for_marker(checkpoint_dir: &Path, name: &str, timeout: Duration) {
    let marker = checkpoint_dir.join(format!("at_{}", name));
    let start = Instant::now();
    while !marker.exists() {
        if start.elapsed() > timeout {
            panic!(
                "timed out waiting for checkpoint marker '{}' after {:?}",
                name, timeout
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Release a writer paused at a wait-point.
pub fn release_checkpoint(checkpoint_dir: &Path, name: &str) {
    std::fs::write(checkpoint_dir.join(format!("release_{}", name)), b"").unwrap();
}

/// Spawn ref-writer as a background process (not waited on) with the
/// given checkpoint dir wired in, optionally crashing at a named
/// checkpoint (R3). Returns the Child so the caller can orchestrate
/// pause/release or SIGKILL timing, then wait_with_output.
pub fn spawn_ref_writer_bg(
    repo: &Path,
    script: &str,
    checkpoint_dir: &Path,
    crash_at: Option<&str>,
) -> (Child, PathBuf) {
    let script_file = script_file(script);

    let git_dir = repo.join(".git");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ref-writer"));
    cmd.arg(&git_dir).arg(script_file.path());
    cmd.env("RUSTGIT_CHECKPOINT_DIR", checkpoint_dir);
    if let Some(point) = crash_at {
        cmd.env("RUSTGIT_CRASH_AT", point);
    }
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = cmd.spawn().expect("failed to spawn ref-writer");
    let script_path = script_file
        .into_temp_path()
        .keep()
        .expect("keep script until child exits");
    (child, script_path)
}

fn walk_for_locks(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            walk_for_locks(&path, found);
        } else if path.extension().map(|e| e == "lock").unwrap_or(false) {
            found.push(path);
        }
    }
}
