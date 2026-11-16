//! The default differential fixture must work in a source archive.

use std::path::Path;
use std::process::Command;

pub fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=RustGit tests",
            "-c",
            "user.email=rustgit@example.invalid",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ])
        .args(args)
        .output()
        .expect("start git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

pub fn small_repo() -> tempfile::TempDir {
    let fixture = tempfile::tempdir().expect("create small repository fixture");
    let repo = fixture.path();
    git(
        repo,
        &[
            "init",
            "-q",
            "--object-format=sha1",
            "--initial-branch=main",
        ],
    );
    let mut content = String::new();
    for index in 0..3 {
        content.push_str(&format!("file revision {index}\n"));
        content.push_str(&"the quick brown fox jumps over the lazy dog\n".repeat(10));
        std::fs::write(repo.join("fixture.txt"), &content).unwrap();
        git(repo, &["add", "fixture.txt"]);
        git(repo, &["commit", "-qm", &format!("fixture commit {index}")]);
    }
    git(repo, &["tag", "fixture-start", "HEAD~2"]);
    git(repo, &["repack", "-adq", "--window=0"]);
    fixture
}
