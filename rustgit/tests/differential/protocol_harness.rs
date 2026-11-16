// Differential harness for spike 02 (protocol v2 client). Oracle
// helpers shell out to real git's own client/inspection commands
// (git for-each-ref, git ls-remote, git fetch-pack, git rev-list) the
// same way spike 01's harness shelled out to verify-pack/cat-file.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Ground truth ref list for P1's ls-refs oracle comparison.
///
/// `--include-root-refs` (confirmed via git-for-each-ref.adoc-adjacent
/// behaviour, checked empirically: it adds HEAD to the listing) is
/// used only for the empty-prefix ("all refs") case, matching ls-refs'
/// own behaviour of including HEAD when no ref-prefix filter narrows
/// the result. For a non-empty prefix list, plain `for-each-ref
/// <pattern>...` is the correct oracle: HEAD is a bare name, not
/// under refs/, so it naturally won't match a "refs/..." prefix -
/// same semantics ls-refs itself has (a ref-prefix filters by refname
/// prefix, and "HEAD" never starts with "refs/").
pub fn oracle_refs(repo: &Path, prefixes: &[&str]) -> BTreeSet<(String, String)> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo)
        .arg("for-each-ref")
        .arg("--format=%(objectname) %(refname)");
    if prefixes.is_empty() {
        cmd.arg("--include-root-refs");
    } else {
        for p in prefixes {
            cmd.arg(p);
        }
    }
    let output = cmd.output().expect("failed to run git for-each-ref");
    assert!(
        output.status.success(),
        "git for-each-ref failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse_oid_refname_lines(&output.stdout)
}

/// P2 oracle: the ground-truth minimal object set for a fetch of
/// `wants` given the client already has `haves`. Equivalent to what a
/// correct negotiation should produce.
/// `git rev-list --objects <wants> --not <haves>`.
pub fn oracle_object_set(repo: &Path, wants: &[String], haves: &[String]) -> BTreeSet<String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo).arg("rev-list").arg("--objects");
    for w in wants {
        cmd.arg(w);
    }
    if !haves.is_empty() {
        cmd.arg("--not");
        for h in haves {
            cmd.arg(h);
        }
    }
    let output = cmd.output().expect("failed to run git rev-list --objects");
    assert!(
        output.status.success(),
        "git rev-list --objects failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Each line is "<oid>" or "<oid> <path>" (path present for blobs/trees
    // reached via a named path from a commit); we only need the oid.
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.split(' ').next().unwrap().to_string())
        .collect()
}

/// Write raw pack bytes received over the wire to a scratch file and
/// build an idx for them via real `git index-pack` - a normal,
/// necessary step any git client performs after a fetch (not a
/// shortcut around anything we're testing: the OBJECT SET the pack
/// contains, produced by our own negotiation logic, is what's under
/// test here, not pack-parsing, which spike 01 already proved).
pub fn index_received_pack(pack_bytes: &[u8], scratch_name: &str) -> (PathBuf, PathBuf) {
    let pack_path = std::env::temp_dir().join(format!(
        "rustgit-proto-{}-{}.pack",
        std::process::id(),
        scratch_name
    ));
    std::fs::write(&pack_path, pack_bytes).expect("failed to write received pack to scratch file");

    let output = Command::new("git")
        .arg("index-pack")
        .arg(&pack_path)
        .output()
        .expect("failed to run git index-pack on received pack");
    assert!(
        output.status.success(),
        "git index-pack failed on received pack: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let idx_path = pack_path.with_extension("idx");
    (pack_path, idx_path)
}

fn parse_oid_refname_lines(bytes: &[u8]) -> BTreeSet<(String, String)> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut parts = l.splitn(2, ' ');
            let oid = parts.next().expect("missing oid").to_string();
            let refname = parts.next().expect("missing refname").to_string();
            (oid, refname)
        })
        .collect()
}
