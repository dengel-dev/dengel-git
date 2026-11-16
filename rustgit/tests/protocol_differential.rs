// Entry point for the protocol v2 differential test suite (spike 02).
// Harness logic lives in tests/differential/protocol_harness.rs.

#[path = "differential/protocol_harness.rs"]
mod protocol_harness;

use protocol_harness::*;
use rustgit::pack;
use rustgit::protocol::capabilities::read_capability_advertisement;
use rustgit::protocol::fetch::{fetch, fetch_multi_round, FetchRequest};
use rustgit::protocol::ls_refs::{ls_refs, LsRefsRequest};
use rustgit::protocol::transport::UploadPackClient;
use std::path::PathBuf;
use std::process::Command;

#[path = "differential/small_repo.rs"]
mod small_repo;

use small_repo::{git, small_repo};

/// Smoke test, not a milestone assertion yet: connect, read the
/// capability advertisement, print it. Confirms the transport and
/// capability parsing work at all before wiring the real P1 oracle
/// comparison.
#[test]
fn smoke_capability_advertisement() {
    let fixture = small_repo();
    let repo = fixture.path();
    let mut client = UploadPackClient::spawn(&repo).expect("failed to spawn git upload-pack");
    let caps = read_capability_advertisement(&mut client)
        .expect("failed to read capability advertisement");

    eprintln!("capabilities: {:?}", caps.entries);
    assert!(caps.has("ls-refs"), "server did not advertise ls-refs");
    assert!(caps.has("fetch"), "server did not advertise fetch");

    // Politely end the connection: empty request (flush only).
    client.write_flush().unwrap();
    client.flush_stdin().unwrap();
    let stderr = client.finish().unwrap();
    assert!(stderr.is_empty(), "upload-pack stderr: {}", stderr);
}

/// Smoke test for ls-refs against this repo, no filter.
#[test]
fn smoke_ls_refs_all() {
    let fixture = small_repo();
    let repo = fixture.path();
    let mut client = UploadPackClient::spawn(&repo).expect("failed to spawn git upload-pack");
    let _caps = read_capability_advertisement(&mut client).unwrap();

    let entries = ls_refs(&mut client, &LsRefsRequest::default()).expect("ls-refs failed");
    eprintln!("ls-refs entries: {:?}", entries);
    assert!(!entries.is_empty(), "expected at least one ref");

    client.write_flush().unwrap();
    client.flush_stdin().unwrap();
    let stderr = client.finish().unwrap();
    assert!(stderr.is_empty(), "upload-pack stderr: {}", stderr);
}

/// P1: for a range of ref-prefix filters, our parsed ls-refs result
/// must exactly match `git for-each-ref`'s ground truth (see
/// oracle_refs's doc comment for how HEAD is handled).
fn assert_ls_refs_matches_oracle(repo: &std::path::Path, prefixes: &[&str], label: &str) {
    let mut client = UploadPackClient::spawn(repo).expect("failed to spawn git upload-pack");
    let _caps = read_capability_advertisement(&mut client).unwrap();

    let req = LsRefsRequest {
        symrefs: false,
        peel: false,
        ref_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
    };
    let entries = ls_refs(&mut client, &req).expect("ls-refs failed");
    client.write_flush().unwrap();
    client.flush_stdin().unwrap();
    let stderr = client.finish().unwrap();
    assert!(
        stderr.is_empty(),
        "[{}] upload-pack stderr: {}",
        label,
        stderr
    );

    let ours: std::collections::BTreeSet<(String, String)> =
        entries.into_iter().map(|e| (e.oid, e.refname)).collect();
    let oracle = oracle_refs(repo, prefixes);

    eprintln!("[{}] ours={:?} oracle={:?}", label, ours, oracle);
    assert_eq!(
        ours, oracle,
        "[{}] ls-refs result does not match git for-each-ref",
        label
    );
}

#[test]
fn p1_ls_refs_all_matches_oracle() {
    assert_ls_refs_matches_oracle(small_repo().path(), &[], "all refs");
}

#[test]
fn p1_ls_refs_heads_only_matches_oracle() {
    assert_ls_refs_matches_oracle(small_repo().path(), &["refs/heads/"], "heads/ only");
}

#[test]
fn p1_ls_refs_tags_only_matches_oracle() {
    assert_ls_refs_matches_oracle(small_repo().path(), &["refs/tags/"], "tags/ only");
}

#[test]
fn p1_ls_refs_nonexistent_prefix_matches_oracle() {
    assert_ls_refs_matches_oracle(
        small_repo().path(),
        &["refs/does-not-exist/"],
        "nonexistent prefix",
    );
}

#[test]
fn p1_ls_refs_multiple_prefixes_matches_oracle() {
    assert_ls_refs_matches_oracle(
        small_repo().path(),
        &["refs/heads/", "refs/tags/"],
        "multiple prefixes",
    );
}

/// P1 against a real-world medium corpus. Not run by default. Point
/// RUSTGIT_FIXTURE at a repo (any spike-01 fixture works, ls-refs
/// doesn't care about pack/delta state) and run with
/// `cargo test --test protocol_differential -- --ignored`.
#[test]
#[ignore]
fn p1_ls_refs_medium_corpus() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repo path"),
    );
    assert_ls_refs_matches_oracle(&repo, &[], "medium corpus, all refs");
    assert_ls_refs_matches_oracle(&repo, &["refs/heads/"], "medium corpus, heads/ only");
    assert_ls_refs_matches_oracle(&repo, &["refs/tags/"], "medium corpus, tags/ only");
}

/// P2: fetch (want/have/done in one round) must produce a pack whose
/// object set exactly matches `git rev-list --objects <wants> --not
/// <haves>` - the documented minimal-correct set. `label` distinguishes
/// full-clone (haves empty) from incremental-fetch scenarios in output.
fn assert_fetch_matches_oracle(
    repo: &std::path::Path,
    wants: Vec<String>,
    haves: Vec<String>,
    scratch_name: &str,
    label: &str,
) {
    let mut client = UploadPackClient::spawn(repo).expect("failed to spawn git upload-pack");
    let _caps = read_capability_advertisement(&mut client).unwrap();

    let resp = fetch(
        &mut client,
        &FetchRequest {
            wants: wants.clone(),
            haves: haves.clone(),
            include_tag: false,
        },
    )
    .unwrap_or_else(|e| panic!("[{}] fetch failed: {}", label, e));
    assert!(
        resp.pack_bytes.starts_with(b"PACK"),
        "[{}] response doesn't start with a PACK signature",
        label
    );

    let stderr = client.finish().unwrap();
    assert!(
        stderr.is_empty(),
        "[{}] upload-pack stderr: {}",
        label,
        stderr
    );

    let (pack_path, idx_path) = index_received_pack(&resp.pack_bytes, scratch_name);
    let ours = pack::read_all(&idx_path, &pack_path);
    let our_oids: std::collections::BTreeSet<String> = ours.iter().map(|o| o.oid.clone()).collect();

    let oracle = oracle_object_set(repo, &wants, &haves);

    eprintln!(
        "[{}] ours={} objects, oracle={} objects, pack_bytes={}",
        label,
        our_oids.len(),
        oracle.len(),
        resp.pack_bytes.len()
    );

    // NOT a strict equality check - see NOTES-02.md's P2 finding.
    // upload-pack's own boundary computation is a conservative
    // superset of the theoretical `rev-list --objects want --not
    // have` minimum, not guaranteed to equal it: on the medium
    // corpus, one incremental fetch came back with exactly one blob
    // beyond the minimal set - a blob independently confirmed
    // reachable from the `have` commit's own tree (so the client
    // already had it under a different path; nothing was ever
    // MISSING, something merely non-minimal was included). This
    // mirrors spike 01's M3/M4 stance: exact/minimal is not the bar,
    // real git's own actual output is. Correctness requires our set
    // be a SUPERSET of the true minimum (nothing missing) and bounded
    // in excess (not wildly over-fetching, which would indicate a
    // real negotiation bug rather than this documented-by-observation
    // server-side looseness).
    let missing: Vec<&String> = oracle.difference(&our_oids).collect();
    assert!(
        missing.is_empty(),
        "[{}] negotiated set is MISSING {} objects the minimal oracle requires: {:?}",
        label,
        missing.len(),
        missing
    );
    let extra = our_oids.len() - oracle.len();
    let extra_fraction = extra as f64 / oracle.len().max(1) as f64;
    assert!(
        extra_fraction <= 0.02,
        "[{}] negotiated set has {} extra objects ({:.2}% over the minimal oracle) - \
         beyond the small-superset slack observed on the medium corpus, likely a real bug",
        label,
        extra,
        extra_fraction * 100.0
    );
    if extra > 0 {
        eprintln!(
            "[{}] {} extra object(s) beyond the theoretical minimum (server-side superset behaviour, not missing objects): {:?}",
            label, extra, our_oids.difference(&oracle).collect::<Vec<_>>()
        );
    }

    std::fs::remove_file(&pack_path).ok();
    std::fs::remove_file(&idx_path).ok();
}

fn head_oid_of(repo: &std::path::Path) -> String {
    let mut client = UploadPackClient::spawn(repo).expect("failed to spawn git upload-pack");
    let _caps = read_capability_advertisement(&mut client).unwrap();
    let refs = ls_refs(
        &mut client,
        &LsRefsRequest {
            ref_prefixes: vec!["refs/heads/".into()],
            ..Default::default()
        },
    )
    .unwrap();
    let oid = refs
        .iter()
        .find(|r| r.refname == "refs/heads/main")
        .expect("no refs/heads/main")
        .oid
        .clone();
    client.write_flush().unwrap();
    client.flush_stdin().unwrap();
    client.finish().unwrap();
    oid
}

#[test]
fn p2_fetch_full_clone_matches_oracle() {
    let fixture = small_repo();
    let repo = fixture.path();
    let head_oid = head_oid_of(&repo);
    assert_fetch_matches_oracle(
        &repo,
        vec![head_oid],
        vec![],
        "p2-full",
        "full clone (no haves)",
    );
}

/// P2 incremental fetch from an existing ancestor in the fixture.
#[test]
fn p2_fetch_incremental_matches_oracle() {
    let fixture = small_repo();
    let repo = fixture.path();
    let head_oid = head_oid_of(repo);
    let full_have = git(repo, &["rev-parse", "HEAD~1"]);

    assert_fetch_matches_oracle(
        &repo,
        vec![head_oid],
        vec![full_have],
        "p2-incremental",
        "incremental fetch (with haves)",
    );
}

/// P2 against a real-world medium corpus. Not run by default. Point
/// RUSTGIT_FIXTURE at a repo with real history depth (e.g. spike 01's
/// full non-shallow gitoxide clone) and run with
/// `cargo test --test protocol_differential -- --ignored`.
#[test]
#[ignore]
fn p2_fetch_medium_corpus() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repo path"),
    );
    let head_oid = head_oid_of(&repo);

    // Full clone.
    assert_fetch_matches_oracle(
        &repo,
        vec![head_oid.clone()],
        vec![],
        "p2-medium-full",
        "medium corpus, full clone",
    );

    // Incremental: have = an ancestor ~50 commits back from HEAD.
    let ancestor = Command::new("git")
        .current_dir(&repo)
        .arg("rev-parse")
        .arg(format!("{}~50", head_oid))
        .output()
        .expect("git rev-parse failed");
    assert!(
        ancestor.status.success(),
        "git rev-parse ~50 failed: {}",
        String::from_utf8_lossy(&ancestor.stderr)
    );
    let ancestor_oid = String::from_utf8_lossy(&ancestor.stdout).trim().to_string();

    assert_fetch_matches_oracle(
        &repo,
        vec![head_oid],
        vec![ancestor_oid],
        "p2-medium-incr",
        "medium corpus, incremental fetch",
    );
}

/// Debug aid (not a milestone test): dump our negotiated object set
/// and the oracle's to files for diffing, when a mismatch needs exact
/// identification rather than a giant assertion diff.
#[test]
#[ignore]
fn debug_dump_incremental_mismatch() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repo path"),
    );
    let head_oid = head_oid_of(&repo);
    let ancestor = Command::new("git")
        .current_dir(&repo)
        .arg("rev-parse")
        .arg(format!("{}~50", head_oid))
        .output()
        .unwrap();
    let ancestor_oid = String::from_utf8_lossy(&ancestor.stdout).trim().to_string();

    let mut client = UploadPackClient::spawn(&repo).unwrap();
    let _caps = read_capability_advertisement(&mut client).unwrap();
    let resp = fetch(
        &mut client,
        &FetchRequest {
            wants: vec![head_oid.clone()],
            haves: vec![ancestor_oid.clone()],
            include_tag: false,
        },
    )
    .unwrap();
    client.finish().unwrap();

    let (pack_path, idx_path) = index_received_pack(&resp.pack_bytes, "debug-dump");
    let ours = pack::read_all(&idx_path, &pack_path);
    let mut our_oids: Vec<String> = ours.iter().map(|o| o.oid.clone()).collect();
    our_oids.sort();
    std::fs::write("/tmp/ours_oids.txt", our_oids.join("\n")).unwrap();
    eprintln!("wrote {} oids to /tmp/ours_oids.txt", our_oids.len());
    eprintln!("head={} ancestor={}", head_oid, ancestor_oid);
}

/// P3: multi-round negotiation, forced to actually take multiple
/// rounds (not just batch_size=1 with a single have, which would
/// collapse to one round regardless - see fn doc comment). Sends a
/// DECOY have first (a real oid in the repo, but NOT an ancestor of
/// `want` - the server must NAK it and continue negotiating) followed
/// by a real common-ancestor have. Asserts `rounds >= 2` to confirm
/// the multi-round code path actually executed, not just that the
/// final result happens to be correct via a single lucky round.
/// Not run by default - needs real branch divergence to construct a
/// genuine decoy, which this repo's small linear history doesn't have.
/// Point RUSTGIT_FIXTURE at a repo with real branches (e.g. spike 01's
/// full gitoxide clone) and run with `-- --ignored`.
#[test]
#[ignore]
fn p3_multi_round_negotiation_medium_corpus() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repo path"),
    );
    let head_oid = head_oid_of(&repo);

    // Find a decoy: a commit reachable from some OTHER ref that is
    // NOT an ancestor of head_oid - the server must NAK it.
    let refs_output = Command::new("git")
        .current_dir(&repo)
        .arg("for-each-ref")
        .arg("--format=%(objectname)")
        .arg("refs/remotes/")
        .output()
        .unwrap();
    let decoy = String::from_utf8_lossy(&refs_output.stdout)
        .lines()
        .find(|oid| {
            let check = Command::new("git")
                .current_dir(&repo)
                .arg("merge-base")
                .arg("--is-ancestor")
                .arg(oid)
                .arg(&head_oid)
                .status()
                .unwrap();
            !check.success() // NOT an ancestor -> good decoy
        })
        .expect("no decoy commit found (repo may be too linear for this test)")
        .to_string();

    let ancestor = Command::new("git")
        .current_dir(&repo)
        .arg("rev-parse")
        .arg(format!("{}~50", head_oid))
        .output()
        .unwrap();
    let ancestor_oid = String::from_utf8_lossy(&ancestor.stdout).trim().to_string();

    eprintln!("decoy={} real ancestor={}", decoy, ancestor_oid);

    let mut client = UploadPackClient::spawn(&repo).expect("failed to spawn git upload-pack");
    let _caps = read_capability_advertisement(&mut client).unwrap();

    let (resp, rounds) = fetch_multi_round(
        &mut client,
        &[head_oid.clone()],
        &[decoy, ancestor_oid.clone()],
        1,
    )
    .expect("multi-round fetch failed");
    let stderr = client.finish().unwrap();
    assert!(stderr.is_empty(), "upload-pack stderr: {}", stderr);

    eprintln!("rounds={} pack_bytes={}", rounds, resp.pack_bytes.len());
    assert!(
        rounds >= 2,
        "expected the decoy to force at least 2 rounds, got {}",
        rounds
    );
    assert!(resp.pack_bytes.starts_with(b"PACK"));

    let (pack_path, idx_path) = index_received_pack(&resp.pack_bytes, "p3-multiround");
    let ours = pack::read_all(&idx_path, &pack_path);
    let our_oids: std::collections::BTreeSet<String> = ours.iter().map(|o| o.oid.clone()).collect();
    let oracle = oracle_object_set(&repo, &[head_oid], &[ancestor_oid]);

    let missing: Vec<&String> = oracle.difference(&our_oids).collect();
    assert!(
        missing.is_empty(),
        "multi-round result is missing {} objects: {:?}",
        missing.len(),
        missing
    );
    let extra_fraction = (our_oids.len() - oracle.len()) as f64 / oracle.len().max(1) as f64;
    assert!(
        extra_fraction <= 0.02,
        "multi-round result has {:.2}% extra objects, beyond expected slack",
        extra_fraction * 100.0
    );

    std::fs::remove_file(&pack_path).ok();
    std::fs::remove_file(&idx_path).ok();
}

/// P4: a server that doesn't speak protocol v2 (spawned without
/// GIT_PROTOCOL=version=2 - see NOTES-02.md's P4 finding for why this,
/// not a server-side config, is the real mechanism) must be detected
/// cleanly, not silently misparsed and not a panic. Full v0 support is
/// out of scope (SPIKE-02.md) - clean failure detection is the bar.
#[test]
fn p4_legacy_server_detected_cleanly() {
    let fixture = small_repo();
    let repo = fixture.path();
    let mut client =
        UploadPackClient::spawn_legacy(&repo).expect("failed to spawn git upload-pack");
    let result = read_capability_advertisement(&mut client);

    match result {
        Err(rustgit::protocol::capabilities::AdvertisementError::NotProtocolV2 { first_line }) => {
            eprintln!(
                "correctly detected legacy server, first line: {:?}",
                first_line
            );
            // Sanity: the legacy line should NOT look anything like our
            // v2 marker, and should contain "HEAD" per the v0 ref
            // advertisement's own shape (oid HEAD\0capabilities...) -
            // confirms we actually read real legacy content, not just
            // an empty/garbage response that happens to not equal
            // "version 2".
            assert!(
                first_line.contains("HEAD"),
                "expected the legacy ref advertisement's first line to mention HEAD, got {:?}",
                first_line
            );
        }
        Err(other) => panic!("expected NotProtocolV2, got a different error: {}", other),
        Ok(caps) => panic!(
            "expected legacy detection to fail cleanly, but parsed capabilities as if v2: {:?}",
            caps
        ),
    }

    client.finish().unwrap();
}

/// P4 companion: confirm the SAME repo, spawned normally (v2
/// requested), still parses fine - proves the legacy detection above
/// is really about the missing GIT_PROTOCOL env var, not some other
/// difference between the two spawn paths.
#[test]
fn p4_normal_spawn_still_speaks_v2() {
    let fixture = small_repo();
    let repo = fixture.path();
    let mut client = UploadPackClient::spawn(&repo).expect("failed to spawn git upload-pack");
    let caps =
        read_capability_advertisement(&mut client).expect("v2 spawn should still parse cleanly");
    assert!(caps.has("ls-refs"));
    client.write_flush().unwrap();
    client.flush_stdin().unwrap();
    client.finish().unwrap();
}
