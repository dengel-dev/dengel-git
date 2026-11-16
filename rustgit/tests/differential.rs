// Entry point for the differential test suite. Actual harness logic
// lives in tests/differential/mod.rs (shared module, not itself a
// separate test binary).

#[path = "differential/mod.rs"]
mod differential;

use differential::*;
use rustgit::pack;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

#[path = "differential/small_repo.rs"]
mod small_repo;

use small_repo::{git, small_repo};

/// A scratch file path under the system temp dir, unique per test
/// (tests run concurrently within this binary, so each caller must
/// pass a name distinct from every other test's).
fn scratch_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rustgit-{}-{}", std::process::id(), name))
}

/// A separate repository for M5, which writes another pack while
/// completing the thin pack.
fn make_scratch_base_repo(name: &str) -> PathBuf {
    let dir = scratch_path(name);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("failed to create scratch base repo dir");
    let init = Command::new("git")
        .current_dir(&dir)
        .arg("init")
        .arg("-q")
        .output()
        .expect("git init failed");
    assert!(
        init.status.success(),
        "git init failed for scratch base repo"
    );

    let content = "the quick brown fox jumps over the lazy dog\n".repeat(10);
    std::fs::write(dir.join("seed.txt"), &content).expect("failed to write seed file");
    let add = Command::new("git")
        .current_dir(&dir)
        .arg("add")
        .arg("seed.txt")
        .output()
        .expect("git add failed");
    assert!(add.status.success(), "git add failed for scratch base repo");
    let commit = Command::new("git")
        .current_dir(&dir)
        .args([
            "-c",
            "user.email=spike@example.com",
            "-c",
            "user.name=spike",
        ])
        .arg("commit")
        .arg("-q")
        .arg("-m")
        .arg("seed")
        .output()
        .expect("git commit failed");
    assert!(
        commit.status.success(),
        "git commit failed for scratch base repo: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let repack = Command::new("git")
        .current_dir(&dir)
        .arg("repack")
        .arg("-a")
        .arg("-d")
        .arg("-q")
        .output()
        .expect("git repack failed");
    assert!(
        repack.status.success(),
        "git repack failed for scratch base repo"
    );

    dir
}

/// Sanity-check the harness itself: run it against a fresh synthetic
/// repository's pack and confirm verify-pack's output parses
/// as expected, and that cat-file agrees with verify-pack's type field.
/// No codec code is exercised yet - this just proves the oracle wiring
/// works before M1 parsing is built.
#[test]
fn harness_parses_verify_pack_output() {
    let fixture = small_repo();
    let repo = fixture.path();
    let idx = find_single_pack_idx(&repo);
    let result = verify_pack(&idx);

    assert!(result.ok, "git verify-pack reported failure: {:?}", result);
    assert!(
        !result.objects.is_empty(),
        "expected at least one object in the pack"
    );

    for obj in &result.objects {
        assert_eq!(obj.oid.len(), 40, "oid should be 40 hex chars (sha1)");
        assert!(
            matches!(obj.kind.as_str(), "commit" | "tree" | "blob" | "tag"),
            "unexpected type {} for {}",
            obj.kind,
            obj.oid
        );

        // Cross-check against a second, independent oracle call.
        let cat_type = cat_file_type(&repo, &obj.oid);
        assert_eq!(
            cat_type, obj.kind,
            "verify-pack and cat-file disagree on type for {}",
            obj.oid
        );
    }
}

/// Confirm cat-file content is retrievable and non-empty for every
/// object verify-pack reports, and that commit content is human
/// readable text mentioning the known commit message.
#[test]
fn harness_cat_file_content_matches_expectations() {
    let fixture = small_repo();
    let repo = fixture.path();
    let idx = find_single_pack_idx(&repo);
    let result = verify_pack(&idx);

    let root = git(repo, &["rev-list", "--max-parents=0", "HEAD"]);
    assert!(result
        .objects
        .iter()
        .any(|object| object.oid == root && object.kind == "commit"));
    let content = cat_file_content(repo, &root);
    let content_str = String::from_utf8_lossy(&content);
    assert!(
        content_str.contains("fixture commit 0"),
        "commit content did not contain expected message:\n{}",
        content_str
    );
}

/// Shared M1 assertion: for every non-delta object git's own oracle
/// (verify-pack) reports in `repo`, our codec must independently
/// compute the same oid, agree on type, and produce byte-identical
/// content to `git cat-file <type>` (raw, not pretty-printed - see
/// cat_file_raw doc comment). This is the milestone-defining check -
/// M1 is "done" only when this passes on real repacked packs.
fn assert_m1_matches_oracle(repo: &std::path::Path) {
    let idx_path = find_single_pack_idx(repo);
    let pack_path = idx_path.with_extension("pack");

    let oracle = verify_pack(&idx_path);
    assert!(oracle.ok, "oracle pack itself failed verification");

    let delta_count = oracle.objects.iter().filter(|o| o.is_delta()).count();
    assert_eq!(
        delta_count, 0,
        "this fixture has {} delta object(s); M1 fixture must be delta-free \
         (repack with `git repack -ad --window=0 -f` to disable deltification), \
         deltas are M2 scope",
        delta_count
    );

    let (ours, skipped) = pack::read_all_non_delta(&idx_path, &pack_path);
    assert_eq!(skipped, 0, "unexpected delta entries skipped: {}", skipped);
    assert_eq!(
        ours.len(),
        oracle.objects.len(),
        "object count mismatch: ours={}, oracle={}",
        ours.len(),
        oracle.objects.len()
    );

    let ours_by_oid: HashMap<&str, &pack::ReadObject> =
        ours.iter().map(|o| (o.oid.as_str(), o)).collect();

    let all_oids: Vec<String> = oracle.objects.iter().map(|o| o.oid.clone()).collect();
    let expected_contents = cat_file_batch_content(repo, &all_oids);

    for oracle_obj in &oracle.objects {
        let mine = ours_by_oid
            .get(oracle_obj.oid.as_str())
            .unwrap_or_else(|| panic!("our codec did not produce oid {}", oracle_obj.oid));

        assert_eq!(
            mine.kind, oracle_obj.kind,
            "type mismatch for {}: ours={}, oracle={}",
            oracle_obj.oid, mine.kind, oracle_obj.kind
        );
        assert_eq!(
            mine.size, oracle_obj.size,
            "size mismatch for {}",
            oracle_obj.oid
        );

        let expected_content = &expected_contents[&oracle_obj.oid];
        assert_eq!(
            &mine.content, expected_content,
            "content mismatch for {} ({})",
            oracle_obj.oid, oracle_obj.kind
        );
    }
}

#[test]
fn m1_codec_matches_oracle_for_all_objects() {
    assert_m1_matches_oracle(small_repo().path());
}

/// M1 against a real-world "medium" corpus fixture (see corpus/README.md).
/// Not run by default - fixtures aren't vendored into this repo. Point
/// RUSTGIT_FIXTURE at a clone repacked with `git repack -a -d --window=0 -f`
/// (no deltas, since delta resolution is M2 scope) and run with
/// `cargo test --test differential -- --ignored`.
#[test]
#[ignore]
fn m1_codec_matches_oracle_medium_corpus() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repacked repo path"),
    );
    assert_m1_matches_oracle(&repo);
}

/// verify-pack can't tell OFS_DELTA from REF_DELTA (see NOTES.md) - so
/// to confirm a fixture actually exercises both wire formats, scan the
/// pack's own raw entry types directly via the codec's pack module.
fn count_delta_flavours(idx_path: &std::path::Path, pack_path: &std::path::Path) -> (usize, usize) {
    let idx = pack::idx::parse(idx_path).expect("failed to parse idx");
    let pack_data = pack::pack::read_pack_file(pack_path).expect("failed to read pack file");

    let mut ofs = 0usize;
    let mut refd = 0usize;
    for entry in &idx.entries {
        let raw = pack::pack::read_raw_entry(&pack_data, entry.offset);
        match raw.kind {
            pack::pack::OBJ_OFS_DELTA => ofs += 1,
            pack::pack::OBJ_REF_DELTA => refd += 1,
            _ => {}
        }
    }
    (ofs, refd)
}

/// M2 read path: resolve every OBJ_OFS_DELTA/OBJ_REF_DELTA chain in
/// `repo`'s pack and confirm the resolved oid, type, size, and content
/// agree with real git for every object - not just the non-delta ones.
/// `label` is used only for the adversarial-fixture guard and log
/// output. Guards fixture quality first (assert_fixture_is_adversarial)
/// so a future accidentally-delta-free or shallow-chain fixture fails
/// loudly instead of silently testing nothing while staying green.
fn assert_m2_matches_oracle(repo: &std::path::Path, label: &str) {
    let idx_path = find_single_pack_idx(repo);
    let pack_path = idx_path.with_extension("pack");

    let oracle = verify_pack(&idx_path);
    assert!(oracle.ok, "oracle pack itself failed verification");

    let mut stats = compute_delta_stats(&oracle.objects);
    let (ofs, refd) = count_delta_flavours(&idx_path, &pack_path);
    stats.ofs_delta_count = ofs;
    stats.ref_delta_count = refd;
    stats.log_summary(label);
    assert_fixture_is_adversarial(&stats, label);

    let ours = pack::read_all(&idx_path, &pack_path);
    assert_eq!(
        ours.len(),
        oracle.objects.len(),
        "[{}] object count mismatch: ours={}, oracle={}",
        label,
        ours.len(),
        oracle.objects.len()
    );

    let ours_by_oid: HashMap<&str, &pack::ReadObject> =
        ours.iter().map(|o| (o.oid.as_str(), o)).collect();

    let all_oids: Vec<String> = oracle.objects.iter().map(|o| o.oid.clone()).collect();
    let expected_contents = cat_file_batch_content(repo, &all_oids);

    for oracle_obj in &oracle.objects {
        let mine = ours_by_oid.get(oracle_obj.oid.as_str()).unwrap_or_else(|| {
            panic!(
                "[{}] our codec did not produce oid {}",
                label, oracle_obj.oid
            )
        });

        assert_eq!(
            mine.kind, oracle_obj.kind,
            "[{}] type mismatch for {}: ours={}, oracle={}",
            label, oracle_obj.oid, mine.kind, oracle_obj.kind
        );

        // NOTE: verify-pack's "size" column is NOT comparable to our
        // resolved object size for delta entries - per
        // gitformat-pack.adoc, for deltified objects that field is
        // "the size of the uncompressed delta" (the delta instruction
        // stream), not the final reconstructed object size. Only
        // non-delta entries have size == final content length there.
        // The real size oracle for every entry, delta or not, is the
        // batched content length below (cat-file --batch's declared
        // size uses %(objectsize) semantics, i.e. `cat-file -s`).
        if !oracle_obj.is_delta() {
            assert_eq!(
                mine.size, oracle_obj.size,
                "[{}] size mismatch for non-delta object {}",
                label, oracle_obj.oid
            );
        }

        let expected_content = &expected_contents[&oracle_obj.oid];
        assert_eq!(
            mine.size,
            expected_content.len() as u64,
            "[{}] resolved size does not match cat-file's reported size for {}",
            label,
            oracle_obj.oid
        );
        assert_eq!(
            &mine.content, expected_content,
            "[{}] content mismatch for {} ({})",
            label, oracle_obj.oid, oracle_obj.kind
        );
    }
}

/// M2 against a normally-repacked real-world corpus (default window/depth,
/// so whatever chain depths git's own heuristics naturally produce).
/// Not run by default - fixture isn't vendored. Point RUSTGIT_FIXTURE at
/// a repo repacked with plain `git repack -a -d -f` (deltas left on) and
/// run with `cargo test --test differential -- --ignored`.
#[test]
#[ignore]
fn m2_codec_matches_oracle_normal_repack() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repacked repo path"),
    );
    assert_m2_matches_oracle(&repo, "normal repack (default window/depth)");
}

/// M2 against an aggressively repacked fixture - large --window/--depth
/// to deliberately force deep OFS_DELTA chains beyond what a normal
/// repack would produce. Point RUSTGIT_FIXTURE at a repo repacked with
/// `git repack -a -d -f --window=250 --depth=250`.
#[test]
#[ignore]
fn m2_codec_matches_oracle_aggressive_repack() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repacked repo path"),
    );
    assert_m2_matches_oracle(&repo, "aggressive repack (window=250 depth=250)");
}

/// M2 against a REF_DELTA-only pack - `git pack-objects` without
/// `--delta-base-offset` always encodes bases as 20-byte oids rather
/// than offsets (git repack passes --delta-base-offset by default, so
/// this flavour has to be produced by calling pack-objects directly).
/// Point RUSTGIT_FIXTURE at a repo whose sole pack was built that way
/// (see corpus/generate_m2_fixtures.sh).
#[test]
#[ignore]
fn m2_codec_matches_oracle_ref_delta_only() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repacked repo path"),
    );
    assert_m2_matches_oracle(&repo, "ref-delta-only pack (no --delta-base-offset)");
}

/// M3 write path: read every object out of a real repacked pack in
/// `repo` (round-tripping through our own M1/M2 read path first, so
/// the object set is real content, not synthetic), write them back
/// out with our writer (non-delta only - M4 adds delta emission), and
/// confirm real git accepts the result:
///   - `git index-pack --strict` on our pack (internal consistency:
///     no broken objects/links)
///   - `git verify-pack -v` on OUR OWN generated idx against our pack
///     (validates the idx writer, not just the pack writer)
///   - the object set git reports matches what we intended to write:
///     same oids, same types, same content (batched against cat-file).
/// Byte-identical output to git is explicitly not the goal per
/// SPIKE.md - only semantic agreement.
fn assert_m3_write_path(repo: &std::path::Path, pack_name: &str, label: &str) {
    let idx_path = find_single_pack_idx(repo);
    let src_pack_path = idx_path.with_extension("pack");
    let source_objects = pack::read_all(&idx_path, &src_pack_path);
    assert!(
        !source_objects.is_empty(),
        "[{}] source fixture has no objects",
        label
    );

    let write_objects: Vec<pack::writer::WriteObject> = source_objects
        .iter()
        .map(|o| pack::writer::WriteObject {
            kind: match o.kind {
                "commit" => pack::pack::OBJ_COMMIT,
                "tree" => pack::pack::OBJ_TREE,
                "blob" => pack::pack::OBJ_BLOB,
                "tag" => pack::pack::OBJ_TAG,
                other => panic!("[{}] unexpected resolved type {}", label, other),
            },
            content: o.content.clone(),
        })
        .collect();

    let written = pack::writer::write_pack(&write_objects);

    let out_pack_path = scratch_path(&format!("{}.pack", pack_name));
    let out_idx_path = scratch_path(&format!("{}.idx", pack_name));
    std::fs::write(&out_pack_path, &written.pack_bytes).expect("failed to write scratch pack");
    std::fs::write(&out_idx_path, &written.idx_bytes).expect("failed to write scratch idx");

    // Oracle 1: does git accept our pack as internally consistent?
    let strict_result = index_pack_strict(&out_pack_path);
    assert!(
        strict_result.success,
        "[{}] git index-pack --strict rejected our pack:\nstdout: {}\nstderr: {}",
        label, strict_result.stdout, strict_result.stderr
    );
    eprintln!(
        "[fixture: {}] git index-pack --strict: accepted ({} objects written)",
        label,
        write_objects.len()
    );

    // Oracle 2: does git accept OUR OWN idx against our pack, and does
    // its object listing match what we intended to write?
    let oracle = verify_pack(&out_idx_path);
    assert!(
        oracle.ok,
        "[{}] git verify-pack rejected our own idx+pack",
        label
    );
    assert_eq!(
        oracle.objects.len(),
        write_objects.len(),
        "[{}] git reports {} objects, we wrote {}",
        label,
        oracle.objects.len(),
        write_objects.len()
    );

    let intended_oids: std::collections::HashSet<&str> =
        source_objects.iter().map(|o| o.oid.as_str()).collect();
    for oracle_obj in &oracle.objects {
        assert!(
            intended_oids.contains(oracle_obj.oid.as_str()),
            "[{}] git reports oid {} that we never intended to write",
            label,
            oracle_obj.oid
        );
        assert!(
            !oracle_obj.is_delta(),
            "[{}] git reports {} as deltified, but M3 writer never emits deltas",
            label,
            oracle_obj.oid
        );
    }

    // Content check: git-verify-pack.adoc doesn't spell out whether
    // verify-pack itself recomputes every object's sha1 (vs trusting
    // the idx's listed oids), so rather than lean on that unconfirmed
    // assumption, prove content directly - drop our pack+idx into a
    // fresh scratch repo and batch-cat-file every object out of it.
    let scratch_repo = scratch_path(&format!("{}-repo", pack_name));
    std::fs::remove_dir_all(&scratch_repo).ok();
    std::fs::create_dir_all(scratch_repo.join(".git/objects/pack")).expect("mkdir scratch repo");
    let init = Command::new("git")
        .current_dir(&scratch_repo)
        .arg("init")
        .arg("-q")
        .output()
        .expect("failed to init scratch repo");
    assert!(
        init.status.success(),
        "[{}] git init failed for content-check scratch repo",
        label
    );
    std::fs::copy(
        &out_pack_path,
        scratch_repo
            .join(".git/objects/pack")
            .join(format!("{}.pack", pack_name)),
    )
    .expect("failed to copy pack into scratch repo");
    std::fs::copy(
        &out_idx_path,
        scratch_repo
            .join(".git/objects/pack")
            .join(format!("{}.idx", pack_name)),
    )
    .expect("failed to copy idx into scratch repo");

    let all_oids: Vec<String> = source_objects.iter().map(|o| o.oid.clone()).collect();
    let scratch_contents = cat_file_batch_content(&scratch_repo, &all_oids);
    for src in &source_objects {
        let via_scratch_repo = &scratch_contents[&src.oid];
        assert_eq!(
            &src.content, via_scratch_repo,
            "[{}] content mismatch reading {} back from our own written pack",
            label, src.oid
        );
    }

    std::fs::remove_dir_all(&scratch_repo).ok();
    std::fs::remove_file(&out_pack_path).ok();
    std::fs::remove_file(&out_idx_path).ok();
}

#[test]
fn m3_write_path_matches_oracle_small() {
    assert_m3_write_path(
        small_repo().path(),
        "m3-small",
        "small fixture (round-trip)",
    );
}

/// M3 against a real-world medium corpus. Not run by default. Point
/// RUSTGIT_FIXTURE at a repacked repo (from any M1/M2 fixture recipe)
/// and run with `cargo test --test differential -- --ignored`.
#[test]
#[ignore]
fn m3_write_path_matches_oracle_medium_corpus() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repacked repo path"),
    );
    assert_m3_write_path(&repo, "m3-medium", "medium corpus (round-trip)");
}

/// Debug aid (not a milestone test): round-trip write_pack's output
/// through our OWN reader (no git involved) to isolate whether a
/// write-path bug is in the encoder or only surfaces against git.
#[test]
#[ignore]
fn debug_writer_self_roundtrip() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repacked repo path"),
    );
    let idx_path = find_single_pack_idx(&repo);
    let src_pack_path = idx_path.with_extension("pack");
    let source_objects = pack::read_all(&idx_path, &src_pack_path);
    eprintln!("source objects: {}", source_objects.len());

    let write_objects: Vec<pack::writer::WriteObject> = source_objects
        .iter()
        .map(|o| pack::writer::WriteObject {
            kind: match o.kind {
                "commit" => pack::pack::OBJ_COMMIT,
                "tree" => pack::pack::OBJ_TREE,
                "blob" => pack::pack::OBJ_BLOB,
                "tag" => pack::pack::OBJ_TAG,
                other => panic!("unexpected type {}", other),
            },
            content: o.content.clone(),
        })
        .collect();

    let written = pack::writer::write_pack(&write_objects);
    eprintln!("written pack: {} bytes", written.pack_bytes.len());

    // Walk the pack SEQUENTIALLY from the header (not via idx offsets)
    // using our own decoder, mirroring exactly what index-pack does
    // when it streams through a pack it has never seen before.
    let header = pack::pack::parse_header(&written.pack_bytes);
    eprintln!(
        "header: version={} count={}",
        header.version, header.object_count
    );
    assert_eq!(header.object_count as usize, write_objects.len());

    let mut offset = 12u64;
    let mut count = 0usize;
    for (i, expected) in write_objects.iter().enumerate() {
        let raw = pack::pack::read_raw_entry(&written.pack_bytes, offset);
        assert_eq!(
            raw.kind, expected.kind,
            "entry {} at offset {}: kind mismatch",
            i, offset
        );
        assert_eq!(
            raw.content,
            expected.content,
            "entry {} at offset {}: content mismatch (len {} vs {})",
            i,
            offset,
            raw.content.len(),
            expected.content.len()
        );
        // Advance offset by re-deriving how many bytes this entry
        // occupied: header bytes + compressed body bytes. We don't
        // track compressed length directly, so recompute it the same
        // way read_raw_entry does by finding where the NEXT valid
        // header would start - simplest: re-zlib-compress and use
        // that length (writer and reader must agree on this).
        let recompressed_len = {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&expected.content).unwrap();
            enc.finish().unwrap().len()
        };
        let header_len = {
            // mirror encode_entry_header's byte count for this (kind, size)
            let mut rest = (expected.content.len() as u64) >> 4;
            let mut n = 1usize;
            while rest > 0 {
                n += 1;
                rest >>= 7;
            }
            n
        };
        offset += header_len as u64 + recompressed_len as u64;
        count += 1;
    }
    eprintln!(
        "decoded {} entries sequentially, final offset {} (pack len {})",
        count,
        offset,
        written.pack_bytes.len()
    );
    assert_eq!(
        offset + 20,
        written.pack_bytes.len() as u64,
        "final offset + trailer should equal pack length"
    );
}

/// M4 delta creation: write `repo`'s object set through
/// write_pack_with_deltas (OFS_DELTA emission on top of M3's writer),
/// confirm real git still accepts the result and the object graph
/// matches what was intended (same oracle checks as M3, since M4 must
/// not regress M3's correctness bar), THEN separately check pack size
/// against git's own `pack-objects` output on the identical object
/// set. Per the explicit M4 scope guard: size parity within 2x is the
/// bar, not matching git's heuristics - if the ratio exceeds 2x this
/// logs a finding and does NOT try to iteratively tune window/depth to
/// close the gap.
fn assert_m4_write_path_with_deltas(repo: &std::path::Path, pack_name: &str, label: &str) {
    let idx_path = find_single_pack_idx(repo);
    let src_pack_path = idx_path.with_extension("pack");
    let source_objects = pack::read_all(&idx_path, &src_pack_path);
    assert!(
        !source_objects.is_empty(),
        "[{}] source fixture has no objects",
        label
    );

    let write_objects: Vec<pack::writer::WriteObject> = source_objects
        .iter()
        .map(|o| pack::writer::WriteObject {
            kind: match o.kind {
                "commit" => pack::pack::OBJ_COMMIT,
                "tree" => pack::pack::OBJ_TREE,
                "blob" => pack::pack::OBJ_BLOB,
                "tag" => pack::pack::OBJ_TAG,
                other => panic!("[{}] unexpected resolved type {}", label, other),
            },
            content: o.content.clone(),
        })
        .collect();

    let written = pack::writer::write_pack_with_deltas(&write_objects);
    eprintln!(
        "[fixture: {}] wrote {} objects: {} full, {} delta ({:.1}% deltified), pack size {} bytes",
        label,
        write_objects.len(),
        written.full_object_count,
        written.delta_object_count,
        100.0 * written.delta_object_count as f64 / write_objects.len() as f64,
        written.pack_bytes.len(),
    );

    let out_pack_path = scratch_path(&format!("{}.pack", pack_name));
    let out_idx_path = scratch_path(&format!("{}.idx", pack_name));
    std::fs::write(&out_pack_path, &written.pack_bytes).expect("failed to write scratch pack");
    std::fs::write(&out_idx_path, &written.idx_bytes).expect("failed to write scratch idx");

    // Same correctness bar as M3: git accepts our pack, our own idx
    // agrees with it, oids/types match intent, resolved content
    // (including through our own delta chains) matches real git.
    let strict_result = index_pack_strict(&out_pack_path);
    assert!(
        strict_result.success,
        "[{}] git index-pack --strict rejected our delta-bearing pack:\nstdout: {}\nstderr: {}",
        label, strict_result.stdout, strict_result.stderr
    );

    let oracle = verify_pack(&out_idx_path);
    assert!(
        oracle.ok,
        "[{}] git verify-pack rejected our own idx+pack",
        label
    );
    assert_eq!(
        oracle.objects.len(),
        write_objects.len(),
        "[{}] git reports {} objects, we wrote {}",
        label,
        oracle.objects.len(),
        write_objects.len()
    );
    let oracle_delta_count = oracle.objects.iter().filter(|o| o.is_delta()).count();
    assert_eq!(
        oracle_delta_count, written.delta_object_count,
        "[{}] git's delta count disagrees with ours",
        label
    );

    let intended_oids: std::collections::HashSet<&str> =
        source_objects.iter().map(|o| o.oid.as_str()).collect();
    for oracle_obj in &oracle.objects {
        assert!(
            intended_oids.contains(oracle_obj.oid.as_str()),
            "[{}] git reports oid {} that we never intended to write",
            label,
            oracle_obj.oid
        );
    }

    // Resolve our own written pack through our own M1/M2 reader - our
    // delta creation and our delta resolution have to agree with each
    // other, not just with git.
    let resolved = pack::read_all(&out_idx_path, &out_pack_path);
    let resolved_by_oid: HashMap<&str, &pack::ReadObject> =
        resolved.iter().map(|o| (o.oid.as_str(), o)).collect();
    for src in &source_objects {
        let back = resolved_by_oid.get(src.oid.as_str()).unwrap_or_else(|| {
            panic!(
                "[{}] our own reader could not find {} in our own written pack",
                label, src.oid
            )
        });
        assert_eq!(
            &back.content, &src.content,
            "[{}] our own reader resolved {} to different content than we wrote",
            label, src.oid
        );
    }

    // Size-parity oracle: git's own pack-objects output on the exact
    // same object set, deltas and all, using whatever heuristics git
    // actually uses (which we deliberately did not try to reproduce).
    let all_oids: Vec<String> = source_objects.iter().map(|o| o.oid.clone()).collect();
    let git_pack_bytes = git_pack_objects_stdout(repo, &all_oids);
    let ratio = written.pack_bytes.len() as f64 / git_pack_bytes.len() as f64;
    eprintln!(
        "[fixture: {}] size parity: ours={} bytes, git's={} bytes, ratio={:.2}x",
        label,
        written.pack_bytes.len(),
        git_pack_bytes.len(),
        ratio
    );
    assert!(
        ratio <= 2.0,
        "[{}] our pack is {:.2}x git's size on the same object set - exceeds the 2x bar. \
         Per SPIKE.md M4 scope: logging this as a finding rather than tuning window/depth \
         further to chase parity.",
        label,
        ratio
    );

    std::fs::remove_file(&out_pack_path).ok();
    std::fs::remove_file(&out_idx_path).ok();
}

#[test]
fn m4_delta_creation_matches_oracle_small() {
    assert_m4_write_path_with_deltas(
        small_repo().path(),
        "m4-small",
        "small fixture (delta round-trip)",
    );
}

/// M4 against a real-world medium corpus. Not run by default. Point
/// RUSTGIT_FIXTURE at a repacked repo and run with
/// `cargo test --test differential -- --ignored`.
#[test]
#[ignore]
fn m4_delta_creation_matches_oracle_medium_corpus() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repacked repo path"),
    );
    assert_m4_write_path_with_deltas(&repo, "m4-medium", "medium corpus (delta round-trip)");
}

/// M5: thin packs, both directions.
///
/// PRODUCE: pick a real blob already in `repo` as an external base,
/// build a "new" object by mutating its content, and write a thin
/// pack containing ONLY the new object, REF_DELTA-encoded against the
/// base blob's oid - which is deliberately NOT included in the pack.
/// Oracle: `git index-pack --stdin --fix-thin` inside `repo` (which
/// already has the base object) must accept it and complete it into a
/// standalone pack. See NOTES.md for why this is `--stdin --fix-thin`
/// and not the brief's original `--fix-thin <pack>.pack` shorthand.
///
/// CONSUME: separately, resolve our own thin pack through our OWN
/// reader (pack::read_all_thin, which falls back to odb::
/// resolve_oid_in_repo for bases not present in the thin pack's own
/// idx) and confirm it reconstructs the intended content - this is
/// the actual "consume a thin pack" requirement, distinct from just
/// handing it to git and trusting --fix-thin's result.
fn assert_m5_thin_pack(repo: &std::path::Path, pack_name: &str, label: &str) {
    let idx_path = find_single_pack_idx(repo);
    let src_pack_path = idx_path.with_extension("pack");
    let source_objects = pack::read_all(&idx_path, &src_pack_path);

    let base = source_objects
        .iter()
        .find(|o| o.kind == "blob" && o.content.len() >= 64)
        .unwrap_or_else(|| {
            panic!(
                "[{}] no blob >=64 bytes found to use as a thin-pack base",
                label
            )
        });

    let mut new_content = base.content.clone();
    new_content
        .extend_from_slice(b"\n-- M5 thin-pack test addition, not part of the original blob --\n");
    let new_oid = pack::pack::compute_oid(pack::pack::OBJ_BLOB, &new_content);
    assert_ne!(
        new_oid, base.oid,
        "[{}] mutated content accidentally collided with the base oid",
        label
    );

    let mut external_bases = HashMap::new();
    external_bases.insert(base.oid.clone(), base.content.clone());

    let write_objects = vec![pack::writer::WriteObject {
        kind: pack::pack::OBJ_BLOB,
        content: new_content.clone(),
    }];
    let thin = pack::writer::write_thin_pack(&write_objects, &external_bases);
    assert_eq!(
        thin.delta_object_count, 1,
        "[{}] expected the new object to be written as a ref-delta against the external base",
        label
    );
    eprintln!(
        "[fixture: {}] thin pack: {} bytes, base oid {} (external, not included), new oid {}",
        label,
        thin.pack_bytes.len(),
        base.oid,
        new_oid
    );

    // CONSUME first, before handing anything to git: our own reader,
    // falling back to the base repo's object store for the ref-delta
    // base that isn't in this pack's own idx.
    let thin_pack_path = scratch_path(&format!("{}.pack", pack_name));
    let thin_idx_path = scratch_path(&format!("{}.idx", pack_name));
    std::fs::write(&thin_pack_path, &thin.pack_bytes).expect("failed to write thin pack");
    std::fs::write(&thin_idx_path, &thin.idx_bytes).expect("failed to write thin idx");

    let resolved = pack::read_all_thin(&thin_idx_path, &thin_pack_path, repo);
    assert_eq!(
        resolved.len(),
        1,
        "[{}] expected exactly one object in the thin pack",
        label
    );
    assert_eq!(
        resolved[0].content, new_content,
        "[{}] our own thin-pack reader did not reconstruct the intended content",
        label
    );
    assert_eq!(
        resolved[0].oid, new_oid,
        "[{}] our own thin-pack reader computed the wrong oid",
        label
    );
    eprintln!(
        "[fixture: {}] CONSUME: our own reader resolved the thin pack correctly",
        label
    );

    // PRODUCE oracle: git must accept and complete this thin pack.
    let pack_dir_before: std::collections::HashSet<PathBuf> =
        std::fs::read_dir(repo.join(".git/objects/pack"))
            .expect("failed to read pack dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();

    let fix_thin_result = index_pack_stdin_fix_thin(repo, &thin.pack_bytes);
    assert!(
        fix_thin_result.success,
        "[{}] git index-pack --stdin --fix-thin rejected our thin pack:\nstdout: {}\nstderr: {}",
        label, fix_thin_result.stdout, fix_thin_result.stderr
    );

    let pack_dir_after: Vec<PathBuf> = std::fs::read_dir(repo.join(".git/objects/pack"))
        .expect("failed to read pack dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    let new_files: Vec<&PathBuf> = pack_dir_after
        .iter()
        .filter(|p| !pack_dir_before.contains(*p))
        .collect();
    assert!(
        !new_files.is_empty(),
        "[{}] git index-pack --stdin --fix-thin succeeded but wrote no new files into objects/pack/",
        label
    );
    eprintln!(
        "[fixture: {}] PRODUCE: git index-pack --stdin --fix-thin accepted and wrote {:?}",
        label,
        new_files
            .iter()
            .map(|p| p.file_name().unwrap())
            .collect::<Vec<_>>()
    );

    // Now the base repo should be able to serve the new object via
    // ordinary cat-file, proving --fix-thin actually completed the
    // pack into a standalone, correct one.
    let via_git = cat_file_batch_content(repo, &[new_oid.clone()]);
    assert_eq!(
        &via_git[&new_oid], &new_content,
        "[{}] after --fix-thin, git cat-file did not return the intended content for the new object",
        label
    );

    // Cleanup: remove the files --fix-thin wrote so repeated runs of
    // this test (or other tests sharing `repo`) start from a clean
    // pack directory.
    for f in new_files {
        std::fs::remove_file(f).ok();
    }
    std::fs::remove_file(&thin_pack_path).ok();
    std::fs::remove_file(&thin_idx_path).ok();
}

#[test]
fn m5_thin_pack_produce_and_consume_small() {
    let repo = make_scratch_base_repo("m5-small-base-repo");
    assert_m5_thin_pack(&repo, "m5-small", "scratch repo (thin pack)");
    std::fs::remove_dir_all(&repo).ok();
}

/// M5 against a real-world medium corpus. Not run by default. Point
/// RUSTGIT_FIXTURE at a repacked repo and run with
/// `cargo test --test differential -- --ignored`.
#[test]
#[ignore]
fn m5_thin_pack_produce_and_consume_medium_corpus() {
    let repo = PathBuf::from(
        std::env::var("RUSTGIT_FIXTURE").expect("set RUSTGIT_FIXTURE to a repacked repo path"),
    );
    assert_m5_thin_pack(&repo, "m5-medium", "medium corpus (thin pack)");
}
