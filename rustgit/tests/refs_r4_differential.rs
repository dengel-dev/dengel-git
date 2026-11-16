// R4 differential test suite (spike 03): packed-refs interaction and
// stale locks. Focused subset (see NOTES-03.md for what's covered vs
// explicitly logged as untested, per SPIKE-03.md's own "implement
// only as far as a milestone requires... log as untested rather than
// assume fine" allowance).

#[path = "differential/refs_harness.rs"]
mod refs_harness;

use refs_harness::*;

const RUNS_FOR_REPRODUCIBILITY: usize = 20;

fn assert_reproducible<F: Fn()>(scenario: F) {
    for i in 0..RUNS_FOR_REPRODUCIBILITY {
        scenario();
        if i == RUNS_FOR_REPRODUCIBILITY - 1 {
            eprintln!(
                "  reproducible across {} consecutive runs",
                RUNS_FOR_REPRODUCIBILITY
            );
        }
    }
}

/// A ref existing both loose AND packed (with different values) - the
/// loose value must win when reading, per git-pack-refs.adoc's own
/// stated precedence ("When a ref is missing from the traditional
/// refs directory hierarchy, it is looked up in this file" - implies
/// loose is checked FIRST). Confirms our resolve_current does the
/// same, by constructing exactly this split-state fixture and reading
/// with both real git and our writer (via a verify op with the loose
/// value as the expected old-oid - passes only if loose wins).
#[test]
fn r4_loose_shadows_packed_when_both_present() {
    assert_reproducible(|| {
        let repo = make_scratch_repo("r4-precedence", &[]);
        ensure_second_object(&repo);

        // Seed packed-refs with the OLD value, then loose with the NEW
        // value - a real "ref updated after packing" split state.
        let packed_refs_content = format!(
            "# pack-refs with: peeled fully-peeled sorted \n{} refs/heads/main\n",
            SEED_OID
        );
        std::fs::write(repo.join(".git/packed-refs"), packed_refs_content).unwrap();
        std::fs::write(
            repo.join(".git/refs/heads/main"),
            format!("{}\n", SEED_OID_2),
        )
        .unwrap();

        // Real git: what does it report as main's value?
        let real_state = dump_ref_state(&repo);
        assert!(
            real_state.contains(SEED_OID_2),
            "[r4_precedence] real git did not resolve loose-shadows-packed as expected: {}",
            real_state
        );

        // Our reader (via a verify op - succeeds only if our resolved
        // current value equals SEED_OID_2, the loose value):
        let script = format!("verify refs/heads/main {}\n", SEED_OID_2);
        let result = run_ref_writer(&repo, &script);
        assert!(
            result.success,
            "[r4_precedence] our resolve_current did not prefer the loose value over packed: {:?}",
            result.stderr
        );

        std::fs::remove_dir_all(&repo).ok();
    });
}

/// Deleting a ref that exists ONLY in packed-refs (no loose file) must
/// still succeed and actually remove it from packed-refs - not silently
/// no-op because there was no loose file to delete.
#[test]
fn r4_delete_packed_only_ref_removes_from_packed_refs() {
    assert_reproducible(|| {
        let repo = make_scratch_repo("r4-delete-packed-only", &[]);
        let packed_refs_content = format!(
            "# pack-refs with: peeled fully-peeled sorted \n{} refs/heads/packed-only\n",
            SEED_OID
        );
        std::fs::write(repo.join(".git/packed-refs"), packed_refs_content).unwrap();

        // Confirm the fixture is set up as intended before testing anything.
        let before = dump_ref_state(&repo);
        assert!(
            before.contains("refs/heads/packed-only"),
            "fixture setup: ref should be visible before delete: {}",
            before
        );

        let script = format!("delete refs/heads/packed-only {}\n", SEED_OID);
        let result = run_ref_writer(&repo, &script);
        assert!(
            result.success,
            "[r4_delete_packed_only] delete of a packed-only ref failed: {:?}",
            result.stderr
        );

        let after = dump_ref_state(&repo);
        assert!(
            !after.contains("refs/heads/packed-only"),
            "[r4_delete_packed_only] ref still visible after delete (packed-refs not actually rewritten?): {}",
            after
        );

        // packed-refs must still be a file real git accepts.
        verify_ref_store(&repo).expect("stock Git accepts the rewritten ref store");

        std::fs::remove_dir_all(&repo).ok();
    });
}

/// Stale lock behaviour matches real git's (confirmed directly against
/// real git during harness-building - see NOTES-03.md): a pre-existing
/// `<ref>.lock` file causes OUR writer to refuse cleanly too, not hang
/// or silently overwrite it.
#[test]
fn r4_stale_lock_rejected_cleanly_matching_real_git() {
    assert_reproducible(|| {
        let repo = make_scratch_repo("r4-stale-lock", &[("refs/heads/main", SEED_OID)]);
        ensure_second_object(&repo);
        std::fs::write(repo.join(".git/refs/heads/main.lock"), b"").unwrap();

        let script = format!("update refs/heads/main {} {}\n", SEED_OID_2, SEED_OID);
        let result = run_ref_writer(&repo, &script);
        assert!(
            !result.success,
            "[r4_stale_lock] writer should refuse when a stale lock is present, but succeeded"
        );
        assert!(
            result.stderr.contains("File exists") || result.stderr.to_lowercase().contains("lock"),
            "[r4_stale_lock] rejection reason doesn't look lock-related: {:?}",
            result.stderr
        );

        // Ref must be untouched.
        let content = std::fs::read_to_string(repo.join(".git/refs/heads/main")).unwrap();
        assert_eq!(
            content.trim(),
            SEED_OID,
            "[r4_stale_lock] ref was modified despite the transaction being rejected"
        );

        // Recovery: after removing the stale lock (documented real-git
        // procedure), the identical transaction must now succeed.
        std::fs::remove_file(repo.join(".git/refs/heads/main.lock")).unwrap();
        let retry = run_ref_writer(&repo, &script);
        assert!(
            retry.success,
            "[r4_stale_lock] retry after removing the stale lock should succeed: {:?}",
            retry.stderr
        );

        std::fs::remove_dir_all(&repo).ok();
    });
}
