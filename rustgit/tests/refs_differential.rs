// R1 differential test suite (spike 03): single-writer transaction
// semantics vs real `git update-ref --stdin`.

#[path = "differential/refs_harness.rs"]
mod refs_harness;

use refs_harness::*;

const RUNS_FOR_REPRODUCIBILITY: usize = 20;

/// Run `scenario` `RUNS_FOR_REPRODUCIBILITY` times, asserting every
/// run agrees. R1 is deterministic single-threaded code, so this
/// mainly demonstrates stability rather than catching scheduler-
/// dependent flakiness (that's R2/R3's job) - but SPIKE-03.md states
/// reproducibility as part of the bar for every milestone, not just
/// the concurrent ones, so this loop exists to satisfy that literally
/// and to give a real recorded run count for NOTES-03.md.
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

/// Core R1 assertion: build two identical scratch repos, run `script`
/// through rustgit on one and real git on the other, assert identical
/// accept/reject decisions and (if accepted) identical resulting ref
/// state, and validate rustgit's resulting repo state either way.
fn assert_transaction_matches_oracle(scenario: &str, initial_refs: &[(&str, &str)], script: &str) {
    let repo_ours = make_scratch_repo(&format!("{}-ours", scenario), initial_refs);
    let repo_oracle = make_scratch_repo(&format!("{}-oracle", scenario), initial_refs);

    let ours = run_ref_writer(&repo_ours, script);
    let oracle = run_real_update_ref(&repo_oracle, script);

    eprintln!(
        "[{}] ours: success={} stdout={:?} stderr={:?}",
        scenario,
        ours.success,
        ours.stdout.trim(),
        ours.stderr.trim()
    );
    eprintln!(
        "[{}] oracle: success={} stdout={:?} stderr={:?}",
        scenario,
        oracle.success,
        oracle.stdout.trim(),
        oracle.stderr.trim()
    );

    assert_eq!(
        ours.success, oracle.success,
        "[{}] accept/reject decision disagrees with oracle (ours={}, oracle={})",
        scenario, ours.success, oracle.success
    );

    if ours.success {
        let ours_state = dump_ref_state(&repo_ours);
        let oracle_state = dump_ref_state(&repo_oracle);
        assert_eq!(
            ours_state, oracle_state,
            "[{}] resulting ref state disagrees with oracle",
            scenario
        );
    }

    if let Err(e) = validate_state(&repo_ours) {
        panic!(
            "[{}] state validation failed after our transaction: {}",
            scenario, e
        );
    }

    std::fs::remove_dir_all(&repo_ours).ok();
    std::fs::remove_dir_all(&repo_oracle).ok();
}

/// Guards against SEED_OID silently drifting from what this
/// checkout's git actually produces for the fixed-timestamp seed
/// commit (see make_scratch_repo's doc comment).
#[test]
fn r1_seed_oid_constant_matches_real_git() {
    let repo = make_scratch_repo("seed-oid-check", &[]);
    seed_commit_oid(&repo); // asserts internally
    std::fs::remove_dir_all(&repo).ok();
}

#[test]
fn r1_update_existing_ref_with_correct_old_oid() {
    assert_reproducible(|| {
        let initial = [("refs/heads/main", SEED_OID)];
        let script = format!("update refs/heads/main {} {}\n", SEED_OID, SEED_OID);
        assert_transaction_matches_oracle("r1_update_existing_correct_old", &initial, &script);
    });
}

#[test]
fn r1_update_rejects_stale_old_oid() {
    assert_reproducible(|| {
        let bogus_old = "1111111111111111111111111111111111111111";
        let initial = [("refs/heads/main", SEED_OID)];
        let script = format!("update refs/heads/main {} {}\n", SEED_OID, bogus_old);
        assert_transaction_matches_oracle("r1_update_stale_old_oid", &initial, &script);
    });
}

#[test]
fn r1_create_new_ref_succeeds() {
    assert_reproducible(|| {
        let script = format!("create refs/heads/newbranch {}\n", SEED_OID);
        assert_transaction_matches_oracle("r1_create_new_ref", &[], &script);
    });
}

#[test]
fn r1_create_rejects_existing_ref() {
    assert_reproducible(|| {
        let initial = [("refs/heads/main", SEED_OID)];
        let script = format!("create refs/heads/main {}\n", SEED_OID);
        assert_transaction_matches_oracle("r1_create_rejects_existing", &initial, &script);
    });
}

#[test]
fn r1_delete_existing_ref_succeeds() {
    assert_reproducible(|| {
        let initial = [("refs/heads/main", SEED_OID)];
        let script = format!("delete refs/heads/main {}\n", SEED_OID);
        assert_transaction_matches_oracle("r1_delete_existing", &initial, &script);
    });
}

/// Real finding (see NOTES-03.md): `delete <ref>` with NO old-oid
/// precondition on an ALREADY-ABSENT ref is accepted as a no-op by
/// real git, not rejected - a natural first reading of
/// git-update-ref.adoc's "after verifying that it exists with
/// <old-oid>, if given" gets this wrong (easy to read "if given" as
/// scoping only the old-oid value, not the whole verification step).
/// Confirmed directly against real git (both --stdin and -d forms)
/// before trusting it, not just inferred from one differential run.
#[test]
fn r1_delete_nonexistent_ref_without_precondition_is_noop_success() {
    assert_reproducible(|| {
        let script = "delete refs/heads/does-not-exist\n";
        assert_transaction_matches_oracle("r1_delete_nonexistent_noop", &[], script);
    });
}

/// Companion case: delete with an EXPLICIT old-oid precondition on an
/// absent ref must still be rejected (the "if given" clause DOES
/// apply once an old-oid is actually given) - distinguishes this from
/// the no-op case above rather than accidentally making all deletes
/// of absent refs succeed.
#[test]
fn r1_delete_nonexistent_ref_with_precondition_rejected() {
    assert_reproducible(|| {
        let bogus_old = "4444444444444444444444444444444444444444";
        let script = format!("delete refs/heads/does-not-exist {}\n", bogus_old);
        assert_transaction_matches_oracle("r1_delete_nonexistent_with_precondition", &[], &script);
    });
}

#[test]
fn r1_delete_rejects_wrong_old_oid() {
    assert_reproducible(|| {
        let bogus_old = "2222222222222222222222222222222222222222";
        let initial = [("refs/heads/main", SEED_OID)];
        let script = format!("delete refs/heads/main {}\n", bogus_old);
        assert_transaction_matches_oracle("r1_delete_wrong_old_oid", &initial, &script);
    });
}

#[test]
fn r1_verify_passes_when_value_matches() {
    assert_reproducible(|| {
        let initial = [("refs/heads/main", SEED_OID)];
        let script = format!("verify refs/heads/main {}\n", SEED_OID);
        assert_transaction_matches_oracle("r1_verify_matches", &initial, &script);
    });
}

#[test]
fn r1_verify_omitted_old_oid_requires_absence() {
    // Documented asymmetry (see transaction.rs's module doc comment):
    // verify with NO old-oid means "must not exist", unlike
    // update/delete where omitted means "no check". This test targets
    // exactly that: main exists, so `verify refs/heads/main` (no
    // old-oid) must be REJECTED per the doc's literal reading -
    // confirmed against the real oracle, not just our own reading.
    assert_reproducible(|| {
        let initial = [("refs/heads/main", SEED_OID)];
        let script = "verify refs/heads/main\n";
        assert_transaction_matches_oracle("r1_verify_omitted_old_oid", &initial, script);
    });
}

#[test]
fn r1_multi_op_transaction_one_failure_rejects_all() {
    // The rejection case SPIKE-03.md calls out as mattering most: a
    // transaction with two operations where the SECOND fails must
    // reject the WHOLE transaction, including the first (valid) op -
    // the classic partial-commit bug this spike exists to hunt.
    // op2 here must be a GENUINE failure - `delete <ref>` with no
    // precondition on an absent ref is a no-op success (see the
    // dedicated finding above), so this uses a delete WITH a
    // precondition against an absent ref, which real git does reject.
    assert_reproducible(|| {
        let initial = [("refs/heads/main", SEED_OID)];
        let bogus_old = "5555555555555555555555555555555555555555";
        let script = format!(
            "create refs/heads/newbranch {}\ndelete refs/heads/does-not-exist {}\n",
            SEED_OID, bogus_old
        );
        assert_transaction_matches_oracle("r1_multi_op_partial_failure", &initial, &script);
    });
}

#[test]
fn r1_multi_op_transaction_all_succeed() {
    assert_reproducible(|| {
        let initial = [("refs/heads/main", SEED_OID)];
        let script = format!(
            "create refs/heads/branch-a {}\ncreate refs/heads/branch-b {}\n",
            SEED_OID, SEED_OID
        );
        assert_transaction_matches_oracle("r1_multi_op_all_succeed", &initial, &script);
    });
}

#[test]
fn r1_repeated_ref_in_transaction_rejected() {
    assert_reproducible(|| {
        let script = format!(
            "create refs/heads/dup {}\ndelete refs/heads/dup\n",
            SEED_OID
        );
        assert_transaction_matches_oracle("r1_repeated_ref", &[], &script);
    });
}

/// Real finding from the first R1 run: our transaction accepted a
/// create/update pointing at an oid that is syntactically valid
/// (40 hex chars) but does NOT correspond to any object actually in
/// the repository - real git rejects this ("trying to write ref ...
/// with nonexistent object ..."). Dedicated regression test, separate
/// from the harness-bug investigation that first surfaced it (see
/// NOTES-03.md).
#[test]
fn r1_create_rejects_nonexistent_object() {
    assert_reproducible(|| {
        let fake_oid = "3333333333333333333333333333333333333333";
        let script = format!("create refs/heads/newbranch {}\n", fake_oid);
        assert_transaction_matches_oracle("r1_create_nonexistent_object", &[], &script);
    });
}
