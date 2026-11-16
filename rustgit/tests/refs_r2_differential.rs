// R2 differential test suite (spike 03): concurrent writers.
//
// Deterministic interleaving via src/refs/checkpoint.rs's pause-point
// protocol (arm a wait-point BEFORE spawning the writer that will hit
// it, wait for its "reached this point" marker, orchestrate the race
// precisely, then release) - per SPIKE-03.md's harness requirement 1:
// "Random stress runs are a supplement, not the method."

#[path = "differential/refs_harness.rs"]
mod refs_harness;

use refs_harness::*;
use std::time::Duration;

const RUNS_FOR_REPRODUCIBILITY: usize = 20;
const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(5);

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

/// R2 scenario 1 (rustgit vs rustgit): two writers update the SAME ref
/// from the SAME old value, deterministically forced to race - writer
/// A is paused right after it acquires the lock (before it can verify/
/// commit), writer B is then run to completion while A still holds
/// the lock, and only then is A released. B MUST fail cleanly (lock
/// contention), A MUST succeed, and the final state must be exactly
/// what A wrote - never a torn value, never B's write silently lost
/// (there's nothing to lose here since B never got the lock at all,
/// but the assertion checks the observable outcome regardless of
/// mechanism).
#[test]
fn r2_same_ref_race_rustgit_vs_rustgit_exactly_one_wins() {
    assert_reproducible(|| {
        let repo = make_scratch_repo("r2-race", &[("refs/heads/main", SEED_OID)]);
        ensure_second_object(&repo);
        let checkpoint_dir = make_checkpoint_dir("r2-race");
        arm_wait(&checkpoint_dir, "after_lock");

        let script_a = format!("update refs/heads/main {} {}\n", SEED_OID_2, SEED_OID);
        let (child_a, script_path_a) = spawn_ref_writer_bg(&repo, &script_a, &checkpoint_dir, None);

        wait_for_marker(&checkpoint_dir, "after_lock", CHECKPOINT_TIMEOUT);
        // A now holds the lock on refs/heads/main and is blocked.

        let script_b = format!("update refs/heads/main {} {}\n", SEED_OID, SEED_OID);
        let result_b = run_ref_writer(&repo, &script_b);
        assert!(
            !result_b.success,
            "writer B should have failed (lock held by A), but succeeded"
        );
        assert!(
            result_b.stderr.contains("cannot lock")
                || result_b.stderr.contains("LockFailed")
                || result_b.stderr.contains("File exists"),
            "writer B's failure should be a lock-contention rejection, got: {:?}",
            result_b.stderr
        );

        release_checkpoint(&checkpoint_dir, "after_lock");
        let output_a = child_a
            .wait_with_output()
            .expect("writer A failed to run to completion");
        assert!(
            output_a.status.success(),
            "writer A should have succeeded (held the lock uncontested once B backed off): stderr={}",
            String::from_utf8_lossy(&output_a.stderr)
        );

        let state = dump_ref_state(&repo);
        assert!(
            state.contains(SEED_OID_2),
            "expected refs/heads/main to be A's value ({}) after A won, got state: {}",
            SEED_OID_2,
            state
        );

        if let Err(e) = validate_state(&repo) {
            panic!("state validation failed after the race: {}", e);
        }

        std::fs::remove_file(&script_path_a).ok();
        std::fs::remove_dir_all(&repo).ok();
        std::fs::remove_dir_all(&checkpoint_dir).ok();
    });
}

/// R2 scenario 2: writers updating DIFFERENT refs must both succeed -
/// neither should observe or be blocked by the other's lock, since
/// they touch disjoint refs (different lock files).
#[test]
fn r2_different_refs_both_succeed() {
    assert_reproducible(|| {
        let repo = make_scratch_repo("r2-different-refs", &[("refs/heads/main", SEED_OID)]);
        ensure_second_object(&repo);
        let checkpoint_dir = make_checkpoint_dir("r2-different-refs");
        arm_wait(&checkpoint_dir, "after_lock");

        let script_a = format!("create refs/heads/branch-a {}\n", SEED_OID);
        let (child_a, script_path_a) = spawn_ref_writer_bg(&repo, &script_a, &checkpoint_dir, None);
        wait_for_marker(&checkpoint_dir, "after_lock", CHECKPOINT_TIMEOUT);
        // A holds the lock on refs/heads/branch-a, but branch-b is untouched.

        let script_b = format!("create refs/heads/branch-b {}\n", SEED_OID_2);
        let result_b = run_ref_writer(&repo, &script_b);
        assert!(
            result_b.success,
            "writer B (different ref) should succeed even while A holds an unrelated lock: {:?}",
            result_b.stderr
        );

        release_checkpoint(&checkpoint_dir, "after_lock");
        let output_a = child_a.wait_with_output().unwrap();
        assert!(
            output_a.status.success(),
            "writer A should succeed: {}",
            String::from_utf8_lossy(&output_a.stderr)
        );

        let state = dump_ref_state(&repo);
        assert!(
            state.contains("refs/heads/branch-a"),
            "branch-a missing from final state: {}",
            state
        );
        assert!(
            state.contains("refs/heads/branch-b"),
            "branch-b missing from final state (B's update lost?): {}",
            state
        );

        if let Err(e) = validate_state(&repo) {
            panic!("state validation failed: {}", e);
        }

        std::fs::remove_file(&script_path_a).ok();
        std::fs::remove_dir_all(&repo).ok();
        std::fs::remove_dir_all(&checkpoint_dir).ok();
    });
}

/// R2 supplement (not the primary method - see module doc comment):
/// real OS-level concurrency, no checkpoint control, many iterations,
/// to catch anything the deterministic scenarios above might not
/// construct. Same assertion as the deterministic same-ref race:
/// exactly one writer's value survives, state stays valid.
#[test]
fn r2_same_ref_race_stress_real_concurrency() {
    for i in 0..RUNS_FOR_REPRODUCIBILITY {
        let repo = make_scratch_repo(
            &format!("r2-stress-{}", i),
            &[("refs/heads/main", SEED_OID)],
        );
        ensure_second_object(&repo);

        // Both writers must change the ref for a successful update to
        // invalidate the other writer's expected value.
        let script = format!("update refs/heads/main {} {}\n", SEED_OID_2, SEED_OID);
        let (child_a, script_path_a) = spawn_ref_writer_bg(
            &repo,
            &script,
            &make_checkpoint_dir(&format!("r2-stress-unused-{}", i)),
            None,
        );
        let (child_b, script_path_b) = spawn_ref_writer_bg(
            &repo,
            &script,
            &make_checkpoint_dir(&format!("r2-stress-unused-b-{}", i)),
            None,
        );

        let out_a = child_a.wait_with_output().unwrap();
        let out_b = child_b.wait_with_output().unwrap();

        let wins = [out_a.status.success(), out_b.status.success()]
            .iter()
            .filter(|&&s| s)
            .count();
        assert_eq!(
            wins,
            1,
            "run {}: expected exactly one writer to win, got {} (a={}, b={})",
            i,
            wins,
            out_a.status.success(),
            out_b.status.success()
        );

        let actual = std::fs::read_to_string(repo.join(".git/refs/heads/main")).unwrap();
        assert_eq!(actual.trim(), SEED_OID_2, "run {i}: winning ref value");
        if let Err(error) = validate_state(&repo) {
            panic!("run {i}: state validation failed: {error}");
        }

        std::fs::remove_file(&script_path_a).ok();
        std::fs::remove_file(&script_path_b).ok();
        std::fs::remove_dir_all(&repo).ok();
    }
    eprintln!(
        "  stress race: exactly-one-winner held across {} real-concurrency runs",
        RUNS_FOR_REPRODUCIBILITY
    );
}
