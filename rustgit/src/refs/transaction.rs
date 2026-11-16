//! Ref transaction: prepare (lock + verify), commit or abort.
//!
//! Operation semantics source: git-reference/Documentation/
//! git-update-ref.adoc's `--stdin` command list (update/create/delete/
//! verify with old-oid preconditions). Quoted directly where the text
//! matters:
//!   update:  "Set <ref> to <new-oid> after verifying <old-oid>, if
//!             given. Specify a zero <new-oid> to ensure the ref does
//!             not exist after the update and/or a zero <old-oid> to
//!             make sure the ref does not exist before the update."
//!   create:  "Create <ref> with <new-oid> after verifying that it
//!             does not exist. The given <new-oid> may not be zero."
//!   delete:  "Delete <ref> after verifying that it exists with
//!             <old-oid>, if given. If given, <old-oid> may not be
//!             zero."
//!   verify:  "Verify <ref> against <old-oid> but do not change it.
//!             If <old-oid> is zero or missing, the ref must not
//!             exist."
//! NOTE the verify/update asymmetry: for update and delete, an OMITTED
//! old-oid means "no precondition, skip the check". For verify, an
//! omitted old-oid is treated the SAME as an explicit zero - "the ref
//! must not exist." This is stated plainly in the doc but is easy to
//! implement wrong by assuming omitted always means "no check" - the
//! differential harness (assert against real `update-ref --stdin`)
//! is what actually confirms this, not just reading the sentence.
//!
//! "If all <ref>s can be locked with matching <old-oid>s
//! simultaneously, all modifications are performed. Otherwise, no
//! modifications are performed." - the all-or-nothing prepare-then-
//! commit structure below exists to satisfy exactly this sentence.

use std::collections::HashMap;
use std::path::Path;

use super::lock::{LockError, RefLock};
use super::loose::{self, LooseRefValue, ZERO_OID};
use super::packed;
use crate::pack::odb::resolve_oid_in_git_dir;

#[derive(Debug, Clone)]
pub enum RefOp {
    Update {
        refname: String,
        new: String,
        old: Option<String>,
    },
    Create {
        refname: String,
        new: String,
    },
    Delete {
        refname: String,
        old: Option<String>,
    },
    Verify {
        refname: String,
        old: Option<String>,
    },
}

impl RefOp {
    pub fn refname(&self) -> &str {
        match self {
            RefOp::Update { refname, .. }
            | RefOp::Create { refname, .. }
            | RefOp::Delete { refname, .. }
            | RefOp::Verify { refname, .. } => refname,
        }
    }
}

#[derive(Debug)]
pub enum TransactionError {
    /// A ref could not be locked (already locked by another writer).
    LockFailed {
        refname: String,
        source: LockError,
    },
    /// A precondition (old-oid, or implicit existence requirement)
    /// did not hold.
    PreconditionFailed {
        refname: String,
        reason: String,
    },
    /// Two operations in the same transaction target the same ref -
    /// doc: "Commands in any other format or a repeated <ref> produce
    /// an error."
    RepeatedRef {
        refname: String,
    },
    /// A create/update op specified an invalid new-oid (e.g. create
    /// with a zero oid - "may not be zero").
    InvalidOperation {
        refname: String,
        reason: String,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionError::LockFailed { refname, source } => {
                write!(f, "cannot lock ref '{}': {}", refname, source)
            }
            TransactionError::PreconditionFailed { refname, reason } => {
                write!(f, "precondition failed for ref '{}': {}", refname, reason)
            }
            TransactionError::RepeatedRef { refname } => {
                write!(
                    f,
                    "ref '{}' specified more than once in the same transaction",
                    refname
                )
            }
            TransactionError::InvalidOperation { refname, reason } => {
                write!(f, "invalid operation for ref '{}': {}", refname, reason)
            }
            TransactionError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}
impl std::error::Error for TransactionError {}
impl From<std::io::Error> for TransactionError {
    fn from(e: std::io::Error) -> Self {
        TransactionError::Io(e)
    }
}

/// Resolve a ref's current value: loose file first, then packed-refs
/// (loose shadows packed - a ref present in both is read from loose;
/// this is the documented precedence rationale for pack-refs' own
/// existence per git-pack-refs.adoc: "When a ref is missing from the
/// traditional $GIT_DIR/refs directory hierarchy, it is looked up in
/// this file").
fn resolve_current(git_dir: &Path, refname: &str) -> std::io::Result<Option<String>> {
    if let Some(value) = loose::read_loose_ref(git_dir, refname)? {
        return Ok(match value {
            LooseRefValue::Oid(oid) => Some(oid),
            LooseRefValue::Symref(_) => None, // R1 scope: symrefs not handled as update targets
        });
    }
    let packed = packed::read_packed_refs(git_dir)?;
    Ok(packed.entries.get(refname).map(|e| e.oid.clone()))
}

/// Execute a batch of operations as a single all-or-nothing
/// transaction against the loose+packed backend rooted at `git_dir`.
pub fn execute_transaction(git_dir: &Path, ops: &[RefOp]) -> Result<(), TransactionError> {
    // Reject repeated refs up front (doc: "a repeated <ref> produce an error").
    let mut seen = std::collections::HashSet::new();
    for op in ops {
        if !seen.insert(op.refname().to_string()) {
            return Err(TransactionError::RepeatedRef {
                refname: op.refname().to_string(),
            });
        }
    }

    // --- prepare: lock every ref, verify preconditions ---
    let mut locks: HashMap<String, RefLock> = HashMap::new();
    let prepare_result = (|| -> Result<(), TransactionError> {
        for op in ops {
            let refname = op.refname();
            let target_path = loose::ref_path(git_dir, refname);
            let lock =
                RefLock::acquire(&target_path).map_err(|e| TransactionError::LockFailed {
                    refname: refname.to_string(),
                    source: e,
                })?;

            let current = resolve_current(git_dir, refname)?;

            match op {
                RefOp::Update { old, new, .. } => {
                    check_update_precondition(refname, &current, old.as_deref())?;
                    if new == ZERO_OID {
                        return Err(TransactionError::InvalidOperation {
                            refname: refname.to_string(),
                            reason: "update to zero-oid should be expressed as delete (R1 scope: not auto-converted)".into(),
                        });
                    }
                    check_object_exists(git_dir, refname, new)?;
                }
                RefOp::Create { new, .. } => {
                    if new == ZERO_OID {
                        return Err(TransactionError::InvalidOperation {
                            refname: refname.to_string(),
                            reason: "create new-oid may not be zero".into(),
                        });
                    }
                    if current.is_some() {
                        return Err(TransactionError::PreconditionFailed {
                            refname: refname.to_string(),
                            reason: format!(
                                "create expects the ref not to exist, but it is {:?}",
                                current
                            ),
                        });
                    }
                    check_object_exists(git_dir, refname, new)?;
                }
                RefOp::Delete { old, .. } => {
                    if old.as_deref() == Some(ZERO_OID) {
                        return Err(TransactionError::InvalidOperation {
                            refname: refname.to_string(),
                            reason: "delete old-oid may not be zero".into(),
                        });
                    }
                    // Doc: "Delete <ref> after verifying that it
                    // exists with <old-oid>, if given." The "if
                    // given" governs the WHOLE verification clause,
                    // not just the old-oid value - confirmed against
                    // real git (see NOTES-03.md), not just this
                    // reading of the sentence: `delete <ref>` with NO
                    // old-oid on an ALREADY-ABSENT ref is accepted as
                    // a no-op, not rejected. Only when old is Some(_)
                    // is existence (and equality) actually checked.
                    if let Some(expected) = old {
                        match &current {
                            None => {
                                return Err(TransactionError::PreconditionFailed {
                                    refname: refname.to_string(),
                                    reason: "delete expects the ref to exist, but it does not"
                                        .into(),
                                })
                            }
                            Some(cur) if cur != expected => {
                                return Err(TransactionError::PreconditionFailed {
                                    refname: refname.to_string(),
                                    reason: format!("expected old oid {}, found {}", expected, cur),
                                })
                            }
                            _ => {}
                        }
                    }
                }
                RefOp::Verify { old, .. } => {
                    // NOTE the asymmetry documented above: omitted
                    // old-oid means "must not exist" for verify,
                    // unlike update/delete where it means "no check".
                    let expect_absent = matches!(old.as_deref(), None | Some(ZERO_OID));
                    if expect_absent {
                        if current.is_some() {
                            return Err(TransactionError::PreconditionFailed {
                                refname: refname.to_string(),
                                reason: "verify expects the ref not to exist, but it does".into(),
                            });
                        }
                    } else {
                        let expected = old.as_deref().unwrap();
                        if current.as_deref() != Some(expected) {
                            return Err(TransactionError::PreconditionFailed {
                                refname: refname.to_string(),
                                reason: format!(
                                    "expected old oid {}, found {:?}",
                                    expected, current
                                ),
                            });
                        }
                    }
                }
            }

            locks.insert(refname.to_string(), lock);
        }
        Ok(())
    })();

    if let Err(e) = prepare_result {
        for (_, lock) in locks {
            lock.abort();
        }
        return Err(e);
    }

    // --- commit: write every change, all locks already held ---
    for op in ops {
        let lock = locks
            .remove(op.refname())
            .expect("lock acquired in prepare phase");
        match op {
            RefOp::Update { new, .. } | RefOp::Create { new, .. } => {
                let mut lock = lock;
                lock.write_content(&loose::format_ref_content(&LooseRefValue::Oid(new.clone())))?;
                lock.commit()?;
            }
            RefOp::Delete { refname, .. } => {
                lock.commit_delete()?;
                remove_from_packed_refs_if_present(git_dir, refname)?;
            }
            RefOp::Verify { .. } => {
                lock.abort(); // no change to make, just release
            }
        }
    }

    Ok(())
}

/// Real git refuses to write a ref pointing at an object that does
/// not actually exist in the repository ("trying to write ref '...'
/// with nonexistent object ...") - caught by the R1 differential
/// harness on its FIRST run (a naive implementation happily wrote
/// syntactically-valid-but-nonexistent oids; real git rejected the
/// same script). See NOTES-03.md. Uses spike 01's object database
/// resolver (loose objects + packs) rather than reimplementing
/// object lookup.
fn check_object_exists(git_dir: &Path, refname: &str, oid: &str) -> Result<(), TransactionError> {
    if resolve_oid_in_git_dir(git_dir, oid).is_none() {
        return Err(TransactionError::InvalidOperation {
            refname: refname.to_string(),
            reason: format!(
                "trying to write ref '{}' with nonexistent object {}",
                refname, oid
            ),
        });
    }
    Ok(())
}

fn check_update_precondition(
    refname: &str,
    current: &Option<String>,
    old: Option<&str>,
) -> Result<(), TransactionError> {
    match old {
        None => Ok(()), // no precondition
        Some(expected) if expected == ZERO_OID => {
            if current.is_some() {
                Err(TransactionError::PreconditionFailed {
                    refname: refname.to_string(),
                    reason: "expected ref not to exist (old-oid zero), but it does".into(),
                })
            } else {
                Ok(())
            }
        }
        Some(expected) => {
            if current.as_deref() != Some(expected) {
                Err(TransactionError::PreconditionFailed {
                    refname: refname.to_string(),
                    reason: format!("expected old oid {}, found {:?}", expected, current),
                })
            } else {
                Ok(())
            }
        }
    }
}

/// After a loose delete, also remove the ref from packed-refs if it's
/// there (a ref can exist in both places; deleting must remove both,
/// or the "deleted" ref would resurface once the loose shadow is
/// gone.) R4 exercises this path directly (deleting a packed-only ref
/// goes through here too, since there's no loose lock target to
/// delete in that case - see the R4 test for how that's handled).
fn remove_from_packed_refs_if_present(git_dir: &Path, refname: &str) -> std::io::Result<()> {
    let mut packed = packed::read_packed_refs(git_dir)?;
    if packed.entries.remove(refname).is_some() {
        rewrite_packed_refs(git_dir, &packed)?;
    }
    Ok(())
}

/// Rewrite packed-refs via the same lock-write-rename discipline as a
/// single ref (lock file "packed-refs.lock", write, atomic rename) -
/// same durability property, applied to the whole file since
/// packed-refs has no per-entry granularity.
pub fn rewrite_packed_refs(git_dir: &Path, refs: &packed::PackedRefs) -> std::io::Result<()> {
    let target = git_dir.join("packed-refs");
    let mut lock = RefLock::acquire(&target).map_err(|e| std::io::Error::other(e.to_string()))?;
    lock.write_content(format_packed_refs_checked(refs).as_bytes())?;
    lock.commit()
}

fn format_packed_refs_checked(refs: &packed::PackedRefs) -> String {
    packed::format_packed_refs(refs)
}
