//! Connectivity closure (ADR-0008 step 4, the check that must never be
//! skipped). For each new ref tip, walk the transitive object graph and
//! prove every referenced object resolves within (quarantined objects
//! UNION main store). A gitlink (tree entry mode 160000) references a
//! commit in another repository and is NOT expected to resolve here.
//!
//! docs/adr/ADR-0008-two-quarantines.md, step 2c: "for every ref the
//! push updates to a new tip, the transitive graph reachable from that
//! tip (commits -> trees+parents, trees -> entries, tags -> target) must
//! resolve entirely within the quarantined objects PLUS the objects
//! already in the main store. A tip whose history is not fully present
//! is rejected. This is never skipped." Graph edges and the gitlink skip
//! reuse the exact same citations already established by G2's
//! server/walk.rs (gitdatamodel.adoc for commit/tree/tag edges,
//! gitsubmodules.adoc for gitlink semantics) - this module is the same
//! walk, over a different "resolves" predicate (quarantine-or-store
//! instead of store-only).

use super::ReceiveError;
use crate::object::{commit, tag, tree, Kind};
use std::collections::{HashMap, VecDeque};

/// Verify an in-memory staged object map, as used by stack uploads.
#[allow(clippy::type_complexity, reason = "matches the object store")]
pub fn verify_closure(
    tips: &[String],
    quarantined: &HashMap<String, (Kind, Vec<u8>)>,
    store_has: &dyn Fn(&str) -> Option<(Kind, Vec<u8>)>,
) -> Result<(), ReceiveError> {
    walk(tips.iter().map(|tip| (tip.as_str(), None)), |oid| {
        Ok(quarantined.get(oid).cloned().or_else(|| store_has(oid)))
    })
}

/// Walk each tip through a lookup that checks quarantine before storage.
pub(super) fn walk<'a>(
    tips: impl IntoIterator<Item = (&'a str, Option<Kind>)>,
    lookup: impl Fn(&str) -> Result<Option<(Kind, Vec<u8>)>, ReceiveError>,
) -> Result<(), ReceiveError> {
    let mut visited = HashMap::new();

    for (tip, expected) in tips {
        let mut queue = VecDeque::from([(tip.to_owned(), expected)]);

        while let Some((oid, expected)) = queue.pop_front() {
            if let Some(&kind) = visited.get(&oid) {
                require_kind(&oid, expected, kind)?;
                continue;
            }

            let Some((kind, content)) = lookup(&oid)? else {
                return Err(ReceiveError::NotConnected {
                    tip: tip.to_owned(),
                    missing: oid,
                });
            };
            require_kind(&oid, expected, kind)?;
            visited.insert(oid, kind);

            match kind {
                Kind::Commit => {
                    let refs = commit::refs(&content).map_err(|e| ReceiveError::Malformed {
                        what: "commit",
                        detail: e.to_string(),
                    })?;
                    queue.push_back((refs.tree, Some(Kind::Tree)));
                    for parent in refs.parents {
                        queue.push_back((parent, Some(Kind::Commit)));
                    }
                }
                Kind::Tree => {
                    let entries = tree::entries(&content).map_err(|e| ReceiveError::Malformed {
                        what: "tree",
                        detail: e.to_string(),
                    })?;
                    for entry in entries {
                        // Gitlink (submodule): the oid names a commit in
                        // a DIFFERENT repository - never expected to
                        // resolve here (see module doc comment).
                        let mut mode = entry.mode.as_slice();
                        while let Some(rest) = mode.strip_prefix(b"0") {
                            mode = rest;
                        }
                        if mode == b"160000" {
                            continue;
                        }
                        // Mode 120000 (symlink) entries are ordinary
                        // blobs on disk and are walked like any other
                        // entry - no special case needed below.
                        let kind = if mode == b"40000" {
                            Kind::Tree
                        } else {
                            Kind::Blob
                        };
                        queue.push_back((entry.oid, Some(kind)));
                    }
                }
                Kind::Tag => {
                    let refs = tag::refs(&content).map_err(|e| ReceiveError::Malformed {
                        what: "tag",
                        detail: e.to_string(),
                    })?;
                    queue.push_back((refs.object, Some(refs.kind)));
                }
                Kind::Blob => {} // leaf: no further references
            }
        }
    }

    Ok(())
}

fn require_kind(oid: &str, expected: Option<Kind>, actual: Kind) -> Result<(), ReceiveError> {
    if let Some(kind) = expected.filter(|kind| *kind != actual) {
        return Err(ReceiveError::Malformed {
            what: "object graph",
            detail: format!("{oid} has type {}, expected {}", actual.name(), kind.name()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::tree::TreeEntry;

    fn blob(content: &[u8]) -> (Kind, Vec<u8>) {
        (Kind::Blob, content.to_vec())
    }

    fn commit_bytes(tree_oid: &str, parents: &[&str]) -> Vec<u8> {
        let mut s = format!("tree {tree_oid}\n");
        for p in parents {
            s.push_str(&format!("parent {p}\n"));
        }
        s.push_str("author a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n");
        s.into_bytes()
    }

    fn tree_bytes(entries: &[(&[u8], &[u8], &str)]) -> Vec<u8> {
        let entries: Vec<TreeEntry> = entries
            .iter()
            .map(|(mode, name, oid)| TreeEntry {
                mode: mode.to_vec(),
                name: name.to_vec(),
                oid: oid.to_string(),
            })
            .collect();
        tree::serialize(&entries)
    }

    const BLOB_OID: &str = "1111111111111111111111111111111111111111";
    const TREE_OID: &str = "2222222222222222222222222222222222222222";
    const COMMIT_OID: &str = "3333333333333333333333333333333333333333";
    const PARENT_OID: &str = "4444444444444444444444444444444444444444";
    const PARENT_TREE_OID: &str = "5555555555555555555555555555555555555555";
    const MISSING_OID: &str = "6666666666666666666666666666666666666666";
    const GITLINK_OID: &str = "7777777777777777777777777777777777777777";

    #[test]
    fn a_fully_present_tip_in_the_quarantine_connects() {
        let mut q = HashMap::new();
        q.insert(BLOB_OID.to_string(), blob(b"hi\n"));
        q.insert(
            TREE_OID.to_string(),
            (Kind::Tree, tree_bytes(&[(b"100644", b"a.txt", BLOB_OID)])),
        );
        q.insert(
            COMMIT_OID.to_string(),
            (Kind::Commit, commit_bytes(TREE_OID, &[])),
        );

        let store_has = |_: &str| None;
        assert!(verify_closure(&[COMMIT_OID.to_string()], &q, &store_has).is_ok());
    }

    #[test]
    fn a_parent_resolved_only_in_the_main_store_still_connects() {
        let mut q = HashMap::new();
        q.insert(BLOB_OID.to_string(), blob(b"hi\n"));
        q.insert(
            TREE_OID.to_string(),
            (Kind::Tree, tree_bytes(&[(b"100644", b"a.txt", BLOB_OID)])),
        );
        q.insert(
            COMMIT_OID.to_string(),
            (Kind::Commit, commit_bytes(TREE_OID, &[PARENT_OID])),
        );

        // The parent commit and everything under it live only in the
        // (simulated) main store, never in the quarantine.
        let store = {
            let mut m: HashMap<String, (Kind, Vec<u8>)> = HashMap::new();
            m.insert(
                PARENT_OID.to_string(),
                (Kind::Commit, commit_bytes(PARENT_TREE_OID, &[])),
            );
            m.insert(PARENT_TREE_OID.to_string(), (Kind::Tree, tree_bytes(&[])));
            m
        };
        let store_has = |oid: &str| store.get(oid).cloned();

        assert!(verify_closure(&[COMMIT_OID.to_string()], &q, &store_has).is_ok());
    }

    #[test]
    fn a_missing_blob_is_reported_as_not_connected() {
        let mut q = HashMap::new();
        q.insert(
            TREE_OID.to_string(),
            (
                Kind::Tree,
                tree_bytes(&[(b"100644", b"a.txt", MISSING_OID)]),
            ),
        );
        q.insert(
            COMMIT_OID.to_string(),
            (Kind::Commit, commit_bytes(TREE_OID, &[])),
        );

        let store_has = |_: &str| None;
        let result = verify_closure(&[COMMIT_OID.to_string()], &q, &store_has);
        match result {
            Err(ReceiveError::NotConnected { tip, missing }) => {
                assert_eq!(tip, COMMIT_OID);
                assert_eq!(missing, MISSING_OID);
            }
            other => panic!("expected NotConnected, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_parent_commit_is_reported_as_not_connected() {
        let mut q = HashMap::new();
        q.insert(TREE_OID.to_string(), (Kind::Tree, tree_bytes(&[])));
        q.insert(
            COMMIT_OID.to_string(),
            (Kind::Commit, commit_bytes(TREE_OID, &[MISSING_OID])),
        );

        let store_has = |_: &str| None;
        let result = verify_closure(&[COMMIT_OID.to_string()], &q, &store_has);
        assert!(matches!(result, Err(ReceiveError::NotConnected { .. })));
    }

    #[test]
    fn gitlink_entries_are_never_required_to_resolve() {
        let mut q = HashMap::new();
        q.insert(
            TREE_OID.to_string(),
            (
                Kind::Tree,
                tree_bytes(&[(b"160000", b"submodule", GITLINK_OID)]),
            ),
        );
        q.insert(
            COMMIT_OID.to_string(),
            (Kind::Commit, commit_bytes(TREE_OID, &[])),
        );

        // GITLINK_OID resolves nowhere - deliberately not inserted into
        // either the quarantine or the store - and must NOT trip
        // NotConnected.
        let store_has = |_: &str| None;
        assert!(verify_closure(&[COMMIT_OID.to_string()], &q, &store_has).is_ok());
    }

    #[test]
    fn an_annotated_tag_tip_walks_through_to_its_target() {
        let mut q = HashMap::new();
        q.insert(TREE_OID.to_string(), (Kind::Tree, tree_bytes(&[])));
        q.insert(
            COMMIT_OID.to_string(),
            (Kind::Commit, commit_bytes(TREE_OID, &[])),
        );
        let tag_content =
            format!("object {COMMIT_OID}\ntype commit\ntag v1\ntagger t <t@x> 0 +0000\n\nmsg\n");
        let tag_oid = "8888888888888888888888888888888888888888".to_string();
        q.insert(tag_oid.clone(), (Kind::Tag, tag_content.into_bytes()));

        let store_has = |_: &str| None;
        assert!(verify_closure(&[tag_oid], &q, &store_has).is_ok());
    }

    #[test]
    fn a_malformed_object_along_the_walk_is_reported_not_silently_skipped() {
        let mut q = HashMap::new();
        q.insert(
            COMMIT_OID.to_string(),
            (Kind::Commit, b"not a well-formed commit body".to_vec()),
        );

        let store_has = |_: &str| None;
        let result = verify_closure(&[COMMIT_OID.to_string()], &q, &store_has);
        assert!(matches!(result, Err(ReceiveError::Malformed { .. })));
    }

    #[test]
    fn rejects_incompatible_object_type_even_after_an_untyped_lookup() {
        let tips = [(BLOB_OID, None), (BLOB_OID, Some(Kind::Commit))];
        assert!(matches!(
            walk(tips, |_| Ok(Some(blob(b"ordinary content")))),
            Err(ReceiveError::Malformed {
                what: "object graph",
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_commit_whose_tree_is_a_blob() {
        let objects = HashMap::from([
            (
                COMMIT_OID.to_owned(),
                (Kind::Commit, commit_bytes(BLOB_OID, &[])),
            ),
            (BLOB_OID.to_owned(), blob(b"ordinary content")),
        ]);
        assert!(matches!(
            verify_closure(&[COMMIT_OID.to_owned()], &objects, &|_| None),
            Err(ReceiveError::Malformed {
                what: "object graph",
                ..
            })
        ));
    }

    #[test]
    fn empty_tips_list_trivially_connects() {
        let q = HashMap::new();
        let store_has = |_: &str| None;
        assert!(verify_closure(&[], &q, &store_has).is_ok());
    }
}
