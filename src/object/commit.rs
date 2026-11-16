//! Commit reference extraction. Deliberately NOT a full commit model:
//! the server only needs the graph edges (tree, parents); everything else -
//! author, committer, gpgsig, mergetag, arbitrary headers - passes through
//! as opaque bytes and is never regenerated.
//!
//! Format source: git-reference/Documentation/gitdatamodel.adoc
//! ("commit") shows an example commit as:
//!
//! ```text
//! tree <oid>
//! parent <oid>
//! author ...
//! committer ...
//! <blank line>
//! <message>
//! ```
//!
//! That page documents this as an example, not a formal grammar, and
//! nothing found under Documentation/ pins down whether other headers
//! (mergetag, gpgsig, encoding, ...) may interleave between tree and the
//! author/committer lines, or whether there is a hard rule that all
//! "parent" lines are contiguous. So this parser does the minimum the
//! example actually supports: "tree" must be the very first line, and
//! every "parent " line is collected wherever it appears in the header
//! block (i.e. before the first blank line), in order. Anything else in
//! the header block is skipped untouched, and nothing after the header
//! block's terminating blank line is ever inspected.
//!
//! PRIOR-KNOWLEDGE DISCLOSURE: multi-line header values (gpgsig,
//! mergetag) are folded with a leading-space continuation convention
//! (email-header-style), which is why a line embedded inside one of
//! those blocks does not falsely match "parent " or trip the blank-line
//! terminator. This parser does not rely on that convention
//! algorithmically - it only ever matches an exact "parent " prefix and
//! an exact empty line - so no behavior here depends on it, but it is
//! the reasoning behind why interleaved binary-ish headers are safe to
//! skip. Not found spelled out under Documentation/; ordinary git
//! ecosystem knowledge. See NOTES.md.

use super::{parse_oid_line, ObjectError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRefs {
    pub tree: String,
    pub parents: Vec<String>,
}

/// Extracts tree and parent oids from commit content (object body, no
/// loose header).
pub fn refs(content: &[u8]) -> Result<CommitRefs, ObjectError> {
    let mut lines = content.split(|&b| b == b'\n');

    let first = lines.next().unwrap_or(&[]);
    let tree = parse_oid_line(first, b"tree ").ok_or_else(|| ObjectError::Malformed {
        what: "commit",
        detail: format!(
            "first header line is not a valid tree line: {:?}",
            String::from_utf8_lossy(first)
        ),
    })?;

    let mut parents = Vec::new();
    for line in lines {
        if line.is_empty() {
            // Header block ends at the first blank line; message body
            // (and anything else after it) is never inspected.
            break;
        }
        if let Some(oid) = parse_oid_line(line, b"parent ") {
            parents.push(oid);
        }
    }

    Ok(CommitRefs { tree, parents })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE: &str = "0123456789abcdef0123456789abcdef01234567";
    const PARENT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PARENT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn root_commit_has_no_parents() {
        let content =
            format!("tree {TREE}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n");
        let refs = refs(content.as_bytes()).unwrap();
        assert_eq!(refs.tree, TREE);
        assert!(refs.parents.is_empty());
    }

    #[test]
    fn ordinary_commit_has_one_parent() {
        let content = format!(
            "tree {TREE}\nparent {PARENT_A}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n"
        );
        let refs = refs(content.as_bytes()).unwrap();
        assert_eq!(refs.parents, vec![PARENT_A.to_string()]);
    }

    #[test]
    fn merge_commit_has_multiple_parents_in_order() {
        let content = format!(
            "tree {TREE}\nparent {PARENT_A}\nparent {PARENT_B}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n"
        );
        let refs = refs(content.as_bytes()).unwrap();
        assert_eq!(
            refs.parents,
            vec![PARENT_A.to_string(), PARENT_B.to_string()]
        );
    }

    #[test]
    fn missing_tree_line_is_malformed() {
        let content = format!("parent {PARENT_A}\nauthor a <a@x> 0 +0000\n\nmsg\n");
        assert!(refs(content.as_bytes()).is_err());
    }

    #[test]
    fn malformed_tree_hex_is_malformed() {
        let content = "tree not-hex\n\nmsg\n";
        assert!(refs(content.as_bytes()).is_err());
    }

    #[test]
    fn empty_content_is_malformed() {
        assert!(refs(&[]).is_err());
    }

    #[test]
    fn message_body_never_inspected_even_if_it_looks_like_a_header() {
        let content = format!("tree {TREE}\n\nparent {PARENT_A}\ntree {PARENT_B}\n");
        let refs = refs(content.as_bytes()).unwrap();
        assert_eq!(refs.tree, TREE);
        assert!(refs.parents.is_empty());
    }

    #[test]
    fn no_blank_line_still_finds_tree_and_parents() {
        // Truncated/corrupt commit missing the header/body separator -
        // the whole remainder is treated as header block.
        let content = format!("tree {TREE}\nparent {PARENT_A}\n");
        let refs = refs(content.as_bytes()).unwrap();
        assert_eq!(refs.tree, TREE);
        assert_eq!(refs.parents, vec![PARENT_A.to_string()]);
    }
}
