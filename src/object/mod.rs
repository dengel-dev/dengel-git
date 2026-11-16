//! G0: the object model rustgit never needed.
//!
//! The spikes treated objects as opaque (kind, bytes) pairs, which was
//! correct for a pack codec. A server needs to see INSIDE three of the
//! four kinds - trees for entry oids, commits for tree+parents, tags for
//! their target - because connectivity checking (G4) and ref peeling (G2)
//! are graph walks over exactly those references. Nothing more is parsed:
//! content is otherwise passed through untouched, which is also what makes
//! byte-exact round-tripping trivially safe.

pub mod commit;
pub mod loose;
pub mod tag;
pub mod tree;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl Kind {
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Blob => "blob",
            Kind::Tree => "tree",
            Kind::Commit => "commit",
            Kind::Tag => "tag",
        }
    }

    pub fn from_name(s: &str) -> Option<Kind> {
        match s {
            "blob" => Some(Kind::Blob),
            "tree" => Some(Kind::Tree),
            "commit" => Some(Kind::Commit),
            "tag" => Some(Kind::Tag),
            _ => None,
        }
    }
}

/// Errors, never panics: this module sits on the untrusted side of the
/// trust boundary once G4 feeds it bytes from the wire.
#[derive(Debug)]
pub enum ObjectError {
    Malformed { what: &'static str, detail: String },
    Io(std::io::Error),
}

impl std::fmt::Display for ObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectError::Malformed { what, detail } => write!(f, "malformed {what}: {detail}"),
            ObjectError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ObjectError {}

impl From<std::io::Error> for ObjectError {
    fn from(e: std::io::Error) -> Self {
        ObjectError::Io(e)
    }
}

/// Shorthand used across the sibling modules to build a `Malformed`.
pub(crate) fn malformed(what: &'static str, detail: impl Into<String>) -> ObjectError {
    ObjectError::Malformed {
        what,
        detail: detail.into(),
    }
}

/// Maps `Kind` to rustgit's pack object-type code (`OBJ_COMMIT` etc,
/// gitformat-pack.adoc "Object types" - already the format source for
/// rustgit's own constants, which this just reuses). G2's server code
/// (walk.rs, ls_refs.rs) crosses between this crate's `Kind` and
/// rustgit's odb/pack-writer constants at every object lookup, so this
/// lives here rather than being re-derived per call site (loose.rs has
/// its own private copy, kept as-is - not worth touching a G0 file for
/// this).
pub fn kind_to_objcode(kind: Kind) -> u8 {
    use rustgit::pack::pack::{OBJ_BLOB, OBJ_COMMIT, OBJ_TAG, OBJ_TREE};
    match kind {
        Kind::Blob => OBJ_BLOB,
        Kind::Tree => OBJ_TREE,
        Kind::Commit => OBJ_COMMIT,
        Kind::Tag => OBJ_TAG,
    }
}

/// Inverse of `kind_to_objcode`. `None` for a code that isn't one of
/// the four object kinds (delta codes 6/7 are resolved away by the odb
/// before this ever sees them; a `None` here past that point means the
/// odb returned something it never should have).
pub fn kind_from_objcode(code: u8) -> Option<Kind> {
    use rustgit::pack::pack::{OBJ_BLOB, OBJ_COMMIT, OBJ_TAG, OBJ_TREE};
    match code {
        OBJ_COMMIT => Some(Kind::Commit),
        OBJ_TREE => Some(Kind::Tree),
        OBJ_BLOB => Some(Kind::Blob),
        OBJ_TAG => Some(Kind::Tag),
        _ => None,
    }
}

/// True iff `s` is exactly 40 lowercase ASCII hex digits.
///
/// This is the only oid spelling `loose::read` trusts before it builds a
/// filesystem path out of it: hex digits cannot spell "." or "/", so this
/// also rejects path traversal by construction. It is deliberately
/// stricter than rustgit's `refs::loose::is_valid_oid_syntax` (which
/// accepts uppercase hex too) - fine for a ref file that only ever gets
/// compared as text, not fine for something that feeds a `path.join`.
pub(crate) fn is_lower_hex40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parses a header line of the form `<prefix><40-lowercase-hex>` with no
/// trailing bytes. Used by commit::refs and tag::refs for their oid
/// header lines ("tree ", "parent ", "object ").
pub(crate) fn parse_oid_line(line: &[u8], prefix: &[u8]) -> Option<String> {
    let rest = line.strip_prefix(prefix)?;
    let s = std::str::from_utf8(rest).ok()?;
    if is_lower_hex40(s) {
        Some(s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_hex40_accepts_valid() {
        assert!(is_lower_hex40("0123456789abcdef0123456789abcdef01234567"));
    }

    #[test]
    fn lower_hex40_rejects_uppercase() {
        assert!(!is_lower_hex40("0123456789ABCDEF0123456789abcdef01234567"));
    }

    #[test]
    fn lower_hex40_rejects_wrong_length() {
        assert!(!is_lower_hex40("abc"));
        assert!(!is_lower_hex40(""));
    }

    #[test]
    fn lower_hex40_rejects_traversal_lookalikes() {
        assert!(!is_lower_hex40("../../../../etc/passwd0000000000000000"));
    }

    #[test]
    fn parse_oid_line_matches_prefix_and_hex() {
        let line = b"tree 0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            parse_oid_line(line, b"tree "),
            Some("0123456789abcdef0123456789abcdef01234567".to_string())
        );
    }

    #[test]
    fn parse_oid_line_rejects_wrong_prefix() {
        let line = b"parent 0123456789abcdef0123456789abcdef01234567";
        assert_eq!(parse_oid_line(line, b"tree "), None);
    }

    #[test]
    fn parse_oid_line_rejects_trailing_garbage() {
        let line = b"tree 0123456789abcdef0123456789abcdef01234567 extra";
        assert_eq!(parse_oid_line(line, b"tree "), None);
    }
}
