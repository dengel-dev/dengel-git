//! Tree entry parsing, with a byte-exact serializer.
//!
//! `mode` is kept verbatim as the bytes git stored (no normalization, no
//! parsing into an integer) - historical repos contain mode spellings that
//! a normalizing writer would silently rewrite, and byte-exact round-trip
//! is the G0 gate. Mode 160000 entries (gitlinks/submodules) parse like
//! any other entry; the G4 connectivity walk is where they must NOT be
//! treated as objects this repository is expected to contain.
//!
//! Format source: git-reference/Documentation/gitdatamodel.adoc ("tree")
//! describes a tree entry conceptually as mode, type, oid, filename, and
//! shows it via `git cat-file -p` (which prints the mode zero-padded and
//! the oid as hex - a *display* transform, not the on-disk bytes).
//!
//! PRIOR-KNOWLEDGE DISCLOSURE (per CLAUDE.md): the exact on-disk binary
//! layout of one tree entry - `<mode-ascii-bytes> SP <name-bytes> NUL
//! <20-raw-oid-bytes>`, repeated with no separator between entries - is
//! not spelled out anywhere under Documentation/ that this search found
//! (gitdatamodel.adoc gives the cat-file -p display form; gitformat-pack
//! and gitformat-loose describe the containing object's compression and
//! addressing but not a tree object's internal byte layout). This is
//! ordinary knowledge from the wider git ecosystem, the same category of
//! fact already disclosed for compute_oid in rustgit's pack.rs and odb.rs,
//! applied here to tree entries specifically. See NOTES.md.

use super::ObjectError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// Raw mode bytes exactly as stored, e.g. b"100644", b"40000".
    pub mode: Vec<u8>,
    /// Raw name bytes (not UTF-8 in general).
    pub name: Vec<u8>,
    /// Lowercase hex.
    pub oid: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        // serialize() is infallible by its signature. entries() only
        // ever produces valid lowercase hex, so this branch is reachable
        // only if a caller hand-builds a TreeEntry with a bad oid string
        // - a caller bug, not untrusted wire data (the trust boundary is
        // entries(), which does validate). Substitute 0 rather than
        // panic, per the module's never-panic rule.
        _ => 0,
    }
}

fn hex_decode20(s: &str) -> [u8; 20] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 20];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = bytes.get(i * 2).copied().map(hex_nibble).unwrap_or(0);
        let lo = bytes.get(i * 2 + 1).copied().map(hex_nibble).unwrap_or(0);
        *slot = (hi << 4) | lo;
    }
    out
}

/// Parses tree content (the object body, without the "tree <len>\0" header).
pub fn entries(content: &[u8]) -> Result<Vec<TreeEntry>, ObjectError> {
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < content.len() {
        let space = content[i..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| ObjectError::Malformed {
                what: "tree entry",
                detail: "missing space after mode".to_string(),
            })?;
        if space == 0 {
            return Err(ObjectError::Malformed {
                what: "tree entry",
                detail: "empty mode".to_string(),
            });
        }
        let mode = content[i..i + space].to_vec();
        i += space + 1;

        let nul =
            content[i..]
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| ObjectError::Malformed {
                    what: "tree entry",
                    detail: "missing NUL after name".to_string(),
                })?;
        let name = content[i..i + nul].to_vec();
        i += nul + 1;

        if content.len() < i + 20 {
            return Err(ObjectError::Malformed {
                what: "tree entry",
                detail: format!(
                    "truncated oid: {} bytes remaining, need 20",
                    content.len() - i
                ),
            });
        }
        let oid = hex_encode(&content[i..i + 20]);
        i += 20;

        out.push(TreeEntry { mode, name, oid });
    }

    Ok(out)
}

/// Inverse of `entries`: must reproduce the original bytes exactly.
pub fn serialize(entries: &[TreeEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        out.extend_from_slice(&e.mode);
        out.push(b' ');
        out.extend_from_slice(&e.name);
        out.push(0);
        out.extend_from_slice(&hex_decode20(&e.oid));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_oid(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    #[test]
    fn round_trips_single_entry() {
        let mut content = Vec::new();
        content.extend_from_slice(b"100644 README.md");
        content.push(0);
        content.extend_from_slice(&raw_oid(0xab));

        let parsed = entries(&content).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].mode, b"100644");
        assert_eq!(parsed[0].name, b"README.md");
        assert_eq!(parsed[0].oid, "ab".repeat(20));

        assert_eq!(serialize(&parsed), content);
    }

    #[test]
    fn round_trips_multiple_entries_and_preserves_mode_bytes() {
        let mut content = Vec::new();
        content.extend_from_slice(b"40000 src"); // no leading zero - historical spelling
        content.push(0);
        content.extend_from_slice(&raw_oid(0x11));
        content.extend_from_slice(b"100755 run.sh");
        content.push(0);
        content.extend_from_slice(&raw_oid(0x22));
        content.extend_from_slice(b"160000 sub");
        content.push(0);
        content.extend_from_slice(&raw_oid(0x33));

        let parsed = entries(&content).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].mode, b"40000");
        assert_eq!(parsed[1].mode, b"100755");
        assert_eq!(parsed[2].mode, b"160000");

        assert_eq!(serialize(&parsed), content);
    }

    #[test]
    fn empty_content_is_empty_tree() {
        assert_eq!(entries(&[]).unwrap(), vec![]);
        assert_eq!(serialize(&[]), Vec::<u8>::new());
    }

    #[test]
    fn truncated_oid_is_malformed() {
        let mut content = Vec::new();
        content.extend_from_slice(b"100644 a");
        content.push(0);
        content.extend_from_slice(&[1, 2, 3]); // way short of 20 bytes
        assert!(entries(&content).is_err());
    }

    #[test]
    fn missing_nul_after_name_is_malformed() {
        let content = b"100644 a".to_vec(); // no NUL, no oid at all
        assert!(entries(&content).is_err());
    }

    #[test]
    fn missing_space_after_mode_is_malformed() {
        let content = b"100644README".to_vec();
        assert!(entries(&content).is_err());
    }

    #[test]
    fn name_bytes_are_not_required_to_be_utf8() {
        let mut content = Vec::new();
        content.extend_from_slice(b"100644 ");
        content.extend_from_slice(&[0xff, 0xfe, b'x']); // not valid utf8
        content.push(0);
        content.extend_from_slice(&raw_oid(0x01));

        let parsed = entries(&content).unwrap();
        assert_eq!(parsed[0].name, vec![0xff, 0xfe, b'x']);
        assert_eq!(serialize(&parsed), content);
    }
}
