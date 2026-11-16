//! packed-refs file parse/write.
//!
//! Format source: NOT documented anywhere in this checkout (searched
//! the whole Documentation/ tree for "pack-refs with" and
//! "fully-peeled" - zero hits; see NOTES-03.md). Derived by direct
//! observation of real git's own output (`git pack-refs --all` on a
//! constructed fixture with lightweight tags, annotated tags, and
//! branches, byte-inspected via xxd):
//!   header:  "# pack-refs with: peeled fully-peeled sorted \n"
//!            (confirmed trailing SPACE before the LF - not a typo)
//!   entry:   "<oid> SP <refname>\n", sorted lexicographically by full
//!            refname (heads and tags interleaved by name, not
//!            grouped by namespace)
//!   peeled:  "^<peeled-oid>\n" immediately after an annotated tag's
//!            entry line (lightweight tags get no peeled line)
//! PRIOR-KNOWLEDGE DISCLOSURE (per CLAUDE.md, maximum weight): the
//! general shape of this format is well-known git folklore; every
//! specific byte above was independently re-confirmed against this
//! checkout's real git, not trusted from memory.

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PackedRefEntry {
    pub oid: String,
    pub peeled: Option<String>,
}

#[derive(Debug, Default)]
pub struct PackedRefs {
    /// refname -> entry, kept in a BTreeMap so iteration is already in
    /// the sorted order the file format requires.
    pub entries: BTreeMap<String, PackedRefEntry>,
}

pub fn parse_packed_refs(content: &str) -> PackedRefs {
    let mut refs = PackedRefs::default();
    let mut last_refname: Option<String> = None;

    for line in content.lines() {
        if line.starts_with('#') {
            continue; // header line, format asserted by round-trip tests rather than parsed
        }
        if let Some(peeled_oid) = line.strip_prefix('^') {
            if let Some(refname) = &last_refname {
                if let Some(entry) = refs.entries.get_mut(refname) {
                    entry.peeled = Some(peeled_oid.to_string());
                }
            }
            continue;
        }
        if let Some((oid, refname)) = line.split_once(' ') {
            refs.entries.insert(
                refname.to_string(),
                PackedRefEntry {
                    oid: oid.to_string(),
                    peeled: None,
                },
            );
            last_refname = Some(refname.to_string());
        }
    }
    refs
}

pub fn format_packed_refs(refs: &PackedRefs) -> String {
    let mut out = String::from("# pack-refs with: peeled fully-peeled sorted \n");
    for (refname, entry) in &refs.entries {
        out.push_str(&entry.oid);
        out.push(' ');
        out.push_str(refname);
        out.push('\n');
        if let Some(peeled) = &entry.peeled {
            out.push('^');
            out.push_str(peeled);
            out.push('\n');
        }
    }
    out
}

pub fn read_packed_refs(git_dir: &Path) -> std::io::Result<PackedRefs> {
    let path = git_dir.join("packed-refs");
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(parse_packed_refs(&content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PackedRefs::default()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_matches_observed_real_git_output() {
        // Byte-for-byte the fixture captured from real git in
        // NOTES-03.md (aaa-branch, zzz-branch, annotated myatag).
        let real_output = "# pack-refs with: peeled fully-peeled sorted \n\
63661295f0d40d16bc8d8d929426a3caa18fd772 refs/heads/aaa-branch\n\
63661295f0d40d16bc8d8d929426a3caa18fd772 refs/heads/zzz-branch\n\
3c8e93b58eee7b4b1086320c614773e6baab5020 refs/tags/myatag\n\
^63661295f0d40d16bc8d8d929426a3caa18fd772\n";

        let parsed = parse_packed_refs(real_output);
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(
            parsed.entries["refs/heads/aaa-branch"].oid,
            "63661295f0d40d16bc8d8d929426a3caa18fd772"
        );
        assert_eq!(
            parsed.entries["refs/tags/myatag"].peeled.as_deref(),
            Some("63661295f0d40d16bc8d8d929426a3caa18fd772")
        );
        assert_eq!(parsed.entries["refs/heads/aaa-branch"].peeled, None);

        let formatted = format_packed_refs(&parsed);
        assert_eq!(
            formatted, real_output,
            "our writer must byte-match real git's observed output"
        );
    }
}
