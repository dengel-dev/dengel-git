//! Loose ref file read/write.
//!
//! Format source: empirically confirmed against real git (see
//! NOTES-03.md) - a loose ref file's content is exactly
//! `<40-hex-char-oid>\n`, nothing else. Symref format (HEAD etc) IS
//! documented: git-symbolic-ref.adoc - "A symbolic ref is a regular
//! file that stores a string that begins with `ref: refs/`", e.g.
//! `ref: refs/heads/main\n`.

use std::path::{Path, PathBuf};

pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LooseRefValue {
    Oid(String),
    Symref(String), // target refname, e.g. "refs/heads/main"
}

/// Map a refname (e.g. "refs/heads/main" or "HEAD") to its loose file
/// path under `git_dir`.
pub fn ref_path(git_dir: &Path, refname: &str) -> PathBuf {
    git_dir.join(refname)
}

pub fn read_loose_ref(git_dir: &Path, refname: &str) -> std::io::Result<Option<LooseRefValue>> {
    let path = ref_path(git_dir, refname);
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(Some(parse_ref_content(&content))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn parse_ref_content(content: &str) -> LooseRefValue {
    let trimmed = content.trim_end_matches('\n');
    if let Some(target) = trimmed.strip_prefix("ref: ") {
        LooseRefValue::Symref(target.to_string())
    } else {
        LooseRefValue::Oid(trimmed.to_string())
    }
}

pub fn format_ref_content(value: &LooseRefValue) -> Vec<u8> {
    match value {
        LooseRefValue::Oid(oid) => format!("{}\n", oid).into_bytes(),
        LooseRefValue::Symref(target) => format!("ref: {}\n", target).into_bytes(),
    }
}

pub fn is_valid_oid_syntax(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}
