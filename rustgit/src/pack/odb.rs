//! M5 support: minimal local object-database resolver, needed so a
//! thin pack's REF_DELTA bases (which live outside the thin pack
//! itself, by definition) can be resolved against a real repo's
//! existing objects when *consuming* a thin pack.
//!
//! Directory layout source: git-reference/Documentation/
//! gitrepository-layout.adoc ("objects/[0-9a-f][0-9a-f]" - loose
//! objects splayed over 256 subdirectories by the first two oid hex
//! chars; "objects/pack" - pack files, format per gitformat-pack.adoc,
//! already used throughout pack.rs/idx.rs).
//!
//! PRIOR-KNOWLEDGE DISCLOSURE (per CLAUDE.md): a loose object file's
//! *content* format (zlib-compressed "<type> <size>\0<content>") is
//! not spelled out in gitrepository-layout.adoc - it's the same fact
//! already disclosed in pack.rs's compute_oid (ordinary public
//! knowledge from the wider git ecosystem, not sourced from
//! Documentation/), applied here to a second location (reading loose
//! files, not just hashing content to produce an oid).

use flate2::read::ZlibDecoder;
use std::io::Read;
use std::path::Path;

use super::idx;
use super::pack;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn read_loose_object(git_dir: &Path, oid: &str) -> Option<(u8, Vec<u8>)> {
    let path = git_dir.join("objects").join(&oid[0..2]).join(&oid[2..]);
    let compressed = std::fs::read(path).ok()?;
    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut raw = Vec::new();
    decoder.read_to_end(&mut raw).ok()?;

    // "<type> <size>\0<content>" - split on the first NUL, then the
    // first space within the header portion.
    let nul_pos = raw.iter().position(|&b| b == 0)?;
    let header = std::str::from_utf8(&raw[..nul_pos]).ok()?;
    let space_pos = header.find(' ')?;
    let type_name = &header[..space_pos];
    let kind = match type_name {
        "commit" => pack::OBJ_COMMIT,
        "tree" => pack::OBJ_TREE,
        "blob" => pack::OBJ_BLOB,
        "tag" => pack::OBJ_TAG,
        _ => return None,
    };
    let content = raw[nul_pos + 1..].to_vec();
    Some((kind, content))
}

/// Resolve `oid` (hex string) to (type, content) by checking a
/// non-bare repo's working-tree root: `repo_dir` (i.e. `.git` is
/// joined internally). Spike 01's M5 (thin pack consumption) always
/// operates on non-bare fixtures, so this convenience wrapper is kept
/// for that call site; see resolve_oid_in_git_dir for the more general
/// form spike 03 needs (works for bare repos too, where there is no
/// `.git` subdirectory - the git dir IS the repo root).
pub fn resolve_oid_in_repo(repo_dir: &Path, oid: &str) -> Option<(u8, Vec<u8>)> {
    resolve_oid_in_git_dir(&repo_dir.join(".git"), oid)
}

/// Resolve `oid` (hex string) to (type, content) by checking `git_dir`'s
/// loose objects, then every pack in objects/pack/ (resolving delta
/// chains within that pack using the same logic as pack::read_all).
/// Returns None if not found anywhere.
pub fn resolve_oid_in_git_dir(git_dir: &Path, oid: &str) -> Option<(u8, Vec<u8>)> {
    if let Some(found) = read_loose_object(git_dir, oid) {
        return Some(found);
    }

    let pack_dir = git_dir.join("objects/pack");
    let entries = std::fs::read_dir(&pack_dir).ok()?;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().map(|e| e == "idx").unwrap_or(false) {
            let parsed_idx = idx::parse(&path).ok()?;
            if let Some(entry) = parsed_idx.entries.iter().find(|e| e.oid == oid) {
                let pack_path = path.with_extension("pack");
                let pack_data = pack::read_pack_file(&pack_path).ok()?;
                let oid_to_offset: std::collections::HashMap<&str, u64> = parsed_idx
                    .entries
                    .iter()
                    .map(|e| (e.oid.as_str(), e.offset))
                    .collect();
                return Some(resolve_at(&pack_data, &oid_to_offset, entry.offset));
            }
        }
    }
    None
}

/// Same delta-chain resolution as pack::mod's resolve_at (M2), but
/// standalone here rather than shared - this walks a base repo's own
/// pack to answer one oid lookup, not a full-pack enumeration, so the
/// memoizing cache pack::mod.rs uses for whole-pack reads isn't worth
/// threading through for a single-oid query.
fn resolve_at(
    pack_data: &[u8],
    oid_to_offset: &std::collections::HashMap<&str, u64>,
    offset: u64,
) -> (u8, Vec<u8>) {
    let raw = pack::read_raw_entry(pack_data, offset);
    match raw.base {
        pack::BaseRef::None => (raw.kind, raw.content),
        pack::BaseRef::Offset(base_offset) => {
            let (base_kind, base_content) = resolve_at(pack_data, oid_to_offset, base_offset);
            (
                base_kind,
                super::delta::apply_delta(&base_content, &raw.content),
            )
        }
        pack::BaseRef::Oid(oid_bytes) => {
            let base_oid = hex(&oid_bytes);
            let base_offset = *oid_to_offset.get(base_oid.as_str()).unwrap_or_else(|| {
                panic!("nested ref-delta base {} not found in base pack", base_oid)
            });
            let (base_kind, base_content) = resolve_at(pack_data, oid_to_offset, base_offset);
            (
                base_kind,
                super::delta::apply_delta(&base_content, &raw.content),
            )
        }
    }
}
