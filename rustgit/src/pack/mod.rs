//! Packfile codec under test. Scope: packfile read and write only, per
//! CLAUDE.md.
//! M1: read path for non-delta objects - done.
//! M2: OBJ_OFS_DELTA / OBJ_REF_DELTA chain resolution - this file.

pub mod delta;
pub mod diff;
pub mod idx;
pub mod odb;
#[allow(
    clippy::module_inception,
    reason = "retain the existing RustGit API path"
)]
pub mod pack;
pub mod writer;

use std::collections::HashMap;
use std::path::Path;

/// A fully resolved object read out of a pack, keyed by oid.
#[derive(Debug, Clone)]
pub struct ReadObject {
    pub oid: String,
    pub kind: &'static str,
    pub size: u64,
    pub content: Vec<u8>,
}

/// Read every non-delta object out of `pack_path` using `idx_path` to
/// locate entries. Delta entries are skipped. Kept as-is from M1;
/// superseded by `read_all` (below) which resolves deltas too, but
/// left in place since the M1 harness test still exercises it on
/// deliberately delta-free fixtures.
/// Returns (resolved objects, count of delta entries skipped).
pub fn read_all_non_delta(idx_path: &Path, pack_path: &Path) -> (Vec<ReadObject>, usize) {
    let idx = idx::parse(idx_path).expect("failed to parse idx");
    let pack_data = pack::read_pack_file(pack_path).expect("failed to read pack file");

    let mut objects = Vec::new();
    let mut skipped_deltas = 0usize;

    for entry in &idx.entries {
        let raw = pack::read_raw_entry(&pack_data, entry.offset);
        if matches!(raw.kind, pack::OBJ_OFS_DELTA | pack::OBJ_REF_DELTA) {
            skipped_deltas += 1;
            continue;
        }

        let oid = pack::compute_oid(raw.kind, &raw.content);
        assert_eq!(
            oid, entry.oid,
            "computed oid does not match idx oid at offset {}",
            entry.offset
        );
        objects.push(ReadObject {
            oid,
            kind: pack::type_name(raw.kind),
            size: raw.size,
            content: raw.content,
        });
    }

    (objects, skipped_deltas)
}

/// Resolve every object in the pack, including OBJ_OFS_DELTA and
/// OBJ_REF_DELTA chains. Ref-delta bases must exist within the same
/// pack (non-thin) - thin pack support is M5 scope.
///
/// Resolution is memoized by pack offset so shared bases in a chain
/// (or objects that are themselves bases for many deltas) are only
/// inflated/applied once, which matters for real repacked corpora
/// where chain depth can run into the dozens.
pub fn read_all(idx_path: &Path, pack_path: &Path) -> Vec<ReadObject> {
    read_all_impl(idx_path, pack_path, None)
}

/// Same as read_all, but for a THIN pack (M5): OBJ_REF_DELTA entries
/// whose base oid is not present in this pack's own idx are resolved
/// by looking `base_repo` up instead (see odb.rs) - the defining
/// property of a thin pack is that some bases live outside it.
pub fn read_all_thin(idx_path: &Path, pack_path: &Path, base_repo: &Path) -> Vec<ReadObject> {
    read_all_impl(idx_path, pack_path, Some(base_repo))
}

fn read_all_impl(idx_path: &Path, pack_path: &Path, base_repo: Option<&Path>) -> Vec<ReadObject> {
    let idx = idx::parse(idx_path).expect("failed to parse idx");
    let pack_data = pack::read_pack_file(pack_path).expect("failed to read pack file");

    let oid_to_offset: HashMap<&str, u64> = idx
        .entries
        .iter()
        .map(|e| (e.oid.as_str(), e.offset))
        .collect();

    let mut cache: HashMap<u64, (u8, Vec<u8>)> = HashMap::new();

    let mut objects = Vec::with_capacity(idx.entries.len());
    for entry in &idx.entries {
        let (kind, content) = resolve_at(
            &pack_data,
            &oid_to_offset,
            entry.offset,
            &mut cache,
            0,
            base_repo,
        );
        let oid = pack::compute_oid(kind, &content);
        assert_eq!(
            oid, entry.oid,
            "computed oid does not match idx oid at offset {}",
            entry.offset
        );
        objects.push(ReadObject {
            oid,
            kind: pack::type_name(kind),
            size: content.len() as u64,
            content,
        });
    }

    objects
}

const MAX_DELTA_CHAIN: usize = 4096; // generous cycle guard, not a spec limit

fn resolve_at(
    pack_data: &[u8],
    oid_to_offset: &HashMap<&str, u64>,
    offset: u64,
    cache: &mut HashMap<u64, (u8, Vec<u8>)>,
    depth: usize,
    base_repo: Option<&Path>,
) -> (u8, Vec<u8>) {
    if let Some(cached) = cache.get(&offset) {
        return cached.clone();
    }
    assert!(
        depth < MAX_DELTA_CHAIN,
        "delta chain exceeds {} entries at offset {} - probable cycle (corrupt pack, or a \
         bug: base offset math should never cycle in a well-formed pack)",
        MAX_DELTA_CHAIN,
        offset
    );

    let raw = pack::read_raw_entry(pack_data, offset);

    let resolved = match raw.base {
        pack::BaseRef::None => (raw.kind, raw.content),
        pack::BaseRef::Offset(base_offset) => {
            let (base_kind, base_content) = resolve_at(
                pack_data,
                oid_to_offset,
                base_offset,
                cache,
                depth + 1,
                base_repo,
            );
            let content = delta::apply_delta(&base_content, &raw.content);
            (base_kind, content)
        }
        pack::BaseRef::Oid(oid_bytes) => {
            let oid = oid_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            match oid_to_offset.get(oid.as_str()) {
                Some(&base_offset) => {
                    let (base_kind, base_content) = resolve_at(
                        pack_data,
                        oid_to_offset,
                        base_offset,
                        cache,
                        depth + 1,
                        base_repo,
                    );
                    let content = delta::apply_delta(&base_content, &raw.content);
                    (base_kind, content)
                }
                None => {
                    // Base not in this pack - only valid for a thin
                    // pack, where the caller supplied base_repo to
                    // resolve it from the local object store instead.
                    let repo = base_repo.unwrap_or_else(|| {
                        panic!(
                            "ref-delta base {} not found in this pack's idx and no base_repo \
                             was supplied - this is only valid for a thin pack (read_all_thin)",
                            oid
                        )
                    });
                    let (base_kind, base_content) = odb::resolve_oid_in_repo(repo, &oid)
                        .unwrap_or_else(|| {
                            panic!(
                                "ref-delta base {} not found in this pack's idx OR in base_repo {}",
                                oid,
                                repo.display()
                            )
                        });
                    let content = delta::apply_delta(&base_content, &raw.content);
                    (base_kind, content)
                }
            }
        }
    };

    cache.insert(offset, resolved.clone());
    resolved
}
