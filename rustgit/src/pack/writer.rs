//! M3/M4: write path. Produce a pack-*.pack and matching pack-*.idx
//! (version 2) from a set of objects, optionally emitting OBJ_OFS_DELTA
//! entries instead of full objects (M4: delta creation).
//!
//! Format sources: git-reference/Documentation/gitformat-pack.adoc for
//! the pack entry header encoding (mirrors decode_entry_header in
//! pack.rs) and the idx v2 layout (mirrors idx.rs's parser - this is
//! that parser's write-side counterpart).
//!
//! M4 scope note (per explicit instruction): the wire format for
//! deltas is specified: git's *heuristics* for which objects to delta
//! against which, and with what window/depth, are not (see
//! pack-heuristics.adoc, an informal IRC transcript the git maintainer
//! himself calls "not exactly it"). The bar here is pack size within
//! 2x of git's own output on the same object set, not heuristic
//! parity - see write_pack_with_deltas's doc comment for the
//! (arbitrary, undisguised) choices made here.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, VecDeque};
use std::io::Write;

use super::diff;
use super::pack::{compute_oid, encode_ofs_delta_offset, OBJ_OFS_DELTA, OBJ_REF_DELTA};

/// An object to be written: its type constant (OBJ_COMMIT etc, from
/// pack.rs) and raw content.
pub struct WriteObject {
    pub kind: u8,
    pub content: Vec<u8>,
}

/// Encode the packed-object header (type+size). Inverse of pack.rs's
/// decode_entry_header. Works for any type including OBJ_OFS_DELTA -
/// `size` just means whatever gitformat-pack.adoc says it means for
/// that type (full content length for non-delta, delta stream length
/// for delta - see the M2 NOTES.md finding on this exact point).
fn encode_entry_header(kind: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = (kind & 0x07) << 4;
    let mut rest = size >> 4;
    let low4 = (size & 0x0f) as u8;
    first |= low4;
    if rest > 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest > 0 {
        let mut byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest > 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("zlib compress failed");
    encoder.finish().expect("zlib finish failed")
}

fn hex_to_bytes(hex: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("bad hex oid");
    }
    out
}

pub struct WrittenPack {
    pub pack_bytes: Vec<u8>,
    pub idx_bytes: Vec<u8>,
    pub full_object_count: usize,
    pub delta_object_count: usize,
}

struct WrittenEntry {
    oid: String,
    offset: u64,
    crc32: u32,
}

/// Append the pack trailer checksum to `pack`, build the matching idx
/// v2 from `written`, and package both. Shared by write_pack and
/// write_pack_with_deltas - only how entries get written into `pack`
/// differs between them.
fn finish(
    mut pack: Vec<u8>,
    mut written: Vec<WrittenEntry>,
    delta_object_count: usize,
) -> WrittenPack {
    let pack_checksum: [u8; 20] = Sha1::digest(&pack).into();
    pack.extend_from_slice(&pack_checksum);

    written.sort_by(|a, b| a.oid.cmp(&b.oid));

    let mut idx = Vec::new();
    idx.extend_from_slice(&[0xff, b't', b'O', b'c']);
    idx.extend_from_slice(&2u32.to_be_bytes());

    let mut fanout = [0u32; 256];
    for w in &written {
        let first_byte = u8::from_str_radix(&w.oid[0..2], 16).expect("bad hex oid");
        for slot in fanout.iter_mut().skip(first_byte as usize) {
            *slot += 1;
        }
    }
    for count in fanout {
        idx.extend_from_slice(&count.to_be_bytes());
    }

    for w in &written {
        idx.extend_from_slice(&hex_to_bytes(&w.oid));
    }
    for w in &written {
        idx.extend_from_slice(&w.crc32.to_be_bytes());
    }
    // Large-offset table intentionally left empty - see write_pack's
    // original note: out of scope for this spike's fixture sizes
    // (packs never approach the 2GiB / 31-bit offset boundary).
    for w in &written {
        assert!(
            w.offset < 0x8000_0000,
            "offset {} exceeds 31 bits - large-offset table not implemented (out of scope \
             for this spike's fixture sizes)",
            w.offset
        );
        idx.extend_from_slice(&(w.offset as u32).to_be_bytes());
    }

    idx.extend_from_slice(&pack_checksum);
    let idx_checksum: [u8; 20] = Sha1::digest(&idx).into();
    idx.extend_from_slice(&idx_checksum);

    let full_object_count = written.len() - delta_object_count;
    WrittenPack {
        pack_bytes: pack,
        idx_bytes: idx,
        full_object_count,
        delta_object_count,
    }
}

/// Write every object in `objects` as a non-delta pack entry, then
/// build a matching version-2 idx (M3). Objects are written in the
/// order given; the idx's own tables are sorted by oid as the format
/// requires regardless of write order.
pub fn write_pack(objects: &[WriteObject]) -> WrittenPack {
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());

    let mut written: Vec<WrittenEntry> = Vec::with_capacity(objects.len());

    for obj in objects {
        let offset = pack.len() as u64;
        let header = encode_entry_header(obj.kind, obj.content.len() as u64);
        let compressed = zlib_compress(&obj.content);

        let entry_start = pack.len();
        pack.extend_from_slice(&header);
        pack.extend_from_slice(&compressed);

        let crc32 = crc32fast::hash(&pack[entry_start..]);
        let oid = compute_oid(obj.kind, &obj.content);
        written.push(WrittenEntry { oid, offset, crc32 });
    }

    finish(pack, written, 0)
}

/// Arbitrary tuning constants for M4's delta search - NOT reverse-
/// engineered from git's own defaults, chosen independently and not
/// tuned further once size parity was reached (per explicit M4 scope
/// guard: size parity is not a correctness question).
const WINDOW_SIZE: usize = 16;
const MAX_DELTA_DEPTH: u32 = 50;

/// Objects above this size neither attempt a delta nor become a delta
/// candidate for others. Discovered necessary, not designed in from
/// the start, and revised down once: a ~1.2MB tree object in the
/// gitoxide corpus made every subsequent same-type object's delta
/// attempt against it pathologically slow; a first cap of 256 KiB
/// still left a long run of ~200-260 KiB blobs (evidently a common
/// size band in this corpus - looks like vendored binary test
/// fixtures) each taking 500ms-1.3s. See NOTES.md. git has an
/// analogous idea. Its core.bigFileThreshold defaults to 512 MiB.
/// The 64 KiB cap limits work in the O(candidates * content_len)
/// block matcher.
const MAX_DELTA_CANDIDATE_SIZE: usize = 64 * 1024;

/// Write `objects`, emitting OBJ_OFS_DELTA entries where a same-type
/// candidate from a small trailing window produces a smaller result
/// than storing the object whole (M4).
///
/// Base-selection strategy: sort by (type, size descending) before
/// assigning write order - type-first because different object types
/// never delta against each other, size-descending within type because
/// deltaing a smaller object against a larger one tends to remove more
/// than it adds (both points are stated, informally, in
/// pack-heuristics.adoc). Everything past that - the fixed window size,
/// depth cap, "pick the smallest delta from the window" tie-break - is
/// our own choice, not reverse-engineered from git, which is why this
/// function is judged on the 2x-size-parity bar rather than heuristic
/// fidelity. pack-heuristics.adoc's basename/path clustering is not
/// implemented at all - WriteObject carries no path, out of scope.
pub fn write_pack_with_deltas(objects: &[WriteObject]) -> WrittenPack {
    let mut order: Vec<usize> = (0..objects.len()).collect();
    order.sort_by(|&a, &b| {
        objects[a]
            .kind
            .cmp(&objects[b].kind)
            .then(objects[b].content.len().cmp(&objects[a].content.len()))
    });

    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());

    let mut written: Vec<WrittenEntry> = Vec::with_capacity(objects.len());

    struct Candidate<'a> {
        offset: u64,
        depth: u32,
        // Built once when this object enters the window, reused for
        // every later target that tries it as a base - see diff.rs's
        // BaseIndex doc comment for why this matters: rebuilding it
        // per attempt turned the medium-corpus run into an
        // effectively-hung O(window * n * base_len) pass (see NOTES.md).
        index: diff::BaseIndex<'a>,
    }
    let mut windows: HashMap<u8, VecDeque<Candidate>> = HashMap::new();
    let mut delta_count = 0usize;

    for &idx in &order {
        let obj = &objects[idx];
        let offset = pack.len() as u64;
        let obj_start = std::time::Instant::now();

        let mut chosen: Option<(u64, Vec<u8>)> = None; // (base_offset, delta_bytes)
        let mut chosen_depth = 0u32;

        let try_delta = obj.content.len() <= MAX_DELTA_CANDIDATE_SIZE
            && windows.get(&obj.kind).is_some_and(|w| !w.is_empty());
        if try_delta {
            // Computed once and reused across every candidate below -
            // see create_delta_with_index_and_hashes's doc comment for
            // why this matters (this was half of the M4 perf bug).
            let target_hashes = diff::hash_windows(&obj.content);
            let window = &windows[&obj.kind];
            for cand in window.iter() {
                if cand.depth >= MAX_DELTA_DEPTH {
                    continue;
                }
                let delta_bytes = diff::create_delta_with_index_and_hashes(
                    &cand.index,
                    &obj.content,
                    &target_hashes,
                );
                let better = match &chosen {
                    None => delta_bytes.len() < obj.content.len(),
                    Some((_, best_bytes)) => delta_bytes.len() < best_bytes.len(),
                };
                if better {
                    chosen_depth = cand.depth + 1;
                    chosen = Some((cand.offset, delta_bytes));
                }
            }
        }

        let entry_start = pack.len();
        if let Some((base_offset, delta_bytes)) = &chosen {
            let header = encode_entry_header(OBJ_OFS_DELTA, delta_bytes.len() as u64);
            pack.extend_from_slice(&header);
            let rel_offset = offset - base_offset;
            pack.extend_from_slice(&encode_ofs_delta_offset(rel_offset));
            let compressed = zlib_compress(delta_bytes);
            pack.extend_from_slice(&compressed);
            delta_count += 1;
        } else {
            let header = encode_entry_header(obj.kind, obj.content.len() as u64);
            pack.extend_from_slice(&header);
            let compressed = zlib_compress(&obj.content);
            pack.extend_from_slice(&compressed);
        }

        let crc32 = crc32fast::hash(&pack[entry_start..]);
        let oid = compute_oid(obj.kind, &obj.content);
        written.push(WrittenEntry { oid, offset, crc32 });

        if obj.content.len() <= MAX_DELTA_CANDIDATE_SIZE {
            let window = windows.entry(obj.kind).or_default();
            window.push_back(Candidate {
                offset,
                depth: chosen_depth,
                index: diff::build_base_index(&obj.content),
            });
            if window.len() > WINDOW_SIZE {
                window.pop_front();
            }
        }

        if written.len().is_multiple_of(20_000) {
            eprintln!(
                "  write_pack_with_deltas: {}/{} objects, {} delta so far",
                written.len(),
                objects.len(),
                delta_count
            );
        }
        let elapsed = obj_start.elapsed();
        if elapsed.as_millis() > 200 {
            eprintln!(
                "  SLOW object #{}: kind={} content_len={} elapsed={:?}",
                written.len(),
                obj.kind,
                obj.content.len(),
                elapsed
            );
        }
    }

    finish(pack, written, delta_count)
}

/// M5: write a THIN pack - `objects` are written as usual, but may be
/// encoded as OBJ_REF_DELTA against an `external_bases` entry (oid,
/// content) that is NOT included in the output pack at all. That's
/// the defining property of a thin pack: it is not self-contained: a
/// receiver needs to already have the referenced base object (e.g.
/// git push, where the receiving repo already has most of the
/// history). No sliding window here - external_bases is the
/// candidate set directly, since M5's scope is "does thin-pack
/// production/consumption work at all", not delta-selection quality
/// (that's M4's concern, already covered by write_pack_with_deltas).
pub fn write_thin_pack(
    objects: &[WriteObject],
    external_bases: &HashMap<String, Vec<u8>>,
) -> WrittenPack {
    let ext_indices: Vec<(&String, diff::BaseIndex)> = external_bases
        .iter()
        .map(|(oid, content)| (oid, diff::build_base_index(content)))
        .collect();

    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());

    let mut written: Vec<WrittenEntry> = Vec::with_capacity(objects.len());
    let mut delta_count = 0usize;

    for obj in objects {
        let offset = pack.len() as u64;
        let target_hashes = diff::hash_windows(&obj.content);

        let mut best: Option<(&str, Vec<u8>)> = None; // (base_oid, delta_bytes)
        for (oid, index) in &ext_indices {
            let delta_bytes =
                diff::create_delta_with_index_and_hashes(index, &obj.content, &target_hashes);
            let better = match &best {
                None => delta_bytes.len() < obj.content.len(),
                Some((_, best_bytes)) => delta_bytes.len() < best_bytes.len(),
            };
            if better {
                best = Some((oid.as_str(), delta_bytes));
            }
        }

        let entry_start = pack.len();
        if let Some((base_oid, delta_bytes)) = &best {
            let header = encode_entry_header(OBJ_REF_DELTA, delta_bytes.len() as u64);
            pack.extend_from_slice(&header);
            pack.extend_from_slice(&hex_to_bytes(base_oid));
            let compressed = zlib_compress(delta_bytes);
            pack.extend_from_slice(&compressed);
            delta_count += 1;
        } else {
            let header = encode_entry_header(obj.kind, obj.content.len() as u64);
            pack.extend_from_slice(&header);
            let compressed = zlib_compress(&obj.content);
            pack.extend_from_slice(&compressed);
        }

        let crc32 = crc32fast::hash(&pack[entry_start..]);
        let oid = compute_oid(obj.kind, &obj.content);
        written.push(WrittenEntry { oid, offset, crc32 });
    }

    finish(pack, written, delta_count)
}
