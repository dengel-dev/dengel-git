//! M4: delta creation. Produces a delta instruction stream (the
//! inverse of delta::apply_delta) that transforms `base` into
//! `target`.
//!
//! PRIOR-KNOWLEDGE DISCLOSURE (per CLAUDE.md): the matching algorithm
//! here - fixed-size block hashing over the base, greedy longest-match
//! extension while scanning the target - is a generic content-diffing
//! technique (the same family as rsync's rolling-checksum algorithm
//! and general LZ77-style matching). It is NOT sourced from any file
//! under Documentation/ - git's own base/window *selection* heuristics
//! are informally described in
//! git-reference/Documentation/technical/pack-heuristics.adoc (an IRC
//! log transcript, explicitly "not exactly it" even by the git
//! maintainer's own admission), but the actual byte-level matching
//! algorithm used here is ordinary prior knowledge applied to satisfy
//! the wire format's copy/insert instruction encoding, not anything
//! git-specific. git's real delta algorithm is unspecified anywhere
//! permitted (or forbidden) for this spike; this is our own choice,
//! not a reconstruction of git's.

use std::collections::HashMap;

const MIN_MATCH: usize = 16;
const MAX_COPY_SIZE: u64 = 0xffffff; // 3-byte size field per instruction encoding
const MAX_INSERT_CHUNK: usize = 127; // 7-bit length field

/// Generic "size encoding" from gitformat-pack.adoc (same scheme
/// delta::apply_delta decodes) - duplicated encode-side here since
/// this module writes delta headers, not just applies them.
fn encode_size(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn hash_block(bytes: &[u8]) -> u64 {
    // FNV-1a, 64-bit. Ordinary general-purpose hash, not part of any
    // git format - see module doc's prior-knowledge disclosure.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// A base object's match index, built once and reused across every
/// target that tries to delta against it. Building this is the
/// expensive part of matching (O(base length)); a candidate base in
/// writer.rs's sliding window is tried against many targets, so
/// rebuilding the index per attempt (as an earlier version of this
/// code did) turned M4's medium-corpus run into an effectively-hung
/// O(window * n * base_len) pass - see NOTES.md.
pub struct BaseIndex<'a> {
    base: &'a [u8],
    blocks: HashMap<u64, Vec<usize>>,
}

pub fn build_base_index(base: &[u8]) -> BaseIndex<'_> {
    let mut blocks: HashMap<u64, Vec<usize>> = HashMap::new();
    if base.len() >= MIN_MATCH {
        for i in 0..=(base.len() - MIN_MATCH) {
            let h = hash_block(&base[i..i + MIN_MATCH]);
            let bucket = blocks.entry(h).or_default();
            if bucket.len() < 64 {
                // Cap bucket size so highly repetitive bases (e.g. runs
                // of zeros) can't turn matching into O(n^2).
                bucket.push(i);
            }
        }
    }
    BaseIndex { base, blocks }
}

/// Create a delta instruction stream transforming `index`'s base into
/// `target`, using a prebuilt BaseIndex (see build_base_index). Always
/// returns a valid delta stream, even a poor one (all literal, no
/// copies) for dissimilar inputs - the caller (writer.rs) is
/// responsible for comparing the resulting size against storing
/// `target` whole and falling back if the delta isn't actually
/// smaller.
/// Convenience wrapper for one-off use (tests, single comparisons):
/// builds the index and creates the delta in one call. writer.rs does
/// NOT use this - it builds each candidate's index once and reuses it
/// across every target tried against that candidate.
pub fn create_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let index = build_base_index(base);
    create_delta_with_index(&index, target)
}

pub fn create_delta_with_index(index: &BaseIndex, target: &[u8]) -> Vec<u8> {
    let target_hashes = hash_windows(target);
    create_delta_with_index_and_hashes(index, target, &target_hashes)
}

/// Precompute the MIN_MATCH-byte window hash at every position of
/// `data`. Shared by every candidate a target is tried against - see
/// create_delta_with_index_and_hashes's doc comment for why this
/// matters. `hashes[i]` corresponds to `data[i..i+MIN_MATCH]`.
pub fn hash_windows(data: &[u8]) -> Vec<u64> {
    if data.len() < MIN_MATCH {
        return Vec::new();
    }
    (0..=(data.len() - MIN_MATCH))
        .map(|i| hash_block(&data[i..i + MIN_MATCH]))
        .collect()
}

/// Same as create_delta_with_index, but takes `target`'s window hashes
/// precomputed via hash_windows instead of recomputing them.
///
/// This split exists because writer.rs tries each target against up
/// to WINDOW_SIZE candidates: computing hash_block afresh at every
/// target position for every candidate multiplies the (already
/// non-trivial, O(16) per call) hashing cost by the window size for no
/// reason, since the target doesn't change between candidates. This
/// was the second half of the M4 performance bug logged in NOTES.md -
/// fixing create_delta's base-side index rebuild alone (BaseIndex)
/// wasn't enough; the target side was still being rehashed from
/// scratch on every one of up to 16 attempts per object.
pub fn create_delta_with_index_and_hashes(
    index: &BaseIndex,
    target: &[u8],
    target_hashes: &[u64],
) -> Vec<u8> {
    let base = index.base;
    let mut out = encode_size(base.len() as u64);
    out.extend(encode_size(target.len() as u64));

    if base.len() < MIN_MATCH || target.is_empty() {
        emit_literal(&mut out, target);
        return out;
    }

    let mut pos = 0usize;
    let mut pending_literal: Vec<u8> = Vec::new();

    while pos < target.len() {
        let mut best_len = 0usize;
        let mut best_base_pos = 0usize;

        if pos + MIN_MATCH <= target.len() {
            let h = target_hashes[pos];
            if let Some(candidates) = index.blocks.get(&h) {
                for &cand in candidates {
                    if base[cand..cand + MIN_MATCH] != target[pos..pos + MIN_MATCH] {
                        continue; // hash collision, not a real match
                    }
                    let max_len = (base.len() - cand)
                        .min(target.len() - pos)
                        .min(MAX_COPY_SIZE as usize);
                    let mut len = MIN_MATCH;
                    while len < max_len && base[cand + len] == target[pos + len] {
                        len += 1;
                    }
                    if len > best_len {
                        best_len = len;
                        best_base_pos = cand;
                    }
                }
            }
        }

        if best_len >= MIN_MATCH {
            flush_literal(&mut out, &mut pending_literal);
            emit_copy(&mut out, best_base_pos as u64, best_len as u64);
            pos += best_len;
        } else {
            pending_literal.push(target[pos]);
            pos += 1;
        }
    }
    flush_literal(&mut out, &mut pending_literal);

    out
}

fn emit_literal(out: &mut Vec<u8>, data: &[u8]) {
    let mut pending = data.to_vec();
    flush_literal(out, &mut pending);
}

fn flush_literal(out: &mut Vec<u8>, pending: &mut Vec<u8>) {
    for chunk in pending.chunks(MAX_INSERT_CHUNK) {
        out.push(chunk.len() as u8); // high bit clear = insert instruction
        out.extend_from_slice(chunk);
    }
    pending.clear();
}

fn emit_copy(out: &mut Vec<u8>, offset: u64, size: u64) {
    // size==0 is not representable directly (it would decode back as
    // 0x10000 per apply_delta) - MIN_MATCH keeps size well above zero,
    // so this is unreachable here, not a real constraint to handle.
    debug_assert!(size > 0 && size <= MAX_COPY_SIZE);

    let offset_bytes = [
        (offset & 0xff) as u8,
        ((offset >> 8) & 0xff) as u8,
        ((offset >> 16) & 0xff) as u8,
        ((offset >> 24) & 0xff) as u8,
    ];
    let size_bytes = [
        (size & 0xff) as u8,
        ((size >> 8) & 0xff) as u8,
        ((size >> 16) & 0xff) as u8,
    ];

    // Omitted bytes decode as zero (see delta::apply_delta), so only
    // non-zero bytes need to be present - this is the "most compact
    // form" the spec describes, not just a correctness-preserving
    // shortcut.
    let mut opcode: u8 = 0x80;
    let mut payload = Vec::with_capacity(7);
    for (i, &b) in offset_bytes.iter().enumerate() {
        if b != 0 {
            opcode |= 1 << i;
            payload.push(b);
        }
    }
    for (i, &b) in size_bytes.iter().enumerate() {
        if b != 0 {
            opcode |= 1 << (4 + i);
            payload.push(b);
        }
    }

    out.push(opcode);
    out.extend_from_slice(&payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::delta::apply_delta;

    fn roundtrip(base: &[u8], target: &[u8]) {
        let delta = create_delta(base, target);
        let result = apply_delta(base, &delta);
        assert_eq!(
            result,
            target,
            "roundtrip failed for base len {}, target len {}",
            base.len(),
            target.len()
        );
    }

    #[test]
    fn identical_content() {
        let data = b"the quick brown fox jumps over the lazy dog, repeated for length ".repeat(10);
        roundtrip(&data, &data);
    }

    #[test]
    fn small_edit() {
        let base = b"the quick brown fox jumps over the lazy dog".repeat(5);
        let mut target = base.clone();
        target.insert(20, b'!');
        roundtrip(&base, &target);
    }

    #[test]
    fn completely_different() {
        let base = vec![0u8; 200];
        let target: Vec<u8> = (0..200).map(|i| (i * 37 % 256) as u8).collect();
        roundtrip(&base, &target);
    }

    #[test]
    fn target_larger_than_base() {
        let base = b"short base content here, sixteen plus bytes".to_vec();
        let mut target = base.clone();
        target.extend_from_slice(b" and then a lot more appended content that was not in the base at all, padding it out");
        roundtrip(&base, &target);
    }

    #[test]
    fn empty_target() {
        roundtrip(b"some base content of reasonable length here", b"");
    }

    #[test]
    fn base_shorter_than_min_match() {
        roundtrip(b"tiny", b"tiny but now longer");
    }
}
