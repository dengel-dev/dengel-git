//! Parser for pack-*.pack files: header, per-object type+size encoding,
//! and zlib-inflated content for undeltified objects.
//!
//! Format source: git-reference/Documentation/gitformat-pack.adoc
//! (Documentation, not C source - permitted under the clean-room rule).
//! Object-id hashing scheme ("<type> <size>\0<content>", sha1) is
//! public knowledge documented widely outside git's C source (Pro Git,
//! gitoxide, etc.), not derived from it; the differential harness
//! (M1 read-path tests) is what actually confirms this scheme against
//! real git rather than trusting the description.

use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::Read;
use std::path::Path;

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(kind: u8) -> &'static str {
    match kind {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        other => panic!("unknown object type {}", other),
    }
}

#[derive(Debug)]
pub struct PackHeader {
    pub version: u32,
    pub object_count: u32,
}

/// Parse the 12-byte pack file header: 'PACK' signature, 4-byte
/// version (network order), 4-byte object count (network order).
pub fn parse_header(data: &[u8]) -> PackHeader {
    assert!(data.len() >= 12, "pack file too short for header");
    assert_eq!(&data[0..4], b"PACK", "bad pack signature");
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    assert!(
        version == 2 || version == 3,
        "unsupported pack version {}",
        version
    );
    let object_count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    PackHeader {
        version,
        object_count,
    }
}

/// A decoded non-delta object entry: its type, declared uncompressed
/// size, and the byte offset immediately after its header where the
/// zlib-compressed body begins.
struct EntryHeader {
    kind: u8,
    size: u64,
    body_start: usize,
}

/// Decode the variable-length type+size header at `offset`.
///
/// Encoding (packed object header):
///   byte 0: MSB continuation flag, bits 6-4 = type, bits 3-0 = size bits 0-3
///   byte N (while previous MSB set): MSB continuation flag, bits 6-0 =
///     next 7 bits of size, least-significant-first overall.
fn decode_entry_header(data: &[u8], offset: usize) -> EntryHeader {
    let mut pos = offset;
    let first = data[pos];
    pos += 1;

    let kind = (first >> 4) & 0b0111;
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift: u32 = 4;

    let mut more = first & 0x80 != 0;
    while more {
        let byte = data[pos];
        pos += 1;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        more = byte & 0x80 != 0;
    }

    EntryHeader {
        kind,
        size,
        body_start: pos,
    }
}

/// For OFS_DELTA/REF_DELTA entries, the type+size header is followed by
/// a base reference before the zlib body. This computes where the zlib
/// body actually starts, and (for now) the raw base reference bytes,
/// since delta base resolution itself is out of scope until M2.
pub enum BaseRef {
    None,
    Offset(u64),
    Oid([u8; 20]),
}

pub(crate) fn decode_ofs_delta_offset(data: &[u8], offset: usize) -> (u64, usize) {
    // offset encoding: n bytes, MSB set on all but the last; value is
    // built from the lower 7 bits of each byte, with
    // 2^7 + 2^14 + ... added per continuation per gitformat-pack.adoc.
    let mut pos = offset;
    let mut byte = data[pos];
    pos += 1;
    let mut value: u64 = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        byte = data[pos];
        pos += 1;
        value += 1;
        value = (value << 7) | (byte & 0x7f) as u64;
    }
    (value, pos)
}

/// Encode the OFS_DELTA offset value, inverse of decode_ofs_delta_offset
/// above (M4: writer.rs needs this to emit OFS_DELTA entries). Derived
/// directly from the decode recurrence rather than sourced from any
/// doc: decode defines v_1 = B1_low7 and v_i = (v_{i-1}+1)*128 +
/// Bi_low7 for i>=2, so working from the target value V = v_n
/// backwards, each step's low 7 bits give B_i and (v_i >> 7) - 1 gives
/// v_{i-1}, until the remainder is < 128 (that remainder is B1 itself,
/// no bias). Round-trip-tested against decode_ofs_delta_offset in
/// pack::writer's unit tests.
pub(crate) fn encode_ofs_delta_offset(value: u64) -> Vec<u8> {
    let mut digits = Vec::new(); // built as [Bn, B(n-1), ..., B1], reversed after
    let mut cur = value;
    loop {
        digits.push((cur & 0x7f) as u8);
        if cur < 0x80 {
            break;
        }
        cur = (cur >> 7) - 1;
    }
    digits.reverse(); // now [B1, ..., Bn] in transmission order
    let last = digits.len() - 1;
    for b in &mut digits[..last] {
        *b |= 0x80;
    }
    digits
}

/// A raw decoded pack entry. For non-delta types, `content` is the
/// final inflated object bytes. For OBJ_OFS_DELTA/OBJ_REF_DELTA,
/// `content` is the inflated *delta instruction stream* (per
/// gitformat-pack.adoc, "the size above is the size of the delta data
/// that follows") - applying it to the resolved base (see
/// delta::apply_delta) is the caller's job (mod.rs's resolver), since
/// resolving the base may require walking further entries in the pack.
pub struct RawEntry {
    pub kind: u8,
    pub size: u64,
    pub content: Vec<u8>,
    pub base: BaseRef,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn compute_oid(kind: u8, content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(type_name(kind).as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(content);
    hex(&hasher.finalize())
}

/// Read and inflate the object entry at `offset` in `pack_data`. Does
/// not resolve deltas - see module doc on `RawEntry::content`.
pub fn read_raw_entry(pack_data: &[u8], offset: u64) -> RawEntry {
    let header = decode_entry_header(pack_data, offset as usize);

    let (base, zlib_start) = match header.kind {
        OBJ_OFS_DELTA => {
            let (delta_offset, next_pos) = decode_ofs_delta_offset(pack_data, header.body_start);
            let base_offset = offset - delta_offset;
            (BaseRef::Offset(base_offset), next_pos)
        }
        OBJ_REF_DELTA => {
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&pack_data[header.body_start..header.body_start + 20]);
            (BaseRef::Oid(oid), header.body_start + 20)
        }
        _ => (BaseRef::None, header.body_start),
    };

    // For delta entries, `header.size` is the size of the delta stream
    // itself (not the resolved target size - that's encoded inside the
    // delta stream's own header, per gitformat-pack.adoc).
    let mut decoder = ZlibDecoder::new(&pack_data[zlib_start..]);
    let mut content = Vec::with_capacity(header.size as usize);
    decoder
        .read_to_end(&mut content)
        .expect("zlib inflate failed");
    assert_eq!(
        content.len() as u64,
        header.size,
        "inflated size does not match declared size"
    );

    RawEntry {
        kind: header.kind,
        size: header.size,
        content,
        base,
    }
}

pub fn read_pack_file(path: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ofs_delta_offset_roundtrip() {
        let values: Vec<u64> = vec![
            0,
            1,
            0x7f,
            0x80,
            0xff,
            0x3fff,
            0x4000,
            1_000_000,
            u32::MAX as u64,
            (1u64 << 40) + 12345,
        ];
        for v in values {
            let encoded = encode_ofs_delta_offset(v);
            let (decoded, consumed) = decode_ofs_delta_offset(&encoded, 0);
            assert_eq!(
                consumed,
                encoded.len(),
                "value {} did not consume all encoded bytes",
                v
            );
            assert_eq!(decoded, v, "roundtrip mismatch for value {}", v);
            // Every byte except the last must have the continuation bit set.
            for (i, b) in encoded.iter().enumerate() {
                let expect_continuation = i + 1 < encoded.len();
                assert_eq!(
                    b & 0x80 != 0,
                    expect_continuation,
                    "byte {} of encoding of {}",
                    i,
                    v
                );
            }
        }
    }
}
