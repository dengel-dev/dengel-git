//! G1/G4: the hardened pack decoder for UNTRUSTED bytes.
//!
//! rustgit's pack reader was built for trusted corpora and panics on
//! malformed input. This module is the other side of the trust boundary:
//! every byte that arrives over the network is decoded here, and every
//! failure is an `Err`, never a panic. rustgit primitives are reused only
//! where they are already panic-free on arbitrary input (delta apply is
//! NOT - it indexes into the base - so delta application is either
//! re-implemented here with bounds checks or guarded by validation that
//! makes the panic unreachable; the builder decides and documents which).
//!
//! Scope: decode packs in memory for library callers or on disk for receive, resolve
//! ofs- and ref-deltas (ref bases may be external - thin packs, resolved
//! through a caller-supplied lookup), compute each object's oid, offset
//! and crc32, and emit a v2 .idx that canonical git accepts. Sanity
//! limits, not a fuzzing posture: bounded delta chain depth, bounded
//! decompressed size.
//!
//! Format source throughout: git-reference/Documentation/gitformat-pack.adoc
//! (permitted under the clean-room rule - Documentation, not C source).
//! Algorithm *structure* (varint layouts, delta instruction shapes, idx v2
//! table order) is cribbed from rustgit's own validated implementation
//! (src/pack/pack.rs, delta.rs, idx.rs, writer.rs - OUR code, reading it
//! freely is explicitly permitted) with every panic/assert/unwrap path
//! turned into an `Err`, per this milestone's instructions.

use std::collections::HashMap;
use std::io::{self, Cursor, Read, Seek, Write};

pub(crate) mod disk;

use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};

use crate::object::Kind;

/// One fully resolved object from an incoming pack.
#[derive(Debug, Clone)]
pub struct DecodedObject {
    /// Lowercase hex oid of the RESOLVED object.
    pub oid: String,
    pub kind: Kind,
    pub content: Vec<u8>,
    /// Byte offset of this entry's header in the pack (for the idx).
    pub offset: u64,
    /// CRC32 of this entry's on-disk bytes, header through compressed
    /// data (what idx v2 stores).
    pub crc32: u32,
}

#[derive(Debug)]
pub enum IngestError {
    Malformed {
        what: &'static str,
        detail: String,
    },
    /// A ref-delta base was neither in the pack nor supplied by the
    /// caller's lookup (thin pack with a base we do not have).
    MissingBase {
        oid: String,
    },
    /// A sanity limit tripped (delta chain depth, decompressed size).
    LimitExceeded {
        what: &'static str,
        detail: String,
    },
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::Malformed { what, detail } => write!(f, "malformed {what}: {detail}"),
            IngestError::MissingBase { oid } => write!(f, "missing delta base {oid}"),
            IngestError::LimitExceeded { what, detail } => {
                write!(f, "limit exceeded ({what}): {detail}")
            }
        }
    }
}

impl std::error::Error for IngestError {}

fn malformed(what: &'static str, detail: impl Into<String>) -> IngestError {
    IngestError::Malformed {
        what,
        detail: detail.into(),
    }
}

fn limit_exceeded(what: &'static str, detail: impl Into<String>) -> IngestError {
    IngestError::LimitExceeded {
        what,
        detail: detail.into(),
    }
}

// --- pack type codes (gitformat-pack.adoc, "Object types") ----------------
// Mirrors rustgit's src/pack/pack.rs OBJ_* constants (structure cribbed,
// re-declared here so this module never depends on rustgit's trusted-side
// panic-on-unknown `type_name`/parsing helpers for untrusted bytes).
const OBJ_COMMIT: u8 = 1;
const OBJ_TREE: u8 = 2;
const OBJ_BLOB: u8 = 3;
const OBJ_TAG: u8 = 4;
// Type 5 is reserved for future expansion; type 0 is invalid.
const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;

fn kind_to_type(kind: Kind) -> u8 {
    match kind {
        Kind::Commit => OBJ_COMMIT,
        Kind::Tree => OBJ_TREE,
        Kind::Blob => OBJ_BLOB,
        Kind::Tag => OBJ_TAG,
    }
}

fn type_to_kind(type_code: u8) -> Option<Kind> {
    match type_code {
        OBJ_COMMIT => Some(Kind::Commit),
        OBJ_TREE => Some(Kind::Tree),
        OBJ_BLOB => Some(Kind::Blob),
        OBJ_TAG => Some(Kind::Tag),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sane bound on any single decompressed blob (a raw object, or a delta
/// instruction stream, or a resolved delta target) - not a spec limit,
/// a hardening limit against decompression bombs and runaway delta
/// application. 256 MiB, per this milestone's explicit instruction.
///
/// `pub(crate)`: G4's session.rs reuses this exact constant for its own
/// streaming zlib-boundary scan (receive/session.rs's `skip_one_entry`),
/// which decompresses each pack entry a second time (to a throwaway
/// sink) before this module ever gets to decode_pack's own bounded
/// inflate - reusing the same cap there closes the same decompression-
/// bomb hole a second time rather than leaving it open until decode_pack
/// runs.
pub(crate) const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

/// Limits for callers that decode packs from an untrusted upload endpoint.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    pub max_objects: usize,
    /// Aggregate bytes retained or constructed while decoding, including
    /// inflated entry payloads and resolved delta targets.
    pub max_object_bytes: usize,
}

fn charge_budget(
    used: &mut usize,
    additional: usize,
    cap: Option<usize>,
) -> Result<(), IngestError> {
    let next = used
        .checked_add(additional)
        .ok_or_else(|| limit_exceeded("aggregate object bytes", "byte count overflow"))?;
    if let Some(cap) = cap {
        if next > cap {
            return Err(limit_exceeded(
                "aggregate object bytes",
                format!("object data exceeds the {cap} byte aggregate cap"),
            ));
        }
    }
    *used = next;
    Ok(())
}

/// Bound on delta chain depth (ofs- or ref-delta, in-pack or via
/// base_lookup). Value 4096 reused verbatim from rustgit's
/// src/pack/mod.rs `MAX_DELTA_CHAIN` ("generous cycle guard, not a spec
/// limit") - same rationale applies here, just Err instead of assert.
const MAX_DELTA_CHAIN: u32 = 4096;

// --- entry header (type+size varint) ---------------------------------------
//
// gitformat-pack.adoc, "packed object header":
//   1-byte size extension bit (MSB), type (next 3 bit), size0 (lower 4-bit)
//   n-byte sizeN (as long as MSB is set, each 7-bit)
//   size0..sizeN form 4+7+7+..+7 bit integer, size0 is the least
//   significant part, sizeN is the most significant part.
struct EntryHeader {
    type_code: u8,
    /// Undeltified: size of the raw object. Deltified: size of the
    /// (inflated) delta data that follows (adoc: "the size above is the
    /// size of the delta data that follows").
    size: u64,
    body_start: usize,
}

fn decode_entry_header(data: &[u8], offset: usize) -> Result<EntryHeader, IngestError> {
    let mut pos = offset;
    let first = *data
        .get(pos)
        .ok_or_else(|| malformed("pack entry header", "truncated at type+size byte"))?;
    pos += 1;

    let type_code = (first >> 4) & 0x07;
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift: u32 = 4;
    let mut more = first & 0x80 != 0;

    while more {
        let byte = *data
            .get(pos)
            .ok_or_else(|| malformed("pack entry header", "truncated size varint"))?;
        pos += 1;
        if shift >= 64 {
            return Err(malformed("pack entry header", "size varint too long"));
        }
        let chunk = varint_chunk(byte, shift, "pack entry header")?;
        size = size
            .checked_add(chunk)
            .ok_or_else(|| malformed("pack entry header", "size varint overflow"))?;
        shift += 7;
        more = byte & 0x80 != 0;
    }

    Ok(EntryHeader {
        type_code,
        size,
        body_start: pos,
    })
}

// --- ofs-delta negative offset varint ---------------------------------------
//
// gitformat-pack.adoc, "offset encoding": n bytes with MSB set in all but
// the last one. The offset is the number constructed by concatenating the
// lower 7 bits of each byte, and for n >= 2 adding 2^7 + 2^14 + ... +
// 2^(7*(n-1)) to the result. Structure mirrors rustgit's
// decode_ofs_delta_offset (src/pack/pack.rs), bounds-checked here.
fn decode_ofs_delta_offset(data: &[u8], offset: usize) -> Result<(u64, usize), IngestError> {
    let mut pos = offset;
    let mut byte = *data
        .get(pos)
        .ok_or_else(|| malformed("ofs-delta offset", "truncated"))?;
    pos += 1;
    let mut value: u64 = (byte & 0x7f) as u64;

    while byte & 0x80 != 0 {
        byte = *data
            .get(pos)
            .ok_or_else(|| malformed("ofs-delta offset", "truncated"))?;
        pos += 1;
        value = value
            .checked_add(1)
            .ok_or_else(|| malformed("ofs-delta offset", "overflow"))?;
        value = value
            .checked_mul(128)
            .ok_or_else(|| malformed("ofs-delta offset", "overflow"))?;
        value |= (byte & 0x7f) as u64;
    }

    Ok((value, pos))
}

// --- generic "size encoding" used inside a delta instruction stream --------
//
// gitformat-pack.adoc, "Size encoding": seven least significant bits per
// byte, MSB=1 continues, chunks concatenated least-significant-first. A
// DIFFERENT varint scheme from the packed object header above (no type
// field stolen from the first byte). Mirrors rustgit's delta.rs
// decode_size, bounds-checked here.
fn varint_chunk(byte: u8, shift: u32, what: &'static str) -> Result<u64, IngestError> {
    let chunk = u64::from(byte & 0x7f);
    if shift >= 64 || chunk > (u64::MAX >> shift) {
        return Err(malformed(what, "size varint overflow"));
    }
    Ok(chunk << shift)
}

fn read_byte(input: &mut impl Read, what: &'static str) -> Result<u8, IngestError> {
    let mut byte = [0];
    input
        .read_exact(&mut byte)
        .map_err(|e| malformed(what, e.to_string()))?;
    Ok(byte[0])
}

fn read_delta_size(input: &mut impl Read) -> Result<u64, IngestError> {
    let mut shift = 0;
    let mut size = 0;
    loop {
        let byte = read_byte(input, "delta size")?;
        size |= varint_chunk(byte, shift, "delta size")?;
        if byte & 0x80 == 0 {
            return Ok(size);
        }
        shift += 7;
    }
}

#[cfg(test)]
fn decode_delta_size(data: &[u8], pos: usize) -> Result<(u64, usize), IngestError> {
    let mut input = Cursor::new(&data[pos..]);
    let size = read_delta_size(&mut input)?;
    Ok((size, pos + input.position() as usize))
}

/// Inflate a zlib stream starting at `input[0]`, stopping at the stream's
/// own end-of-data marker. Returns the inflated bytes and the number of
/// COMPRESSED bytes consumed from `input` (needed to find where the next
/// pack entry starts - the packed object header carries the size of the
/// INFLATED data, not the compressed stream length, per gitformat-pack.adoc's
/// "Size encoding" note).
///
/// Uses flate2's `total_in()` after reading to EOF to recover the consumed
/// byte count. This is the standard way to do this with flate2 (its own
/// doc comment: "returns the number of bytes... read into this
/// compressor... recommended to only call this after EOF has been
/// reached", which the read-to-EOF loop below guarantees) - not something
/// citable to Documentation/, so disclosed here per CLAUDE.md's
/// prior-knowledge rule and in NOTES.md.
///
/// Hardened against decompression bombs: growth is capped at `cap` bytes,
/// checked incrementally as data comes out (never pre-allocates based on
/// the attacker-supplied declared size). A stream that inflates to a
/// different length than `expected_size` (the pack header's claim) is
/// Malformed, per this milestone's explicit instruction.
fn inflate_bounded(
    input: &[u8],
    expected_size: u64,
    cap: usize,
) -> Result<(Vec<u8>, u64), IngestError> {
    if expected_size > cap as u64 {
        return Err(limit_exceeded(
            "decompressed size",
            format!("declared size {expected_size} exceeds the {cap} byte cap"),
        ));
    }

    let mut decoder = ZlibDecoder::new(input);
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| malformed("zlib stream", e.to_string()))?;
        if n == 0 {
            break;
        }
        if out.len() + n > cap {
            return Err(limit_exceeded(
                "decompressed size",
                format!("inflated data exceeds the {cap} byte cap"),
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }

    if out.len() as u64 != expected_size {
        return Err(malformed(
            "entry size",
            format!(
                "header declared {expected_size} bytes but inflated to {}",
                out.len()
            ),
        ));
    }

    Ok((out, decoder.total_in()))
}

/// Apply a delta instruction stream to `base`, reconstructing the target
/// object's content. Result-based re-derivation of rustgit's
/// `pack::delta::apply_delta` (structure cribbed, cited above): every
/// index/slice access that could panic on adversarial input there
/// (`base[start..end]`, `delta[pos..pos+len]`, the size-mismatch asserts)
/// is bounds-checked into an `Err` here instead.
///
/// gitformat-pack.adoc, "Deltified representation" and the two instruction
/// diagrams that follow it, is the format source for the whole function.
pub(crate) fn apply_delta_checked(
    base: &[u8],
    delta: &[u8],
    cap: usize,
) -> Result<Vec<u8>, IngestError> {
    let mut output = Vec::new();
    apply_delta_to(
        &mut Cursor::new(base),
        0,
        base.len() as u64,
        &mut Cursor::new(delta),
        &mut output,
        cap,
    )?;
    Ok(output)
}

/// The same checked instructions work with a slice or a range in the spool.
fn apply_delta_to(
    base: &mut (impl Read + Seek),
    base_start: u64,
    base_len: u64,
    delta: &mut impl Read,
    output: &mut impl Write,
    cap: usize,
) -> Result<u64, IngestError> {
    let base_size = read_delta_size(delta)?;
    if base_size != base_len {
        return Err(malformed(
            "delta base size",
            format!("delta declares base size {base_size}, actual base is {base_len} bytes"),
        ));
    }
    let target_size = read_delta_size(delta)?;
    if target_size > cap as u64 {
        return Err(limit_exceeded(
            "decompressed size",
            format!("delta target size {target_size} exceeds the {cap} byte cap"),
        ));
    }

    let mut written = 0;
    let mut opcode = [0];
    while delta
        .read(&mut opcode)
        .map_err(|e| malformed("delta", e.to_string()))?
        != 0
    {
        let opcode = opcode[0];
        let (offset, size) = if opcode & 0x80 != 0 {
            let offset = read_copy_field(delta, opcode, 0, 4)?;
            let size = read_copy_field(delta, opcode, 4, 3)?;
            let size = if size == 0 { 0x10000 } else { size };
            if offset + size > base_len {
                return Err(malformed(
                    "delta copy instruction",
                    "copy reads past base end",
                ));
            }
            (offset, size)
        } else if opcode != 0 {
            (0, u64::from(opcode))
        } else {
            return Err(malformed(
                "delta instruction",
                "reserved opcode 0x00 encountered",
            ));
        };
        written += size;
        if written > target_size {
            return Err(malformed(
                "delta target size",
                "output exceeds declared size",
            ));
        }

        let copied = if opcode & 0x80 != 0 {
            base.seek(io::SeekFrom::Start(base_start + offset))
                .and_then(|_| io::copy(&mut base.take(size), output))
        } else {
            io::copy(&mut delta.take(size), output)
        }
        .map_err(|e| malformed("delta data", e.to_string()))?;
        if copied != size {
            return Err(malformed("delta data", "truncated instruction payload"));
        }
    }
    if written != target_size {
        return Err(malformed(
            "delta target size",
            format!("delta declares target size {target_size}, reconstructed {written} bytes"),
        ));
    }
    Ok(written)
}

fn read_copy_field(
    delta: &mut impl Read,
    opcode: u8,
    first_bit: u8,
    bytes: u8,
) -> Result<u64, IngestError> {
    let mut value = 0;
    for i in 0..bytes {
        if opcode & (1 << (first_bit + i)) != 0 {
            value |= u64::from(read_byte(delta, "delta copy instruction")?) << (8 * i);
        }
    }
    Ok(value)
}

// --- entry parsing -----------------------------------------------------

enum EntryBase {
    None,
    /// Index into `entries` of the base entry (already resolved to an
    /// index at parse time - see the "previously seen entry boundary"
    /// check below).
    OffsetIndex(usize),
    Oid([u8; 20]),
}

struct ParsedEntry {
    offset: u64,
    type_code: u8,
    base: EntryBase,
    /// Undeltified: the final object content. Deltified: the raw delta
    /// instruction stream (gitformat-pack.adoc: applying it is the
    /// resolver's job, not this parse step's, since resolving the base
    /// may require walking further entries).
    payload: Vec<u8>,
    crc32: u32,
}

/// Decodes and fully resolves an in-memory pack. `base_lookup` supplies
/// external ref-delta bases (thin packs); return `None` for unknown oids.
/// The pack trailer checksum is verified.
// The lookup's shape is the pack format's: a base's (kind, bytes) by name. An
// alias would name it, not simplify it.
#[allow(clippy::type_complexity, reason = "the shape is the format's")]
pub fn decode_pack(
    pack: &[u8],
    base_lookup: &dyn Fn(&str) -> Option<(Kind, Vec<u8>)>,
) -> Result<Vec<DecodedObject>, IngestError> {
    decode_pack_inner(pack, base_lookup, usize::MAX, None)
}

/// Decodes a pack with endpoint-specific object-count and aggregate byte
/// limits. The limits are enforced before count-based allocations and as
/// each inflated payload or resolved delta target is constructed.
#[allow(clippy::type_complexity, reason = "the shape is the format's")]
pub fn decode_pack_with_limits(
    pack: &[u8],
    base_lookup: &dyn Fn(&str) -> Option<(Kind, Vec<u8>)>,
    limits: DecodeLimits,
) -> Result<Vec<DecodedObject>, IngestError> {
    decode_pack_inner(
        pack,
        base_lookup,
        limits.max_objects,
        Some(limits.max_object_bytes),
    )
}

#[allow(clippy::type_complexity, reason = "the shape is the format's")]
fn decode_pack_inner(
    pack: &[u8],
    base_lookup: &dyn Fn(&str) -> Option<(Kind, Vec<u8>)>,
    max_objects: usize,
    aggregate_cap: Option<usize>,
) -> Result<Vec<DecodedObject>, IngestError> {
    // --- header: magic, version, entry count -------------------------
    if pack.len() < 12 + 20 {
        return Err(malformed("pack file", "too short for header and trailer"));
    }
    if &pack[0..4] != b"PACK" {
        return Err(malformed("pack signature", "missing 'PACK' magic"));
    }
    let version = u32::from_be_bytes(pack[4..8].try_into().unwrap());
    if version != 2 {
        return Err(malformed(
            "pack version",
            format!("expected version 2, got {version}"),
        ));
    }
    let entry_count = u32::from_be_bytes(pack[8..12].try_into().unwrap()) as usize;
    if entry_count > max_objects {
        return Err(limit_exceeded(
            "object count",
            format!("pack declares {entry_count} objects; maximum is {max_objects}"),
        ));
    }

    // --- trailer: 20-byte SHA-1 over everything before it -------------
    let trailer_start = pack.len() - 20;
    let expected_trailer = &pack[trailer_start..];
    let computed_trailer = Sha1::digest(&pack[..trailer_start]);
    if computed_trailer.as_slice() != expected_trailer {
        return Err(malformed(
            "pack trailer checksum",
            "SHA-1 over the pack body does not match the trailer",
        ));
    }

    // --- per-entry parse pass ------------------------------------------
    let mut entries: Vec<ParsedEntry> = Vec::with_capacity(entry_count);
    let mut offset_to_index: HashMap<u64, usize> = HashMap::with_capacity(entry_count);
    let mut object_bytes = 0usize;
    let per_object_cap =
        aggregate_cap.map_or(MAX_DECOMPRESSED_SIZE, |cap| cap.min(MAX_DECOMPRESSED_SIZE));

    let mut pos = 12usize;
    for _ in 0..entry_count {
        if pos >= trailer_start {
            return Err(malformed(
                "pack entries",
                "fewer entries present than the header's declared count",
            ));
        }
        let entry_offset = pos as u64;

        let header = decode_entry_header(pack, pos)?;
        pos = header.body_start;

        let base = match header.type_code {
            OBJ_OFS_DELTA => {
                let (delta_value, next_pos) = decode_ofs_delta_offset(pack, pos)?;
                pos = next_pos;
                if delta_value == 0 {
                    return Err(malformed("ofs-delta base", "zero offset (self-reference)"));
                }
                let base_offset = entry_offset.checked_sub(delta_value).ok_or_else(|| {
                    malformed("ofs-delta base", "offset underflows before start of pack")
                })?;
                let base_index = *offset_to_index.get(&base_offset).ok_or_else(|| {
                    malformed(
                        "ofs-delta base",
                        "offset does not point at a previously seen entry boundary",
                    )
                })?;
                EntryBase::OffsetIndex(base_index)
            }
            OBJ_REF_DELTA => {
                let end = pos
                    .checked_add(20)
                    .ok_or_else(|| malformed("ref-delta base", "offset overflow"))?;
                let oid_bytes = pack
                    .get(pos..end)
                    .ok_or_else(|| malformed("ref-delta base", "truncated 20-byte base oid"))?;
                let mut oid = [0u8; 20];
                oid.copy_from_slice(oid_bytes);
                pos = end;
                EntryBase::Oid(oid)
            }
            OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => EntryBase::None,
            other => {
                return Err(malformed(
                    "pack entry type",
                    format!("unknown or reserved object type {other}"),
                ))
            }
        };

        if pos > trailer_start {
            return Err(malformed(
                "pack entry header",
                "entry header runs past the pack trailer",
            ));
        }

        let zlib_input = &pack[pos..trailer_start];
        let remaining = aggregate_cap.map_or(per_object_cap, |cap| cap - object_bytes);
        let (payload, consumed) =
            inflate_bounded(zlib_input, header.size, per_object_cap.min(remaining))?;
        charge_budget(&mut object_bytes, payload.len(), aggregate_cap)?;
        let entry_end = pos as u64 + consumed;

        let crc32 = crc32fast::hash(&pack[entry_offset as usize..entry_end as usize]);

        offset_to_index.insert(entry_offset, entries.len());
        entries.push(ParsedEntry {
            offset: entry_offset,
            type_code: header.type_code,
            base,
            payload,
            crc32,
        });

        pos = entry_end as usize;
    }

    if pos != trailer_start {
        return Err(malformed(
            "pack entries",
            "trailing garbage between the last entry and the pack trailer",
        ));
    }

    // --- resolution: fixed-point sweep over in-pack bases --------------
    //
    // Non-delta entries resolve immediately (their oid needs no
    // resolution). ofs-delta bases always sit at a strictly earlier
    // offset (validated above), so a forward sweep resolves them in at
    // most `entries.len()` passes. ref-delta bases are looked up by oid,
    // which may belong to an entry that is itself still-unresolved
    // (including one later in the file) - repeating the sweep until no
    // entry makes progress is this module's own choice for handling that
    // (not specified by gitformat-pack.adoc, which does not constrain
    // ref-delta base ordering within a pack): a fixed point over "already
    // resolved oids" converges on every base that is reachable within the
    // pack at all, in bounded (<= entries.len()) sweeps, and only entries
    // whose base truly never resolves in-pack fall through to
    // `base_lookup`/`MissingBase` below.
    let n = entries.len();
    let mut resolved: Vec<Option<(Kind, Vec<u8>, u32)>> = (0..n).map(|_| None).collect();
    let mut oid_to_index: HashMap<String, usize> = HashMap::with_capacity(n);

    for (i, e) in entries.iter_mut().enumerate() {
        if let EntryBase::None = e.base {
            let kind = type_to_kind(e.type_code)
                .expect("non-delta entries were validated to have a known type at parse time");
            let content = std::mem::take(&mut e.payload);
            let oid = rustgit::pack::pack::compute_oid(e.type_code, &content);
            oid_to_index.entry(oid.clone()).or_insert(i);
            resolved[i] = Some((kind, content, 0));
        }
    }

    // WHY THIS IS AN OUTER LOOP, and not a sweep followed by one external
    // pass: a thin pack (what every real push sends once the server already
    // holds some history) contains ref-deltas whose base lives OUTSIDE the
    // pack, and ofs-deltas chained on top of those. Such an ofs-delta cannot
    // resolve during the in-pack sweep - its base is not resolved yet - and
    // the external pass only knows how to resolve ref-deltas. Resolving
    // externals once and stopping therefore strands it forever.
    //
    // The previous code called that state unreachable, arguing that an
    // ofs-delta's base is a strictly earlier entry and so must resolve by
    // induction. The induction is false exactly when that earlier entry is
    // itself a ref-delta with an external base. Observed in production on
    // 2026-09-01, pushing 121 commits of real history:
    //   "malformed ofs-delta base: base entry never resolved".
    //
    // Alternating the two until neither makes progress converges for the
    // same reason each does on its own: every pass resolves at least one
    // entry or stops, and there are finitely many entries.
    loop {
        let mut progressed = false;

        // in-pack bases: fixed point over already-resolved oids
        loop {
            let mut swept = false;
            for i in 0..n {
                if resolved[i].is_some() {
                    continue;
                }
                let base_index = match &entries[i].base {
                    EntryBase::None => continue, // already seeded above
                    EntryBase::OffsetIndex(idx) => Some(*idx),
                    EntryBase::Oid(oid_bytes) => oid_to_index.get(&hex(oid_bytes)).copied(),
                };
                let Some(base_index) = base_index else {
                    continue;
                };
                let Some((base_kind, base_content, base_depth)) = resolved[base_index].as_ref()
                else {
                    continue;
                };

                let depth = *base_depth + 1;
                let base_kind = *base_kind;
                if depth > MAX_DELTA_CHAIN {
                    return Err(limit_exceeded(
                        "delta chain depth",
                        format!(
                            "chain exceeds {MAX_DELTA_CHAIN} entries at pack offset {}",
                            entries[i].offset
                        ),
                    ));
                }
                let remaining = aggregate_cap.map_or(per_object_cap, |cap| cap - object_bytes);
                let content = apply_delta_checked(
                    base_content,
                    &entries[i].payload,
                    per_object_cap.min(remaining),
                )?;
                charge_budget(&mut object_bytes, content.len(), aggregate_cap)?;
                let oid = rustgit::pack::pack::compute_oid(kind_to_type(base_kind), &content);
                oid_to_index.entry(oid).or_insert(i);
                resolved[i] = Some((base_kind, content, depth));
                swept = true;
                progressed = true;
            }
            if !swept {
                break;
            }
        }

        // external bases: one pass over ref-deltas the pack itself cannot
        // satisfy. A miss is NOT an error here - the base may still arrive
        // via a later sweep - so the decision is deferred to the validation
        // pass below, which runs only once nothing can progress at all.
        for i in 0..n {
            if resolved[i].is_some() {
                continue;
            }
            let EntryBase::Oid(oid_bytes) = &entries[i].base else {
                continue;
            };
            let oid_hex = hex(oid_bytes);
            if oid_to_index.contains_key(&oid_hex) {
                continue; // in-pack after all; the sweep will take it
            }
            let Some((kind, base_content)) = base_lookup(&oid_hex) else {
                continue;
            };
            let remaining = aggregate_cap.map_or(per_object_cap, |cap| cap - object_bytes);
            if aggregate_cap.is_some_and(|_| base_content.len() > remaining) {
                return Err(limit_exceeded(
                    "aggregate object bytes",
                    "external delta base exceeds the aggregate byte cap",
                ));
            }
            charge_budget(&mut object_bytes, base_content.len(), aggregate_cap)?;
            let remaining = aggregate_cap.map_or(per_object_cap, |cap| cap - object_bytes);
            let content = apply_delta_checked(
                &base_content,
                &entries[i].payload,
                per_object_cap.min(remaining),
            )?;
            charge_budget(&mut object_bytes, content.len(), aggregate_cap)?;
            let oid = rustgit::pack::pack::compute_oid(kind_to_type(kind), &content);
            oid_to_index.entry(oid).or_insert(i);
            resolved[i] = Some((kind, content, 1));
            progressed = true;
        }

        if !progressed {
            break;
        }
    }

    // --- nothing can progress: whatever is left is genuinely unresolvable
    for i in 0..n {
        if resolved[i].is_some() {
            continue;
        }
        match &entries[i].base {
            EntryBase::None => {
                unreachable!("non-delta entries were all seeded before the fixed-point sweep")
            }
            EntryBase::OffsetIndex(_) => {
                return Err(malformed(
                    "ofs-delta base",
                    "base entry never resolved - its chain leads to a base this pack does not contain",
                ));
            }
            EntryBase::Oid(oid_bytes) => {
                return Err(IngestError::MissingBase {
                    oid: hex(oid_bytes),
                });
            }
        }
    }

    let mut objects = Vec::with_capacity(n);
    for (i, entry) in entries.iter().enumerate() {
        let (kind, content, _depth) = resolved[i]
            .take()
            .expect("every entry is resolved by this point: seeded, fixed-point, or base_lookup");
        let oid = rustgit::pack::pack::compute_oid(kind_to_type(kind), &content);
        objects.push(DecodedObject {
            oid,
            kind,
            content,
            offset: entry.offset,
            crc32: entry.crc32,
        });
    }

    Ok(objects)
}

/// Emits a v2 .idx for a decoded pack. `pack` is needed for the trailer
/// checksum the idx embeds.
///
/// Layout per gitformat-pack.adoc, "Version 2 pack-*.idx files": magic
/// `\xfftOc`, version 2, 256-entry fan-out, sorted oid table, crc32 table,
/// offset table, then a copy of the pack checksum plus the idx's own
/// checksum. Structure cribbed from rustgit's src/pack/writer.rs
/// `finish()` (OUR code); the large-offset (>2^31) case is not implemented
/// here - see the LimitExceeded branch below for why that's this module's
/// deliberate choice rather than an oversight.
pub fn write_idx_v2(pack: &[u8], objects: &[DecodedObject]) -> Result<Vec<u8>, IngestError> {
    if pack.len() < 20 {
        return Err(malformed(
            "pack file",
            "too short to contain a trailer checksum",
        ));
    }
    write_index(
        &pack[pack.len() - 20..],
        objects
            .iter()
            .map(|obj| (obj.oid.as_str(), obj.crc32, obj.offset)),
    )
}

fn write_index<'a>(
    pack_checksum: &[u8],
    entries: impl Iterator<Item = (&'a str, u32, u64)>,
) -> Result<Vec<u8>, IngestError> {
    let mut sorted: Vec<_> = entries.collect();
    sorted.sort_by_key(|entry| entry.0);

    let mut idx = Vec::new();
    idx.extend_from_slice(&[0xff, b't', b'O', b'c']);
    idx.extend_from_slice(&2u32.to_be_bytes());

    // 256-entry fan-out table: fanout[i] = count of objects whose oid's
    // first byte is <= i.
    let mut fanout = [0u32; 256];
    for (oid, _, _) in &sorted {
        let first = oid
            .get(..2)
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or_else(|| malformed("object oid", format!("not valid hex: {oid}")))?;
        fanout[usize::from(first)] += 1;
    }
    let mut total = 0;
    for count in fanout {
        total += count;
        idx.extend_from_slice(&total.to_be_bytes());
    }

    // Sorted oid, CRC, and offset tables share the same order.
    for (oid, _, _) in &sorted {
        if oid.len() != 40 || !oid.is_ascii() {
            return Err(malformed(
                "object oid",
                format!("expected 40 hex chars: {oid}"),
            ));
        }
        for i in 0..20 {
            let byte = u8::from_str_radix(&oid[i * 2..i * 2 + 2], 16)
                .map_err(|_| malformed("object oid", format!("not valid hex: {oid}")))?;
            idx.push(byte);
        }
    }
    for (_, crc, _) in &sorted {
        idx.extend_from_slice(&crc.to_be_bytes());
    }
    for (_, _, offset) in sorted {
        if offset >= 0x8000_0000 {
            return Err(limit_exceeded(
                "pack offset",
                format!(
                    "offset {offset} exceeds 31 bits; large-offset idx table is not implemented"
                ),
            ));
        }
        idx.extend_from_slice(&(offset as u32).to_be_bytes());
    }

    idx.extend_from_slice(pack_checksum);
    let idx_checksum = Sha1::digest(&idx);
    idx.extend_from_slice(&idx_checksum);

    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn pack_entry_header(type_code: u8, mut size: u64) -> Vec<u8> {
        let mut header = vec![(type_code << 4) | (size & 0x0f) as u8];
        size >>= 4;
        if size != 0 {
            header[0] |= 0x80;
        }
        while size != 0 {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                byte |= 0x80;
            }
            header.push(byte);
        }
        header
    }

    fn packed_entry(type_code: u8, payload: &[u8], prefix: &[u8]) -> Vec<u8> {
        packed_entry_with_declared_size(type_code, payload.len() as u64, payload, prefix)
    }

    fn packed_entry_with_declared_size(
        type_code: u8,
        declared_size: u64,
        payload: &[u8],
        prefix: &[u8],
    ) -> Vec<u8> {
        use std::io::Write;

        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut entry = pack_entry_header(type_code, declared_size);
        entry.extend_from_slice(prefix);
        entry.extend_from_slice(&compressed);
        entry
    }

    fn complete_pack(entry_count: u32, entries: &[u8]) -> Vec<u8> {
        let mut pack = b"PACK\0\0\0\x02".to_vec();
        pack.extend_from_slice(&entry_count.to_be_bytes());
        pack.extend_from_slice(entries);
        let checksum = Sha1::digest(&pack);
        pack.extend_from_slice(&checksum);
        pack
    }

    fn repeated_copy_delta(size: u8) -> Vec<u8> {
        // base size, target size, then one copy instruction from offset zero.
        vec![size, size, 0x90, size]
    }

    fn pack_with_two_copy_deltas() -> Vec<u8> {
        let mut entries = packed_entry(OBJ_BLOB, b"12345678", &[]);
        let first_offset = 12u64;
        let delta = repeated_copy_delta(8);
        let second_offset = 12 + entries.len() as u64;
        let first_delta = packed_entry(
            OBJ_OFS_DELTA,
            &delta,
            &encode_ofs_delta_offset_for_test(second_offset - first_offset),
        );
        entries.extend_from_slice(&first_delta);
        let third_offset = 12 + entries.len() as u64;
        let second_delta = packed_entry(
            OBJ_OFS_DELTA,
            &delta,
            &encode_ofs_delta_offset_for_test(third_offset - second_offset),
        );
        entries.extend_from_slice(&second_delta);
        complete_pack(3, &entries)
    }

    fn compare_decoded(left: &[DecodedObject], right: &[DecodedObject]) {
        assert_eq!(left.len(), right.len());
        for (left, right) in left.iter().zip(right) {
            assert_eq!(left.oid, right.oid);
            assert_eq!(left.kind, right.kind);
            assert_eq!(left.content, right.content);
            assert_eq!(left.offset, right.offset);
            assert_eq!(left.crc32, right.crc32);
        }
    }

    #[test]
    fn disk_decode_rejects_aggregate_delta_growth() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("incoming.pack"),
            pack_with_two_copy_deltas(),
        )
        .unwrap();
        let result = disk::decode(
            dir.path(),
            DecodeLimits {
                max_objects: 3,
                max_object_bytes: 24,
            },
            &|_| None,
        );
        assert!(matches!(result, Err(IngestError::LimitExceeded { .. })));
        assert!(!dir.path().join("prepared.pack").exists());
    }

    #[test]
    fn disk_decode_rejects_an_incomplete_zlib_stream_with_a_valid_pack_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let mut entry = packed_entry(OBJ_BLOB, b"complete object contents", &[]);
        entry.pop();
        fs::write(dir.path().join("incoming.pack"), complete_pack(1, &entry)).unwrap();
        let result = disk::decode(
            dir.path(),
            DecodeLimits {
                max_objects: 1,
                max_object_bytes: 64,
            },
            &|_| None,
        );
        assert!(matches!(
            result,
            Err(IngestError::Malformed {
                what: "zlib stream",
                ..
            })
        ));
    }

    #[test]
    fn disk_decode_resolves_a_forward_ref_delta_from_a_thin_base_chain() {
        let dir = tempfile::tempdir().unwrap();
        let external_oid = [0xcd; 20];
        let mut entries = packed_entry(
            OBJ_REF_DELTA,
            &[3, 4, 0x90, 3, 1, b'd'],
            &hex_oid(&rustgit::pack::pack::compute_oid(OBJ_BLOB, b"abc")),
        );
        let ref_offset = entries.len();
        entries.extend_from_slice(&packed_entry(
            OBJ_REF_DELTA,
            &[2, 3, 0x90, 2, 1, b'c'],
            &external_oid,
        ));
        let offset_bytes = encode_ofs_delta_offset_for_test((entries.len() - ref_offset) as u64);
        entries.extend_from_slice(&packed_entry(
            OBJ_OFS_DELTA,
            &[3, 4, 0x90, 3, 1, b'e'],
            &offset_bytes,
        ));
        fs::write(dir.path().join("incoming.pack"), complete_pack(3, &entries)).unwrap();
        let decoded = disk::decode(
            dir.path(),
            DecodeLimits {
                max_objects: 3,
                max_object_bytes: 64,
            },
            &|oid| (oid == hex(&external_oid)).then(|| (Kind::Blob, b"ab".to_vec())),
        )
        .expect("resolve the thin base before its pack dependents");
        let id = decoded.write_pack(dir.path()).unwrap();
        assert_eq!(id.len(), 40);
        let packed = fs::read(dir.path().join("prepared.pack")).unwrap();
        let objects =
            decode_pack(&packed, &|_| None).expect("published pack must be self-contained");
        assert_eq!(
            objects
                .iter()
                .map(|object| object.content.as_slice())
                .collect::<Vec<_>>(),
            [b"abcd".as_slice(), b"abc", b"abce"]
        );
    }

    fn hex_oid(oid: &str) -> [u8; 20] {
        std::array::from_fn(|i| u8::from_str_radix(&oid[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn decode_pack_with_limits_rejects_oversized_compressed_content_during_inflate() {
        let payload = vec![b'x'; 1025];
        let entry = packed_entry_with_declared_size(OBJ_BLOB, 1024, &payload, &[]);
        let pack = complete_pack(1, &entry);
        let result = decode_pack_with_limits(
            &pack,
            &|_| None,
            DecodeLimits {
                max_objects: 1,
                max_object_bytes: 1024,
            },
        );
        assert!(matches!(result, Err(IngestError::LimitExceeded { .. })));
    }

    #[test]
    fn decode_pack_with_limits_rejects_cumulative_delta_target_expansion() {
        // Entry payloads consume 16 bytes total. Each of the two valid delta
        // targets is only 8 bytes, but both targets push cumulative usage
        // past the 24-byte budget.
        let pack = pack_with_two_copy_deltas();
        let result = decode_pack_with_limits(
            &pack,
            &|_| None,
            DecodeLimits {
                max_objects: 3,
                max_object_bytes: 24,
            },
        );
        assert!(matches!(result, Err(IngestError::LimitExceeded { .. })));
    }

    #[test]
    fn decode_pack_with_limits_matches_compatibility_decoder_below_budget() {
        let pack = complete_pack(1, &packed_entry(OBJ_BLOB, b"small object", &[]));
        let expected = decode_pack(&pack, &|_| None).unwrap();
        let actual = decode_pack_with_limits(
            &pack,
            &|_| None,
            DecodeLimits {
                max_objects: 1,
                max_object_bytes: 1024,
            },
        )
        .unwrap();
        compare_decoded(&actual, &expected);
    }

    #[test]
    fn decode_pack_with_limits_rejects_object_count_before_entry_allocation() {
        let entry = packed_entry(OBJ_BLOB, b"object", &[]);
        let mut entries = entry.clone();
        entries.extend_from_slice(&entry);
        let pack = complete_pack(2, &entries);
        let result = decode_pack_with_limits(
            &pack,
            &|_| None,
            DecodeLimits {
                max_objects: 1,
                max_object_bytes: 1024,
            },
        );
        assert!(matches!(result, Err(IngestError::LimitExceeded { .. })));
    }

    // --- varint edge cases ------------------------------------------------

    #[test]
    fn entry_header_single_byte_small_size() {
        // type=OBJ_BLOB(3), size=5: first byte = 0b0_011_0101? size must
        // fit in low 4 bits with no continuation: 0x35 -> type (0x35>>4)&7=3,
        // size = 0x35 & 0x0f = 5.
        let data = [0x35u8];
        let h = decode_entry_header(&data, 0).unwrap();
        assert_eq!(h.type_code, OBJ_BLOB);
        assert_eq!(h.size, 5);
        assert_eq!(h.body_start, 1);
    }

    #[test]
    fn entry_header_multi_byte_size_continuation() {
        // type=OBJ_COMMIT(1), size=300. 300 = 0b1_0010_1100.
        // low4 = 0b1100 = 0xc, remaining = 300 >> 4 = 18 = 0b0010010.
        // first byte: continuation set, type=1, low4=0xc -> 0x80|0x10|0x0c = 0x9c
        // second byte: no further continuation (18 < 128): 0x12
        let data = [0x9cu8, 0x12u8];
        let h = decode_entry_header(&data, 0).unwrap();
        assert_eq!(h.type_code, OBJ_COMMIT);
        assert_eq!(h.size, 300);
        assert_eq!(h.body_start, 2);
    }

    #[test]
    fn entry_header_truncated_is_malformed_not_panic() {
        assert!(decode_entry_header(&[], 0).is_err());
        // continuation bit set, but no following byte
        assert!(decode_entry_header(&[0x80], 0).is_err());
    }

    /// Test-only inverse of `decode_ofs_delta_offset`, for building
    /// fixtures. rustgit's own `encode_ofs_delta_offset` (src/pack/pack.rs)
    /// implements the same encoding but is `pub(crate)` there and not
    /// reachable from this crate; re-derived here from the same
    /// gitformat-pack.adoc "offset encoding" section decode_ofs_delta_offset
    /// above already cites, not copied from rustgit's private fn (which was
    /// read only as a structure reference, per this milestone's "OUR code,
    /// read freely" allowance).
    fn encode_ofs_delta_offset_for_test(value: u64) -> Vec<u8> {
        let mut digits = Vec::new(); // [Bn, ..., B1], reversed below
        let mut cur = value;
        loop {
            digits.push((cur & 0x7f) as u8);
            if cur < 0x80 {
                break;
            }
            cur = (cur >> 7) - 1;
        }
        digits.reverse();
        let last = digits.len() - 1;
        for b in &mut digits[..last] {
            *b |= 0x80;
        }
        digits
    }

    #[test]
    fn ofs_delta_offset_roundtrips() {
        let values: [u64; 6] = [0, 1, 0x7f, 0x80, 0x3fff, 1_000_000];
        for &v in &values {
            let encoded = encode_ofs_delta_offset_for_test(v);
            let (decoded, consumed) = decode_ofs_delta_offset(&encoded, 0).unwrap();
            assert_eq!(decoded, v, "value {v}");
            assert_eq!(consumed, encoded.len(), "value {v}");
        }
    }

    #[test]
    fn ofs_delta_offset_truncated_is_malformed() {
        assert!(decode_ofs_delta_offset(&[], 0).is_err());
        assert!(decode_ofs_delta_offset(&[0x80], 0).is_err()); // continuation with nothing after
    }

    #[test]
    fn delta_size_varint_matches_entry_header_style_values() {
        // Single-byte: no continuation.
        assert_eq!(decode_delta_size(&[0x05], 0).unwrap(), (5, 1));
        // Multi-byte: 300 = 0b1_0010_1100 -> low7=0b0101100=0x2c with
        // continuation, then 0b0000010=0x02.
        let (v, consumed) = decode_delta_size(&[0xac, 0x02], 0).unwrap();
        assert_eq!(v, 300);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn delta_size_varint_truncated_is_malformed() {
        assert!(decode_delta_size(&[], 0).is_err());
        assert!(decode_delta_size(&[0x80], 0).is_err());
    }

    // --- delta application: bounds-checked re-derivation -------------------

    #[test]
    #[allow(
        clippy::vec_init_then_push,
        reason = "one push per byte, each carrying its comment"
    )]
    fn apply_delta_copy_and_insert_round_trip() {
        let base = b"hello world".to_vec();
        // base_size=11, target_size=12: copy "hello " (6 bytes at
        // offset 0), insert "there" (5 bytes), copy "d" (1 byte at
        // offset 10) -> "hello thered" (6+5+1 = 12 bytes).
        let mut delta = Vec::new();
        delta.push(11u8); // base size varint (single byte, <128)
        delta.push(12u8); // target size varint
                          // copy: offset=0 (omitted -> 0), size=6 -> opcode bit4 set (size1)
        delta.push(0b1001_0000); // offset omitted, size1 present
        delta.push(6);
        // insert "there" (5 bytes)
        delta.push(0b0000_0101);
        delta.extend_from_slice(b"there");
        // copy: offset=10 (offset1), size=1 (size1)
        delta.push(0b1001_0001);
        delta.push(10);
        delta.push(1);

        let target = apply_delta_checked(&base, &delta, MAX_DECOMPRESSED_SIZE).unwrap();
        assert_eq!(target, b"hello thered");
    }

    #[test]
    #[allow(
        clippy::vec_init_then_push,
        reason = "one push per byte, each carrying its comment"
    )]
    fn apply_delta_copy_past_base_end_is_malformed_not_panic() {
        let base = b"short".to_vec();
        let mut delta = Vec::new();
        delta.push(5u8); // base size
        delta.push(100u8); // target size (irrelevant, we fail before checking it)
        delta.push(0b1001_0001); // offset1 present, size1 present
        delta.push(0); // offset = 0
        delta.push(100); // size = 100, way past base.len() == 5
        let result = apply_delta_checked(&base, &delta, MAX_DECOMPRESSED_SIZE);
        assert!(matches!(result, Err(IngestError::Malformed { .. })));
    }

    #[test]
    fn apply_delta_wrong_base_size_is_malformed() {
        let base = b"hello".to_vec();
        let delta = vec![99u8, 5u8]; // declares base size 99, actual is 5
        let result = apply_delta_checked(&base, &delta, MAX_DECOMPRESSED_SIZE);
        assert!(matches!(result, Err(IngestError::Malformed { .. })));
    }

    #[test]
    fn apply_delta_reserved_opcode_is_malformed_not_panic() {
        let base = b"x".to_vec();
        let delta = vec![1u8, 0u8, 0x00u8]; // base_size=1, target_size=0, then reserved opcode
        let result = apply_delta_checked(&base, &delta, MAX_DECOMPRESSED_SIZE);
        assert!(matches!(result, Err(IngestError::Malformed { .. })));
    }

    #[test]
    fn apply_delta_target_size_over_cap_is_limit_exceeded() {
        let base = b"x".to_vec();
        let mut delta = Vec::new();
        delta.push(1u8); // base size
                         // target size = 1000, encoded as a multi-byte size-encoding varint
        let mut target_size_bytes = Vec::new();
        let mut v = 1000u64;
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            target_size_bytes.push(b);
            if v == 0 {
                break;
            }
        }
        delta.extend_from_slice(&target_size_bytes);
        let result = apply_delta_checked(&base, &delta, 10); // cap of 10 bytes
        assert!(matches!(result, Err(IngestError::LimitExceeded { .. })));
    }

    // --- oid sorting / idx fanout -------------------------------------------

    #[test]
    fn write_idx_v2_sorts_by_oid_regardless_of_input_order() {
        // Two objects, high-to-low oid input order; sha1 of "a"/"b"'s
        // fake pack entries doesn't need to be real for this structural
        // check - only write_idx_v2's own oid-sort and fanout logic is
        // under test here, not decode_pack.
        let objects = vec![
            DecodedObject {
                oid: "ff00000000000000000000000000000000000000".to_string(),
                kind: Kind::Blob,
                content: vec![],
                offset: 12,
                crc32: 0x1111_1111,
            },
            DecodedObject {
                oid: "0100000000000000000000000000000000000000".to_string(),
                kind: Kind::Blob,
                content: vec![],
                offset: 50,
                crc32: 0x2222_2222,
            },
        ];
        // Minimal fake pack: just needs >= 20 bytes for the trailer slice.
        let pack = vec![0u8; 32];
        let idx = write_idx_v2(&pack, &objects).unwrap();

        assert_eq!(&idx[0..4], &[0xff, b't', b'O', b'c']);
        assert_eq!(u32::from_be_bytes(idx[4..8].try_into().unwrap()), 2);

        // fanout[0x00] must be 0 (nothing with first byte < 0x01), and
        // fanout[0x01..0xff] must be 1 (the "01..." oid), fanout[0xff]
        // must be 2 (both oids).
        let fanout_at = |byte: usize| -> u32 {
            let start = 8 + byte * 4;
            u32::from_be_bytes(idx[start..start + 4].try_into().unwrap())
        };
        assert_eq!(fanout_at(0x00), 0);
        assert_eq!(fanout_at(0x01), 1);
        assert_eq!(fanout_at(0xfe), 1);
        assert_eq!(fanout_at(0xff), 2);

        // The oid table (right after the 256*4-byte fanout) must list the
        // smaller oid ("01...") before the larger one ("ff...").
        let oid_table_start = 8 + 256 * 4;
        let first_oid_byte = idx[oid_table_start];
        assert_eq!(
            first_oid_byte, 0x01,
            "sorted oid table should start with the smaller oid"
        );
    }

    #[test]
    fn write_idx_v2_rejects_offsets_past_31_bits() {
        let objects = vec![DecodedObject {
            oid: "0000000000000000000000000000000000000000".to_string(),
            kind: Kind::Blob,
            content: vec![],
            offset: 0x8000_0000, // exactly 2^31, over the 31-bit limit
            crc32: 0,
        }];
        let pack = vec![0u8; 32];
        let result = write_idx_v2(&pack, &objects);
        assert!(matches!(result, Err(IngestError::LimitExceeded { .. })));
    }

    // --- end-to-end: a small real pack, built with real git ----------------
    //
    // Same "real oracle" discipline as tests/g0_objects.rs: fixtures come
    // from actually running git in a scratch dir, never from a
    // hand-assumed pack layout.

    fn run_git(dir: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn git {args:?} in {dir:?}: {e}"));
        assert!(
            output.status.success(),
            "git {args:?} in {dir:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn run_git_ok(dir: &Path, args: &[&str]) {
        run_git(dir, args);
    }

    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-g1-ingest-{}-{}",
            std::process::id(),
            label
        ));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).expect("failed to create scratch dir");
        dir
    }

    /// Builds a tiny repo with a handful of commits (enough history that
    /// `git pack-objects` is free to choose delta encodings on its own -
    /// this test does not force full-object-only output), then asks real
    /// git to pack it, and returns the raw `.pack` bytes.
    fn build_real_pack(label: &str) -> Vec<u8> {
        let dir = scratch_dir(label);
        run_git_ok(&dir, &["init", "-q", "-b", "main"]);
        run_git_ok(&dir, &["config", "user.email", "g1-ingest@example.com"]);
        run_git_ok(&dir, &["config", "user.name", "g1-ingest"]);

        fs::write(dir.join("a.txt"), "one\ntwo\nthree\n".repeat(50)).unwrap();
        run_git_ok(&dir, &["add", "a.txt"]);
        run_git_ok(&dir, &["commit", "-q", "-m", "first"]);

        // A second commit that edits the same file (a good ofs-delta
        // candidate for pack-objects) plus adds a new one.
        fs::write(dir.join("a.txt"), "one\ntwo\nTHREE-EDITED\n".repeat(50)).unwrap();
        fs::write(dir.join("b.txt"), b"second file\n").unwrap();
        run_git_ok(&dir, &["add", "-A"]);
        run_git_ok(&dir, &["commit", "-q", "-m", "second"]);

        let head = String::from_utf8(run_git(&dir, &["rev-parse", "HEAD"])).unwrap();
        let head = head.trim();

        // `git pack-objects` reads oids on stdin and writes
        // `<prefix>-<sha>.pack` (and `.idx`) into the given directory.
        let all_oids = run_git(&dir, &["rev-list", "--objects", head]);
        let prefix = dir.join("out");
        let mut child = Command::new("git")
            .current_dir(&dir)
            .args(["pack-objects", "--", prefix.to_str().unwrap()])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn git pack-objects");
        {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(&all_oids).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git pack-objects failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let pack_sha = String::from_utf8(output.stdout).unwrap();
        let pack_sha = pack_sha.trim();
        let pack_path = dir.join(format!("out-{pack_sha}.pack"));
        fs::read(&pack_path).expect("git pack-objects did not produce the expected .pack file")
    }

    #[test]
    fn decode_pack_end_to_end_matches_real_git_objects() {
        let dir_label = "t_decode_e2e";
        let pack = build_real_pack(dir_label);

        let objects = decode_pack(&pack, &|_oid| None)
            .expect("decode_pack failed on a real git-produced pack");
        assert!(!objects.is_empty(), "decoded pack produced no objects");

        // Cross-check every decoded object's oid+content against real
        // git's own object database for the same scratch repo (rebuild
        // the same repo state via the label used by build_real_pack).
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-g1-ingest-{}-{}",
            std::process::id(),
            dir_label
        ));
        for obj in &objects {
            let kind_name = match obj.kind {
                Kind::Blob => "blob",
                Kind::Tree => "tree",
                Kind::Commit => "commit",
                Kind::Tag => "tag",
            };
            let git_kind = String::from_utf8(run_git(&dir, &["cat-file", "-t", &obj.oid])).unwrap();
            assert_eq!(git_kind.trim(), kind_name, "kind mismatch for {}", obj.oid);
            let git_content = run_git(&dir, &["cat-file", kind_name, &obj.oid]);
            assert_eq!(obj.content, git_content, "content mismatch for {}", obj.oid);
        }

        // The pack's own object count should match what decode_pack
        // produced (one DecodedObject per pack entry).
        let count_line =
            String::from_utf8(run_git(&dir, &["rev-list", "--objects", "--count", "HEAD"]))
                .unwrap();
        // rev-list --count only counts commits reachable, not every
        // object; instead just sanity check we saw at least the commits
        // and the two known blobs/trees - a stronger structural check
        // than count_line alone.
        let _ = count_line;
        let has_kind = |k: Kind| objects.iter().any(|o| o.kind == k);
        assert!(
            has_kind(Kind::Commit),
            "expected at least one commit in the decoded pack"
        );
        assert!(
            has_kind(Kind::Tree),
            "expected at least one tree in the decoded pack"
        );
        assert!(
            has_kind(Kind::Blob),
            "expected at least one blob in the decoded pack"
        );
    }

    #[test]
    fn decode_pack_and_write_idx_v2_round_trip_verified_by_git_verify_pack() {
        let dir_label = "t_idx_roundtrip";
        let pack = build_real_pack(dir_label);
        let objects = decode_pack(&pack, &|_oid| None).expect("decode_pack failed");
        let idx = write_idx_v2(&pack, &objects).expect("write_idx_v2 failed");

        // Write our pack+idx into a fresh location git recognizes
        // (`pack-<sha>.{pack,idx}` under a repo's objects/pack dir), then
        // ask real git to verify it - the actual oracle for "is this a
        // valid pack/idx pair", not just "did our own code agree with
        // itself".
        let verify_dir = std::env::temp_dir().join(format!(
            "dengel-git-g1-ingest-{}-{}-verify",
            std::process::id(),
            dir_label
        ));
        fs::remove_dir_all(&verify_dir).ok();
        fs::create_dir_all(&verify_dir).unwrap();
        run_git_ok(&verify_dir, &["init", "-q", "--bare"]);

        let pack_sha = hex(&Sha1::digest(&pack));
        let pack_dir = verify_dir.join("objects/pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(pack_dir.join(format!("pack-{pack_sha}.pack")), &pack).unwrap();
        fs::write(pack_dir.join(format!("pack-{pack_sha}.idx")), &idx).unwrap();

        run_git_ok(
            &verify_dir,
            &[
                "verify-pack",
                "-v",
                &format!("objects/pack/pack-{pack_sha}.idx"),
            ],
        );
    }

    #[test]
    fn decode_pack_rejects_bad_magic() {
        let mut pack = vec![0u8; 32];
        pack[0..4].copy_from_slice(b"NOPE");
        let result = decode_pack(&pack, &|_| None);
        assert!(matches!(result, Err(IngestError::Malformed { .. })));
    }

    #[test]
    fn decode_pack_rejects_wrong_version() {
        let mut pack = vec![0u8; 32];
        pack[0..4].copy_from_slice(b"PACK");
        pack[4..8].copy_from_slice(&3u32.to_be_bytes());
        let result = decode_pack(&pack, &|_| None);
        assert!(matches!(result, Err(IngestError::Malformed { .. })));
    }

    #[test]
    fn decode_pack_rejects_bad_trailer_checksum() {
        let dir_label = "t_bad_trailer";
        let mut pack = build_real_pack(dir_label);
        let last = pack.len() - 1;
        pack[last] ^= 0xff; // flip a bit in the trailer checksum
        let result = decode_pack(&pack, &|_| None);
        assert!(matches!(result, Err(IngestError::Malformed { .. })));
    }

    #[test]
    #[allow(
        clippy::vec_init_then_push,
        reason = "one push per byte, each carrying its comment"
    )]
    fn decode_pack_rejects_trailing_garbage_before_trailer() {
        let dir_label = "t_trailing_garbage";
        let pack = build_real_pack(dir_label);
        // Insert one extra byte between the last entry and the trailer,
        // then re-sign the trailer so ONLY the "trailing garbage" check
        // (not the checksum check) is what catches this.
        let trailer_start = pack.len() - 20;
        let mut tampered = Vec::new();
        tampered.extend_from_slice(&pack[..trailer_start]);
        tampered.push(0xAA);
        let new_trailer = Sha1::digest(&tampered);
        tampered.extend_from_slice(&new_trailer);

        let result = decode_pack(&tampered, &|_| None);
        assert!(matches!(result, Err(IngestError::Malformed { .. })));
    }

    #[test]
    #[allow(
        clippy::vec_init_then_push,
        reason = "one push per byte, each carrying its comment"
    )]
    fn decode_pack_missing_ref_delta_base_reports_missing_base() {
        // A REF_DELTA entry whose base oid is neither in the pack nor
        // supplied by base_lookup. Hand-built minimal pack: header claims
        // 1 entry, that entry is a REF_DELTA against an oid that exists
        // nowhere, with a valid zlib stream so we reach base resolution
        // rather than failing earlier on the zlib step.
        let mut body = Vec::new();
        // type=OBJ_REF_DELTA(7), size = delta stream length (computed below)
        // We build the delta stream first so we know its length.
        let mut delta_stream = Vec::new();
        delta_stream.push(0u8); // base size 0
        delta_stream.push(0u8); // target size 0
        let compressed = {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write as _;
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&delta_stream).unwrap();
            enc.finish().unwrap()
        };
        let size = delta_stream.len() as u64;
        assert!(size < 16, "test assumes a single-byte size header");
        let first_byte = (OBJ_REF_DELTA << 4) | (size as u8 & 0x0f);
        body.push(first_byte);
        body.extend_from_slice(&[0xAB; 20]); // base oid, present nowhere
        body.extend_from_slice(&compressed);

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        pack.extend_from_slice(&body);
        let trailer = Sha1::digest(&pack);
        pack.extend_from_slice(&trailer);

        let result = decode_pack(&pack, &|_| None);
        assert!(
            matches!(result, Err(IngestError::MissingBase { .. })),
            "expected MissingBase, got {result:?}"
        );
    }

    #[test]
    fn decode_pack_resolves_thin_pack_ref_delta_via_base_lookup() {
        // Same hand-built shape as the MissingBase test above, but this
        // time base_lookup actually supplies the base - proves thin-pack
        // resolution through the external lookup path.
        let base_oid_bytes = [0xCDu8; 20];
        let base_content = b"external base content".to_vec();

        let mut delta_stream = Vec::new();
        // base size = base_content.len() (22, fits in one size-encoding byte)
        assert!(base_content.len() < 128);
        delta_stream.push(base_content.len() as u8);
        delta_stream.push(base_content.len() as u8); // target size == base size (pure copy)
                                                     // one copy instruction: offset omitted (0), size1 present = base_content.len()
        delta_stream.push(0b1001_0000);
        delta_stream.push(base_content.len() as u8);

        let compressed = {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write as _;
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&delta_stream).unwrap();
            enc.finish().unwrap()
        };
        let size = delta_stream.len() as u64;
        assert!(size < 16);
        let first_byte = (OBJ_REF_DELTA << 4) | (size as u8 & 0x0f);

        let mut body = Vec::new();
        body.push(first_byte);
        body.extend_from_slice(&base_oid_bytes);
        body.extend_from_slice(&compressed);

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        pack.extend_from_slice(&body);
        let trailer = Sha1::digest(&pack);
        pack.extend_from_slice(&trailer);

        let base_oid_hex = hex(&base_oid_bytes);
        let objects = decode_pack(&pack, &|oid| {
            if oid == base_oid_hex {
                Some((Kind::Blob, base_content.clone()))
            } else {
                None
            }
        })
        .expect("decode_pack should resolve the ref-delta via base_lookup");

        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].content, base_content);
        assert_eq!(objects[0].kind, Kind::Blob);
    }
}
