//! Delta instruction decoding and application (M2: delta resolution).
//!
//! Format source: git-reference/Documentation/gitformat-pack.adoc,
//! sections "Size encoding" and "Deltified representation"
//! (Documentation, not C source - permitted under the clean-room rule).

/// Generic "size encoding" from gitformat-pack.adoc: seven least
/// significant bits per byte, MSB=1 means continue, chunks
/// concatenated least-significant-first. This is a DIFFERENT varint
/// scheme from the packed object header's type+size byte (which
/// steals 3 bits for type in its first byte) - delta headers use the
/// plain form since there's no type field here.
fn decode_size(data: &[u8], pos: usize) -> (u64, usize) {
    let mut shift: u32 = 0;
    let mut result: u64 = 0;
    let mut p = pos;
    loop {
        let byte = data[p];
        p += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    (result, p)
}

/// Apply a delta instruction stream to `base`, reconstructing the
/// target object's content.
///
/// Delta stream layout (gitformat-pack.adoc "Deltified representation"):
///   size-encoded base size, size-encoded target size, then a sequence
///   of instructions:
///     - copy (high bit set): offset1-4/size1-3 optional little-endian
///       bytes selected by bits 0-6 of the opcode; a present size of
///       zero (all size bits present-and-zero, or all size bits
///       absent) means 0x10000, not zero.
///     - insert (high bit clear, opcode != 0): opcode & 0x7f literal
///       bytes follow and are appended verbatim.
///     - opcode == 0x00: reserved, not valid in any known pack.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Vec<u8> {
    let (base_size, pos) = decode_size(delta, 0);
    assert_eq!(
        base.len() as u64,
        base_size,
        "delta's declared base size does not match actual base content length"
    );
    let (target_size, mut pos) = decode_size(delta, pos);

    let mut target = Vec::with_capacity(target_size as usize);

    while pos < delta.len() {
        let opcode = delta[pos];
        pos += 1;

        if opcode & 0x80 != 0 {
            // Copy instruction.
            let mut offset: u64 = 0;
            let mut size: u64 = 0;
            for i in 0..4 {
                if opcode & (1 << i) != 0 {
                    offset |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if opcode & (1 << (4 + i)) != 0 {
                    size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let start = offset as usize;
            let end = start + size as usize;
            assert!(
                end <= base.len(),
                "copy instruction reads past end of base object (start={}, size={}, base_len={})",
                start,
                size,
                base.len()
            );
            target.extend_from_slice(&base[start..end]);
        } else if opcode != 0 {
            // Insert instruction: low 7 bits are the literal length.
            let len = (opcode & 0x7f) as usize;
            target.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
        } else {
            panic!("reserved delta instruction (0x00) encountered - not valid per spec");
        }
    }

    assert_eq!(
        target.len() as u64,
        target_size,
        "reconstructed target length does not match delta's declared target size"
    );
    target
}
