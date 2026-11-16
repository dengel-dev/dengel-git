//! One pack entry read with positioned reads (NMA-2243 latency).
//!
//! `ObjectStore` used to read a whole pack file into memory on the first
//! lookup it served from that pack (`rustgit::pack::pack::read_pack_file`),
//! so every query, clone and fetch paid O(pack size) time and memory per
//! request: about 600 ms and 1 GB of RSS on the 1 GB latency repository.
//! This reader fetches only the entry's header and its zlib stream from
//! the file, so a lookup costs O(entry), and returns `Err` (never panics)
//! on a malformed entry.
//!
//! Format (gitformat-pack): a size-and-type varint header; for an ofs-delta
//! a second varint with the negative offset to the base; for a ref-delta a
//! 20-byte base id; then a zlib stream that inflates to exactly the header's
//! size. The parse is equivalent to `rustgit::pack::pack::read_raw_entry`,
//! checked against it on real packs in `tests::matches_rustgit_on_every_entry`.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;

use flate2::read::ZlibDecoder;
use rustgit::pack::pack::BaseRef;

use crate::objectstore::StoreError;

const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;
/// Longest header we read up front: a 10-byte size varint, a 10-byte
/// offset varint or a 20-byte base id, with room to spare.
const HEADER_PROBE: usize = 64;

pub(crate) struct Entry {
    pub kind: u8,
    pub content: Vec<u8>,
    pub base: BaseRef,
}

fn malformed(detail: String) -> StoreError {
    StoreError::Malformed {
        what: "pack entry",
        detail,
    }
}

/// `Read` over a file from a position, by `read_at`; does not move any
/// shared cursor, so several entries of one `File` can be read in any order.
struct At<'a> {
    file: &'a File,
    pos: u64,
}

impl Read for At<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.file.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// Read and inflate the entry at `offset`. Deltas are not applied.
/// `max_size` bounds the declared inflated size.
pub(crate) fn read_entry(
    file: &File,
    offset: u64,
    max_size: usize,
    discard_blob: bool,
) -> Result<Entry, StoreError> {
    let mut head = [0u8; HEADER_PROBE];
    let mut got = 0;
    while got < HEADER_PROBE {
        let n = file.read_at(&mut head[got..], offset + got as u64)?;
        if n == 0 {
            break;
        }
        got += n;
    }
    let head = &head[..got];
    let byte = |i: usize| {
        head.get(i)
            .copied()
            .ok_or_else(|| malformed(format!("entry header at {offset} runs past the pack end")))
    };

    let mut i = 0;
    let mut c = byte(i)?;
    i += 1;
    let kind = (c >> 4) & 0x7;
    let mut size = u64::from(c & 0x0f);
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        c = byte(i)?;
        i += 1;
        if shift > 60 {
            return Err(malformed(format!("size varint too long at {offset}")));
        }
        size |= u64::from(c & 0x7f) << shift;
        shift += 7;
    }

    let base = match kind {
        OBJ_OFS_DELTA => {
            let mut c = byte(i)?;
            i += 1;
            let mut rel = u64::from(c & 0x7f);
            while c & 0x80 != 0 {
                c = byte(i)?;
                i += 1;
                rel = rel
                    .checked_add(1)
                    .and_then(|r| r.checked_mul(128))
                    .map(|r| r | u64::from(c & 0x7f))
                    .ok_or_else(|| malformed(format!("ofs-delta offset overflows at {offset}")))?;
            }
            let base = offset.checked_sub(rel).filter(|_| rel > 0).ok_or_else(|| {
                malformed(format!(
                    "ofs-delta at {offset} points before the pack start"
                ))
            })?;
            BaseRef::Offset(base)
        }
        OBJ_REF_DELTA => {
            let mut oid = [0u8; 20];
            let end = i + 20;
            if head.len() < end {
                return Err(malformed(format!(
                    "ref-delta base id truncated at {offset}"
                )));
            }
            oid.copy_from_slice(&head[i..end]);
            i = end;
            BaseRef::Oid(oid)
        }
        1..=4 => BaseRef::None,
        other => return Err(malformed(format!("unknown entry type {other} at {offset}"))),
    };

    if size > max_size as u64 {
        return Err(malformed(format!(
            "entry at {offset} declares {size} bytes, more than {max_size}"
        )));
    }
    let reader = At {
        file,
        pos: offset + i as u64,
    };
    let mut decoder = ZlibDecoder::new(reader).take(size + 1);
    let discard = discard_blob && kind == rustgit::pack::pack::OBJ_BLOB;
    let mut content = Vec::new();
    let inflated = if discard {
        std::io::copy(&mut decoder, &mut std::io::sink())
    } else {
        decoder.read_to_end(&mut content).map(|count| count as u64)
    }
    .map_err(|e| malformed(format!("zlib stream at {offset}: {e}")))?;
    if inflated != size {
        return Err(malformed(format!(
            "entry at {offset} inflates to {inflated} bytes, header says {size}",
        )));
    }
    Ok(Entry {
        kind,
        content,
        base,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let ok = Command::new("git")
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "A")
            .env("GIT_AUTHOR_EMAIL", "a@example.com")
            .env("GIT_COMMITTER_NAME", "A")
            .env("GIT_COMMITTER_EMAIL", "a@example.com")
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    /// Every entry of a real, delta-heavy pack (ofs-deltas from `gc`, and a
    /// ref-delta pack from `--no-delta-base-offset`) reads the same as
    /// rustgit's whole-file reader.
    #[test]
    fn matches_rustgit_on_every_entry() {
        for ofs in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let w = tmp.path();
            git(w, &["init", "-q"]);
            let mut text = String::new();
            for i in 0..60 {
                text.push_str(&format!("line {i} {}\n", "x".repeat(i % 7)));
                std::fs::write(w.join("f.txt"), &text).unwrap();
                std::fs::write(
                    w.join(format!("g{}.txt", i % 5)),
                    format!("{i}\n").repeat(50),
                )
                .unwrap();
                git(w, &["add", "."]);
                git(w, &["commit", "-q", "-m", &format!("c{i}")]);
            }
            let offsets = format!("repack.useDeltaBaseOffset={ofs}");
            git(
                w,
                &[
                    "-c",
                    &offsets,
                    "repack",
                    "-adf",
                    "-q",
                    "--depth=50",
                    "--window=50",
                ],
            );
            let pack_dir = w.join(".git/objects/pack");
            let idx_path = std::fs::read_dir(&pack_dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| p.extension().is_some_and(|e| e == "idx"))
                .unwrap();
            let parsed = rustgit::pack::idx::parse(&idx_path).unwrap();
            let pack_path = idx_path.with_extension("pack");
            let bytes = std::fs::read(&pack_path).unwrap();
            let file = File::open(&pack_path).unwrap();
            let mut deltas = 0;
            for e in parsed.entries {
                let theirs = rustgit::pack::pack::read_raw_entry(&bytes, e.offset);
                let ours = read_entry(&file, e.offset, usize::MAX, false).unwrap();
                assert_eq!(ours.kind, theirs.kind);
                assert_eq!(ours.content, theirs.content);
                match (&ours.base, &theirs.base) {
                    (BaseRef::None, BaseRef::None) => {}
                    (BaseRef::Offset(a), BaseRef::Offset(b)) => {
                        assert_eq!(a, b);
                        deltas += 1;
                    }
                    (BaseRef::Oid(a), BaseRef::Oid(b)) => {
                        assert_eq!(a, b);
                        deltas += 1;
                    }
                    _ => panic!("base kind differs at {}", e.offset),
                }
            }
            assert!(deltas > 10, "the fixture must exercise deltas ({deltas})");
        }
    }

    #[test]
    fn malformed_entries_are_errors_not_panics() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("bad.pack");
        // A blob header declaring 5 bytes followed by garbage, not zlib.
        std::fs::write(&p, [0x35, 0xff, 0xff, 0xff]).unwrap();
        let f = File::open(&p).unwrap();
        assert!(read_entry(&f, 0, 1 << 20, false).is_err());
        // Header past the end of the file.
        assert!(read_entry(&f, 100, 1 << 20, false).is_err());
        // Declared size over the bound.
        std::fs::write(&p, [0xbf, 0xff, 0x7f]).unwrap();
        let f = File::open(&p).unwrap();
        assert!(read_entry(&f, 0, 16, false).is_err());
        // An ofs-delta pointing before the start.
        std::fs::write(&p, [0x65, 0x05, 0x78, 0x9c]).unwrap();
        let f = File::open(&p).unwrap();
        assert!(read_entry(&f, 0, 1 << 20, false).is_err());
    }
}
