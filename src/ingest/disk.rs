//! Receive-pack decoder. Payloads and delta results share one quarantine
//! spool. Only entry metadata, the index and fixed-size I/O buffers stay
//! resident while processing incoming blobs.

use super::*;
use flate2::{write::ZlibEncoder, Compression, Decompress, FlushDecompress, Status};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
struct Span {
    start: u64,
    len: u64,
}

struct Entry {
    pack_offset: u64,
    span: Span,
    base: EntryBase,
}

pub(crate) struct Object {
    pub oid: String,
    pub kind: Kind,
    span: Span,
    depth: u32,
}

pub(crate) struct DecodedPack {
    spool: PathBuf,
    objects: Vec<Object>,
    by_oid: HashMap<String, usize>,
}

impl DecodedPack {
    pub(crate) fn objects(&self) -> &[Object] {
        &self.objects
    }

    pub(crate) fn get(&self, oid: &str) -> Option<&Object> {
        self.by_oid.get(oid).map(|&index| &self.objects[index])
    }

    pub(crate) fn read(&self, object: &Object) -> io::Result<Vec<u8>> {
        let mut content = Vec::with_capacity(object.span.len as usize);
        file_span(&self.spool, object.span)?.read_to_end(&mut content)?;
        if content.len() as u64 != object.span.len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "quarantine object truncated",
            ));
        }
        Ok(content)
    }

    /// Emit whole objects so the published pack is independent of thin
    /// bases. Keep the entry CRCs and offsets for the shared idx writer.
    pub(crate) fn write_pack(&self, dir: &Path) -> Result<String, IngestError> {
        let file = File::create(dir.join("prepared.pack")).map_err(spool_error)?;
        let mut pack = PackWriter {
            output: BufWriter::new(file),
            sha: Sha1::new(),
            crc: crc32fast::Hasher::new(),
            offset: 0,
        };
        pack.write_all(b"PACK").map_err(spool_error)?;
        pack.write_all(&2u32.to_be_bytes()).map_err(spool_error)?;
        pack.write_all(&(self.objects.len() as u32).to_be_bytes())
            .map_err(spool_error)?;

        let mut index = Vec::with_capacity(self.objects.len());
        for object in &self.objects {
            let offset = pack.offset;
            pack.crc.reset();
            pack.write_all(&encode_header(object.kind, object.span.len))
                .map_err(spool_error)?;
            let mut encoder = ZlibEncoder::new(&mut pack, Compression::default());
            // Fix the encoder's input window even when the reader can
            // report the size of the whole backing file.
            let mut content = file_span(&self.spool, object.span).map_err(spool_error)?;
            let mut buf = [0; 32 * 1024];
            while content.limit() > 0 {
                let count = content.read(&mut buf).map_err(spool_error)?;
                if count == 0 {
                    return Err(malformed("quarantine spool", "object truncated"));
                }
                encoder.write_all(&buf[..count]).map_err(spool_error)?;
            }
            encoder.finish().map_err(spool_error)?;
            index.push((object.oid.as_str(), pack.crc.clone().finalize(), offset));
        }

        let checksum = pack.sha.finalize();
        pack.output.write_all(&checksum).map_err(spool_error)?;
        pack.output.flush().map_err(spool_error)?;
        pack.output.get_ref().sync_all().map_err(spool_error)?;

        let mut idx = File::create(dir.join("prepared.idx")).map_err(spool_error)?;
        idx.write_all(&write_index(&checksum, index.into_iter())?)
            .map_err(spool_error)?;
        idx.sync_all().map_err(spool_error)?;
        Ok(hex(&checksum))
    }
}

fn spool_error(error: io::Error) -> IngestError {
    malformed("quarantine I/O", error.to_string())
}

/// Separate file handles allow delta copies to seek in a base while the
/// output grows at the end of the same file.
fn file_span(path: &Path, span: Span) -> io::Result<io::Take<File>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(span.start))?;
    Ok(file.take(span.len))
}

fn hash_reader(mut input: impl Read, sha: &mut Sha1) -> io::Result<u64> {
    let mut buf = [0; 32 * 1024];
    let mut bytes = 0;
    loop {
        let count = input.read(&mut buf)?;
        if count == 0 {
            return Ok(bytes);
        }
        sha.update(&buf[..count]);
        bytes += count as u64;
    }
}

fn object_oid(path: &Path, kind: Kind, span: Span) -> Result<String, IngestError> {
    let name = match kind {
        Kind::Commit => "commit",
        Kind::Tree => "tree",
        Kind::Blob => "blob",
        Kind::Tag => "tag",
    };
    let mut sha = Sha1::new();
    sha.update(format!("{name} {}\0", span.len).as_bytes());
    let copied =
        hash_reader(file_span(path, span).map_err(spool_error)?, &mut sha).map_err(spool_error)?;
    if copied != span.len {
        return Err(malformed("quarantine spool", "object truncated"));
    }
    Ok(hex(&sha.finalize()))
}

struct PackWriter {
    output: BufWriter<File>,
    sha: Sha1,
    crc: crc32fast::Hasher,
    offset: u64,
}

impl Write for PackWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let count = self.output.write(buf)?;
        self.sha.update(&buf[..count]);
        self.crc.update(&buf[..count]);
        self.offset += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn encode_header(kind: Kind, size: u64) -> Vec<u8> {
    let mut out = vec![(kind_to_type(kind) << 4) | (size & 0x0f) as u8];
    let mut remaining = size >> 4;
    while remaining != 0 {
        *out.last_mut().expect("header starts with a type byte") |= 0x80;
        out.push((remaining & 0x7f) as u8);
        remaining >>= 7;
    }
    out
}

fn read_prefix(
    input: &mut impl Read,
    what: &'static str,
) -> Result<([u8; 10], usize), IngestError> {
    let mut prefix = [0; 10];
    for (index, slot) in prefix.iter_mut().enumerate() {
        *slot = read_byte(input, what)?;
        if *slot & 0x80 == 0 {
            return Ok((prefix, index + 1));
        }
    }
    Err(malformed(what, "varint exceeds 10 bytes"))
}

fn verify_checksum(file: &mut File, body_len: u64) -> Result<(), IngestError> {
    let mut sha = Sha1::new();
    hash_reader(file.take(body_len), &mut sha).map_err(spool_error)?;
    let mut trailer = [0; 20];
    file.read_exact(&mut trailer).map_err(spool_error)?;
    if sha.finalize().as_slice() != trailer {
        return Err(malformed(
            "pack trailer checksum",
            "SHA-1 over the pack body does not match the trailer",
        ));
    }
    file.rewind().map_err(spool_error)
}

fn inflate_to(
    reader: &mut impl BufRead,
    output: &mut impl Write,
    size: u64,
) -> Result<u64, IngestError> {
    let mut decoder = Decompress::new(true);
    let mut buf = [0; 32 * 1024];
    loop {
        let input = reader.fill_buf().map_err(spool_error)?;
        let (previous_in, previous_out) = (decoder.total_in(), decoder.total_out());
        let status = decoder
            .decompress(input, &mut buf, FlushDecompress::None)
            .map_err(|e| malformed("zlib stream", e.to_string()))?;
        let consumed = (decoder.total_in() - previous_in) as usize;
        let produced = (decoder.total_out() - previous_out) as usize;
        reader.consume(consumed);
        if decoder.total_out() > size {
            return Err(malformed(
                "entry size",
                format!("inflated data exceeds declared size {size}"),
            ));
        }
        output.write_all(&buf[..produced]).map_err(spool_error)?;
        if status == Status::StreamEnd {
            if decoder.total_out() != size {
                return Err(malformed(
                    "entry size",
                    format!("expected {size} bytes but inflated {}", decoder.total_out()),
                ));
            }
            return Ok(decoder.total_in());
        }
        if consumed == 0 && produced == 0 {
            return Err(malformed("zlib stream", "truncated compressed entry"));
        }
    }
}

/// Decode and verify the staged wire pack. Out-of-pack delta bases use
/// the same object store as connectivity checking.
#[allow(clippy::type_complexity, reason = "the shape is the format's")]
pub(crate) fn decode(
    dir: &Path,
    limits: DecodeLimits,
    base_lookup: &dyn Fn(&str) -> Option<(Kind, Vec<u8>)>,
) -> Result<DecodedPack, IngestError> {
    let mut file = File::open(dir.join("incoming.pack")).map_err(spool_error)?;
    let body_len = file
        .metadata()
        .map_err(spool_error)?
        .len()
        .checked_sub(20)
        .filter(|len| *len >= 12)
        .ok_or_else(|| malformed("pack file", "too short for header and trailer"))?;
    verify_checksum(&mut file, body_len)?;
    let mut reader = BufReader::new(file.take(body_len));
    let mut header = [0; 12];
    reader.read_exact(&mut header).map_err(spool_error)?;
    if &header[..8] != b"PACK\0\0\0\x02" {
        return Err(malformed("pack header", "expected a version 2 PACK header"));
    }
    let count = u32::from_be_bytes(header[8..].try_into().unwrap()) as usize;
    if count > limits.max_objects {
        return Err(limit_exceeded(
            "object count",
            format!("{count} exceeds {}", limits.max_objects),
        ));
    }

    let spool = dir.join("decoded");
    let mut output = BufWriter::new(File::create(&spool).map_err(spool_error)?);
    let mut entries = Vec::with_capacity(count);
    let mut offsets = HashMap::with_capacity(count);
    let mut resolved: Vec<Option<Object>> = (0..count).map(|_| None).collect();
    let mut by_oid = HashMap::with_capacity(count);
    let mut dependencies = vec![Vec::new(); count];
    let mut by_base_oid = HashMap::<String, Vec<usize>>::new();
    let mut ready = VecDeque::new();
    let mut pack_offset = 12;
    let mut used = 0;
    let mut spool_end = 0;

    for (index, slot) in resolved.iter_mut().enumerate() {
        let entry_offset = pack_offset;
        let (prefix, len) = read_prefix(&mut reader, "pack entry header")?;
        let header = decode_entry_header(&prefix[..len], 0)?;
        pack_offset += len as u64;
        let base = match header.type_code {
            OBJ_OFS_DELTA => {
                let (prefix, len) = read_prefix(&mut reader, "ofs-delta offset")?;
                let (distance, _) = decode_ofs_delta_offset(&prefix[..len], 0)?;
                pack_offset += len as u64;
                let base = entry_offset
                    .checked_sub(distance)
                    .and_then(|offset| offsets.get(&offset).copied())
                    .ok_or_else(|| {
                        malformed("ofs-delta base", "offset is not a preceding entry boundary")
                    })?;
                EntryBase::OffsetIndex(base)
            }
            OBJ_REF_DELTA => {
                let mut oid = [0; 20];
                reader
                    .read_exact(&mut oid)
                    .map_err(|e| malformed("ref-delta base", e.to_string()))?;
                pack_offset += 20;
                EntryBase::Oid(oid)
            }
            OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => EntryBase::None,
            _ => {
                return Err(malformed(
                    "pack entry type",
                    "unknown or reserved object type",
                ))
            }
        };
        let cap = (limits.max_object_bytes - used).min(MAX_DECOMPRESSED_SIZE);
        if header.size > cap as u64 {
            return Err(limit_exceeded(
                "decompressed size",
                format!("declared size {} exceeds the {cap} byte cap", header.size),
            ));
        }
        pack_offset += inflate_to(&mut reader, &mut output, header.size)?;
        used += header.size as usize;
        let span = Span {
            start: spool_end,
            len: header.size,
        };
        spool_end += span.len;
        offsets.insert(entry_offset, index);

        match base {
            EntryBase::None => {
                let kind =
                    type_to_kind(header.type_code).expect("plain object type validated above");
                output.flush().map_err(spool_error)?;
                let oid = object_oid(&spool, kind, span)?;
                by_oid.entry(oid.clone()).or_insert(index);
                *slot = Some(Object {
                    oid,
                    kind,
                    span,
                    depth: 0,
                });
                ready.push_back(index);
            }
            EntryBase::OffsetIndex(parent) => dependencies[parent].push(index),
            EntryBase::Oid(oid) => by_base_oid.entry(hex(&oid)).or_default().push(index),
        }
        entries.push(Entry {
            pack_offset: entry_offset,
            span,
            base,
        });
    }

    if pack_offset != body_len {
        return Err(malformed(
            "pack entries",
            "trailing garbage between the last entry and the pack trailer",
        ));
    }
    output.flush().map_err(spool_error)?;

    // Drain all known in-pack bases before trying the existing object
    // store. Each resolved entry wakes its offset and OID dependents.
    let mut base_file = File::open(&spool).map_err(spool_error)?;
    let mut external_keys = by_base_oid.keys().cloned().collect::<Vec<_>>();
    external_keys.sort_unstable();
    let mut external_keys = external_keys.into_iter();
    loop {
        while let Some(parent) = ready.pop_front() {
            let base = resolved[parent]
                .as_ref()
                .expect("queued objects are resolved");
            let (kind, span, depth) = (base.kind, base.span, base.depth + 1);
            let by_oid_children = by_base_oid.remove(&base.oid).unwrap_or_default();
            for child in std::mem::take(&mut dependencies[parent])
                .into_iter()
                .chain(by_oid_children)
            {
                let object = resolve_delta(
                    &spool,
                    &mut output,
                    &mut base_file,
                    span,
                    kind,
                    depth,
                    &entries[child],
                    spool_end,
                    (limits.max_object_bytes - used).min(MAX_DECOMPRESSED_SIZE),
                )?;
                used += object.span.len as usize;
                spool_end += object.span.len;
                by_oid.entry(object.oid.clone()).or_insert(child);
                resolved[child] = Some(object);
                ready.push_back(child);
            }
        }

        // Each distinct external OID is looked up once. Resolve one
        // group then drain its in-pack descendants before proceeding.
        let external = external_keys.find_map(|oid| {
            if !by_base_oid.contains_key(&oid) {
                return None;
            }
            let (kind, content) = base_lookup(&oid)?;
            let children = by_base_oid
                .remove(&oid)
                .expect("base has unresolved children");
            Some((kind, content, children))
        });
        let Some((kind, content, children)) = external else {
            break;
        };
        let span = Span {
            start: 0,
            len: content.len() as u64,
        };
        let mut base = Cursor::new(content);
        for child in children {
            charge_budget(&mut used, span.len as usize, Some(limits.max_object_bytes))?;
            let object = resolve_delta(
                &spool,
                &mut output,
                &mut base,
                span,
                kind,
                1,
                &entries[child],
                spool_end,
                (limits.max_object_bytes - used).min(MAX_DECOMPRESSED_SIZE),
            )?;
            used += object.span.len as usize;
            spool_end += object.span.len;
            by_oid.entry(object.oid.clone()).or_insert(child);
            resolved[child] = Some(object);
            ready.push_back(child);
        }
    }

    let objects = resolved
        .into_iter()
        .zip(entries)
        .map(|(object, entry)| {
            object.ok_or_else(|| match entry.base {
                EntryBase::Oid(oid) => IngestError::MissingBase { oid: hex(&oid) },
                _ => malformed("ofs-delta base", "base entry never resolved"),
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(DecodedPack {
        spool,
        objects,
        by_oid,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "delta source, destination and checked metadata"
)]
fn resolve_delta(
    spool: &Path,
    output: &mut BufWriter<File>,
    base: &mut (impl Read + Seek),
    span: Span,
    kind: Kind,
    depth: u32,
    entry: &Entry,
    start: u64,
    cap: usize,
) -> Result<Object, IngestError> {
    if depth > MAX_DELTA_CHAIN {
        return Err(limit_exceeded(
            "delta chain depth",
            format!(
                "chain exceeds {MAX_DELTA_CHAIN} entries at pack offset {}",
                entry.pack_offset
            ),
        ));
    }
    let mut delta = BufReader::new(file_span(spool, entry.span).map_err(spool_error)?);
    let len = apply_delta_to(base, span.start, span.len, &mut delta, output, cap)?;
    let span = Span { start, len };
    output.flush().map_err(spool_error)?;
    let oid = object_oid(spool, kind, span)?;
    Ok(Object {
        oid,
        kind,
        span,
        depth,
    })
}
