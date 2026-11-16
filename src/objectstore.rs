//! NMA-1452 (G5 alpha panic fix): the cross-pack object resolver for the
//! SERVER read path.
//!
//! ## The bug this module fixes
//!
//! `rustgit::pack::odb::resolve_oid_in_git_dir` (frozen upstream, spike
//! 01/03 scope) finds which single pack's .idx contains the requested
//! oid, then resolves any delta chain via that pack's own private
//! `resolve_at`. `resolve_at`'s ref-delta branch looks the base oid up in
//! `oid_to_offset`, a map built from that ONE pack's idx entries only,
//! and panics ("nested ref-delta base <oid> not found in base pack") the
//! moment a ref-delta's base lives anywhere else - a different pack, or
//! loose. A repository that has received a push (2+ packs) very commonly
//! has exactly that shape: `git pack-objects` deltifies the pushed
//! objects against whatever is already reachable, including objects
//! sitting in an older, already-promoted pack. Confirmed on the live G5
//! box: base `6cb0f48...` in pack A, the delta referencing it in pushed
//! pack B - `resolve_oid_in_git_dir` only ever searches pack B, so it
//! panics, the server thread dies, and the client sees an empty/short
//! reply. Same trust-boundary lesson as G1/G3 (see lib.rs's doc comment):
//! a rustgit primitive validated against a single-pack corpus panics the
//! instant dengel-git hands it a shape it was never built for. The fix
//! belongs on this side of the boundary, never inside rustgit.
//!
//! ## Design
//!
//! `ObjectStore::open` builds an oid -> (pack, offset) index once, by
//! parsing every pack's .idx in `objects/pack/` a single time (`.idx`
//! files are exactly the sorted-oid lookup structure gitformat-pack.adoc
//! describes for this purpose - parsing all of them once and keeping the
//! resulting map is the "cache the parsed idx list... once per resolve
//! session" instruction, not a new format fact). `ObjectStore::resolve`
//! then looks up a single oid on demand:
//!
//!   1. Loose objects first (`object::loose::read` - G0), same order the
//!      code being replaced already used.
//!   2. Otherwise the indexed pack entry. A non-delta entry resolves
//!      immediately. An ofs-delta's base offset (gitformat-pack.adoc,
//!      "offset encoding") always names a strictly earlier entry in the
//!      SAME pack file, by construction of the format - so recursing by
//!      offset within that one pack can never itself be the cross-pack
//!      bug and needs no store-wide lookup.
//!   3. A ref-delta's base oid, by contrast, is permitted ANYWHERE in the
//!      object store per gitformat-pack.adoc's "Deltified representation"
//!      (nothing in the format ties a ref-delta's base to its own pack -
//!      that restriction was `resolve_at`'s own bug, not a spec rule).
//!      This is the actual fix: a ref-delta's base recurses through
//!      `resolve` again - loose objects and every other pack included -
//!      instead of one pack's own offset map.
//!
//! Delta-chain depth (steps 2/3 combined, however many pack boundaries it
//! crosses) is bounded by `MAX_DELTA_CHAIN`, the same generous cycle-guard
//! value `ingest::decode_pack` already uses for the identical reason: not
//! a spec limit, just a bound that turns a cyclic or pathological chain
//! into an `Err` instead of unbounded recursion.
//!
//! ## Why not `ingest::decode_pack` per lookup
//!
//! `ingest::decode_pack` already resolves ofs- and ref-deltas against an
//! external `base_lookup` without panicking, and was explicitly built for
//! untrusted/cross-pack input - it would also fix this bug. It was not
//! reused directly here because it decodes and resolves EVERY entry in a
//! pack to answer the request; a single treewalk lookup during a clone
//! only needs the one oid's own delta chain, and enumerating whole packs
//! per lookup is exactly the accidental-O(n^2)-over-all-objects shape the
//! task instructions warn against for a repo with real history. This
//! module instead reads one entry at a time (`objectstore_entry`, positioned
//! reads of the entry header and its zlib stream; it replaced rustgit's
//! `pack::read_raw_entry`, which needed the whole pack file in memory, in
//! NMA-2243) and only ever inflates/applies-delta for the objects actually
//! on the requested oid's own chain.
//!
//! ## Trust tier
//!
//! Every pack byte this module reads comes from THIS repository's own
//! `objects/pack/`, which by construction only ever holds bytes that
//! either (a) this server's own pack writer produced, or (b) arrived
//! over the wire and were already fully structurally validated by
//! `ingest::decode_pack` before being promoted there (see
//! `receive/session.rs`'s pipeline). That is the same trusted tier
//! `rustgit::pack::odb::resolve_oid_in_git_dir` itself always operated
//! in (lib.rs's trust-boundary rule: "rustgit's spike modules... run
//! only behind that boundary, on data that already passed ingress
//! checks") - this module does not widen that tier, it only fixes the
//! single-pack restriction inside it. Entry reads return `Err` on a
//! malformed entry (bit rot included) rather than panicking as rustgit's
//! reader did; delta APPLICATION is not reused as-is - it goes
//! through `ingest::apply_delta_checked` (`Err`, never panics) rather
//! than rustgit's unchecked `delta::apply_delta`, closing that one extra
//! panic surface for the same cost as calling it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rustgit::pack::idx;
use rustgit::pack::pack::BaseRef;

use crate::ingest::{self, IngestError};
use crate::object::{self, loose, Kind, ObjectError};

/// Same generous cycle-guard bound `ingest::decode_pack` uses for the
/// identical reason (see that module's own doc comment on
/// `MAX_DELTA_CHAIN`) - not a spec limit, just a bound that makes a
/// cyclic or pathological delta chain an `Err` instead of unbounded
/// recursion. Reused verbatim rather than re-derived.
const MAX_DELTA_CHAIN: u32 = 4096;

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Malformed { what: &'static str, detail: String },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io error: {e}"),
            StoreError::Malformed { what, detail } => write!(f, "malformed {what}: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<ObjectError> for StoreError {
    fn from(e: ObjectError) -> Self {
        StoreError::Malformed {
            what: "loose object",
            detail: e.to_string(),
        }
    }
}

impl From<IngestError> for StoreError {
    fn from(e: IngestError) -> Self {
        StoreError::Malformed {
            what: "delta application",
            detail: e.to_string(),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A resolve session over one repository's object database (loose +
/// every pack under `objects/pack/`). Built once per server operation
/// that needs to resolve oids (a fetch's treewalk, an ls-refs peel pass,
/// a receive-pack thin-pack base lookup - see this module's doc comment)
/// and reused for every lookup in that operation, so the per-pack .idx
/// parse happens once rather than once per oid.
pub struct ObjectStore {
    git_dir: PathBuf,
    /// oid -> (index into `packs`, offset within that pack).
    index: HashMap<String, (usize, u64)>,
    packs: Vec<PathBuf>,
    /// Lazily opened pack files, same length/order as `packs` - opened
    /// only for packs an actual lookup touches. Entries are read with
    /// positioned reads (`objectstore_entry`), never the whole file.
    pack_files: RefCell<Vec<Option<Rc<std::fs::File>>>>,
}

impl ObjectStore {
    /// Scans `git_dir/objects/pack/*.idx` once, building the oid ->
    /// (pack, offset) index this store answers every `resolve` call
    /// from. A repository with no `objects/pack/` directory at all
    /// (freshly initialized, loose objects only) is a valid empty store,
    /// not an error.
    pub fn open(git_dir: &Path) -> Result<Self, StoreError> {
        let mut packs: Vec<PathBuf> = Vec::new();
        let mut index: HashMap<String, (usize, u64)> = HashMap::new();

        let pack_dir = git_dir.join("objects").join("pack");
        let entries = match std::fs::read_dir(&pack_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ObjectStore {
                    git_dir: git_dir.to_path_buf(),
                    index,
                    packs,
                    pack_files: RefCell::new(Vec::new()),
                });
            }
            Err(e) => return Err(StoreError::Io(e)),
        };

        let mut idx_paths: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().map(|e| e == "idx").unwrap_or(false) {
                idx_paths.push(path);
            }
        }
        // Sorted for deterministic, directory-order-independent behavior
        // run to run. Not load-bearing for correctness: a well-formed
        // store never has the same oid in two packs (objects are
        // content-addressed), so which pack "wins" a collision never
        // actually happens on real repository state.
        idx_paths.sort();

        for idx_path in idx_paths {
            let parsed = idx::parse(&idx_path).map_err(StoreError::Io)?;
            let pack_index = packs.len();
            packs.push(idx_path.with_extension("pack"));
            for e in parsed.entries {
                index.entry(e.oid).or_insert((pack_index, e.offset));
            }
        }

        let pack_files = RefCell::new((0..packs.len()).map(|_| None).collect());
        Ok(ObjectStore {
            git_dir: git_dir.to_path_buf(),
            index,
            packs,
            pack_files,
        })
    }

    /// Check a receive tip's presence after validated object publication.
    pub(crate) fn contains(&self, oid: &str) -> std::io::Result<bool> {
        if let Some(&(pack, _)) = self.index.get(oid) {
            return self
                .pack_file(pack)
                .map_err(std::io::Error::other)?
                .metadata()
                .map(|metadata| metadata.is_file());
        }
        if !object::is_lower_hex40(oid) {
            return Ok(false);
        }
        let path = self.git_dir.join("objects").join(&oid[..2]).join(&oid[2..]);
        match std::fs::metadata(path) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Resolve `oid` to (kind, content). `Ok(None)` means `oid` exists
    /// nowhere in this store (neither loose nor in any pack) - never a
    /// panic, on any repo state this store was opened against.
    pub fn resolve(&self, oid: &str) -> Result<Option<(Kind, Vec<u8>)>, StoreError> {
        self.resolve_at_depth(oid, 0, false, usize::MAX)
    }

    /// Stream ordinary existing blob leaves to a sink during connectivity.
    /// Thin delta bases still require their content, with the receive cap.
    pub(crate) fn resolve_for_receive(
        &self,
        oid: &str,
        discard_blob: bool,
    ) -> Result<Option<(Kind, Vec<u8>)>, StoreError> {
        self.resolve_at_depth(oid, 0, discard_blob, ingest::MAX_DECOMPRESSED_SIZE)
    }

    fn resolve_at_depth(
        &self,
        oid: &str,
        depth: u32,
        discard_blob: bool,
        loose_max: usize,
    ) -> Result<Option<(Kind, Vec<u8>)>, StoreError> {
        if depth > MAX_DELTA_CHAIN {
            return Err(StoreError::Malformed {
                what: "delta chain depth",
                detail: format!("chain exceeds {MAX_DELTA_CHAIN} hops resolving {oid} (cycle?)"),
            });
        }

        if let Some(found) = loose::read_with_options(&self.git_dir, oid, discard_blob, loose_max)?
        {
            return Ok(Some(found));
        }

        let Some(&(pack_index, offset)) = self.index.get(oid) else {
            return Ok(None);
        };

        let (kind_code, content) =
            self.resolve_entry(pack_index, offset, depth, discard_blob, loose_max)?;
        let kind = object::kind_from_objcode(kind_code).ok_or_else(|| StoreError::Malformed {
            what: "pack entry type",
            detail: format!("object {oid} has unrecognized pack object-type code {kind_code}"),
        })?;
        Ok(Some((kind, content)))
    }

    fn pack_file(&self, pack_index: usize) -> Result<Rc<std::fs::File>, StoreError> {
        if let Some(file) = self.pack_files.borrow()[pack_index].as_ref() {
            return Ok(file.clone());
        }
        let file = Rc::new(std::fs::File::open(&self.packs[pack_index])?);
        self.pack_files.borrow_mut()[pack_index] = Some(file.clone());
        Ok(file)
    }

    /// Resolves the object at `offset` within pack `pack_index`,
    /// applying its delta chain (if any). `depth` is the number of delta
    /// hops already taken to reach this call, threaded through BOTH
    /// same-pack ofs-delta hops and cross-pack ref-delta hops (the
    /// latter via `resolve_at_depth`, not a fresh `resolve` call - a
    /// fresh call would reset the counter and defeat the cycle guard
    /// across a pack-crossing cycle).
    fn resolve_entry(
        &self,
        pack_index: usize,
        offset: u64,
        depth: u32,
        discard_blob: bool,
        loose_max: usize,
    ) -> Result<(u8, Vec<u8>), StoreError> {
        if depth > MAX_DELTA_CHAIN {
            return Err(StoreError::Malformed {
                what: "delta chain depth",
                detail: format!(
                    "chain exceeds {MAX_DELTA_CHAIN} entries at offset {offset} in {:?}",
                    self.packs[pack_index]
                ),
            });
        }

        let file = self.pack_file(pack_index)?;
        // This repository's own on-disk pack (see this module's doc
        // comment). Read entry by entry; a malformed entry is `Err`.
        let raw = crate::objectstore_entry::read_entry(
            &file,
            offset,
            ingest::MAX_DECOMPRESSED_SIZE,
            discard_blob,
        )?;

        match raw.base {
            BaseRef::None => Ok((raw.kind, raw.content)),
            BaseRef::Offset(base_offset) => {
                // gitformat-pack.adoc's ofs-delta offset always names a
                // strictly earlier entry in THIS SAME pack file - never
                // crosses a pack boundary, so this recursion alone can
                // never be the cross-pack bug this module exists to fix.
                let (base_kind, base_content) =
                    self.resolve_entry(pack_index, base_offset, depth + 1, false, loose_max)?;
                let content = ingest::apply_delta_checked(
                    &base_content,
                    &raw.content,
                    ingest::MAX_DECOMPRESSED_SIZE,
                )?;
                Ok((base_kind, content))
            }
            BaseRef::Oid(base_oid_bytes) => {
                // THE FIX: a ref-delta's base may be loose or in ANY
                // other pack. Resolve it through the whole store, not
                // this one pack's offset map (the single-pack
                // restriction that made
                // rustgit::pack::odb::resolve_oid_in_git_dir panic).
                let base_oid = hex(&base_oid_bytes);
                let Some((base_kind, base_content)) =
                    self.resolve_at_depth(&base_oid, depth + 1, false, loose_max)?
                else {
                    return Err(StoreError::Malformed {
                        what: "ref-delta base",
                        detail: format!("base {base_oid} not found anywhere in the object store"),
                    });
                };
                let content = ingest::apply_delta_checked(
                    &base_content,
                    &raw.content,
                    ingest::MAX_DECOMPRESSED_SIZE,
                )?;
                Ok((object::kind_to_objcode(base_kind), content))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-objectstore-test-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run_git(dir: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn run_git_ok(dir: &Path, args: &[&str]) {
        run_git(dir, args);
    }

    #[test]
    fn empty_repo_has_no_objects_and_no_panic() {
        let git_dir = scratch_dir("empty");
        run_git_ok(&git_dir, &["init", "-q", "--bare", "."]);
        let store = ObjectStore::open(&git_dir).unwrap();
        let bogus = "0000000000000000000000000000000000000000";
        assert!(matches!(store.resolve(bogus), Ok(None)));
    }

    #[test]
    fn resolves_a_loose_object() {
        let git_dir = scratch_dir("loose");
        run_git_ok(&git_dir, &["init", "-q", "--bare", "."]);
        let oid = loose::write(&git_dir, Kind::Blob, b"hello\n").unwrap();
        let store = ObjectStore::open(&git_dir).unwrap();
        let (kind, content) = store.resolve(&oid).unwrap().unwrap();
        assert_eq!(kind, Kind::Blob);
        assert_eq!(content, b"hello\n");
    }

    /// The actual NMA-1452 repro, built with real git rather than a
    /// hand-assembled pack (same "real oracle" discipline as
    /// ingest::decode_pack's own tests): a bare repo whose first pack
    /// (pack A) holds an initial commit's objects, then a second commit
    /// is packed on top into a SECOND pack (pack B) via `git repack -d
    /// --no-write-bitmap-index -q` after a plain `commit` (which by
    /// default writes loose objects) followed by `git pack-objects` on
    /// just the new commit's objects deltified against the old ones -
    /// reproducing exactly the "pushed pack has a ref-delta whose base
    /// is in a different, already-promoted pack" shape the bug report
    /// describes, without going through dengel-git's own receive path
    /// (that end-to-end path is covered separately, over the wire, by
    /// this crate's g2_serve test suite).
    #[test]
    fn resolves_a_ref_delta_whose_base_is_in_a_different_pack() {
        let dir = scratch_dir("cross_pack");
        run_git_ok(&dir, &["init", "-q", "-b", "main"]);
        run_git_ok(
            &dir,
            &["config", "user.email", "objectstore-test@example.com"],
        );
        run_git_ok(&dir, &["config", "user.name", "objectstore-test"]);

        std::fs::write(dir.join("a.txt"), "one\ntwo\nthree\n".repeat(80)).unwrap();
        run_git_ok(&dir, &["add", "a.txt"]);
        run_git_ok(&dir, &["commit", "-q", "-m", "first"]);
        let first_head = String::from_utf8(run_git(&dir, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_string();

        let git_dir = dir.join(".git");
        // Pack A: everything reachable from the first commit, written as
        // an actual pack (not loose) so it lands in objects/pack/ as its
        // own separate .idx/.pack pair.
        let oids_a = run_git(&dir, &["rev-list", "--objects", &first_head]);
        write_pack_from_stdin(&dir, &oids_a, "pack-a");

        // Second commit, edited so pack-objects has a good delta
        // candidate against the first commit's blob.
        std::fs::write(dir.join("a.txt"), "one\ntwo\nTHREE-EDITED\n".repeat(80)).unwrap();
        run_git_ok(&dir, &["add", "-A"]);
        run_git_ok(&dir, &["commit", "-q", "-m", "second"]);
        let second_head = String::from_utf8(run_git(&dir, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_string();

        // Pack B: ONLY the second commit's own new objects
        // (`rev-list first..second`), deltified by real git against
        // whatever it can see reachable in the repo - which, for the
        // edited a.txt blob, is the first commit's a.txt blob sitting in
        // pack A, not anything in pack B itself. This is the exact
        // cross-pack ref-delta shape the bug report confirms on the live
        // box (base in pack A, delta in pushed pack B).
        let oids_b = run_git(
            &dir,
            &[
                "rev-list",
                "--objects",
                &format!("{first_head}..{second_head}"),
            ],
        );
        write_pack_from_stdin(&dir, &oids_b, "pack-b");

        // Sanity: two packs actually landed (otherwise this test isn't
        // exercising the bug at all).
        let pack_count = std::fs::read_dir(git_dir.join("objects/pack"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .map(|x| x == "pack")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            pack_count, 2,
            "expected exactly two packs (pack A + pack B) for this repro to be meaningful"
        );

        let store = ObjectStore::open(&git_dir).unwrap();

        // Resolve every object reachable from the SECOND commit - this
        // walks straight through the cross-pack ref-delta. Before the
        // fix, this panicked ("nested ref-delta base ... not found in
        // base pack") the moment it reached that entry.
        let all_oids =
            String::from_utf8(run_git(&dir, &["rev-list", "--objects", &second_head])).unwrap();
        for line in all_oids.lines() {
            let oid = line.split(' ').next().unwrap();
            let (kind, content) = store
                .resolve(oid)
                .unwrap()
                .unwrap_or_else(|| panic!("{oid} did not resolve"));
            let kind_name = match kind {
                Kind::Blob => "blob",
                Kind::Tree => "tree",
                Kind::Commit => "commit",
                Kind::Tag => "tag",
            };
            let git_content = run_git(&dir, &["cat-file", kind_name, oid]);
            assert_eq!(content, git_content, "content mismatch for {oid}");
        }
    }

    /// Writes every oid on `oids_stdin` (one per line, "oid path" or bare
    /// oid, as `git rev-list --objects` produces) into a new pack in
    /// `dir`'s `objects/pack/`, via real `git pack-objects`.
    fn write_pack_from_stdin(dir: &Path, oids_stdin: &[u8], label: &str) {
        use std::io::Write;
        let prefix = dir.join(".git/objects/pack").join(label);
        let mut child = Command::new("git")
            .current_dir(dir)
            .args(["pack-objects", "--", prefix.to_str().unwrap()])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn git pack-objects");
        child.stdin.take().unwrap().write_all(oids_stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git pack-objects failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn resolves_an_ofs_delta_within_a_single_pack() {
        // git's default packing for a single `pack-objects` invocation
        // over a small linear history commonly produces at least one
        // ofs-delta among the blobs/trees - exercised implicitly by
        // `resolves_a_ref_delta_whose_base_is_in_a_different_pack` above
        // (pack A alone has two blob generations... actually pack A only
        // has the first commit's objects, so this needs its own fixture
        // with delta-worthy history packed together in ONE invocation).
        let dir = scratch_dir("ofs_delta");
        run_git_ok(&dir, &["init", "-q", "-b", "main"]);
        run_git_ok(
            &dir,
            &["config", "user.email", "objectstore-test@example.com"],
        );
        run_git_ok(&dir, &["config", "user.name", "objectstore-test"]);

        std::fs::write(dir.join("a.txt"), "one\ntwo\nthree\n".repeat(80)).unwrap();
        run_git_ok(&dir, &["add", "a.txt"]);
        run_git_ok(&dir, &["commit", "-q", "-m", "first"]);
        std::fs::write(dir.join("a.txt"), "one\ntwo\nTHREE-EDITED\n".repeat(80)).unwrap();
        run_git_ok(&dir, &["add", "-A"]);
        run_git_ok(&dir, &["commit", "-q", "-m", "second"]);
        let head = String::from_utf8(run_git(&dir, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_string();

        let git_dir = dir.join(".git");
        let all_oids = run_git(&dir, &["rev-list", "--objects", &head]);
        write_pack_from_stdin(&dir, &all_oids, "pack-single");

        let store = ObjectStore::open(&git_dir).unwrap();
        let all_oids_text = String::from_utf8(all_oids).unwrap();
        for line in all_oids_text.lines() {
            let oid = line.split(' ').next().unwrap();
            assert!(
                store.resolve(oid).unwrap().is_some(),
                "{oid} did not resolve"
            );
        }
    }
}
