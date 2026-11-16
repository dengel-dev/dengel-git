//! Loose object read and write. Read existed in rustgit only as a private
//! helper inside pack::odb; write did not exist at all.
//!
//! Format source: git-reference/Documentation/gitformat-loose.adoc
//! ("Loose objects" - the "<type> <size>\0<content>" prefix, zlib
//! compression of the whole prefix+content, and the two-hex-char
//! fan-out directory). rustgit's src/pack/odb.rs::read_loose_object is
//! the validated prior art for the read half; this module follows the
//! same shape and adds the write half (write-to-temp, rename into
//! place) that rustgit never needed.

use super::{is_lower_hex40, malformed, Kind, ObjectError};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use rustgit::pack::pack::{compute_oid, OBJ_BLOB, OBJ_COMMIT, OBJ_TAG, OBJ_TREE};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

fn kind_to_obj_code(kind: Kind) -> u8 {
    match kind {
        Kind::Blob => OBJ_BLOB,
        Kind::Tree => OBJ_TREE,
        Kind::Commit => OBJ_COMMIT,
        Kind::Tag => OBJ_TAG,
    }
}

/// `$GIT_DIR/objects/<first-2-hex>/<remaining-38-hex>`, per
/// gitformat-loose.adoc. Caller must have already validated `oid` with
/// `is_lower_hex40` - this only ever runs on a validated oid.
fn object_path(git_dir: &Path, oid: &str) -> PathBuf {
    git_dir.join("objects").join(&oid[0..2]).join(&oid[2..])
}

/// Reads one loose object. `Ok(None)` when no loose object with this oid
/// exists (it may still exist packed - that is pack::odb's business, not
/// this function's).
pub fn read(git_dir: &Path, oid: &str) -> Result<Option<(Kind, Vec<u8>)>, ObjectError> {
    read_with_options(git_dir, oid, false, usize::MAX)
}

/// Limit trusted reads during receive and discard ordinary blob leaves
/// after validating their size.
pub(crate) fn read_with_options(
    git_dir: &Path,
    oid: &str,
    discard_blob: bool,
    max_size: usize,
) -> Result<Option<(Kind, Vec<u8>)>, ObjectError> {
    if !is_lower_hex40(oid) {
        return Err(malformed(
            "oid",
            format!("not 40 lowercase hex chars: {:?}", oid),
        ));
    }
    let path = object_path(git_dir, oid);

    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ObjectError::Io(e)),
    };

    // A 64-bit decimal length and a Git object kind fit in 32 bytes.
    let mut decoder = BufReader::new(ZlibDecoder::new(file));
    let mut raw_header = Vec::new();
    (&mut decoder)
        .take(32)
        .read_until(0, &mut raw_header)
        .map_err(|e| malformed("zlib stream", e.to_string()))?;
    let header = raw_header
        .strip_suffix(&[0])
        .ok_or_else(|| malformed("loose object header", "no NUL terminator found".to_string()))?;
    let header = std::str::from_utf8(header)
        .map_err(|_| malformed("loose object header", "header is not utf8".to_string()))?;
    let mut parts = header.splitn(2, ' ');
    let type_name = parts.next().unwrap_or("");
    let size_str = parts.next().ok_or_else(|| {
        malformed(
            "loose object header",
            format!("no size field in header: {:?}", header),
        )
    })?;

    let kind = Kind::from_name(type_name).ok_or_else(|| {
        malformed(
            "loose object header",
            format!("unknown object type: {:?}", type_name),
        )
    })?;

    if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed(
            "loose object header",
            format!("size is not a decimal integer: {:?}", size_str),
        ));
    }
    let declared_size: usize = size_str.parse().map_err(|_| {
        malformed(
            "loose object header",
            format!("size out of range: {:?}", size_str),
        )
    })?;

    if declared_size > max_size {
        return Err(malformed(
            "loose object header",
            format!("declared size {declared_size} exceeds {max_size}"),
        ));
    }
    let mut reader = decoder.take((declared_size as u64).saturating_add(1));
    let mut content = Vec::new();
    let inflated = if discard_blob && kind == Kind::Blob {
        io::copy(&mut reader, &mut io::sink())
    } else {
        reader.read_to_end(&mut content).map(|count| count as u64)
    }
    .map_err(|e| malformed("zlib stream", e.to_string()))?;
    if inflated != declared_size as u64 {
        return Err(malformed(
            "loose object header",
            format!(
                "declared size {declared_size} does not match actual content length {inflated}"
            ),
        ));
    }

    Ok(Some((kind, content)))
}

/// Writes content as a loose object, returning its oid. Write-to-temp then
/// rename into place; an object file is never observable half-written.
pub fn write(git_dir: &Path, kind: Kind, content: &[u8]) -> Result<String, ObjectError> {
    let oid = compute_oid(kind_to_obj_code(kind), content);
    let path = object_path(git_dir, &oid);

    // Objects are content-addressed and immutable: if this oid's file
    // already exists its bytes are guaranteed identical to what we would
    // write (same hash input), so there is nothing to do - git semantics
    // per gitformat-loose.adoc's description of the object id as the
    // hash of the (type, content) pair.
    if path.exists() {
        return Ok(oid);
    }

    let dir = path
        .parent()
        .expect("object_path always nests the file under a fan-out directory");
    std::fs::create_dir_all(dir)?;

    let mut header = format!("{} {}\0", kind.name(), content.len()).into_bytes();
    header.extend_from_slice(content);

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&header)?;
    let compressed = encoder.finish()?;

    // Unique temp name in the same directory as the final path, so the
    // rename is same-filesystem and therefore atomic.
    let tmp_name = format!(
        ".tmp-obj-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = dir.join(tmp_name);
    std::fs::write(&tmp_path, &compressed)?;

    match std::fs::rename(&tmp_path, &path) {
        Ok(()) => Ok(oid),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(ObjectError::Io(e))
        }
    }
}

/// Writes a loose object with private permissions for managed repositories.
/// Unlike [`write`], this refuses unsafe pre-existing paths and verifies any
/// existing object before treating it as an idempotent success.
///
/// The managed repository root and its ancestors must be trusted. This does
/// not protect against a same-user process racing path replacement.
#[cfg(unix)]
pub fn write_private(git_dir: &Path, kind: Kind, content: &[u8]) -> Result<String, ObjectError> {
    let oid = compute_oid(kind_to_obj_code(kind), content);
    let objects_dir = git_dir.join("objects");
    ensure_private_objects_dir(git_dir)?;
    let fanout = objects_dir.join(&oid[..2]);
    ensure_private_fanout_dir(&fanout, &objects_dir)?;
    let path = fanout.join(&oid[2..]);

    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            validate_existing_object(git_dir, &path, &metadata, &oid, kind, content)?;
            set_private_object_mode(&path)?;
            sync_directory(&fanout)?;
            sync_directory(&objects_dir)?;
            return Ok(oid);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ObjectError::Io(error)),
    }

    let (tmp_path, file) = create_private_temp(&fanout)?;
    let write_result = (|| -> Result<(), ObjectError> {
        let mut encoder = ZlibEncoder::new(file, Compression::default());
        encoder.write_all(format!("{} {}\0", kind.name(), content.len()).as_bytes())?;
        encoder.write_all(content)?;
        let file = encoder.finish()?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }

    // A hard link publishes the complete, synced inode atomically without
    // replacing an object another writer may have published first.
    match std::fs::hard_link(&tmp_path, &path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&tmp_path);
            let metadata = std::fs::symlink_metadata(&path)?;
            validate_existing_object(git_dir, &path, &metadata, &oid, kind, content)?;
            set_private_object_mode(&path)?;
            sync_directory(&fanout)?;
            sync_directory(&objects_dir)?;
            return Ok(oid);
        }
        Err(error) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ObjectError::Io(error));
        }
    }

    std::fs::remove_file(&tmp_path)?;
    sync_directory(&fanout)?;
    sync_directory(&objects_dir)?;
    Ok(oid)
}

/// Ensures the object fan-out for `oid` is a real private directory.
/// This is intended for gix replay output under a managed private root.
#[cfg(unix)]
pub fn secure_private_fanout(git_dir: &Path, oid: &str) -> Result<(), ObjectError> {
    if !is_lower_hex40(oid) {
        return Err(malformed(
            "oid",
            format!("not 40 lowercase hex chars: {oid:?}"),
        ));
    }
    ensure_private_objects_dir(git_dir)?;
    let objects_dir = git_dir.join("objects");
    let fanout = objects_dir.join(&oid[..2]);
    ensure_private_fanout_dir(&fanout, &objects_dir)?;
    sync_directory(&fanout)?;
    sync_directory(&objects_dir)?;
    Ok(())
}

#[cfg(unix)]
fn ensure_private_objects_dir(git_dir: &Path) -> Result<(), ObjectError> {
    let objects_dir = git_dir.join("objects");
    match std::fs::symlink_metadata(&objects_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(malformed(
            "object directory",
            "objects path is not a real directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&objects_dir) {
                Ok(()) => {
                    std::fs::set_permissions(&objects_dir, std::fs::Permissions::from_mode(0o700))?;
                    sync_directory(git_dir)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    match std::fs::symlink_metadata(&objects_dir) {
                        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
                        Ok(_) => Err(malformed(
                            "object directory",
                            "objects path is not a real directory",
                        )),
                        Err(error) => Err(ObjectError::Io(error)),
                    }
                }
                Err(error) => Err(ObjectError::Io(error)),
            }
        }
        Err(error) => Err(ObjectError::Io(error)),
    }
}

#[cfg(unix)]
fn ensure_private_fanout_dir(fanout: &Path, objects_dir: &Path) -> Result<(), ObjectError> {
    match std::fs::symlink_metadata(fanout) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            std::fs::set_permissions(fanout, std::fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Ok(_) => Err(malformed(
            "object fan-out directory",
            "fan-out path is not a real directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(fanout) {
                Ok(()) => {
                    std::fs::set_permissions(fanout, std::fs::Permissions::from_mode(0o700))?;
                    sync_directory(objects_dir)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    match std::fs::symlink_metadata(fanout) {
                        Ok(metadata) if metadata.file_type().is_dir() => {
                            std::fs::set_permissions(
                                fanout,
                                std::fs::Permissions::from_mode(0o700),
                            )?;
                            Ok(())
                        }
                        Ok(_) => Err(malformed(
                            "object fan-out directory",
                            "fan-out path is not a real directory",
                        )),
                        Err(error) => Err(ObjectError::Io(error)),
                    }
                }
                Err(error) => Err(ObjectError::Io(error)),
            }
        }
        Err(error) => Err(ObjectError::Io(error)),
    }
}

#[cfg(unix)]
fn create_private_temp(fanout: &Path) -> Result<(PathBuf, std::fs::File), ObjectError> {
    for attempt in 0..100u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = fanout.join(format!(".tmp-obj-{}-{nanos}-{attempt}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
                    drop(file);
                    let _ = std::fs::remove_file(&path);
                    return Err(ObjectError::Io(error));
                }
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ObjectError::Io(error)),
        }
    }
    Err(ObjectError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not choose a unique temporary object path",
    )))
}

#[cfg(unix)]
fn validate_existing_object(
    git_dir: &Path,
    path: &Path,
    metadata: &std::fs::Metadata,
    oid: &str,
    expected_kind: Kind,
    expected_content: &[u8],
) -> Result<(), ObjectError> {
    if !metadata.file_type().is_file() {
        return Err(malformed(
            "loose object path",
            "existing object is not a regular file",
        ));
    }
    let Some((kind, content)) = read(git_dir, oid)? else {
        return Err(malformed(
            "loose object path",
            "existing object disappeared",
        ));
    };
    if kind != expected_kind || content != expected_content {
        return Err(malformed(
            "loose object path",
            "existing object kind or bytes differ from the requested object",
        ));
    }
    if compute_oid(kind_to_obj_code(kind), &content) != oid {
        return Err(malformed(
            "loose object path",
            format!("existing object at {path:?} does not match its oid"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_object_mode(path: &Path) -> Result<(), ObjectError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ObjectError> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub fn write_private(_git_dir: &Path, _kind: Kind, _content: &[u8]) -> Result<String, ObjectError> {
    Err(ObjectError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private loose object writes require Unix file mode support",
    )))
}

#[cfg(not(unix))]
pub fn secure_private_fanout(_git_dir: &Path, _oid: &str) -> Result<(), ObjectError> {
    Err(ObjectError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private loose object directories require Unix file mode support",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-loose-test-{}-{}-{}",
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

    #[test]
    fn read_missing_object_is_ok_none() {
        let git_dir = scratch_dir("missing");
        let oid = "0123456789abcdef0123456789abcdef01234567";
        assert!(matches!(read(&git_dir, oid), Ok(None)));
    }

    #[test]
    fn read_rejects_bad_oid_syntax() {
        let git_dir = scratch_dir("bad-oid");
        assert!(read(&git_dir, "not-an-oid").is_err());
        assert!(read(&git_dir, "../../../../etc/passwd").is_err());
    }

    #[test]
    fn write_then_read_round_trips() {
        let git_dir = scratch_dir("roundtrip");
        let content = b"hello loose object";
        let oid = write(&git_dir, Kind::Blob, content).unwrap();
        assert_eq!(oid.len(), 40);

        let (kind, read_back) = read(&git_dir, &oid).unwrap().unwrap();
        assert_eq!(kind, Kind::Blob);
        assert_eq!(read_back, content);
    }

    #[test]
    fn write_matches_real_git_hash_object_scheme() {
        // Known-answer check, not a differential test (that is the
        // oracle's job): confirmed by hand against real git in a
        // scratch dir (`printf '' | git hash-object --stdin -t blob`),
        // reproduced here as a sanity check on compute_oid wiring.
        let git_dir = scratch_dir("empty-blob");
        let oid = write(&git_dir, Kind::Blob, b"").unwrap();
        assert_eq!(oid, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }

    #[test]
    fn tree_write_matches_real_git_mktree() {
        // Known-answer check confirmed by hand against real git in a
        // scratch dir: `git hash-object -w -t blob` on "hello\n" gives
        // blob oid ce013625030ba8dba906f756967f9e9ca394464a; feeding
        // "100644 blob.txt\0<20 raw oid bytes>" to `git mktree` gives
        // tree oid 7014586adee00b99af2256ca31ac26c387f35b8c. Reproduced
        // here end to end through tree::serialize + loose::write, which
        // exercises the prior-knowledge-disclosed tree entry binary
        // layout (NOTES.md) against a real git-produced answer rather
        // than only against this crate's own round-trip.
        let git_dir = scratch_dir("tree-mktree");
        let blob_oid = write(&git_dir, Kind::Blob, b"hello\n").unwrap();
        assert_eq!(blob_oid, "ce013625030ba8dba906f756967f9e9ca394464a");

        let entry = super::super::tree::TreeEntry {
            mode: b"100644".to_vec(),
            name: b"blob.txt".to_vec(),
            oid: blob_oid,
        };
        let tree_content = super::super::tree::serialize(&[entry]);
        let tree_oid = write(&git_dir, Kind::Tree, &tree_content).unwrap();
        assert_eq!(tree_oid, "7014586adee00b99af2256ca31ac26c387f35b8c");
    }

    #[test]
    fn write_is_idempotent_for_identical_content() {
        let git_dir = scratch_dir("idempotent");
        let oid1 = write(&git_dir, Kind::Blob, b"same content").unwrap();
        let oid2 = write(&git_dir, Kind::Blob, b"same content").unwrap();
        assert_eq!(oid1, oid2);
    }

    #[cfg(unix)]
    #[test]
    fn private_write_modes_do_not_depend_on_default_directory_permissions() {
        let git_dir = scratch_dir("private-modes");
        let objects_dir = git_dir.join("objects");
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o777);
        builder.create(&objects_dir).unwrap();

        let content = b"private object";
        let oid = write_private(&git_dir, Kind::Blob, content).unwrap();
        let fanout = objects_dir.join(&oid[..2]);
        let object_path = fanout.join(&oid[2..]);
        assert_eq!(
            std::fs::metadata(&fanout).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&object_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(read(&git_dir, &oid).unwrap().unwrap().1, content);
    }

    #[cfg(unix)]
    #[test]
    fn private_write_rejects_unsafe_existing_paths() {
        use std::os::unix::fs::symlink;

        let git_dir = scratch_dir("private-unsafe-fanout");
        let objects_dir = git_dir.join("objects");
        std::fs::create_dir_all(&objects_dir).unwrap();
        let oid = compute_oid(OBJ_BLOB, b"symlinked fanout");
        let fanout = objects_dir.join(&oid[..2]);
        let target_dir = git_dir.join("elsewhere");
        std::fs::create_dir(&target_dir).unwrap();
        symlink(&target_dir, &fanout).unwrap();
        assert!(write_private(&git_dir, Kind::Blob, b"symlinked fanout").is_err());

        let other_git = scratch_dir("private-unsafe-object");
        let other_objects = other_git.join("objects");
        let other_fanout = other_objects.join(&oid[..2]);
        std::fs::create_dir_all(&other_fanout).unwrap();
        let object_path = other_fanout.join(&oid[2..]);
        let outside_file = other_git.join("outside-object");
        std::fs::write(&outside_file, b"outside target").unwrap();
        symlink(&outside_file, &object_path).unwrap();
        assert!(write_private(&other_git, Kind::Blob, b"symlinked fanout").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_write_rejects_corrupt_existing_object() {
        let git_dir = scratch_dir("private-corrupt-existing");
        let content = b"will be corrupted";
        let oid = write_private(&git_dir, Kind::Blob, content).unwrap();
        let path = object_path(&git_dir, &oid);
        std::fs::write(&path, b"not a zlib object").unwrap();

        assert!(write_private(&git_dir, Kind::Blob, content).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_write_retry_tightens_existing_directory_and_file_modes() {
        let git_dir = scratch_dir("private-retry-modes");
        let content = b"pre-existing ordinary object";
        let oid = write(&git_dir, Kind::Blob, content).unwrap();
        let fanout = git_dir.join("objects").join(&oid[..2]);
        let path = fanout.join(&oid[2..]);
        std::fs::set_permissions(&fanout, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(write_private(&git_dir, Kind::Blob, content).unwrap(), oid);
        assert_eq!(
            std::fs::metadata(&fanout).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_write_permission_tests_pass_under_umask_0002() {
        let test_executable = std::env::current_exe().unwrap();
        for exact_test in [
            "object::loose::tests::private_write_modes_do_not_depend_on_default_directory_permissions",
            "object::loose::tests::private_write_retry_tightens_existing_directory_and_file_modes",
        ] {
            let output = std::process::Command::new("/bin/bash")
                .arg("-c")
                .arg("umask \"$1\"; shift; exec \"$@\"")
                .arg("private-write-umask-test")
                .arg("0002")
                .arg(&test_executable)
                .arg("--exact")
                .arg(exact_test)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child test {exact_test} failed under umask 0002\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[test]
    fn read_detects_size_mismatch() {
        let git_dir = scratch_dir("size-mismatch");
        let oid = write(&git_dir, Kind::Blob, b"0123456789").unwrap();
        let path = object_path(&git_dir, &oid);

        // Corrupt the declared size in the header while leaving the
        // zlib stream otherwise valid, by re-compressing a header that
        // lies about the length.
        let mut header = b"blob 999\0".to_vec();
        header.extend_from_slice(b"0123456789");
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&header).unwrap();
        let compressed = encoder.finish().unwrap();
        std::fs::write(&path, compressed).unwrap();

        assert!(read(&git_dir, &oid).is_err());
    }

    #[test]
    fn read_detects_corrupt_zlib() {
        let git_dir = scratch_dir("corrupt-zlib");
        let oid = "0123456789abcdef0123456789abcdef01234567";
        let path = object_path(&git_dir, oid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not zlib data at all").unwrap();

        assert!(read(&git_dir, oid).is_err());
    }
}
