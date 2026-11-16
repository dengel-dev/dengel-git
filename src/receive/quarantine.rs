//! Stage validated pack files in a per-push directory on the same filesystem
//! as the live object store. Publication owns final pack names and recovery.

use super::{publication, ReceiveError};
use std::fs::{self, File};
use std::io;
#[cfg(test)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct Quarantine {
    dir: PathBuf,
    _lease: File,
}

#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) const QUARANTINE_PREFIX: &str = "dengel-quarantine-";

// Leave a grace period between directory creation and opening its lease.
const STALE_QUARANTINE_AGE: Duration = Duration::from_secs(10 * 60);

/// Reclaim older quarantines only when no receiver holds their lease.
fn sweep_stale_quarantine_dirs(objects_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(objects_dir) else {
        return;
    };
    let now = std::time::SystemTime::now();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(QUARANTINE_PREFIX) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        // `duration_since` errors if `modified` is in the future
        // (clock skew, or - the important case - a dir that was JUST
        // created by a concurrent push racing this very sweep): treated
        // as "not stale", never as license to delete it.
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age >= STALE_QUARANTINE_AGE {
            if let Ok(lease) = File::open(entry.path()) {
                if lease.try_lock().is_ok() {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
    }
}

pub(crate) fn sweep_repository(git_dir: &Path) {
    sweep_stale_quarantine_dirs(&git_dir.join("objects"));
}

pub(super) fn discard_crashed(repo: &Path, name: &str) -> io::Result<()> {
    if !name.starts_with(QUARANTINE_PREFIX)
        || !name[QUARANTINE_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid quarantine name",
        ));
    }
    let dir = repo.join("objects").join(name);
    match fs::symlink_metadata(&dir) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(io::Error::other("quarantine is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let lease = File::open(&dir)?;
    match lease.try_lock() {
        Ok(()) => {
            fs::remove_dir_all(&dir)?;
            publication::sync_dir(&repo.join("objects"))
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(()),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

impl Quarantine {
    /// Create a fresh quarantine dir under `<git_dir>/objects/`, first
    /// sweeping any stale dirs a prior (crashed/killed) run left behind -
    /// see `sweep_stale_quarantine_dirs`.
    pub fn create(git_dir: &Path) -> Result<Self, ReceiveError> {
        let objects_dir = git_dir.join("objects");
        sweep_stale_quarantine_dirs(&objects_dir);

        let nonce = format!(
            "{QUARANTINE_PREFIX}{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let dir = objects_dir.join(nonce);
        fs::create_dir(&dir)?;
        let lease = File::open(&dir)?;
        lease.lock()?;
        Ok(Quarantine { dir, _lease: lease })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Writes the raw, not-yet-validated pack bytes into the quarantine
    /// dir - ADR-0008 step 1 taken literally ("the incoming pack lands
    /// in a fresh temporary directory... " BEFORE any check runs, not
    /// only at promote time). Named generically (`incoming.pack`, not
    /// `pack-<sha>`) since at this point the bytes may not even be
    /// well-formed enough to compute a trailer sha from - `promote`
    /// writes the FINAL validated pack+idx under their real names
    /// separately once decode/well-formedness/connectivity have all
    /// passed. This file is never itself promoted (never renamed out of
    /// `self.dir`); it exists purely so a crash between "pack received"
    /// and "pack validated" is observable on disk, and is removed along
    /// with the rest of the staging dir by `Drop` either way.
    #[cfg(test)]
    fn write_incoming(&self, pack_bytes: &[u8]) -> Result<(), ReceiveError> {
        std::fs::write(self.dir.join("incoming.pack"), pack_bytes)?;
        Ok(())
    }

    /// The streaming writer has already synced both files. Rename them
    /// within quarantine and measure the exact bytes publication will add.
    pub(super) fn prepare_files(&self, id: String) -> io::Result<PreparedPack> {
        let pack = self.dir.join(format!("pack-{id}.pack"));
        let index = self.dir.join(format!("pack-{id}.idx"));
        fs::rename(self.dir.join("prepared.pack"), &pack)?;
        fs::rename(self.dir.join("prepared.idx"), &index)?;
        let pack = fs::metadata(pack)?;
        let index = fs::metadata(index)?;
        Ok(PreparedPack {
            owner: publication::PackOwner {
                pack: publication::FileIdentity::new(&pack),
                index: publication::FileIdentity::new(&index),
                id,
            },
            bytes: pack.len() + index.len(),
        })
    }

    #[cfg(test)]
    pub(super) fn prepare(
        &self,
        pack_bytes: &[u8],
        idx_bytes: &[u8],
    ) -> Result<PreparedPack, ReceiveError> {
        let trailer = pack_bytes
            .len()
            .checked_sub(20)
            .ok_or_else(|| ReceiveError::Malformed {
                what: "pack file",
                detail: "too short to contain a trailer checksum".into(),
            })?;
        let id = hex(&pack_bytes[trailer..]);
        let write = |name: &str, bytes: &[u8]| -> io::Result<publication::FileIdentity> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.dir.join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(publication::FileIdentity::new(&file.metadata()?))
        };
        let owner = publication::PackOwner {
            pack: write(&format!("pack-{id}.pack"), pack_bytes)?,
            index: write(&format!("pack-{id}.idx"), idx_bytes)?,
            id,
        };
        Ok(PreparedPack {
            owner,
            bytes: pack_bytes.len() as u64 + idx_bytes.len() as u64,
        })
    }

    #[cfg(test)]
    fn promote(
        &self,
        git_dir: &Path,
        pack_bytes: &[u8],
        idx_bytes: &[u8],
    ) -> Result<(), ReceiveError> {
        let pack = self.prepare(pack_bytes, idx_bytes)?;
        if pack.needs_publication(git_dir)? {
            pack.publish(git_dir, self)?;
        }
        Ok(())
    }
}

pub(super) struct PreparedPack {
    owner: publication::PackOwner,
    bytes: u64,
}

impl PreparedPack {
    pub(super) fn owner(&self) -> &publication::PackOwner {
        &self.owner
    }

    pub(super) fn bytes(&self) -> u64 {
        self.bytes
    }

    fn names(&self) -> [String; 2] {
        [
            format!("pack-{}.pack", self.owner.id),
            format!("pack-{}.idx", self.owner.id),
        ]
    }

    pub(super) fn needs_publication(&self, repo: &Path) -> io::Result<bool> {
        let dir = repo.join("objects/pack");
        let [pack, index] = self.names();
        match (dir.join(pack).try_exists()?, dir.join(index).try_exists()?) {
            (false, false) => Ok(true),
            (true, true) => Ok(false),
            _ => Err(io::Error::other("live pack is missing its pack or index")),
        }
    }

    pub(super) fn publish(&self, repo: &Path, quarantine: &Quarantine) -> io::Result<()> {
        let object_dir = repo.join("objects");
        let pack_dir = object_dir.join("pack");
        fs::create_dir_all(&pack_dir)?;
        for name in self.names() {
            fs::hard_link(quarantine.dir.join(&name), pack_dir.join(name))?;
        }
        publication::sync_dir(&pack_dir)?;
        publication::sync_dir(&object_dir)
    }
}

impl Drop for Quarantine {
    fn drop(&mut self) {
        // Zero debris on any early return / error / panic: the dir only
        // survives if the caller explicitly forgets it after a successful
        // promote. Removal is best-effort - a failure to clean is a leaked
        // temp dir, never a corrupt store.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_git_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-quarantine-test-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("objects")).unwrap();
        dir
    }

    #[test]
    fn create_makes_a_fresh_dir_under_objects() {
        let git_dir = scratch_git_dir("create");
        let q = Quarantine::create(&git_dir).unwrap();
        assert!(q.dir().is_dir());
        assert!(q.dir().starts_with(git_dir.join("objects")));
    }

    #[test]
    fn drop_removes_the_dir_when_promote_was_never_called() {
        let git_dir = scratch_git_dir("drop_cleanup");
        let dir_path;
        {
            let q = Quarantine::create(&git_dir).unwrap();
            dir_path = q.dir().to_path_buf();
            assert!(dir_path.is_dir());
        }
        assert!(
            !dir_path.exists(),
            "quarantine dir should be gone after Drop with no promote"
        );
    }

    #[test]
    fn promote_moves_pack_and_idx_into_objects_pack_and_cleans_the_staging_dir() {
        let git_dir = scratch_git_dir("promote");
        let pack_bytes: Vec<u8> = {
            let mut v = vec![b'P', b'A', b'C', b'K'];
            v.extend_from_slice(&[0u8; 8]); // fake header (version+count, not parsed here)
            v.extend_from_slice(&[0xABu8; 20]); // fake 20-byte trailer
            v
        };
        let idx_bytes = vec![1, 2, 3, 4];
        let expected_sha = hex(&pack_bytes[pack_bytes.len() - 20..]);
        let dir_path;

        {
            let q = Quarantine::create(&git_dir).unwrap();
            dir_path = q.dir().to_path_buf();
            q.promote(&git_dir, &pack_bytes, &idx_bytes).unwrap();
        }

        let final_pack = git_dir
            .join("objects/pack")
            .join(format!("pack-{expected_sha}.pack"));
        let final_idx = git_dir
            .join("objects/pack")
            .join(format!("pack-{expected_sha}.idx"));
        assert_eq!(std::fs::read(&final_pack).unwrap(), pack_bytes);
        assert_eq!(std::fs::read(&final_idx).unwrap(), idx_bytes);
        assert!(
            !dir_path.exists(),
            "staging dir should be cleaned up after promote"
        );
    }

    #[test]
    fn promote_rejects_a_pack_too_short_for_a_trailer() {
        let git_dir = scratch_git_dir("too_short");
        let q = Quarantine::create(&git_dir).unwrap();
        let result = q.promote(&git_dir, &[0u8; 5], &[1, 2, 3]);
        assert!(matches!(result, Err(ReceiveError::Malformed { .. })));
    }

    #[test]
    fn write_incoming_lands_the_raw_bytes_under_the_staging_dir() {
        let git_dir = scratch_git_dir("write_incoming");
        let q = Quarantine::create(&git_dir).unwrap();
        q.write_incoming(b"not-yet-validated pack bytes").unwrap();
        assert_eq!(
            std::fs::read(q.dir().join("incoming.pack")).unwrap(),
            b"not-yet-validated pack bytes"
        );
    }

    #[test]
    fn create_sweeps_a_stale_quarantine_dir_but_leaves_a_fresh_one_alone() {
        let git_dir = scratch_git_dir("sweep");
        let objects_dir = git_dir.join("objects");

        // A stale dir: backdate its mtime well past the staleness
        // threshold via `File::set_modified` (stable std, no extra
        // dependency), simulating a prior run's dir that survived a
        // SIGKILL (Drop skipped) long enough ago to be safely swept.
        let stale = objects_dir.join(format!("{QUARANTINE_PREFIX}stale-leftover"));
        std::fs::create_dir_all(&stale).unwrap();
        let old_time =
            std::time::SystemTime::now() - (STALE_QUARANTINE_AGE + Duration::from_secs(60));
        std::fs::File::open(&stale)
            .unwrap()
            .set_modified(old_time)
            .unwrap();

        // A fresh dir with the same prefix - must NOT be swept (it looks
        // exactly like a concurrent in-flight push's own staging dir).
        let fresh = objects_dir.join(format!("{QUARANTINE_PREFIX}fresh-concurrent"));
        std::fs::create_dir_all(&fresh).unwrap();

        let _q = Quarantine::create(&git_dir).unwrap();

        assert!(
            !stale.exists(),
            "a stale quarantine dir should have been swept"
        );
        assert!(
            fresh.exists(),
            "a fresh (recently created) quarantine dir must never be swept"
        );
    }
}
