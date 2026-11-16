//! Recoverable publication for the loose and packed ref backend.

use super::{commands::RefUpdate, quarantine};
use crate::objectstore::ObjectStore;
use crate::refvalidate::{valid_oid, valid_wire_refname};
use rustgit::refs::lock::RefLock;
use rustgit::refs::loose::{format_ref_content, read_loose_ref, LooseRefValue, ZERO_OID};
use rustgit::refs::packed::{format_packed_refs, read_packed_refs};
use rustgit::refs::transaction::TransactionError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const INTENT: &str = ".dengel-push.json";
const STAGING_INTENT: &str = ".dengel-push.json.tmp";

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl FileIdentity {
    pub fn new(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    fn remove_owned(&self, path: &Path) -> io::Result<()> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() && (meta.dev(), meta.ino()) == (self.dev, self.ino) => {
                remove_if_exists(path)
            }
            Ok(_) => Err(invalid(
                "live file does not belong to the interrupted publication",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct PackOwner {
    pub id: String,
    pub pack: FileIdentity,
    pub index: FileIdentity,
}

#[derive(Deserialize, Serialize)]
struct Intent {
    // Only a pair absent before this push may be reclaimed.
    new_pack: Option<PackOwner>,
    updates: Vec<RefUpdate>,
    packed_deletes: BTreeMap<String, String>,
    // A loose change may be hidden by a packed ref with the same value.
    #[serde(default)]
    loose_deletes: BTreeSet<String>,
    #[serde(default)]
    loose_creates: BTreeSet<String>,
    quarantine: Option<String>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn begin(repo: &Path) -> io::Result<File> {
    let lock = File::open(repo)?;
    lock.lock()?;
    recover(repo)?;
    Ok(lock)
}

pub(crate) fn read_guard(repo: &Path) -> io::Result<File> {
    let lock = File::open(repo)?;
    loop {
        lock.lock_shared()?;
        if !has_pending(repo)? {
            return Ok(lock);
        }
        lock.unlock()?;
        lock.lock()?;
        recover(repo)?;
        lock.unlock()?;
    }
}

/// Reconcile an interrupted push before serving this repository.
pub fn recover_repository(repo: &Path) -> io::Result<()> {
    if has_pending(repo)? {
        let _lock = begin(repo)?;
    }
    Ok(())
}

fn has_pending(repo: &Path) -> io::Result<bool> {
    Ok(repo.join(INTENT).try_exists()? || repo.join(STAGING_INTENT).try_exists()?)
}

pub(super) fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn current_refs(repo: &Path, updates: &[RefUpdate]) -> io::Result<Vec<String>> {
    let packed = read_packed_refs(repo)?;
    updates
        .iter()
        .map(|update| match read_loose_ref(repo, &update.refname)? {
            Some(LooseRefValue::Oid(oid)) => Ok(oid),
            Some(LooseRefValue::Symref(_)) => Err(invalid("symbolic ref is not a push target")),
            None => Ok(packed
                .entries
                .get(&update.refname)
                .map_or_else(|| ZERO_OID.to_owned(), |entry| entry.oid.clone())),
        })
        .collect()
}

fn ref_lock(repo: &Path, name: &str) -> PathBuf {
    rustgit::refs::lock::lock_path_for(&repo.join(name))
}

pub(super) fn preflight(repo: &Path, updates: &[RefUpdate]) -> Result<(), TransactionError> {
    let mut seen = HashSet::new();
    for update in updates {
        let name = &update.refname;
        if !seen.insert(name.as_str()) {
            return Err(TransactionError::RepeatedRef {
                refname: name.clone(),
            });
        }
        if update.is_create() && update.is_delete() {
            return Err(TransactionError::InvalidOperation {
                refname: name.clone(),
                reason: "both object IDs are zero".into(),
            });
        }
        if ref_lock(repo, name).try_exists()? {
            return Err(TransactionError::PreconditionFailed {
                refname: name.clone(),
                reason: "ref has an existing lock".into(),
            });
        }
    }
    for update in updates {
        if Path::new(&update.refname)
            .ancestors()
            .skip(1)
            .any(|parent| parent.to_str().is_some_and(|name| seen.contains(name)))
        {
            return Err(TransactionError::InvalidOperation {
                refname: update.refname.clone(),
                reason: "ref batch has overlapping paths".into(),
            });
        }
    }
    if updates.iter().any(RefUpdate::is_delete) && ref_lock(repo, "packed-refs").try_exists()? {
        return Err(invalid("packed-refs has an existing lock").into());
    }
    check_expected_refs(repo, updates)
}

fn check_expected_refs(repo: &Path, updates: &[RefUpdate]) -> Result<(), TransactionError> {
    for (update, actual) in updates.iter().zip(current_refs(repo, updates)?) {
        if update.old != actual {
            return Err(TransactionError::PreconditionFailed {
                refname: update.refname.clone(),
                reason: format!("expected old oid {}, found {actual}", update.old),
            });
        }
    }
    Ok(())
}

/// Compute the exact storage delta for the ref batch. Deletes may free
/// loose ref bytes and rewrite the packed-refs file.
pub(super) fn ref_bytes(repo: &Path, updates: &[RefUpdate]) -> io::Result<(u64, u64)> {
    let file_bytes = |path: &Path| match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(metadata.len()),
        Ok(_) => Err(invalid("ref path is not a file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    };
    let mut prior = 0;
    let mut next = 0;
    for update in updates {
        prior += file_bytes(&repo.join(&update.refname))?;
        if !update.is_delete() {
            // The ref backend writes the 40-digit OID followed by LF.
            next += 41;
        }
    }
    if updates.iter().any(RefUpdate::is_delete) {
        let mut packed = read_packed_refs(repo)?;
        let count = packed.entries.len();
        for update in updates.iter().filter(|update| update.is_delete()) {
            packed.entries.remove(&update.refname);
        }
        if packed.entries.len() != count {
            prior += file_bytes(&repo.join("packed-refs"))?;
            next += format_packed_refs(&packed).len() as u64;
        }
    }
    Ok((prior, next))
}

pub(super) fn record(
    repo: &Path,
    new_pack: Option<&PackOwner>,
    updates: &[RefUpdate],
    quarantine: Option<&str>,
) -> io::Result<()> {
    let packed = read_packed_refs(repo)?;
    let packed_deletes = updates
        .iter()
        .filter(|update| update.is_delete())
        .filter_map(|update| {
            packed
                .entries
                .get(&update.refname)
                .map(|entry| (update.refname.clone(), entry.oid.clone()))
        })
        .collect();
    let mut loose_deletes = BTreeSet::new();
    let mut loose_creates = BTreeSet::new();
    for update in updates {
        let present = repo.join(&update.refname).try_exists()?;
        if update.is_delete() && present {
            loose_deletes.insert(update.refname.clone());
        } else if !update.is_delete() && !present {
            loose_creates.insert(update.refname.clone());
        }
    }
    let intent = Intent {
        new_pack: new_pack.cloned(),
        updates: updates.to_vec(),
        packed_deletes,
        loose_deletes,
        loose_creates,
        quarantine: quarantine.map(str::to_owned),
    };
    let temp = repo.join(STAGING_INTENT);
    remove_if_exists(&temp)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    serde_json::to_writer(&file, &intent)?;
    file.sync_all()?;
    fs::rename(temp, repo.join(INTENT))?;
    sync_dir(repo)
}

/// Prepare every ref lock and check CAS before publishing any ref file.
/// The receive path already verified object integrity and connectivity. An
/// index/loose lookup under the write lock confirms each exact tip is still
/// present without the legacy transaction's full-pack object lookup.
pub(super) fn apply(repo: &Path, updates: &[RefUpdate]) -> Result<(), TransactionError> {
    let acquire = |name: &str| {
        RefLock::acquire(&repo.join(name)).map_err(|source| TransactionError::LockFailed {
            refname: name.to_owned(),
            source,
        })
    };
    let mut locks = Vec::with_capacity(updates.len());
    for update in updates {
        locks.push(acquire(&update.refname)?);
    }
    let mut packed_lock = if updates.iter().any(RefUpdate::is_delete) {
        Some(acquire("packed-refs")?)
    } else {
        None
    };
    check_expected_refs(repo, updates)?;
    if updates.iter().any(|update| !update.is_delete()) {
        let store = ObjectStore::open(repo).map_err(io::Error::other)?;
        for update in updates.iter().filter(|update| !update.is_delete()) {
            if !store.contains(&update.new)? {
                return Err(TransactionError::PreconditionFailed {
                    refname: update.refname.clone(),
                    reason: format!("object {} does not exist", update.new),
                });
            }
        }
    }
    let mut rewrite_packed = false;
    if let Some(lock) = packed_lock.as_mut() {
        let mut packed = read_packed_refs(repo)?;
        for update in updates.iter().filter(|update| update.is_delete()) {
            rewrite_packed |= packed.entries.remove(&update.refname).is_some();
        }
        if rewrite_packed {
            lock.write_content(format_packed_refs(&packed).as_bytes())?;
        }
    }
    for (update, lock) in updates.iter().zip(&mut locks) {
        if !update.is_delete() {
            lock.write_content(&format_ref_content(&LooseRefValue::Oid(update.new.clone())))?;
        }
    }
    for (update, lock) in updates.iter().zip(locks) {
        if update.is_delete() {
            lock.commit_delete()?;
        } else {
            lock.commit()?;
        }
    }
    if rewrite_packed {
        packed_lock.expect("packed rewrite was prepared").commit()?;
    }
    Ok(())
}

pub(super) fn committed(repo: &Path, updates: &[RefUpdate]) -> io::Result<()> {
    let mut directories = BTreeSet::new();
    for update in updates {
        let target = repo.join(&update.refname);
        directories.extend(
            target
                .ancestors()
                .skip(1)
                .take_while(|p| *p != repo)
                .map(Path::to_owned),
        );
    }
    for directory in directories.iter().rev() {
        if directory.try_exists()? {
            sync_dir(directory)?;
        }
    }
    sync_dir(repo)?;
    remove_if_exists(&repo.join(INTENT))?;
    sync_dir(repo)
}

pub(super) fn recover(repo: &Path) -> io::Result<bool> {
    let stage = repo.join(STAGING_INTENT);
    if stage.try_exists()? {
        remove_if_exists(&stage)?;
        sync_dir(repo)?;
    }
    let file = match File::open(repo.join(INTENT)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let intent: Intent = serde_json::from_reader(file)?;
    if intent.updates.iter().any(|update| {
        !valid_wire_refname(&update.refname) || !valid_oid(&update.old) || !valid_oid(&update.new)
    }) || intent
        .new_pack
        .as_ref()
        .is_some_and(|owner| !valid_oid(&owner.id))
    {
        return Err(invalid("invalid pending Git publication"));
    }
    let current = current_refs(repo, &intent.updates)?;
    if intent.updates.iter().zip(&current).any(|(update, actual)| {
        actual != &update.old
            && actual != &update.new
            && (!update.is_delete() || intent.packed_deletes.get(&update.refname) != Some(actual))
    }) {
        return Err(invalid("a ref changed outside the pending Git publication"));
    }
    let mut did_commit = intent
        .updates
        .iter()
        .zip(&current)
        .any(|(update, actual)| actual != &update.old);
    for update in &intent.updates {
        let present = repo.join(&update.refname).try_exists()?;
        did_commit |= (!present && intent.loose_deletes.contains(&update.refname))
            || (present && intent.loose_creates.contains(&update.refname));
    }

    // The intent was recorded with these lock paths absent. Every
    // receive-pack writer holds the outer lock before touching them.
    for update in &intent.updates {
        remove_if_exists(&ref_lock(repo, &update.refname))?;
    }
    if intent.updates.iter().any(RefUpdate::is_delete) {
        remove_if_exists(&ref_lock(repo, "packed-refs"))?;
    }
    if did_commit {
        let remaining = intent
            .updates
            .iter()
            .zip(&current)
            .filter(|(update, actual)| &update.new != *actual)
            .map(|(update, actual)| {
                let mut expected = update.clone();
                expected.old.clone_from(actual);
                expected
            })
            .collect::<Vec<_>>();
        apply(repo, &remaining).map_err(io::Error::other)?;
    } else if let Some(pack) = &intent.new_pack {
        let pack_dir = repo.join("objects/pack");
        pack.index
            .remove_owned(&pack_dir.join(format!("pack-{}.idx", pack.id)))?;
        pack.pack
            .remove_owned(&pack_dir.join(format!("pack-{}.pack", pack.id)))?;
        if pack_dir.try_exists()? {
            sync_dir(&pack_dir)?;
        }
    }
    if let Some(name) = &intent.quarantine {
        quarantine::discard_crashed(repo, name)?;
    }
    committed(repo, &intent.updates)?;
    Ok(did_commit)
}

#[cfg(test)]
mod tests {
    use super::super::session::to_ref_op;
    use super::*;
    use crate::object::{loose, Kind};
    use crate::receive::quarantine::Quarantine;
    use rustgit::pack::writer::{write_pack, WriteObject};
    use rustgit::refs::transaction::{execute_transaction, RefOp};

    fn bare() -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        fs::create_dir_all(repo.path().join("objects")).unwrap();
        fs::create_dir_all(repo.path().join("refs/tags")).unwrap();
        fs::write(repo.path().join("HEAD"), "ref: refs/heads/main\n").unwrap();
        repo
    }

    fn create(name: &str, oid: &str) -> RefUpdate {
        RefUpdate {
            old: ZERO_OID.into(),
            new: oid.into(),
            refname: format!("refs/tags/{name}"),
        }
    }

    #[test]
    fn quota_projection_matches_combined_loose_and_packed_ref_writes() {
        let repo = bare();
        let repo = repo.path();
        let oid = loose::write(repo, Kind::Blob, b"existing object").unwrap();
        let name = "refs/tags/replaced";
        fs::write(repo.join(name), format!("{oid}\n")).unwrap();
        // Stock Git normally emits a header, but the backend also reads
        // older headerless files and adds a header when it rewrites them.
        fs::write(repo.join("packed-refs"), format!("{oid} {name}\n")).unwrap();
        let updates = [
            RefUpdate {
                old: oid.clone(),
                new: ZERO_OID.to_owned(),
                refname: name.to_owned(),
            },
            create("new", &oid),
        ];
        let before = crate::receive::session::stored_bytes(repo).unwrap();
        let (old_refs, new_refs) = ref_bytes(repo, &updates).unwrap();
        apply(repo, &updates).unwrap();
        assert_eq!(
            before - old_refs + new_refs,
            crate::receive::session::stored_bytes(repo).unwrap()
        );
    }

    #[test]
    fn recovery_discards_only_the_interrupted_push_pack() {
        let repo = bare();
        let repo = repo.path();
        let make_pack = |content: &[u8]| {
            write_pack(&[WriteObject {
                kind: 3,
                content: content.to_vec(),
            }])
        };
        let quarantine = Quarantine::create(repo).unwrap();
        let older = make_pack(b"previous push");
        let previous = quarantine
            .prepare(&older.pack_bytes, &older.idx_bytes)
            .unwrap();
        previous.publish(repo, &quarantine).unwrap();
        let incoming = make_pack(b"interrupted push");
        let staged = quarantine
            .prepare(&incoming.pack_bytes, &incoming.idx_bytes)
            .unwrap();
        let oid = rustgit::pack::pack::compute_oid(3, b"interrupted push");
        let update = create("new", &oid);
        let original_bytes = crate::receive::session::stored_bytes(repo).unwrap();
        {
            let _lock = begin(repo).unwrap();
            preflight(repo, std::slice::from_ref(&update)).unwrap();
            record(repo, Some(staged.owner()), &[update], None).unwrap();
            staged.publish(repo, &quarantine).unwrap();
        }
        recover_repository(repo).unwrap();
        assert!(staged.needs_publication(repo).unwrap());
        assert!(!previous.needs_publication(repo).unwrap());
        assert_eq!(
            crate::receive::session::stored_bytes(repo).unwrap(),
            original_bytes
        );
    }

    #[test]
    fn recovery_does_not_delete_a_replaced_pack() {
        let repo = bare();
        let repo = repo.path();
        let q = Quarantine::create(repo).unwrap();
        let pack = write_pack(&[WriteObject {
            kind: 3,
            content: b"staged".to_vec(),
        }]);
        let staged = q.prepare(&pack.pack_bytes, &pack.idx_bytes).unwrap();
        let oid = rustgit::pack::pack::compute_oid(3, b"staged");
        let update = create("new", &oid);
        {
            let _lock = begin(repo).unwrap();
            preflight(repo, std::slice::from_ref(&update)).unwrap();
            record(repo, Some(staged.owner()), &[update], None).unwrap();
            staged.publish(repo, &q).unwrap();
        }
        let live = repo
            .join("objects/pack")
            .join(format!("pack-{}.pack", staged.owner().id));
        fs::remove_file(&live).unwrap();
        fs::write(&live, b"external replacement").unwrap();

        assert!(recover_repository(repo).is_err());
        assert_eq!(fs::read(live).unwrap(), b"external replacement");
    }

    #[test]
    fn wire_read_completes_all_refs_of_an_interrupted_batch() {
        let repo = bare();
        let repo = repo.path();
        let oid = loose::write(repo, Kind::Blob, b"tag payload").unwrap();
        let updates = [create("one", &oid), create("two", &oid)];
        {
            let _lock = begin(repo).unwrap();
            preflight(repo, &updates).unwrap();
            record(repo, None, &updates, None).unwrap();
            execute_transaction(repo, &[to_ref_op(&updates[0])]).unwrap();
            fs::write(ref_lock(repo, &updates[1].refname), "").unwrap();
        }
        {
            let _read = read_guard(repo).unwrap();
            assert_eq!(
                current_refs(repo, &updates).unwrap(),
                vec![oid.clone(), oid]
            );
            assert!(!repo.join(INTENT).exists());
            assert!(!ref_lock(repo, &updates[1].refname).exists());
        }
        recover_repository(repo).unwrap();
    }

    #[test]
    fn recovery_finishes_delete_when_the_packed_shadow_has_the_same_oid() {
        let repo = bare();
        let repo = repo.path();
        let oid = loose::write(repo, Kind::Blob, b"shared ref value").unwrap();
        let name = "refs/tags/deleted";
        fs::write(repo.join(name), format!("{oid}\n")).unwrap();
        fs::write(repo.join("packed-refs"), format!("{oid} {name}\n")).unwrap();
        let update = RefUpdate {
            old: oid,
            new: ZERO_OID.to_owned(),
            refname: name.to_owned(),
        };
        record(repo, None, std::slice::from_ref(&update), None).unwrap();
        fs::remove_file(repo.join(name)).unwrap();

        assert!(recover(repo).unwrap());
        assert_eq!(
            current_refs(repo, &[update]).unwrap(),
            [ZERO_OID.to_owned()]
        );
    }

    #[test]
    fn recovery_finishes_delete_when_a_packed_shadow_was_exposed() {
        let repo = bare();
        let repo = repo.path();
        let old = loose::write(repo, Kind::Blob, b"packed").unwrap();
        let new = loose::write(repo, Kind::Blob, b"loose").unwrap();
        let refname = "refs/tags/delete";
        fs::write(repo.join("packed-refs"), format!("{old} {refname}\n")).unwrap();
        execute_transaction(
            repo,
            &[RefOp::Update {
                refname: refname.to_owned(),
                new: new.clone(),
                old: Some(old.clone()),
            }],
        )
        .unwrap();
        let update = RefUpdate {
            old: new,
            new: ZERO_OID.into(),
            refname: refname.into(),
        };
        {
            let _lock = begin(repo).unwrap();
            preflight(repo, std::slice::from_ref(&update)).unwrap();
            record(repo, None, std::slice::from_ref(&update), None).unwrap();
            fs::remove_file(repo.join(refname)).unwrap();
        }
        recover_repository(repo).unwrap();
        assert_eq!(
            current_refs(repo, &[update]).unwrap(),
            vec![ZERO_OID.to_owned()]
        );
    }
}
