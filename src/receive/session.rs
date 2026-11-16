//! The receive-pack conversation: advertise refs, read the command list
//! and pack, run the ADR-0008 pipeline, emit report-status. Acknowledge
//! ONLY after the ref transaction commits.
//!
//! UNLIKE G2's upload-pack (server/session.rs), this is NOT protocol v2:
//! gitprotocol-pack.adoc's "Pushing Data to a Server" section defines an
//! entirely separate, older wire shape for receive-pack - a plain
//! ref advertisement (no `version 2` line, no command=/delim-pkt
//! wrapping), a client-sent command list, then the packfile as RAW bytes
//! (no pkt-line framing at all) immediately after the command list's
//! flush-pkt, then report-status. Real git never speaks protocol v2 for
//! push, regardless of `protocol.version` - only fetch got a v2
//! redefinition. Every grammar fragment below cites the exact adoc
//! section it comes from.

use super::{commands, connectivity, publication, quarantine, ReceiveError};
use crate::ingest;
use crate::object::{commit, tag, tree, Kind};
use crate::server;
use rustgit::protocol::pktline::{self, PktLine};
use rustgit::refs::checkpoint::checkpoint;
use rustgit::refs::loose::ZERO_OID;
#[cfg(test)]
use rustgit::refs::transaction::RefOp;
use rustgit::refs::transaction::TransactionError;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

// All supported ref changes share a recoverable publication and are
// reported as one batch. Only advertise capabilities we accept.
const CAPABILITIES: &str = "report-status delete-refs ofs-delta atomic";
const MAX_PUSH_OBJECTS: usize = 100_000;
const MAX_INFLATED_PUSH_BYTES: usize = 256 * 1024 * 1024;
const MAX_PACK_BYTES: usize = 64 * 1024 * 1024;
const MAX_REF_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_REF_COMMANDS: usize = 1024;

/// The only ref namespace a `candidate_only` push may touch.
pub const CANDIDATE_REF_PREFIX: &str = "refs/heads/candidate/";

/// The report-status reason a push gets for a ref under a reserved prefix.
pub const RESERVED_REF_MESSAGE: &str =
    "this ref belongs to a run and is written only with that run's token";

/// The report-status reason a `candidate_only` push gets for any other ref.
pub const CANDIDATE_ONLY_MESSAGE: &str =
    "only refs/heads/candidate/* may be pushed; main changes only through review";

/// What a push is allowed to do, decided by whoever serves the repository.
/// `Default` is no restriction - the behaviour every caller had before this
/// type existed (the stdio flavor and the legacy shared-token server).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceivePolicy {
    /// Every command (create, update, delete, tags too) must name a ref
    /// under `CANDIDATE_REF_PREFIX`; any other ref rejects the whole push
    /// before the pack is read.
    pub candidate_only: bool,
    /// Upper bound on the repository's stored bytes once the incoming pack
    /// is written; exceeding it rejects the whole push before promotion.
    pub max_repo_bytes: Option<u64>,
    /// Ref namespaces a push may not touch at all, each ending in `/`
    /// (NMA-2442: `refs/heads/candidate/<run-id>/` belongs to that run and is
    /// written only through the run's token). Any command under one rejects
    /// the whole push before the pack is read.
    pub reserved_prefixes: Vec<String>,
}

/// The hosted adapter supplies the current quota and a cross-process guard
/// after validation. The guard remains held through publication and recovery.
pub struct PublicationAdmission {
    max_repo_bytes: Option<u64>,
    _guard: Box<dyn Send>,
}

impl PublicationAdmission {
    pub fn new(max_repo_bytes: Option<u64>, guard: impl Send + 'static) -> Self {
        Self {
            max_repo_bytes,
            _guard: Box::new(guard),
        }
    }
}

/// Serve one receive-pack session over arbitrary read/write halves
/// (stdio flavor; HTTP reuses `advertisement` + `handle_receive_body`
/// per POST/GET - see http.rs).
pub fn serve_receive_pack(
    git_dir: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), ReceiveError> {
    serve_receive_pack_with_policy(git_dir, input, output, &ReceivePolicy::default())
}

/// [`serve_receive_pack`] under a policy, for transports that must enforce
/// what the managed HTTP listener enforces (NMA-2371: SSH pushes are
/// candidate-only with the same quota).
pub fn serve_receive_pack_with_policy(
    git_dir: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
    policy: &ReceivePolicy,
) -> Result<(), ReceiveError> {
    serve_receive_pack_with_admission(git_dir, input, output, policy, || {
        Ok(PublicationAdmission::new(policy.max_repo_bytes, ()))
    })
}

pub fn serve_receive_pack_with_admission(
    git_dir: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
    policy: &ReceivePolicy,
    admit: impl FnOnce() -> std::io::Result<PublicationAdmission>,
) -> Result<(), ReceiveError> {
    // Same `&mut dyn Read` -> generic-`R: Read` bridging trick as G2's
    // server/session.rs (see that file's comment on the identical line)
    // - `&mut dyn Read` is itself `Sized` and implements `Read`.
    let mut input = input;

    output.write_all(&advertisement(git_dir)?)?;
    output.flush()?;

    let report = process_push(git_dir, &mut input, policy, admit)?;
    output.write_all(&report)?;
    output.flush()?;
    Ok(())
}

/// Handles one complete receive-pack request read from `body` (the
/// command list, then the pack if one was sent - see `process_push`),
/// with no advertisement writing of its own (the GET /info/refs handler
/// already sent it - see http.rs).
pub(crate) fn handle_receive_reader(
    git_dir: &Path,
    input: &mut dyn Read,
    policy: &ReceivePolicy,
    admit: impl FnOnce() -> std::io::Result<PublicationAdmission>,
) -> Result<Vec<u8>, ReceiveError> {
    process_push(git_dir, input, policy, admit)
}

/// gitprotocol-pack.adoc, "Reference Discovery" (push side), which
/// itself points back at the fetch-side grammar (gitprotocol-pack.adoc,
/// "Reference Discovery", fetch side):
///   advertised-refs = *1("version 1") (no-refs / list-of-refs) *shallow flush-pkt
///   no-refs         = PKT-LINE(zero-id SP "capabilities^{}" NUL capability-list)
///   list-of-refs    = first-ref *other-ref
///   first-ref       = PKT-LINE(obj-id SP refname NUL capability-list)
///   other-ref       = PKT-LINE(other-tip / other-peeled)
///   other-tip       = obj-id SP refname
/// "shallow"/"other-peeled" are not applicable here (receive-pack
/// advertises no peeled tag lines and this server has no shallow
/// support at all). No `version 1` prefix line - that only appears when
/// the Git transport's `version=1` extra-parameter was sent, which this
/// server's transports (stdio/ssh-equivalent, smart-HTTP) never use.
pub(crate) fn advertisement(git_dir: &Path) -> Result<Vec<u8>, ReceiveError> {
    let _read = publication::read_guard(git_dir)?;
    let refs = server::ls_refs::enumerate_all_refs(git_dir)?;

    let mut out = Vec::new();
    if refs.is_empty() {
        let line = format!("{ZERO_OID} capabilities^{{}}\0{CAPABILITIES}\n");
        out.extend_from_slice(&pktline::encode_data(line.as_bytes()));
    } else {
        for (i, (refname, oid)) in refs.iter().enumerate() {
            let line = if i == 0 {
                format!("{oid} {refname}\0{CAPABILITIES}\n")
            } else {
                format!("{oid} {refname}\n")
            };
            out.extend_from_slice(&pktline::encode_data(line.as_bytes()));
        }
    }
    out.extend_from_slice(&pktline::encode_flush());
    Ok(out)
}

/// Reads the command list, then (if the push needs one) the pack, runs
/// the ADR-0008 pipeline, and returns the report-status bytes - or an
/// empty response for the degenerate "client sent nothing to do" case
/// (a lone flush-pkt right after the advertisement).
///
/// Every failure from here on - including a broken/truncated pack that
/// `stage_pack`'s own boundary scan chokes on - is turned into
/// report-status bytes rather than an `Err` that would abort the whole
/// session with no response at all. A hand-verified regression (fixed
/// alongside the report-status completeness fix below): before this,
/// `stage_pack`'s `?` propagated straight out of `process_push`,
/// so a garbage pack made `serve_receive_pack` return `Err` and the
/// client got NOTHING on the wire (just a closed connection / our
/// stderr) instead of a `unpack <error>` line - confirmed by feeding
/// the same broken request to real `git receive-pack`, which always
/// answers with report-status even for a pack it cannot even parse the
/// magic of. See NOTES.md.
fn process_push(
    git_dir: &Path,
    input: &mut dyn Read,
    policy: &ReceivePolicy,
    admit: impl FnOnce() -> std::io::Result<PublicationAdmission>,
) -> Result<Vec<u8>, ReceiveError> {
    let mut input = input;
    let (updates, _capabilities) = read_command_list(&mut input)?;
    if updates.is_empty() {
        return Ok(Vec::new());
    }

    // Policy refusal comes before the pack is even read: nothing of a push
    // that touches a non-candidate ref is processed, and the whole push is
    // reported rejected through the same reject-all path as a failed
    // transaction.
    if policy.candidate_only {
        if let Some(offender) = updates
            .iter()
            .find(|u| !u.refname.starts_with(CANDIDATE_REF_PREFIX))
        {
            let mut out = Vec::new();
            append_report_status(
                &mut out,
                &updates,
                &Outcome::Rejected {
                    primary_refname: offender.refname.clone(),
                    primary_reason: CANDIDATE_ONLY_MESSAGE.to_string(),
                },
            );
            return Ok(out);
        }
    }

    if let Some(offender) = updates.iter().find(|u| {
        policy.reserved_prefixes.iter().any(|prefix| {
            u.refname.starts_with(prefix.as_str()) || u.refname == prefix.trim_end_matches('/')
        })
    }) {
        let mut out = Vec::new();
        append_report_status(
            &mut out,
            &updates,
            &Outcome::Rejected {
                primary_refname: offender.refname.clone(),
                primary_reason: RESERVED_REF_MESSAGE.to_string(),
            },
        );
        return Ok(out);
    }

    // gitprotocol-pack.adoc, "Reference Update Request and Packfile
    // Transfer": "The packfile MUST NOT be sent if the only command used
    // is 'delete'." - a delete-only push has no bytes at all after the
    // command list's flush-pkt, so reading a pack must be skipped
    // entirely rather than trying to parse zero bytes as one.
    let needs_pack = updates.iter().any(|u| !u.is_delete());

    let mut out = Vec::new();
    let staged = if needs_pack {
        let accept_pack = |input: &mut dyn Read| -> Result<quarantine::Quarantine, ReceiveError> {
            let quarantine = quarantine::Quarantine::create(git_dir)?;
            let mut ingress = std::fs::File::create(quarantine.dir().join("incoming.pack"))?;
            stage_pack(input, &mut ingress)?;
            ingress.sync_all()?;
            checkpoint("after_quarantine_write");
            Ok(quarantine)
        };
        match accept_pack(input) {
            Ok(quarantine) => Some(quarantine),
            Err(error) => {
                append_unpack_failure(&mut out, &updates, &error.to_string());
                return Ok(out);
            }
        }
    } else {
        None
    };

    match run_pipeline(git_dir, &updates, staged, admit) {
        Ok(()) => append_report_status(&mut out, &updates, &Outcome::Success),
        Err(StageError::PolicyRejected(reason)) => append_report_status(
            &mut out,
            &updates,
            &Outcome::Rejected {
                primary_refname: updates[0].refname.clone(),
                primary_reason: reason,
            },
        ),
        Err(StageError::UnpackFailed(msg)) => append_unpack_failure(&mut out, &updates, &msg),
        Err(StageError::NotConnected { tip, missing }) => {
            // Real git's own wording for this exact case (hand-verified
            // below): "unpack ok" (the pack itself decoded fine), then
            // a per-ref "missing necessary objects" - NOT the blanket
            // "unpack <error>" / "unpacker error" shape a decode-level
            // failure gets. `tip` names which update's `new` oid the
            // walk was rooted at when it found the gap; `missing` (the
            // actual absent oid) goes into the `unpack ok` line's
            // sibling detail only via NOTES.md/logs, not the wire -
            // gitprotocol-pack.adoc's error-msg has no structured field
            // for it and real git doesn't send it either.
            let _ = &missing; // named for the doc comment above, not the wire text
            let primary_refname = updates
                .iter()
                .find(|u| u.new == tip)
                .map(|u| u.refname.clone())
                .unwrap_or(tip);
            let primary_reason = "missing necessary objects".to_string();
            append_report_status(
                &mut out,
                &updates,
                &Outcome::Rejected {
                    primary_refname,
                    primary_reason,
                },
            );
        }
        Err(StageError::RefsRejected(e)) => {
            let (primary_refname, primary_reason) = transaction_error_refname_reason(&e);
            append_report_status(
                &mut out,
                &updates,
                &Outcome::Rejected {
                    primary_refname,
                    primary_reason,
                },
            );
        }
    }
    Ok(out)
}

enum StageError {
    /// The pack itself never became a usable object set - decode,
    /// per-object well-formedness, the idx write, or the promote I/O
    /// failed. No ref could possibly have landed. Reported as `unpack
    /// <error>` PLUS a blanket `ng <ref> unpacker error` for every
    /// update in the push - hand-verified against real `git
    /// receive-pack` fed a deliberately garbage pack with two ref
    /// updates: it answers `unpack protocol error (pack signature
    /// mismatch detected)` then `ng refs/heads/one unpacker error` /
    /// `ng refs/heads/two unpacker error`, i.e. every ref gets the same
    /// generic per-ref reason regardless of which ref it is - matched
    /// exactly by `append_unpack_failure` below. See NOTES.md.
    UnpackFailed(String),
    /// The pack decoded and every object parsed fine, but a tip's
    /// history is not fully connected (ADR-0008 step 4, never skipped).
    /// Real git reports THIS case differently from `UnpackFailed`:
    /// `unpack ok` (the pack itself was fine) then a per-ref `ng <ref>
    /// missing necessary objects` - hand-verified against real `git
    /// receive-pack` fed a pack missing a commit's parent. Kept as a
    /// single atomic-batch rejection here (see `Outcome::Rejected`)
    /// rather than letting an unaffected ref in the same push land,
    /// per this milestone's explicit "do not change atomic semantics"
    /// instruction - real git's own default (non-atomic) posture would
    /// let other refs land independently, which this server
    /// deliberately does not do (see `CAPABILITIES`'s doc comment on
    /// why `atomic` is unconditional here).
    NotConnected { tip: String, missing: String },
    /// The pack (if any) was fine, but `execute_transaction` rejected
    /// the batch (old-oid CAS mismatch, lock contention, ...). Refs did
    /// NOT move - ADR-0008: "the promoted pack is harmless (unreferenced
    /// objects, valid repo)".
    RefsRejected(TransactionError),
    /// The pack was fine but storing it would break the `ReceivePolicy`
    /// (the repository size cap). Nothing was promoted, no ref moved.
    PolicyRejected(String),
}

/// Runs steps 1-6 of ADR-0008: quarantine dir -> write the raw,
/// not-yet-validated pack into it (literally step 1's "the incoming
/// pack lands in a fresh temporary directory... BEFORE" anything is
/// checked) -> decode -> well-formedness -> connectivity closure ->
/// promote -> ref transaction. Step 7 (report-status) is the caller's
/// job - this function's `Ok(())` means "the transaction committed",
/// nothing more; the report line text still needs the update list,
/// which the caller already has.
///
/// Three checkpoints (via rustgit's generic, no-op-unless-configured
/// `REFSTORE_HARNESS_CHECKPOINT_DIR` mechanism - see
/// `rustgit::refs::checkpoint`'s own doc comment, reused verbatim, same
/// convention as G3's `refs::lock`) mark the boundaries the crash role
/// asked to target directly instead of coarse timing:
///   - `after_quarantine_write`: the raw pack bytes are durably on disk
///     in the quarantine dir, decode/well-formedness/connectivity have
///     NOT run yet. A SIGKILL here must leave `objects/pack/` and every
///     ref untouched, with at most a stale `dengel-quarantine-*` dir
///     behind (cleaned by `Quarantine::create`'s own sweep on the next
///     push, or by this process's own `Drop` if it hadn't been killed).
///   - `after_connectivity_ok`: the pack is proven fully connected but
///     NOT yet promoted (still only under the quarantine dir, not
///     `objects/pack/`). A SIGKILL here must leave the SAME
///     post-condition as the previous checkpoint.
///   - `after_promote`: the pack and index are linked into
///     `objects/pack/`, with the recovery intent already durable.
///     If no ref committed, recovery removes only the files owned by
///     this push. If ref publication began, recovery finishes the batch.
fn run_pipeline(
    git_dir: &Path,
    updates: &[commands::RefUpdate],
    staged: Option<quarantine::Quarantine>,
    admit: impl FnOnce() -> std::io::Result<PublicationAdmission>,
) -> Result<(), StageError> {
    let staged = if let Some(quarantine) = staged {
        let _read = publication::read_guard(git_dir).map_err(stage_unpack_failed)?;
        let store = crate::objectstore::ObjectStore::open(git_dir).map_err(stage_unpack_failed)?;
        let resolve_from_store = |oid: &str| store.resolve_for_receive(oid, false).ok().flatten();
        let decoded = ingest::disk::decode(
            quarantine.dir(),
            ingest::DecodeLimits {
                max_objects: MAX_PUSH_OBJECTS,
                max_object_bytes: MAX_INFLATED_PUSH_BYTES,
            },
            &resolve_from_store,
        )
        .map_err(stage_unpack_failed)?;

        for obj in decoded.objects() {
            if obj.kind != Kind::Blob {
                let content = decoded.read(obj).map_err(stage_unpack_failed)?;
                well_formed(obj, &content).map_err(StageError::UnpackFailed)?;
            }
        }
        let tips = updates.iter().filter(|u| !u.is_delete()).map(|u| {
            let expected = u.refname.starts_with("refs/heads/").then_some(Kind::Commit);
            (u.new.as_str(), expected)
        });
        connectivity::walk(tips, |oid| {
            if let Some(object) = decoded.get(oid) {
                let content = if object.kind == Kind::Blob {
                    Vec::new()
                } else {
                    decoded.read(object)?
                };
                Ok(Some((object.kind, content)))
            } else {
                Ok(store.resolve_for_receive(oid, true).ok().flatten())
            }
        })
        .map_err(|e| match e {
            ReceiveError::NotConnected { tip, missing } => {
                StageError::NotConnected { tip, missing }
            }
            other => StageError::UnpackFailed(other.to_string()),
        })?;
        checkpoint("after_connectivity_ok");

        if decoded.objects().is_empty() {
            None
        } else {
            let id = decoded
                .write_pack(quarantine.dir())
                .map_err(stage_unpack_failed)?;
            let pack = quarantine.prepare_files(id).map_err(stage_unpack_failed)?;
            Some((quarantine, pack))
        }
    } else {
        None
    };

    let admission = admit().map_err(stage_unpack_failed)?;
    let _repo_lock = publication::begin(git_dir).map_err(stage_unpack_failed)?;
    publication::preflight(git_dir, updates).map_err(StageError::RefsRejected)?;
    let new_pack = staged
        .as_ref()
        .map(|(_, pack)| {
            pack.needs_publication(git_dir)
                .map(|needed| needed.then_some(pack.owner()))
        })
        .transpose()
        .map_err(stage_unpack_failed)?
        .flatten();

    if let Some(max) = admission.max_repo_bytes {
        let pack_growth = staged
            .as_ref()
            .zip(new_pack)
            .map_or(0, |((_, pack), _)| pack.bytes());
        let (prior_refs, next_refs) =
            publication::ref_bytes(git_dir, updates).map_err(stage_unpack_failed)?;
        let original = stored_bytes(git_dir).map_err(stage_unpack_failed)?;
        let total = original
            .saturating_sub(prior_refs)
            .saturating_add(next_refs)
            .saturating_add(pack_growth);
        if total > max && total > original {
            return Err(StageError::PolicyRejected(format!(
                "repository size limit exceeded: {total} bytes would exceed the {max} byte limit"
            )));
        }
    }

    let quarantine_name = staged
        .as_ref()
        .and_then(|(quarantine, _)| quarantine.dir().file_name()?.to_str());
    publication::record(git_dir, new_pack, updates, quarantine_name)
        .map_err(stage_unpack_failed)?;
    if let Some(((quarantine, pack), _)) = staged.as_ref().zip(new_pack) {
        if let Err(error) = pack.publish(git_dir, quarantine) {
            publication::recover(git_dir).map_err(stage_unpack_failed)?;
            return Err(stage_unpack_failed(error));
        }
        checkpoint("after_promote");
    }

    if let Err(error) = publication::apply(git_dir, updates) {
        if !publication::recover(git_dir).map_err(stage_unpack_failed)? {
            return Err(StageError::RefsRejected(error));
        }
    } else {
        publication::committed(git_dir, updates).map_err(stage_unpack_failed)?;
    }
    checkpoint("after_durable_commit");

    Ok(())
}

/// Bytes the repository holds on disk, excluding in-flight quarantine dirs
/// (the incoming raw pack is not stored; what `promote` would add is counted
/// separately by the caller). Symlinks are not followed.
/// Bytes stored under `dir`, recursively: what the repository size quota
/// counts (also used by the server-side write routes, NMA-2442).
pub fn stored_bytes(dir: &Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(quarantine::QUARANTINE_PREFIX)
        {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            total += stored_bytes(&entry.path())?;
        } else if file_type.is_file() {
            total += entry.metadata()?.len();
        }
    }
    Ok(total)
}

fn stage_unpack_failed<E: std::fmt::Display>(e: E) -> StageError {
    StageError::UnpackFailed(e.to_string())
}

fn well_formed(obj: &ingest::disk::Object, content: &[u8]) -> Result<(), String> {
    match obj.kind {
        Kind::Commit => commit::refs(content)
            .map(|_| ())
            .map_err(|e| format!("commit {}: {}", obj.oid, e)),
        Kind::Tree => tree::entries(content)
            .map(|_| ())
            .map_err(|e| format!("tree {}: {}", obj.oid, e)),
        Kind::Tag => tag::refs(content)
            .map(|_| ())
            .map_err(|e| format!("tag {}: {}", obj.oid, e)),
        Kind::Blob => Ok(()),
    }
}

#[cfg(test)]
pub(super) fn to_ref_op(u: &commands::RefUpdate) -> RefOp {
    if u.is_create() {
        RefOp::Create {
            refname: u.refname.clone(),
            new: u.new.clone(),
        }
    } else if u.is_delete() {
        // `old` is the client's believed current value - the CAS
        // precondition that makes a concurrent-modification push fail
        // rather than silently deleting the wrong history. If `old` is
        // itself the zero oid (a syntactically valid but semantically
        // nonsensical "delete a ref I already believe doesn't exist"
        // line - see commands.rs's `is_create_and_is_delete_are_...`
        // test), `execute_transaction` rejects it on its own
        // ("delete old-oid may not be zero") - deliberately NOT
        // special-cased away here, so that rejection surfaces as a
        // legitimate per-ref `ng` rather than being silently reinterpreted.
        RefOp::Delete {
            refname: u.refname.clone(),
            old: Some(u.old.clone()),
        }
    } else {
        RefOp::Update {
            refname: u.refname.clone(),
            new: u.new.clone(),
            old: Some(u.old.clone()),
        }
    }
}

/// Pulls `(refname, reason)` out of whichever `TransactionError` variant
/// `execute_transaction` returned, for the report-status line that
/// blames the one ref that actually tripped the (atomic, all-or-nothing)
/// transaction - see `Outcome::Rejected` and `append_report_status`.
fn transaction_error_refname_reason(e: &TransactionError) -> (String, String) {
    match e {
        TransactionError::LockFailed { refname, source } => (refname.clone(), source.to_string()),
        TransactionError::PreconditionFailed { refname, reason } => {
            (refname.clone(), reason.clone())
        }
        TransactionError::RepeatedRef { refname } => {
            (refname.clone(), "repeated ref in the same push".to_string())
        }
        TransactionError::InvalidOperation { refname, reason } => (refname.clone(), reason.clone()),
        TransactionError::Io(io_err) => (String::new(), io_err.to_string()),
    }
}

enum Outcome {
    Success,
    Rejected {
        primary_refname: String,
        primary_reason: String,
    },
}

/// gitprotocol-pack.adoc, "Report Status":
///   report-status  = unpack-status 1*(command-status) flush-pkt
///   unpack-status  = PKT-LINE("unpack" SP unpack-result)
///   unpack-result  = "ok" / error-msg
///   command-status = command-ok / command-fail
///   command-ok     = PKT-LINE("ok" SP refname)
///   command-fail   = PKT-LINE("ng" SP refname SP error-msg)
/// Called only when the pack (if any) unpacked cleanly - "unpack ok" is
/// unconditional here; a genuine unpack failure goes through
/// `append_unpack_failure` instead and never reaches this function.
///
/// JUDGMENT CALL (not in the grammar, logged per CLAUDE.md): since
/// `execute_transaction` is called ONCE, atomically, over the whole
/// command list (ADR-0008's explicit instruction - not the client-
/// requested `atomic` capability, which this server does not even
/// advertise, see `CAPABILITIES`'s doc comment), a single rejected
/// precondition rolls back every ref in the same push, not just the one
/// that failed its own check. The ref actually named by the
/// `TransactionError` gets its specific reason; every other ref in the
/// same push gets a generic "transaction rejected" line naming the
/// primary failure, since none of them landed either - reporting them
/// as `ok` would be exactly the silent-wrongness ADR-0008 exists to
/// prevent. See NOTES.md.
fn append_report_status(out: &mut Vec<u8>, updates: &[commands::RefUpdate], outcome: &Outcome) {
    out.extend_from_slice(&pktline::encode_data(b"unpack ok\n"));
    for u in updates {
        let line = match outcome {
            Outcome::Success => format!("ok {}\n", u.refname),
            Outcome::Rejected {
                primary_refname,
                primary_reason,
            } => {
                if &u.refname == primary_refname {
                    format!("ng {} {}\n", u.refname, primary_reason)
                } else {
                    format!(
                        "ng {} transaction rejected ({}: {})\n",
                        u.refname, primary_refname, primary_reason
                    )
                }
            }
        };
        out.extend_from_slice(&pktline::encode_data(line.as_bytes()));
    }
    out.extend_from_slice(&pktline::encode_flush());
}

/// `unpack-status` (the specific decode/scan error) PLUS a blanket
/// `ng <refname> unpacker error` command-status line for EVERY update
/// in the push - never `ok` (ADR-0008 / this milestone's brief: "no ok
/// lines" on an unpack failure). The per-ref reason is the fixed
/// literal string "unpacker error", not the specific decode message -
/// hand-verified against real `git receive-pack` fed the identical
/// broken multi-ref request (see `StageError::UnpackFailed`'s doc
/// comment and NOTES.md): real git uses that exact generic wording for
/// every ref regardless of which one, reserving the specific error text
/// for the `unpack` line alone.
///
/// CORRECTNESS NOTE: an earlier version of this function emitted only
/// the `unpack <msg>` line with no per-ref lines at all, which is a
/// real regression from real git's own report-status shape for this
/// exact case - a client pushing several refs against one broken pack
/// got zero per-ref feedback. Fixed here; see NOTES.md.
fn append_unpack_failure(out: &mut Vec<u8>, updates: &[commands::RefUpdate], msg: &str) {
    let line = format!("unpack {msg}\n");
    out.extend_from_slice(&pktline::encode_data(line.as_bytes()));
    for u in updates {
        let ng = format!("ng {} unpacker error\n", u.refname);
        out.extend_from_slice(&pktline::encode_data(ng.as_bytes()));
    }
    out.extend_from_slice(&pktline::encode_flush());
}

/// Reads the command-list section: PKT-LINE(command NUL capability-list)
/// *PKT-LINE(command) flush-pkt (gitprotocol-pack.adoc, "Reference
/// Update Request and Packfile Transfer" - quoted in full in
/// commands.rs's own doc comment). A lone flush-pkt (or clean EOF before
/// any bytes) is a legitimate empty request, same convention as G2's
/// server/session.rs::read_command_request.
fn read_command_list<R: Read>(
    input: &mut R,
) -> Result<(Vec<commands::RefUpdate>, String), ReceiveError> {
    let mut raw_lines: Vec<Vec<u8>> = Vec::new();
    let mut command_bytes = 0;
    loop {
        match pktline::read_pkt_line(input)? {
            None => break, // clean EOF before a flush - treat like an empty request
            Some(PktLine::Flush) => break,
            Some(PktLine::Data(bytes)) => {
                command_bytes += bytes.len();
                if raw_lines.len() == MAX_REF_COMMANDS || command_bytes > MAX_REF_COMMAND_BYTES {
                    return Err(malformed(
                        "command list",
                        "ref update batch exceeds receive limit",
                    ));
                }
                raw_lines.push(bytes);
            }
            Some(other) => {
                return Err(ReceiveError::Malformed {
                    what: "command list",
                    detail: format!("unexpected pkt-line: {other:?}"),
                })
            }
        }
    }
    commands::parse(&raw_lines)
}

// Preserve each byte on disk while the framing scan finds the end of the
// pack. SSH does not close stdin while waiting for report-status.
struct TeeReader<'a> {
    inner: &'a mut dyn Read,
    captured: &'a mut std::fs::File,
    len: usize,
}

impl Read for TeeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.len = self.len.saturating_add(n);
        if self.len > MAX_PACK_BYTES {
            return Err(std::io::Error::other(
                "incoming pack exceeds its byte limit",
            ));
        }
        self.captured.write_all(&buf[..n])?;
        Ok(n)
    }
}

/// Reads the raw packfile that follows the command list's flush-pkt with
/// NO framing of its own (gitprotocol-pack.adoc: `packfile = "PACK"
/// 28*(OCTET)`, sent as bare bytes, not pkt-line-wrapped) - and, unlike
/// G2's fetch response, there is nothing AFTER the pack before the
/// client falls silent waiting for report-status. That means this
/// cannot simply "read until EOF": over a live pipe (stdio/ext::/ssh)
/// the client keeps its write side open while it waits for our
/// response, so a read-to-EOF would hang forever. Instead this performs
/// its own lightweight structural walk of the pack (header -> N entries
/// -> 20-byte trailer, mirroring `ingest::decode_entry_header` /
/// `decode_ofs_delta_offset`'s bit layouts, cited there from
/// gitformat-pack.adoc) purely to find the boundary, stopping the moment
/// the declared entry count and trailer have been consumed - never
/// asking the input for a single byte more than the pack itself
/// contains. The real, error-checked decode still happens in the bounded decoder after this file is written.
///
/// PRIOR-KNOWLEDGE DISCLOSURE (per CLAUDE.md, at the maximum weight this
/// milestone calls for): using `flate2::bufread::ZlibDecoder<R: BufRead>`
/// specifically (not `flate2::read::ZlibDecoder<R: Read>`) is what makes
/// this safe - the `bufread` variant consumes only as many bytes as the
/// deflate stream actually needs from the `BufRead`'s own buffer (via
/// `fill_buf`/`consume`), leaving any look-ahead bytes in place for the
/// next entry's read instead of discarding them inside its own private
/// buffer the way the plain `read` variant would. This is ordinary
/// flate2-crate usage knowledge, not documented in gitformat-pack.adoc
/// (which describes the on-disk bytes, not how a streaming reader should
/// consume them from a live, non-seekable source) - not found under
/// Documentation/, logged in NOTES.md.
fn stage_pack(input: &mut dyn Read, captured: &mut std::fs::File) -> Result<(), ReceiveError> {
    let tee = TeeReader {
        inner: input,
        captured,
        len: 0,
    };
    let mut reader = BufReader::new(tee);

    let mut header = [0u8; 12];
    reader.read_exact(&mut header).map_err(|e| {
        malformed(
            "pack header",
            format!("truncated before the 12-byte header: {e}"),
        )
    })?;
    if &header[0..4] != b"PACK" {
        return Err(malformed("pack signature", "missing 'PACK' magic"));
    }
    let entry_count = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;

    if entry_count > MAX_PUSH_OBJECTS {
        return Err(malformed(
            "pack header",
            "object count exceeds receive limit",
        ));
    }
    let mut remaining = MAX_INFLATED_PUSH_BYTES;
    for _ in 0..entry_count {
        let entry_budget = remaining.min(ingest::MAX_DECOMPRESSED_SIZE);
        remaining -= skip_one_entry(&mut reader, entry_budget)?;
    }

    let mut trailer = [0u8; 20];
    reader.read_exact(&mut trailer).map_err(|e| {
        malformed(
            "pack trailer",
            format!("truncated before the 20-byte trailer: {e}"),
        )
    })?;

    Ok(())
}

fn malformed(what: &'static str, detail: impl Into<String>) -> ReceiveError {
    ReceiveError::Malformed {
        what,
        detail: detail.into(),
    }
}

/// Consumes exactly one pack entry (header, delta-base prefix if any,
/// zlib payload) from `reader` without needing to know its decompressed
/// content - only where it ends. Structural mirror of
/// `ingest::decode_entry_header` / `decode_ofs_delta_offset` (both
/// gitformat-pack.adoc-cited there), reading byte-at-a-time from a
/// stream instead of indexing a slice, since a live pipe has no
/// look-ahead length to index into.
fn skip_one_entry<R: BufRead>(reader: &mut R, entry_budget: usize) -> Result<usize, ReceiveError> {
    const OBJ_COMMIT: u8 = 1;
    const OBJ_TREE: u8 = 2;
    const OBJ_BLOB: u8 = 3;
    const OBJ_TAG: u8 = 4;
    const OBJ_OFS_DELTA: u8 = 6;
    const OBJ_REF_DELTA: u8 = 7;

    let mut first = [0u8; 1];
    reader
        .read_exact(&mut first)
        .map_err(|e| malformed("pack entry header", e.to_string()))?;
    let type_code = (first[0] >> 4) & 0x07;
    let mut more = first[0] & 0x80 != 0;
    while more {
        let mut b = [0u8; 1];
        reader
            .read_exact(&mut b)
            .map_err(|e| malformed("pack entry header", format!("truncated size varint: {e}")))?;
        more = b[0] & 0x80 != 0;
    }

    match type_code {
        OBJ_OFS_DELTA => {
            // gitformat-pack.adoc "offset encoding": n bytes, MSB set in
            // all but the last - only the byte COUNT matters here, not
            // the decoded value (this scan never needs the offset
            // itself, only where the varint ends).
            loop {
                let mut b = [0u8; 1];
                reader
                    .read_exact(&mut b)
                    .map_err(|e| malformed("ofs-delta offset", e.to_string()))?;
                if b[0] & 0x80 == 0 {
                    break;
                }
            }
        }
        OBJ_REF_DELTA => {
            let mut base_oid = [0u8; 20];
            reader
                .read_exact(&mut base_oid)
                .map_err(|e| malformed("ref-delta base", e.to_string()))?;
        }
        OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => {}
        other => {
            return Err(malformed(
                "pack entry type",
                format!("unknown or reserved object type {other}"),
            ))
        }
    }

    // Consume exactly the zlib stream's compressed bytes - see this
    // function's caller's doc comment for why `bufread::ZlibDecoder`
    // specifically is what makes this safe on a live, non-seekable
    // reader. Bounded by the same decompressed-size cap `ingest`
    // enforces (`ingest::MAX_DECOMPRESSED_SIZE`) - this scan discards
    // the decompressed bytes, but a decompression bomb would still burn
    // CPU/memory here, before `ingest::decode_pack`'s own bounded
    // inflate ever gets a chance to reject it, if left uncapped.
    let mut decoder = flate2::bufread::ZlibDecoder::new(reader);
    let mut discard = [0u8; 8192];
    let mut total: usize = 0;
    loop {
        let n = decoder
            .read(&mut discard)
            .map_err(|e| malformed("zlib stream", e.to_string()))?;
        if n == 0 {
            break;
        }
        total += n;
        if total > entry_budget {
            return Err(malformed(
                "decompressed size",
                format!(
                    "pack entry exceeds the remaining {entry_budget} byte cap while scanning for the pack boundary"
                ),
            ));
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_ref_op_maps_create_update_delete() {
        let zero = "0".repeat(40);
        let old = "a".repeat(40);
        let new = "b".repeat(40);

        let create = commands::RefUpdate {
            old: zero.clone(),
            new: new.clone(),
            refname: "refs/heads/x".to_string(),
        };
        assert!(matches!(to_ref_op(&create), RefOp::Create { .. }));

        let delete = commands::RefUpdate {
            old: old.clone(),
            new: zero.clone(),
            refname: "refs/heads/x".to_string(),
        };
        assert!(matches!(
            to_ref_op(&delete),
            RefOp::Delete { old: Some(_), .. }
        ));

        let update = commands::RefUpdate {
            old,
            new,
            refname: "refs/heads/x".to_string(),
        };
        assert!(matches!(
            to_ref_op(&update),
            RefOp::Update { old: Some(_), .. }
        ));
    }

    #[test]
    fn read_command_list_treats_a_lone_flush_as_empty() {
        let mut input: &[u8] = &pktline::encode_flush();
        let (updates, caps) = read_command_list(&mut input).unwrap();
        assert!(updates.is_empty());
        assert_eq!(caps, "");
    }

    #[test]
    fn read_command_list_treats_clean_eof_as_empty() {
        let mut input: &[u8] = &[];
        let (updates, _caps) = read_command_list(&mut input).unwrap();
        assert!(updates.is_empty());
    }

    #[test]
    fn advertisement_on_an_empty_repo_uses_the_zero_id_no_refs_form() {
        let git_dir = std::env::temp_dir().join(format!(
            "dengel-git-receive-session-test-empty-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&git_dir).unwrap();

        let out = advertisement(&git_dir).unwrap();
        let mut cursor = std::io::Cursor::new(out);
        let line = pktline::read_pkt_line(&mut cursor).unwrap().unwrap();
        match line {
            PktLine::Data(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                assert!(
                    text.starts_with(&format!("{ZERO_OID} capabilities^{{}}\0")),
                    "{text:?}"
                );
                assert!(text.contains("report-status"));
            }
            other => panic!("expected a data pkt-line, got {other:?}"),
        }
        assert_eq!(
            pktline::read_pkt_line(&mut cursor).unwrap(),
            Some(PktLine::Flush)
        );
    }
}
