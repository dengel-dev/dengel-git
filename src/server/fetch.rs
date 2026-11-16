//! `command=fetch` responder: wants/haves negotiation and the packfile
//! section, sideband-multiplexed.
//!
//! Format source: git-reference/Documentation/gitprotocol-v2.adoc,
//! "fetch" section - request arguments (want/have/done/thin-pack/
//! no-progress/include-tag/ofs-delta) and the response grammar:
//!
//!   output = acknowledgements flush-pkt |
//!            [acknowledgments delim-pkt] ... packfile flush-pkt
//!   acknowledgments = PKT-LINE("acknowledgments" LF) (nak | *ack) (ready)
//!   ready = PKT-LINE("ready" LF)
//!   nak = PKT-LINE("NAK" LF)
//!   ack = PKT-LINE("ACK" SP obj-id LF)
//!   packfile = PKT-LINE("packfile" LF) *PKT-LINE(%x01-03 *%x00-ff)
//!
//! and the acknowledgments-section bullets: "If the client... sending a
//! 'done' line... the acknowledgments sections MUST be omitted", "NAK"
//! if none of the haves were common, "ACK obj-id" for each common have,
//! "ready" when the server has "found an acceptable common base".
//! Sideband multiplexing (channel 1 = pack data) is gitprotocol-pack.adoc's
//! side-band-64k description, already reused by spike 02's client-side
//! `read_packfile_section` (rustgit::protocol::fetch) - the shape here is
//! its exact write-side counterpart.
//!
//! ACK/ready DECISION RULE (prior-knowledge disclosure, see NOTES.md):
//! gitprotocol-v2.adoc says a have is "common" if the server recognizes
//! it and says "ready" once it has "found an acceptable common base",
//! but does not spell out the recognition/cut-point algorithm itself.
//! This implementation treats a have as recognized iff it resolves in
//! our own odb at all (not "reachable from an advertised ref" or any
//! stronger notion), and sends "ready" iff at least one have was
//! recognized, or there were no haves at all (an initial/full-clone
//! request has nothing to negotiate against, so it is trivially
//! "ready" - per this milestone's superset-correctness philosophy,
//! never blocking on finding a minimal cut point). This is a design
//! choice informed by general familiarity with git's negotiation loop,
//! not a citation - flagged at spike 03's "maximum weight" per
//! CLAUDE.md's prior-knowledge rule, extended to this milestone.
//!
//! Superset rule (spike 02 P2 finding, inherited via server/mod.rs's own
//! doc comment): `walk::closure` already errs toward sending more, not
//! less - this module does not second-guess that.
//!
//! ## Shallow (SHALLOW clone/fetch only - not partial clone)
//!
//! `deepen <depth>` and `shallow <oid>` are the two shallow-specific
//! request arguments gitprotocol-v2.adoc's fetch section defines, and
//! the response's `shallow-info` section (`shallow`/`unshallow` lines,
//! placed after `acknowledgments` and before `packfile`, each section
//! its own PKT-LINE header followed by a delim-pkt per the "output ="
//! grammar quoted above) is this module's write-side counterpart. The
//! actual depth-bounded walk and the shallow-boundary computation itself
//! live in `walk::closure_with_depth` - see that function's doc comment
//! for exactly how the boundary is derived and why it cannot
//! under-report.
//!
//! Explicitly NOT implemented, and rejected as malformed by
//! `parse_args` rather than silently ignored (same "fail loud on
//! anything unrecognized" rule the base fetch arguments already use):
//! `deepen-since`, `deepen-not`, `deepen-relative`, `want-ref`
//! (ref-in-want), `sideband-all`, `packfile-uris`, `wait-for-done`.
//! `filter` is now implemented (see the "Partial clone" section right
//! below) but only its `blob:none`/`blob:limit=<n>` forms - every other
//! filter-spec form is rejected the same loud way. `advertise.rs`
//! advertises exactly `fetch=shallow filter` for exactly this reason -
//! see that module's doc comment.
//!
//! ## Partial clone (`filter=blob:none` / `filter=blob:limit=<n>`, not shallow)
//!
//! `filter <filter-spec>` (gitprotocol-v2.adoc's fetch section, gated
//! behind the `filter` feature - advertise.rs's job to only claim it
//! for what this module actually validates) is parsed here into
//! `walk::BlobFilter` and handed to `walk::closure_with_filter`, a
//! sibling of `closure`/`closure_with_depth` that omits a blob's own
//! bytes from the pack per rev-list-options.adoc's `--filter=blob:none`
//! / `--filter=blob:limit=<n>` semantics (that module's doc comment has
//! the exact boundary rule and the scope note on why only these two
//! forms are accepted). No new response section is required for
//! partial clone the way shallow needed `shallow-info`: the spec gives
//! the client no server-side acknowledgement grammar to render here -
//! "marking the remote a promisor" and "fetch omitted objects on
//! demand" are entirely client-side behavior triggered by having sent
//! `filter` in the first place, not something this server signals back
//! over the wire (checked: gitprotocol-v2.adoc's only other `filter`-
//! adjacent grammar is the unrelated `promisor-remote` capability,
//! which advertises OTHER remotes' filters and is not implemented or
//! needed here).
//!
//! `filter` and `deepen` together (a partial+shallow clone, e.g. what a
//! large-monorepo host might call `--depth=1 --filter=blob:none`) are
//! REJECTED rather than composed: `parse_args` below returns
//! `Malformed` the moment both are present on one request, before
//! either walk function is ever called. This is a deliberate scope cut,
//! not an oversight - `closure_with_depth`'s boundary derivation is
//! already the single most delicate piece of this module (see its own
//! doc comment's disclosure on why the algorithm is a design choice,
//! not a citation), and composing it with a per-blob omission decision
//! would multiply, not add to, the invariants that computation has to
//! keep proving. Rejecting loudly is strictly safer than silently
//! picking one feature over the other or attempting an unproven
//! composition; revisiting this is a follow-up, not something to build
//! ahead of unprompted (same discipline CLAUDE.md's scope-discipline
//! section already applies to this crate's other milestones).
//!
//! ## Promisor follow-up fetch (`want <oid>` naming a NON-ref-tip object)
//!
//! `blob:none`/`blob:limit=<n>` (above) only decide what the INITIAL
//! pack omits. A client that cloned with either marks this remote a
//! "promisor" remote and, later (typically at checkout, or on-demand
//! whenever a command needs an omitted blob's bytes), issues a fresh
//! `fetch` request whose `want` line names that blob's oid directly -
//! not a ref tip, not anything `ls-refs` ever advertised. This is what
//! makes a NON-bare `git clone --filter=blob:none` actually work (a
//! bare clone never checks anything out, so it never needs this).
//!
//! gitprotocol-v2.adoc's fetch section states this as base-command
//! behavior, not a gated feature: `want <oid>` is documented as "Wants
//! can be anything and are not limited to advertised objects" in the
//! same paragraph as `have`/`done`/`thin-pack` - contrast with
//! `shallow`/`filter`/`want-ref`/`sideband-all`/`packfile-uris`/
//! `wait-for-done` immediately below it, each explicitly gated behind
//! "If the 'X' feature is advertised". No capability name exists for
//! this in the spec text, and none is added to `advertise.rs`'s
//! `fetch=` value here - there is nothing new to advertise, since this
//! was never a feature in the first place.
//!
//! EMPIRICAL CHECK (not assumed from the spec text alone - logged in
//! NOTES.md): real git's config knobs that sound like they gate this
//! (`uploadpack.allowTipSHA1InWant`, `uploadpack.allowReachableSHA1InWant`,
//! `uploadpack.allowAnySHA1InWant` - config/uploadpack.adoc) turn out
//! NOT to restrict protocol v2's `fetch` command at all in the git
//! version this was checked against (2.50.1): a hand-built v2 `fetch`
//! request (`want <oid>` for an oid neither at nor reachable via any
//! ref, sent straight to `git upload-pack --stateless-rpc` with
//! default config, no `allowReachableSHA1InWant`/`allowAnySHA1InWant`
//! set) was served without complaint. `allowTipSHA1InWant`'s own doc
//! text is consistent with this once read closely: it says the
//! restriction applies "When uploadpack.hideRefs is in effect" - these
//! knobs gate a HIDDEN-ref bypass technique, not general non-tip wants,
//! and appear to be enforced (if at all) only on the legacy v0/v1 path
//! this server does not implement. This server therefore adds NO
//! reachability or "must match a config allowlist" check of its own for
//! `want <oid>` - doing so would be inventing a restriction real git's
//! own v2 server does not itself enforce, not matching an established
//! contract.
//!
//! **What this actually widens, and why it is flagged here rather than
//! silently accepted:** before this, a want had to be (or descend from,
//! via the closure walk starting at) an oid `ls-refs` would advertise -
//! effectively "whatever a normal clone/fetch could already reach".
//! After this, ANY oid this repository's object store happens to
//! contain - blob, tree, commit, or tag, walked or not, reachable from
//! a CURRENT ref or not - is fetchable by a client that knows (or is
//! simply handed, e.g. from a stale local clone made before an upstream
//! force-push) that oid. Two things make this narrower than it sounds:
//! oids are 160-bit content hashes, so blind guessing is infeasible,
//! and `walk::closure`'s `resolve_object` (this function's own
//! pre-check, see `respond` below) only ever returns what our own
//! store already has - nothing is fetched from anywhere else on a
//! client's say-so. But it is NOT narrowed to "reachable from a ref
//! `ls-refs` would advertise right now": `dengel-mirror` is fetch-only
//! (ADR-0001) and, as of this milestone, does not itself prune objects
//! that stop being reachable after an upstream force-push (that is
//! repack/gc's job, tracked separately, still in progress in a sibling
//! worktree as this is written) - so a client that retained an oid from
//! before such a force-push could still retrieve that content here,
//! even though the current `ls-refs` advertisement no longer points at
//! it anywhere. Whether that gap needs closing (e.g. restricting `want`
//! to the reachable-from-currently-advertised-refs set, at the cost of
//! diverging from real git's own more permissive v2 behavior, and at
//! the cost of the "computationally expensive" reachability check
//! `allowReachableSHA1InWant`'s own doc text warns about) is a decision
//! for a human, not invented here - reported instead of silently
//! assumed either way, per this task's own instruction.
//!
//! **Failure mode for a want naming an oid we do NOT have** (property 2
//! of the task that added this section): checked by `respond` below,
//! up front, before any acknowledgments/packfile bytes are written -
//! see `ServeError::UnknownWant`'s own doc comment for why this is a
//! distinct error from `Repo` (this is a legitimate, well-formed
//! request that this repository simply cannot satisfy, not a sign our
//! own store is broken), and why checking it before any other response
//! bytes exist rules out ever answering with a technically-well-formed
//! but empty/truncated pack that a client's `index-pack` would treat as
//! "the promisor remote had nothing to give me" rather than a clear
//! failure.

use super::{walk, ServeError};
use crate::objectstore::ObjectStore;
use rustgit::pack::writer;
use rustgit::protocol::pktline;
use std::path::Path;

/// Max raw pack bytes per sideband data pkt-line: pktline's own payload
/// cap (pktline::MAX_PAYLOAD_LEN = 65516, gitprotocol-common.adoc) minus
/// the 1-byte sideband channel prefix (gitprotocol-pack.adoc's side-band
/// description).
const SIDEBAND_CHUNK: usize = pktline::MAX_PAYLOAD_LEN - 1;

#[derive(Debug, Default)]
struct FetchArgs {
    wants: Vec<String>,
    haves: Vec<String>,
    done: bool,
    ofs_delta: bool,
    /// `shallow <oid>` lines: commits the CLIENT already considers a
    /// boundary (it has no parents for them locally). Only meaningful
    /// together with `deepen` - see walk::closure_with_depth's scope
    /// note - but parsed unconditionally since a conforming client may
    /// send them on any shallow-repo fetch.
    shallow: Vec<String>,
    /// `deepen <depth>`, parsed as the plain (non-relative) depth
    /// gitprotocol-v2.adoc's fetch section describes. `None` means no
    /// `deepen` line was sent - an ordinary, non-shallow fetch, and the
    /// existing (pre-shallow) code path below is taken unchanged.
    deepen: Option<u32>,
    /// `filter <filter-spec>`, validated down to the two IN-scope forms
    /// (see this module's "Partial clone" doc comment section) as
    /// `walk::BlobFilter`. `None` means no `filter` line was sent - an
    /// ordinary, unfiltered fetch.
    filter: Option<walk::BlobFilter>,
}

fn parse_args(args: &[String]) -> Result<FetchArgs, ServeError> {
    let mut parsed = FetchArgs::default();

    for arg in args {
        if let Some(oid) = arg.strip_prefix("want ") {
            parsed.wants.push(oid.to_string());
        } else if let Some(oid) = arg.strip_prefix("have ") {
            parsed.haves.push(oid.to_string());
        } else if arg == "done" {
            parsed.done = true;
        } else if arg == "ofs-delta" {
            parsed.ofs_delta = true;
        } else if arg == "thin-pack" || arg == "no-progress" || arg == "include-tag" {
            // Base fetch arguments per gitprotocol-v2.adoc, recognized so
            // a conforming client's request is never rejected as
            // malformed, but this milestone does not implement thin-pack
            // production, progress suppression, or include-tag's "also
            // send the tag object" behavior (see the module doc comment)
            // - accepted and otherwise a no-op.
        } else if let Some(oid) = arg.strip_prefix("shallow ") {
            parsed.shallow.push(oid.to_string());
        } else if let Some(n) = arg.strip_prefix("deepen ") {
            let n: u32 = n.trim().parse().map_err(|_| ServeError::Malformed {
                what: "fetch argument",
                detail: format!("deepen value not a valid non-negative integer: {:?}", n),
            })?;
            parsed.deepen = Some(n);
        } else if let Some(spec) = arg.strip_prefix("filter ") {
            parsed.filter = Some(parse_filter_spec(spec)?);
        } else {
            return Err(ServeError::Malformed {
                what: "fetch argument",
                detail: format!("unrecognized or unimplemented: {:?}", arg),
            });
        }
    }

    if parsed.wants.is_empty() {
        return Err(ServeError::Malformed {
            what: "fetch request",
            detail: "no want lines".to_string(),
        });
    }

    if parsed.filter.is_some() && parsed.deepen.is_some() {
        // See the module doc comment's "Partial clone" section for why
        // this is a deliberate scope cut (composing closure_with_filter
        // with closure_with_depth's already-delicate boundary derivation
        // is not attempted here), not an oversight.
        return Err(ServeError::Malformed {
            what: "fetch request",
            detail: "filter combined with deepen is not supported".to_string(),
        });
    }

    Ok(parsed)
}

/// Validates a `filter <filter-spec>` value down to the two IN-scope
/// forms (see the module doc comment's "Partial clone" section):
/// `blob:none` and `blob:limit=<n>[kmg]`. Any other filter-spec form
/// (`tree:<depth>`, `sparse:oid=...`, `object:type=...`, `combine:...`,
/// or anything unrecognized) is rejected as `Malformed` rather than
/// silently ignored - see this module's doc comment on why an ignored
/// filter is a silent contract violation, not a harmless superset.
fn parse_filter_spec(spec: &str) -> Result<walk::BlobFilter, ServeError> {
    if spec == "blob:none" {
        return Ok(walk::BlobFilter::None);
    }
    if let Some(n) = spec.strip_prefix("blob:limit=") {
        let bytes = parse_scaled_size(n).ok_or_else(|| ServeError::Malformed {
            what: "filter argument",
            detail: format!("blob:limit value not a valid size (expected an integer, optionally suffixed k/m/g): {:?}", n),
        })?;
        return Ok(walk::BlobFilter::Limit(bytes));
    }
    Err(ServeError::Malformed {
        what: "filter argument",
        detail: format!(
            "unsupported or unimplemented filter-spec (only blob:none and blob:limit=<n> are implemented): {:?}",
            spec
        ),
    })
}

/// Parses a `blob:limit=<n>[kmg]` value's numeric part. rev-list-
/// options.adoc: "senders SHOULD translate scaled integers... into a
/// fully-expanded form... However, receivers SHOULD accept the
/// following suffixes: 'k', 'm', and 'g' for 1024, 1048576, and
/// 1073741824, respectively." A conforming client (this crate's own
/// test oracle, real git, included) already sends the expanded form per
/// the SHOULD-translate half of that sentence, but this function still
/// implements the receiver's SHOULD-accept half rather than assuming
/// every sender does - accepting a form we may never actually be sent
/// costs one small function, whereas silently mis-parsing (or rejecting)
/// a conforming-but-unexpanded request would not.
fn parse_scaled_size(s: &str) -> Option<u64> {
    let (digits, multiplier) = match s.strip_suffix('k') {
        Some(d) => (d, 1024u64),
        None => match s.strip_suffix('m') {
            Some(d) => (d, 1024 * 1024),
            None => match s.strip_suffix('g') {
                Some(d) => (d, 1024 * 1024 * 1024),
                None => (s, 1),
            },
        },
    };
    digits.parse::<u64>().ok()?.checked_mul(multiplier)
}

/// Handles one fetch request (stateless: everything the client said is in
/// `args`), returning the complete pkt-line encoded response body.
pub fn respond(git_dir: &Path, args: &[String]) -> Result<Vec<u8>, ServeError> {
    let req = parse_args(args)?;
    let mut out = Vec::new();

    // Every `want` must resolve in our own store BEFORE any response
    // bytes are produced (not even the acknowledgments section) - see
    // `ServeError::UnknownWant`'s doc comment. This is the property a
    // promisor client's follow-up fetch (asking for one specific,
    // possibly wrong or long-gone, oid) most needs: a clean top-level
    // ERR, never a truncated ack section or a technically-well-formed
    // but empty packfile the client would read as "your want was
    // satisfied by nothing" instead of "we don't have it". Before this
    // check existed, a want naming an oid our store did not contain hit
    // `walk::resolve_object` mid-walk and came back as `ServeError::Repo`
    // - which is loud (fine, an ERR pkt still went out - see session.rs/
    // http.rs's error handling) but mislabels a legitimate "the client
    // asked for something we don't have" outcome as "our own store is
    // broken", which `Repo`'s own doc comment reserves for a different
    // failure mode. Checking here also means the failure is reported
    // before the have-side acknowledgments work below runs at all, not
    // interleaved with it.
    let store = ObjectStore::open(git_dir)?;
    for oid in &req.wants {
        if !matches!(store.resolve(oid), Ok(Some(_))) {
            return Err(ServeError::UnknownWant { oid: oid.clone() });
        }
    }

    if !req.done {
        // Reuses the `store` opened above for the want-validation check -
        // one resolve session for the whole request (not one .idx parse
        // per have oid - see objectstore.rs's doc comment). Was
        // rustgit::pack::odb::resolve_oid_in_git_dir directly, which
        // panics on a repo with 2+ packs whose ref-deltas cross pack
        // boundaries (NMA-1452) - see walk.rs's resolve_object, this
        // module's counterpart for the same underlying store.
        let recognized: Vec<&String> = req
            .haves
            .iter()
            .filter(|h| matches!(store.resolve(h), Ok(Some(_))))
            .collect();
        // See the module doc comment's "ACK/ready decision rule" for why
        // this is the rule, and that it is a design choice, not spec text.
        let ready = req.haves.is_empty() || !recognized.is_empty();

        out.extend_from_slice(&pktline::encode_data(b"acknowledgments\n"));
        if !req.haves.is_empty() {
            if recognized.is_empty() {
                out.extend_from_slice(&pktline::encode_data(b"NAK\n"));
            } else {
                for oid in &recognized {
                    out.extend_from_slice(&pktline::encode_data(format!("ACK {oid}\n").as_bytes()));
                }
            }
        }
        // Empty haves + not ready-yet is unreachable (ready is defined as
        // true whenever haves is empty), so no separate empty-haves-no-ack
        // branch is needed here.

        if !ready {
            out.extend_from_slice(&pktline::encode_flush());
            return Ok(out);
        }

        out.extend_from_slice(&pktline::encode_data(b"ready\n"));
        out.extend_from_slice(&pktline::encode_delim());
    }
    // Reaching here means either the client sent `done` (acknowledgments
    // MUST be omitted, per spec) or we just sent `ready` above - both
    // mean "produce and send the pack now".

    // Shallow only when the client actually sent `deepen`: no `deepen`
    // line means an ordinary fetch, and must produce byte-for-byte the
    // same output as before this feature existed (see the module doc
    // comment's advertise.rs cross-reference and this file's own
    // regression test for that).
    let objects = if let Some(depth) = req.deepen {
        let shallow_result =
            walk::closure_with_depth(git_dir, &req.wants, &req.haves, depth, &req.shallow)?;
        if !shallow_result.shallow.is_empty() || !shallow_result.unshallow.is_empty() {
            // Per gitprotocol-v2.adoc's shallow-info section: "included
            // if ... the server needs to inform the client of any
            // shallow boundaries or adjustments" - omitted entirely
            // (not sent as an empty section) when there is nothing to
            // report, which is exactly what "depth deeper than the
            // repository's own history" produces (every reachable
            // commit's real parents are all included, so nothing is
            // shallow - see closure_with_depth's boundary derivation).
            out.extend_from_slice(&pktline::encode_data(
                b"shallow-info
",
            ));
            for oid in &shallow_result.shallow {
                out.extend_from_slice(&pktline::encode_data(
                    format!(
                        "shallow {oid}
"
                    )
                    .as_bytes(),
                ));
            }
            for oid in &shallow_result.unshallow {
                out.extend_from_slice(&pktline::encode_data(
                    format!(
                        "unshallow {oid}
"
                    )
                    .as_bytes(),
                ));
            }
            out.extend_from_slice(&pktline::encode_delim());
        }
        shallow_result.objects
    } else if let Some(filter) = req.filter {
        // No response-section counterpart to shallow-info here - see the
        // module doc comment's "Partial clone" section for why partial
        // clone has nothing to write back beyond a smaller packfile.
        walk::closure_with_filter(git_dir, &req.wants, &req.haves, filter)?
    } else {
        walk::closure(git_dir, &req.wants, &req.haves)?
    };
    let write_objects: Vec<writer::WriteObject> = objects
        .into_iter()
        .map(|(kind, content)| writer::WriteObject { kind, content })
        .collect();

    // ofs-delta output is only ever sent if the client said it can read
    // OBJ_OFS_DELTA (gitprotocol-v2.adoc's "ofs-delta" argument) - our
    // pack writer's delta path always emits ofs-deltas, so a client that
    // did not advertise support gets the delta-free writer instead.
    // The delta search scales with the total uncompressed data. Large
    // requests prefer a bigger pack to a response that times out.
    const MAX_DELTA_SEARCH_BYTES: usize = 64 * 1024 * 1024;
    let try_deltas = req.ofs_delta
        && write_objects
            .iter()
            .map(|object| object.content.len())
            .sum::<usize>()
            <= MAX_DELTA_SEARCH_BYTES;
    let written = if try_deltas {
        writer::write_pack_with_deltas(&write_objects)
    } else {
        writer::write_pack(&write_objects)
    };

    out.extend_from_slice(&pktline::encode_data(b"packfile\n"));
    for chunk in written.pack_bytes.chunks(SIDEBAND_CHUNK) {
        let mut payload = Vec::with_capacity(chunk.len() + 1);
        payload.push(1u8); // sideband channel 1: pack data
        payload.extend_from_slice(chunk);
        out.extend_from_slice(&pktline::encode_data(&payload));
    }
    out.extend_from_slice(&pktline::encode_flush());

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{loose, tree, Kind};
    use rustgit::protocol::pktline::PktLine;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-fetch-test-{}-{}-{}",
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

    fn write_commit_fixture(name: &str) -> (PathBuf, String) {
        let git_dir = scratch_dir(name);
        let blob = loose::write(&git_dir, Kind::Blob, b"hello\n").unwrap();
        let tree_content = tree::serialize(&[tree::TreeEntry {
            mode: b"100644".to_vec(),
            name: b"a.txt".to_vec(),
            oid: blob,
        }]);
        let tree_oid = loose::write(&git_dir, Kind::Tree, &tree_content).unwrap();
        let commit_content =
            format!("tree {tree_oid}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n");
        let commit_oid = loose::write(&git_dir, Kind::Commit, commit_content.as_bytes()).unwrap();
        (git_dir, commit_oid)
    }

    /// Two commits, `parent` -> `child` (in that ancestry direction),
    /// sharing the same tree. Returns (git_dir, parent_oid, child_oid).
    fn write_two_commit_chain(name: &str) -> (PathBuf, String, String) {
        let git_dir = scratch_dir(name);
        let blob = loose::write(&git_dir, Kind::Blob, b"hello\n").unwrap();
        let tree_content = tree::serialize(&[tree::TreeEntry {
            mode: b"100644".to_vec(),
            name: b"a.txt".to_vec(),
            oid: blob,
        }]);
        let tree_oid = loose::write(&git_dir, Kind::Tree, &tree_content).unwrap();
        let parent_content = format!(
            "tree {tree_oid}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nparent msg\n"
        );
        let parent_oid = loose::write(&git_dir, Kind::Commit, parent_content.as_bytes()).unwrap();
        let child_content =
            format!("tree {tree_oid}\nparent {parent_oid}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nchild msg\n");
        let child_oid = loose::write(&git_dir, Kind::Commit, child_content.as_bytes()).unwrap();
        (git_dir, parent_oid, child_oid)
    }

    fn sections(bytes: &[u8]) -> Vec<PktLine> {
        let mut cursor = Cursor::new(bytes);
        let mut out = Vec::new();
        loop {
            match pktline::read_pkt_line(&mut cursor).unwrap() {
                None => break,
                Some(line) => {
                    let is_flush = matches!(line, PktLine::Flush);
                    out.push(line);
                    if is_flush {
                        break;
                    }
                }
            }
        }
        out
    }

    #[test]
    fn no_want_lines_is_malformed() {
        let git_dir = scratch_dir("no_wants");
        let result = respond(&git_dir, &["done".to_string()]);
        assert!(matches!(result, Err(ServeError::Malformed { .. })));
    }

    #[test]
    fn done_with_no_haves_skips_straight_to_packfile() {
        let (git_dir, commit_oid) = write_commit_fixture("done_no_haves");
        let out = respond(
            &git_dir,
            &[format!("want {commit_oid}"), "done".to_string()],
        )
        .unwrap();
        let lines = sections(&out);
        let PktLine::Data(header) = &lines[0] else {
            panic!("expected a data pkt-line")
        };
        assert_eq!(header, b"packfile\n");
        assert_eq!(lines.last(), Some(&PktLine::Flush));

        // Sideband channel 1 bytes, concatenated, must start with the
        // pack magic.
        let mut pack_bytes = Vec::new();
        for line in &lines[1..lines.len() - 1] {
            if let PktLine::Data(bytes) = line {
                assert_eq!(bytes[0], 1, "expected sideband channel 1 (pack data)");
                pack_bytes.extend_from_slice(&bytes[1..]);
            }
        }
        assert_eq!(&pack_bytes[0..4], b"PACK");
    }

    #[test]
    fn no_haves_and_not_done_sends_ready_and_packfile() {
        let (git_dir, commit_oid) = write_commit_fixture("ready_no_haves");
        let out = respond(&git_dir, &[format!("want {commit_oid}")]).unwrap();
        let lines = sections(&out);
        let texts: Vec<String> = lines
            .iter()
            .filter_map(|l| match l {
                PktLine::Data(bytes) => Some(
                    String::from_utf8_lossy(bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                _ => None,
            })
            .collect();
        assert_eq!(texts[0], "acknowledgments");
        assert_eq!(texts[1], "ready");
        assert_eq!(texts[2], "packfile");
        assert!(lines.contains(&PktLine::Delim));
    }

    #[test]
    fn unrecognized_have_gets_a_nak_and_no_packfile_this_round() {
        let (git_dir, commit_oid) = write_commit_fixture("nak");
        let bogus_have = "0000000000000000000000000000000000000000".to_string();
        let out = respond(
            &git_dir,
            &[format!("want {commit_oid}"), format!("have {bogus_have}")],
        )
        .unwrap();
        let lines = sections(&out);
        let texts: Vec<String> = lines
            .iter()
            .filter_map(|l| match l {
                PktLine::Data(bytes) => Some(
                    String::from_utf8_lossy(bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                _ => None,
            })
            .collect();
        assert_eq!(
            texts,
            vec!["acknowledgments".to_string(), "NAK".to_string()]
        );
        assert_eq!(lines.last(), Some(&PktLine::Flush));
        assert!(
            !texts.iter().any(|t| t == "packfile"),
            "must not send a packfile without done or ready"
        );
    }

    #[test]
    fn recognized_have_gets_acked_and_is_ready() {
        let (git_dir, commit_oid) = write_commit_fixture("ack");
        let out = respond(
            &git_dir,
            &[format!("want {commit_oid}"), format!("have {commit_oid}")],
        )
        .unwrap();
        let lines = sections(&out);
        let texts: Vec<String> = lines
            .iter()
            .filter_map(|l| match l {
                PktLine::Data(bytes) => Some(
                    String::from_utf8_lossy(bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                _ => None,
            })
            .collect();
        assert_eq!(texts[0], "acknowledgments");
        assert_eq!(texts[1], format!("ACK {commit_oid}"));
        assert_eq!(texts[2], "ready");
        assert_eq!(texts[3], "packfile");
    }

    #[test]
    fn unrecognized_fetch_argument_is_malformed() {
        // "shallow <oid>" used to be this test's example of an
        // unimplemented argument - it no longer is (see this module's
        // "Shallow" doc comment section), so asserting Malformed for it
        // would now be testing the WRONG intended behavior. `deepen-since`
        // is still genuinely out of scope (deepen-since/deepen-not/
        // deepen-relative/filter/ref-in-want/sideband-all/packfile-uris/
        // wait-for-done all are) and must still be rejected rather than
        // silently ignored.
        let git_dir = scratch_dir("bad_arg");
        let result = respond(
            &git_dir,
            &["deepen-since 12345".to_string(), "done".to_string()],
        );
        assert!(matches!(result, Err(ServeError::Malformed { .. })));
    }

    // --- shallow wiring: wire-format placement, not the boundary
    // algorithm itself (that is walk.rs's own unit tests - these only
    // check that `respond` puts the shallow-info section in the right
    // place with the right content when walk::closure_with_depth says
    // there is something to report, and omits it entirely when not). ---

    #[test]
    fn deepen_one_puts_a_shallow_info_section_before_packfile() {
        let (git_dir, _parent_oid, child_oid) = write_two_commit_chain("deepen_one");
        let out = respond(
            &git_dir,
            &[
                format!("want {child_oid}"),
                "deepen 1".to_string(),
                "done".to_string(),
            ],
        )
        .unwrap();
        let lines = sections(&out);
        let texts: Vec<String> = lines
            .iter()
            .filter_map(|l| match l {
                PktLine::Data(bytes) => Some(
                    String::from_utf8_lossy(bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                _ => None,
            })
            .collect();
        // done => acknowledgments MUST be omitted; shallow-info comes
        // first, then packfile.
        assert_eq!(texts[0], "shallow-info");
        assert_eq!(texts[1], format!("shallow {child_oid}"));
        assert_eq!(texts[2], "packfile");
        // A delim-pkt must separate shallow-info from packfile (the
        // "output = ... [shallow-info delim-pkt] ... packfile" grammar
        // quoted in the module doc comment).
        let shallow_info_idx = lines
            .iter()
            .position(|l| {
                l == &PktLine::Data(
                    b"shallow-info
"
                    .to_vec(),
                )
            })
            .unwrap();
        assert_eq!(
            lines[shallow_info_idx + 2],
            PktLine::Delim,
            "expected a delim-pkt right after the shallow line, before packfile"
        );
    }

    #[test]
    fn deepen_deeper_than_history_sends_no_shallow_info_section_at_all() {
        let (git_dir, commit_oid) = write_commit_fixture("deepen_deep");
        let out = respond(
            &git_dir,
            &[
                format!("want {commit_oid}"),
                "deepen 1000".to_string(),
                "done".to_string(),
            ],
        )
        .unwrap();
        let lines = sections(&out);
        let PktLine::Data(header) = &lines[0] else {
            panic!("expected a data pkt-line")
        };
        assert_eq!(
            header,
            b"packfile
",
            "no shallow-info section should be sent when there is nothing to report"
        );
        assert!(
            !lines.contains(&PktLine::Delim),
            "no delim-pkt expected either, with acknowledgments and shallow-info both omitted"
        );
    }

    // --- partial clone (`filter`) wiring: parsing + end-to-end pack
    // content through `respond`. The exact blob:limit boundary rule
    // itself is walk.rs's own unit coverage (closure_with_filter) -
    // these check argument parsing, the deepen+filter rejection, and
    // that `respond`'s actual packfile bytes (decoded the same way
    // ingest decodes an incoming pack, not re-derived here) reflect
    // what the filter said to omit. ---

    /// Decodes the pack bytes out of a `respond` response (concatenated
    /// sideband channel-1 payloads following the "packfile" section
    /// header) via `ingest::decode_pack` - reusing the crate's own pack
    /// reader as the assertion oracle rather than parsing pack bytes a
    /// second, independent way in a test helper.
    fn decoded_pack_objects(out: &[u8]) -> Vec<crate::ingest::DecodedObject> {
        let lines = sections(out);
        let mut pack_bytes = Vec::new();
        let mut in_pack = false;
        for line in &lines {
            if let PktLine::Data(bytes) = line {
                if bytes.as_slice() == b"packfile\n" {
                    in_pack = true;
                    continue;
                }
                if in_pack && !bytes.is_empty() && bytes[0] == 1 {
                    pack_bytes.extend_from_slice(&bytes[1..]);
                }
            }
        }
        crate::ingest::decode_pack(&pack_bytes, &|_| None)
            .expect("respond's own pack must decode cleanly")
    }

    #[test]
    fn parse_scaled_size_expands_k_m_g_suffixes() {
        assert_eq!(parse_scaled_size("1024"), Some(1024));
        assert_eq!(parse_scaled_size("1k"), Some(1024));
        assert_eq!(parse_scaled_size("1m"), Some(1024 * 1024));
        assert_eq!(parse_scaled_size("1g"), Some(1024 * 1024 * 1024));
        assert_eq!(
            parse_scaled_size("0"),
            Some(0),
            "blob:limit=0 must be a valid size, per rev-list-options.adoc's \"n may be zero\""
        );
        assert_eq!(parse_scaled_size("bogus"), None);
        assert_eq!(parse_scaled_size(""), None);
    }

    #[test]
    fn filter_blob_none_omits_the_blob_from_the_actual_pack_bytes() {
        let (git_dir, commit_oid) = write_commit_fixture("filter_blob_none");
        let out = respond(
            &git_dir,
            &[
                format!("want {commit_oid}"),
                "filter blob:none".to_string(),
                "done".to_string(),
            ],
        )
        .unwrap();
        let objects = decoded_pack_objects(&out);
        assert!(
            objects.iter().any(|o| o.kind == Kind::Commit),
            "commit must still be sent"
        );
        assert!(
            objects.iter().any(|o| o.kind == Kind::Tree),
            "tree must still be sent"
        );
        assert!(
            !objects.iter().any(|o| o.kind == Kind::Blob),
            "blob:none must omit every blob: {objects:?}"
        );
    }

    #[test]
    fn filter_blob_limit_omits_only_blobs_at_or_over_the_threshold() {
        let git_dir = scratch_dir("filter_blob_limit");
        let n = 10usize;
        let at_limit = loose::write(&git_dir, Kind::Blob, &vec![b'a'; n]).unwrap();
        let under_limit = loose::write(&git_dir, Kind::Blob, &vec![b'b'; n - 1]).unwrap();
        let tree_content = tree::serialize(&[
            tree::TreeEntry {
                mode: b"100644".to_vec(),
                name: b"at.txt".to_vec(),
                oid: at_limit.clone(),
            },
            tree::TreeEntry {
                mode: b"100644".to_vec(),
                name: b"under.txt".to_vec(),
                oid: under_limit.clone(),
            },
        ]);
        let tree_oid = loose::write(&git_dir, Kind::Tree, &tree_content).unwrap();
        let commit_content =
            format!("tree {tree_oid}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n");
        let commit_oid = loose::write(&git_dir, Kind::Commit, commit_content.as_bytes()).unwrap();

        let out = respond(
            &git_dir,
            &[
                format!("want {commit_oid}"),
                format!("filter blob:limit={n}"),
                "done".to_string(),
            ],
        )
        .unwrap();
        let objects = decoded_pack_objects(&out);
        let sent_oids: std::collections::HashSet<&str> =
            objects.iter().map(|o| o.oid.as_str()).collect();
        assert!(
            !sent_oids.contains(at_limit.as_str()),
            "a blob of exactly the limit must be omitted: {sent_oids:?}"
        );
        assert!(
            sent_oids.contains(under_limit.as_str()),
            "a blob one byte under the limit must be sent: {sent_oids:?}"
        );
        assert!(
            sent_oids.contains(tree_oid.as_str()),
            "the tree naming both blobs must always be sent"
        );
    }

    #[test]
    fn filter_combined_with_deepen_is_malformed_not_silently_composed() {
        let (git_dir, commit_oid) = write_commit_fixture("filter_plus_deepen");
        let result = respond(
            &git_dir,
            &[
                format!("want {commit_oid}"),
                "filter blob:none".to_string(),
                "deepen 1".to_string(),
                "done".to_string(),
            ],
        );
        assert!(
            matches!(result, Err(ServeError::Malformed { .. })),
            "filter+deepen must be rejected, not composed: {result:?}"
        );
    }

    #[test]
    fn unsupported_filter_spec_forms_are_rejected_not_silently_ignored() {
        let (git_dir, commit_oid) = write_commit_fixture("filter_unsupported");
        for spec in [
            "tree:0",
            "sparse:oid=deadbeef",
            "object:type=blob",
            "combine:tree:3+blob:none",
            "bogus",
        ] {
            let result = respond(
                &git_dir,
                &[
                    format!("want {commit_oid}"),
                    format!("filter {spec}"),
                    "done".to_string(),
                ],
            );
            assert!(
                matches!(result, Err(ServeError::Malformed { .. })),
                "filter-spec {spec:?} must be rejected, not ignored (an ignored filter silently sends MORE than the client asked for): {result:?}"
            );
        }
    }

    #[test]
    fn filter_blob_none_is_a_no_op_regression_for_haves_negotiation() {
        // The filter parsing/dispatch must not disturb the ordinary
        // haves negotiation path when there ARE haves - same shape as
        // the pre-existing recognized_have_gets_acked_and_is_ready test,
        // just with a filter also present.
        let (git_dir, commit_oid) = write_commit_fixture("filter_with_haves");
        let out = respond(
            &git_dir,
            &[
                format!("want {commit_oid}"),
                format!("have {commit_oid}"),
                "filter blob:none".to_string(),
            ],
        )
        .unwrap();
        let lines = sections(&out);
        let texts: Vec<String> = lines
            .iter()
            .filter_map(|l| match l {
                PktLine::Data(bytes) => Some(
                    String::from_utf8_lossy(bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                _ => None,
            })
            .collect();
        assert_eq!(texts[0], "acknowledgments");
        assert_eq!(texts[1], format!("ACK {commit_oid}"));
        assert_eq!(texts[2], "ready");
        assert_eq!(texts[3], "packfile");
    }
}
