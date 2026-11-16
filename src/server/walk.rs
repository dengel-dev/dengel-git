//! Reachability closure for pack assembly: commits walked via
//! object::commit::refs, trees via object::tree::entries, tags peeled via
//! object::tag::refs. Objects resolve through `objectstore::ObjectStore`
//! (loose + every pack, cross-pack ref-deltas included - see that
//! module's doc comment for why `rustgit::pack::odb` itself is no longer
//! used here: NMA-1452, it panics on a ref-delta whose base sits outside
//! its own pack, which any repo that has received a push commonly has).
//! Gitlink entries (mode 160000) reference commits in OTHER repositories
//! and are never expected to resolve here.
//!
//! Format source for the graph edges themselves: git-reference/
//! Documentation/gitdatamodel.adoc (commit -> tree/parents, tree entries,
//! tag -> object) - already cited in object/commit.rs, object/tree.rs,
//! object/tag.rs, which this module only calls into. Mode 160000
//! (gitlink) semantics: git-reference/Documentation/gitsubmodules.adoc
//! and gitattributes' tree-entry mode table describe a gitlink as
//! recording a commit oid in a separate repository, never an object this
//! repository's own store contains.
//!
//! `closure_with_depth` below adds a depth-bounded variant of `closure`
//! for `deepen <depth>` (SHALLOW clone/fetch only - see its own doc
//! comment for the exact scope and for the design note on where its
//! algorithm is this module's own choice rather than a citation).
//!
//! `closure_with_filter` below adds a blob-omitting variant of `closure`
//! for `filter <filter-spec>` (PARTIAL clone - a separate capability
//! from shallow, and not combined with it: see fetch.rs's arg parser,
//! which rejects `filter` and `deepen` together rather than attempting
//! to compose the two boundary computations). Scope is exactly
//! `blob:none` and `blob:limit=<n>` (they are one mechanism - a
//! per-blob size threshold, with `blob:none` being `limit=0`'s "omit
//! unconditionally" special case stated as its own spec form) -
//! `tree:<depth>`, `sparse:oid=`, `object:type=`, and `combine:` are
//! all rejected as malformed by fetch.rs's parser, never silently
//! ignored (an ignored filter means MORE is sent than the client asked
//! for, which is not incorrect per this crate's superset rule, but IS a
//! silent contract violation the client has no way to detect - the
//! client would believe its promisor remote is honoring a filter it
//! is not).

use super::ServeError;
use crate::object::{self, commit, tag, tree, Kind};
use crate::objectstore::ObjectStore;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

/// Resolve `oid` to (kind, content) via the object store (loose + every
/// pack, cross-pack deltas resolved - see the module doc comment). A
/// miss or a store error is `ServeError::Repo`: nothing that calls this
/// should ever be handed an oid our own store doesn't actually contain,
/// so either case means the store itself is broken, not a bad client
/// request - loud by design (see `ServeError::Repo`'s own doc comment).
pub fn resolve_object(store: &ObjectStore, oid: &str) -> Result<(Kind, Vec<u8>), ServeError> {
    match store.resolve(oid) {
        Ok(Some((kind, content))) => Ok((kind, content)),
        Ok(None) => Err(ServeError::Repo {
            detail: format!("object {oid} not found in the object database"),
        }),
        Err(e) => Err(ServeError::Repo {
            detail: format!("object {oid} failed to resolve: {e}"),
        }),
    }
}

/// Everything reachable from `wants` minus everything reachable from
/// `haves` (haves that do not resolve are ignored - the client may know
/// objects we do not). Returned as (kind_code, content) pairs ready for
/// rustgit's pack writer, in an order where deltas can find their bases.
pub fn closure(
    git_dir: &Path,
    wants: &[String],
    haves: &[String],
) -> Result<Vec<(u8, Vec<u8>)>, ServeError> {
    // One resolve session for the whole closure computation (have-side
    // walk plus want-side walk): the store's per-pack .idx parse happens
    // once here, not once per oid - see objectstore.rs's doc comment.
    let store = ObjectStore::open(git_dir)?;

    let have_set = reachable_closure(&store, haves, true)?;

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = wants.iter().cloned().collect();
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();

    while let Some(oid) = queue.pop_front() {
        if !visited.insert(oid.clone()) {
            continue;
        }
        if have_set.contains(&oid) {
            // The client's have-closure already covers this whole
            // subgraph (have_set is itself a full reachability closure,
            // not just the have oids themselves), so there is nothing
            // further to walk or send from here.
            continue;
        }
        let (kind, content) = resolve_object(&store, &oid)?;
        enqueue_children(kind, &content, &mut queue)?;
        out.push((object::kind_to_objcode(kind), content));
    }

    Ok(out)
}

/// A `filter <filter-spec>` request, reduced to the one mechanism the IN
/// scope covers: a per-blob size threshold. `blob:none` and
/// `blob:limit=<n>` share this exact mechanism (rev-list-options.adoc's
/// `--filter` documentation: "The form `--filter=blob:none` omits all
/// blobs" and "The form `--filter=blob:limit=<n>[kmg]` omits blobs of
/// size at least <n> bytes... <n> may be zero") - `blob:none` is kept as
/// its own variant rather than folded into `Limit(0)` only so
/// `fetch.rs`'s parser and this type stay a direct, readable mirror of
/// the two spec forms a client can actually send; `omits` below treats
/// them identically (both omit "size >= n", with `None` acting as if
/// n were infinite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobFilter {
    /// `blob:none`.
    None,
    /// `blob:limit=<n>`, n already fully expanded from any k/m/g suffix
    /// by fetch.rs's parser - this type only ever sees a plain byte
    /// count.
    Limit(u64),
}

impl BlobFilter {
    /// True iff a blob of `size` bytes must be OMITTED from the pack.
    ///
    /// BOUNDARY (the exact wording this crate treats as authoritative):
    /// rev-list-options.adoc says `blob:limit=<n>` "omits blobs of size
    /// at least <n> bytes" - "at least" is `>=`, so a blob of EXACTLY n
    /// bytes is omitted, not sent. Confirmed against real git
    /// empirically (not just read as prose) before relying on it - see
    /// NOTES.md's "blob:limit boundary" entry for the exact repro (a
    /// fixture blob of precisely n bytes, real git's own
    /// `--filter=blob:limit=<n>` clone omits it too).
    fn omits(&self, size: u64) -> bool {
        match self {
            BlobFilter::None => true,
            BlobFilter::Limit(n) => size >= *n,
        }
    }
}

/// Depth-unbounded want-side walk with `closure`'s own semantics (see
/// its doc comment), except that a blob object `filter` says to omit is
/// walked (so nothing reachable only through it is missed - a blob has
/// no children anyway, so this is a no-op in practice, stated only for
/// symmetry) but never pushed into the returned object list - UNLESS the
/// blob's own oid is itself one of `wants` (see EXPLICIT WANTS below).
///
/// PROPERTY THIS FUNCTION MUST PRESERVE ("only blobs may be omitted",
/// per the task that added this function): the omission check below is
/// gated on `kind == Kind::Blob` and nothing else - a tree or commit is
/// always pushed once reached, exactly like `closure`, so the client
/// always receives every tree that names an omitted blob (the pack
/// stays internally consistent: the client can see the oid the tree
/// entry names and fetch it lazily later, which is the entire point of
/// marking the remote a promisor).
///
/// EXPLICIT WANTS ARE NEVER OMITTED, EVEN WHEN THE FILTER WOULD
/// OTHERWISE OMIT THEM (promisor follow-up fetch, added alongside this
/// doc comment): a client's promisor-remote follow-up fetch for one
/// missing blob asks for that blob's oid directly, as a `want` line -
/// and re-sends the SAME `filter blob:none`/`blob:limit=<n>` the
/// original clone used (empirically confirmed - a real `git clone
/// --filter=blob:none` reuses `remote.<name>.partialclonefilter` for
/// every later lazy fetch, GIT_TRACE_PACKET capture logged in
/// NOTES.md). A server that applied the filter uniformly to every blob
/// it reaches - including one the client asked for BY NAME - would send
/// an empty pack for exactly that request: not wrong per any single
/// object-omission rule, but a silent contract violation from the
/// client's point of view (it asked for specific bytes and got a
/// pack with nothing in it, which this crate's own house rule treats as
/// exactly the kind of thing that must fail loud, not disappear - see
/// `fetch.rs`'s `parse_filter_spec` doc comment for the same principle
/// applied to an unrecognized filter-spec). Reproduced against this
/// server before this fix (a non-bare `git clone --filter=blob:none`
/// failed checkout with "could not fetch <oid> from promisor remote"
/// even though the object existed in our store - NOTES.md). The oracle
/// for the fix itself: `git rev-list --objects --filter=blob:none
/// <blob-oid>` (the blob's oid given directly, the exact shape of a
/// `want` line) still lists that blob - only a blob reached
/// TRANSITIVELY (via a tree walked from some other starting point) is
/// omitted. `wants` is therefore checked as a plain set-membership test
/// against the CURRENT oid, not "was this oid reached via a tree" -
/// which is exactly the same distinction rev-list's own oracle draws
/// between a positional revision argument and a traversed object.
pub fn closure_with_filter(
    git_dir: &Path,
    wants: &[String],
    haves: &[String],
    filter: BlobFilter,
) -> Result<Vec<(u8, Vec<u8>)>, ServeError> {
    // Have-side walk is IDENTICAL to `closure`'s: a filtered clone's
    // `have` lines mean exactly the same thing a normal clone's do (full
    // ancestry-reachability, unlike the shallow-specific `have_set` in
    // closure_with_depth) - filtering only ever decides whether an
    // object's BYTES are sent, never what the have/want negotiation
    // means.
    let store = ObjectStore::open(git_dir)?;
    let have_set = reachable_closure(&store, haves, true)?;

    // See this function's "EXPLICIT WANTS" doc comment section above -
    // membership in the ORIGINAL want list, not how (or whether) an oid
    // was later reached by the walk.
    let explicit_wants: HashSet<&str> = wants.iter().map(String::as_str).collect();

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = wants.iter().cloned().collect();
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();

    while let Some(oid) = queue.pop_front() {
        if !visited.insert(oid.clone()) {
            continue;
        }
        if have_set.contains(&oid) {
            continue;
        }
        let (kind, content) = resolve_object(&store, &oid)?;
        enqueue_children(kind, &content, &mut queue)?;
        if kind == Kind::Blob
            && filter.omits(content.len() as u64)
            && !explicit_wants.contains(oid.as_str())
        {
            // Omitted per the client's filter-spec. The tree entry that
            // names this oid was already pushed (or will be, from the
            // enqueue above) unconditionally - see this function's doc
            // comment's PROPERTY note - so skipping the blob's own bytes
            // here cannot leave a tree pointing at nothing the pack
            // itself doesn't otherwise account for. Excluded here
            // (`!explicit_wants.contains`) is the EXPLICIT WANTS case
            // above - a directly-requested blob is always sent.
            continue;
        }
        out.push((object::kind_to_objcode(kind), content));
    }

    Ok(out)
}

/// The direct-reference child oids of `content` (kind `kind`) - a
/// commit's tree followed by its parents (in that order), a tree's
/// non-gitlink entries, a tag's target, or nothing for a blob. Factored
/// out as a pure function (no queue side effect) so `closure_with_depth`
/// below can apply its own depth bookkeeping to a commit's PARENT edges
/// specifically, while still sharing this exact edge list - and exact
/// ordering - with the plain `enqueue_children` wrapper `closure` and
/// `reachable_closure` use.
fn child_oids(kind: Kind, content: &[u8]) -> Result<Vec<String>, ServeError> {
    let mut out = Vec::new();
    match kind {
        Kind::Commit => {
            let refs = commit::refs(content).map_err(malformed_in_store("commit"))?;
            out.push(refs.tree);
            out.extend(refs.parents);
        }
        Kind::Tree => {
            let entries = tree::entries(content).map_err(malformed_in_store("tree"))?;
            for entry in entries {
                // Gitlink (submodule): the oid names a commit in a
                // DIFFERENT repository - per this module's doc comment,
                // never expected to resolve here, so never enqueued.
                if entry.mode.as_slice() == b"160000" {
                    continue;
                }
                // Mode 120000 (symlink) entries are ordinary blobs on
                // disk and are walked like any other entry.
                out.push(entry.oid);
            }
        }
        Kind::Tag => {
            let refs = tag::refs(content).map_err(malformed_in_store("tag"))?;
            out.push(refs.object);
        }
        Kind::Blob => {} // leaf: no further references
    }
    Ok(out)
}

/// Pushes the oids `content` (of the given `kind`) directly references
/// onto `queue`. Shared between `closure`'s want-side walk and
/// `reachable_closure`'s have-side walk - both need the exact same graph
/// edges, just different termination/error behavior around them.
fn enqueue_children(
    kind: Kind,
    content: &[u8],
    queue: &mut VecDeque<String>,
) -> Result<(), ServeError> {
    queue.extend(child_oids(kind, content)?);
    Ok(())
}

fn malformed_in_store(what: &'static str) -> impl Fn(object::ObjectError) -> ServeError {
    move |e| ServeError::Repo {
        detail: format!("malformed {what} object in our own store: {e}"),
    }
}

/// Everything reachable from `oids`. When `ignore_unresolvable` is true
/// (the haves case - "the client may know objects we do not"), an oid
/// that doesn't resolve is silently skipped rather than erroring; when
/// false, a miss is `ServeError::Repo` (our own store failed to resolve
/// something it should own) - kept as a parameter rather than two
/// near-duplicate walks, even though `closure` above only ever calls
/// this with `true` today.
fn reachable_closure(
    store: &ObjectStore,
    oids: &[String],
    ignore_unresolvable: bool,
) -> Result<HashSet<String>, ServeError> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = oids.iter().cloned().collect();

    while let Some(oid) = queue.pop_front() {
        if !visited.insert(oid.clone()) {
            continue;
        }
        let (kind, content) = match store.resolve(&oid) {
            Ok(Some((kind, content))) => (kind, content),
            Ok(None) => {
                if ignore_unresolvable {
                    continue;
                }
                return Err(ServeError::Repo {
                    detail: format!("object {oid} not found in the object database"),
                });
            }
            Err(e) => {
                if ignore_unresolvable {
                    // A have oid whose resolution failed is treated the
                    // same as one that simply isn't present: "the client
                    // may know objects we do not" already covers a
                    // resolve failure just as well as a clean miss, for
                    // this caller's purposes.
                    continue;
                }
                return Err(ServeError::Repo {
                    detail: format!("object {oid} failed to resolve: {e}"),
                });
            }
        };
        enqueue_children(kind, &content, &mut queue)?;
    }

    Ok(visited)
}

/// Result of a depth-bounded (shallow) want-side walk: the objects to
/// pack, plus the shallow boundary this response must report per
/// gitprotocol-v2.adoc's shallow-info section (see `closure_with_depth`).
#[derive(Debug, Default)]
pub struct ShallowClosure {
    pub objects: Vec<(u8, Vec<u8>)>,
    /// Commits whose parents are NOT included in `objects` - a "shallow
    /// obj-id" line for each, per the spec's "The server sends a
    /// 'shallow obj-id' line for each commit whose parents will not be
    /// sent in the following packfile."
    pub shallow: Vec<String>,
    /// Oids the client told us (via `shallow <oid>` request lines) it
    /// already considers a boundary, but which this fetch has made not
    /// a boundary anymore (all their parents are now included) - an
    /// "unshallow obj-id" line for each.
    pub unshallow: Vec<String>,
}

/// The oids a `have` line (or anything reachable from one WITHOUT
/// crossing a commit's PARENT edge) proves the client already
/// possesses, for a `deepen` request specifically - see
/// `closure_with_depth`.
///
/// This is deliberately NOT `reachable_closure` (which `closure` above
/// uses safely for ordinary, non-shallow negotiation): `reachable_closure`
/// treats "client has commit X" as "client has X's entire ancestry",
/// which is exactly true for a NORMAL client's `have`, but false for a
/// SHALLOW client's `have` of its own shallow tip - that client has the
/// commit OBJECT (it downloaded it) but, by definition, none of its
/// parents. Confirmed empirically against real git (GIT_TRACE_PACKET on
/// a real `git fetch --depth=N` deepening a real `--depth=1` clone -
/// not read from any Documentation/ page, logged as a prior-knowledge/
/// empirical-verification item in NOTES.md): the exact oid sent as
/// `deepen`'s `want` is ALSO sent as a `have` line, for precisely this
/// reason (git already has that one object, and is telling the server
/// so, without claiming anything about its ancestry).
///
/// A commit's own TREE is still walked and included here (so its
/// blobs/subtrees are not needlessly resent): tree/blob completeness
/// for a commit the client actually possesses is not a shallow concern
/// at all (shallow only ever truncates the ANCESTRY chain, never a
/// possessed commit's own content) - only PARENT edges are withheld.
/// Non-commit oids (a `have` naming a tree/blob/tag directly) keep the
/// same full-expansion behavior `reachable_closure` uses, since none of
/// them can be a shallow boundary in the first place.
fn have_known_objects(
    store: &ObjectStore,
    haves: &[String],
) -> Result<HashSet<String>, ServeError> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = haves.iter().cloned().collect();

    while let Some(oid) = queue.pop_front() {
        if !visited.insert(oid.clone()) {
            continue;
        }
        let (kind, content) = match store.resolve(&oid) {
            Ok(Some(v)) => v,
            // Same "the client may know objects we do not" tolerance
            // `reachable_closure` uses for the have-side walk - a have
            // oid our own store cannot resolve is simply not added.
            Ok(None) => continue,
            Err(_) => continue,
        };
        match kind {
            Kind::Commit => {
                let refs = commit::refs(&content).map_err(malformed_in_store("commit"))?;
                // Tree only - NEVER parents (see this function's doc
                // comment: that is the entire point of this function
                // existing separately from `reachable_closure`).
                queue.push_back(refs.tree);
            }
            Kind::Tree | Kind::Tag | Kind::Blob => {
                queue.extend(child_oids(kind, &content)?);
            }
        }
    }

    Ok(visited)
}

/// Depth-bounded variant of `closure`, for a `deepen <depth>` request
/// (gitprotocol-v2.adoc's fetch section: "Requests that the fetch/clone
/// should be shallow having a commit depth of <depth> relative to the
/// remote side"). `depth` is relative to `wants` themselves, per the
/// same section's plain (non-"deepen-relative") semantics - a want is
/// depth 1 (matching shallow.adoc's "chain length": `--depth 20` keeps
/// chains of length at most 20, tip included), each real parent step
/// adds 1. `deepen-relative`/`deepen-since`/`deepen-not` are explicitly
/// out of scope for this milestone (see the module doc comment) and are
/// rejected before this function is ever called - see fetch.rs's arg
/// parser.
///
/// DESIGN NOTE (prior-knowledge disclosure, logged in NOTES.md): the
/// prose above is gitprotocol-v2.adoc's, but the spec does not spell out
/// the walk algorithm itself (how "depth" is measured across multiple
/// wants, or exactly which commit gets marked shallow) any more than
/// spike 02's ACK/ready rule was spelled out for `fetch.rs` above - this
/// is this module's own design, not a citation. The property that must
/// hold regardless of the exact algorithm - "never under-report the
/// shallow boundary" - is enforced structurally below: `shallow` is
/// derived from each PACKED commit's ACTUAL parents (re-derived from the
/// commit object itself, not from depth arithmetic), never from the
/// depth counter alone. A merge commit therefore needs no special case:
/// whichever of its real parents did not make it into `objects` marks it
/// shallow, however many that is.
///
/// Multi-want depth is a simple multi-source BFS: every want starts at
/// depth 1, and a commit's depth is the FIRST (i.e. minimum - BFS visits
/// in non-decreasing depth order from a uniform-depth source set) depth
/// at which any want's ancestry reaches it. A commit reached at exactly
/// `depth` has its own parent edges deliberately not walked further; a
/// commit reached at a lesser depth via some OTHER want is unaffected by
/// that cut, because depth/visitation is per-oid, not per-edge.
///
/// `haves` + `deepen` TOGETHER (a `git fetch --depth=N` against an
/// ALREADY-shallow clone, as opposed to a fresh `clone --depth=N`):
/// tested and handled - see `have_known_objects` below for the actual
/// bug this needed and its fix, confirmed against real git's own wire
/// trace (GIT_TRACE_PACKET) deepening a real shallow clone. The short
/// version: a `have <oid>` line proves the client possesses that EXACT
/// object, never that it possesses that object's ancestry (a shallow
/// client's `have` for its own shallow tip is precisely a claim of the
/// first kind, never the second) - `have_set` here is built to reflect
/// only that narrower, always-safe claim.
pub fn closure_with_depth(
    git_dir: &Path,
    wants: &[String],
    haves: &[String],
    depth: u32,
    client_shallow: &[String],
) -> Result<ShallowClosure, ServeError> {
    let store = ObjectStore::open(git_dir)?;
    let have_set = have_known_objects(&store, haves)?;

    let mut visited: HashSet<String> = HashSet::new();
    // Depth actually assigned to each COMMIT this response includes -
    // the set this is keyed on IS "what will be sent", so the boundary
    // check below can never disagree with the packfile it describes.
    let mut commit_depth: HashMap<String, u32> = HashMap::new();
    let mut commit_parents: HashMap<String, Vec<String>> = HashMap::new();
    // Queue items carry Some(depth) for a commit-ancestry edge (a want,
    // or a parent-of-a-commit-at-depth-d edge) and None for every other
    // edge (a commit's own tree, a tree's entries, a tag's target) -
    // depth only ever applies to commit ancestry (gitprotocol-v2.adoc:
    // "shallow copies of A COMMIT"), never to tree/blob content, and
    // never survives a tag peel (peeling to the tagged object is not an
    // ancestry step, so the peeled-to commit still starts fresh at 1 if
    // that is the first time it is reached at all).
    let mut queue: VecDeque<(String, Option<u32>)> =
        wants.iter().cloned().map(|w| (w, Some(1))).collect();
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();

    while let Some((oid, incoming_depth)) = queue.pop_front() {
        if !visited.insert(oid.clone()) {
            continue;
        }
        // NOTE: unlike `closure` above, a `have_set` hit does NOT skip
        // resolving/walking here - see `have_known_objects`'s doc
        // comment for why a commit's ancestry must always still be
        // walked (bounded by depth) even when the commit ITSELF is
        // already known to the client. `known` below only ever
        // suppresses re-adding an object's OWN bytes to `out`.
        let known = have_set.contains(&oid);
        let (kind, content) = resolve_object(&store, &oid)?;

        if kind == Kind::Commit {
            let d = incoming_depth.unwrap_or(1);
            let refs = commit::refs(&content).map_err(malformed_in_store("commit"))?;
            commit_depth.insert(oid.clone(), d);
            commit_parents.insert(oid.clone(), refs.parents.clone());
            queue.push_back((refs.tree, None));
            if d < depth {
                for parent in refs.parents {
                    queue.push_back((parent, Some(d + 1)));
                }
            }
            // d == depth: the cut point. Parents deliberately not
            // enqueued from here - whether that makes `oid` a shallow
            // boundary is decided after the walk (below), from its real
            // parent list against the final `commit_depth` set, not
            // here.
            if !known {
                out.push((object::kind_to_objcode(kind), content));
            }
        } else if known {
            // Tree/tag/blob the client already has: unlike a commit's
            // PARENT edges, tree/blob completeness for an object the
            // client possesses is never subject to shallow truncation
            // (shallow only ever truncates commit ancestry - see
            // `have_known_objects`), so it is always safe to stop
            // walking right here.
        } else {
            for child in child_oids(kind, &content)? {
                queue.push_back((child, None));
            }
            out.push((object::kind_to_objcode(kind), content));
        }
    }

    // Boundary: a commit we are sending is shallow iff at least one of
    // its REAL parents is neither being sent now (in `commit_depth`) nor
    // already known to the client (in `have_set`) - grounded in the
    // actual parent list re-derived from the packed object itself, so
    // this can never under-report relative to what the packfile above
    // actually contains, and a root commit (empty parent list) is
    // correctly never marked shallow even if the depth walk reaches it
    // exactly at the cut (vacuous `any()` over no parents is `false`).
    let mut shallow: Vec<String> = commit_parents
        .iter()
        .filter(|(_, parents)| {
            parents
                .iter()
                .any(|p| !commit_depth.contains_key(p) && !have_set.contains(p))
        })
        .map(|(oid, _)| oid.clone())
        .collect();
    shallow.sort();

    let shallow_set: HashSet<&String> = shallow.iter().collect();
    // Unshallow: an oid the CLIENT told us (via a `shallow <oid>`
    // request line) it already considers a boundary, which this fetch
    // is sending (so it is in `commit_depth`) and which the check above
    // did NOT mark shallow again - i.e. every one of its parents is now
    // covered. Per gitprotocol-v2.adoc: "The server MUST NOT send any
    // 'unshallow' lines for anything which the client has not indicated
    // was shallow" - enforced here by only ever iterating `client_shallow`
    // itself, never anything derived from our own walk.
    let mut unshallow: Vec<String> = client_shallow
        .iter()
        .filter(|oid| commit_depth.contains_key(*oid) && !shallow_set.contains(oid))
        .cloned()
        .collect();
    unshallow.sort();

    Ok(ShallowClosure {
        objects: out,
        shallow,
        unshallow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{loose, tree::TreeEntry};
    use std::path::PathBuf;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-walk-test-{}-{}-{}",
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

    /// Writes a tiny fixture: one commit -> one tree -> one blob, no
    /// parents. Returns (git_dir, commit_oid, tree_oid, blob_oid).
    fn write_fixture(name: &str) -> (PathBuf, String, String, String) {
        let git_dir = scratch_dir(name);
        let blob_oid = loose::write(&git_dir, Kind::Blob, b"hello\n").unwrap();
        let tree_content = tree::serialize(&[TreeEntry {
            mode: b"100644".to_vec(),
            name: b"a.txt".to_vec(),
            oid: blob_oid.clone(),
        }]);
        let tree_oid = loose::write(&git_dir, Kind::Tree, &tree_content).unwrap();
        let commit_content =
            format!("tree {tree_oid}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n");
        let commit_oid = loose::write(&git_dir, Kind::Commit, commit_content.as_bytes()).unwrap();
        (git_dir, commit_oid, tree_oid, blob_oid)
    }

    #[test]
    fn closure_with_no_haves_returns_the_whole_reachable_set() {
        let (git_dir, commit_oid, tree_oid, blob_oid) = write_fixture("no_haves");
        let objects = closure(&git_dir, std::slice::from_ref(&commit_oid), &[]).unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(oids, HashSet::from([commit_oid, tree_oid, blob_oid]));
    }

    #[test]
    fn closure_subtracts_everything_reachable_from_haves() {
        let (git_dir, commit_oid, tree_oid, blob_oid) = write_fixture("with_haves");
        // Client already has the tree (and therefore, transitively, the
        // blob) - only the commit itself should come back.
        let objects = closure(
            &git_dir,
            std::slice::from_ref(&commit_oid),
            std::slice::from_ref(&tree_oid),
        )
        .unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(oids, HashSet::from([commit_oid]));
        assert!(!oids.contains(&tree_oid));
        assert!(!oids.contains(&blob_oid));
    }

    #[test]
    fn closure_ignores_a_have_that_does_not_resolve() {
        let (git_dir, commit_oid, tree_oid, blob_oid) = write_fixture("bad_have");
        let bogus_have = "0000000000000000000000000000000000000000".to_string();
        let objects = closure(&git_dir, std::slice::from_ref(&commit_oid), &[bogus_have]).unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(oids, HashSet::from([commit_oid, tree_oid, blob_oid]));
    }

    #[test]
    fn closure_skips_gitlink_entries() {
        let git_dir = scratch_dir("gitlink");
        let blob_oid = loose::write(&git_dir, Kind::Blob, b"x\n").unwrap();
        let submodule_oid = "1111111111111111111111111111111111111111"; // deliberately never written - must never be resolved
        let tree_content = tree::serialize(&[
            TreeEntry {
                mode: b"100644".to_vec(),
                name: b"a.txt".to_vec(),
                oid: blob_oid.clone(),
            },
            TreeEntry {
                mode: b"160000".to_vec(),
                name: b"sub".to_vec(),
                oid: submodule_oid.to_string(),
            },
        ]);
        let tree_oid = loose::write(&git_dir, Kind::Tree, &tree_content).unwrap();

        let objects = closure(&git_dir, std::slice::from_ref(&tree_oid), &[]).unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(oids, HashSet::from([tree_oid, blob_oid]));
    }

    #[test]
    fn missing_object_reachable_from_a_want_is_a_loud_repo_error() {
        let git_dir = scratch_dir("missing_want");
        let bogus = "2222222222222222222222222222222222222222".to_string();
        let result = closure(&git_dir, &[bogus], &[]);
        assert!(matches!(result, Err(ServeError::Repo { .. })));
    }

    // --- closure_with_depth: direct unit coverage (the integration
    // tests in tests/shallow_clone.rs cover the same properties
    // end-to-end against real git; these are the fast, no-subprocess
    // versions of the same claims, exercising closure_with_depth's own
    // return value shape directly). ---

    /// Writes one shared blob+tree (content is irrelevant to depth
    /// bookkeeping) and returns its oid, for synthetic commits below to
    /// share.
    fn write_shared_tree(git_dir: &Path) -> String {
        let blob_oid = loose::write(git_dir, Kind::Blob, b"x\n").unwrap();
        let tree_content = tree::serialize(&[TreeEntry {
            mode: b"100644".to_vec(),
            name: b"a.txt".to_vec(),
            oid: blob_oid,
        }]);
        loose::write(git_dir, Kind::Tree, &tree_content).unwrap()
    }

    /// Writes a commit with the given parents and a caller-chosen
    /// message (kept distinct per call so otherwise-identical commits -
    /// e.g. two root commits sharing `tree_oid` - still get different
    /// oids).
    fn write_commit(git_dir: &Path, tree_oid: &str, parents: &[String], msg: &str) -> String {
        let mut content = format!("tree {tree_oid}\n");
        for p in parents {
            content.push_str(&format!("parent {p}\n"));
        }
        content.push_str(&format!(
            "author a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\n{msg}\n"
        ));
        loose::write(git_dir, Kind::Commit, content.as_bytes()).unwrap()
    }

    #[test]
    fn depth_cut_marks_only_the_boundary_commit_shallow_never_a_true_root() {
        let git_dir = scratch_dir("depth_cut");
        let tree_oid = write_shared_tree(&git_dir);
        let c1 = write_commit(&git_dir, &tree_oid, &[], "c1 root"); // depth 3 if reached
        let c2 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c1), "c2"); // depth 2
        let c3 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c2), "c3"); // depth 1 (the want)

        // depth=2: c3 (1) and c2 (2, the cut) are sent; c1 is not.
        let result = closure_with_depth(&git_dir, std::slice::from_ref(&c3), &[], 2, &[]).unwrap();
        let sent_commits: HashSet<String> = result
            .objects
            .iter()
            .filter(|(code, _)| *code == object::kind_to_objcode(Kind::Commit))
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert!(
            sent_commits.contains(&c3) && sent_commits.contains(&c2),
            "expected c3 and c2 to be sent: {sent_commits:?}"
        );
        assert!(
            !sent_commits.contains(&c1),
            "c1 must NOT be sent at depth=2: {sent_commits:?}"
        );
        assert_eq!(
            result.shallow,
            vec![c2.clone()],
            "c2 is the only commit with an unsent parent"
        );
        assert!(result.unshallow.is_empty());

        // depth=10 (deeper than the fixture's 3-commit history): every
        // commit is sent, and c1 (a genuine root - empty parent list)
        // must never be marked shallow just because the walk happened
        // to reach it exactly "at" some cut.
        let deep = closure_with_depth(&git_dir, std::slice::from_ref(&c3), &[], 10, &[]).unwrap();
        assert!(
            deep.shallow.is_empty(),
            "depth deeper than history must report no shallow boundary: {:?}",
            deep.shallow
        );
        assert!(deep.unshallow.is_empty());
    }

    #[test]
    fn merge_commit_at_the_cut_gets_exactly_one_shallow_line_for_two_missing_parents() {
        let git_dir = scratch_dir("merge_cut");
        let tree_oid = write_shared_tree(&git_dir);
        let p1 = write_commit(&git_dir, &tree_oid, &[], "p1 root");
        let p2 = write_commit(&git_dir, &tree_oid, &[], "p2 root");
        let merge = write_commit(&git_dir, &tree_oid, &[p1.clone(), p2.clone()], "merge"); // depth 2
        let tip = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&merge), "tip"); // depth 1

        let result = closure_with_depth(&git_dir, &[tip], &[], 2, &[]).unwrap();
        assert_eq!(
            result.shallow,
            vec![merge],
            "the merge commit must get exactly one shallow line, not one per missing parent"
        );
        assert!(result.unshallow.is_empty());

        let sent_oids: HashSet<String> = result
            .objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert!(
            !sent_oids.contains(&p1) && !sent_oids.contains(&p2),
            "neither of the merge commit's parents should be sent at this depth"
        );
    }

    #[test]
    fn deepening_past_a_previously_reported_boundary_reports_unshallow() {
        let git_dir = scratch_dir("unshallow");
        let tree_oid = write_shared_tree(&git_dir);
        let c1 = write_commit(&git_dir, &tree_oid, &[], "c1 root");
        let c2 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c1), "c2");
        let c3 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c2), "c3");

        // First fetch (depth=2) would have reported c2 as the boundary
        // - simulate the client now holding that as its local shallow
        // state and asking to deepen to depth=3.
        let result =
            closure_with_depth(&git_dir, &[c3], &[], 3, std::slice::from_ref(&c2)).unwrap();
        assert!(
            result.shallow.is_empty(),
            "c1 is a true root - reaching it must not (re-)mark anything shallow: {:?}",
            result.shallow
        );
        assert_eq!(
            result.unshallow,
            vec![c2],
            "c2's only parent (c1) is now sent, so it must be reported unshallow"
        );
    }

    /// The exact wire scenario real git produces for `git fetch
    /// --depth=N` against an already-shallow clone (confirmed via
    /// GIT_TRACE_PACKET, see this task's report/NOTES.md): the client
    /// sends its shallow tip as BOTH `want` (unchanged - nothing new
    /// upstream) and `have` (it already possesses that exact object),
    /// plus `shallow <tip>` and `deepen <n>`. A `have` for a shallow
    /// client's own boundary must NOT be treated as "the client also
    /// has this commit's ancestry" - if it were, the walk would stop
    /// dead at the tip and deepening would silently do nothing.
    #[test]
    fn have_on_the_shallow_tip_does_not_block_walking_past_it() {
        let git_dir = scratch_dir("have_deepen");
        let tree_oid = write_shared_tree(&git_dir);
        let c1 = write_commit(&git_dir, &tree_oid, &[], "c1 root");
        let c2 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c1), "c2");
        let c3 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c2), "c3");
        let c4 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c3), "c4");
        let c5 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c4), "c5 tip"); // the shallow tip

        // want=c5 (unchanged), have=c5 (client already has that exact
        // object), shallow=[c5] (client's declared boundary), deepen=3.
        let result = closure_with_depth(
            &git_dir,
            std::slice::from_ref(&c5),
            std::slice::from_ref(&c5),
            3,
            std::slice::from_ref(&c5),
        )
        .unwrap();

        let sent_commits: HashSet<String> = result
            .objects
            .iter()
            .filter(|(code, _)| *code == object::kind_to_objcode(Kind::Commit))
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        // c4 and c3 MUST be walked and sent - the bug this test guards
        // against is the walk stopping at c5 because c5 is a `have`.
        assert!(
            sent_commits.contains(&c4),
            "c4 must be sent - the have on c5 must not block walking its parent: {sent_commits:?}"
        );
        assert!(
            sent_commits.contains(&c3),
            "c3 must be sent (depth=3 reaches it): {sent_commits:?}"
        );
        // c5 itself is redundant (client already has it) and c2/c1 are
        // beyond the requested depth - neither should be resent, though
        // only c5's absence is load-bearing (the "superset is fine"
        // rule means c2/c1 absence is a nice-to-have, not a
        // correctness requirement).
        assert!(
            !sent_commits.contains(&c5),
            "c5 is a have - its own bytes should not be resent"
        );

        assert_eq!(
            result.shallow,
            vec![c3.clone()],
            "c3 is the new boundary (its parent c2 is neither sent nor a have)"
        );
        assert_eq!(
            result.unshallow,
            vec![c5],
            "c5's parent (c4) is now sent, so c5 must be reported unshallow"
        );
    }

    #[test]
    fn a_commit_reached_at_a_shorter_depth_via_a_second_want_is_not_cut() {
        let git_dir = scratch_dir("multi_want");
        let tree_oid = write_shared_tree(&git_dir);
        let c1 = write_commit(&git_dir, &tree_oid, &[], "c1 root");
        let c2 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c1), "c2");
        let c3 = write_commit(&git_dir, &tree_oid, std::slice::from_ref(&c2), "c3");

        // want #1 (c3) puts c2 at depth 2 (the cut, for depth=2) and
        // would never enqueue c1. want #2 (c2 itself, e.g. a second
        // branch tip) reaches c2 at depth 1 directly - the shorter path
        // must win, so c2 gets to expand to c1 after all, and neither
        // c2 nor anything else ends up shallow.
        let result = closure_with_depth(&git_dir, &[c3, c2], &[], 2, &[]).unwrap();
        let sent_oids: HashSet<String> = result
            .objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert!(
            sent_oids.contains(&c1),
            "c1 should be reachable via the second want's shorter path: {sent_oids:?}"
        );
        assert!(
            result.shallow.is_empty(),
            "no commit should be shallow once the shorter path reaches the root: {:?}",
            result.shallow
        );
    }

    // --- closure_with_filter: direct unit coverage (tests/partial_clone.rs
    // covers the same properties end-to-end against real git; these are
    // the fast, no-subprocess versions of the same claims, exercising
    // closure_with_filter's own return value shape directly). ---

    #[test]
    fn blob_none_omits_the_blob_but_keeps_the_tree_and_commit() {
        let (git_dir, commit_oid, tree_oid, blob_oid) = write_fixture("blob_none");
        let objects = closure_with_filter(
            &git_dir,
            std::slice::from_ref(&commit_oid),
            &[],
            BlobFilter::None,
        )
        .unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(
            oids,
            HashSet::from([commit_oid, tree_oid]),
            "commit and tree must still be sent"
        );
        assert!(
            !oids.contains(&blob_oid),
            "blob:none must omit the blob's own bytes"
        );
    }

    #[test]
    fn blob_limit_boundary_is_exact_a_blob_of_exactly_n_bytes_is_omitted() {
        let git_dir = scratch_dir("blob_limit_boundary");
        // Two blobs: one exactly N bytes (must be omitted - "size at
        // least N"), one N-1 bytes (must be sent).
        let n: u64 = 10;
        let at_limit = loose::write(&git_dir, Kind::Blob, &vec![b'a'; n as usize]).unwrap();
        let under_limit =
            loose::write(&git_dir, Kind::Blob, &vec![b'b'; (n - 1) as usize]).unwrap();
        let tree_content = tree::serialize(&[
            TreeEntry {
                mode: b"100644".to_vec(),
                name: b"at.txt".to_vec(),
                oid: at_limit.clone(),
            },
            TreeEntry {
                mode: b"100644".to_vec(),
                name: b"under.txt".to_vec(),
                oid: under_limit.clone(),
            },
        ]);
        let tree_oid = loose::write(&git_dir, Kind::Tree, &tree_content).unwrap();
        let commit_content =
            format!("tree {tree_oid}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n");
        let commit_oid = loose::write(&git_dir, Kind::Commit, commit_content.as_bytes()).unwrap();

        let objects =
            closure_with_filter(&git_dir, &[commit_oid], &[], BlobFilter::Limit(n)).unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert!(
            !oids.contains(&at_limit),
            "a blob of exactly the limit must be omitted (>= n): {oids:?}"
        );
        assert!(
            oids.contains(&under_limit),
            "a blob one byte under the limit must be sent: {oids:?}"
        );
        assert!(
            oids.contains(&tree_oid),
            "the tree naming both blobs must always be sent"
        );
    }

    #[test]
    fn blob_limit_zero_omits_every_blob_same_as_blob_none() {
        let (git_dir, commit_oid, tree_oid, blob_oid) = write_fixture("blob_limit_zero");
        let objects = closure_with_filter(
            &git_dir,
            std::slice::from_ref(&commit_oid),
            &[],
            BlobFilter::Limit(0),
        )
        .unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(
            oids,
            HashSet::from([commit_oid, tree_oid]),
            "limit=0 must omit every blob, per rev-list-options.adoc's \"n may be zero\""
        );
        assert!(!oids.contains(&blob_oid));
    }

    #[test]
    fn blob_none_still_sends_a_blob_that_is_itself_an_explicit_want() {
        // The promisor follow-up fetch case: the client's SECOND request
        // (after a `blob:none` clone already succeeded) wants the
        // omitted blob BY OID directly, still carrying `filter
        // blob:none` (see this function's "EXPLICIT WANTS" doc comment
        // - real git's own promisor-remote lazy fetch reuses the same
        // filter config on every follow-up request). The blob must come
        // back even though the filter would otherwise omit it.
        let (git_dir, _commit_oid, _tree_oid, blob_oid) = write_fixture("blob_none_explicit_want");
        let objects = closure_with_filter(
            &git_dir,
            std::slice::from_ref(&blob_oid),
            &[],
            BlobFilter::None,
        )
        .unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(
            oids,
            HashSet::from([blob_oid]),
            "an explicitly wanted blob must never be omitted by the filter"
        );
    }

    #[test]
    fn blob_limit_still_sends_an_over_limit_blob_that_is_an_explicit_want() {
        let git_dir = scratch_dir("blob_limit_explicit_want");
        let big_blob = loose::write(&git_dir, Kind::Blob, &[b'a'; 100]).unwrap();
        let objects = closure_with_filter(
            &git_dir,
            std::slice::from_ref(&big_blob),
            &[],
            BlobFilter::Limit(10),
        )
        .unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(
            oids,
            HashSet::from([big_blob]),
            "an explicitly wanted over-limit blob must still be sent"
        );
    }

    #[test]
    fn filter_still_subtracts_everything_reachable_from_haves() {
        let (git_dir, commit_oid, tree_oid, blob_oid) = write_fixture("filter_haves");
        // Client already has the tree (and blob) - only the commit
        // itself should come back, same have-subtraction `closure`
        // itself gets, independent of the filter applied on top.
        let objects = closure_with_filter(
            &git_dir,
            std::slice::from_ref(&commit_oid),
            std::slice::from_ref(&tree_oid),
            BlobFilter::None,
        )
        .unwrap();
        let oids: HashSet<String> = objects
            .iter()
            .map(|(code, content)| rustgit::pack::pack::compute_oid(*code, content))
            .collect();
        assert_eq!(oids, HashSet::from([commit_oid]));
        assert!(!oids.contains(&tree_oid));
        assert!(!oids.contains(&blob_oid));
    }
}
