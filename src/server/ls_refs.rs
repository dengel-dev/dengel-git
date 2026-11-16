//! `command=ls-refs` responder: enumerate refs (loose + packed via
//! rustgit::refs), honor symrefs/peel/ref-prefix arguments, emit the
//! response.
//!
//! Format source: git-reference/Documentation/gitprotocol-v2.adoc,
//! "ls-refs" section - request arguments (symrefs, peel, ref-prefix) and
//! output grammar:
//!   ref = PKT-LINE(obj-id-or-unborn SP refname *(SP ref-attribute) LF)
//!   ref-attribute = ("symref-target:" symref-target) | ("peeled:" obj-id)
//! (this is also exactly what spike 02's client-side parser in
//! rustgit::protocol::ls_refs already expects - see its
//! parse_ls_refs_line, which this module's own tests cross-check
//! against). The `unborn` feature (and its argument) is NOT implemented -
//! not advertised in advertise.rs, so a conforming client never sends it;
//! an unrecognized argument here is treated as malformed rather than
//! silently ignored.
//!
//! ORDERING NOTE (prior-knowledge disclosure, see NOTES.md): the v2
//! ls-refs grammar itself specifies no output ordering at all. HEAD-
//! first-then-bytewise-by-refname is carried over from general
//! familiarity with git's ref advertisement conventions (and is what
//! gitprotocol-http.adoc's DUMB-protocol section states explicitly,
//! for a different wire format) rather than from anything in
//! gitprotocol-v2.adoc's ls-refs section itself - flagged per CLAUDE.md
//! and hand-verified against real git's ls-refs output (see NOTES.md).

use super::{walk, ServeError};
use crate::object::{tag, Kind};
use crate::objectstore::ObjectStore;
use rustgit::protocol::pktline;
use rustgit::refs::loose as rloose;
use rustgit::refs::packed as rpacked;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Default)]
struct LsRefsArgs {
    symrefs: bool,
    peel: bool,
    ref_prefixes: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<LsRefsArgs, ServeError> {
    let mut parsed = LsRefsArgs::default();
    for arg in args {
        if arg == "symrefs" {
            parsed.symrefs = true;
        } else if arg == "peel" {
            parsed.peel = true;
        } else if let Some(prefix) = arg.strip_prefix("ref-prefix ") {
            parsed.ref_prefixes.push(prefix.to_string());
        } else {
            // Includes "unborn" - a real base-command argument per the
            // spec, but gated behind a feature we do not advertise (see
            // module doc comment), so a conforming client never sends
            // it and receiving it anyway is treated as malformed.
            return Err(ServeError::Malformed {
                what: "ls-refs argument",
                detail: format!("unrecognized or unimplemented: {:?}", arg),
            });
        }
    }
    Ok(parsed)
}

/// `args` are the request's argument lines (after the delim-pkt), one
/// per element, already stripped of pkt-line framing.
pub fn respond(git_dir: &Path, args: &[String]) -> Result<Vec<u8>, ServeError> {
    let parsed = parse_args(args)?;

    // refname -> value. packed-refs populated first, then overwritten by
    // loose refs of the same name - "loose SHADOWS packed" per this
    // milestone's instruction, and rustgit::refs' own transactional
    // store treats packed-refs as the fallback tier for exactly this
    // reason.
    let mut refs: BTreeMap<String, rloose::LooseRefValue> = BTreeMap::new();

    let packed = rpacked::read_packed_refs(git_dir)?;
    for (name, entry) in packed.entries {
        refs.insert(name, rloose::LooseRefValue::Oid(entry.oid));
    }

    walk_loose_refs(&git_dir.join("refs"), "refs", &mut refs)?;

    // HEAD lives outside refs/ entirely - read directly, per the
    // milestone's "plus HEAD" instruction.
    if let Some(head_value) = rloose::read_loose_ref(git_dir, "HEAD")? {
        refs.insert("HEAD".to_string(), head_value);
    }

    let mut selected: Vec<(&String, &rloose::LooseRefValue)> = refs
        .iter()
        .filter(|(name, _)| {
            parsed.ref_prefixes.is_empty()
                || parsed
                    .ref_prefixes
                    .iter()
                    .any(|p| name.starts_with(p.as_str()))
        })
        .collect();

    // HEAD first (see the module doc comment's ordering note), then
    // bytewise by refname - BTreeMap<String, _> iteration is already
    // bytewise for the ASCII-only refnames git produces, so a stable
    // sort here only needs to special-case HEAD's position.
    selected.sort_by(|(a, _), (b, _)| match (a.as_str(), b.as_str()) {
        ("HEAD", "HEAD") => std::cmp::Ordering::Equal,
        ("HEAD", _) => std::cmp::Ordering::Less,
        (_, "HEAD") => std::cmp::Ordering::Greater,
        _ => a.cmp(b),
    });

    // Only built when actually needed (the "peel" argument was sent) -
    // parsing every pack's .idx is pointless work for the common
    // no-peel request. Built once, outside the loop below, so it is at
    // most one resolve session per response rather than one per tag.
    let store = if parsed.peel {
        Some(ObjectStore::open(git_dir)?)
    } else {
        None
    };

    let mut out = Vec::new();
    for (refname, value) in selected {
        let Some(oid) = resolve_final_oid(git_dir, &refs, value)? else {
            // Symref chain bottoms out at nothing we can resolve (an
            // unborn branch, or a dangling symref target). We do not
            // implement the `unborn` feature, so such a ref is simply
            // omitted rather than reported with a placeholder oid.
            continue;
        };

        let mut line = format!("{oid} {refname}");
        if parsed.symrefs {
            if let rloose::LooseRefValue::Symref(target) = value {
                line.push_str(&format!(" symref-target:{target}"));
            }
        }
        if parsed.peel {
            if let Some(peeled_oid) = peel_tag(
                store.as_ref().expect("built above whenever parsed.peel"),
                &oid,
            )? {
                line.push_str(&format!(" peeled:{peeled_oid}"));
            }
        }
        line.push('\n');
        out.extend_from_slice(&pktline::encode_data(line.as_bytes()));
    }
    out.extend_from_slice(&pktline::encode_flush());

    Ok(out)
}

/// Recursively walks `dir` (a `refs/` subtree), inserting every loose
/// ref file found as `refname_prefix/<relative-path>` into `out`. Not
/// documented anywhere as a walk algorithm (there is no such thing to
/// document - it's just "read every file under refs/"); the only format
/// fact here (a loose ref file's content) is rustgit::refs::loose's, not
/// this function's own.
fn walk_loose_refs(
    dir: &Path,
    refname_prefix: &str,
    out: &mut BTreeMap<String, rloose::LooseRefValue>,
) -> Result<(), ServeError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()), // no refs/ at all - empty repo
        Err(e) => return Err(ServeError::Io(e)),
    };

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let child_refname = format!("{}/{}", refname_prefix, name.to_string_lossy());

        if file_type.is_dir() {
            walk_loose_refs(&entry.path(), &child_refname, out)?;
        } else if file_type.is_file() {
            let content = std::fs::read_to_string(entry.path())?;
            out.insert(child_refname, rloose::parse_ref_content(&content));
        }
        // Symlinks under refs/ are not expected in this milestone's
        // fixtures and are silently skipped rather than followed.
    }

    Ok(())
}

/// Follows a symref chain to its final oid. `refs` is consulted first
/// (the enumerated set this response is already built from); a target
/// outside that set (e.g. HEAD pointing somewhere not under refs/, or a
/// target this walk hasn't reached for some other reason) falls back to
/// a direct disk read. `Ok(None)` means the chain bottoms out at
/// nothing resolvable (unborn/dangling) rather than an oid.
fn resolve_final_oid(
    git_dir: &Path,
    refs: &BTreeMap<String, rloose::LooseRefValue>,
    value: &rloose::LooseRefValue,
) -> Result<Option<String>, ServeError> {
    let mut current = value.clone();
    for _ in 0..10 {
        match current {
            rloose::LooseRefValue::Oid(oid) => return Ok(Some(oid)),
            rloose::LooseRefValue::Symref(target) => match refs.get(&target) {
                Some(v) => current = v.clone(),
                None => match rloose::read_loose_ref(git_dir, &target)? {
                    Some(v) => current = v,
                    None => return Ok(None),
                },
            },
        }
    }
    Err(ServeError::Malformed {
        what: "ref",
        detail: "symref chain too deep (possible cycle)".to_string(),
    })
}

/// Peels `oid` through a chain of annotated tag objects to the first
/// non-tag target. `Ok(None)` if `oid` itself is not a tag (lightweight
/// tags and ordinary branches alike get no peeled attribute, per the
/// "peel" argument's "Show peeled tags" wording).
fn peel_tag(store: &ObjectStore, oid: &str) -> Result<Option<String>, ServeError> {
    let mut current = oid.to_string();
    let mut peeled_any = false;
    for _ in 0..10 {
        let (kind, content) = walk::resolve_object(store, &current)?;
        match kind {
            Kind::Tag => {
                let refs = tag::refs(&content).map_err(|e| ServeError::Repo {
                    detail: format!("malformed tag object {current} in our own store: {e}"),
                })?;
                current = refs.object;
                peeled_any = true;
            }
            _ => return Ok(if peeled_any { Some(current) } else { None }),
        }
    }
    Err(ServeError::Malformed {
        what: "tag",
        detail: "tag peel chain too deep (possible cycle)".to_string(),
    })
}

/// Enumerate every ref (HEAD + loose + packed, loose shadowing packed),
/// resolved to a final oid, sorted HEAD-first-then-bytewise, with no
/// prefix filtering and no symref/peel attributes. Factors out exactly
/// the "which refs, in what order, resolved to what oid" logic `respond`
/// above already implements and tests, for a second caller that needs
/// the identical set but a different (non-v2) wire shape: G4's
/// receive-pack reference-discovery advertisement.
/// gitprotocol-pack.adoc, "Reference Discovery" (push side): "The
/// reference discovery phase is done nearly the same way as it is in the
/// fetching protocol" - same ref set and ordering convention, different
/// capability list and framing (built by receive/session.rs, not here).
/// Public for callers that list refs (`(refname, oid)` pairs, HEAD first).
pub fn enumerate_all_refs(git_dir: &Path) -> Result<Vec<(String, String)>, ServeError> {
    let mut refs: BTreeMap<String, rloose::LooseRefValue> = BTreeMap::new();

    let packed = rpacked::read_packed_refs(git_dir)?;
    for (name, entry) in packed.entries {
        refs.insert(name, rloose::LooseRefValue::Oid(entry.oid));
    }

    walk_loose_refs(&git_dir.join("refs"), "refs", &mut refs)?;

    if let Some(head_value) = rloose::read_loose_ref(git_dir, "HEAD")? {
        refs.insert("HEAD".to_string(), head_value);
    }

    let mut selected: Vec<(&String, &rloose::LooseRefValue)> = refs.iter().collect();
    selected.sort_by(|(a, _), (b, _)| match (a.as_str(), b.as_str()) {
        ("HEAD", "HEAD") => std::cmp::Ordering::Equal,
        ("HEAD", _) => std::cmp::Ordering::Less,
        (_, "HEAD") => std::cmp::Ordering::Greater,
        _ => a.cmp(b),
    });

    let mut out = Vec::new();
    for (refname, value) in selected {
        if let Some(oid) = resolve_final_oid(git_dir, &refs, value)? {
            out.push((refname.clone(), oid));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::loose;
    use rustgit::protocol::pktline::PktLine;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-lsrefs-test-{}-{}-{}",
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

    fn write_loose_ref(git_dir: &Path, refname: &str, value: &rloose::LooseRefValue) {
        let path = rloose::ref_path(git_dir, refname);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, rloose::format_ref_content(value)).unwrap();
    }

    #[test]
    fn parse_args_rejects_unborn_since_it_is_not_advertised() {
        let result = parse_args(&["unborn".to_string()]);
        assert!(matches!(result, Err(ServeError::Malformed { .. })));
    }

    #[test]
    fn empty_repo_produces_just_a_flush() {
        let git_dir = scratch_dir("empty");
        let out = respond(&git_dir, &[]).unwrap();
        assert_eq!(out, pktline::encode_flush());
    }

    #[test]
    fn lists_a_branch_and_head_symref_target() {
        let git_dir = scratch_dir("branch_and_head");
        let oid = loose::write(&git_dir, Kind::Blob, b"x\n").unwrap(); // stand-in oid, ls-refs never resolves the object itself
        write_loose_ref(
            &git_dir,
            "refs/heads/main",
            &rloose::LooseRefValue::Oid(oid.clone()),
        );
        write_loose_ref(
            &git_dir,
            "HEAD",
            &rloose::LooseRefValue::Symref("refs/heads/main".to_string()),
        );

        let out = respond(&git_dir, &["symrefs".to_string()]).unwrap();

        let mut cursor = Cursor::new(out);
        let mut texts = Vec::new();
        while let Some(line) = pktline::read_pkt_line(&mut cursor).unwrap() {
            match line {
                PktLine::Data(bytes) => texts.push(
                    String::from_utf8_lossy(&bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                PktLine::Flush => break,
                other => panic!("unexpected pkt-line: {other:?}"),
            }
        }

        // Cross-checked shape against spike 02's own client-side parser
        // (rustgit::protocol::ls_refs::parse_ls_refs_line is private, but
        // its public entry point `ls_refs` documents the exact same
        // "oid SP refname *(SP attr)" line shape asserted here directly).
        assert!(
            texts
                .iter()
                .any(|t| t == &format!("{oid} HEAD symref-target:refs/heads/main")),
            "{texts:?}"
        );
        assert!(
            texts.iter().any(|t| t == &format!("{oid} refs/heads/main")),
            "{texts:?}"
        );
        // HEAD sorts first.
        assert!(texts[0].contains("HEAD"));
    }

    #[test]
    fn ref_prefix_filters_to_matching_refs_only() {
        let git_dir = scratch_dir("prefix");
        let oid_a = loose::write(&git_dir, Kind::Blob, b"a\n").unwrap();
        let oid_b = loose::write(&git_dir, Kind::Blob, b"b\n").unwrap();
        write_loose_ref(
            &git_dir,
            "refs/heads/main",
            &rloose::LooseRefValue::Oid(oid_a),
        );
        write_loose_ref(&git_dir, "refs/tags/v1", &rloose::LooseRefValue::Oid(oid_b));

        let out = respond(&git_dir, &["ref-prefix refs/heads/".to_string()]).unwrap();
        let mut cursor = Cursor::new(out);
        let mut texts = Vec::new();
        while let Some(line) = pktline::read_pkt_line(&mut cursor).unwrap() {
            match line {
                PktLine::Data(bytes) => texts.push(
                    String::from_utf8_lossy(&bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                PktLine::Flush => break,
                _ => panic!("unexpected pkt-line"),
            }
        }
        assert_eq!(texts.len(), 1);
        assert!(texts[0].ends_with("refs/heads/main"));
    }

    #[test]
    fn peels_an_annotated_tag_but_not_a_lightweight_one() {
        let git_dir = scratch_dir("peel");
        let target_oid = loose::write(&git_dir, Kind::Blob, b"target\n").unwrap();
        let tag_content =
            format!("object {target_oid}\ntype blob\ntag t\ntagger t <t@x> 0 +0000\n\nmsg\n");
        let tag_oid = loose::write(&git_dir, Kind::Tag, tag_content.as_bytes()).unwrap();

        write_loose_ref(
            &git_dir,
            "refs/tags/annotated",
            &rloose::LooseRefValue::Oid(tag_oid.clone()),
        );
        write_loose_ref(
            &git_dir,
            "refs/tags/lightweight",
            &rloose::LooseRefValue::Oid(target_oid.clone()),
        );

        let out = respond(&git_dir, &["peel".to_string()]).unwrap();
        let mut cursor = Cursor::new(out);
        let mut texts = Vec::new();
        while let Some(line) = pktline::read_pkt_line(&mut cursor).unwrap() {
            match line {
                PktLine::Data(bytes) => texts.push(
                    String::from_utf8_lossy(&bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                PktLine::Flush => break,
                _ => panic!("unexpected pkt-line"),
            }
        }

        assert!(
            texts
                .iter()
                .any(|t| t == &format!("{tag_oid} refs/tags/annotated peeled:{target_oid}")),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|t| t == &format!("{target_oid} refs/tags/lightweight")),
            "{texts:?}"
        );
    }

    #[test]
    fn loose_ref_shadows_packed_ref_of_the_same_name() {
        let git_dir = scratch_dir("shadow");
        let packed_oid = "1111111111111111111111111111111111111111";
        let loose_oid = loose::write(&git_dir, Kind::Blob, b"loose\n").unwrap();

        std::fs::write(
            git_dir.join("packed-refs"),
            format!(
                "# pack-refs with: peeled fully-peeled sorted \n{packed_oid} refs/heads/main\n"
            ),
        )
        .unwrap();
        write_loose_ref(
            &git_dir,
            "refs/heads/main",
            &rloose::LooseRefValue::Oid(loose_oid.clone()),
        );

        let out = respond(&git_dir, &[]).unwrap();
        let mut cursor = Cursor::new(out);
        let mut texts = Vec::new();
        while let Some(line) = pktline::read_pkt_line(&mut cursor).unwrap() {
            match line {
                PktLine::Data(bytes) => texts.push(
                    String::from_utf8_lossy(&bytes)
                        .trim_end_matches('\n')
                        .to_string(),
                ),
                PktLine::Flush => break,
                _ => panic!("unexpected pkt-line"),
            }
        }
        assert_eq!(texts, vec![format!("{loose_oid} refs/heads/main")]);
    }
}
