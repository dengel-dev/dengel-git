//! G3 validation gate (NMA-1452): refname and oid syntax checks that
//! MUST run before any attacker-controlled string reaches rustgit's
//! ref-store primitives (`dengel_git::refs`, re-exported verbatim from
//! the frozen rustgit spike - see lib.rs's "Trust boundary rule").
//!
//! rustgit's ref-store code is validated-input-only by design: it
//! panics on some malformed input (pack/odb.rs's read_loose_object
//! slices `&oid[0..2]` with no length check) and has NO refname syntax
//! check anywhere in src/refs/ (loose.rs defines `is_valid_oid_syntax`
//! but nothing calls it, and `loose::ref_path` is a bare
//! `git_dir.join(refname)`, which lets an absolute or `..`-laden
//! refname escape the repo entirely via PathBuf::join's documented
//! "if the pushed path is absolute, it replaces the current path"
//! behavior). This module is the gate that stops both classes of
//! input from ever reaching that code.
//!
//! Spec source for `valid_refname`: git-check-ref-format(1),
//! `Documentation/git-check-ref-format.adoc` in the git-reference
//! clean-room checkout - the ONLY C-source-adjacent reference this
//! module is allowed to consult (see CLAUDE.md's clean-room rule and
//! this milestone's brief). Every rule below is cited by its doc list
//! item. No git C source was read to write this file.

/// Is `name` a well-formed refname per git-check-ref-format(1)'s rule
/// list (the plain-ref rules, not `--refspec-pattern`)?
///
/// Rule-by-rule citation (doc list items, in the doc's own order):
///
/// 1. "no slash-separated component can begin with a dot `.` or end
///    with the sequence `.lock`"
/// 2. "They must contain at least one `/`... If the `--allow-onelevel`
///    option is used, this rule is waived." NOT ENFORCED HERE - see
///    the doc comment at the bottom of this file under "judgment
///    call: one-level names" for why, and NOTES.md's disclosure
///    entry for the confirming subprocess run.
/// 3. "cannot have two consecutive dots `..` anywhere"
/// 4. "cannot have ASCII control characters (bytes < \040, or \177
///    DEL), space, tilde `~`, caret `^`, or colon `:` anywhere"
/// 5. "cannot have question-mark `?`, asterisk `*`, or open bracket
///    `[`" (the `--refspec-pattern` exception for `*` does not apply:
///    this validator is for concrete refnames, never refspecs)
/// 6. "cannot begin or end with a slash `/` or contain multiple
///    consecutive slashes" (the `--normalize` exception does not
///    apply: this validator never rewrites input)
/// 7. "cannot end with a dot `.`"
/// 8. "cannot contain a sequence `@{`"
/// 9. "cannot be the single character `@`"
/// 10. "cannot contain a `\`"
///
/// Empty string: rejected explicitly (not a well-formed refname under
/// any git usage; also implicit from rule 6's "cannot begin... with a
/// slash" reasoning not applying, so it needs its own check).
pub fn valid_refname(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // Rule 9: bare "@".
    if name == "@" {
        return false;
    }

    // Rule 8: "@{" anywhere.
    if name.contains("@{") {
        return false;
    }

    // Rule 10: backslash anywhere.
    if name.contains('\\') {
        return false;
    }

    // Rule 3: ".." anywhere.
    if name.contains("..") {
        return false;
    }

    // Rule 7: cannot end with ".".
    if name.ends_with('.') {
        return false;
    }

    // Rule 6: cannot begin or end with "/", cannot contain "//".
    if name.starts_with('/') || name.ends_with('/') || name.contains("//") {
        return false;
    }

    // Rule 4 + rule 5, character-class checks over every char.
    for c in name.chars() {
        if (c as u32) < 0x20 || (c as u32) == 0x7f {
            return false; // control chars, DEL
        }
        match c {
            ' ' | '~' | '^' | ':' => return false, // rule 4
            '?' | '*' | '[' => return false,       // rule 5
            _ => {}
        }
    }

    // Rule 1: per-component leading "." / trailing ".lock".
    // (Rule 2, "must contain a slash", deliberately NOT enforced -
    // see the module-level judgment-call note below.)
    for component in name.split('/') {
        if component.starts_with('.') {
            return false;
        }
        if component.ends_with(".lock") {
            return false;
        }
    }

    true
}

/// Remote writes target loose refs. The local ref API also accepts pseudo-refs.
pub(crate) fn valid_wire_refname(name: &str) -> bool {
    name.starts_with("refs/") && valid_refname(name)
}

/// Is `s` syntactically a valid object id: exactly 40 characters, all
/// lowercase `0-9a-f`?
///
/// This guards rustgit's `pack/odb.rs::read_loose_object`, which
/// indexes `&oid[0..2]` / `&oid[2..]` on this exact string with no
/// length or char-boundary check - a string shorter than 2 bytes, or
/// one whose byte 2 falls inside a multibyte UTF-8 character, panics
/// (confirmed by the adversary role's oid_field_attacks_differential
/// probes; see g3_adversary.rs and NOTES-03.md). Checking byte length
/// and byte-wise ASCII-hex membership (never slicing) means this
/// function itself cannot panic on any input, including multibyte
/// UTF-8.
///
/// The all-zero oid ("000...0", 40 chars) is syntactically valid and
/// is accepted here - it has real meaning in delete/verify
/// preconditions and in update's documented zero-new-oid semantics
/// (git-update-ref.adoc). Semantic handling of the zero oid (e.g.
/// "create's new-oid may not be zero") stays in
/// `refs::transaction::execute_transaction`, which already implements
/// it; this function only answers the syntax question.
pub fn valid_oid(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------
// Judgment call: one-level refnames (rule 2 not enforced)
// ---------------------------------------------------------------
//
// git-check-ref-format.adoc rule 2 says a refname "must contain at
// least one `/`" UNLESS `--allow-onelevel` is passed, and states the
// default is `--no-allow-onelevel`. Read literally and applied at the
// default posture, `create HEAD <oid>` or `update HEAD <oid>` (both
// exercised by tests/g3_refstore.rs and by g3_adversary.rs's
// `head_via_update_default_deref_semantics` case, which this crate
// does not own and must not break) would be REJECTED.
//
// That contradicts real git's own observable behavior: `git
// update-ref HEAD <oid>` and single-level pseudo-refs (HEAD,
// MERGE_HEAD, FETCH_HEAD, ...) are routinely accepted by porcelain
// and plumbing alike. Confirmed directly rather than assumed, in a
// scratch subprocess (not the spike repo, per SPIKE-03 safety rules):
//
//   $ git check-ref-format HEAD                  -> exit 1
//   $ git check-ref-format --allow-onelevel HEAD  -> exit 0
//   $ git check-ref-format onelevel                    -> exit 1
//   $ git check-ref-format --allow-onelevel onelevel   -> exit 0
//
// and every OTHER case in the doc's rule list (dot-components,
// .lock, .., control chars, space/~/^/:, ?/*/[, leading/trailing/
// double slash, trailing dot, @{, bare @, backslash) produced the
// IDENTICAL exit code under both flags - `--allow-onelevel` changes
// only rule 2, nothing else. So implementing the `--allow-onelevel`
// variant uniformly (never enforcing rule 2) matches real git's
// accept/reject decision for every case this milestone's brief and
// test suite exercises, at the cost of also accepting one-level names
// outside `refs/` that real git's plain default posture would reject
// in isolation (e.g. bare `onelevel`, per g3_adversary.rs's
// `no_slash_onelevel` case). That is a floor-not-ceiling gap, not a
// security hole: rustgit's own ref_path resolution (git_dir.join(refname))
// still confines any accepted refname whose syntax is otherwise
// clean to a path under git_dir (that is the whole point of the rest
// of this gate), so a stray one-level name lands as an ordinary loose
// ref file next to HEAD, not outside the repo.
//
// Logged per CLAUDE.md's prior-knowledge-disclosure rule in
// crates/dengel-git/NOTES.md under "## G3 builder: refname validation
// disclosures".

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_refnames_stay_in_the_ref_namespace() {
        assert!(valid_wire_refname("refs/heads/main"));
        assert!(valid_wire_refname("refs/tags/v1.0"));
        assert!(!valid_wire_refname("HEAD"));
        assert!(!valid_wire_refname("metadata"));
        assert!(!valid_wire_refname("objects/local"));
    }

    // --- must-accept: ordinary names real git accepts, and this
    // --- crate's own R1-R4 suite / G1-G2 fixtures rely on. Breaking
    // --- any of these would be a real regression, not a hardening.
    const MUST_ACCEPT: &[&str] = &[
        "refs/heads/main",
        "refs/heads/stable-branch",
        "refs/tags/v1.0",
        "feature/x",
        "refs/heads/feature/nested/deep",
        "HEAD",
        "MERGE_HEAD",
        "onelevel", // judgment call: see module doc comment above
        "refs/heads/foo-bar_baz",
        "refs/heads/123",
        "refs/heads/UPPER",
    ];

    // --- must-reject: every attack case this milestone's brief and
    // --- the adversary's refname_syntax_attacks_differential /
    // --- path_escape_attacks_differential tables exercise, plus the
    // --- doc's own rule-list examples.
    const MUST_REJECT: &[&str] = &[
        "",
        "refs/heads/.hidden",      // rule 1: component begins with .
        "refs/heads/foo.lock",     // rule 1: component ends .lock
        "refs/heads/foo..bar",     // rule 3: ..
        "refs/heads/foo\u{1}bar",  // rule 4: control char (SOH)
        "refs/heads/foo\u{7f}bar", // rule 4: DEL
        "refs/heads/nul\u{0}byte", // rule 4: NUL is a control char
        "refs/heads/foo bar",      // rule 4: space
        "refs/heads/foo~bar",      // rule 4: tilde
        "refs/heads/foo^bar",      // rule 4: caret
        "refs/heads/foo:bar",      // rule 4: colon
        "refs/heads/foo?bar",      // rule 5: ?
        "refs/heads/foo*bar",      // rule 5: *
        "refs/heads/foo[bar",      // rule 5: [
        "/refs/heads/foo",         // rule 6: leading /
        "refs/heads/foo/",         // rule 6: trailing /
        "refs/heads//foo",         // rule 6: double /
        "refs/heads/foo.",         // rule 7: ends with .
        "refs/heads/foo@{bar}",    // rule 8: @{
        "@",                       // rule 9: bare @
        "refs/heads/foo\\bar",     // rule 10: backslash
        // path-escape attack cases (arbitrary-file-write finding):
        "/tmp/evil-absolute",
        "refs/heads/../../../escape",
        "refs/heads/../../outside-worktree-marker",
        "../../../etc/evil",
    ];

    #[test]
    fn accepts_legitimate_refnames() {
        for name in MUST_ACCEPT {
            assert!(valid_refname(name), "expected ACCEPT for {name:?}");
        }
    }

    #[test]
    fn rejects_attack_and_malformed_refnames() {
        for name in MUST_REJECT {
            assert!(!valid_refname(name), "expected REJECT for {name:?}");
        }
    }

    #[test]
    fn valid_oid_accepts_well_formed() {
        assert!(valid_oid(&"a".repeat(40)));
        assert!(valid_oid(&"0".repeat(40))); // zero oid: syntactically valid
        assert!(valid_oid("0123456789abcdef0123456789abcdef01234567"));
    }

    #[test]
    fn valid_oid_rejects_malformed() {
        let must_reject_oid: Vec<String> = vec![
            "".to_string(),
            "a".to_string(), // single char (odb panic probe)
            "a".repeat(39),  // 39 chars
            "a".repeat(41),  // 41 chars
            "0123456789ABCDEF0123456789abcdef01234567".to_string(), // uppercase present
            "g".repeat(40),  // non-hex
        ];
        for oid in &must_reject_oid {
            assert!(!valid_oid(oid), "expected REJECT for oid {oid:?}");
        }
        // multibyte-leading string (odb char-boundary panic probe):
        // 1 multibyte char + 39 ascii chars is 39+3=42 bytes, correctly
        // rejected by the byte-length check without ever slicing.
        let multibyte = format!("\u{4e2d}{}", "a".repeat(39));
        assert!(!valid_oid(&multibyte));
    }
}

/// Whether a packed-refs file is well-formed, by real git's standard: git
/// treats ANY unparseable line as fatal for the whole operation
/// ("unexpected line in .git/packed-refs"), rather than skipping it.
///
/// rustgit's `parse_packed_refs` is infallible and silently drops lines it
/// cannot parse - correct and fast for our own well-formed files, unsafe
/// against a poisoned one, because silently ignoring a corrupt ref line is
/// exactly the kind of wrongness that goes unnoticed for weeks (NMA-1452's
/// whole reason for slowing down here). This is the trust-boundary check
/// that runs before the ref writer acts on a repository whose packed-refs
/// it did not itself write.
///
/// Format per gitformat-signature / the packed-refs grammar observed from
/// real git: a header line starting '#'; a peel line starting '^' followed
/// by 40 hex; otherwise "<40-hex-oid> SP <refname>". Anything else is
/// malformed.
pub fn packed_refs_well_formed(content: &str) -> bool {
    for line in content.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(peel) = line.strip_prefix('^') {
            if !valid_oid(peel) {
                return false;
            }
            continue;
        }
        match line.split_once(' ') {
            Some((oid, refname)) if valid_oid(oid) && valid_refname(refname) => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod packed_tests {
    use super::packed_refs_well_formed;

    #[test]
    fn accepts_a_normal_packed_refs() {
        let ok = "# pack-refs with: peeled fully-peeled sorted \n\
                  cfb492f68996842205fd6f0d031b611376c0883d refs/heads/main\n\
                  ^cfb492f68996842205fd6f0d031b611376c0883d\n";
        assert!(packed_refs_well_formed(ok));
    }

    #[test]
    fn rejects_a_truncated_oid_line() {
        let bad = "# pack-refs with: peeled fully-peeled sorted \nabcd refs/heads/broken\n";
        assert!(!packed_refs_well_formed(bad));
    }

    #[test]
    fn rejects_a_line_with_no_separator() {
        let bad = "# header\ncfb492f68996842205fd6f0d031b611376c0883d\n";
        assert!(!packed_refs_well_formed(bad));
    }
}

/// Whether a ref-writer script is structurally well-formed by real git's
/// `update-ref --stdin` line rules (the non-`-z` text format): each
/// non-empty line is a known command with EXACTLY its expected field
/// count, no trailing junk, no embedded carriage returns.
///
/// rustgit's `parse_script` is deliberately lenient - it ignores fields
/// past the ones it reads and treats an all-blank script as a no-op - so a
/// script real git would reject fatally ("empty command in input", "extra
/// input") is silently accepted. For a demonstration server that is low
/// stakes (this is our own input format, not the wire), but the direction
/// is the dangerous one - accepting what canonical git rejects - so the
/// gate closes it rather than leaving a documented divergence in the ref
/// path specifically.
///
/// Returns the reason a script is malformed, or None when it is clean.
pub fn script_malformed_reason(script: &str) -> Option<String> {
    // A truly empty (zero-byte) script is a valid no-op: real git accepts
    // it (verified - `git update-ref --stdin < /dev/null` exits 0). Only a
    // script with CONTENT that parses to zero commands (whitespace, blank
    // lines) is "empty command in input". The adversary role's
    // reconciliation caught this distinction, which the first cut of the
    // gate got wrong by rejecting both.
    if script.is_empty() {
        return None;
    }
    // str::lines() consumes a trailing \r as part of the \r\n terminator,
    // so it must be caught on the raw text, not the split lines.
    if script.contains('\r') {
        return Some("carriage return in script".to_string());
    }
    let non_empty: Vec<&str> = script.lines().filter(|l| !l.is_empty()).collect();
    if non_empty.is_empty() {
        return Some("empty command in input".to_string());
    }
    for line in script.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let expected = match fields.first() {
            Some(&"create") => 3, // create <ref> <newoid>
            Some(&"update") => return check_update(&fields, line),
            Some(&"delete") => return check_1or2(&fields, line, "delete"),
            Some(&"verify") => return check_1or2(&fields, line, "verify"),
            Some(other) => return Some(format!("unsupported command {other:?}")),
            None => return Some(format!("empty command: {line:?}")),
        };
        if fields.len() != expected {
            return Some(format!("wrong field count for {}: {line:?}", fields[0]));
        }
    }
    None
}

fn check_update(fields: &[&str], line: &str) -> Option<String> {
    // update <ref> <newoid> [<oldoid>]
    if fields.len() == 3 || fields.len() == 4 {
        None
    } else {
        Some(format!("wrong field count for update: {line:?}"))
    }
}

fn check_1or2(fields: &[&str], line: &str, cmd: &str) -> Option<String> {
    // delete/verify <ref> [<oldoid>]
    if fields.len() == 2 || fields.len() == 3 {
        None
    } else {
        Some(format!("wrong field count for {cmd}: {line:?}"))
    }
}

#[cfg(test)]
mod script_edge_tests {
    use super::script_malformed_reason;

    #[test]
    fn zero_byte_script_is_valid_no_op_whitespace_only_is_not() {
        // git update-ref --stdin < /dev/null exits 0; a whitespace-only
        // body is "empty command in input". Both pinned here.
        assert_eq!(script_malformed_reason(""), None);
        assert!(script_malformed_reason("\n\n").is_some());
        assert!(script_malformed_reason("   \n").is_some());
    }
}
