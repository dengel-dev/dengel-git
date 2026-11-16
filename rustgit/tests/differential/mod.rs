// Differential test harness: shells out to a real `git` binary as the
// oracle and parses its output into structured facts the codec under
// test can be checked against. Every milestone's correctness claim is
// judged by this harness, per CLAUDE.md.
//
// Source of truth for `git verify-pack -v` output format:
// git-reference/Documentation/git-verify-pack.adoc (Documentation, not
// C source - permitted under the clean-room rule).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleObject {
    pub oid: String,
    pub kind: String,
    pub size: u64,
    pub size_in_pack: u64,
    pub offset: u64,
    pub depth: Option<u32>,
    pub base_oid: Option<String>,
}

impl OracleObject {
    #[allow(dead_code)] // used starting M2 (delta resolution)
    pub fn is_delta(&self) -> bool {
        self.depth.is_some()
    }
}

#[derive(Debug)]
pub struct VerifyPackResult {
    pub objects: Vec<OracleObject>,
    pub ok: bool,
}

/// Run `git verify-pack -v <idx>` and parse its output.
///
/// Format per git-verify-pack.adoc:
///   non-delta: object-name type size size-in-packfile offset-in-packfile
///   delta:     object-name type size size-in-packfile offset-in-packfile depth base-object-name
pub fn verify_pack(idx_path: &Path) -> VerifyPackResult {
    let output = Command::new("git")
        .arg("verify-pack")
        .arg("-v")
        .arg(idx_path)
        .output()
        .expect("failed to run git verify-pack - is git on PATH?");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut objects = Vec::new();

    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Summary/trailer lines ("non delta: N objects", "chain length = N: ...",
        // "<path>: ok") don't parse as object records; skip them by field count
        // and by requiring the first field to look like a hex object id.
        if fields.len() != 5 && fields.len() != 7 {
            continue;
        }
        if !fields[0].chars().all(|c| c.is_ascii_hexdigit()) || fields[0].len() < 40 {
            continue;
        }

        let oid = fields[0].to_string();
        let kind = fields[1].to_string();
        let size: u64 = fields[2].parse().expect("size field not a number");
        let size_in_pack: u64 = fields[3].parse().expect("size-in-pack field not a number");
        let offset: u64 = fields[4].parse().expect("offset field not a number");

        let (depth, base_oid) = if fields.len() == 7 {
            let depth: u32 = fields[5].parse().expect("depth field not a number");
            (Some(depth), Some(fields[6].to_string()))
        } else {
            (None, None)
        };

        objects.push(OracleObject {
            oid,
            kind,
            size,
            size_in_pack,
            offset,
            depth,
            base_oid,
        });
    }

    let ok = String::from_utf8_lossy(&output.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&output.stderr).lines())
        .any(|l| l.trim_end().ends_with(": ok"));

    VerifyPackResult { objects, ok }
}

/// Run `git cat-file -p <oid>` inside `repo_dir` and return raw content bytes.
pub fn cat_file_content(repo_dir: &Path, oid: &str) -> Vec<u8> {
    let output = Command::new("git")
        .current_dir(repo_dir)
        .arg("cat-file")
        .arg("-p")
        .arg(oid)
        .output()
        .expect("failed to run git cat-file -p");
    assert!(
        output.status.success(),
        "git cat-file -p {} failed: {}",
        oid,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Run `git cat-file -t <oid>` inside `repo_dir` and return the type string.
pub fn cat_file_type(repo_dir: &Path, oid: &str) -> String {
    let output = Command::new("git")
        .current_dir(repo_dir)
        .arg("cat-file")
        .arg("-t")
        .arg(oid)
        .output()
        .expect("failed to run git cat-file -t");
    assert!(
        output.status.success(),
        "git cat-file -t {} failed: {}",
        oid,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Run `git cat-file --batch` once, feeding every oid in `oids` on
/// stdin and streaming raw content back for all of them, instead of
/// spawning one `git cat-file` process per object. On a 7000+ object
/// corpus, one-process-per-object took ~160s; batched, the same
/// fixture resolves in low single-digit seconds - a harness that gets
/// run hundreds of times during delta work needs to stay fast enough
/// to actually get run.
///
/// Output format per git-cat-file.adoc BATCH OUTPUT section (default
/// format, no --batch=<format> given):
///   <oid> SP <type> SP <size> LF
///   <contents> LF
/// (content is exactly <size> bytes; the trailing LF is a separator,
/// not part of the object. This is raw content - the same semantics
/// as the positional `git cat-file <type> <oid>` form, NOT `-p`, which
/// pretty-prints and reformats tree entries; see the M1 finding in
/// NOTES.md - just batched into one process instead of one per object.)
pub fn cat_file_batch_content(repo_dir: &Path, oids: &[String]) -> HashMap<String, Vec<u8>> {
    let mut child = Command::new("git")
        .current_dir(repo_dir)
        .arg("cat-file")
        .arg("--batch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn git cat-file --batch");

    let mut stdin = child.stdin.take().expect("child stdin not piped");
    let oids_owned: Vec<String> = oids.to_vec();
    let writer = std::thread::spawn(move || {
        for oid in &oids_owned {
            writeln!(stdin, "{}", oid).expect("failed writing oid to git cat-file --batch stdin");
        }
        // stdin dropped here (EOF) once the closure returns.
    });

    let mut stdout = child.stdout.take().expect("child stdout not piped");
    let mut buf = Vec::new();
    stdout
        .read_to_end(&mut buf)
        .expect("failed reading git cat-file --batch stdout");

    writer.join().expect("stdin writer thread panicked");
    let status = child
        .wait()
        .expect("failed waiting on git cat-file --batch");
    assert!(status.success(), "git cat-file --batch exited non-zero");

    let mut result = HashMap::with_capacity(oids.len());
    let mut pos = 0usize;
    while pos < buf.len() {
        let nl = buf[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .expect("truncated batch header line")
            + pos;
        let header = std::str::from_utf8(&buf[pos..nl]).expect("non-utf8 batch header line");
        pos = nl + 1;

        let parts: Vec<&str> = header.split(' ').collect();
        assert!(
            !(parts.len() == 2 && parts[1] == "missing"),
            "oid {} reported missing by git cat-file --batch",
            parts[0]
        );
        assert_eq!(parts.len(), 3, "unexpected batch header line: {:?}", header);
        let oid = parts[0].to_string();
        let size: usize = parts[2].parse().expect("batch size field not a number");

        let content = buf[pos..pos + size].to_vec();
        pos += size;
        assert_eq!(buf[pos], b'\n', "expected LF separator after batch content");
        pos += 1;

        result.insert(oid, content);
    }

    result
}

/// Chain-depth histogram (depth -> object count) plus max depth and
/// delta fraction, derived from a `VerifyPackResult`. Used both to log
/// what a fixture actually exercises and to assert M2 fixtures are
/// adversarial rather than accidentally delta-free.
#[derive(Debug)]
pub struct DeltaStats {
    pub total_objects: usize,
    pub delta_objects: usize,
    pub max_depth: u32,
    pub depth_histogram: Vec<(u32, usize)>, // sorted by depth ascending
    pub ofs_delta_count: usize,
    pub ref_delta_count: usize,
}

impl DeltaStats {
    pub fn delta_fraction(&self) -> f64 {
        if self.total_objects == 0 {
            0.0
        } else {
            self.delta_objects as f64 / self.total_objects as f64
        }
    }

    pub fn log_summary(&self, label: &str) {
        eprintln!(
            "[fixture: {}] {} objects, {} deltified ({:.1}%), max depth {}, ofs-delta {}, ref-delta {}",
            label,
            self.total_objects,
            self.delta_objects,
            self.delta_fraction() * 100.0,
            self.max_depth,
            self.ofs_delta_count,
            self.ref_delta_count,
        );
        eprintln!("  depth histogram: {:?}", self.depth_histogram);
    }
}

/// verify-pack's `-v` output does not label delta flavour: both
/// OBJ_OFS_DELTA and OBJ_REF_DELTA print the same
/// "depth base-object-name" trailer (git resolves an ofs-delta's
/// offset back to an oid for display), so ofs_delta_count/
/// ref_delta_count here are left at zero and filled in separately by
/// the caller from the codec's own raw entry scan (which does see the
/// wire-format type byte) - see differential.rs's flavour tally.
pub fn compute_delta_stats(objects: &[OracleObject]) -> DeltaStats {
    let total_objects = objects.len();
    let delta_objects = objects.iter().filter(|o| o.is_delta()).count();
    let max_depth = objects.iter().filter_map(|o| o.depth).max().unwrap_or(0);

    let mut counts: HashMap<u32, usize> = HashMap::new();
    for o in objects {
        if let Some(d) = o.depth {
            *counts.entry(d).or_insert(0) += 1;
        }
    }
    let mut depth_histogram: Vec<(u32, usize)> = counts.into_iter().collect();
    depth_histogram.sort_by_key(|(d, _)| *d);

    DeltaStats {
        total_objects,
        delta_objects,
        max_depth,
        depth_histogram,
        ofs_delta_count: 0, // filled in by caller when flavour matters
        ref_delta_count: 0,
    }
}

/// Assert a fixture is a legitimate M2 adversarial target: it must
/// actually contain deltas, with non-trivial chain depth and a
/// meaningful fraction of objects deltified. This exists specifically
/// so a future fixture regenerated without care (e.g. `--window=0`
/// left in a script by accident) fails loudly instead of quietly
/// testing nothing while staying green.
pub fn assert_fixture_is_adversarial(stats: &DeltaStats, label: &str) {
    assert!(
        stats.delta_objects > 0,
        "fixture '{}' has zero delta objects - not a valid M2 fixture \
         (regenerate without --window=0 / --no-reuse-delta)",
        label
    );
    assert!(
        stats.max_depth > 1,
        "fixture '{}' max delta chain depth is {}, expected > 1 - \
         too shallow to exercise real chain resolution",
        label,
        stats.max_depth
    );
    let fraction = stats.delta_fraction();
    assert!(
        fraction >= 0.10,
        "fixture '{}' only {:.1}% of objects are deltified, expected >= 10% - \
         not a meaningful delta workload",
        label,
        fraction * 100.0
    );
}

#[derive(Debug)]
pub struct IndexPackResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run `git index-pack --strict <pack_path>`, standalone (no repo
/// context required - index-pack is plumbing that operates on a raw
/// pack file and writes a sibling .idx). Used to validate M3-written
/// packs: strict mode makes git die on broken objects or links, so
/// success here means git accepts our pack as internally consistent.
pub fn index_pack_strict(pack_path: &Path) -> IndexPackResult {
    let output = Command::new("git")
        .arg("index-pack")
        .arg("--strict")
        .arg(pack_path)
        .output()
        .expect("failed to run git index-pack --strict");
    IndexPackResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Run `git index-pack --stdin --fix-thin` inside `repo_dir`, feeding
/// `thin_pack_bytes` on stdin. Per git-index-pack.adoc, --fix-thin
/// "only makes sense in conjunction with --stdin" - the SPIKE brief's
/// shorthand (`--fix-thin <pack>.pack`, no --stdin) does not match the
/// documented synopsis; this is the corrected invocation (see NOTES.md).
/// `repo_dir` must already contain the thin pack's missing base
/// objects (loose or packed) for --fix-thin to complete it.
///
/// index-pack has no --stdout flag (that section of the docs is about
/// printing the resulting pack's *hash*, not pack bytes); with no
/// explicit <pack-file> the completed pack+idx are written into
/// repo_dir/.git/objects/pack/ under a name git derives from the pack
/// content. Caller is expected to diff that directory's contents
/// before/after to find the new files.
#[allow(dead_code)] // used starting M5 (thin packs)
pub fn index_pack_stdin_fix_thin(repo_dir: &Path, thin_pack_bytes: &[u8]) -> IndexPackResult {
    let mut child = Command::new("git")
        .current_dir(repo_dir)
        .arg("index-pack")
        .arg("--stdin")
        .arg("--fix-thin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn git index-pack --stdin --fix-thin");

    let mut stdin = child.stdin.take().expect("child stdin not piped");
    let bytes = thin_pack_bytes.to_vec();
    let writer = std::thread::spawn(move || {
        stdin
            .write_all(&bytes)
            .expect("failed writing thin pack to git index-pack stdin");
    });

    let output = child
        .wait_with_output()
        .expect("failed waiting on git index-pack --stdin --fix-thin");
    writer.join().expect("stdin writer thread panicked");

    IndexPackResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Run `git pack-objects --stdout` inside `repo_dir`, feeding the
/// given oids (one per line) on stdin, and return the resulting pack
/// bytes. Used as the M4 size-parity oracle: git's own pack, built
/// from the exact same object set, with its own (undocumented)
/// delta-selection heuristics left on.
pub fn git_pack_objects_stdout(repo_dir: &Path, oids: &[String]) -> Vec<u8> {
    let mut child = Command::new("git")
        .current_dir(repo_dir)
        .arg("pack-objects")
        .arg("--stdout")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn git pack-objects --stdout");

    let mut stdin = child.stdin.take().expect("child stdin not piped");
    let oids_owned: Vec<String> = oids.to_vec();
    let writer = std::thread::spawn(move || {
        for oid in &oids_owned {
            writeln!(stdin, "{}", oid).expect("failed writing oid to git pack-objects stdin");
        }
    });

    let output = child
        .wait_with_output()
        .expect("failed waiting on git pack-objects --stdout");
    writer.join().expect("stdin writer thread panicked");
    assert!(
        output.status.success(),
        "git pack-objects --stdout failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Find the single pack (.idx path) in a repo's objects/pack dir.
/// Panics if there isn't exactly one - callers should `git repack -ad`
/// their fixture first so results are deterministic.
pub fn find_single_pack_idx(repo_dir: &Path) -> PathBuf {
    let pack_dir = repo_dir.join(".git/objects/pack");
    let mut idx_files: Vec<PathBuf> = std::fs::read_dir(&pack_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", pack_dir.display(), e))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|ext| ext == "idx").unwrap_or(false))
        .collect();
    idx_files.sort();
    assert_eq!(
        idx_files.len(),
        1,
        "expected exactly one .idx in {}, found {:?}",
        pack_dir.display(),
        idx_files
    );
    idx_files.remove(0)
}
