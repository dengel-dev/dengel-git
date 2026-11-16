//! Parser for the `git update-ref --stdin` text command format (the
//! non -z, whitespace-separated form) - used so the test harness can
//! feed the IDENTICAL command text to both real git and rustgit,
//! rather than constructing two different representations that could
//! silently drift apart.
//!
//! Format source: git-reference/Documentation/git-update-ref.adoc:
//!   update SP <ref> SP <new-oid> [SP <old-oid>] LF
//!   create SP <ref> SP <new-oid> LF
//!   delete SP <ref> [SP <old-oid>] LF
//!   verify SP <ref> [SP <old-oid>] LF
//! R1 scope: only these four command types (symref-*, option, start/
//! prepare/commit/abort are out of scope - see SPIKE-03.md's "as far
//! as a milestone requires" allowance).

use super::transaction::RefOp;

#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Parse a full --stdin script (one command per line, blank lines
/// ignored) into a Vec<RefOp>.
pub fn parse_script(script: &str) -> Result<Vec<RefOp>, ParseError> {
    script
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(parse_line)
        .collect()
}

fn parse_line(line: &str) -> Result<RefOp, ParseError> {
    let mut parts = line.split(' ');
    let cmd = parts
        .next()
        .ok_or_else(|| ParseError(format!("empty line: {:?}", line)))?;
    let rest: Vec<&str> = parts.collect();

    match cmd {
        "update" => {
            let refname = *rest
                .first()
                .ok_or_else(|| ParseError(format!("update missing ref: {:?}", line)))?;
            let new = *rest
                .get(1)
                .ok_or_else(|| ParseError(format!("update missing new-oid: {:?}", line)))?;
            let old = rest.get(2).map(|s| s.to_string());
            Ok(RefOp::Update {
                refname: refname.to_string(),
                new: new.to_string(),
                old,
            })
        }
        "create" => {
            let refname = *rest
                .first()
                .ok_or_else(|| ParseError(format!("create missing ref: {:?}", line)))?;
            let new = *rest
                .get(1)
                .ok_or_else(|| ParseError(format!("create missing new-oid: {:?}", line)))?;
            Ok(RefOp::Create {
                refname: refname.to_string(),
                new: new.to_string(),
            })
        }
        "delete" => {
            let refname = *rest
                .first()
                .ok_or_else(|| ParseError(format!("delete missing ref: {:?}", line)))?;
            let old = rest.get(1).map(|s| s.to_string());
            Ok(RefOp::Delete {
                refname: refname.to_string(),
                old,
            })
        }
        "verify" => {
            let refname = *rest
                .first()
                .ok_or_else(|| ParseError(format!("verify missing ref: {:?}", line)))?;
            let old = rest.get(1).map(|s| s.to_string());
            Ok(RefOp::Verify {
                refname: refname.to_string(),
                old,
            })
        }
        other => Err(ParseError(format!(
            "unsupported command {:?} (R1 scope: update/create/delete/verify only)",
            other
        ))),
    }
}

/// Render ops back to --stdin script text, for feeding to real git as
/// the oracle (same script text both sides consume).
pub fn format_script(ops: &[RefOp]) -> String {
    let mut out = String::new();
    for op in ops {
        match op {
            RefOp::Update { refname, new, old } => {
                out.push_str(&format!("update {} {}", refname, new));
                if let Some(old) = old {
                    out.push_str(&format!(" {}", old));
                }
                out.push('\n');
            }
            RefOp::Create { refname, new } => {
                out.push_str(&format!("create {} {}\n", refname, new));
            }
            RefOp::Delete { refname, old } => {
                out.push_str(&format!("delete {}", refname));
                if let Some(old) = old {
                    out.push_str(&format!(" {}", old));
                }
                out.push('\n');
            }
            RefOp::Verify { refname, old } => {
                out.push_str(&format!("verify {}", refname));
                if let Some(old) = old {
                    out.push_str(&format!(" {}", old));
                }
                out.push('\n');
            }
        }
    }
    out
}
