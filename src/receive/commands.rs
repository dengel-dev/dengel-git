//! Parsing the receive-pack command list: "<old> <new> <ref>" lines the
//! client sends before the pack, plus the client's capability line.
//!
//! Format source: git-reference/Documentation/gitprotocol-pack.adoc,
//! "Reference Update Request and Packfile Transfer":
//!   command-list = PKT-LINE(command NUL capability-list)
//!                 *PKT-LINE(command)
//!                 flush-pkt
//!   command      = create / delete / update
//!   create       = zero-id SP new-id  SP name
//!   delete       = old-id  SP zero-id SP name
//!   update       = old-id  SP new-id  SP name
//! and "pkt-line Format": "unless otherwise noted the usual pkt-line LF
//! rules apply: the sender SHOULD include a LF, but the receiver MUST
//! NOT complain if it is not present" - so a trailing LF is stripped if
//! present, never required.
//!
//! Every oid and refname on this list is attacker-controlled input, so
//! each is run through the SAME validation gate (`refvalidate`) that
//! guards every other entry point into rustgit's ref store (G3's rule,
//! restated at MAXIMUM weight here since this is the actual network
//! trust boundary G3 only modeled).

use super::ReceiveError;
use crate::refvalidate::{valid_oid, valid_wire_refname};

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub refname: String,
}

impl RefUpdate {
    pub fn is_delete(&self) -> bool {
        self.new.chars().all(|c| c == '0')
    }
    pub fn is_create(&self) -> bool {
        self.old.chars().all(|c| c == '0')
    }
}

fn malformed(detail: impl Into<String>) -> ReceiveError {
    ReceiveError::Malformed {
        what: "receive-pack command line",
        detail: detail.into(),
    }
}

/// Strips a single trailing LF, per the pkt-line-LF rule quoted above -
/// never requires one.
fn strip_trailing_lf(line: &[u8]) -> &[u8] {
    match line.last() {
        Some(b'\n') => &line[..line.len() - 1],
        _ => line,
    }
}

/// Parse the pkt-line command section (already de-framed into payload
/// lines, one `Vec<u8>` per pkt-line, flush-pkt NOT included). The first
/// command line may carry a NUL-separated capability list; return the
/// updates and the raw capability string. Rejects the WHOLE push (no
/// partial acceptance) on the first malformed line, oid, or refname -
/// callers must never let a partially-validated command list reach the
/// ref store.
pub fn parse(lines: &[Vec<u8>]) -> Result<(Vec<RefUpdate>, String), ReceiveError> {
    if lines.is_empty() {
        return Ok((Vec::new(), String::new()));
    }

    let mut updates = Vec::with_capacity(lines.len());
    let mut capabilities = String::new();

    for (i, raw) in lines.iter().enumerate() {
        let mut line: &[u8] = raw;

        if i == 0 {
            if let Some(nul_pos) = line.iter().position(|&b| b == 0) {
                let cap_bytes = strip_trailing_lf(&line[nul_pos + 1..]);
                capabilities = String::from_utf8_lossy(cap_bytes).into_owned();
                line = &line[..nul_pos];
            }
        }

        let line = strip_trailing_lf(line);
        let text = std::str::from_utf8(line).map_err(|_| {
            malformed(format!(
                "command line is not utf8: {:?}",
                String::from_utf8_lossy(line)
            ))
        })?;

        // "<old-id> SP <new-id> SP <name>" - splitn(3, ' ') so a
        // refname containing spaces (rejected below by valid_wire_refname
        // anyway) doesn't get truncated at its first internal space.
        let mut parts = text.splitn(3, ' ');
        let old = parts.next().unwrap_or("");
        let new = parts
            .next()
            .ok_or_else(|| malformed(format!("missing new-id field: {:?}", text)))?;
        let refname = parts
            .next()
            .ok_or_else(|| malformed(format!("missing refname field: {:?}", text)))?;

        if !valid_oid(old) {
            return Err(malformed(format!(
                "old-id is not a well-formed oid: {:?}",
                old
            )));
        }
        if !valid_oid(new) {
            return Err(malformed(format!(
                "new-id is not a well-formed oid: {:?}",
                new
            )));
        }
        if !valid_wire_refname(refname) {
            return Err(malformed(format!(
                "refname is not well-formed: {:?}",
                refname
            )));
        }

        updates.push(RefUpdate {
            old: old.to_string(),
            new: new.to_string(),
            refname: refname.to_string(),
        });
    }

    Ok((updates, capabilities))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: &str = "0000000000000000000000000000000000000000";
    const OLD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEW: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn line(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn empty_command_list_is_empty() {
        let (updates, caps) = parse(&[]).unwrap();
        assert!(updates.is_empty());
        assert_eq!(caps, "");
    }

    #[test]
    fn parses_a_create_with_capabilities_on_the_first_line() {
        let first = format!("{ZERO} {NEW} refs/heads/main\0report-status delete-refs ofs-delta\n");
        let (updates, caps) = parse(&[first.into_bytes()]).unwrap();
        assert_eq!(
            updates,
            vec![RefUpdate {
                old: ZERO.to_string(),
                new: NEW.to_string(),
                refname: "refs/heads/main".to_string()
            }]
        );
        assert!(updates[0].is_create());
        assert!(!updates[0].is_delete());
        assert_eq!(caps, "report-status delete-refs ofs-delta");
    }

    #[test]
    fn parses_an_update_and_a_delete_with_no_lf_on_the_last_line() {
        let first = line(&format!("{OLD} {NEW} refs/heads/main\0\n"));
        let second = format!("{OLD} {ZERO} refs/heads/gone").into_bytes(); // no trailing LF - MUST NOT be rejected
        let (updates, _caps) = parse(&[first, second]).unwrap();
        assert_eq!(updates.len(), 2);
        assert!(!updates[0].is_create() && !updates[0].is_delete());
        assert!(updates[1].is_delete());
    }

    #[test]
    fn rejects_a_malformed_old_oid() {
        let l = format!("not-an-oid {NEW} refs/heads/main\0\n").into_bytes();
        assert!(matches!(parse(&[l]), Err(ReceiveError::Malformed { .. })));
    }

    #[test]
    fn rejects_a_malformed_new_oid() {
        let l = format!("{OLD} short refs/heads/main\0\n").into_bytes();
        assert!(matches!(parse(&[l]), Err(ReceiveError::Malformed { .. })));
    }

    #[test]
    fn rejects_an_invalid_wire_refname() {
        let l = format!("{OLD} {NEW} refs/heads/../escape\0\n").into_bytes();
        assert!(matches!(parse(&[l]), Err(ReceiveError::Malformed { .. })));
    }

    #[test]
    fn rejects_the_whole_push_when_a_later_line_is_malformed() {
        let good = format!("{OLD} {NEW} refs/heads/main\0\n").into_bytes();
        let bad = format!("{OLD} {NEW} refs/heads/foo.lock\n").into_bytes(); // rule 1: ends .lock
        assert!(matches!(
            parse(&[good, bad]),
            Err(ReceiveError::Malformed { .. })
        ));
    }

    #[test]
    fn is_create_and_is_delete_are_mutually_informative_not_exclusive() {
        // A line with both old and new all-zero is syntactically valid
        // here (oid-syntax and refname-syntax are all this parser
        // checks) - semantic rejection of that nonsensical combination
        // is the ref-store transaction's job (see session.rs / NOTES.md).
        let l = format!("{ZERO} {ZERO} refs/heads/weird\0\n").into_bytes();
        let (updates, _) = parse(&[l]).unwrap();
        assert!(updates[0].is_create());
        assert!(updates[0].is_delete());
    }

    #[test]
    fn missing_refname_field_is_malformed() {
        let l = format!("{OLD} {NEW}\0\n").into_bytes();
        assert!(matches!(parse(&[l]), Err(ReceiveError::Malformed { .. })));
    }
}
