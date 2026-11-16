//! ls-refs command: request a filtered ref advertisement.
//!
//! Format source: git-reference/Documentation/gitprotocol-v2.adoc,
//! "ls-refs" section (request args: symrefs, peel, ref-prefix; output
//! grammar: `PKT-LINE(obj-id-or-unborn SP refname *(SP ref-attribute) LF)`)
//! and "Command Request" section for the request envelope
//! (command line, capability-list, delim-pkt, command-args, flush-pkt).

use super::pktline::PktLine;
use super::transport::UploadPackClient;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsRefsEntry {
    pub oid: String, // "unborn" is possible per spec but not requested unless we send `unborn` (P1 doesn't)
    pub refname: String,
    pub symref_target: Option<String>,
    pub peeled: Option<String>,
}

#[derive(Debug, Default)]
pub struct LsRefsRequest {
    pub symrefs: bool,
    pub peel: bool,
    pub ref_prefixes: Vec<String>,
}

pub fn ls_refs(
    client: &mut UploadPackClient,
    req: &LsRefsRequest,
) -> std::io::Result<Vec<LsRefsEntry>> {
    client.write_data_line(b"command=ls-refs\n")?;
    client.write_delim()?; // end of capability-list (we send none)
    if req.symrefs {
        client.write_data_line(b"symrefs\n")?;
    }
    if req.peel {
        client.write_data_line(b"peel\n")?;
    }
    for prefix in &req.ref_prefixes {
        client.write_data_line(format!("ref-prefix {}\n", prefix).as_bytes())?;
    }
    client.write_flush()?;
    client.flush_stdin()?;

    let lines = client.read_until_flush()?;
    let mut entries = Vec::new();
    for line in lines {
        match line {
            PktLine::Data(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let text = text.trim_end_matches('\n');
                entries.push(parse_ls_refs_line(text));
            }
            PktLine::Flush => break,
            other => panic!("unexpected pkt-line in ls-refs response: {:?}", other),
        }
    }
    Ok(entries)
}

fn parse_ls_refs_line(line: &str) -> LsRefsEntry {
    let mut parts = line.split(' ');
    let oid = parts.next().expect("ls-refs line missing oid").to_string();
    let refname = parts
        .next()
        .expect("ls-refs line missing refname")
        .to_string();

    let mut symref_target = None;
    let mut peeled = None;
    for attr in parts {
        if let Some(target) = attr.strip_prefix("symref-target:") {
            symref_target = Some(target.to_string());
        } else if let Some(oid) = attr.strip_prefix("peeled:") {
            peeled = Some(oid.to_string());
        }
    }

    LsRefsEntry {
        oid,
        refname,
        symref_target,
        peeled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_ref() {
        let e = parse_ls_refs_line("aabbccddeeff00112233445566778899aabbccd refs/heads/main");
        assert_eq!(e.oid, "aabbccddeeff00112233445566778899aabbccd");
        assert_eq!(e.refname, "refs/heads/main");
        assert_eq!(e.symref_target, None);
        assert_eq!(e.peeled, None);
    }

    #[test]
    fn parses_symref_attribute() {
        let e = parse_ls_refs_line(
            "aabbccddeeff00112233445566778899aabbccd HEAD symref-target:refs/heads/main",
        );
        assert_eq!(e.refname, "HEAD");
        assert_eq!(e.symref_target.as_deref(), Some("refs/heads/main"));
    }

    #[test]
    fn parses_peeled_attribute() {
        let e = parse_ls_refs_line(
            "aabbccddeeff00112233445566778899aabbccd refs/tags/v1 peeled:1111111111111111111111111111111111111111",
        );
        assert_eq!(
            e.peeled.as_deref(),
            Some("1111111111111111111111111111111111111111")
        );
    }
}
