//! Capability advertisement, v2. Spike 02 has the parser; this is the
//! writer that never existed.
//!
//! Format source: git-reference/Documentation/gitprotocol-v2.adoc,
//! "Capability Advertisement" (`protocol-version capability-list
//! flush-pkt`, each capability a pkt-line `key[=value]`), "agent"
//! (server may advertise `agent=X`), "object-format" (server may
//! advertise `object-format=X`, SHA-1 assumed if absent - advertised
//! explicitly here anyway, to be unambiguous), and "ls-refs"/"fetch"
//! ("Additional features not supported in the base command will be
//! advertised as the value of the command... in the form of a space
//! separated list of features" - the converse of this, which this
//! function relies on, is that a command with NO such extra features
//! implemented is advertised with no value at all).
//!
//! What's advertised is deliberately exactly what's implemented, per
//! this milestone's instruction:
//!   - `ls-refs`, no value: ls_refs.rs implements the base command
//!     (symrefs, peel, ref-prefix are base arguments, not "features" -
//!     see the ls-refs section) but not the `unborn` feature, so no
//!     `=unborn` value is sent.
//!   - `fetch=shallow filter`: fetch.rs implements the base command
//!     (want/have/done/thin-pack/no-progress/include-tag/ofs-delta are
//!     all base arguments) PLUS two features: `shallow` (`deepen
//!     <depth>`, `shallow <oid>` request lines, and the
//!     `shallow`/`unshallow` response section) and `filter` (the
//!     `filter <filter-spec>` request argument, restricted to
//!     `blob:none`/`blob:limit=<n>` - see fetch.rs's and walk.rs's own
//!     doc comments for exactly what each does and does not cover, and
//!     for why the two are rejected in combination rather than
//!     advertised as composable). None of ref-in-want/sideband-all/
//!     packfile-uris/wait-for-done is implemented, so none of those
//!     feature values is ever sent - advertising a feature this server
//!     does not fully support would be worse than not advertising it (a
//!     client would use it and fail in a way it cannot diagnose), so
//!
//!     NOTE on promisor follow-up fetches (`want <oid>` for a non-ref-tip
//!     object, e.g. a client lazily fetching one blob a `blob:none`
//!     clone omitted): this needs no third value here. gitprotocol-
//!     v2.adoc documents arbitrary-oid `want` as BASE fetch-command
//!     behavior ("Wants can be anything and are not limited to
//!     advertised objects"), not as one of the "if X feature is
//!     advertised" list `shallow`/`filter`/etc. belong to - so there is
//!     no capability name to add, and fetch.rs's own doc comment ("##
//!     Promisor follow-up fetch") has the full empirical check for why
//!     that reading holds against real git's actual v2 server behavior,
//!     not just the spec's wording.
//!     the rule here is still exactly "advertise what is actually
//!     implemented, no more."

use rustgit::protocol::pktline;

/// The pkt-line encoded advertisement: version 2, agent, ls-refs, fetch,
/// object-format=sha1. Mandatory-four scope (NMA-1405 stays Slice 3).
pub fn capability_advertisement() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&pktline::encode_data(b"version 2\n"));
    out.extend_from_slice(&pktline::encode_data(b"agent=dengel-git/0.1.0\n"));
    out.extend_from_slice(&pktline::encode_data(b"ls-refs\n"));
    out.extend_from_slice(&pktline::encode_data(b"fetch=shallow filter\n"));
    out.extend_from_slice(&pktline::encode_data(b"object-format=sha1\n"));
    out.extend_from_slice(&pktline::encode_flush());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustgit::protocol::pktline::PktLine;
    use std::io::Cursor;

    fn read_all(bytes: &[u8]) -> Vec<PktLine> {
        let mut cursor = Cursor::new(bytes);
        let mut out = Vec::new();
        while let Some(line) = pktline::read_pkt_line(&mut cursor).unwrap() {
            let is_flush = matches!(line, PktLine::Flush);
            out.push(line);
            if is_flush {
                break;
            }
        }
        out
    }

    #[test]
    fn starts_with_version_2_and_ends_with_flush() {
        let lines = read_all(&capability_advertisement());
        assert_eq!(lines.first(), Some(&PktLine::Data(b"version 2\n".to_vec())));
        assert_eq!(lines.last(), Some(&PktLine::Flush));
    }

    #[test]
    fn advertises_exactly_the_implemented_capabilities_with_no_extra_features() {
        let lines = read_all(&capability_advertisement());
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
        assert!(
            texts.contains(&"ls-refs".to_string()),
            "ls-refs should be advertised with no value: {texts:?}"
        );
        // fetch now advertises exactly the "shallow" and "filter"
        // features (both implemented - see this module's doc comment)
        // and nothing else.
        assert!(
            texts.contains(&"fetch=shallow filter".to_string()),
            "fetch should advertise exactly the shallow and filter features: {texts:?}"
        );
        assert!(texts.contains(&"object-format=sha1".to_string()));
        assert!(texts.iter().any(|t| t.starts_with("agent=dengel-git/")));
        // Nothing advertises an unimplemented feature value.
        assert!(!texts.iter().any(|t| t.starts_with("ls-refs=")));
        assert!(
            !texts.iter().any(|t| t.starts_with("fetch=") && t != "fetch=shallow filter"),
            "fetch must not advertise any feature beyond shallow+filter (ref-in-want/sideband-all/packfile-uris/wait-for-done are all unimplemented): {texts:?}"
        );
    }
}
