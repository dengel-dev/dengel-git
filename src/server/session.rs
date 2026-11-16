//! The stdio conversation: what `dengel-git upload-pack <git-dir>` runs.
//!
//! Grammar source: git-reference/Documentation/gitprotocol-v2.adoc,
//! "Command Request" section:
//!   command-request = command capability-list delim-pkt command-args flush-pkt
//!   command = PKT-LINE("command=" key LF)
//!   empty-request = flush-pkt
//! and "Packet-Line Framing" (delim-pkt separates sections, flush-pkt
//! ends a message). Error reporting uses gitprotocol-pack.adoc's
//! error-line: `PKT-LINE("ERR" SP explanation-text)`. pkt-line codec
//! reused verbatim from rustgit (rustgit::protocol::pktline), per this
//! milestone's instructions - no framing is hand-rolled here.
//!
//! This module also backs the stateless-HTTP flavor (see http.rs):
//! `handle_one_command` reads and dispatches exactly one command-request
//! from a byte slice, with no advertisement writing and no loop - the
//! GET /info/refs handler already sent the advertisement, and each POST
//! is its own self-contained request per protocol v2's stateless-by-
//! default rule.

use super::{advertise, fetch, ls_refs, ServeError};
use rustgit::protocol::pktline::{self, PktLine};
use std::io::{Read, Write};
use std::path::Path;

struct CommandRequest {
    command: String,
    args: Vec<String>,
}

/// Serves one protocol v2 upload-pack session over arbitrary read/write
/// halves: emit the capability advertisement, then handle `ls-refs` and
/// `fetch` commands until the client disconnects.
pub fn serve_upload_pack(
    git_dir: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), ServeError> {
    // `input`/`output` are trait objects; rustgit's pkt-line functions
    // are generic over `R: Read`/`W: Write` (which implicitly requires
    // `Sized`, so `dyn Read` itself cannot fill that type parameter).
    // Shadowing with a `mut` local of the same `&mut dyn ...` type gives
    // something we CAN take `&mut` of again - `&mut dyn Read` itself
    // implements `Read` (the blanket `impl<R: Read + ?Sized> Read for
    // &mut R`), and as a reference-to-a-trait-object it is Sized, so
    // `R = &mut dyn Read` satisfies the generic bound.
    let mut input = input;

    // `Stdout`/`StdoutLock` (the concrete writer `dengel-git upload-pack`
    // hands in) is block-buffered whenever it isn't a terminal - which a
    // subprocess pipe never is. Without an explicit flush after every
    // write, bytes sit in OUR process's buffer instead of reaching the
    // client, and the client blocks forever waiting for a response that
    // was, from our side, already "written" - hand-verified: an
    // unflushed advertisement here hung a real `git clone` against this
    // binary over the ext:: transport before this flush was added (see
    // NOTES.md). Every write below is followed by a flush for the same
    // reason - a command response and an ERR pkt are exactly as
    // vulnerable to this as the advertisement is.
    output.write_all(&advertise::capability_advertisement())?;
    output.flush()?;

    loop {
        match read_command_request(&mut input) {
            Ok(None) => return Ok(()), // EOF, or an empty-request flush-pkt - either way, the client is done
            Ok(Some(request)) => match dispatch(git_dir, &request) {
                Ok(bytes) => {
                    output.write_all(&bytes)?;
                    output.flush()?;
                }
                Err(e) => {
                    write_err(output, &e)?;
                    output.flush()?;
                    return Err(e);
                }
            },
            Err(e) => {
                write_err(output, &e)?;
                output.flush()?;
                return Err(e);
            }
        }
    }
}

/// Handles exactly one command-request read from `body` (a complete,
/// self-contained request - see http.rs), returning the response bytes
/// with no advertisement of its own.
pub(crate) fn handle_one_command(git_dir: &Path, body: &[u8]) -> Result<Vec<u8>, ServeError> {
    let mut cursor = std::io::Cursor::new(body);
    match read_command_request(&mut cursor)? {
        Some(request) => dispatch(git_dir, &request),
        None => Err(ServeError::Malformed {
            what: "command request",
            detail: "empty request (just a flush-pkt) - nothing to do".to_string(),
        }),
    }
}

fn dispatch(git_dir: &Path, request: &CommandRequest) -> Result<Vec<u8>, ServeError> {
    let _read = crate::receive::publication::read_guard(git_dir)?;
    match request.command.as_str() {
        "ls-refs" => ls_refs::respond(git_dir, &request.args),
        "fetch" => fetch::respond(git_dir, &request.args),
        other => Err(ServeError::Malformed {
            what: "command",
            detail: format!("unknown or unadvertised command {:?}", other),
        }),
    }
}

fn write_err(output: &mut dyn Write, e: &ServeError) -> Result<(), ServeError> {
    let payload = format!("ERR {e}\n");
    output.write_all(&pktline::encode_data(payload.as_bytes()))?;
    Ok(())
}

/// Reads one command-request. `Ok(None)` covers both a clean EOF before
/// any bytes of a new request (the pipe closed) and a legitimate
/// empty-request (a lone flush-pkt, per the grammar's `empty-request =
/// flush-pkt` - the client's documented way of saying "no more
/// requests") - callers treat both identically (stop serving).
fn read_command_request<R: Read>(input: &mut R) -> Result<Option<CommandRequest>, ServeError> {
    let command = match pktline::read_pkt_line(input)? {
        None => return Ok(None),
        Some(PktLine::Flush) => return Ok(None),
        Some(PktLine::Data(bytes)) => {
            let text = String::from_utf8(bytes).map_err(|_| ServeError::Malformed {
                what: "command line",
                detail: "not utf8".to_string(),
            })?;
            let text = text.trim_end_matches('\n');
            text.strip_prefix("command=")
                .ok_or_else(|| ServeError::Malformed {
                    what: "command line",
                    detail: format!("expected \"command=<key>\", got {:?}", text),
                })?
                .to_string()
        }
        Some(other) => {
            return Err(ServeError::Malformed {
                what: "command line",
                detail: format!("unexpected pkt-line: {other:?}"),
            })
        }
    };

    // capability-list: zero or more data pkt-lines (we implement no
    // request-side capabilities to react to - agent, server-option -
    // so every one is read and discarded), terminated by delim-pkt.
    loop {
        match pktline::read_pkt_line(input)? {
            Some(PktLine::Data(_)) => continue,
            Some(PktLine::Delim) => break,
            None => {
                return Err(ServeError::Malformed {
                    what: "command request",
                    detail: "EOF before delim-pkt".to_string(),
                })
            }
            Some(other) => {
                return Err(ServeError::Malformed {
                    what: "command request",
                    detail: format!("unexpected pkt-line in capability-list: {other:?}"),
                })
            }
        }
    }

    // command-args: zero or more data pkt-lines, terminated by flush-pkt.
    let mut args = Vec::new();
    loop {
        match pktline::read_pkt_line(input)? {
            Some(PktLine::Data(bytes)) => {
                let text = String::from_utf8(bytes).map_err(|_| ServeError::Malformed {
                    what: "command arg",
                    detail: "not utf8".to_string(),
                })?;
                args.push(text.trim_end_matches('\n').to_string());
            }
            Some(PktLine::Flush) => break,
            None => {
                return Err(ServeError::Malformed {
                    what: "command request",
                    detail: "EOF before flush-pkt".to_string(),
                })
            }
            Some(other) => {
                return Err(ServeError::Malformed {
                    what: "command args",
                    detail: format!("unexpected pkt-line: {other:?}"),
                })
            }
        }
    }

    Ok(Some(CommandRequest { command, args }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{loose, Kind};
    use std::io::Cursor;

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dengel-git-session-test-{}-{}-{}",
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

    fn build_ls_refs_request() -> Vec<u8> {
        let mut req = Vec::new();
        req.extend_from_slice(&pktline::encode_data(b"command=ls-refs\n"));
        req.extend_from_slice(&pktline::encode_delim());
        req.extend_from_slice(&pktline::encode_flush());
        req
    }

    #[test]
    fn advertisement_is_written_before_anything_is_read() {
        let git_dir = scratch_dir("advert");
        let mut input: &[u8] = &[]; // EOF immediately - client hangs up right after reading the advertisement
        let mut output = Vec::new();
        serve_upload_pack(&git_dir, &mut input, &mut output).unwrap();
        assert_eq!(output, advertise::capability_advertisement());
    }

    #[test]
    fn empty_request_after_advertisement_ends_the_session_cleanly() {
        let git_dir = scratch_dir("empty_request");
        let mut input: &[u8] = &pktline::encode_flush();
        let mut output = Vec::new();
        serve_upload_pack(&git_dir, &mut input, &mut output).unwrap();
        assert_eq!(output, advertise::capability_advertisement());
    }

    #[test]
    fn serves_an_ls_refs_command_then_ends_on_eof() {
        let git_dir = scratch_dir("ls_refs_roundtrip");
        let oid = loose::write(&git_dir, Kind::Blob, b"x\n").unwrap();
        let path = rustgit::refs::loose::ref_path(&git_dir, "refs/heads/main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("{oid}\n")).unwrap();

        let req = build_ls_refs_request();
        let mut input = Cursor::new(req);
        let mut output = Vec::new();
        serve_upload_pack(&git_dir, &mut input, &mut output).unwrap();

        let mut expected = advertise::capability_advertisement();
        expected.extend_from_slice(&ls_refs::respond(&git_dir, &[]).unwrap());
        assert_eq!(output, expected);
    }

    #[test]
    fn unknown_command_writes_an_err_pkt_and_returns_err() {
        let git_dir = scratch_dir("unknown_command");
        let mut req = Vec::new();
        req.extend_from_slice(&pktline::encode_data(b"command=bundle-uri\n"));
        req.extend_from_slice(&pktline::encode_delim());
        req.extend_from_slice(&pktline::encode_flush());
        let mut input = Cursor::new(req);
        let mut output = Vec::new();

        let result = serve_upload_pack(&git_dir, &mut input, &mut output);
        assert!(result.is_err());

        let advert_len = advertise::capability_advertisement().len();
        let err_bytes = &output[advert_len..];
        let mut cursor = Cursor::new(err_bytes);
        let line = pktline::read_pkt_line(&mut cursor).unwrap().unwrap();
        match line {
            PktLine::Data(bytes) => assert!(
                bytes.starts_with(b"ERR "),
                "{:?}",
                String::from_utf8_lossy(&bytes)
            ),
            other => panic!("expected an ERR data pkt-line, got {other:?}"),
        }
    }

    #[test]
    fn handle_one_command_answers_a_single_request_with_no_advertisement() {
        let git_dir = scratch_dir("http_style");
        let req = build_ls_refs_request();
        let response = handle_one_command(&git_dir, &req).unwrap();
        assert_eq!(response, ls_refs::respond(&git_dir, &[]).unwrap());
    }

    #[test]
    fn handle_one_command_rejects_an_empty_body() {
        let git_dir = scratch_dir("http_empty_body");
        let result = handle_one_command(&git_dir, &pktline::encode_flush());
        assert!(matches!(result, Err(ServeError::Malformed { .. })));
    }
}
