//! fetch command: want/have negotiation to a packfile.
//!
//! Format source: git-reference/Documentation/gitprotocol-v2.adoc,
//! "fetch" section (request args: want/have/done/thin-pack/
//! no-progress/include-tag/ofs-delta; response grammar: optional
//! acknowledgments/shallow-info/wanted-refs/packfile-uris sections,
//! then "packfile" section whose payload is sideband-multiplexed -
//! "each packet... is made up of a leading 4-byte pkt-line length,
//! followed by a 1-byte stream code, followed by the actual data...
//! 1 - pack data, 2 - progress messages, 3 - fatal error").
//!
//! P2 scope (see SPIKE-02.md and NOTES-02.md): single-round
//! negotiation only - the client sends its full want/have set AND
//! `done` in the same request. Per the doc: "If the client determines
//! that it is finished with negotiations by sending a 'done' line...
//! the acknowledgments sections MUST be omitted from the server's
//! response" - so this is not a shortcut around negotiation, it's the
//! documented behaviour for a client that already knows what it wants
//! (a legitimate strategy, not "cheating" the protocol). P3 is where
//! the multi-round acknowledgments dance actually gets exercised.

use super::pktline::PktLine;
use super::transport::UploadPackClient;
use std::collections::VecDeque;

#[derive(Debug, Default)]
pub struct FetchRequest {
    pub wants: Vec<String>,
    pub haves: Vec<String>,
    pub include_tag: bool,
}

#[derive(Debug, Default)]
pub struct FetchResponse {
    /// Raw pack bytes, demultiplexed from the sideband (channel 1
    /// only - channel 2 progress and channel 3 error text are handled
    /// separately, not mixed into this buffer).
    pub pack_bytes: Vec<u8>,
    pub progress_messages: Vec<String>,
}

#[derive(Debug)]
pub struct FetchError {
    pub server_message: String,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "server reported a fatal error during fetch: {}",
            self.server_message
        )
    }
}
impl std::error::Error for FetchError {}

/// Send a single-round fetch request (want/have/done all in one
/// request) and return the demultiplexed packfile bytes.
pub fn fetch(
    client: &mut UploadPackClient,
    req: &FetchRequest,
) -> Result<FetchResponse, Box<dyn std::error::Error>> {
    write_fetch_request(client, &req.wants, &req.haves, true, req.include_tag)?;
    parse_fetch_response(client)
}

fn write_fetch_request(
    client: &mut UploadPackClient,
    wants: &[String],
    haves: &[String],
    done: bool,
    include_tag: bool,
) -> std::io::Result<()> {
    client.write_data_line(b"command=fetch\n")?;
    client.write_delim()?; // end of capability-list (we send none)

    for want in wants {
        client.write_data_line(format!("want {}\n", want).as_bytes())?;
    }
    for have in haves {
        client.write_data_line(format!("have {}\n", have).as_bytes())?;
    }
    // We fully support OBJ_OFS_DELTA (spike 01 M2/M3/M4) so advertise
    // it; this is a real capability of our codec, not an assumption.
    client.write_data_line(b"ofs-delta\n")?;
    if include_tag {
        client.write_data_line(b"include-tag\n")?;
    }
    if done {
        client.write_data_line(b"done\n")?;
    }
    client.write_flush()?;
    client.flush_stdin()
}

/// P3: multi-round negotiation. Sends `haves` in batches of
/// `batch_size` (NOT all at once, deliberately, to force the
/// multi-round path to actually execute rather than converging in one
/// request the way P2's single-shot `fetch` does - see SPIKE-02.md's
/// P3 milestone). Every request restates the full `wants` list and
/// the FULL cumulative have set sent so far - protocol v2 is stateless
/// by default per gitprotocol-v2.adoc's Capabilities section ("all
/// commands must only last a single round and be stateless from the
/// perspective of the server side, unless the client has requested a
/// capability indicating that state should be maintained"), and we
/// request no such capability, so nothing is assumed to persist
/// server-side between our requests on the same connection - each
/// request is written to stand alone. `done` is sent only once we've
/// exhausted our have set (or the server said "ready" earlier, in
/// which case the packfile arrives in that same response, per spec:
/// "ready"... "is ready to make and send a packfile (which will be
/// found in the packfile section of the same response)").
pub fn fetch_multi_round(
    client: &mut UploadPackClient,
    wants: &[String],
    all_haves: &[String],
    batch_size: usize,
) -> Result<(FetchResponse, usize), Box<dyn std::error::Error>> {
    assert!(batch_size > 0, "batch_size must be positive");
    let mut remaining: VecDeque<String> = all_haves.iter().cloned().collect();
    let mut sent_so_far: Vec<String> = Vec::new();
    let mut rounds = 0usize;

    loop {
        rounds += 1;
        let mut batch = Vec::new();
        for _ in 0..batch_size {
            match remaining.pop_front() {
                Some(h) => batch.push(h),
                None => break,
            }
        }
        sent_so_far.extend(batch);
        let out_of_haves = remaining.is_empty();

        write_fetch_request(client, wants, &sent_so_far, out_of_haves, false)?;

        let header = match client.read_pkt_line()? {
            Some(PktLine::Data(bytes)) => String::from_utf8_lossy(&bytes)
                .trim_end_matches('\n')
                .to_string(),
            Some(PktLine::Flush) => return Err("empty response (no sections at all)".into()),
            other => {
                return Err(format!(
                    "unexpected pkt-line where a section header was expected: {:?}",
                    other
                )
                .into())
            }
        };

        match header.as_str() {
            "packfile" => {
                // Only valid if we sent `done` this round (out_of_haves).
                let mut response = FetchResponse::default();
                read_packfile_section(client, &mut response)?;
                return Ok((response, rounds));
            }
            "acknowledgments" => {
                let ack = parse_acknowledgments(client)?;
                if ack.ready {
                    // Per spec, the packfile section follows in this
                    // SAME response - read the delim then continue.
                    let header2 = match client.read_pkt_line()? {
                        Some(PktLine::Data(bytes)) => String::from_utf8_lossy(&bytes)
                            .trim_end_matches('\n')
                            .to_string(),
                        Some(PktLine::Flush) => {
                            return Err("server said ready but sent no packfile section".into())
                        }
                        other => {
                            return Err(
                                format!("unexpected pkt-line after ready: {:?}", other).into()
                            )
                        }
                    };
                    if header2 != "packfile" {
                        return Err(format!(
                            "expected packfile section after ready, got {:?}",
                            header2
                        )
                        .into());
                    }
                    let mut response = FetchResponse::default();
                    read_packfile_section(client, &mut response)?;
                    return Ok((response, rounds));
                }
                if out_of_haves {
                    // We sent `done` but the server responded with
                    // acknowledgments instead of going straight to a
                    // packfile - this contradicts the doc's "the
                    // acknowledgments sections MUST be omitted" rule
                    // for a client that sent done. Surface it as an
                    // error rather than silently looping forever.
                    return Err(
                        "server sent acknowledgments (not ready) even though we sent 'done' and \
                         have no more haves - contradicts gitprotocol-v2.adoc; see NOTES-02.md"
                            .into(),
                    );
                }
                // Negotiation continues: loop with the next batch.
            }
            other => {
                return Err(format!(
                    "unexpected fetch response section during negotiation: {:?}",
                    other
                )
                .into())
            }
        }
    }
}

#[derive(Debug, Default)]
struct Acknowledgments {
    nak: bool,
    acks: Vec<String>,
    ready: bool,
}

/// Parse an "acknowledgments" section: PKT-LINE("acknowledgments" LF)
/// already consumed by the caller (that's how the section was
/// identified); this reads (nak | *ack) then an optional "ready", then
/// the section-ending flush-pkt (there is no delim after
/// acknowledgments unless a further section - i.e. packfile after
/// ready - follows, which the caller handles separately).
fn parse_acknowledgments(client: &mut UploadPackClient) -> std::io::Result<Acknowledgments> {
    let mut ack = Acknowledgments::default();
    loop {
        match client.read_pkt_line()? {
            Some(PktLine::Data(bytes)) => {
                let text = String::from_utf8_lossy(&bytes);
                let text = text.trim_end_matches('\n');
                if text == "NAK" {
                    ack.nak = true;
                } else if text == "ready" {
                    ack.ready = true;
                } else if let Some(oid) = text.strip_prefix("ACK ") {
                    ack.acks.push(oid.to_string());
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unrecognized line in acknowledgments section: {:?}", text),
                    ));
                }
            }
            Some(PktLine::Flush) => return Ok(ack),
            Some(PktLine::Delim) => return Ok(ack), // ready + more sections follow, caller reads them
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "unexpected pkt-line in acknowledgments section: {:?}",
                        other
                    ),
                ))
            }
        }
    }
}

fn parse_fetch_response(
    client: &mut UploadPackClient,
) -> Result<FetchResponse, Box<dyn std::error::Error>> {
    let mut response = FetchResponse::default();

    // We sent `done`, so per spec the acknowledgments section MUST be
    // omitted - the response should go straight to whichever of
    // shallow-info/wanted-refs/packfile-uris/packfile sections apply.
    // We didn't request shallow/want-ref/packfile-uris features, so in
    // practice this loop expects exactly one section: "packfile".
    // Written as a loop over sections (delimited by delim-pkt) rather
    // than assuming "packfile" is first, since asserting our own
    // assumption would be exactly the kind of thing that turns into a
    // silent wrong-parse bug if it's ever violated.
    loop {
        let header = match client.read_pkt_line()? {
            Some(PktLine::Data(bytes)) => String::from_utf8_lossy(&bytes)
                .trim_end_matches('\n')
                .to_string(),
            Some(PktLine::Flush) => return Ok(response), // empty response, nothing more
            other => {
                return Err(format!(
                    "unexpected pkt-line where a section header was expected: {:?}",
                    other
                )
                .into())
            }
        };

        match header.as_str() {
            "packfile" => {
                read_packfile_section(client, &mut response)?;
                return Ok(response);
            }
            "acknowledgments" => {
                return Err(
                    "server sent an acknowledgments section despite an immediate 'done' - P2 scope \
                     doesn't implement multi-round negotiation parsing (see P3)"
                        .into(),
                );
            }
            "shallow-info" | "wanted-refs" | "packfile-uris" => {
                // Not requested, but tolerate and skip if a server
                // sends one anyway - consume until the next delim/flush.
                skip_section(client)?;
            }
            other => {
                return Err(format!("unknown fetch response section header: {:?}", other).into())
            }
        }
    }
}

fn skip_section(client: &mut UploadPackClient) -> std::io::Result<()> {
    loop {
        match client.read_pkt_line()? {
            Some(PktLine::Data(_)) => continue,
            Some(PktLine::Delim) | Some(PktLine::Flush) | None => return Ok(()),
            Some(other) => panic!(
                "unexpected pkt-line while skipping a fetch response section: {:?}",
                other
            ),
        }
    }
}

/// Read the packfile section: sideband-multiplexed pkt-lines until
/// flush. Channel 1 -> pack bytes, channel 2 -> progress text
/// (collected, not printed - test harness decides what to do with
/// it), channel 3 -> fatal error (returned as Err immediately).
fn read_packfile_section(
    client: &mut UploadPackClient,
    response: &mut FetchResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match client.read_pkt_line()? {
            Some(PktLine::Data(bytes)) => {
                if bytes.is_empty() {
                    return Err("empty sideband pkt-line (missing channel byte)".into());
                }
                let (channel, payload) = (bytes[0], &bytes[1..]);
                match channel {
                    1 => response.pack_bytes.extend_from_slice(payload),
                    2 => response
                        .progress_messages
                        .push(String::from_utf8_lossy(payload).to_string()),
                    3 => {
                        return Err(Box::new(FetchError {
                            server_message: String::from_utf8_lossy(payload).to_string(),
                        }))
                    }
                    other => return Err(format!("unknown sideband channel byte {}", other).into()),
                }
            }
            Some(PktLine::Flush) => return Ok(()),
            other => {
                return Err(format!("unexpected pkt-line in packfile section: {:?}", other).into())
            }
        }
    }
}
