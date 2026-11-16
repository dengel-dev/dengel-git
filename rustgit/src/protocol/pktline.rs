//! pkt-line framing, shared by every protocol v2 command.
//!
//! Format source: git-reference/Documentation/gitprotocol-common.adoc
//! ("pkt-line Format" section) - 4-byte hex length prefix (including
//! itself), payload follows. flush-pkt = "0000" (length field 0, no
//! payload, distinct from an empty pkt-line "0004" which SHOULD NOT be
//! sent but is a valid concept). Protocol v2 adds two more reserved
//! zero-payload markers on top of flush-pkt, per gitprotocol-v2.adoc's
//! "Packet-Line Framing" section: delim-pkt "0001" (separates sections
//! of a v2 response) and response-end-pkt "0002" (end of response for
//! stateless connections - not expected to appear over our persistent-
//! pipe transport, but recognized so parsing doesn't choke on it).

use std::io::{self, Read, Write};

pub const MAX_PAYLOAD_LEN: usize = 65516; // gitprotocol-common.adoc: max pkt-line data component

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktLine {
    Data(Vec<u8>),
    Flush,       // "0000"
    Delim,       // "0001"
    ResponseEnd, // "0002"
}

/// Encode a single data pkt-line: 4-byte hex length (of length-field +
/// payload) followed by the payload verbatim. Caller is responsible
/// for including a trailing LF in `payload` if the line is meant to be
/// treated as text (pkt-line framing itself does not add one).
pub fn encode_data(payload: &[u8]) -> Vec<u8> {
    assert!(
        payload.len() <= MAX_PAYLOAD_LEN,
        "pkt-line payload {} bytes exceeds max {}",
        payload.len(),
        MAX_PAYLOAD_LEN
    );
    let total_len = payload.len() + 4;
    let mut out = format!("{:04x}", total_len).into_bytes();
    out.extend_from_slice(payload);
    out
}

pub fn encode_flush() -> Vec<u8> {
    b"0000".to_vec()
}

pub fn encode_delim() -> Vec<u8> {
    b"0001".to_vec()
}

/// Read one pkt-line from `r`. Returns Ok(None) on clean EOF before
/// any bytes of a new pkt-line were read (the pipe closed); any other
/// short read is an error, since a pkt-line's length prefix promises
/// an exact byte count.
pub fn read_pkt_line<R: Read>(r: &mut R) -> io::Result<Option<PktLine>> {
    let mut len_buf = [0u8; 4];
    if !read_exact_or_eof(r, &mut len_buf)? {
        return Ok(None);
    }
    let len_str = std::str::from_utf8(&len_buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pkt-line length not utf8"))?;
    let total_len = usize::from_str_radix(len_str, 16).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad pkt-line length {:?}", len_str),
        )
    })?;

    match total_len {
        0 => Ok(Some(PktLine::Flush)),
        1 => Ok(Some(PktLine::Delim)),
        2 => Ok(Some(PktLine::ResponseEnd)),
        3 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pkt-line length 0003 is reserved and unused",
        )),
        n => {
            let payload_len = n - 4;
            let mut payload = vec![0u8; payload_len];
            r.read_exact(&mut payload)?;
            Ok(Some(PktLine::Data(payload)))
        }
    }
}

/// Like std::io::Read::read_exact, but returns Ok(false) instead of an
/// UnexpectedEof error when zero bytes were read before EOF (i.e. EOF
/// exactly at a pkt-line boundary, not mid-line).
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut read_so_far = 0;
    while read_so_far < buf.len() {
        match r.read(&mut buf[read_so_far..]) {
            Ok(0) => {
                if read_so_far == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF mid pkt-line",
                ));
            }
            Ok(n) => read_so_far += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Read pkt-lines until a Flush (inclusive - the flush is included in
/// the returned vec as PktLine::Flush) or EOF. Convenience for reading
/// one full section/response at a time.
pub fn read_until_flush<R: Read>(r: &mut R) -> io::Result<Vec<PktLine>> {
    let mut lines = Vec::new();
    loop {
        match read_pkt_line(r)? {
            None => return Ok(lines),
            Some(PktLine::Flush) => {
                lines.push(PktLine::Flush);
                return Ok(lines);
            }
            Some(line) => lines.push(line),
        }
    }
}

pub fn write_data_line<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    w.write_all(&encode_data(payload))
}

pub fn write_flush<W: Write>(w: &mut W) -> io::Result<()> {
    w.write_all(&encode_flush())
}

pub fn write_delim<W: Write>(w: &mut W) -> io::Result<()> {
    w.write_all(&encode_delim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn examples_from_gitprotocol_common_adoc() {
        // Table straight from the doc: "0006a\n" -> "a\n", "0005a" -> "a",
        // "000bfoobar\n" -> "foobar\n", "0004" -> "" (empty, not flush).
        assert_eq!(encode_data(b"a\n"), b"0006a\n");
        assert_eq!(encode_data(b"a"), b"0005a");
        assert_eq!(encode_data(b"foobar\n"), b"000bfoobar\n");
        assert_eq!(encode_data(b""), b"0004");
    }

    #[test]
    fn roundtrip_data_flush_delim() {
        let mut buf = Vec::new();
        write_data_line(&mut buf, b"version 2\n").unwrap();
        write_data_line(&mut buf, b"agent=git/test\n").unwrap();
        write_delim(&mut buf).unwrap();
        write_data_line(&mut buf, b"command=ls-refs\n").unwrap();
        write_flush(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        assert_eq!(
            read_pkt_line(&mut cursor).unwrap(),
            Some(PktLine::Data(b"version 2\n".to_vec()))
        );
        assert_eq!(
            read_pkt_line(&mut cursor).unwrap(),
            Some(PktLine::Data(b"agent=git/test\n".to_vec()))
        );
        assert_eq!(read_pkt_line(&mut cursor).unwrap(), Some(PktLine::Delim));
        assert_eq!(
            read_pkt_line(&mut cursor).unwrap(),
            Some(PktLine::Data(b"command=ls-refs\n".to_vec()))
        );
        assert_eq!(read_pkt_line(&mut cursor).unwrap(), Some(PktLine::Flush));
        assert_eq!(read_pkt_line(&mut cursor).unwrap(), None);
    }

    #[test]
    fn clean_eof_at_boundary_is_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_pkt_line(&mut cursor).unwrap(), None);
    }
}
