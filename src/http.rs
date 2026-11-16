//! Smart HTTP wire responses shared by both listeners.

use crate::receive;
use crate::receive::session::{PublicationAdmission, ReceivePolicy};
use crate::server::{advertise, session};
use axum::body::{Body, Bytes, HttpBody};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use rustgit::protocol::pktline;
use std::io::{self, Read};
use std::path::Path;

/// Largest request body the server accepts (a push is one POST body).
/// axum's implicit default (2 MiB) refused any real push above it.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;

/// `WWW-Authenticate` sent with every 401: stock git only prompts for (or
/// sends URL) credentials after a 401 carrying a Basic challenge.
pub const WWW_AUTHENTICATE_VALUE: &str = "Basic realm=\"Dengel Git\"";

/// The token in an `Authorization` header: the Bearer value, or the password
/// of HTTP Basic credentials (the user name is ignored). For callers that
/// mount their own router and do their own token check.
pub fn presented_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(token.to_owned());
    }
    let encoded = value.strip_prefix("Basic ")?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded.trim()).ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    let (_user, password) = credentials.split_once(':')?;
    Some(password.to_owned())
}

/// 401 with the Basic challenge stock git needs before it sends credentials.
pub fn unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, WWW_AUTHENTICATE_VALUE)
        .body(Body::from("unauthorized\n"))
        .expect("a static 401 response cannot fail to build")
}

/// Length-independent-first, then byte-wise constant-time equality: git
/// credentials pass through here on every request, and a naive `==` leaks
/// how many leading bytes matched via early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn bad_request(msg: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(msg))
        .expect("a static 400 response cannot fail to build")
}

fn bad_request_detail(detail: String) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(detail))
        .expect("a response built from a dynamic string body cannot fail")
}

fn server_error(detail: String) -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(detail))
        .expect("a response built from a dynamic string body cannot fail")
}

/// `GET .../info/refs?service=...` against an already resolved git dir.
/// `raw_query` is the request's raw query string; anything but exactly one
/// supported `service=` parameter is a 400.
pub fn info_refs_response(git_dir: &Path, raw_query: Option<&str>) -> Response {
    // "The request MUST contain exactly one query parameter,
    // service=$servicename... MUST NOT contain additional query
    // parameters" - gitprotocol-http.adoc. This server implements
    // exactly two services; anything else (including no service at all)
    // is rejected up front, same as before G4 added the second branch.
    let service = match raw_query {
        Some("service=git-upload-pack") => "git-upload-pack",
        Some("service=git-receive-pack") => "git-receive-pack",
        _ => return bad_request("expected exactly one query parameter: service=git-upload-pack or service=git-receive-pack\n"),
    };

    let advert = if service == "git-upload-pack" {
        // The Git-Protocol request header (carrying "version=2") is not
        // inspected: this server has no v0/v1 advertisement to fall back
        // to in the first place, so its answer is the same v2
        // advertisement either way - noted here rather than silently
        // ignored, per this milestone's instruction to call out that
        // choice explicitly.
        advertise::capability_advertisement()
    } else {
        match receive::session::advertisement(git_dir) {
            Ok(bytes) => bytes,
            Err(e) => return server_error(e.to_string()),
        }
    };

    let mut body = Vec::new();
    body.extend_from_slice(&pktline::encode_data(
        format!("# service={service}\n").as_bytes(),
    ));
    body.extend_from_slice(&pktline::encode_flush());
    body.extend_from_slice(&advert);

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            format!("application/x-{service}-advertisement"),
        )
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .expect("a response built from a static content-type and a byte body cannot fail")
}

/// Maximum size a gzip-encoded request body may expand to.
///
/// WHY A CAP AT ALL: a decompressor with no bound turns a few kilobytes of
/// attacker-chosen input into as much memory as they like. dengel-m1 has
/// 1.8GB of RAM and its own database to run; an unbounded decoder here is a
/// denial of service anyone can send. 64MiB is far beyond any real fetch
/// request - the observed failing case was a want/have list of a few
/// kilobytes - while still refusing the pathological ones.
const MAX_DECOMPRESSED_BODY: u64 = 64 * 1024 * 1024;

/// Decode a request body, decompressing it when the client gzipped it.
///
/// WHY THIS EXISTS: git compresses an upload-pack request body once it grows
/// past a threshold, and announces it with `Content-Encoding: gzip`
/// (gitprotocol-http.adoc, "The Negotiation Algorithm"). Without this, the
/// pkt-line reader is handed gzip's magic bytes where a 4-byte hex length
/// should be and fails with "pkt-line length not utf8" - which is what a
/// misaligned stream looks like, not a length that happened to be
/// non-ASCII.
///
/// The failure mode this closes is worse than it sounds: SMALL requests are
/// not compressed, so a clone and an already-up-to-date fetch both work. It
/// only bites once a client has enough history to negotiate over - which is
/// every real incremental fetch, and none of the tests that existed before
/// this was found in production.
// The upstream response *is* the failure: this function reports what the server
// said, and boxing it would change a signature to satisfy a size heuristic.
#[allow(
    clippy::result_large_err,
    reason = "the response is the error by design"
)]
fn decode_body(headers: &HeaderMap, body: Bytes) -> Result<Vec<u8>, Response> {
    let gzipped = gzip_encoded(headers);
    if !gzipped {
        return Ok(body.to_vec());
    }

    let mut out = Vec::new();
    // Fully qualified: without `std::io::Read` in scope, a bare `.take()`
    // binds to `Iterator::take` and silently means something else.
    let mut decoder = std::io::Read::take(
        flate2::read::GzDecoder::new(&body[..]),
        MAX_DECOMPRESSED_BODY,
    );
    match std::io::Read::read_to_end(&mut decoder, &mut out) {
        Ok(_) if (out.len() as u64) < MAX_DECOMPRESSED_BODY => Ok(out),
        // Hitting the cap exactly is indistinguishable from being truncated
        // by it, so both are refused rather than passed on as a body that
        // might be missing its tail.
        Ok(_) => Err(bad_request(
            "gzip-encoded body exceeds the decompression limit",
        )),
        Err(e) => Err(bad_request_detail(format!(
            "gzip-encoded body could not be decoded: {e}"
        ))),
    }
}

fn gzip_encoded(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|e| e.trim().eq_ignore_ascii_case("gzip")))
        .unwrap_or(false)
}

/// `POST .../git-upload-pack` against an already resolved git dir. `headers`
/// are the request's (a gzip `Content-Encoding` is decoded, bounded).
pub fn upload_pack_response(git_dir: &Path, headers: &HeaderMap, body: Bytes) -> Response {
    let body = match decode_body(headers, body) {
        Ok(b) => b,
        Err(response) => return response,
    };

    let response_bytes = match session::handle_one_command(git_dir, &body) {
        Ok(bytes) => bytes,
        Err(e) => {
            // Errors are reported IN the pkt-line stream (an ERR pkt),
            // not via the HTTP status - gitprotocol-pack.adoc's
            // error-line is transport-agnostic, and gitprotocol-http.adoc
            // does not define a distinct HTTP-level error framing for
            // this endpoint, so the same err-pkt convention session.rs
            // uses for the stdio flavor applies here too.
            let payload = format!("ERR {e}\n");
            pktline::encode_data(payload.as_bytes())
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-upload-pack-result")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(response_bytes))
        .expect("a response built from a static content-type and a byte body cannot fail")
}

/// `POST .../git-receive-pack` against an already resolved git dir, under
/// `policy`. A policy refusal is a report-status rejection of the whole
/// push (HTTP 200, as git expects), never a partial landing.
pub fn receive_pack_response(
    git_dir: &Path,
    headers: &HeaderMap,
    body: Bytes,
    policy: &ReceivePolicy,
) -> Response {
    receive_pack_response_with_admission(git_dir, headers, body, policy, || {
        Ok(PublicationAdmission::new(policy.max_repo_bytes, ()))
    })
}

pub fn receive_pack_response_with_admission(
    git_dir: &Path,
    headers: &HeaderMap,
    body: Bytes,
    policy: &ReceivePolicy,
    admit: impl FnOnce() -> std::io::Result<PublicationAdmission>,
) -> Response {
    let body = match decode_body(headers, body) {
        Ok(b) => b,
        Err(response) => return response,
    };

    receive_report(git_dir, &mut io::Cursor::new(body), policy, admit)
}

struct BodyReader {
    body: Body,
    runtime: tokio::runtime::Handle,
    remaining: usize,
    frame: Bytes,
}

impl Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.frame.is_empty() {
            let Some(frame) = self.runtime.block_on(self.body.frame()) else {
                return Ok(0);
            };
            if let Ok(bytes) = frame.map_err(io::Error::other)?.into_data() {
                self.remaining = self
                    .remaining
                    .checked_sub(bytes.len())
                    .ok_or_else(|| io::Error::other("Git request exceeds its byte limit"))?;
                self.frame = bytes;
            }
        }
        let count = self.frame.len().min(buf.len());
        buf[..count].copy_from_slice(&self.frame.split_to(count));
        Ok(count)
    }
}

/// Read smart HTTP receive data on a Tokio blocking task. Encoded bytes
/// are bounded while reading. The receiver separately limits inflation.
pub fn receive_pack_streaming_response(
    git_dir: &Path,
    headers: &HeaderMap,
    body: Body,
    max_body_bytes: usize,
    policy: &ReceivePolicy,
    admit: impl FnOnce() -> io::Result<PublicationAdmission>,
) -> Response {
    if body
        .size_hint()
        .exact()
        .is_some_and(|size| size > max_body_bytes as u64)
    {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut input = BodyReader {
        body,
        runtime,
        remaining: max_body_bytes,
        frame: Bytes::new(),
    };
    if gzip_encoded(headers) {
        let mut decoded = flate2::read::GzDecoder::new(input).take(MAX_DECOMPRESSED_BODY);
        receive_report(git_dir, &mut decoded, policy, admit)
    } else {
        receive_report(git_dir, &mut input, policy, admit)
    }
}

fn receive_report(
    git_dir: &Path,
    input: &mut dyn Read,
    policy: &ReceivePolicy,
    admit: impl FnOnce() -> io::Result<PublicationAdmission>,
) -> Response {
    let response_bytes =
        match receive::session::handle_receive_reader(git_dir, input, policy, admit) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Same transport-agnostic error-line convention as
                // upload_pack above.
                let payload = format!("ERR {e}\n");
                pktline::encode_data(payload.as_bytes())
            }
        };

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/x-git-receive-pack-result",
        )
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(response_bytes))
        .expect("a response built from a static content-type and a byte body cannot fail")
}

#[cfg(test)]
mod decode_body_tests {
    use super::*;
    use std::io::Write;

    fn gz(bytes: &[u8]) -> Bytes {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(bytes).unwrap();
        Bytes::from(e.finish().unwrap())
    }

    fn headers_with(encoding: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = encoding {
            h.insert(header::CONTENT_ENCODING, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn an_uncompressed_body_passes_through_untouched() {
        let body = Bytes::from_static(b"0011command=fetch\n0001");
        let out = decode_body(&headers_with(None), body.clone()).unwrap();
        assert_eq!(
            out,
            body.to_vec(),
            "a body with no Content-Encoding must not be altered"
        );
    }

    #[test]
    fn a_gzipped_body_is_decoded_to_the_original_bytes() {
        // The bug: this arrived at the pkt-line reader still compressed, so
        // gzip's magic was parsed as a 4-byte hex length.
        let original = b"0011command=fetch\n0001000ahave x\n0000";
        let out = decode_body(&headers_with(Some("gzip")), gz(original)).unwrap();
        assert_eq!(out, original.to_vec());
    }

    #[test]
    fn content_encoding_is_matched_case_insensitively_and_within_a_list() {
        let original = b"0011command=fetch\n";
        for header_value in ["GZIP", "identity, gzip", "gzip "] {
            let out = decode_body(&headers_with(Some(header_value)), gz(original))
                .unwrap_or_else(|_| panic!("{header_value:?} should be recognised as gzip"));
            assert_eq!(
                out,
                original.to_vec(),
                "for Content-Encoding: {header_value:?}"
            );
        }
    }

    #[test]
    fn a_body_that_expands_past_the_cap_is_refused_rather_than_buffered() {
        // A few hundred KB of zeros compresses to almost nothing and expands
        // past the cap - the shape of a decompression bomb, which on a 1.8GB
        // box is a denial of service anyone can post.
        let huge = vec![0u8; (MAX_DECOMPRESSED_BODY + 1) as usize];
        let err = decode_body(&headers_with(Some("gzip")), gz(&huge)).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_malformed_gzip_body_is_refused_not_passed_through() {
        // Claiming gzip and sending something else must fail loudly. Passing
        // it through is exactly the bug being fixed, in reverse.
        let err = decode_body(
            &headers_with(Some("gzip")),
            Bytes::from_static(b"not gzip at all"),
        )
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
}
