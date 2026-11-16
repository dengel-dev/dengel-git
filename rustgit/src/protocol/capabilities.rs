//! Capability advertisement parsing.
//!
//! Format source: git-reference/Documentation/gitprotocol-v2.adoc,
//! "Capability Advertisement" section:
//!   capability-advertisement = protocol-version capability-list flush-pkt
//!   protocol-version = PKT-LINE("version 2" LF)
//!   capability-list = *capability
//!   capability = PKT-LINE(key[=value] LF)
//!
//! P4 (see NOTES-02.md): a server not speaking protocol v2 sends the
//! legacy v0/v1 ref advertisement instead (first line looks like
//! "<oid> HEAD\0<capabilities...>", not "version 2"). This module
//! detects that shape and returns a distinct, recognizable error
//! rather than panicking or silently misparsing the legacy line as if
//! it were a v2 capability - see AdvertisementError::NotProtocolV2.
//! Full v0 protocol support is out of scope (SPIKE-02.md P4): clean
//! detection is the bar.

use std::collections::HashMap;
use std::fmt;

use super::pktline::PktLine;
use super::transport::UploadPackClient;

#[derive(Debug, Default)]
pub struct Capabilities {
    /// key -> value (None if the capability was sent without "=value")
    pub entries: HashMap<String, Option<String>>,
}

impl Capabilities {
    pub fn has(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn value(&self, key: &str) -> Option<&str> {
        self.entries.get(key).and_then(|v| v.as_deref())
    }

    /// A command capability's advertised value is a space-separated
    /// feature list, e.g. "fetch=shallow wait-for-done" - per
    /// gitprotocol-v2.adoc: "Additional features not supported in the
    /// base command will be advertised as the value of the command...
    /// in the form of a space separated list of features".
    pub fn command_features(&self, command: &str) -> Vec<String> {
        self.value(command)
            .map(|v| {
                v.split(' ')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug)]
pub enum AdvertisementError {
    /// The first line of the response was not exactly "version 2" -
    /// most likely a legacy v0/v1 ref advertisement (whose first line
    /// looks like "<oid-or-zero-id> HEAD\0<capabilities>" rather than
    /// a version string). `first_line` is the raw text for diagnosis;
    /// we deliberately do NOT attempt to parse it as a legacy ref
    /// advertisement - full v0 support is out of scope, this variant
    /// exists so callers can detect and report cleanly instead of the
    /// alternative of misinterpreting server-option/other capability
    /// lines as if this were a v2 stream.
    NotProtocolV2 {
        first_line: String,
    },
    Io(std::io::Error),
    UnexpectedPktLine(String),
}

impl fmt::Display for AdvertisementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvertisementError::NotProtocolV2 { first_line } => write!(
                f,
                "server did not speak protocol v2 (first line was {:?}, not \"version 2\") - \
                 likely a legacy v0/v1 server; this client does not implement v0/v1 fallback",
                first_line
            ),
            AdvertisementError::Io(e) => {
                write!(f, "io error reading capability advertisement: {}", e)
            }
            AdvertisementError::UnexpectedPktLine(desc) => {
                write!(
                    f,
                    "unexpected pkt-line in capability advertisement: {}",
                    desc
                )
            }
        }
    }
}
impl std::error::Error for AdvertisementError {}
impl From<std::io::Error> for AdvertisementError {
    fn from(e: std::io::Error) -> Self {
        AdvertisementError::Io(e)
    }
}

fn parse_capability_line(line: &str) -> (String, Option<String>) {
    match line.split_once('=') {
        Some((k, v)) => (k.to_string(), Some(v.to_string())),
        None => (line.to_string(), None),
    }
}

/// Read and parse the capability advertisement, which is always the
/// FIRST thing the server sends after we spawn it (no request needed
/// to trigger it - it's unconditional on connect, per the doc's
/// "capability-advertisement" production having no preceding client
/// message in its grammar).
///
/// Returns Err(NotProtocolV2) - not a panic - if the server responded
/// with anything other than a v2 stream, so callers (and P4's test)
/// can assert on clean failure detection rather than a crash.
pub fn read_capability_advertisement(
    client: &mut UploadPackClient,
) -> Result<Capabilities, AdvertisementError> {
    let lines = client.read_until_flush()?;
    let mut caps = Capabilities::default();
    let mut seen_version = false;

    for line in lines {
        match line {
            PktLine::Data(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let text = text.trim_end_matches('\n').to_string();
                if !seen_version {
                    if text != "version 2" {
                        return Err(AdvertisementError::NotProtocolV2 { first_line: text });
                    }
                    seen_version = true;
                    continue;
                }
                let (key, value) = parse_capability_line(&text);
                caps.entries.insert(key, value);
            }
            PktLine::Flush => break,
            other => {
                return Err(AdvertisementError::UnexpectedPktLine(format!(
                    "{:?}",
                    other
                )))
            }
        }
    }

    if !seen_version {
        return Err(AdvertisementError::NotProtocolV2 {
            first_line: String::new(),
        });
    }
    Ok(caps)
}
