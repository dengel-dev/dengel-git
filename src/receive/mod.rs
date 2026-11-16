//! Receive-pack ingress, object quarantine and ref publication.
//!
//! Validate objects in quarantine before entering the publication lock.
//! Record intent before linking packs into the live store. The existing
//! ref transaction does the expected-old comparison and moves the batch.
//! Recovery under the publication lock clears an uncommitted pack or
//! finishes a partially published ref batch. Git wire readers take the
//! same lock in shared mode and recover pending work before reading.
//! Report success only after the ref changes are durable.

pub mod commands;
pub mod connectivity;
pub(crate) mod publication;
pub mod quarantine;
pub mod session;

pub use publication::recover_repository;

#[derive(Debug)]
pub enum ReceiveError {
    Malformed {
        what: &'static str,
        detail: String,
    },
    /// A new ref tip's history is not fully present in quarantine + store.
    NotConnected {
        tip: String,
        missing: String,
    },
    /// The ref transaction was rejected (old-oid mismatch, etc.). The push
    /// is NOT acknowledged.
    RefRejected {
        detail: String,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveError::Malformed { what, detail } => write!(f, "malformed {what}: {detail}"),
            ReceiveError::NotConnected { tip, missing } => {
                write!(f, "tip {tip} not connected: missing {missing}")
            }
            ReceiveError::RefRejected { detail } => write!(f, "ref rejected: {detail}"),
            ReceiveError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ReceiveError {}

impl From<std::io::Error> for ReceiveError {
    fn from(e: std::io::Error) -> Self {
        ReceiveError::Io(e)
    }
}

/// The receive-pack advertisement reuses G2's `server::ls_refs::
/// enumerate_all_refs` (same ref set, same HEAD-first-then-bytewise
/// order - see that function's own doc comment) rather than
/// reimplementing ref enumeration a third time.
impl From<crate::server::ServeError> for ReceiveError {
    fn from(e: crate::server::ServeError) -> Self {
        ReceiveError::Malformed {
            what: "ref store (during receive-pack advertisement)",
            detail: e.to_string(),
        }
    }
}
