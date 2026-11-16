//! G2: protocol v2, server side. Spike 02 built the client half of this
//! exact conversation; this is the same grammar from the other end, with
//! canonical git as the client.
//!
//! Transport-agnostic core: `serve_upload_pack` speaks the stdio flavor
//! (advertise, then serve commands until EOF); the stateless-HTTP flavor
//! reuses the same request handlers per-POST via `http.rs`. Request bytes
//! come from the network: parsing is Result-based, never panicking, even
//! though the adversary role formally targets only G3/G4.
//!
//! The one behavioral rule inherited from spike 02's P2 finding
//! (rustgit NOTES-02): the object set a server sends is a SUPERSET of the
//! theoretical minimum. Correctness here means the client ends up with a
//! connected, fsck-clean repository - never that the pack is minimal.

pub mod advertise;
pub mod fetch;
pub mod ls_refs;
pub mod session;
pub mod walk;

#[derive(Debug)]
pub enum ServeError {
    Malformed {
        what: &'static str,
        detail: String,
    },
    Io(std::io::Error),
    /// The repository itself is broken (our own store failed to resolve
    /// an object a ref reachable from a WANT points at, or a HAVE we
    /// were told not to tolerate misses on). Loud by design - this
    /// means our own store is inconsistent, not that the client asked
    /// for something unreasonable.
    Repo {
        detail: String,
    },
    /// A `want <oid>` line named an object this repository's object
    /// store simply does not contain. Distinct from `Repo`: this is
    /// the client's request being unsatisfiable (a promisor follow-up
    /// fetch for an oid we never had, a typo, a stale client), never a
    /// sign our own store is broken - see fetch.rs's `respond`, which
    /// checks every want up front, before any acknowledgments/packfile
    /// framing is written, so this always turns into a clean top-level
    /// ERR rather than a truncated or empty response.
    UnknownWant {
        oid: String,
    },
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::Malformed { what, detail } => write!(f, "malformed {what}: {detail}"),
            ServeError::Io(e) => write!(f, "io error: {e}"),
            ServeError::Repo { detail } => write!(f, "repository error: {detail}"),
            ServeError::UnknownWant { oid } => {
                write!(f, "upload-pack: want {oid} not found in this repository")
            }
        }
    }
}

impl std::error::Error for ServeError {}

impl From<std::io::Error> for ServeError {
    fn from(e: std::io::Error) -> Self {
        ServeError::Io(e)
    }
}

impl From<crate::objectstore::StoreError> for ServeError {
    fn from(e: crate::objectstore::StoreError) -> Self {
        ServeError::Repo {
            detail: format!("failed to open object store: {e}"),
        }
    }
}
