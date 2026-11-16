//! Shared Git transport, object storage, and ref transactions.

pub mod http;
pub mod ingest;
pub mod object;
pub mod objectstore;
mod objectstore_entry;
pub mod receive;
pub mod refvalidate;
pub mod repository_name;
pub mod server;
pub mod standalone;

/// The spike-validated pack codec, re-exported as-is. TRUSTED-SIDE ONLY:
/// these entry points panic on malformed input by design (they were
/// validated against trusted corpora, and a panic there means our own
/// store is corrupt, which should be loud). Bytes from the network go
/// through `ingest`, never through this.
pub use rustgit::pack;

/// The spike-validated ref store, re-exported as-is (G3). Its
/// `checkpoint()` instrumentation already speaks the generic
/// REFSTORE_HARNESS_* contract, so the standalone harness drives
/// dengel-git's ref writer without any adapter.
pub use rustgit::refs;
