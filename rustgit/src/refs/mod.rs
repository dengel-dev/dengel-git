//! Transactional ref store against the loose-ref + packed-refs (files)
//! backend. Scope: see CLAUDE.md and SPIKE-03.md. Reftable explicitly
//! out of scope.

pub mod checkpoint;
pub mod lock;
pub mod loose;
pub mod packed;
pub mod stdin_format;
pub mod transaction;
