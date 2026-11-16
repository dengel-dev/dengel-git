//! Protocol v2 FETCH CLIENT. Scope: capability advertisement, ls-refs,
//! want/have negotiation - see CLAUDE.md and SPIKE-02.md. No server
//! implementation; real git plays the server role via a local
//! `git upload-pack` subprocess (see transport.rs).

pub mod capabilities;
pub mod fetch;
pub mod ls_refs;
pub mod pktline;
pub mod transport;
