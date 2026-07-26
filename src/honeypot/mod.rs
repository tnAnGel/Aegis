//! Honeypot path matching + tarpit response.
//!
//! Operators publish a curated set of "no legitimate user ever
//! requests these" paths (WordPress login, .env files, phpMyAdmin,
//! and 15 other built-in packs). Requests that hit any of them get
//! a slow-drip tarpit response that ties up the scanner's worker
//! pool for ~30 s without consuming our backend.
//!
//! Each pack can be enabled / disabled globally and per-host via the
//! admin panel — operators who actually run WordPress on `blog.acme`
//! just turn that one pack off for that one host.
//!
//! No false positives by design: the filter only matches paths that
//! exist exclusively in scanner wordlists.

pub mod matcher;
pub mod packs;
pub mod state;
pub mod tarpit;

pub use packs::{BUILTIN_PACKS, Pack};
pub use state::{HoneypotDecision, HoneypotState, HoneypotStore};
pub use tarpit::TarpitBody;
