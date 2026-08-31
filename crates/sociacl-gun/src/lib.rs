//! GunDB adapter for the SociACL authority plane.
//!
//! In-graph Gun data is the native ACL. Check evaluates graph
//! relations on souls and nodes. Non-Gun data is a [`UrlLeaf`]: a
//! permalink is not a Gun node and not a grant.
//!
//! This crate maps Gun types onto existing [`sociacl_core`] Check
//! predicates and the keep-operating [`sociacl_core::Relation::Delegate`]
//! grant. It does not add a Gun-only verb and it does not fork the
//! locked s3r.ch graph.
//!
//! s3r.ch reimplements the handoff types in TypeScript. It does not
//! import this crate. The Gun adapter surface for that product is
//! Check + `delegate` only. Elect, wills, and Case C mint stay off
//! that surface. This crate may Check a Case C [`sociacl_core::Client`]
//! the way the rest of SociACL does.
//!
//! See [docs/gun.md](../../docs/gun.md).

mod adapter;
mod error;
mod hint;
mod leaf;
mod soul;

pub use adapter::{
    accept_hint, accept_hint_bytes, add_claim, add_wallet, cancel, check, check_execute, check_see,
    client_check, client_elect_from_hint, client_mint_grant, client_remint, elect_from_delegate,
    elect_from_hint, map_action, remint, GunCheckResult,
};
pub use error::GunError;
pub use hint::{HandoffHint, MAGIC as HINT_MAGIC, VERSION as HINT_VERSION};
pub use leaf::{normalize_permalink, ItemShape, UrlLeaf};
pub use soul::{GunNode, GunNodeKind, GunSoul, S3RCH_ROOT, S3RCH_USERS};

/// Lighter s3r.ch Check: `CHECK(see, claim, accessor)` at now.
/// Mapped onto Check `read`.
pub const SEE: &str = "see";
