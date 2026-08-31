//! GunDB adapter for the SociACL authority plane.
//!
//! In-graph Gun data is the native ACL. A Check object is a
//! Gun-native feed item (`s3rch/items/<encodeKey(id)>`) or a held
//! claim on the user node. Non-Gun data is a [`UrlLeaf`]: RSS3,
//! RSS/Atom, and issuer HTTP calls are not Gun nodes and not grants.
//!
//! This crate maps Gun types onto existing [`sociacl_core`] Check
//! predicates and the keep-operating [`sociacl_core::Relation::Delegate`]
//! grant. It does not add a Gun-only verb and it does not fork the
//! locked s3r.ch graph.
//!
//! s3r.ch copies [docs/s3rch-check.d.ts](../../docs/s3rch-check.d.ts)
//! and runs light Check in the browser. It does not import this crate.
//! The Gun adapter surface for that product is Check + `delegate`
//! only. Elect, wills, and Case C mint stay off that surface. This
//! crate may Check a Case C [`sociacl_core::Client`] the way the rest
//! of SociACL does.
//!
//! See [docs/s3rch-check.md](../../docs/s3rch-check.md) and
//! [docs/gun.md](../../docs/gun.md).

mod adapter;
mod error;
mod feed;
mod hint;
mod leaf;
mod soul;

pub use adapter::{
    accept_hint, accept_hint_bytes, add_claim, add_feed_node, add_item, add_wallet,
    apply_see_grant, cancel, check, check_execute, check_see, check_see_grant, client_check,
    client_elect_from_hint, client_mint_grant, client_remint, elect_from_delegate, elect_from_hint,
    map_action, remint, GunCheckResult,
};
pub use error::GunError;
pub use feed::{
    from_gun_node, item_key, to_gun_node, FeedItem, FeedMeta, FeedSource, FeedTab, GunFeedNode,
    GunUserNode, IdentityClaimKind, IdentitySeeGrant, OffGraphKind,
};
pub use hint::{HandoffHint, MAGIC as HINT_MAGIC, VERSION as HINT_VERSION};
pub use leaf::{normalize_permalink, normalize_tags, split_tags, ItemShape, UrlLeaf};
pub use soul::{
    encode_key, GunNode, GunNodeKind, GunSoul, S3RCH_ITEMS, S3RCH_META, S3RCH_ROOT, S3RCH_USERS,
};

/// Lighter s3r.ch Check: `CHECK(see, object, accessor)` at now.
/// Object is a Gun-native feed item or held claim. Mapped onto Check `read`.
pub const SEE: &str = "see";
