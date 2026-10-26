//! GunDB signed mesh admission, Check, and transport types.
//!
//! Ownership enters only through [`MeshSeeGraph::put_object`], which verifies a
//! signed `sociacl-object-v2` record with authenticated identity history. Checks
//! use that admitted record; neither a caller-supplied owner nor a core
//! [`sociacl_core::Plane`] can supply mesh authority. Feed ids, hints, and URL
//! leaves remain data. A hop, hint, wrap, request, or inbox delivery never grants.
//!
//! The former core-plane adapter is removed. Use `MeshSeeGraph` for signed Gun
//! objects and grants. The generic core plane remains a separate trusted API.
//! C/Python expose Gun hint transport and URL normalization only; there is no
//! signed mesh C/Python binding yet. See [docs/gun.md](../../docs/gun.md).
//!
//! Unsigned ownership and core-plane checks are deliberately unavailable:
//! ```compile_fail,E0432
//! use sociacl_gun::add_claim;
//! ```
//! ```compile_fail,E0432
//! use sociacl_gun::add_item;
//! ```
//! ```compile_fail,E0432
//! use sociacl_gun::add_feed_node;
//! ```
//! ```compile_fail,E0432
//! use sociacl_gun::check;
//! ```
//! ```compile_fail,E0432
//! use sociacl_gun::check_see;
//! ```
//! ```compile_fail,E0432
//! use sociacl_gun::client_check;
//! ```

mod adapter;
mod error;
mod feed;
mod group;
mod hint;
mod hop;
mod leaf;
mod mesh;
mod post;
mod request;
mod soul;

pub use adapter::{accept_hint, accept_hint_bytes, map_action};
pub use error::GunError;
pub use feed::{
    from_gun_node, to_gun_node, FeedItem, FeedMeta, FeedSource, FeedTab, GunFeedNode, GunUserNode,
    IdentityClaimKind, IdentitySeeGrant, OffGraphKind,
};
pub use group::{
    DecodedGroupPayload, GroupPredicate, GroupPresentation, GroupSnapshotMember,
    GroupSnapshotObjectSet, MeshMembership, ObjectSetName, PresentedGroup,
};
pub use hint::{HandoffHint, MAGIC as HINT_MAGIC, VERSION as HINT_VERSION};
pub use hop::{accept_hop, accept_hop_bytes, decode_hop, HopFactor};
pub use leaf::{normalize_permalink, normalize_tags, split_tags, ItemShape, UrlLeaf};
pub use mesh::{
    factor_grants, GunAclEdge, MeshCheckResult, MeshSeeGrant, MeshSeeGraph, MESH_REASON_ACL,
    MESH_REASON_CANCELLED, MESH_REASON_DELEGATE, MESH_REASON_META, MESH_REASON_MISSING,
    MESH_REASON_OWNER, MESH_REASON_URL_LEAF,
};
pub use post::MESH_REASON_POST;
pub use request::{request_owner, ApprovedRequest};
pub use sociacl_ids::{membership_soul, object_set_soul};
pub use soul::{GunNode, GunNodeKind, GunSoul, S3RCH_ACL, S3RCH_META, S3RCH_ROOT};

/// Lighter s3r.ch Check: `CHECK(see, object, accessor)` at now.
/// Object must have an admitted signed object record. A derived feed or claim
/// id alone does not establish ownership. Hop is an optional factor.
pub const SEE: &str = "see";

#[cfg(test)]
mod group_predicate_tests;
