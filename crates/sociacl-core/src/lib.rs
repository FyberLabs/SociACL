//! SociACL core: social-graph authority plane.
//!
//! Live [`Plane::check`] is server-evaluated against an in-memory graph.
//! Case C (plane gone or hostile) is types and comments only.

pub mod cache;
pub mod check;
pub mod error;
pub mod graph;
pub mod types;
pub mod verbs;

pub use cache::{CacheKey, HashCache, MemoryHashCache, Snapshot, SnapshotHash, Zookie};
pub use check::{CheckRequest, CheckResult};
pub use error::{CheckError, VerbError};
pub use graph::Plane;
pub use types::{
    Action, AuthnState, Capability, ClientHeldShare, Clock, CutBoundary, DestroyResult, Device,
    DiscoverResult, Edge, ElectResult, NodeId, NodeKind, Object, ObjectVersion, PredicateId,
    Principal, Relation, Timestamp, Verb, Will, WillDisposition, WillTemplate,
};

/// Hopcap for named-circle (and any future walk). This cut is 1.
pub const HOPCAP: u32 = 1;
