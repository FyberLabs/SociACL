//! SociACL core: social-graph authority plane.
//!
//! Live [`Plane::check`] is server-evaluated against an in-memory graph.
//! Case C (plane gone or hostile) is types and comments only.

pub mod attestation;
pub mod cache;
pub mod check;
pub mod error;
pub mod graph;
pub mod types;
pub mod verbs;
pub mod will;

pub use attestation::{
    Attestation, AttestationBinding, AttestationClaim, AttestationFactor, AttestationSig,
    Enrollment, EnrollmentKind,
};
pub use cache::{
    CacheAnchors, CacheKey, EdgeTypeSet, HashCache, MemoryHashCache, Snapshot, SnapshotHash, Zookie,
};
pub use check::{CheckRequest, CheckResult, ParsedObject};
pub use error::{AttestationError, CheckError, VerbError, WillError};
pub use graph::{Plane, DEFAULT_PRIVILEGE_UP_DELAY};
pub use types::{
    Action, AuthnState, Capability, ClientHeldShare, Clock, CutBoundary, DestroyResult, Device,
    DiscoverResult, Edge, ElectResult, NodeId, NodeKind, Object, ObjectKind, ObjectProperties,
    ObjectVersion, PosixBits, PosixMode, PredicateId, Principal, Relation, Timestamp, Verb,
};
pub use will::{
    DestroyMaterial, Will, WillBody, WillClause, WillDisposition, WillSubject, WillValidateCtx,
};

/// Hopcap for named-circle (and any future walk). This cut is 1.
pub const HOPCAP: u32 = 1;
