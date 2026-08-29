//! SociACL core: social-graph authority plane.
//!
//! Live [`Plane::check`] is server-evaluated against an in-memory graph.
//! Case C writes a durable [`CutBundle`] and evaluates the same named
//! predicates offline on [`Client`]. Elect stays refuse-closed on that path.

pub mod attestation;
pub mod bundle;
pub mod cache;
pub mod check;
pub mod client;
mod codec;
pub mod error;
pub mod graph;
pub mod types;
pub mod verbs;
pub mod will;

pub use attestation::{
    Attestation, AttestationBinding, AttestationClaim, AttestationFactor, AttestationSig,
    Enrollment, EnrollmentKind,
};
pub use bundle::CutBundle;
pub use cache::{
    CacheAnchors, CacheKey, EdgeTypeSet, HashCache, MemoryHashCache, Snapshot, SnapshotHash, Zookie,
};
pub use check::{CheckRequest, CheckResult, ParsedObject};
pub use client::Client;
pub use error::{AttestationError, CheckError, VerbError, WillError};
pub use graph::{Plane, DEFAULT_ELECT_WAIT, DEFAULT_PRIVILEGE_UP_DELAY};
pub use types::{
    Action, AuthnState, Capability, ClientHeldShare, Clock, CutBoundary, DestroyResult, Device,
    DiscoverResult, Edge, ElectResult, ElectState, NodeId, NodeKind, Object, ObjectKind,
    ObjectProperties, ObjectVersion, PendingElect, PosixBits, PosixMode, PredicateId, Principal,
    Relation, Timestamp, Verb,
};
pub use will::{
    DestroyMaterial, Will, WillBody, WillClause, WillDisposition, WillSubject, WillValidateCtx,
};

/// Hopcap for named-circle (and any future walk). This cut is 1.
pub const HOPCAP: u32 = 1;
