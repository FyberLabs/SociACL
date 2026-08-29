use thiserror::Error;

use crate::types::{NodeId, PredicateId};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CheckError {
    #[error("unknown predicate {0}; fail closed")]
    UnknownPredicate(PredicateId),
    #[error("object {0} not found")]
    ObjectNotFound(NodeId),
    #[error("object {0} destroyed")]
    ObjectDestroyed(NodeId),
    #[error("accessor {0} not found")]
    AccessorNotFound(NodeId),
    #[error("object {0} does not name a predicate; fail closed")]
    ObjectPredicateMissing(NodeId),
    #[error(
        "requested predicate {requested} does not match object predicate {named}; fail closed"
    )]
    PredicateMismatch {
        requested: PredicateId,
        named: PredicateId,
    },
    #[error("attestation rejected: {0}")]
    AttestationRejected(AttestationError),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum VerbError {
    #[error("object {0} not found")]
    ObjectNotFound(NodeId),
    #[error("object {0} destroyed")]
    ObjectDestroyed(NodeId),
    #[error("principal {0} not found")]
    PrincipalNotFound(NodeId),
    #[error("principal {0} authn is not live")]
    AuthnNotLive(NodeId),
    #[error("ACL does not name principal {0} on {1}")]
    AclDoesNotNamePrincipal(NodeId, NodeId),
    #[error("no will written while alive for {0}")]
    NoWill(NodeId),
    #[error("will for {0} was canceled")]
    WillCanceled(NodeId),
    #[error("keep-operating would suffice for {0}; elect refused")]
    KeepOperatingSuffices(NodeId),
    #[error("will for {0} prescribes destroy, not elect")]
    WillPrescribesDestroy(NodeId),
    #[error("will for {0} names an heir; destroy refused")]
    HasHeir(NodeId),
    #[error("testator {0} must be the live owner to write a will")]
    CannotWriteWill(NodeId),
    #[error("principal {0} may not cancel this will")]
    CannotCancel(NodeId),
    #[error("will must be written while testator authn is live")]
    TestatorNotAlive,
    #[error("invalid will: {0}")]
    InvalidWill(WillError),
    #[error("elect does not fire on an attestation")]
    ElectDoesNotFireOnAttestation,
    #[error("will for {0} has no elect path")]
    NoElectPath(NodeId),
    #[error("will for {0} has no destroy path")]
    NoDestroyPath(NodeId),
    #[error("not enough live cancelers to elect on {0}")]
    CannotElectWithoutCancelers(NodeId),
    #[error("attestation rejected: {0}")]
    AttestationRejected(AttestationError),
    #[error("elect on {0} is already pending")]
    ElectPending(NodeId),
    #[error("no pending elect on {0}")]
    ElectNotPending(NodeId),
    #[error("elect wait has not elapsed on {0}")]
    ElectWaitNotElapsed(NodeId),
    #[error("will for {0} was written after the cut")]
    PostCutWill(NodeId),
    #[error("attestation issuer {0} is not a remint issuer named by the will")]
    RemintIssuerNotNamed(NodeId),
    #[error("client path refuses elect; silence is not a vote")]
    ClientRefusesElect,
    #[error("rejoin will not union post-cut memberships")]
    RejoinUnionRefused,
    #[error("rejoin requires the same pre-cut")]
    RejoinCutMismatch,
    #[error("rejoin quorum is unavailable; stay degraded")]
    RejoinQuorumUnavailable,
    #[error("bundle contains post-cut material")]
    PostCutMaterial,
    #[error("principal {0} has no pre-cut right to hold a share of {1}")]
    NoHeldShare(NodeId, NodeId),
    #[error("principal {0} has no pre-cut share to export")]
    NothingToExport(NodeId),
    #[error("share reconstruction failed for {0}")]
    ShareReconstruct(NodeId),
    #[error("bundle encoding is corrupt")]
    BundleCorrupt,
    #[error("unsupported bundle version {0}")]
    UnsupportedBundleVersion(u16),
    #[error("bundle io failed")]
    BundleIo,
    #[error("bundle signature is missing or does not verify")]
    BundleSignature,
    #[error("holder secret required to export or open a bundle")]
    HolderSecretRequired,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AttestationError {
    #[error("issuer {0} is not enrolled; oracle refuses")]
    NotEnrolled(NodeId),
    #[error("issuer {0} is not a graph node")]
    IssuerNotFound(NodeId),
    #[error("issuer {0} was enrolled after the cut")]
    PostCutEnrollment(NodeId),
    #[error("attestation issued after the cut")]
    PostCutAttestation,
    #[error("forbidden claim {0}")]
    ForbiddenClaim(String),
    #[error("unnamed claim {0}; fail closed")]
    UnnamedClaim(String),
    #[error("claim {0} is not a Check factor")]
    CheckMustNotConsume(String),
    #[error("claim {0} is not a Remint factor")]
    RemintMustNotConsume(String),
    #[error("attestation binding does not match the current snapshot")]
    BindingMismatch,
    #[error("attestation signature does not match the statement")]
    BadSignature,
    #[error("enrollment has no valid verify key; fail closed")]
    InvalidVerifyKey,
    #[error("attestation subject {0} is not the named principal")]
    SubjectMismatch(NodeId),
    #[error("enrollment kind {0} is unnamed")]
    UnnamedEnrollmentKind(String),
    #[error("forbidden channel {0}")]
    ForbiddenChannel(String),
    #[error("unnamed channel {0}; fail closed")]
    UnnamedChannel(String),
    #[error("channel {0} is not allowed for this verb")]
    ChannelMustNotConsume(String),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum WillError {
    #[error("{0}")]
    Parse(String),
    #[error("unnamed verb {0}; fail closed")]
    UnnamedVerb(String),
    #[error("dead-hand shape {0}; fail closed")]
    DeadHand(String),
    #[error("clock mix: {0}")]
    ClockMix(String),
    #[error("issuer {0} is not enrolled")]
    MissingEnrollment(NodeId),
    #[error("elect clause must name clock elect")]
    ElectClockRequired,
    #[error("elect without cancel is automatic seizure; fail closed")]
    ElectRequiresCancel,
    #[error("heir-template is never a will verb or a Check predicate")]
    HeirTemplate,
    #[error("vacancy listing is forbidden")]
    VacancyAd,
    #[error("node {0} not found")]
    NodeNotFound(NodeId),
    #[error("will has no clauses")]
    Empty,
}
