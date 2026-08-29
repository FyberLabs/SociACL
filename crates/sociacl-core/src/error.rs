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
}
