use sociacl_core::{CheckError, VerbError};
use thiserror::Error;

/// Adapter errors. Decode of an untrusted hint fails closed.
/// A present hint never becomes a grant by itself.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum GunError {
    #[error("handoff hint is corrupt")]
    HintCorrupt,
    #[error("unsupported handoff hint version {0}")]
    UnsupportedHintVersion(u16),
    #[error("handoff hint principal is empty")]
    EmptyPrincipal,
    #[error("handoff hint target is empty")]
    EmptyTarget,
    #[error("URL leaf is not a Gun node and not an ACL grant")]
    UrlLeafNotANode,
    #[error("permalink URL is not a leaf pointer")]
    InvalidUrl,
    #[error("elect does not fire on a handoff hint")]
    ElectFromHint,
    #[error("Case C client has no mint path for new Gun grants")]
    ClientHasNoMintPath,
    #[error("dest ACL write is owner-only")]
    AclOwnerOnly,
    #[error("mesh object is not in-graph")]
    ObjectNotInGraph,
    #[error("group name is empty")]
    EmptyGroupName,
    #[error("set owner is unknown")]
    SetUnknown,
    #[error("set already has an owner")]
    SetOwnerConflict,
    #[error("set id is not bound to this owner")]
    UnboundSetOwner,
    #[error("membership speaker is not the member or the set owner")]
    MembershipSpeaker,
    #[error("signer is not enrolled")]
    SignerNotEnrolled,
    #[error("row signature is not valid")]
    RowSignature,
    #[error("post grant field is not a canonical integer")]
    PostGrantField,
    #[error("access request field is not canonical")]
    AccessRequestField,
    #[error("a withdrawn request does not grant")]
    AccessRequestWithdrawn,
    #[error("members auto-approve did not allow")]
    AccessRequestNotMember,
    #[error("check rejected: {0}")]
    Check(CheckError),
    #[error("{0}")]
    Verb(VerbError),
}

impl From<CheckError> for GunError {
    fn from(e: CheckError) -> Self {
        Self::Check(e)
    }
}

impl From<VerbError> for GunError {
    fn from(e: VerbError) -> Self {
        Self::Verb(e)
    }
}
