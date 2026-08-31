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
