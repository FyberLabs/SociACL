use thiserror::Error;

/// Fail-closed errors for the encrypted-discovery slice.
///
/// Messages name the check that failed. They do not include key bytes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EncDiscError {
    #[error("account id is empty")]
    EmptyAccount,
    #[error("device id is empty")]
    EmptyDevice,
    #[error("SEA key is not a P-256 point")]
    BadKey,
    #[error("lane id is not 32 lowercase hex bytes")]
    BadLane,
    #[error("revision id is not SHA-256 lowercase hex")]
    BadRevision,
    #[error("decimal is not canonical")]
    BadDecimal,
    #[error("canonical field is longer than uint32")]
    FieldTooLong,
    #[error("wrap target is not in the named set")]
    UnnamedReader,
    #[error("named set or reader list has a duplicate")]
    DuplicateName,
    #[error("account binding rejected")]
    BindingRejected,
    #[error("epub is required")]
    EpubRequired,
    #[error("identity pub is missing")]
    IdentityPubMissing,
    #[error("pub does not match the enrolled account key")]
    PubMismatch,
    #[error("epub does not match the enrolled account key")]
    EpubMismatch,
    #[error("signature rejected")]
    SignatureRejected,
    #[error("wrap rejected")]
    WrapRejected,
    #[error("wrap scope and target are not a defined pair")]
    ScopeRejected,
    #[error("object id is empty")]
    EmptyObject,
    #[error("group id is empty")]
    EmptyGroup,
    #[error("length-prefixed encoding is not canonical")]
    BadEncoding,
    #[error("commitment rejected")]
    CommitmentRejected,
    #[error("grant payload rejected")]
    PayloadRejected,
    #[error("blinded row rejected")]
    RowRejected,
    #[error("author unwrap rejected")]
    AuthorUnwrapRejected,
    #[error("presenter binding rejected")]
    PresenterRejected,
    #[error("epoch status rejected")]
    StatusRejected,
    #[error("epoch rejected")]
    EpochRejected,
    #[error("rotation rejected")]
    RotationRejected,
    #[error("migration rejected")]
    MigrationRejected,
    #[error("channel rejected")]
    ChannelRejected,
    #[error("digest rejected")]
    DigestRejected,
    #[error("forbidden hop")]
    ForbiddenHop,
    #[error("inbox append rejected")]
    InboxRejected,
    #[error("not a principal ({0})")]
    NotPrincipal(String),
    #[error("identity rejected ({0})")]
    IdentityRejected(String),
    #[error("wrap store rejected")]
    StoreRejected,
}
