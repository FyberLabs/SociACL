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
    #[error("witnessed encryption public key is unknown")]
    EpubUnknown,
    #[error("encryption public key is already held")]
    EpubReuse,
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
    #[error("recovery rejected")]
    RecoveryRejected,
    #[error("recovery parameters rejected")]
    RecoveryParams,
    /// The passphrase failed the seal-time strength gate.
    ///
    /// `warning` and `suggestions` are for the UI. This error does not
    /// contain the passphrase, and callers must not log the passphrase.
    #[error("recovery passphrase is too weak")]
    RecoveryWeakPassphrase {
        score: u8,
        warning: String,
        suggestions: Vec<String>,
    },
    #[error("recovery copy is stale")]
    RecoveryStale,
    #[error("keyring is too large")]
    KeyringTooLarge,
    /// Missing contact-lane secret, missing prior history, or a rotation
    /// sequence that is not a safe non-negative integer.
    #[error("keyring-rejected")]
    KeyringRejected,
    /// Stale, forged, tampered, and misaddressed contact-lane grants share this.
    /// The caller does not choose the code.
    #[error("lane-grant-rejected")]
    LaneGrantRejected,
}
