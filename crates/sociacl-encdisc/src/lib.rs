//! Encrypted-discovery reference slice.
//!
//! This crate implements the account SEA key, device enrollment, the
//! wrapped-key edge, blinded grant rows, commitment opening, author fast
//! unwrap, [`check_presented_grant`], and inbox admission. Canonical ids
//! are checked against `vectors/encrypted-discovery/`. The read-key half
//! of [`epoch_step_current`] runs inside that check. Epoch publication,
//! rotation, migration, and a shard-close watermark are not in this slice.
//!
//! s3r.ch copies `docs/s3rch-check.d.ts` and reimplements that contract
//! in TypeScript. It does not import this crate. `sociacl-gun` evaluates
//! plaintext `MeshSeeGrant` rows and direct `same-group` / `named-circle`
//! edges. It does not evaluate a wrap. This crate does not change that
//! Check. A hop, a hint, or a wrap never mints. SEA `priv` and `epriv`
//! are not on the Gun public view.
//!
//! # Wire choices
//!
//! Where the spec names SEA primitives but not the byte layout, this
//! crate fails closed:
//!
//! * `pub` and `epub` are SEA JWK coordinates, `base64url(x).base64url(y)`,
//!   no padding. `priv` and `epriv` are base64url of the 32-byte scalar.
//! * A signature is P-256 ECDSA-SHA256 over the length-prefixed bytes,
//!   once. The string is lowercase hex of low-s IEEE P1363 `r || s`.
//!   A SEA `{m,s}` envelope, a DER encoding, or a high-s encoding does
//!   not verify.
//! * A reader wrap is ECDH P-256. The shared secret is the 32-byte x
//!   coordinate. The AES-256-GCM key is SHA-256 of the length-prefixed
//!   fields `s3rch-sea-secret-v1` and the lowercase hex of that
//!   coordinate. SEA.encrypt's password salt envelope is not this wrap.
//! * A group-epoch wrap has no reader `epub`. Its AES key is SHA-256 of
//!   `s3rch-group-epoch-wrap-v1` and the lowercase hex of the 32-byte
//!   group key.
//! * The AES-GCM plaintext is the length-prefixed wrapped-key fields,
//!   including `revisionId` and the key. The cleartext label on
//!   [`WrappedKey`] must match. Version `1` is a reader wrap (65-byte
//!   uncompressed ephemeral point, 12-byte nonce, ciphertext and tag).
//!   Version `2` is a group-epoch wrap (nonce, ciphertext and tag).
//! * `keyCommitment` stays an opaque string. This slice does not define it.
//! * `laneId` is 32 random bytes chosen when the account key is minted.
//!   Enrollment copies it. It is not derived from the account id.
//! * A grant commitment is SHA-256 of the length-prefixed blinding and
//!   the canonical grant. The blinding is not on the visible row.
//! * A presenter binding is a P-256 signature over the length-prefixed
//!   domain, nonce, commitment hash, and verifier audience.
//! * `AuthenticatedPresenterChannel` is minted only by its `open`
//!   constructor. `AuthenticatedWriterChannel` is minted only by
//!   `open_with_possession`, after a signature over
//!   `s3rch-writer-channel-v1` and the writer id verifies. The private
//!   brand is not a public field.
//! * A writer append and an inbox stamp are P-256 signatures over the
//!   length-prefixed domain and `entryId`. Proof-of-work is SHA-256 of
//!   the length-prefixed domain, nonce, `entryId`, and solution.
//! * The relay that accepts an append learns the writer id. The stored
//!   row does not carry it. An append and an opened wrap never grant.

#![forbid(unsafe_code)]

mod account;
mod canonical;
mod epoch;
mod error;
mod grant;
mod hexutil;
mod inbox;
mod present;
mod presenter;
mod sea;
mod see;
mod wrap;
mod writer;

pub use account::{
    accept_first_contact, verify_item_auth, AcceptedIntro, AccountKeyBinding, AccountSeaKey,
    AccountSeaSecret, DeviceEnrollment, EnrolledSeaPub, FirstContactIntro, RecipientInbox,
};
pub use canonical::{
    account_binding_bytes, account_binding_sha256, canonical_decimal, decode_length_prefixed,
    epoch_finalization_bytes, epoch_finalization_id, epoch_revision_bytes, epoch_revision_id,
    epoch_status_bytes, epoch_status_sha256, grant_commitment_bytes, grant_commitment_hash,
    grant_payload_bytes, grant_payload_digest, inbox_entry_bytes, inbox_entry_encoded_len,
    inbox_entry_id, inbox_pow_bytes, inbox_pow_digest, inbox_pow_sha256, inbox_stamp_bytes,
    inbox_stamp_sha256, item_auth_bytes, item_auth_sha256, leading_zero_bits, length_prefixed,
    parse_canonical_decimal, plaintext_digest, presenter_binding_bytes, presenter_binding_sha256,
    sha256, sha256_fields, sha256_hex, writer_append_bytes, writer_append_sha256,
    writer_channel_bytes, writer_channel_sha256, EpochManifestBody, EpochStatusBody,
    GrantPayloadBody, InboxEntryBody, InboxWrapFields, ItemAuthFields, DOMAIN_ACCOUNT_BINDING,
    DOMAIN_EPOCH, DOMAIN_EPOCH_FINALIZATION, DOMAIN_EPOCH_STATUS, DOMAIN_GRANT_COMMITMENT,
    DOMAIN_GRANT_PAYLOAD, DOMAIN_GROUP_WRAP, DOMAIN_INBOX, DOMAIN_INBOX_POW, DOMAIN_INBOX_STAMP,
    DOMAIN_ITEM_AUTH, DOMAIN_PRESENTER_BINDING, DOMAIN_SEA_SECRET, DOMAIN_WRAPPED_KEY,
    DOMAIN_WRITER_APPEND, DOMAIN_WRITER_CHANNEL, JS_SAFE_INTEGER_MAX,
};
pub use epoch::{
    epoch_read_key, epoch_step_current, status_is_fresh, AclObjectSet, AclScope, AclSnapshotBody,
    AclSnapshotEntry, EpochFinalization, EpochReadKey, EpochReplicaView, EpochStatusProof,
    LightZookie, SETTLE_WINDOW_DEFAULT_MS, SETTLE_WINDOW_MAX_MS, SETTLE_WINDOW_MIN_MS,
};
pub use error::EncDiscError;
pub use grant::{
    commit_grant, decode_grant_bytes, encode_grant_bytes, fresh_blinding, grant_digest,
    inbox_body_of, open_commitment, row_entry_matches, row_exposes_opening, seal_blinded_row,
    AuthorFastUnwrap, BlindedGrantRow, GrantCommitment, GrantPresentation, GrantStated,
    MeshSeeGrant, SignedGrantPayload,
};
pub use inbox::{
    filter_inbox_append, lane_id_is_opaque, lanes_per_device, replicated_row_admitted,
    scan_daily_shard, shard_close_watermark_implemented, shard_scan_uses_device_cursor,
    stored_row_reveals_writer, writer_from_stored_row, AdmissionChallenge, AdmissionEvidence,
    DailyShardScan, InboxAdmission, InboxAppendResult, InboxLane, InboxWriteDecision,
    InboxWriteFilter, InboxWriteHook, InboxWritePolicy, ReaderInboxes, SenderQuota, ShardScan,
    VerifierAdmissionState, INBOX_ENTRY_MAX_BYTES,
};
pub use present::{
    check_presented_grant, PresentedGrantDecision, PresentedGrantInput, VerifierGrantRevision,
    VerifierGrantRevisionState,
};
pub use presenter::{
    binding_for, verify_presenter_binding, AuthenticatedPresenterChannel, PresenterBinding,
    PresenterChallenge, VerifierChallengeState,
};
pub use sea::{sign_sea, verify_sea};
pub use see::{
    check_group_see, check_opened_grant, hop_forbidden, CheckResult, GroupPredicate, HandoffHint,
    HopFactor, IdentitySeeGrant, MeshMembership, ObjectSetName, PresentedGroup, SeeGraph,
};
pub use wrap::{
    open_group_epoch_wrap, open_reader_wrap, wrap_group_key_to_members,
    wrap_item_dek_to_group_epoch, wrap_item_dek_to_readers, GroupEpochKey, ItemDek, NamedSet,
    OpenedWrap, WrapScope, WrapTarget, WrappedKey,
};
#[cfg(any(test, feature = "deterministic-wrap"))]
pub use wrap::{
    wrap_group_key_to_members_with, wrap_item_dek_to_group_epoch_with,
    wrap_item_dek_to_readers_with, DetachedEphemeral,
};
pub use writer::{
    signature_covers_claimed_id, verify_inbox_envelope, AuthenticatedWriterChannel, InboxEnvelope,
    WriterAppendAuth, WriterAppendProof,
};
