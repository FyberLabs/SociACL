//! Encrypted-discovery reference slice.
//!
//! This crate implements the first slice of
//! [docs/encrypted-discovery.md](../../docs/encrypted-discovery.md):
//! one SEA keypair per account, device enrollment, and the wrapped-key
//! edge. Canonical ids for an inbox entry, an epoch revision, and the
//! item-auth tuple are checked against
//! `vectors/encrypted-discovery/canonical.json`.
//!
//! s3r.ch copies `docs/s3rch-check.d.ts` and reimplements that contract
//! in TypeScript. It does not import this crate. `sociacl-gun` still
//! evaluates plaintext `MeshSeeGrant` rows only. This crate does not
//! change Check. A hop, a hint, or a wrap never mints. SEA `priv` and
//! `epriv` are not on the Gun public view.
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
//!
//! Epoch settlement, inbox admission, presenter binding, rotation, and
//! migration are not in this slice.

#![forbid(unsafe_code)]

mod account;
mod canonical;
mod error;
mod hexutil;
mod sea;
mod wrap;

pub use account::{
    accept_first_contact, verify_item_auth, AcceptedIntro, AccountKeyBinding, AccountSeaKey,
    AccountSeaSecret, DeviceEnrollment, EnrolledSeaPub, FirstContactIntro, RecipientInbox,
};
pub use canonical::{
    account_binding_bytes, account_binding_sha256, canonical_decimal, epoch_revision_bytes,
    epoch_revision_id, inbox_entry_bytes, inbox_entry_id, item_auth_bytes, item_auth_sha256,
    length_prefixed, parse_canonical_decimal, plaintext_digest, sha256, sha256_fields, sha256_hex,
    EpochManifestBody, InboxEntryBody, InboxWrapFields, ItemAuthFields, DOMAIN_ACCOUNT_BINDING,
    DOMAIN_EPOCH, DOMAIN_GROUP_WRAP, DOMAIN_INBOX, DOMAIN_ITEM_AUTH, DOMAIN_SEA_SECRET,
    DOMAIN_WRAPPED_KEY,
};
pub use error::EncDiscError;
pub use sea::{sign_sea, verify_sea};
pub use wrap::{
    open_group_epoch_wrap, open_reader_wrap, wrap_group_key_to_members,
    wrap_group_key_to_members_with, wrap_item_dek_to_group_epoch,
    wrap_item_dek_to_group_epoch_with, wrap_item_dek_to_readers, wrap_item_dek_to_readers_with,
    DetachedEphemeral, GroupEpochKey, ItemDek, NamedSet, OpenedWrap, WrapScope, WrapTarget,
    WrappedKey,
};
