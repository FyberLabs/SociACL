//! Length-prefixed UTF-8 encodings shared by the contract.
//!
//! Each field is a uint32 little-endian byte length, then the UTF-8
//! bytes. An empty field is four zero bytes. Integers are ASCII
//! decimal with no sign and no leading zeros. The value 0 is the
//! single byte `0x30`. The id is SHA-256 of that encoding, lowercase
//! hex. A hex encoding of the raw body is not the id.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::EncDiscError;

pub const DOMAIN_INBOX: &str = "s3rch-inbox-entry-v1";
pub const DOMAIN_EPOCH: &str = "s3rch-epoch-revision-v1";
pub const DOMAIN_ITEM_AUTH: &str = "s3rch-item-auth-v1";
pub const DOMAIN_ACCOUNT_BINDING: &str = "s3rch-account-binding-v1";
pub const DOMAIN_SEA_SECRET: &str = "s3rch-sea-secret-v1";
pub const DOMAIN_GROUP_WRAP: &str = "s3rch-group-epoch-wrap-v1";
pub const DOMAIN_WRAPPED_KEY: &str = "s3rch-wrapped-key-v1";

/// Cleartext fields that `inboxEntryId` hashes. `wrap` is absent or present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxEntryBody {
    pub lane_id: String,
    pub grant_ciphertext: String,
    pub commitment_hash: String,
    pub wrap: Option<InboxWrapFields>,
}

/// Cleartext wrap fields inside an inbox entry id.
///
/// Absent `object` or `group` encodes the same as an empty string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxWrapFields {
    pub scope: String,
    pub epoch: u64,
    pub target: String,
    pub target_id: String,
    pub object: Option<String>,
    pub group: Option<String>,
    pub revision_id: String,
    pub wrapped_key: String,
}

/// Canonical epoch manifest body. `revisionId` is the hash of this
/// encoding, not of the signature and not of `revisionId` itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochManifestBody {
    pub object: String,
    pub epoch: u64,
    pub previous_epoch: u64,
    pub device_id: String,
    pub key_commitment: String,
    pub settle_window_ms: u64,
    pub acl_snapshot: String,
}

/// Item-auth tuple. The signature covers these fields and is not one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemAuthFields {
    pub object: String,
    pub epoch: u64,
    pub version: u64,
    pub plaintext_digest: String,
    pub revision_id: String,
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    digest.zeroize();
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::hexutil::encode_hex(&sha256(bytes))
}

pub fn length_prefixed(fields: &[&str]) -> Result<Vec<u8>, EncDiscError> {
    let mut out = Vec::new();
    for field in fields {
        let raw = field.as_bytes();
        let len = u32::try_from(raw.len()).map_err(|_| EncDiscError::FieldTooLong)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(raw);
    }
    Ok(out)
}

pub fn sha256_fields(fields: &[&str]) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&length_prefixed(fields)?))
}

/// Largest integer JavaScript `Number.isSafeInteger` accepts.
///
/// Rust and the TypeScript contract both reject a larger decimal.
pub const JS_SAFE_INTEGER_MAX: u64 = (1 << 53) - 1;

/// ASCII decimal. `0` is `"0"`. No leading zeros.
///
/// Values above [`JS_SAFE_INTEGER_MAX`] are `BadDecimal`.
pub fn canonical_decimal(value: u64) -> Result<String, EncDiscError> {
    if value > JS_SAFE_INTEGER_MAX {
        return Err(EncDiscError::BadDecimal);
    }
    Ok(value.to_string())
}

pub fn parse_canonical_decimal(text: &str) -> Result<u64, EncDiscError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EncDiscError::BadDecimal);
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(EncDiscError::BadDecimal);
    }
    let value = text.parse::<u64>().map_err(|_| EncDiscError::BadDecimal)?;
    if value > JS_SAFE_INTEGER_MAX {
        return Err(EncDiscError::BadDecimal);
    }
    Ok(value)
}

fn empty_as_blank(value: Option<&str>) -> &str {
    match value {
        Some(text) if !text.is_empty() => text,
        _ => "",
    }
}

pub fn inbox_entry_bytes(body: &InboxEntryBody) -> Result<Vec<u8>, EncDiscError> {
    let epoch = match &body.wrap {
        Some(wrap) => canonical_decimal(wrap.epoch)?,
        None => String::new(),
    };
    let (flag, scope, target, target_id, object, group, revision, wrapped) = match &body.wrap {
        Some(wrap) => (
            "1",
            wrap.scope.as_str(),
            wrap.target.as_str(),
            wrap.target_id.as_str(),
            empty_as_blank(wrap.object.as_deref()),
            empty_as_blank(wrap.group.as_deref()),
            wrap.revision_id.as_str(),
            wrap.wrapped_key.as_str(),
        ),
        None => ("0", "", "", "", "", "", "", ""),
    };
    length_prefixed(&[
        DOMAIN_INBOX,
        &body.lane_id,
        &body.grant_ciphertext,
        &body.commitment_hash,
        flag,
        scope,
        &epoch,
        target,
        target_id,
        object,
        group,
        revision,
        wrapped,
    ])
}

pub fn inbox_entry_id(body: &InboxEntryBody) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&inbox_entry_bytes(body)?))
}

pub fn epoch_revision_bytes(body: &EpochManifestBody) -> Result<Vec<u8>, EncDiscError> {
    let epoch = canonical_decimal(body.epoch)?;
    let previous = canonical_decimal(body.previous_epoch)?;
    let window = canonical_decimal(body.settle_window_ms)?;
    length_prefixed(&[
        DOMAIN_EPOCH,
        &body.object,
        &epoch,
        &previous,
        &body.device_id,
        &body.key_commitment,
        &window,
        &body.acl_snapshot,
    ])
}

pub fn epoch_revision_id(body: &EpochManifestBody) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&epoch_revision_bytes(body)?))
}

pub fn item_auth_bytes(fields: &ItemAuthFields) -> Result<Vec<u8>, EncDiscError> {
    let epoch = canonical_decimal(fields.epoch)?;
    let version = canonical_decimal(fields.version)?;
    length_prefixed(&[
        DOMAIN_ITEM_AUTH,
        &fields.object,
        &epoch,
        &version,
        &fields.plaintext_digest,
        &fields.revision_id,
    ])
}

pub fn item_auth_sha256(fields: &ItemAuthFields) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&item_auth_bytes(fields)?))
}

pub fn account_binding_bytes(
    account: &str,
    sea_pub: &str,
    epub: &str,
) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(&[DOMAIN_ACCOUNT_BINDING, account, sea_pub, epub])
}

pub fn account_binding_sha256(
    account: &str,
    sea_pub: &str,
    epub: &str,
) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&account_binding_bytes(account, sea_pub, epub)?))
}

/// SHA-256 of the raw plaintext, lowercase hex. Not a hex encoding of the text.
pub fn plaintext_digest(plaintext: &[u8]) -> String {
    sha256_hex(plaintext)
}

pub fn require_revision_id(revision_id: &str) -> Result<(), EncDiscError> {
    if revision_id.len() != 64 {
        return Err(EncDiscError::BadRevision);
    }
    if crate::hexutil::decode_hex(revision_id).is_err() {
        return Err(EncDiscError::BadRevision);
    }
    Ok(())
}

pub fn require_digest_hex(digest: &str) -> Result<(), EncDiscError> {
    if digest.len() != 64 || crate::hexutil::decode_hex(digest).is_err() {
        return Err(EncDiscError::BadRevision);
    }
    Ok(())
}
