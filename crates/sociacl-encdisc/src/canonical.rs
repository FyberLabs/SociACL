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
pub const DOMAIN_GRANT_COMMITMENT: &str = "s3rch-grant-commitment-v1";
pub const DOMAIN_GRANT_PAYLOAD: &str = "s3rch-grant-payload-v1";
pub const DOMAIN_PRESENTER_BINDING: &str = "s3rch-presenter-binding-v1";
pub const DOMAIN_EPOCH_STATUS: &str = "s3rch-epoch-status-v1";
pub const DOMAIN_EPOCH_FINALIZATION: &str = "s3rch-epoch-finalization-v1";
pub const DOMAIN_WRITER_APPEND: &str = "s3rch-writer-append-v1";
pub const DOMAIN_WRITER_CHANNEL: &str = "s3rch-writer-channel-v1";
pub const DOMAIN_INBOX_POW: &str = "s3rch-inbox-pow-v1";
pub const DOMAIN_INBOX_STAMP: &str = "s3rch-inbox-stamp-v1";
pub const DOMAIN_ACL_SNAPSHOT: &str = "s3rch-acl-snapshot-v1";
pub const DOMAIN_EPOCH_MANIFEST_SIG: &str = "s3rch-epoch-manifest-sig-v1";
pub const DOMAIN_EPOCH_FINALIZATION_SIG: &str = "s3rch-epoch-finalization-sig-v1";
pub const DOMAIN_GROUP_EPOCH_CONFIG: &str = "s3rch-group-epoch-config-v1";

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

/// Byte length of a length-prefixed encoding, without building it.
///
/// A field longer than `u32::MAX`, or a total that does not fit in
/// `usize`, is [`EncDiscError::FieldTooLong`].
pub fn prefixed_total(fields: &[&str]) -> Result<usize, EncDiscError> {
    let lengths: Vec<usize> = fields.iter().map(|field| field.len()).collect();
    prefixed_total_lens(&lengths)
}

pub(crate) fn prefixed_total_lens(lengths: &[usize]) -> Result<usize, EncDiscError> {
    let mut total = 0usize;
    for &len in lengths {
        if len > u32::MAX as usize {
            return Err(EncDiscError::FieldTooLong);
        }
        total = total
            .checked_add(4 + len)
            .ok_or(EncDiscError::FieldTooLong)?;
    }
    Ok(total)
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

fn inbox_entry_fields<'a>(body: &'a InboxEntryBody, epoch: &'a str) -> [&'a str; 13] {
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
    [
        DOMAIN_INBOX,
        body.lane_id.as_str(),
        body.grant_ciphertext.as_str(),
        body.commitment_hash.as_str(),
        flag,
        scope,
        epoch,
        target,
        target_id,
        object,
        group,
        revision,
        wrapped,
    ]
}

pub fn inbox_entry_bytes(body: &InboxEntryBody) -> Result<Vec<u8>, EncDiscError> {
    let epoch = match &body.wrap {
        Some(wrap) => canonical_decimal(wrap.epoch)?,
        None => String::new(),
    };
    length_prefixed(&inbox_entry_fields(body, &epoch))
}

/// Canonical entry length. Does not allocate the encoding or hash it.
pub fn inbox_entry_encoded_len(body: &InboxEntryBody) -> Result<usize, EncDiscError> {
    let epoch = match &body.wrap {
        Some(wrap) => canonical_decimal(wrap.epoch)?,
        None => String::new(),
    };
    prefixed_total(&inbox_entry_fields(body, &epoch))
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

/// Split a length-prefixed encoding back into UTF-8 fields.
pub fn decode_length_prefixed(bytes: &[u8]) -> Result<Vec<String>, EncDiscError> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(EncDiscError::BadEncoding);
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let len = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;
        if bytes.len() - offset < len {
            return Err(EncDiscError::BadEncoding);
        }
        let field = std::str::from_utf8(&bytes[offset..offset + len])
            .map_err(|_| EncDiscError::BadEncoding)?;
        out.push(field.to_string());
        offset += len;
    }
    Ok(out)
}

/// Canonical grant fields the commitment hashes, after the blinding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantPayloadBody {
    pub object: String,
    pub accessor: String,
    pub from: u64,
    pub until: u64,
    pub stated: u64,
    pub epoch: u64,
    pub owner: String,
    pub grant_revision: u64,
    pub item_ciphertext_digest: String,
}

pub fn grant_commitment_bytes(
    blinding: &str,
    payload: &GrantPayloadBody,
) -> Result<Vec<u8>, EncDiscError> {
    let from = canonical_decimal(payload.from)?;
    let until = canonical_decimal(payload.until)?;
    let stated = canonical_decimal(payload.stated)?;
    let epoch = canonical_decimal(payload.epoch)?;
    let revision = canonical_decimal(payload.grant_revision)?;
    length_prefixed(&[
        DOMAIN_GRANT_COMMITMENT,
        blinding,
        &payload.object,
        &payload.accessor,
        &from,
        &until,
        &stated,
        &epoch,
        &payload.owner,
        &revision,
        &payload.item_ciphertext_digest,
    ])
}

pub fn grant_commitment_hash(
    blinding: &str,
    payload: &GrantPayloadBody,
) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&grant_commitment_bytes(blinding, payload)?))
}

pub fn grant_payload_bytes(payload: &GrantPayloadBody) -> Result<Vec<u8>, EncDiscError> {
    let from = canonical_decimal(payload.from)?;
    let until = canonical_decimal(payload.until)?;
    let stated = canonical_decimal(payload.stated)?;
    let epoch = canonical_decimal(payload.epoch)?;
    let revision = canonical_decimal(payload.grant_revision)?;
    length_prefixed(&[
        DOMAIN_GRANT_PAYLOAD,
        &payload.object,
        &payload.accessor,
        &from,
        &until,
        &stated,
        &epoch,
        &payload.owner,
        &revision,
        &payload.item_ciphertext_digest,
    ])
}

pub fn grant_payload_digest(payload: &GrantPayloadBody) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&grant_payload_bytes(payload)?))
}

pub fn presenter_binding_bytes(
    nonce: &str,
    commitment_hash: &str,
    audience: &str,
) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(&[DOMAIN_PRESENTER_BINDING, nonce, commitment_hash, audience])
}

pub fn presenter_binding_sha256(
    nonce: &str,
    commitment_hash: &str,
    audience: &str,
) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&presenter_binding_bytes(
        nonce,
        commitment_hash,
        audience,
    )?))
}

/// Owner-signed epoch/status bytes. The signature is not a field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStatusBody {
    pub object: String,
    pub epoch: u64,
    pub revision_id: String,
    pub accessor: String,
    pub grant_revision: u64,
    pub stated: u64,
    pub signed_at: u64,
    pub max_age_ms: u64,
    pub zookie_object: String,
    pub zookie_version: u64,
    pub zookie_snapshot: String,
}

pub fn epoch_status_bytes(body: &EpochStatusBody) -> Result<Vec<u8>, EncDiscError> {
    let epoch = canonical_decimal(body.epoch)?;
    let revision = canonical_decimal(body.grant_revision)?;
    let stated = canonical_decimal(body.stated)?;
    let signed_at = canonical_decimal(body.signed_at)?;
    let max_age = canonical_decimal(body.max_age_ms)?;
    let version = canonical_decimal(body.zookie_version)?;
    length_prefixed(&[
        DOMAIN_EPOCH_STATUS,
        &body.object,
        &epoch,
        &body.revision_id,
        &body.accessor,
        &revision,
        &stated,
        &signed_at,
        &max_age,
        &body.zookie_object,
        &version,
        &body.zookie_snapshot,
    ])
}

pub fn epoch_status_sha256(body: &EpochStatusBody) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&epoch_status_bytes(body)?))
}

pub fn epoch_finalization_bytes(
    object: &str,
    epoch: u64,
    previous_epoch: u64,
    revision_id: &str,
    previous_finalization_id: &str,
    candidates: &[String],
) -> Result<Vec<u8>, EncDiscError> {
    let epoch_text = canonical_decimal(epoch)?;
    let previous = canonical_decimal(previous_epoch)?;
    let mut fields = vec![
        DOMAIN_EPOCH_FINALIZATION.to_string(),
        object.to_string(),
        epoch_text,
        previous,
        revision_id.to_string(),
        previous_finalization_id.to_string(),
    ];
    fields.extend(candidates.iter().cloned());
    let borrowed: Vec<&str> = fields.iter().map(String::as_str).collect();
    length_prefixed(&borrowed)
}

pub fn writer_channel_bytes(writer: &str) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(&[DOMAIN_WRITER_CHANNEL, writer])
}

pub fn writer_channel_sha256(writer: &str) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&writer_channel_bytes(writer)?))
}

pub fn writer_append_bytes(entry_id: &str) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(&[DOMAIN_WRITER_APPEND, entry_id])
}

pub fn writer_append_sha256(entry_id: &str) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&writer_append_bytes(entry_id)?))
}

pub fn inbox_pow_bytes(
    nonce: &str,
    entry_id: &str,
    solution: &str,
) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(&[DOMAIN_INBOX_POW, nonce, entry_id, solution])
}

pub fn inbox_pow_digest(
    nonce: &str,
    entry_id: &str,
    solution: &str,
) -> Result<[u8; 32], EncDiscError> {
    Ok(sha256(&inbox_pow_bytes(nonce, entry_id, solution)?))
}

pub fn inbox_pow_sha256(
    nonce: &str,
    entry_id: &str,
    solution: &str,
) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&inbox_pow_bytes(nonce, entry_id, solution)?))
}

pub fn inbox_stamp_bytes(entry_id: &str) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(&[DOMAIN_INBOX_STAMP, entry_id])
}

pub fn inbox_stamp_sha256(entry_id: &str) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&inbox_stamp_bytes(entry_id)?))
}

/// Leading zero bits in a SHA-256 digest. Difficulty 0 accepts any digest.
pub fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0u32;
    for byte in digest {
        if *byte == 0 {
            count = count.saturating_add(8);
        } else {
            count = count.saturating_add(byte.leading_zeros());
            break;
        }
    }
    count
}

pub fn epoch_manifest_sig_bytes(revision_id: &str) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(&[DOMAIN_EPOCH_MANIFEST_SIG, revision_id])
}

pub fn epoch_finalization_sig_bytes(finalization_id: &str) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(&[DOMAIN_EPOCH_FINALIZATION_SIG, finalization_id])
}

/// Signed group-epoch config bytes. The signature is not a field.
pub fn group_epoch_config_bytes(
    owner: &str,
    set_id: &str,
    predicate: &str,
    settle_window_ms: u64,
    config_revision: u64,
) -> Result<Vec<u8>, EncDiscError> {
    let window = canonical_decimal(settle_window_ms)?;
    let revision = canonical_decimal(config_revision)?;
    length_prefixed(&[
        DOMAIN_GROUP_EPOCH_CONFIG,
        owner,
        set_id,
        predicate,
        &window,
        &revision,
    ])
}

pub fn group_epoch_config_digest(
    owner: &str,
    set_id: &str,
    predicate: &str,
    settle_window_ms: u64,
    config_revision: u64,
) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&group_epoch_config_bytes(
        owner,
        set_id,
        predicate,
        settle_window_ms,
        config_revision,
    )?))
}

pub fn epoch_finalization_id(
    object: &str,
    epoch: u64,
    previous_epoch: u64,
    revision_id: &str,
    previous_finalization_id: &str,
    candidates: &[String],
) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&epoch_finalization_bytes(
        object,
        epoch,
        previous_epoch,
        revision_id,
        previous_finalization_id,
        candidates,
    )?))
}
