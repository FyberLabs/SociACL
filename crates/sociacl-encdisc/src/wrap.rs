//! Wrapped-key edge.
//!
//! A per-item DEK is wrapped to each reader's SEA `epub`, or once to
//! the group epoch key. A group epoch key is wrapped to each member's
//! `epub`. `revisionId` is inside the AES-GCM plaintext. A swapped
//! cleartext label does not open.
//!
//! A wrap is not a grant. These functions do not call Check and cannot
//! set `allowed`. The named set is the accessors a live grant or a
//! direct membership already named. A target outside that set fails
//! the call, and no wrap from that call is returned.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::account::EnrolledSeaPub;
use crate::canonical::{self, DOMAIN_GROUP_WRAP, DOMAIN_SEA_SECRET, DOMAIN_WRAPPED_KEY};
use crate::error::EncDiscError;
use crate::hexutil::{decode_hex, encode_hex};
use crate::sea::{self, ecdh_secret, ecdh_x, parse_sea_point, uncompressed_point};

const MAX_WRAP_BYTES: usize = 8192;
const VER_READER: u8 = 1;
const VER_GROUP: u8 = 2;

/// 32-byte item DEK. It does not sit on the shared graph.
#[derive(Clone)]
pub struct ItemDek {
    bytes: Zeroizing<[u8; 32]>,
}

/// 32-byte group epoch key. Membership is still a direct edge.
#[derive(Clone)]
pub struct GroupEpochKey {
    bytes: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapScope {
    ItemDek,
    GroupKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapTarget {
    ReaderEpub,
    GroupEpoch,
}

/// Cleartext label plus the authenticated blob.
///
/// `revision_id` here is a label. Open fails unless the sealed copy
/// matches it. Peers can read the label. They cannot swap it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub scope: WrapScope,
    pub epoch: u64,
    pub target: WrapTarget,
    pub target_id: String,
    pub object: Option<String>,
    pub group: Option<String>,
    pub revision_id: String,
    /// Lowercase hex of the versioned AES-GCM blob.
    pub wrapped_key: String,
}

/// Accessors a live grant or a direct membership already names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedSet {
    accessors: Vec<String>,
}

/// Fixed ephemeral scalar and nonce, for conformance vectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedEphemeral {
    pub epriv: String,
    pub nonce: [u8; 12],
}

/// Key bytes opened from a wrap. Holding them does not make Check allow.
#[derive(Clone)]
#[must_use]
pub struct OpenedWrap {
    key: Zeroizing<[u8; 32]>,
    revision_id: String,
    scope: WrapScope,
}

#[derive(Clone, Debug)]
struct Plan {
    scope: WrapScope,
    epoch: u64,
    target: WrapTarget,
    target_id: String,
    object: Option<String>,
    group: Option<String>,
    revision_id: String,
}

impl ItemDek {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for ItemDek {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ItemDek(<redacted>)")
    }
}

impl GroupEpochKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for GroupEpochKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GroupEpochKey(<redacted>)")
    }
}

impl WrapScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ItemDek => "item-dek",
            Self::GroupKey => "group-key",
        }
    }

    fn parse(text: &str) -> Result<Self, EncDiscError> {
        match text {
            "item-dek" => Ok(Self::ItemDek),
            "group-key" => Ok(Self::GroupKey),
            _ => Err(EncDiscError::WrapRejected),
        }
    }
}

impl WrapTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReaderEpub => "reader-epub",
            Self::GroupEpoch => "group-epoch",
        }
    }

    fn parse(text: &str) -> Result<Self, EncDiscError> {
        match text {
            "reader-epub" => Ok(Self::ReaderEpub),
            "group-epoch" => Ok(Self::GroupEpoch),
            _ => Err(EncDiscError::WrapRejected),
        }
    }
}

impl NamedSet {
    pub fn try_from_accessors<I, S>(ids: I) -> Result<Self, EncDiscError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut accessors = Vec::new();
        for id in ids {
            let id = id.into();
            if id.is_empty() {
                return Err(EncDiscError::EmptyAccount);
            }
            if accessors.iter().any(|existing| existing == &id) {
                return Err(EncDiscError::DuplicateName);
            }
            accessors.push(id);
        }
        Ok(Self { accessors })
    }

    pub fn contains(&self, accessor: &str) -> bool {
        self.accessors.iter().any(|existing| existing == accessor)
    }
}

impl OpenedWrap {
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    pub fn scope(&self) -> WrapScope {
        self.scope
    }

    /// Holding a DEK does not make Check allow.
    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn item_dek(&self) -> Result<ItemDek, EncDiscError> {
        if self.scope != WrapScope::ItemDek {
            return Err(EncDiscError::ScopeRejected);
        }
        Ok(ItemDek::from_bytes(*self.key))
    }

    pub fn group_key(&self) -> Result<GroupEpochKey, EncDiscError> {
        if self.scope != WrapScope::GroupKey {
            return Err(EncDiscError::ScopeRejected);
        }
        Ok(GroupEpochKey::from_bytes(*self.key))
    }
}

impl std::fmt::Debug for OpenedWrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenedWrap")
            .field("scope", &self.scope)
            .field("revision_id", &self.revision_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl WrappedKey {
    pub fn inbox_fields(&self) -> crate::canonical::InboxWrapFields {
        crate::canonical::InboxWrapFields {
            scope: self.scope.as_str().to_string(),
            epoch: self.epoch,
            target: self.target.as_str().to_string(),
            target_id: self.target_id.clone(),
            object: self.object.clone(),
            group: self.group.clone(),
            revision_id: self.revision_id.clone(),
            wrapped_key: self.wrapped_key.clone(),
        }
    }
}

/// Wrap one item DEK to each named reader's `epub`.
pub fn wrap_item_dek_to_readers(
    dek: &ItemDek,
    epoch: u64,
    object: &str,
    revision_id: &str,
    readers: &[EnrolledSeaPub],
    granted: &NamedSet,
) -> Result<Vec<WrappedKey>, EncDiscError> {
    let seals = fresh_seals(readers.len())?;
    wrap_item_dek_to_readers_with(dek, epoch, object, revision_id, readers, granted, &seals)
}

pub fn wrap_item_dek_to_readers_with(
    dek: &ItemDek,
    epoch: u64,
    object: &str,
    revision_id: &str,
    readers: &[EnrolledSeaPub],
    granted: &NamedSet,
    seals: &[DetachedEphemeral],
) -> Result<Vec<WrappedKey>, EncDiscError> {
    if object.is_empty() {
        return Err(EncDiscError::EmptyObject);
    }
    canonical::require_revision_id(revision_id)?;
    if seals.len() != readers.len() {
        return Err(EncDiscError::WrapRejected);
    }
    check_readers(readers, granted)?;
    let mut out = Vec::with_capacity(readers.len());
    for (reader, seal) in readers.iter().zip(seals.iter()) {
        let plan = Plan {
            scope: WrapScope::ItemDek,
            epoch,
            target: WrapTarget::ReaderEpub,
            target_id: reader.epub.clone(),
            object: Some(object.to_string()),
            group: None,
            revision_id: revision_id.to_string(),
        };
        out.push(seal_reader(
            dek.as_bytes(),
            &reader.epub,
            &plan,
            &seal.epriv,
            &seal.nonce,
        )?);
    }
    Ok(out)
}

/// Wrap the group epoch key to each direct member. Does not add a member.
pub fn wrap_group_key_to_members(
    group_key: &GroupEpochKey,
    epoch: u64,
    group_id: &str,
    revision_id: &str,
    members: &[EnrolledSeaPub],
    direct_members: &NamedSet,
) -> Result<Vec<WrappedKey>, EncDiscError> {
    let seals = fresh_seals(members.len())?;
    wrap_group_key_to_members_with(
        group_key,
        epoch,
        group_id,
        revision_id,
        members,
        direct_members,
        &seals,
    )
}

pub fn wrap_group_key_to_members_with(
    group_key: &GroupEpochKey,
    epoch: u64,
    group_id: &str,
    revision_id: &str,
    members: &[EnrolledSeaPub],
    direct_members: &NamedSet,
    seals: &[DetachedEphemeral],
) -> Result<Vec<WrappedKey>, EncDiscError> {
    if group_id.is_empty() {
        return Err(EncDiscError::EmptyGroup);
    }
    canonical::require_revision_id(revision_id)?;
    if seals.len() != members.len() {
        return Err(EncDiscError::WrapRejected);
    }
    check_readers(members, direct_members)?;
    let mut out = Vec::with_capacity(members.len());
    for (member, seal) in members.iter().zip(seals.iter()) {
        let plan = Plan {
            scope: WrapScope::GroupKey,
            epoch,
            target: WrapTarget::ReaderEpub,
            target_id: member.epub.clone(),
            object: None,
            group: Some(group_id.to_string()),
            revision_id: revision_id.to_string(),
        };
        out.push(seal_reader(
            group_key.as_bytes(),
            &member.epub,
            &plan,
            &seal.epriv,
            &seal.nonce,
        )?);
    }
    Ok(out)
}

/// Wrap the item DEK once to the group epoch key. Not once per member.
///
/// The nonce is fresh for this call. A caller does not supply it.
pub fn wrap_item_dek_to_group_epoch(
    dek: &ItemDek,
    group_key: &GroupEpochKey,
    epoch: u64,
    object: &str,
    group_id: &str,
    revision_id: &str,
) -> Result<WrappedKey, EncDiscError> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    seal_item_dek_to_group_epoch(dek, group_key, epoch, object, group_id, revision_id, &nonce)
}

/// Same wrap with a caller-chosen nonce.
///
/// Not part of the production API. The AES key is the group epoch key,
/// so two calls with the same key and nonce reuse an AES-GCM nonce.
/// Unit tests compile this. A production build includes it only with
/// the `deterministic-wrap` feature.
#[cfg(any(test, feature = "deterministic-wrap"))]
pub fn wrap_item_dek_to_group_epoch_with(
    dek: &ItemDek,
    group_key: &GroupEpochKey,
    epoch: u64,
    object: &str,
    group_id: &str,
    revision_id: &str,
    nonce: &[u8; 12],
) -> Result<WrappedKey, EncDiscError> {
    seal_item_dek_to_group_epoch(dek, group_key, epoch, object, group_id, revision_id, nonce)
}

fn seal_item_dek_to_group_epoch(
    dek: &ItemDek,
    group_key: &GroupEpochKey,
    epoch: u64,
    object: &str,
    group_id: &str,
    revision_id: &str,
    nonce: &[u8; 12],
) -> Result<WrappedKey, EncDiscError> {
    if object.is_empty() {
        return Err(EncDiscError::EmptyObject);
    }
    if group_id.is_empty() {
        return Err(EncDiscError::EmptyGroup);
    }
    canonical::require_revision_id(revision_id)?;
    let plan = Plan {
        scope: WrapScope::ItemDek,
        epoch,
        target: WrapTarget::GroupEpoch,
        target_id: group_id.to_string(),
        object: Some(object.to_string()),
        group: Some(group_id.to_string()),
        revision_id: revision_id.to_string(),
    };
    seal_group(dek.as_bytes(), group_key, &plan, nonce)
}

pub fn open_reader_wrap(
    wrapped: &WrappedKey,
    epriv: &str,
    epub: &str,
) -> Result<OpenedWrap, EncDiscError> {
    if wrapped.target != WrapTarget::ReaderEpub || wrapped.target_id != epub {
        return Err(EncDiscError::WrapRejected);
    }
    let secret = ecdh_secret(epriv).map_err(|_| EncDiscError::WrapRejected)?;
    let derived = sea::sea_pub_from_secret(&secret).map_err(|_| EncDiscError::WrapRejected)?;
    if derived != epub {
        return Err(EncDiscError::WrapRejected);
    }
    let blob = decode_blob(&wrapped.wrapped_key)?;
    if blob.first().copied() != Some(VER_READER) || blob.len() < 1 + 65 + 12 + 16 {
        return Err(EncDiscError::WrapRejected);
    }
    let ephemeral = PublicPoint::parse(&blob[1..66])?;
    let nonce: [u8; 12] = blob[66..78]
        .try_into()
        .map_err(|_| EncDiscError::WrapRejected)?;
    let ciphertext = &blob[78..];
    let shared = ecdh_x(&secret, &ephemeral.public).map_err(|_| EncDiscError::WrapRejected)?;
    let aes_key = Zeroizing::new(kdf_reader(&shared)?);
    let plain = Zeroizing::new(decrypt(&aes_key, &nonce, ciphertext)?);
    parse_opened(&plain, wrapped)
}

pub fn open_group_epoch_wrap(
    wrapped: &WrappedKey,
    group_id: &str,
    group_key: &GroupEpochKey,
) -> Result<OpenedWrap, EncDiscError> {
    // Group-epoch wraps carry an item DEK. group-key + group-epoch is not a pair.
    if wrapped.target != WrapTarget::GroupEpoch
        || wrapped.target_id != group_id
        || wrapped.scope != WrapScope::ItemDek
    {
        return Err(EncDiscError::WrapRejected);
    }
    let blob = decode_blob(&wrapped.wrapped_key)?;
    if blob.first().copied() != Some(VER_GROUP) || blob.len() < 1 + 12 + 16 {
        return Err(EncDiscError::WrapRejected);
    }
    let nonce: [u8; 12] = blob[1..13]
        .try_into()
        .map_err(|_| EncDiscError::WrapRejected)?;
    let ciphertext = &blob[13..];
    let aes_key = Zeroizing::new(kdf_group(group_key.as_bytes())?);
    let plain = Zeroizing::new(decrypt(&aes_key, &nonce, ciphertext)?);
    parse_opened(&plain, wrapped)
}

struct PublicPoint {
    public: p256::PublicKey,
}

impl PublicPoint {
    fn parse(bytes: &[u8]) -> Result<Self, EncDiscError> {
        let public =
            p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| EncDiscError::WrapRejected)?;
        Ok(Self { public })
    }
}

fn check_readers(readers: &[EnrolledSeaPub], named: &NamedSet) -> Result<(), EncDiscError> {
    let mut seen = Vec::new();
    for reader in readers {
        if reader.account.is_empty() {
            return Err(EncDiscError::EmptyAccount);
        }
        if seen
            .iter()
            .any(|existing: &String| existing == &reader.account)
        {
            return Err(EncDiscError::DuplicateName);
        }
        seen.push(reader.account.clone());
        if !named.contains(&reader.account) {
            return Err(EncDiscError::UnnamedReader);
        }
        if reader.epub.is_empty() {
            return Err(EncDiscError::EpubRequired);
        }
        if reader.identity_pub.is_empty() {
            return Err(EncDiscError::IdentityPubMissing);
        }
        if reader.identity_pub != reader.sea_pub {
            return Err(EncDiscError::PubMismatch);
        }
        parse_sea_point(&reader.epub)?;
        parse_sea_point(&reader.sea_pub)?;
    }
    Ok(())
}

fn fresh_seals(count: usize) -> Result<Vec<DetachedEphemeral>, EncDiscError> {
    let mut rng = OsRng;
    let mut seals = Vec::with_capacity(count);
    for _ in 0..count {
        let secret = p256::SecretKey::random(&mut rng);
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        seals.push(DetachedEphemeral {
            epriv: sea::sea_priv_from_secret(&secret)?,
            nonce,
        });
    }
    Ok(seals)
}

fn seal_reader(
    key: &[u8; 32],
    recipient_epub: &str,
    plan: &Plan,
    epriv: &str,
    nonce: &[u8; 12],
) -> Result<WrappedKey, EncDiscError> {
    let secret = ecdh_secret(epriv)?;
    let peer = parse_sea_point(recipient_epub)?;
    let shared = ecdh_x(&secret, &peer)?;
    let aes_key = Zeroizing::new(kdf_reader(&shared)?);
    let plain = Zeroizing::new(sealed_plain(key, plan)?);
    let ciphertext = encrypt(&aes_key, nonce, &plain)?;
    let ephemeral = uncompressed_point(&secret.public_key())?;
    let mut blob = Vec::with_capacity(1 + 65 + 12 + ciphertext.len());
    blob.push(VER_READER);
    blob.extend_from_slice(&ephemeral);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext);
    finish_blob(plan, blob)
}

fn seal_group(
    key: &[u8; 32],
    group_key: &GroupEpochKey,
    plan: &Plan,
    nonce: &[u8; 12],
) -> Result<WrappedKey, EncDiscError> {
    let aes_key = Zeroizing::new(kdf_group(group_key.as_bytes())?);
    let plain = Zeroizing::new(sealed_plain(key, plan)?);
    let ciphertext = encrypt(&aes_key, nonce, &plain)?;
    let mut blob = Vec::with_capacity(1 + 12 + ciphertext.len());
    blob.push(VER_GROUP);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext);
    finish_blob(plan, blob)
}

fn finish_blob(plan: &Plan, blob: Vec<u8>) -> Result<WrappedKey, EncDiscError> {
    if blob.len() > MAX_WRAP_BYTES {
        return Err(EncDiscError::WrapRejected);
    }
    Ok(WrappedKey {
        scope: plan.scope,
        epoch: plan.epoch,
        target: plan.target,
        target_id: plan.target_id.clone(),
        object: plan.object.clone(),
        group: plan.group.clone(),
        revision_id: plan.revision_id.clone(),
        wrapped_key: encode_hex(&blob),
    })
}

fn sealed_plain(key: &[u8; 32], plan: &Plan) -> Result<Vec<u8>, EncDiscError> {
    let epoch = canonical::canonical_decimal(plan.epoch);
    let object = plan.object.as_deref().unwrap_or("");
    let group = plan.group.as_deref().unwrap_or("");
    let key_hex = encode_hex(key);
    canonical::length_prefixed(&[
        DOMAIN_WRAPPED_KEY,
        plan.scope.as_str(),
        &epoch,
        plan.target.as_str(),
        &plan.target_id,
        object,
        group,
        &plan.revision_id,
        &key_hex,
    ])
}

fn kdf_reader(shared_x: &[u8; 32]) -> Result<[u8; 32], EncDiscError> {
    let hex = encode_hex(shared_x);
    let bytes = canonical::length_prefixed(&[DOMAIN_SEA_SECRET, &hex])?;
    Ok(canonical::sha256(&bytes))
}

fn kdf_group(group_key: &[u8; 32]) -> Result<[u8; 32], EncDiscError> {
    let hex = encode_hex(group_key);
    let bytes = canonical::length_prefixed(&[DOMAIN_GROUP_WRAP, &hex])?;
    Ok(canonical::sha256(&bytes))
}

fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::WrapRejected)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| EncDiscError::WrapRejected)
}

fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::WrapRejected)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| EncDiscError::WrapRejected)
}

fn decode_blob(hex_text: &str) -> Result<Vec<u8>, EncDiscError> {
    if hex_text.len() > MAX_WRAP_BYTES * 2 {
        return Err(EncDiscError::WrapRejected);
    }
    decode_hex(hex_text).map_err(|_| EncDiscError::WrapRejected)
}

fn parse_opened(plain: &[u8], wrapped: &WrappedKey) -> Result<OpenedWrap, EncDiscError> {
    let mut rest = plain;
    let domain = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    let scope = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    let epoch = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    let target = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    let target_id = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    let object = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    let group = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    let revision = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    let key_hex = read_field(&mut rest).map_err(|_| EncDiscError::WrapRejected)?;
    if !rest.is_empty() || domain != DOMAIN_WRAPPED_KEY {
        return Err(EncDiscError::WrapRejected);
    }
    let parsed_scope = WrapScope::parse(scope).map_err(|_| EncDiscError::WrapRejected)?;
    let parsed_target = WrapTarget::parse(target).map_err(|_| EncDiscError::WrapRejected)?;
    let parsed_epoch =
        canonical::parse_canonical_decimal(epoch).map_err(|_| EncDiscError::WrapRejected)?;
    if parsed_scope != wrapped.scope
        || parsed_target != wrapped.target
        || parsed_epoch != wrapped.epoch
        || target_id != wrapped.target_id
        || revision != wrapped.revision_id
        || object != wrapped.object.as_deref().unwrap_or("")
        || group != wrapped.group.as_deref().unwrap_or("")
    {
        return Err(EncDiscError::WrapRejected);
    }
    if canonical::require_revision_id(revision).is_err() {
        return Err(EncDiscError::WrapRejected);
    }
    let key =
        crate::hexutil::decode_hex_array::<32>(key_hex).map_err(|_| EncDiscError::WrapRejected)?;
    Ok(OpenedWrap {
        key: Zeroizing::new(key),
        revision_id: revision.to_string(),
        scope: parsed_scope,
    })
}

fn read_field<'a>(input: &mut &'a [u8]) -> Result<&'a str, EncDiscError> {
    if input.len() < 4 {
        return Err(EncDiscError::WrapRejected);
    }
    let len = u32::from_le_bytes(
        input[..4]
            .try_into()
            .map_err(|_| EncDiscError::WrapRejected)?,
    ) as usize;
    *input = &input[4..];
    if input.len() < len {
        return Err(EncDiscError::WrapRejected);
    }
    let (field, rest) = input.split_at(len);
    *input = rest;
    std::str::from_utf8(field).map_err(|_| EncDiscError::WrapRejected)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_blob, decrypt, kdf_group, seal_group, wrap_item_dek_to_group_epoch_with, Plan,
    };
    use crate::error::EncDiscError;
    use crate::wrap::{open_group_epoch_wrap, GroupEpochKey, ItemDek, WrapScope, WrapTarget};

    #[test]
    fn revision_id_is_inside_the_plaintext() {
        let dek = ItemDek::from_bytes([7u8; 32]);
        let group = GroupEpochKey::from_bytes([9u8; 32]);
        let revision = "ab".repeat(32);
        let nonce = [3u8; 12];
        let wrapped = wrap_item_dek_to_group_epoch_with(
            &dek,
            &group,
            4,
            "s3rch/items/post",
            "circle-1",
            &revision,
            &nonce,
        )
        .unwrap();
        let blob = decode_blob(&wrapped.wrapped_key).unwrap();
        assert_eq!(blob[0], 2);
        let aes = kdf_group(group.as_bytes()).unwrap();
        let plain = decrypt(&aes, &nonce, &blob[13..]).unwrap();
        let text = String::from_utf8(plain).unwrap();
        assert!(text.contains(&revision));
        assert!(text.contains("s3rch-wrapped-key-v1"));
        assert!(!text.contains("priv"));
    }

    #[test]
    fn group_epoch_open_rejects_a_group_key_scope() {
        let dek = ItemDek::from_bytes([7u8; 32]);
        let group = GroupEpochKey::from_bytes([9u8; 32]);
        let revision = "ab".repeat(32);
        let nonce = [3u8; 12];
        let plan = Plan {
            scope: WrapScope::GroupKey,
            epoch: 4,
            target: WrapTarget::GroupEpoch,
            target_id: "circle-1".to_string(),
            object: Some("s3rch/items/post".to_string()),
            group: Some("circle-1".to_string()),
            revision_id: revision.clone(),
        };
        let wrapped = seal_group(dek.as_bytes(), &group, &plan, &nonce).unwrap();
        assert_eq!(wrapped.scope, WrapScope::GroupKey);
        assert_eq!(wrapped.target, WrapTarget::GroupEpoch);
        assert_eq!(
            open_group_epoch_wrap(&wrapped, "circle-1", &group).unwrap_err(),
            EncDiscError::WrapRejected
        );
        let item = wrap_item_dek_to_group_epoch_with(
            &dek,
            &group,
            4,
            "s3rch/items/post",
            "circle-1",
            &revision,
            &nonce,
        )
        .unwrap();
        let opened = open_group_epoch_wrap(&item, "circle-1", &group).unwrap();
        assert_eq!(opened.key_bytes(), dek.as_bytes());
        assert!(!opened.grants_see());
    }
}
