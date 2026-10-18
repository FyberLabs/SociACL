//! Passphrase recovery copy of an [`AccountKeyring`].
//!
//! The sealing key is Argon2id. The passphrase is an argument and is not
//! stored. The envelope goes to a [`RecoveryCopyStore`], which keeps
//! ciphertext only. Panopticon is that kind of adapter: an index, not the
//! authority. `priv` and `epriv` never go on Gun.
//!
//! The public seal draws the salt and nonce internally.
//! [`seal_recovery_copy_with`] takes caller-chosen values for tests and is
//! not re-exported.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use sociacl_ids::{parse_principal_id, PrincipalId};
use zeroize::{Zeroize, Zeroizing};

use crate::canonical::{self, JS_SAFE_INTEGER_MAX};
use crate::error::EncDiscError;
use crate::hexutil::{self, encode_hex};
use crate::keyring::{rotate_keyring, AccountKeyring, KeyringRotation, RotationMint};
use crate::limits::{
    in_bound, ARGON2ID_LIMITS, KEYRING_SERIAL_MAX, RECOVERY_ABSOLUTE_MAX, RECOVERY_ENVELOPE_MAX,
    RECOVERY_HEADER_LEN, RECOVERY_NONCE_LEN, RECOVERY_TAG_LEN,
};
use unicode_normalization::UnicodeNormalization;
pub(crate) const DOMAIN_RECOVERY: &str = "sociacl-recovery-copy-v1";
pub(crate) const DOMAIN_KEYRING_PLAIN: &str = "sociacl-keyring-plain-v1";

/// Ciphertext of one keyring version. The store does not see the passphrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryEnvelope {
    pub principal: PrincipalId,
    pub rotation_seq: u64,
    pub bytes: Vec<u8>,
}

/// Ciphertext adapter. Not an authority, and not Gun.
///
/// `put_copy` refuses a `rotation_seq` below the stored copy. An equal
/// sequence replaces that row. A higher sequence is held beside the current
/// copy until [`commit_recovery_copy`] promotes it. Adapters, Panopticon
/// included, replace a row atomically and only forward: write the new row,
/// then drop the old one. There is never a window with zero copies.
pub trait RecoveryCopyStore {
    fn put_copy(&mut self, envelope: &RecoveryEnvelope) -> Result<(), EncDiscError>;

    fn get_copy(
        &self,
        principal: &PrincipalId,
        rotation_seq: u64,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError>;

    /// Move the pending copy onto the current copy when its sequence is
    /// `verified_seq`. The slot keeps a current copy for the whole call.
    fn promote_pending(
        &mut self,
        principal: &PrincipalId,
        verified_seq: u64,
    ) -> Result<(), EncDiscError>;

    fn is_authority(&self) -> bool {
        false
    }

    fn sees_plaintext(&self) -> bool {
        false
    }

    fn sees_passphrase(&self) -> bool {
        false
    }
}

/// Current recovery copy, plus at most one newer copy waiting on the chain.
#[derive(Clone, Debug)]
struct RecoverySlot {
    current: RecoveryEnvelope,
    pending: Option<RecoveryEnvelope>,
}

/// In-memory adapter. One slot per principal.
///
/// `get_copy` returns a clone, so the caller cannot alias the stored bytes.
/// Promotion assigns the pending envelope onto `current` in place.
#[derive(Clone, Debug, Default)]
pub struct MemoryRecoveryStore {
    by_principal: BTreeMap<String, RecoverySlot>,
}

impl MemoryRecoveryStore {
    pub fn len(&self) -> usize {
        self.by_principal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_principal.is_empty()
    }
}

impl RecoveryCopyStore for MemoryRecoveryStore {
    fn put_copy(&mut self, envelope: &RecoveryEnvelope) -> Result<(), EncDiscError> {
        if envelope.bytes.len() > RECOVERY_ABSOLUTE_MAX || envelope.bytes.is_empty() {
            return Err(EncDiscError::StoreRejected);
        }
        let seq = header_rotation_seq(&envelope.bytes)?;
        if seq != envelope.rotation_seq {
            return Err(EncDiscError::StoreRejected);
        }
        let key = envelope.principal.as_ref().to_string();
        let Some(slot) = self.by_principal.get_mut(&key) else {
            self.by_principal.insert(
                key,
                RecoverySlot {
                    current: envelope.clone(),
                    pending: None,
                },
            );
            return Ok(());
        };
        let incoming = envelope.rotation_seq;
        if incoming < slot.current.rotation_seq {
            return Err(EncDiscError::StoreRejected);
        }
        if incoming == slot.current.rotation_seq {
            slot.current = envelope.clone();
            return Ok(());
        }
        if let Some(pending) = &slot.pending {
            if incoming < pending.rotation_seq {
                return Err(EncDiscError::StoreRejected);
            }
            if incoming == pending.rotation_seq {
                slot.pending = Some(envelope.clone());
                return Ok(());
            }
        }
        slot.pending = Some(envelope.clone());
        Ok(())
    }

    fn get_copy(
        &self,
        principal: &PrincipalId,
        rotation_seq: u64,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError> {
        let Some(slot) = self.by_principal.get(principal.as_ref()) else {
            return Ok(None);
        };
        if slot.current.rotation_seq == rotation_seq {
            return Ok(Some(slot.current.clone()));
        }
        Ok(slot.pending.as_ref().and_then(|pending| {
            if pending.rotation_seq == rotation_seq {
                Some(pending.clone())
            } else {
                None
            }
        }))
    }

    fn promote_pending(
        &mut self,
        principal: &PrincipalId,
        verified_seq: u64,
    ) -> Result<(), EncDiscError> {
        let Some(slot) = self.by_principal.get_mut(principal.as_ref()) else {
            return Err(EncDiscError::StoreRejected);
        };
        let Some(pending) = slot.pending.take() else {
            return Err(EncDiscError::StoreRejected);
        };
        if pending.rotation_seq != verified_seq {
            slot.pending = Some(pending);
            return Err(EncDiscError::StoreRejected);
        }
        slot.current = pending;
        Ok(())
    }
}

/// NFC then UTF-8, in the style of an RFC 8265 OpaqueString, against Unicode 16.0.0.
///
/// A code point unassigned in Unicode 16.0.0 is [`EncDiscError::RecoveryParams`]
/// before NFC, so a later Unicode mark cannot reorder. Whitespace is the
/// Unicode 16 `White_Space` set, including U+0085. U+FEFF is not whitespace.
/// An empty string and a whitespace-only string are
/// [`EncDiscError::RecoveryParams`]. Leading and trailing whitespace on a
/// passphrase that also has a non-whitespace character is preserved.
///
/// The NFC buffer is [`Zeroizing`]. The caller's `&str` and any scratch
/// inside `unicode-normalization` are not wiped. TypeScript strings cannot
/// be wiped either. The byte API does not normalize; it receives these bytes
/// and applies the same Unicode 16 checks.
pub fn encode_passphrase(passphrase: &str) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    debug_assert_eq!(crate::unicode16::UNICODE_VERSION, "16.0.0");
    if passphrase.is_empty()
        || passphrase
            .chars()
            .any(|ch| !crate::unicode16::assigned(ch as u32))
    {
        return Err(EncDiscError::RecoveryParams);
    }
    let mut nfc = Zeroizing::new(String::new());
    for ch in passphrase.nfc() {
        nfc.push(ch);
    }
    if nfc
        .chars()
        .all(|ch| crate::unicode16::passphrase_whitespace(ch as u32))
    {
        return Err(EncDiscError::RecoveryParams);
    }
    let owned = std::mem::take(&mut *nfc);
    Ok(Zeroizing::new(owned.into_bytes()))
}

/// Seal with a passphrase string. The string is normalized by [`encode_passphrase`].
pub fn seal_recovery_copy_str(
    keyring: &AccountKeyring,
    passphrase: &str,
    store: &mut impl RecoveryCopyStore,
) -> Result<RecoveryEnvelope, EncDiscError> {
    let bytes = encode_passphrase(passphrase)?;
    seal_recovery_copy(keyring, &bytes, store)
}

/// Open with a passphrase string. The string is normalized by [`encode_passphrase`].
pub fn open_recovery_copy_str(
    passphrase: &str,
    envelope: &RecoveryEnvelope,
    expected: &PrincipalId,
    expected_rotation_seq: u64,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<AccountKeyring, EncDiscError> {
    let bytes = encode_passphrase(passphrase)?;
    open_recovery_copy(
        &bytes,
        envelope,
        expected,
        expected_rotation_seq,
        rotations,
        context,
    )
}

/// Seal `keyring` under `passphrase` and store the ciphertext.
///
/// Salt and nonce are drawn here. The passphrase is not written to `store`.
pub fn seal_recovery_copy(
    keyring: &AccountKeyring,
    passphrase: &[u8],
    store: &mut impl RecoveryCopyStore,
) -> Result<RecoveryEnvelope, EncDiscError> {
    let mut salt = vec![0u8; ARGON2ID_LIMITS.salt_length.floor as usize];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; RECOVERY_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let envelope = seal_recovery_copy_with(keyring, passphrase, &salt, &nonce, store);
    salt.zeroize();
    nonce.zeroize();
    envelope
}

/// Caller-chosen salt and nonce. Tests only. Not a public export.
pub(crate) fn seal_recovery_copy_with(
    keyring: &AccountKeyring,
    passphrase: &[u8],
    salt: &[u8],
    nonce: &[u8],
    store: &mut impl RecoveryCopyStore,
) -> Result<RecoveryEnvelope, EncDiscError> {
    if passphrase_rejected(passphrase) {
        return Err(EncDiscError::RecoveryParams);
    }
    if salt.len() < ARGON2ID_LIMITS.salt_length.floor as usize
        || salt.len() > ARGON2ID_LIMITS.salt_length.ceiling as usize
        || nonce.len() != RECOVERY_NONCE_LEN
    {
        return Err(EncDiscError::RecoveryParams);
    }
    let mut plain = encode_keyring(keyring)?;
    let mut key = derive_key(
        passphrase,
        salt,
        ARGON2ID_LIMITS.memory_kib.floor,
        ARGON2ID_LIMITS.iterations.floor,
        ARGON2ID_LIMITS.parallelism.floor,
        ARGON2ID_LIMITS.hash_length.floor,
    )?;
    let aad = recovery_aad(
        keyring.principal().as_ref(),
        keyring.rotation_seq(),
        ARGON2ID_LIMITS.memory_kib.floor,
        ARGON2ID_LIMITS.iterations.floor,
        ARGON2ID_LIMITS.parallelism.floor,
        ARGON2ID_LIMITS.hash_length.floor,
        ARGON2ID_LIMITS.version.floor,
        salt,
    )?;
    let ciphertext = aes_encrypt(&key, nonce, &aad, &plain)?;
    plain.zeroize();
    key.zeroize();
    let mut bytes =
        Vec::with_capacity(RECOVERY_HEADER_LEN + salt.len() + nonce.len() + ciphertext.len());
    write_header(
        &mut bytes,
        ARGON2ID_LIMITS.version.floor,
        ARGON2ID_LIMITS.memory_kib.floor,
        ARGON2ID_LIMITS.iterations.floor,
        ARGON2ID_LIMITS.parallelism.floor,
        ARGON2ID_LIMITS.hash_length.floor,
        salt,
        keyring.rotation_seq(),
    );
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&ciphertext);
    if bytes.len() > RECOVERY_ABSOLUTE_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let envelope = RecoveryEnvelope {
        principal: keyring.principal().clone(),
        rotation_seq: keyring.rotation_seq(),
        bytes,
    };
    store.put_copy(&envelope)?;
    Ok(envelope)
}

/// Open a recovery copy.
///
/// A wrong passphrase and a tampered envelope both return
/// [`EncDiscError::RecoveryRejected`]. A parameter outside
/// [`ARGON2ID_LIMITS`] returns [`EncDiscError::RecoveryParams`] before the
/// KDF runs. An authentic copy whose version is not `expected_rotation_seq`
/// returns [`EncDiscError::RecoveryStale`].
pub fn open_recovery_copy(
    passphrase: &[u8],
    envelope: &RecoveryEnvelope,
    expected: &PrincipalId,
    expected_rotation_seq: u64,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<AccountKeyring, EncDiscError> {
    if envelope.bytes.len() > RECOVERY_ABSOLUTE_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let header = parse_header(&envelope.bytes)?;
    if passphrase_rejected(passphrase) {
        return Err(EncDiscError::RecoveryParams);
    }
    if envelope.principal.as_ref() != expected.as_ref()
        || header.rotation_seq != envelope.rotation_seq
    {
        return Err(EncDiscError::RecoveryRejected);
    }
    if header.rotation_seq > JS_SAFE_INTEGER_MAX {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut key = derive_key(
        passphrase,
        &header.salt,
        header.memory_kib,
        header.iterations,
        header.parallelism,
        header.hash_length,
    )?;
    let aad = recovery_aad(
        expected.as_ref(),
        header.rotation_seq,
        header.memory_kib,
        header.iterations,
        header.parallelism,
        header.hash_length,
        header.version,
        &header.salt,
    )?;
    let mut plain = match aes_decrypt(&key, &header.nonce, &aad, &header.ciphertext) {
        Ok(plain) => plain,
        Err(error) => {
            key.zeroize();
            return Err(error);
        }
    };
    key.zeroize();
    if plain.len() > KEYRING_SERIAL_MAX {
        plain.zeroize();
        return Err(EncDiscError::KeyringTooLarge);
    }
    let fields = match decode_keyring(&plain) {
        Ok(fields) => fields,
        Err(error) => {
            plain.zeroize();
            return Err(error);
        }
    };
    plain.zeroize();
    let parsed = parse_principal_id(fields.principal.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if parsed.as_ref() != fields.principal.as_str() || parsed.as_ref() != expected.as_ref() {
        return Err(EncDiscError::RecoveryRejected);
    }
    if fields.rotation_seq != header.rotation_seq {
        return Err(EncDiscError::RecoveryRejected);
    }
    if fields.rotation_seq != expected_rotation_seq {
        return Err(EncDiscError::RecoveryStale);
    }
    let retired: Vec<(&str, &str)> = fields
        .retired
        .iter()
        .map(|(epub, epriv)| (epub.as_str(), epriv.as_str()))
        .collect();
    let prior: Vec<&str> = fields
        .prior_lanes
        .iter()
        .map(|lane| lane.as_str())
        .collect();
    AccountKeyring::import_with_prior_lanes(
        fields.principal.as_str(),
        fields.genesis_epub.as_str(),
        fields.current_pub.as_str(),
        fields.current_priv.as_str(),
        fields.current_epub.as_str(),
        fields.current_epriv.as_str(),
        &retired,
        fields.lane_id.as_str(),
        fields.content_epoch,
        fields.rotation_seq,
        rotations,
        context,
        &prior,
    )
}

/// Rotate, then seal a pending recovery copy of the new keyring version.
///
/// The current copy stays until [`commit_recovery_copy`] sees that rotation
/// in the trusted chain. An unpublished draft does not replace it.
pub fn rotate_and_reseal<F>(
    keyring: &AccountKeyring,
    trusted: &[&str],
    lost: &str,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    mint: F,
    passphrase: &[u8],
    store: &mut impl RecoveryCopyStore,
) -> Result<(KeyringRotation, RecoveryEnvelope), EncDiscError>
where
    F: FnOnce() -> Result<RotationMint, EncDiscError>,
{
    let rotation = rotate_keyring(keyring, trusted, lost, rotations, context, mint)?;
    let envelope = seal_recovery_copy(&rotation.keyring, passphrase, store)?;
    Ok((rotation, envelope))
}

/// Promote the pending copy after the trusted chain includes that rotation.
///
/// A chain that does not resolve, or a verified sequence that is not the
/// pending copy, is [`EncDiscError::StoreRejected`]. Both copies stay.
pub fn commit_recovery_copy(
    principal: &PrincipalId,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    store: &mut impl RecoveryCopyStore,
) -> Result<(), EncDiscError> {
    let resolved = sociacl_ids::resolve_current_key(principal, rotations, context);
    let account = resolved.result.map_err(|_| EncDiscError::StoreRejected)?;
    let verified = account.rotations.len() as u64;
    store.promote_pending(principal, verified)
}

pub(crate) struct KeyringFields {
    pub principal: Zeroizing<String>,
    pub genesis_epub: Zeroizing<String>,
    pub current_pub: Zeroizing<String>,
    pub current_priv: Zeroizing<String>,
    pub current_epub: Zeroizing<String>,
    pub current_epriv: Zeroizing<String>,
    pub retired: Vec<(Zeroizing<String>, Zeroizing<String>)>,
    pub lane_id: Zeroizing<String>,
    pub prior_lanes: Vec<Zeroizing<String>>,
    pub content_epoch: u64,
    pub rotation_seq: u64,
}

pub(crate) fn encode_keyring(keyring: &AccountKeyring) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    let retired_count = canonical::canonical_decimal(keyring.retired().len() as u64)?;
    let prior_count = canonical::canonical_decimal(keyring.prior_lanes().len() as u64)?;
    let epoch = canonical::canonical_decimal(keyring.content_epoch())?;
    let seq = canonical::canonical_decimal(keyring.rotation_seq())?;
    let mut total = 0usize;
    let mut add = |len: usize| -> Result<(), EncDiscError> {
        total = total
            .checked_add(4 + len)
            .ok_or(EncDiscError::FieldTooLong)?;
        Ok(())
    };
    add(DOMAIN_KEYRING_PLAIN.len())?;
    add(keyring.principal().as_ref().len())?;
    add(keyring.genesis_epub().as_ref().len())?;
    add(keyring.current_pub().as_ref().len())?;
    add(keyring.current_priv().len())?;
    add(keyring.current_epub().as_ref().len())?;
    add(keyring.current_epriv().len())?;
    add(retired_count.len())?;
    for row in keyring.retired() {
        add(row.epub().as_ref().len())?;
        add(row.epriv().len())?;
    }
    add(keyring.lane_id().len())?;
    add(prior_count.len())?;
    for lane in keyring.prior_lanes() {
        add(lane.len())?;
    }
    add(epoch.len())?;
    add(seq.len())?;
    if total > KEYRING_SERIAL_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    write_field(&mut out, DOMAIN_KEYRING_PLAIN);
    write_field(&mut out, keyring.principal().as_ref());
    write_field(&mut out, keyring.genesis_epub().as_ref());
    write_field(&mut out, keyring.current_pub().as_ref());
    write_field(&mut out, keyring.current_priv());
    write_field(&mut out, keyring.current_epub().as_ref());
    write_field(&mut out, keyring.current_epriv());
    write_field(&mut out, &retired_count);
    for row in keyring.retired() {
        write_field(&mut out, row.epub().as_ref());
        write_field(&mut out, row.epriv());
    }
    write_field(&mut out, keyring.lane_id());
    write_field(&mut out, &prior_count);
    for lane in keyring.prior_lanes() {
        write_field(&mut out, lane);
    }
    write_field(&mut out, &epoch);
    write_field(&mut out, &seq);
    if out.len() != total {
        return Err(EncDiscError::BadEncoding);
    }
    Ok(out)
}

pub(crate) fn decode_keyring(bytes: &[u8]) -> Result<KeyringFields, EncDiscError> {
    if bytes.len() > KEYRING_SERIAL_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let mut cursor = Cursor { bytes, offset: 0 };
    let domain = cursor.next_string()?;
    if domain.as_str() != DOMAIN_KEYRING_PLAIN {
        return Err(EncDiscError::RecoveryRejected);
    }
    let principal = cursor.next_string()?;
    let genesis_epub = cursor.next_string()?;
    let current_pub = cursor.next_string()?;
    let current_priv = cursor.next_string()?;
    let current_epub = cursor.next_string()?;
    let current_epriv = cursor.next_string()?;
    let retired_count = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if retired_count > 1024 {
        return Err(EncDiscError::IdentityRejected("too-many-keys".into()));
    }
    if retired_count.saturating_mul(8) > cursor.remaining() as u64 {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut retired = Vec::with_capacity(retired_count as usize);
    for _ in 0..retired_count {
        let epub = cursor.next_string()?;
        let epriv = cursor.next_string()?;
        retired.push((epub, epriv));
    }
    let lane_id = cursor.next_string()?;
    let prior_count = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if prior_count.saturating_mul(4) > cursor.remaining() as u64 {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut prior_lanes = Vec::with_capacity(prior_count as usize);
    for _ in 0..prior_count {
        prior_lanes.push(cursor.next_string()?);
    }
    let content_epoch = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    let rotation_seq = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if cursor.remaining() != 0 {
        return Err(EncDiscError::RecoveryRejected);
    }
    Ok(KeyringFields {
        principal,
        genesis_epub,
        current_pub,
        current_priv,
        current_epub,
        current_epriv,
        retired,
        lane_id,
        prior_lanes,
        content_epoch,
        rotation_seq,
    })
}

struct Header {
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    rotation_seq: u64,
    salt: Vec<u8>,
    nonce: [u8; RECOVERY_NONCE_LEN],
    ciphertext: Vec<u8>,
}

fn parse_header(bytes: &[u8]) -> Result<Header, EncDiscError> {
    if bytes.len() < RECOVERY_HEADER_LEN || bytes[0] != 1 {
        return Err(EncDiscError::RecoveryRejected);
    }
    let version = read_u32(bytes, 1);
    let memory_kib = read_u32(bytes, 5);
    let iterations = read_u32(bytes, 9);
    let parallelism = read_u32(bytes, 13);
    let hash_length = read_u32(bytes, 17);
    let salt_len = read_u32(bytes, 21);
    let rotation_seq = read_u64(bytes, 25);
    if !params_allowed(
        version,
        memory_kib,
        iterations,
        parallelism,
        hash_length,
        salt_len,
    ) {
        return Err(EncDiscError::RecoveryParams);
    }
    let salt_len = salt_len as usize;
    let salt_end = RECOVERY_HEADER_LEN
        .checked_add(salt_len)
        .ok_or(EncDiscError::RecoveryRejected)?;
    let nonce_end = salt_end
        .checked_add(RECOVERY_NONCE_LEN)
        .ok_or(EncDiscError::RecoveryRejected)?;
    if bytes.len() < nonce_end {
        return Err(EncDiscError::RecoveryRejected);
    }
    let ciphertext = &bytes[nonce_end..];
    if ciphertext.len() > KEYRING_SERIAL_MAX + RECOVERY_TAG_LEN {
        return Err(EncDiscError::KeyringTooLarge);
    }
    if ciphertext.len() < RECOVERY_TAG_LEN {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut salt = Vec::with_capacity(salt_len);
    salt.extend_from_slice(&bytes[RECOVERY_HEADER_LEN..salt_end]);
    let mut nonce = [0u8; RECOVERY_NONCE_LEN];
    nonce.copy_from_slice(&bytes[salt_end..nonce_end]);
    Ok(Header {
        version,
        memory_kib,
        iterations,
        parallelism,
        hash_length,
        rotation_seq,
        salt,
        nonce,
        ciphertext: ciphertext.to_vec(),
    })
}

fn passphrase_rejected(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            text.chars()
                .any(|ch| !crate::unicode16::assigned(ch as u32))
                || text
                    .chars()
                    .all(|ch| crate::unicode16::passphrase_whitespace(ch as u32))
        }
        Err(_) => false,
    }
}

fn params_allowed(
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    salt_len: u32,
) -> bool {
    in_bound(version, ARGON2ID_LIMITS.version)
        && in_bound(memory_kib, ARGON2ID_LIMITS.memory_kib)
        && in_bound(iterations, ARGON2ID_LIMITS.iterations)
        && in_bound(parallelism, ARGON2ID_LIMITS.parallelism)
        && in_bound(hash_length, ARGON2ID_LIMITS.hash_length)
        && in_bound(salt_len, ARGON2ID_LIMITS.salt_length)
}

fn header_rotation_seq(bytes: &[u8]) -> Result<u64, EncDiscError> {
    if bytes.len() < RECOVERY_HEADER_LEN || bytes[0] != 1 {
        return Err(EncDiscError::StoreRejected);
    }
    Ok(read_u64(bytes, 25))
}

fn write_header(
    out: &mut Vec<u8>,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    salt: &[u8],
    rotation_seq: u64,
) {
    out.push(1);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&memory_kib.to_le_bytes());
    out.extend_from_slice(&iterations.to_le_bytes());
    out.extend_from_slice(&parallelism.to_le_bytes());
    out.extend_from_slice(&hash_length.to_le_bytes());
    out.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    out.extend_from_slice(&rotation_seq.to_le_bytes());
    out.extend_from_slice(salt);
}

fn recovery_aad(
    principal: &str,
    rotation_seq: u64,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    argon_version: u32,
    salt: &[u8],
) -> Result<Vec<u8>, EncDiscError> {
    let parsed = parse_principal_id(principal).map_err(|_| EncDiscError::RecoveryRejected)?;
    if parsed.as_ref() != principal {
        return Err(EncDiscError::RecoveryRejected);
    }
    let salt_hex = encode_hex(salt);
    canonical::length_prefixed(&[
        DOMAIN_RECOVERY,
        parsed.as_ref(),
        canonical::canonical_decimal(rotation_seq)?.as_str(),
        canonical::canonical_decimal(u64::from(memory_kib))?.as_str(),
        canonical::canonical_decimal(u64::from(iterations))?.as_str(),
        canonical::canonical_decimal(u64::from(parallelism))?.as_str(),
        canonical::canonical_decimal(u64::from(hash_length))?.as_str(),
        canonical::canonical_decimal(u64::from(argon_version))?.as_str(),
        salt_hex.as_str(),
    ])
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
) -> Result<Zeroizing<[u8; 32]>, EncDiscError> {
    if !params_allowed(
        ARGON2ID_LIMITS.version.floor,
        memory_kib,
        iterations,
        parallelism,
        hash_length,
        salt.len() as u32,
    ) || hash_length != 32
    {
        return Err(EncDiscError::RecoveryParams);
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|_| EncDiscError::RecoveryParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    Ok(key)
}

fn aes_encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, EncDiscError> {
    if nonce.len() != RECOVERY_NONCE_LEN {
        return Err(EncDiscError::RecoveryRejected);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::RecoveryRejected)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| EncDiscError::RecoveryRejected)
}

fn aes_decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::RecoveryRejected)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    Ok(Zeroizing::new(plain))
}

fn write_field(out: &mut Vec<u8>, field: &str) {
    let raw = field.as_bytes();
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(raw);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn next_string(&mut self) -> Result<Zeroizing<String>, EncDiscError> {
        if self.remaining() < 4 {
            return Err(EncDiscError::RecoveryRejected);
        }
        let len = read_u32(self.bytes, self.offset) as usize;
        self.offset += 4;
        if self.remaining() < len {
            return Err(EncDiscError::RecoveryRejected);
        }
        let field = std::str::from_utf8(&self.bytes[self.offset..self.offset + len])
            .map_err(|_| EncDiscError::RecoveryRejected)?;
        self.offset += len;
        Ok(Zeroizing::new(field.to_string()))
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(raw)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GenesisAccount;
    use serde_json::Value;
    use sociacl_ids::{
        history_state, HistoryResolver, Jwks, KeyState, Reason, ResolutionContext, Rotate,
        SiwePolicy,
    };
    use std::collections::{BTreeMap, BTreeSet};

    const RING: &str = include_str!("../../../vectors/encrypted-discovery/account-keyring.json");
    const RECOVERY: &str = include_str!("../../../vectors/encrypted-discovery/recovery-copy.json");
    const RECORDS: &str = include_str!("../../../vectors/ids/records.json");

    fn recovery() -> Value {
        serde_json::from_str(RECOVERY).unwrap()
    }

    fn ring() -> Value {
        serde_json::from_str(RING).unwrap()
    }

    #[test]
    fn argon2id_small_vector_matches_hash_wasm() {
        // m=32 is below the floor. This only checks the library against hash-wasm.
        let params = Params::new(32, 3, 4, Some(32)).unwrap();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(b"password", b"somesalt", &mut out)
            .unwrap();
        assert_eq!(
            encode_hex(&out),
            "bb0cc80a3e671149526915418c6eefe761bb19d5d2d567a017703e0cea6ab05c"
        );
    }

    #[test]
    fn limits_match_the_shared_vector() {
        let v = recovery();
        let limits = &v["limits"];
        assert_eq!(
            limits["version"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.version.floor)
        );
        assert_eq!(
            limits["version"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.version.ceiling)
        );
        assert_eq!(
            limits["memoryKiB"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.memory_kib.floor)
        );
        assert_eq!(
            limits["memoryKiB"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.memory_kib.ceiling)
        );
        assert_eq!(
            limits["iterations"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.iterations.floor)
        );
        assert_eq!(
            limits["iterations"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.iterations.ceiling)
        );
        assert_eq!(
            limits["parallelism"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.parallelism.floor)
        );
        assert_eq!(
            limits["parallelism"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.parallelism.ceiling)
        );
        assert_eq!(
            limits["hashLength"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.hash_length.floor)
        );
        assert_eq!(
            limits["hashLength"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.hash_length.ceiling)
        );
        assert_eq!(
            limits["saltLength"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.salt_length.floor)
        );
        assert_eq!(
            limits["saltLength"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.salt_length.ceiling)
        );
        assert_eq!(
            limits["keyringSerialMax"].as_u64().unwrap() as usize,
            KEYRING_SERIAL_MAX
        );
        assert_eq!(
            limits["deliveryBlobMax"].as_u64().unwrap() as usize,
            crate::limits::DELIVERY_BLOB_MAX
        );
        assert_eq!(
            limits["recoveryEnvelopeMax"].as_u64().unwrap() as usize,
            RECOVERY_ENVELOPE_MAX
        );
        assert_eq!(
            limits["recoveryAbsoluteMax"].as_u64().unwrap() as usize,
            RECOVERY_ABSOLUTE_MAX
        );
        assert_eq!(
            limits["wrapsPerPrincipal"].as_u64().unwrap() as usize,
            crate::limits::MAX_WRAPS_PER_PRINCIPAL
        );
        assert_eq!(
            v["unicodeVersion"].as_str().unwrap(),
            crate::unicode16::UNICODE_VERSION
        );
        assert_eq!(
            RECOVERY_ABSOLUTE_MAX,
            RECOVERY_ENVELOPE_MAX + ARGON2ID_LIMITS.salt_length.ceiling as usize
        );
        assert_eq!(v["domain"].as_str().unwrap(), DOMAIN_RECOVERY);
        assert_eq!(v["keyringDomain"].as_str().unwrap(), DOMAIN_KEYRING_PLAIN);
        assert_eq!(
            v["bindDomain"].as_str().unwrap(),
            crate::delivery::DOMAIN_DELIVERY_BIND
        );
        assert_eq!(
            v["sigDomain"].as_str().unwrap(),
            crate::delivery::DOMAIN_DELIVERY_SIG
        );
    }

    #[test]
    fn parameter_and_size_rejects_happen_before_the_kdf() {
        let v = recovery();
        let principal = principal_of();
        let held = hold();
        let ctx = context_of(&held);
        for row in v["rejects"].as_array().unwrap() {
            if row["blobBytes"].is_u64() {
                continue;
            }
            let name = row["name"].as_str().unwrap();
            let started = std::time::Instant::now();
            let envelope = if let Some(bytes) = row["envelopeBytes"].as_u64() {
                RecoveryEnvelope {
                    principal: principal.clone(),
                    rotation_seq: 0,
                    bytes: vec![0u8; bytes as usize],
                }
            } else if let Some(ciphertext_bytes) = row["ciphertextBytes"].as_u64() {
                crafted(row, ciphertext_bytes as usize, &principal)
            } else {
                crafted(row, 16, &principal)
            };
            let error = open_recovery_copy(b"x", &envelope, &principal, 0, &[], &ctx).unwrap_err();
            assert!(started.elapsed().as_millis() < 200, "{name} ran the KDF");
            assert_eq!(token(&error), row["error"].as_str().unwrap(), "{name}");
        }
    }

    fn crafted(row: &Value, ciphertext_len: usize, principal: &PrincipalId) -> RecoveryEnvelope {
        let limits = &recovery()["limits"];
        let version = row["version"]
            .as_u64()
            .unwrap_or(limits["version"]["floor"].as_u64().unwrap()) as u32;
        let memory = row["memoryKiB"]
            .as_u64()
            .unwrap_or(limits["memoryKiB"]["floor"].as_u64().unwrap()) as u32;
        let iterations = row["iterations"]
            .as_u64()
            .unwrap_or(limits["iterations"]["floor"].as_u64().unwrap())
            as u32;
        let parallelism = row["parallelism"]
            .as_u64()
            .unwrap_or(limits["parallelism"]["floor"].as_u64().unwrap())
            as u32;
        let hash_length = row["hashLength"]
            .as_u64()
            .unwrap_or(limits["hashLength"]["floor"].as_u64().unwrap())
            as u32;
        let salt = if let Some(hex) = row["saltHex"].as_str() {
            hexutil::decode_hex(hex).unwrap()
        } else {
            vec![0x11; 16]
        };
        let mut bytes = Vec::new();
        write_header(
            &mut bytes,
            version,
            memory,
            iterations,
            parallelism,
            hash_length,
            &salt,
            0,
        );
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&vec![0u8; ciphertext_len]);
        RecoveryEnvelope {
            principal: principal.clone(),
            rotation_seq: 0,
            bytes,
        }
    }

    fn token(err: &EncDiscError) -> String {
        match err {
            EncDiscError::RecoveryRejected => "recovery-rejected".into(),
            EncDiscError::RecoveryParams => "recovery-params".into(),
            EncDiscError::RecoveryStale => "recovery-stale".into(),
            EncDiscError::KeyringTooLarge => "keyring-too-large".into(),
            EncDiscError::StoreRejected => "store-rejected".into(),
            EncDiscError::IdentityRejected(reason) => reason.clone(),
            other => panic!("unexpected {other}"),
        }
    }

    fn principal_of() -> PrincipalId {
        parse_principal_id(ring()["genesis"]["principal"].as_str().unwrap()).unwrap()
    }

    fn genesis_keyring() -> AccountKeyring {
        let g = &ring()["genesis"];
        let account = GenesisAccount::import(
            g["laneId"].as_str().unwrap(),
            g["signingPub"].as_str().unwrap(),
            g["signingPriv"].as_str().unwrap(),
            g["epub"].as_str().unwrap(),
            g["epriv"].as_str().unwrap(),
        )
        .unwrap();
        AccountKeyring::from_genesis(&account).unwrap()
    }

    struct Hold {
        jwks: Jwks,
        policy: SiwePolicy,
        pinned: BTreeSet<String>,
        links: BTreeMap<String, Value>,
        binding: Vec<Value>,
        revocations: Vec<Value>,
        now: u64,
    }

    fn hold() -> Hold {
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let ctx = &records["context"];
        let ring = ring();
        Hold {
            jwks: serde_json::from_value(ctx["jwks"].clone()).unwrap(),
            policy: serde_json::from_value(ctx["policy"].clone()).unwrap(),
            pinned: ctx["pinnedIss"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect(),
            links: ctx["links"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
                .collect(),
            binding: vec![ring["genesisBinding"].clone()],
            revocations: Vec::new(),
            now: ctx["now"].as_u64().unwrap(),
        }
    }

    fn missing_history(_: &PrincipalId, _: u64, _: u64) -> Result<KeyState, Reason> {
        Err(Reason::MissingHistory)
    }

    fn context_of(hold: &Hold) -> ResolutionContext<'_> {
        ResolutionContext {
            jwks: &hold.jwks,
            links: &hold.links,
            revocations: &hold.revocations,
            now: hold.now,
            policy: &hold.policy,
            pinned_iss: &hold.pinned,
            history: &missing_history,
            genesis_epub_bindings: &hold.binding,
        }
    }

    #[test]
    fn recovery_copy_matches_the_shared_vector_and_stays_off_gun() {
        let v = recovery();
        let keyring = genesis_keyring();
        let held = hold();
        let ctx = context_of(&held);
        let mut store = MemoryRecoveryStore::default();
        let salt = hexutil::decode_hex(v["saltHex"].as_str().unwrap()).unwrap();
        let nonce = hexutil::decode_hex(v["nonceHex"].as_str().unwrap()).unwrap();
        let envelope = seal_recovery_copy_with(
            &keyring,
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &salt,
            &nonce,
            &mut store,
        )
        .unwrap();
        let hex = encode_hex(&envelope.bytes);
        let expected = v["envelopeHex"].as_str().unwrap();
        if expected.is_empty() {
            panic!("envelope {hex}");
        }
        assert_eq!(hex, expected);
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_some());
        assert!(!store.is_authority());
        assert!(!store.sees_plaintext());
        assert!(!store.sees_passphrase());
        let opened = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            0,
            &[],
            &ctx,
        )
        .unwrap();
        assert_eq!(opened.principal(), keyring.principal());
        assert_eq!(opened.current_priv(), keyring.current_priv());
        assert_eq!(opened.current_epriv(), keyring.current_epriv());
        assert_eq!(opened.lane_id(), keyring.lane_id());
        let gun = opened.gun_document();
        assert!(!gun.contains(keyring.current_priv()));
        assert!(!gun.contains(keyring.current_epriv()));
        assert!(!gun.contains(keyring.lane_id()));
        assert!(!hex.contains(keyring.current_priv()));
        assert!(!hex.contains(keyring.lane_id()));
        let wrong = open_recovery_copy(
            v["wrongPassphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            0,
            &[],
            &ctx,
        )
        .unwrap_err();
        let mut tampered = envelope.clone();
        let last = tampered.bytes.len() - 1;
        tampered.bytes[last] ^= 0x01;
        let tamper = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &tampered,
            keyring.principal(),
            0,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(token(&wrong), token(&tamper));
        assert_eq!(token(&wrong), "recovery-rejected");
        let stale = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            1,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(token(&stale), "recovery-stale");
    }

    #[test]
    fn rotation_reseals_a_new_version_and_writes_only_the_adapter() {
        let v = recovery();
        let ring = ring();
        let keyring = genesis_keyring();
        let held = hold();
        let ctx = context_of(&held);
        let mut store = MemoryRecoveryStore::default();
        let old = RecoveryEnvelope {
            principal: keyring.principal().clone(),
            rotation_seq: 0,
            bytes: hexutil::decode_hex(v["envelopeHex"].as_str().unwrap()).unwrap(),
        };
        store.put_copy(&old).unwrap();
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_some());
        let trusted: Vec<&str> = ring["trusted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect();
        let (rotation, envelope) = rotate_and_reseal(
            &keyring,
            &trusted,
            ring["lost"].as_str().unwrap(),
            &[],
            &ctx,
            || {
                Ok(crate::keyring::RotationMint {
                    signing_pub: ring["mint"]["signingPub"].as_str().unwrap().to_string(),
                    signing_priv: Zeroizing::new(
                        ring["mint"]["signingPriv"].as_str().unwrap().to_string(),
                    ),
                    epub: ring["mint"]["epub"].as_str().unwrap().to_string(),
                    epriv: Zeroizing::new(ring["mint"]["epriv"].as_str().unwrap().to_string()),
                    lane_id: ring["mint"]["laneId"].as_str().unwrap().to_string(),
                })
            },
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &mut store,
        )
        .unwrap();
        assert_eq!(rotation.keyring.rotation_seq(), 1);
        assert_eq!(envelope.rotation_seq, 1);
        assert!(store.get_copy(keyring.principal(), 1).unwrap().is_some());
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_some());
        let unpublished =
            commit_recovery_copy(keyring.principal(), &[], &ctx, &mut store).unwrap_err();
        assert_eq!(
            token(&unpublished),
            v["retention"]["commitUnverified"].as_str().unwrap()
        );
        assert!(store.get_copy(keyring.principal(), 1).unwrap().is_some());
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_some());
        let hex = encode_hex(&envelope.bytes);
        assert!(!hex.contains(rotation.keyring.current_priv()));
        assert!(!hex.contains(rotation.keyring.current_epriv()));
        assert!(!hex.contains(rotation.keyring.lane_id()));
        assert!(!rotation
            .keyring
            .gun_document()
            .contains(rotation.keyring.current_priv()));
        let stale = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &old,
            keyring.principal(),
            1,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(token(&stale), "recovery-stale");
        let imported = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            1,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert!(matches!(imported, EncDiscError::PubMismatch));
    }

    #[test]
    fn the_store_copies_envelopes_and_keeps_only_the_latest() {
        let principal = principal_of();
        let mut store = MemoryRecoveryStore::default();
        let mut older = dummy_envelope(&principal, 0);
        let original = older.bytes.clone();
        store.put_copy(&older).unwrap();
        older.bytes[40] ^= 0x01;
        let stored = store.get_copy(&principal, 0).unwrap().unwrap();
        assert_eq!(stored.bytes, original);
        let mut viewed = store.get_copy(&principal, 0).unwrap().unwrap();
        viewed.bytes[40] ^= 0xff;
        assert_eq!(
            store.get_copy(&principal, 0).unwrap().unwrap().bytes,
            original
        );
        let newer = dummy_envelope(&principal, 1);
        store.put_copy(&newer).unwrap();
        assert!(store.get_copy(&principal, 0).unwrap().is_some());
        assert!(store.get_copy(&principal, 1).unwrap().is_some());
        assert_eq!(store.len(), 1);
        let mut resealed = dummy_envelope(&principal, 0);
        resealed.bytes[40] ^= 0x11;
        store.put_copy(&resealed).unwrap();
        assert_eq!(
            store.get_copy(&principal, 0).unwrap().unwrap().bytes,
            resealed.bytes
        );
        assert!(store.get_copy(&principal, 1).unwrap().is_some());
        let downgrade = dummy_envelope(&principal, 0);
        let mut high = MemoryRecoveryStore::default();
        high.put_copy(&dummy_envelope(&principal, 2)).unwrap();
        let refused = high.put_copy(&downgrade).unwrap_err();
        assert_eq!(
            token(&refused),
            recovery()["retention"]["downgrade"].as_str().unwrap()
        );
        assert!(high.get_copy(&principal, 2).unwrap().is_some());
        assert!(high.get_copy(&principal, 0).unwrap().is_none());
        let between = high.put_copy(&dummy_envelope(&principal, 1)).unwrap_err();
        assert!(matches!(between, EncDiscError::StoreRejected));
        assert!(high.get_copy(&principal, 2).unwrap().is_some());
        let mut gap = MemoryRecoveryStore::default();
        gap.put_copy(&dummy_envelope(&principal, 0)).unwrap();
        gap.put_copy(&dummy_envelope(&principal, 2)).unwrap();
        let skipped = gap.put_copy(&dummy_envelope(&principal, 1)).unwrap_err();
        assert!(matches!(skipped, EncDiscError::StoreRejected));
        assert!(gap.get_copy(&principal, 0).unwrap().is_some());
        assert!(gap.get_copy(&principal, 2).unwrap().is_some());
    }

    #[test]
    fn composed_and_decomposed_passphrases_derive_the_same_key() {
        let n = &recovery()["normalization"];
        let nfc = encode_passphrase(n["nfc"].as_str().unwrap()).unwrap();
        let nfd = encode_passphrase(n["nfd"].as_str().unwrap()).unwrap();
        assert_eq!(nfc.as_slice(), nfd.as_slice());
        assert_eq!(encode_hex(&nfc), "636166c3a9");
        let salt = hexutil::decode_hex(n["saltHex"].as_str().unwrap()).unwrap();
        let key = derive_key(&nfc, &salt, 65536, 3, 4, 32).unwrap();
        assert_eq!(
            encode_hex(key.as_ref()),
            n["derivedKeyHex"].as_str().unwrap()
        );
        assert!(matches!(
            encode_passphrase("").unwrap_err(),
            EncDiscError::RecoveryParams
        ));
        assert!(matches!(
            encode_passphrase(" \t\n").unwrap_err(),
            EncDiscError::RecoveryParams
        ));
        let vector = recovery();
        let rejects = vector["passphraseRejects"].as_array().unwrap();
        for row in rejects {
            let text = row["passphrase"].as_str().unwrap();
            let rejected = encode_passphrase(text).unwrap_err();
            assert_eq!(token(&rejected), row["error"].as_str().unwrap(), "{text:?}");
            let bytes = text.as_bytes();
            let sealed = seal_recovery_copy_with(
                &genesis_keyring(),
                bytes,
                &[0x11; 16],
                &[0x22; 12],
                &mut MemoryRecoveryStore::default(),
            )
            .unwrap_err();
            assert_eq!(token(&sealed), "recovery-params");
        }
        assert_eq!(
            encode_hex(encode_passphrase("\u{feff}").unwrap().as_ref()),
            "efbbbf"
        );
        let spaced = encode_passphrase(" café").unwrap();
        assert_eq!(spaced[0], b' ');
        let started = std::time::Instant::now();
        let rejected = seal_recovery_copy_with(
            &genesis_keyring(),
            b"   ",
            &[0x11; 16],
            &[0x22; 12],
            &mut MemoryRecoveryStore::default(),
        )
        .unwrap_err();
        assert!(started.elapsed().as_millis() < 200);
        assert!(matches!(rejected, EncDiscError::RecoveryParams));
    }

    #[test]
    fn a_cross_principal_envelope_is_recovery_rejected_before_the_kdf() {
        let v = recovery();
        let principal = principal_of();
        let other = parse_principal_id(ring()["mint"]["signingPub"].as_str().unwrap()).unwrap();
        let held = hold();
        let ctx = context_of(&held);
        let envelope = RecoveryEnvelope {
            principal: principal.clone(),
            rotation_seq: 0,
            bytes: hexutil::decode_hex(v["envelopeHex"].as_str().unwrap()).unwrap(),
        };
        let started = std::time::Instant::now();
        let swapped = open_recovery_copy(b"x", &envelope, &other, 0, &[], &ctx).unwrap_err();
        assert!(started.elapsed().as_millis() < 200);
        assert_eq!(token(&swapped), "recovery-rejected");
        let mut both = envelope.clone();
        both.principal = other.clone();
        let ad = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &both,
            &other,
            0,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(token(&ad), "recovery-rejected");
    }

    #[test]
    fn a_recovery_copy_opens_after_rotation_against_its_chain() {
        let v = recovery();
        let ring = ring();
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let rotation = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == ring["witnessed"]["rotationName"].as_str().unwrap())
            .unwrap()["input"]
            .clone();
        let (genesis_pub, _genesis_priv) =
            scalar_sea(ring["witnessed"]["genesisScalar"].as_u64().unwrap() as u16);
        let (genesis_epub, genesis_epriv) =
            scalar_sea(ring["witnessed"]["genesisEpubScalar"].as_u64().unwrap() as u16);
        let (current_pub, current_priv) =
            scalar_sea(ring["witnessed"]["currentScalar"].as_u64().unwrap() as u16);
        let (current_epub, current_epriv) =
            scalar_sea(ring["witnessed"]["epubScalar"].as_u64().unwrap() as u16);
        let ctx = &records["context"];
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let pinned: BTreeSet<String> = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        let links: BTreeMap<String, Value> = ctx["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
            .collect();
        let authenticated = ctx["authenticatedAccounts"].clone();
        let history = |principal: &PrincipalId, at, until| {
            if !authenticated
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str() == Some(principal.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            let empty: Vec<Rotate> = Vec::new();
            Ok(history_state(principal, &empty, at, until))
        };
        let resolver: &HistoryResolver<'_> = &history;
        let revocations = Vec::new();
        let base = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &revocations,
            now: ctx["now"].as_u64().unwrap(),
            policy: &policy,
            pinned_iss: &pinned,
            history: resolver,
            genesis_epub_bindings: &[],
        };
        let retired = [(genesis_epub.as_str(), genesis_epriv.as_str())];
        let rotations = [rotation];
        let keyring = AccountKeyring::import(
            &genesis_pub,
            &genesis_epub,
            &current_pub,
            current_priv.as_str(),
            &current_epub,
            current_epriv.as_str(),
            &retired,
            ring["witnessed"]["laneId"].as_str().unwrap(),
            ring["witnessed"]["contentEpoch"].as_u64().unwrap(),
            ring["witnessed"]["rotationSeq"].as_u64().unwrap(),
            &rotations,
            &base,
        )
        .unwrap();
        let mut store = MemoryRecoveryStore::default();
        let salt = hexutil::decode_hex(v["saltHex"].as_str().unwrap()).unwrap();
        let nonce = hexutil::decode_hex(v["nonceHex"].as_str().unwrap()).unwrap();
        let envelope = seal_recovery_copy_with(
            &keyring,
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &salt,
            &nonce,
            &mut store,
        )
        .unwrap();
        let opened = open_recovery_copy_str(
            v["passphraseUtf8"].as_str().unwrap(),
            &envelope,
            keyring.principal(),
            1,
            &rotations,
            &base,
        )
        .unwrap();
        assert_eq!(opened.rotation_seq(), 1);
        assert_eq!(opened.current_priv(), keyring.current_priv());
        let unsigned = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            1,
            &[],
            &base,
        )
        .unwrap_err();
        assert!(matches!(unsigned, EncDiscError::PubMismatch));
        let mut forward = MemoryRecoveryStore::default();
        forward
            .put_copy(&dummy_envelope(keyring.principal(), 0))
            .unwrap();
        forward
            .put_copy(&dummy_envelope(keyring.principal(), 1))
            .unwrap();
        commit_recovery_copy(keyring.principal(), &rotations, &base, &mut forward).unwrap();
        assert!(forward.get_copy(keyring.principal(), 0).unwrap().is_none());
        assert!(forward.get_copy(keyring.principal(), 1).unwrap().is_some());
        let again = commit_recovery_copy(keyring.principal(), &rotations, &base, &mut forward);
        assert!(matches!(again, Err(EncDiscError::StoreRejected)));
        assert!(forward.get_copy(keyring.principal(), 1).unwrap().is_some());
        let older = forward.put_copy(&dummy_envelope(keyring.principal(), 0));
        assert!(matches!(older, Err(EncDiscError::StoreRejected)));
        let mut stuck = MemoryRecoveryStore::default();
        stuck
            .put_copy(&dummy_envelope(keyring.principal(), 0))
            .unwrap();
        stuck
            .put_copy(&dummy_envelope(keyring.principal(), 1))
            .unwrap();
        let unverified = commit_recovery_copy(keyring.principal(), &[], &base, &mut stuck);
        assert!(matches!(unverified, Err(EncDiscError::StoreRejected)));
        assert!(stuck.get_copy(keyring.principal(), 0).unwrap().is_some());
        assert!(stuck.get_copy(keyring.principal(), 1).unwrap().is_some());
    }

    fn dummy_envelope(principal: &PrincipalId, seq: u64) -> RecoveryEnvelope {
        let mut bytes = Vec::new();
        write_header(&mut bytes, 0x13, 65536, 3, 4, 32, &[0x11; 16], seq);
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&[0u8; 16]);
        RecoveryEnvelope {
            principal: principal.clone(),
            rotation_seq: seq,
            bytes,
        }
    }

    fn scalar_sea(n: u16) -> (String, Zeroizing<String>) {
        let mut bytes = [0u8; 32];
        bytes[30] = (n >> 8) as u8;
        bytes[31] = n as u8;
        let secret = p256::SecretKey::from_slice(&bytes).unwrap();
        bytes.zeroize();
        (
            crate::sea::sea_pub_from_secret(&secret).unwrap(),
            crate::sea::sea_priv_from_secret(&secret).unwrap(),
        )
    }
}
