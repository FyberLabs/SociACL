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
use crate::hexutil::{self, encode_hex, encode_secret_hex};
use crate::keyring::{rotate_keyring, AccountKeyring, KeyringRotation, RotationMint};
use crate::limits::{
    in_bound, ARGON2ID_LIMITS, KEYRING_SERIAL_MAX, RECOVERY_ENVELOPE_MAX, RECOVERY_HEADER_LEN,
    RECOVERY_NONCE_LEN, RECOVERY_TAG_LEN,
};
use crate::sea;

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
pub trait RecoveryCopyStore {
    fn put_copy(&mut self, envelope: &RecoveryEnvelope) -> Result<(), EncDiscError>;

    fn get_copy(
        &self,
        principal: &PrincipalId,
        rotation_seq: u64,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError>;

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

/// In-memory adapter. One ciphertext per principal and keyring version.
#[derive(Clone, Debug, Default)]
pub struct MemoryRecoveryStore {
    by_principal: BTreeMap<String, BTreeMap<u64, RecoveryEnvelope>>,
}

impl MemoryRecoveryStore {
    pub fn len(&self) -> usize {
        self.by_principal.values().map(|rows| rows.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RecoveryCopyStore for MemoryRecoveryStore {
    fn put_copy(&mut self, envelope: &RecoveryEnvelope) -> Result<(), EncDiscError> {
        if envelope.bytes.len() > RECOVERY_ENVELOPE_MAX || envelope.bytes.is_empty() {
            return Err(EncDiscError::StoreRejected);
        }
        let seq = header_rotation_seq(&envelope.bytes)?;
        if seq != envelope.rotation_seq {
            return Err(EncDiscError::StoreRejected);
        }
        self.by_principal
            .entry(envelope.principal.as_ref().to_string())
            .or_default()
            .insert(envelope.rotation_seq, envelope.clone());
        Ok(())
    }

    fn get_copy(
        &self,
        principal: &PrincipalId,
        rotation_seq: u64,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError> {
        Ok(self
            .by_principal
            .get(principal.as_ref())
            .and_then(|rows| rows.get(&rotation_seq))
            .cloned())
    }
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
    if passphrase.is_empty() {
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
    if bytes.len() > RECOVERY_ENVELOPE_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    keyring_ciphertext_hides_secrets(&bytes, keyring)?;
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
    if envelope.bytes.len() > RECOVERY_ENVELOPE_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let header = parse_header(&envelope.bytes)?;
    if passphrase.is_empty() {
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

/// Rotate, then seal a recovery copy of the new keyring version.
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

pub(crate) fn keyring_ciphertext_hides_secrets(
    blob: &[u8],
    keyring: &AccountKeyring,
) -> Result<(), EncDiscError> {
    let mut needles = Vec::new();
    needles.push(scalar_bytes(keyring.current_priv())?);
    needles.push(scalar_bytes(keyring.current_epriv())?);
    for row in keyring.retired() {
        needles.push(scalar_bytes(row.epriv())?);
    }
    needles.push(lane_bytes(keyring.lane_id())?);
    for lane in keyring.prior_lanes() {
        needles.push(lane_bytes(lane)?);
    }
    let hex = encode_hex(blob);
    for needle in &needles {
        if contains_bytes(blob, needle.as_slice()) {
            return Err(EncDiscError::RecoveryRejected);
        }
        let encoded = encode_secret_hex(needle.as_slice());
        if hex.contains(encoded.as_str()) {
            return Err(EncDiscError::RecoveryRejected);
        }
    }
    for lane in
        std::iter::once(keyring.lane_id()).chain(keyring.prior_lanes().iter().map(String::as_str))
    {
        if hex.contains(lane) {
            return Err(EncDiscError::RecoveryRejected);
        }
    }
    Ok(())
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

fn scalar_bytes(text: &str) -> Result<Zeroizing<[u8; 32]>, EncDiscError> {
    let secret = sea::ecdh_secret(text)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(secret.to_bytes().as_slice());
    Ok(out)
}

fn lane_bytes(text: &str) -> Result<Zeroizing<[u8; 32]>, EncDiscError> {
    hexutil::decode_secret_array::<32>(text).map_err(|_| EncDiscError::BadLane)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GenesisAccount;
    use serde_json::Value;
    use sociacl_ids::{Jwks, KeyState, Reason, ResolutionContext, SiwePolicy};
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
        assert_eq!(v["domain"].as_str().unwrap(), DOMAIN_RECOVERY);
        assert_eq!(v["keyringDomain"].as_str().unwrap(), DOMAIN_KEYRING_PLAIN);
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
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_none());
        let hex = encode_hex(&envelope.bytes);
        assert!(!hex.contains(rotation.keyring.current_priv()));
        assert!(!hex.contains(rotation.keyring.current_epriv()));
        assert!(!hex.contains(rotation.keyring.lane_id()));
        assert!(!rotation
            .keyring
            .gun_document()
            .contains(rotation.keyring.current_priv()));
        let old = RecoveryEnvelope {
            principal: keyring.principal().clone(),
            rotation_seq: 0,
            bytes: hexutil::decode_hex(v["envelopeHex"].as_str().unwrap()).unwrap(),
        };
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
}
