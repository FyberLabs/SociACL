//! Passphrase custody for a local item. Unlocking is not identity or read authority.
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use sociacl_ids::{parse_principal_id, PrincipalId};
use zeroize::Zeroizing;
use crate::{encode_passphrase, check_recovery_passphrase, EncDiscError};
use crate::hexutil::{decode_hex, encode_hex};

pub const VAULT_ITEM_MAX_BYTES: usize = 1_048_576;
pub const VAULT_METADATA_MAX_BYTES: usize = 16_384;
const MAGIC: &[u8; 8] = b"SAVFILE1";
// magic | salt16 | wrapNonce24 | dataNonce24 | itemId32 | versionId32
const HEADER: usize = 136;
const WRAPPED_KEY: usize = 48;
const INNER_HEADER: usize = 87 + 4 + 4;
pub const VAULT_LOCAL_MAX_BYTES: usize = HEADER + WRAPPED_KEY + INNER_HEADER + VAULT_METADATA_MAX_BYTES + VAULT_ITEM_MAX_BYTES + 16;
const MIN_BYTES: usize = HEADER + WRAPPED_KEY + INNER_HEADER + 16;
const MAX_PASSPHRASE_BYTES: usize = 4096;

/// An encrypted local custody envelope, not an authorized vault version.
#[derive(Clone)]
pub struct LocalVaultEnvelope { bytes: Vec<u8> }
pub struct OpenedLocalVaultItem {
    metadata: Zeroizing<Vec<u8>>,
    content: Zeroizing<Vec<u8>>,
}
impl OpenedLocalVaultItem {
    pub fn metadata(&self) -> &[u8] { &self.metadata }
    pub fn content(&self) -> &[u8] { &self.content }
}
impl LocalVaultEnvelope {
    /// Size and format admission only. Authentication happens in open_local_vault_item.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EncDiscError> {
        validate(&bytes)?; Ok(Self { bytes })
    }
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    pub fn item_id(&self) -> String { encode_hex(&self.bytes[72..104]) }
    pub fn version_id(&self) -> String { encode_hex(&self.bytes[104..136]) }
}
fn reject<T>(_: T) -> EncDiscError { EncDiscError::VaultRejected }
fn validate(bytes: &[u8]) -> Result<(), EncDiscError> {
    if bytes.len() < MIN_BYTES || bytes.len() > VAULT_LOCAL_MAX_BYTES || &bytes[..8] != MAGIC {
        return Err(EncDiscError::VaultRejected);
    }
    Ok(())
}
fn passphrase(text: &str) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    if text.len() > MAX_PASSPHRASE_BYTES { return Err(EncDiscError::VaultRejected); }
    let encoded = encode_passphrase(text).map_err(reject)?;
    if encoded.len() > MAX_PASSPHRASE_BYTES { return Err(EncDiscError::VaultRejected); }
    Ok(encoded)
}
fn derive(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8;32]>, EncDiscError> {
    // Fixed v1 cost: no attacker-controlled work factor, and no weak fallback.
    let params = Params::new(65_536, 3, 4, Some(32)).map_err(reject)?;
    let mut key = Zeroizing::new([0u8;32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut()).map_err(reject)?;
    Ok(key)
}
fn aad(domain: &[u8], header: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(domain.len() + header.len());
    result.extend_from_slice(domain); result.extend_from_slice(header); result
}
/// Fresh random DEK, salt and both nonces. `None` mints a new opaque item ID; updates
/// supply the existing item ID. Every call generates a new opaque version ID.
/// Metadata and expected owner are inside encryption. The owner is not authenticated
/// by passphrase possession: signed-version/Check/epoch verification is still required.
pub fn seal_local_vault_item(owner: &PrincipalId, item_id: Option<&str>, metadata: &[u8], content: &[u8],
    password: &str) -> Result<LocalVaultEnvelope, EncDiscError> {
    parse_principal_id(owner.as_ref()).map_err(reject)?;
    if metadata.len() > VAULT_METADATA_MAX_BYTES || content.len() > VAULT_ITEM_MAX_BYTES { return Err(EncDiscError::VaultRejected); }
    let password = passphrase(password)?;
    check_recovery_passphrase(&password, owner, None)?;
    let mut header = [0u8;HEADER]; OsRng.fill_bytes(&mut header[8..]); header[..8].copy_from_slice(MAGIC);
    if let Some(id) = item_id {
        if id.len() != 64 { return Err(EncDiscError::VaultRejected); }
        header[72..104].copy_from_slice(&decode_hex(id).map_err(reject)?);
    }
    let kek = derive(&password, &header[8..24])?;
    let mut dek = Zeroizing::new([0u8;32]); OsRng.fill_bytes(dek.as_mut());
    let wrap_aad = aad(b"sociacl-vault-local-wrap-v1\0", &header);
    let wrapped = XChaCha20Poly1305::new_from_slice(&kek[..]).map_err(reject)?
        .encrypt(XNonce::from_slice(&header[24..48]), Payload { msg: &dek[..], aad: &wrap_aad }).map_err(reject)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(INNER_HEADER + metadata.len() + content.len()));
    plain.extend_from_slice(owner.as_ref().as_bytes());
    plain.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    plain.extend_from_slice(&(content.len() as u32).to_le_bytes());
    plain.extend_from_slice(metadata); plain.extend_from_slice(content);
    let mut data_aad = aad(b"sociacl-vault-local-data-v1\0", &header); data_aad.extend_from_slice(&wrapped);
    let encrypted = XChaCha20Poly1305::new_from_slice(&dek[..]).map_err(reject)?
        .encrypt(XNonce::from_slice(&header[48..72]), Payload { msg: &plain, aad: &data_aad }).map_err(reject)?;
    let mut bytes = header.to_vec(); bytes.extend(wrapped); bytes.extend(encrypted);
    LocalVaultEnvelope::from_bytes(bytes)
}
/// Local custody unlock only. The caller must enforce current authorization before
/// releasing an item to a grantee or executing it. Current strength scoring is not
/// applied on open, so later scoring changes cannot destroy an existing backup.
pub fn open_local_vault_item(envelope: &LocalVaultEnvelope, expected_owner: &PrincipalId,
    password: &str) -> Result<OpenedLocalVaultItem, EncDiscError> {
    let bytes = envelope.bytes(); validate(bytes)?;
    parse_principal_id(expected_owner.as_ref()).map_err(reject)?;
    let password = passphrase(password)?; let header = &bytes[..HEADER];
    let kek = derive(&password, &header[8..24])?;
    let wrapped = &bytes[HEADER..HEADER+WRAPPED_KEY];
    let wrap_aad = aad(b"sociacl-vault-local-wrap-v1\0", header);
    let dek = Zeroizing::new(XChaCha20Poly1305::new_from_slice(&kek[..]).map_err(reject)?
        .decrypt(XNonce::from_slice(&header[24..48]), Payload { msg: wrapped, aad: &wrap_aad }).map_err(reject)?);
    if dek.len() != 32 { return Err(EncDiscError::VaultRejected); }
    let mut data_aad = aad(b"sociacl-vault-local-data-v1\0", header); data_aad.extend_from_slice(wrapped);
    let plain = Zeroizing::new(XChaCha20Poly1305::new_from_slice(&dek).map_err(reject)?
        .decrypt(XNonce::from_slice(&header[48..72]), Payload { msg: &bytes[HEADER+WRAPPED_KEY..], aad: &data_aad }).map_err(reject)?);
    if plain.len() < INNER_HEADER || &plain[..87] != expected_owner.as_ref().as_bytes() { return Err(EncDiscError::VaultRejected); }
    let meta = u32::from_le_bytes(plain[87..91].try_into().map_err(reject)?) as usize;
    let body = u32::from_le_bytes(plain[91..95].try_into().map_err(reject)?) as usize;
    if meta > VAULT_METADATA_MAX_BYTES || body > VAULT_ITEM_MAX_BYTES || INNER_HEADER + meta + body != plain.len() { return Err(EncDiscError::VaultRejected); }
    Ok(OpenedLocalVaultItem { metadata: Zeroizing::new(plain[INNER_HEADER..INNER_HEADER+meta].to_vec()),
        content: Zeroizing::new(plain[INNER_HEADER+meta..].to_vec()) })
}
