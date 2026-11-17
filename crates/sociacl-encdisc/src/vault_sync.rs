//! Private sync-head contract shared with sociacl-ids/vault-sync.
//! No decryption, durable floor storage, remote freshness or item read authority.
use crate::{canonical, EncDiscError};
use serde_json::Value;
use sociacl_ids::{parse_principal_id, verify_signed_at, ResolutionContext};
pub const VAULT_SYNC_HEAD_DOMAIN: &str = "sociacl-vault-sync-head-v1";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSyncHead {
    pub v: u64, pub owner: String, pub vault_id: String, pub revision: u64,
    pub previous_digest: String, pub keybag_digest: String, pub index_digest: String,
    pub minimum_profile: u64, pub issued_at: u64, pub sig: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSyncHeadFloor { pub revision: u64, pub digest: String }
fn integer(value: &Value) -> Result<u64, EncDiscError> {
    let n = value.as_f64().ok_or(EncDiscError::BadEncoding)?;
    if !n.is_finite() || n.is_sign_negative() || n.fract() != 0.0 || n > 9_007_199_254_740_991.0 {
        return Err(EncDiscError::BadEncoding);
    }
    Ok(n as u64)
}
/// Parse a JSON value with the same exact fields and safe-integer bounds as TS.
/// As with JSON.parse, duplicate wire keys must be handled by the outer decoder.
pub fn parse_vault_sync_head(value: &Value) -> Result<VaultSyncHead, EncDiscError> {
    let m = value.as_object().ok_or(EncDiscError::BadEncoding)?;
    let fields = ["v", "owner", "vaultId", "revision", "previousDigest", "keybagDigest", "indexDigest", "minimumProfile", "issuedAt", "sig"];
    if m.len() != fields.len() || fields.iter().any(|key| !m.contains_key(*key)) { return Err(EncDiscError::BadEncoding); }
    let text = |key: &str| m[key].as_str().map(String::from).ok_or(EncDiscError::BadEncoding);
    let head = VaultSyncHead { v: integer(&m["v"])?, owner: text("owner")?, vault_id: text("vaultId")?, revision: integer(&m["revision"])?,
        previous_digest: text("previousDigest")?, keybag_digest: text("keybagDigest")?, index_digest: text("indexDigest")?,
        minimum_profile: integer(&m["minimumProfile"])?, issued_at: integer(&m["issuedAt"])?, sig: text("sig")? };
    vault_sync_head_signing_bytes(&head)?;
    Ok(head)
}
/// The signature is excluded. Encrypt the complete signed head before sync.
pub fn vault_sync_head_signing_bytes(h: &VaultSyncHead) -> Result<Vec<u8>, EncDiscError> {
    parse_principal_id(&h.owner).map_err(|r| EncDiscError::IdentityRejected(r.to_string()))?;
    for id in [&h.vault_id, &h.previous_digest, &h.keybag_digest, &h.index_digest] { canonical::require_digest_hex(id)?; }
    if h.v != 1 || h.revision == 0 || ![1, 2].contains(&h.minimum_profile) ||
        (h.revision == 1) != (h.previous_digest == "00".repeat(32)) || h.sig.len() != 86 ||
        !h.sig.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') { return Err(EncDiscError::BadEncoding); }
    canonical::length_prefixed(&[VAULT_SYNC_HEAD_DOMAIN, "1", &h.owner, &h.vault_id,
        &canonical::canonical_decimal(h.revision)?, &h.previous_digest, &h.keybag_digest,
        &h.index_digest, &h.minimum_profile.to_string(), &canonical::canonical_decimal(h.issued_at)?])
}
pub fn vault_sync_head_floor(h: &VaultSyncHead) -> Result<VaultSyncHeadFloor, EncDiscError> {
    Ok(VaultSyncHeadFloor { revision: h.revision, digest: canonical::sha256_hex(&vault_sync_head_signing_bytes(h)?) })
}
/// Authentication only. The caller separately compares an independently held
/// floor and rechecks authority at durable commit; success never grants a read.
pub fn verify_vault_sync_head(h: &VaultSyncHead, owner: &str, vault_id: &str,
    rotations: &[Value], context: &ResolutionContext<'_>) -> Result<(), EncDiscError> {
    let bytes = vault_sync_head_signing_bytes(h)?;
    canonical::canonical_decimal(context.now)?;
    if h.owner != owner || h.vault_id != vault_id || h.issued_at > context.now { return Err(EncDiscError::VaultRejected); }
    let principal = parse_principal_id(owner).map_err(|_| EncDiscError::VaultRejected)?;
    let proof = verify_signed_at(&principal, rotations, context, &bytes, &h.sig, h.issued_at).map_err(|_| EncDiscError::VaultRejected)?;
    let history = (context.history)(&principal, h.issued_at, context.now).map_err(|_| EncDiscError::VaultRejected)?;
    if history.key != proof.key || history.current_key != proof.key { return Err(EncDiscError::VaultRejected); }
    Ok(())
}
/// Structural continuity only: authenticate the next head separately and durably
/// compare-and-swap the independent floor after exact ciphertext readback.
pub fn validate_vault_sync_successor(previous: &VaultSyncHead, next: &VaultSyncHead) -> Result<(), EncDiscError> {
    let floor = vault_sync_head_floor(previous)?;
    vault_sync_head_signing_bytes(next)?;
    if previous.owner != next.owner || previous.vault_id != next.vault_id || previous.revision.checked_add(1) != Some(next.revision) ||
        next.previous_digest != floor.digest || next.minimum_profile < previous.minimum_profile || next.issued_at < previous.issued_at {
        return Err(EncDiscError::VaultRejected);
    }
    Ok(())
}
