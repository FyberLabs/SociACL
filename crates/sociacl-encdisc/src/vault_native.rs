//! Native passphrase custody for private sync heads, using the existing SAVFILE1
//! profile. This is not container v2, a hardware slot, or item-read authority.
use serde_json::{json, Value};
use sociacl_ids::{parse_principal_id, ResolutionContext};
use zeroize::Zeroizing;
use crate::{canonical, EncDiscError, LocalVaultEnvelope, VaultSyncHead, VaultSyncHeadFloor,
    open_local_vault_item, seal_local_vault_item, parse_vault_sync_head,
    vault_sync_head_signing_bytes, vault_sync_head_floor, verify_vault_sync_head};

const DOMAIN: &[u8] = b"sociacl-native-vault-head-v1";
const MAX_HEAD_BYTES: usize = 8192;
const MAX_ENVELOPE_BYTES: usize = 16384;

/// Prepare once and retain these exact ciphertext bytes across ambiguous writes.
/// Preparation checks the schema, not authorization. The native consumer verifies
/// the signature and current history again inside its durable transaction.
pub fn seal_native_vault_head(head: &VaultSyncHead, password: &str) -> Result<LocalVaultEnvelope, EncDiscError> {
    vault_sync_head_signing_bytes(head)?;
    let owner = parse_principal_id(&head.owner).map_err(|_| EncDiscError::VaultRejected)?;
    let bytes = Zeroizing::new(serde_json::to_vec(&json!({"v":head.v,"owner":head.owner,"vaultId":head.vault_id,
        "revision":head.revision,"previousDigest":head.previous_digest,"keybagDigest":head.keybag_digest,
        "indexDigest":head.index_digest,"minimumProfile":head.minimum_profile,"issuedAt":head.issued_at,"sig":head.sig}))
        .map_err(|_| EncDiscError::VaultRejected)?);
    if bytes.len() > MAX_HEAD_BYTES { return Err(EncDiscError::VaultRejected); }
    // A fresh opaque item ID makes each prepared snapshot immutable. Never overwrite
    // the ciphertext referenced by the last committed independent floor.
    seal_local_vault_item(&owner, None, DOMAIN, &bytes, password)
}

/// Custody unlock only. Use NativeVaultCustody for authenticated, floor-bound reads.
pub fn open_native_vault_head(envelope: &LocalVaultEnvelope, owner: &str, vault_id: &str,
    password: &str) -> Result<VaultSyncHead, EncDiscError> {
    if envelope.bytes().len() > MAX_ENVELOPE_BYTES { return Err(EncDiscError::VaultRejected); }
    let principal = parse_principal_id(owner).map_err(|_| EncDiscError::VaultRejected)?;
    let opened = open_local_vault_item(envelope, &principal, password)?;
    if opened.metadata() != DOMAIN || opened.content().len() > MAX_HEAD_BYTES { return Err(EncDiscError::VaultRejected); }
    let value: Value = serde_json::from_slice(opened.content()).map_err(|_| EncDiscError::VaultRejected)?;
    let head = parse_vault_sync_head(&value)?;
    if head.owner != owner || head.vault_id != vault_id { return Err(EncDiscError::VaultRejected); }
    Ok(head)
}

pub(crate) fn authenticate(head: &VaultSyncHead, owner: &str, vault: &str, floor: &VaultSyncHeadFloor,
    checked_at: u64, rotations: &[Value], context: &ResolutionContext<'_>) -> Result<u64, EncDiscError> {
    canonical::canonical_decimal(checked_at)?;
    if vault_sync_head_floor(head)? != *floor || context.now < checked_at { return Err(EncDiscError::VaultRejected); }
    verify_vault_sync_head(head, owner, vault, rotations, context)?;
    Ok(context.now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sociacl_ids::{history_state, sign_with_keyring, Jwks, PrincipalId, Reason, SiwePolicy};
    #[test]
    fn custody_authentication_requires_exact_floor_fresh_clock_and_live_history() {
        let fixture: Value = serde_json::from_str(include_str!("../../../vectors/vault/sync-head.json")).unwrap();
        let mut head = parse_vault_sync_head(&fixture["head"]).unwrap();
        let owner = parse_principal_id(&head.owner).unwrap();
        let mut scalar = [0u8; 32]; scalar[31] = 1;
        head.sig = sign_with_keyring(&scalar, &vault_sync_head_signing_bytes(&head).unwrap(), &owner).unwrap();
        let floor = vault_sync_head_floor(&head).unwrap();
        let jwks = Jwks { keys: vec![] }; let links = Default::default(); let issuers = Default::default();
        let policy = SiwePolicy { allowed_domains: vec![], allowed_uris: vec![], allowed_chain_ids: vec![], clock_skew_seconds: 0 };
        let history = |p: &PrincipalId, at, until| Ok(history_state(p, &[], at, until));
        let mut context = ResolutionContext { jwks: &jwks, links: &links, revocations: &[], now: 20, policy: &policy,
            pinned_iss: &issuers, history: &history, genesis_epub_bindings: &[] };
        assert_eq!(authenticate(&head, &head.owner, &head.vault_id, &floor, 20, &[], &context).unwrap(), 20);
        assert!(authenticate(&head, &head.owner, &head.vault_id, &floor, 21, &[], &context).is_err());
        let mut wrong = floor.clone(); wrong.digest = "67".repeat(32);
        assert!(authenticate(&head, &head.owner, &head.vault_id, &wrong, 20, &[], &context).is_err());
        let missing = |_: &PrincipalId, _, _| Err(Reason::MissingHistory);
        context.history = &missing;
        assert!(authenticate(&head, &head.owner, &head.vault_id, &floor, 20, &[], &context).is_err());
        context.history = &history;
        head.sig = "A".repeat(86);
        assert!(authenticate(&head, &head.owner, &head.vault_id, &floor, 20, &[], &context).is_err());
    }
}
