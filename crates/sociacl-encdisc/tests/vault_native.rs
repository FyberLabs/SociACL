use sociacl_encdisc::*;
use sociacl_ids::parse_principal_id;

fn head() -> VaultSyncHead {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("../../../vectors/vault/sync-head.json")).unwrap();
    parse_vault_sync_head(&fixture["head"]).unwrap()
}
const PASSWORD: &str = "violet radar platypus 47 granite orchestra";

#[test]
fn native_custody_binds_owner_namespace_domain_and_ciphertext() {
    let h = head();
    let sealed = seal_native_vault_head(&h, PASSWORD).unwrap();
    assert_eq!(open_native_vault_head(&sealed, &h.owner, &h.vault_id, PASSWORD).unwrap(), h);
    assert!(open_native_vault_head(&sealed, &h.owner, &"56".repeat(32), PASSWORD).is_err());
    assert!(open_native_vault_head(&sealed, &h.owner, &h.vault_id, "incorrect").is_err());
    let mut corrupt = sealed.bytes().to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(open_native_vault_head(&LocalVaultEnvelope::from_bytes(corrupt).unwrap(), &h.owner, &h.vault_id, PASSWORD).is_err());
    let owner = parse_principal_id(&h.owner).unwrap();
    let wrong_domain = seal_local_vault_item(&owner, None, b"some other private data", b"{}", PASSWORD).unwrap();
    assert!(open_native_vault_head(&wrong_domain, &h.owner, &h.vault_id, PASSWORD).is_err());
    // A custody opener is deliberately not a signature verifier; the durable
    // consumer must authenticate even a successfully decrypted envelope.
    assert_eq!(h.sig, "A".repeat(86));
    let resealed = seal_native_vault_head(&h, PASSWORD).unwrap();
    assert_ne!(sealed.item_id(), resealed.item_id());
    assert_ne!(sealed.bytes(), resealed.bytes());
}

#[test]
fn malformed_heads_and_weak_new_passphrases_refuse_before_persistence() {
    let mut h = head(); h.revision = 0;
    assert!(seal_native_vault_head(&h, PASSWORD).is_err());
    assert!(seal_native_vault_head(&head(), "password").is_err());
}
