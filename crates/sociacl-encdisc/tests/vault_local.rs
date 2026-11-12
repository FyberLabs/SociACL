use sociacl_encdisc::*;
use sociacl_ids::parse_principal_id;
const OWNER: &str = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU";
const OTHER: &str = "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg.B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E";
const PASSWORD: &str = "violet radar platypus 47 granite orchestra";
#[test]
fn local_custody_is_confidential_randomized_and_owner_bound() {
    let owner = parse_principal_id(OWNER).unwrap();
    let a = seal_local_vault_item(&owner, None, b"private item name", b"private secret payload", PASSWORD).unwrap();
    let b = seal_local_vault_item(&owner, Some(&a.item_id()), b"private item name", b"private secret payload", PASSWORD).unwrap();
    assert_eq!(a.item_id(), b.item_id()); assert_ne!(a.version_id(), b.version_id()); assert_ne!(a.bytes(), b.bytes());
    for secret in [OWNER.as_bytes(), b"private item name", b"private secret payload", PASSWORD.as_bytes()] {
        assert!(!a.bytes().windows(secret.len()).any(|window| window == secret));
    }
    let opened = open_local_vault_item(&a, &owner, PASSWORD).unwrap();
    assert_eq!(opened.metadata(), b"private item name"); assert_eq!(opened.content(), b"private secret payload");
    assert!(open_local_vault_item(&a, &owner, "a completely different wrong passphrase").is_err());
    assert!(open_local_vault_item(&a, &parse_principal_id(OTHER).unwrap(), PASSWORD).is_err());
    let mut changed = a.bytes().to_vec(); let end = changed.len()-1; changed[end] ^= 1;
    assert!(open_local_vault_item(&LocalVaultEnvelope::from_bytes(changed).unwrap(), &owner, PASSWORD).is_err());
    let mut substituted = a.bytes().to_vec(); substituted[104..136].copy_from_slice(&b.bytes()[104..136]);
    assert!(open_local_vault_item(&LocalVaultEnvelope::from_bytes(substituted).unwrap(), &owner, PASSWORD).is_err());
}
#[test]
fn custody_enforces_one_mib_and_bounded_metadata() {
    let owner = parse_principal_id(OWNER).unwrap();
    let content = vec![0x5a; VAULT_ITEM_MAX_BYTES]; let metadata = vec![0x42; VAULT_METADATA_MAX_BYTES];
    let envelope = seal_local_vault_item(&owner, None, &metadata, &content, PASSWORD).unwrap();
    assert_eq!(envelope.bytes().len(), VAULT_LOCAL_MAX_BYTES);
    let opened = open_local_vault_item(&envelope, &owner, PASSWORD).unwrap();
    assert_eq!(opened.content(), content); assert_eq!(opened.metadata(), metadata);
    assert!(seal_local_vault_item(&owner, None, &[], &vec![0; VAULT_ITEM_MAX_BYTES+1], PASSWORD).is_err());
    assert!(seal_local_vault_item(&owner, None, &vec![0; VAULT_METADATA_MAX_BYTES+1], &[], PASSWORD).is_err());
    assert!(LocalVaultEnvelope::from_bytes(vec![0; VAULT_LOCAL_MAX_BYTES+1]).is_err());
    assert!(LocalVaultEnvelope::from_bytes(vec![0; 100]).is_err());
    assert!(seal_local_vault_item(&owner, None, &[], &[], &"a".repeat(4097)).is_err());
    assert!(seal_local_vault_item(&owner, None, &[], &[], "password").is_err());
}
