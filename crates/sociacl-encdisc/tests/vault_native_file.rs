#![cfg(unix)]
use sociacl_encdisc::*;
use sociacl_ids::{history_state, parse_principal_id, sign_with_keyring, Jwks, PrincipalId, Reason, ResolutionContext, SiwePolicy};
use std::{cell::Cell, fs, os::unix::fs::{symlink, PermissionsExt}, sync::{Arc, Barrier}};
const PASSWORD: &str = "violet radar platypus 47 granite orchestra";
fn signed(previous: Option<&VaultSyncHead>, index: &str) -> VaultSyncHead {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("../../../vectors/vault/sync-head.json")).unwrap();
    let mut head = parse_vault_sync_head(&fixture["head"]).unwrap();
    head.index_digest = index.repeat(32);
    if let Some(previous) = previous {
        head.revision = previous.revision + 1;
        head.previous_digest = vault_sync_head_floor(previous).unwrap().digest;
        head.issued_at = previous.issued_at + 1;
    }
    let mut scalar = [0u8; 32]; scalar[31] = 1;
    head.sig = sign_with_keyring(&scalar, &vault_sync_head_signing_bytes(&head).unwrap(), &parse_principal_id(&head.owner).unwrap()).unwrap();
    head
}
fn policy() -> SiwePolicy {
    SiwePolicy { allowed_domains: vec![], allowed_uris: vec![], allowed_chain_ids: vec![], clock_skew_seconds: 0 }
}
#[test]
#[ignore = "native custody filesystem lifecycle belongs to central scheduled CI"]
fn native_custody_restart_retry_race_and_fail_closed_state() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(std::env::var("GITHUB_EVENT_NAME").as_deref(), Ok("schedule"));
    assert_eq!(std::env::var("NIGHTLY_SUITE").as_deref(), Ok("sociacl-browser"));
    let initial = signed(None, "34");
    let envelope = seal_native_vault_head(&initial, PASSWORD).unwrap();
    let base = std::env::temp_dir().join(format!("sociacl-native-{}", envelope.item_id()));
    fs::create_dir(&base).unwrap();
    let ciphertext = base.join("ciphertext"); let ledger = base.join("trusted-state");
    let jwks = Jwks { keys: vec![] }; let links = Default::default(); let issuers = Default::default(); let policy = policy();
    let now = Cell::new(20); let revoked = Cell::new(false);
    let history = |p: &PrincipalId, at, until| if revoked.get() { Err(Reason::MissingHistory) } else { Ok(history_state(p, &[], at, until)) };
    let current = || Ok(ResolutionContext { jwks: &jwks, links: &links, revocations: &[], now: now.get(), policy: &policy,
        pinned_iss: &issuers, history: &history, genesis_epub_bindings: &[] });
    let store = NativeVaultCustody::open(&ciphertext, &ledger, &initial.owner, &initial.vault_id, true).unwrap();
    let anchor = vault_sync_head_floor(&initial).unwrap();
    let mut wrong_anchor = anchor.clone(); wrong_anchor.digest = "56".repeat(32);
    assert!(store.initialize(&envelope, &wrong_anchor, PASSWORD, &[], &current).is_err());
    assert_eq!(store.initialize(&envelope, &anchor, PASSWORD, &[], &current).unwrap(), initial);
    assert_eq!(store.initialize(&envelope, &anchor, PASSWORD, &[], &current).unwrap(), initial);
    assert_eq!(fs::metadata(ledger.join("head.floor")).unwrap().permissions().mode() & 0o777, 0o600);
    drop(store);
    let store = NativeVaultCustody::open(&ciphertext, &ledger, &initial.owner, &initial.vault_id, false).unwrap();
    assert_eq!(store.read(PASSWORD, &[], &current).unwrap(), initial);
    now.set(19); assert!(store.read(PASSWORD, &[], &current).is_err()); now.set(20);
    revoked.set(true); assert!(store.read(PASSWORD, &[], &current).is_err()); revoked.set(false);
    let next = signed(Some(&initial), "45"); let prepared = seal_native_vault_head(&next, PASSWORD).unwrap();
    // Authentication can expire after ciphertext persistence but before floor CAS.
    let calls = Cell::new(0);
    let expires = || { calls.set(calls.get() + 1); if calls.get() > 1 { Err(EncDiscError::VaultRejected) } else { current() } };
    assert!(store.advance(&prepared, &anchor, PASSWORD, &[], expires).is_err());
    assert_eq!(store.read(PASSWORD, &[], &current).unwrap(), initial);
    assert_eq!(store.advance(&prepared, &anchor, PASSWORD, &[], &current).unwrap(), next);
    drop(store);
    let store = NativeVaultCustody::open(&ciphertext, &ledger, &initial.owner, &initial.vault_id, false).unwrap();
    assert_eq!(store.advance(&prepared, &anchor, PASSWORD, &[], &current).unwrap(), next);
    let resealed = seal_native_vault_head(&next, PASSWORD).unwrap();
    assert!(store.advance(&resealed, &anchor, PASSWORD, &[], &current).is_err());
    assert!(store.advance(&envelope, &anchor, PASSWORD, &[], &current).is_err());
    let floor = vault_sync_head_floor(&next).unwrap();
    let candidates = [signed(Some(&next), "67"), signed(Some(&next), "78")];
    let barrier = Arc::new(Barrier::new(2));
    let attempts: Vec<_> = candidates.iter().map(|candidate| {
        let sealed = seal_native_vault_head(candidate, PASSWORD).unwrap();
        let ciphertext = ciphertext.clone(); let ledger = ledger.clone(); let owner = initial.owner.clone(); let vault = initial.vault_id.clone();
        let barrier = Arc::clone(&barrier); let floor = floor.clone();
        let store = NativeVaultCustody::open(ciphertext, ledger, &owner, &vault, false).unwrap();
        std::thread::spawn(move || {
            let jwks = Jwks { keys: vec![] }; let links = Default::default(); let issuers = Default::default();
            let policy = SiwePolicy { allowed_domains: vec![], allowed_uris: vec![], allowed_chain_ids: vec![], clock_skew_seconds: 0 };
            let history = |p: &PrincipalId, at, until| Ok(history_state(p, &[], at, until));
            barrier.wait();
            store.advance(&sealed, &floor, PASSWORD, &[], || Ok(ResolutionContext { jwks: &jwks, links: &links,
                revocations: &[], now: 20, policy: &policy, pinned_iss: &issuers, history: &history, genesis_epub_bindings: &[] }))
        })
    }).collect();
    let results: Vec<_> = attempts.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(store.read(PASSWORD, &[], &current).unwrap(), winner);
    let state = ledger.join("head.floor"); let retained = ledger.join("retained");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.read(PASSWORD, &[], &current).is_err());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&state, &retained).unwrap(); symlink(&retained, &state).unwrap();
    assert!(store.read(PASSWORD, &[], &current).is_err());
    fs::remove_file(&state).unwrap();
    assert!(NativeVaultCustody::open(&ciphertext, &ledger, &initial.owner, &initial.vault_id, false).is_err());
    assert!(store.initialize(&envelope, &anchor, PASSWORD, &[], &current).is_err());
    fs::rename(&retained, &state).unwrap();
    assert_eq!(store.read(PASSWORD, &[], &current).unwrap(), winner);
    drop(store);
    fs::remove_dir_all(base).unwrap();
}
