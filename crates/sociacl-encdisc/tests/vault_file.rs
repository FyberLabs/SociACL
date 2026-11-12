#![cfg(unix)]
use sociacl_encdisc::*;
use sociacl_ids::parse_principal_id;
use std::{fs, os::unix::fs::{symlink, PermissionsExt}, sync::{Arc, Barrier}};
const OWNER: &str = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU";
fn guard() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(std::env::var("GITHUB_EVENT_NAME").as_deref(), Ok("schedule"));
    assert_eq!(std::env::var("NIGHTLY_SUITE").as_deref(), Ok("sociacl-browser"));
}
#[test]
#[ignore = "filesystem lifecycle belongs to central scheduled CI"]
fn private_atomic_cas_restart_retry_and_hostile_paths() {
    guard();
    let owner = parse_principal_id(OWNER).unwrap();
    let password = "violet radar platypus 47 granite orchestra";
    let a = seal_local_vault_item(&owner, None, b"name", b"original", password).unwrap();
    let b = seal_local_vault_item(&owner, Some(&a.item_id()), b"name", b"second", password).unwrap();
    let c = seal_local_vault_item(&owner, Some(&a.item_id()), b"name", b"third", password).unwrap();
    let root = std::env::temp_dir().join(format!("sociacl-vault-{}", a.version_id()));
    let store = LocalVaultFileStore::open(&root, true).unwrap();
    let original = store.write(&a, None).unwrap();
    assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
    let file = root.join(format!("{}.vault", a.item_id()));
    assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(store.write(&a, None).unwrap(), original); // Lost create response.
    assert!(store.write(&b, None).is_err());
    drop(store);
    let store = LocalVaultFileStore::open(&root, false).unwrap();
    assert_eq!(store.read(&original).unwrap().bytes(), a.bytes());
    let barrier = Arc::new(Barrier::new(2));
    let attempts: Vec<_> = [b.clone(), c.clone()].into_iter().map(|envelope| {
        let root = root.clone(); let expected = original.clone(); let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || { let store = LocalVaultFileStore::open(root, false).unwrap(); barrier.wait(); store.write(&envelope, Some(&expected)) })
    }).collect();
    let outcomes: Vec<_> = attempts.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    let winner = outcomes.into_iter().find_map(Result::ok).unwrap();
    let body = if winner.version_id == b.version_id() { &b } else { &c };
    assert_eq!(store.write(body, Some(&original)).unwrap(), winner); // Lost update response.
    assert!(store.read(&original).is_err()); assert_eq!(store.read(&winner).unwrap().bytes(), body.bytes());
    // A leftover crash lock fails closed and preserves committed data.
    let lock = root.join(format!("{}.lock", a.item_id())); fs::create_dir(&lock).unwrap();
    assert!(store.write(&a, Some(&winner)).is_err()); fs::remove_dir(&lock).unwrap();
    assert_eq!(store.read(&winner).unwrap().bytes(), body.bytes());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.read(&winner).is_err()); fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let target = root.join("outside.vault"); fs::rename(&file, &target).unwrap(); symlink(&target, &file).unwrap();
    assert!(store.read(&winner).is_err()); assert!(store.write(&a, Some(&winner)).is_err());
    assert_eq!(fs::read(&target).unwrap(), body.bytes());
    fs::remove_file(&file).unwrap(); fs::rename(&target, &file).unwrap();
    // Simulated rolled-back bytes cannot satisfy an independently retained head.
    fs::write(&file, a.bytes()).unwrap(); assert!(store.read(&winner).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "encrypted history persistence belongs to central scheduled CI"]
fn encrypted_history_survives_file_restart_and_exact_retry() {
    guard();
    use sociacl_ids::{history_state, PrincipalId, Jwks, SiwePolicy, ResolutionContext};
    let fixture:serde_json::Value=serde_json::from_str(include_str!("../../../vectors/encrypted-discovery/sea-fixture.json")).unwrap();
    let account=GenesisAccount::import(fixture["laneId"].as_str().unwrap(),fixture["signing"]["pub"].as_str().unwrap(),
        fixture["signing"]["priv"].as_str().unwrap(),fixture["encryption"]["epub"].as_str().unwrap(),fixture["encryption"]["epriv"].as_str().unwrap()).unwrap().into_secret();
    let version=VaultVersion{item_id:"11".repeat(32),version_id:"22".repeat(32),owner:account.account().into(),parents:vec![],epoch:1,
        revision_id:"aa".repeat(32),ciphertext_digest:"33".repeat(32),sensitive:true,issued_at:1};
    let signed=SignedVaultVersion{signature:account.sign_vault_version(&version).unwrap(),version:version.clone()};
    let expected=VaultReadExpectation{object:"local-secret".into(),owner:version.owner.clone(),item_id:version.item_id.clone(),version_id:version.version_id.clone(),
        ciphertext_digest:version.ciphertext_digest.clone(),epoch:1,revision_id:version.revision_id.clone()};
    let jwks=Jwks{keys:vec![]};let links=Default::default();let issuers=Default::default();
    let policy=SiwePolicy{allowed_domains:vec![],allowed_uris:vec![],allowed_chain_ids:vec![],clock_skew_seconds:0};
    let history=|p:&PrincipalId,at,until|Ok(history_state(p,&[],at,until));
    let ctx=ResolutionContext{jwks:&jwks,links:&links,revocations:&[],now:10,policy:&policy,pinned_iss:&issuers,history:&history,genesis_epub_bindings:&[]};
    let graph=VaultVersionHistory::initialize(&signed,&expected,&sha256_hex(&vault_version_signing_bytes(&version).unwrap()),&[],&ctx).unwrap();
    let password="violet radar platypus 47 granite orchestra";
    let (envelope,checkpoint)=seal_vault_history(&graph,None,password).unwrap();
    let root=std::env::temp_dir().join(format!("sociacl-history-{}",envelope.version_id()));
    let store=LocalVaultFileStore::open(&root,true).unwrap();
    let head=store.write(&envelope,None).unwrap();
    assert_eq!(store.write(&envelope,None).unwrap(),head);
    drop(store);
    let store=LocalVaultFileStore::open(&root,false).unwrap();
    let loaded=store.read(&head).unwrap();
    let restored=open_vault_history(&loaded,&checkpoint,password).unwrap();
    assert_eq!(restored.read_expectation().unwrap().object,"local-secret");
    assert_eq!(restored.read_expectation().unwrap().version_id,version.version_id);
    let event=VaultAudit{event_id:"44".repeat(32),item_id:version.item_id.clone(),version_id:version.version_id.clone(),actor:account.account().into(),
        device_id:"55".repeat(32),operation:"put".into(),outcome:"allowed".into(),issued_at:1,previous_digest:"00".repeat(32)};
    let signed_audit=SignedVaultAudit{signature:account.sign_vault_audit(&event).unwrap(),event:event.clone()};
    let audit=VaultAuditHistory::initialize(&signed_audit,&graph,account.account(),&sha256_hex(&vault_audit_signing_bytes(&event).unwrap()),&[],&ctx).unwrap();
    let journal=VaultJournal::new(graph.clone(),audit.clone()).unwrap();
    let (combined,combined_head)=seal_vault_journal(&journal,None,password).unwrap();
    let published=store.write(&combined,None).unwrap();
    assert_eq!(store.write(&combined,None).unwrap(),published);
    drop(store);let store=LocalVaultFileStore::open(&root,false).unwrap();
    let loaded=store.read(&published).unwrap();
    let recovered=open_vault_journal(&loaded,&combined_head,password).unwrap();
    assert_eq!(recovered.audit().head(),audit.head());
    assert_eq!(recovered.versions().read_expectation().unwrap().version_id,version.version_id);
    let next_event=VaultAudit{event_id:"66".repeat(32),operation:"read".into(),issued_at:2,previous_digest:audit.head().into(),..event};
    let next_signed=SignedVaultAudit{signature:account.sign_vault_audit(&next_event).unwrap(),event:next_event};
    let next_audit=audit.advance(&next_signed,&graph,account.account(),&[],&ctx).unwrap();
    let next=VaultJournal::new(graph,next_audit).unwrap();
    let (updated,updated_head)=seal_vault_journal(&next,Some(&combined.item_id()),password).unwrap();
    let current=store.write(&updated,Some(&published)).unwrap();
    assert_eq!(store.write(&updated,Some(&published)).unwrap(),current);
    assert!(store.read(&published).is_err());
    assert!(open_vault_journal(&combined,&updated_head,password).is_err());
    let recovered=open_vault_journal(&store.read(&current).unwrap(),&updated_head,password).unwrap();
    assert!(recovered.audit().event(&"66".repeat(32)).is_some());
    let file=root.join(format!("{}.vault",envelope.item_id()));fs::remove_file(file).unwrap();
    assert!(store.read(&head).is_err());
    fs::remove_dir_all(root).unwrap();
}
