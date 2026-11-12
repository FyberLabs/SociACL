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
