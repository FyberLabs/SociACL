//! Consume-contract checks for encrypted discovery.
//!
//! The shared fixture is `vectors/encrypted-discovery/consume.json`.
//! A hop, a status statement, and a chat node do not mint.

use sociacl_encdisc::{
    accept_current_key, accept_envelope, accept_grant_manifest, accept_group_inbox_sender,
    accept_item_locator, accept_revision_manifest, accept_status_signer, account_key_entry_hash,
    account_key_head_bytes, account_key_head_signed_by_sea, account_key_log_bytes,
    consume_statement_mints, env_digest, epoch_revision_bytes, epoch_revision_id,
    grant_manifest_bytes, group_inbox_body_hash, group_inbox_sig_bytes, group_inbox_soul,
    item_revision_soul, item_root_soul, length_prefixed, manifest_soul, revision_manifest_bytes,
    sha256_hex, status_authority_bytes, AccountKeyLogEntry, AccountKeyLogHead, ConsumeDecision,
    CurrentKeyDecision, EpochManifestBody, GroupInboxWriteSig, RevisionManifest,
    StatusAuthorityBinding,
};

const FIXTURE: &str = include_str!("../../../vectors/encrypted-discovery/consume.json");

fn case(name: &str) -> (usize, String) {
    let document: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let row = document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap();
    (
        row["encodedLen"].as_u64().unwrap() as usize,
        row["sha256"].as_str().unwrap().to_string(),
    )
}

fn expect_hash(name: &str, bytes: &[u8], hash: &str) {
    let (len, expected) = case(name);
    assert_eq!(bytes.len(), len, "{name}");
    assert_eq!(hash, expected, "{name}");
    assert_eq!(hash, sha256_hex(bytes), "{name}");
}

fn manifest(env: &str, status: Option<&str>) -> RevisionManifest {
    RevisionManifest {
        item_id: "itema".to_string(),
        e: 1,
        rev: "rev1".to_string(),
        parent: "none".to_string(),
        key_id: "a".repeat(64),
        env_digest: env.to_string(),
        status_auth_pub: status.map(str::to_string),
    }
}

fn genesis() -> AccountKeyLogEntry {
    AccountKeyLogEntry {
        account: "provider:acct".to_string(),
        key_pub: "sea-current".to_string(),
        seq: 0,
        prev: "none".to_string(),
    }
}

fn next(prev: &str) -> AccountKeyLogEntry {
    AccountKeyLogEntry {
        account: "provider:acct".to_string(),
        key_pub: "sea-next".to_string(),
        seq: 1,
        prev: prev.to_string(),
    }
}

#[test]
fn canonical_consume_vectors_match() {
    let env_bytes = length_prefixed(&[
        "s3rch-env-digest-v1",
        "itema",
        "1",
        "rev1",
        "aes-gcm",
        "aabb",
        "ccdd",
    ])
    .unwrap();
    let env = env_digest("itema", 1, "rev1", "aes-gcm", "aabb", "ccdd").unwrap();
    expect_hash("env-digest", &env_bytes, &env);

    let plain = manifest(&env, None);
    let plain_bytes = revision_manifest_bytes(&plain).unwrap();
    expect_hash("revision-manifest", &plain_bytes, &sha256_hex(&plain_bytes));
    let authed = manifest(&env, Some("sea-status-pub"));
    let authed_bytes = revision_manifest_bytes(&authed).unwrap();
    expect_hash(
        "revision-manifest-auth",
        &authed_bytes,
        &sha256_hex(&authed_bytes),
    );
    assert_ne!(sha256_hex(&plain_bytes), sha256_hex(&authed_bytes));

    let soul = manifest_soul("itema", "rev1").unwrap();
    let grant = grant_manifest_bytes("itema", "rev1", &soul).unwrap();
    expect_hash("grant-manifest", &grant, &sha256_hex(&grant));

    let binding = StatusAuthorityBinding {
        account: "provider:acct".to_string(),
        account_pub: "sea-account".to_string(),
        status_auth_pub: "sea-status-pub".to_string(),
        seq: 2,
    };
    let binding_bytes = status_authority_bytes(&binding).unwrap();
    expect_hash(
        "status-authority",
        &binding_bytes,
        &sha256_hex(&binding_bytes),
    );

    let body_bytes = length_prefixed(&["s3rch-group-inbox-body-v1", "eph", "ct", "iv"]).unwrap();
    let body_hash = group_inbox_body_hash("eph", "ct", "iv").unwrap();
    expect_hash("group-inbox-body", &body_bytes, &body_hash);
    let sig = GroupInboxWriteSig {
        tag: "gtag".to_string(),
        entry_id: "entry1".to_string(),
        sender_pub: "sea-sender".to_string(),
        body_hash: body_hash.clone(),
    };
    let sig_bytes = group_inbox_sig_bytes(&sig).unwrap();
    expect_hash("group-inbox-ssig", &sig_bytes, &sha256_hex(&sig_bytes));

    let genesis = genesis();
    let genesis_bytes = account_key_log_bytes(&genesis).unwrap();
    let genesis_hash = account_key_entry_hash(&genesis).unwrap();
    expect_hash("account-key-genesis", &genesis_bytes, &genesis_hash);
    let next = next(&genesis_hash);
    let next_bytes = account_key_log_bytes(&next).unwrap();
    let next_hash = account_key_entry_hash(&next).unwrap();
    expect_hash("account-key-next", &next_bytes, &next_hash);
    let head = AccountKeyLogHead {
        account: "provider:acct".to_string(),
        seq: 1,
        entry_hash: next_hash,
    };
    let head_bytes = account_key_head_bytes(&head).unwrap();
    expect_hash("account-key-head", &head_bytes, &sha256_hex(&head_bytes));
    assert!(!account_key_head_signed_by_sea());

    let epoch = EpochManifestBody {
        object: "chat_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111".to_string(),
        epoch: 1,
        previous_epoch: 0,
        device_id: "device-1".to_string(),
        key_commitment: "opaque-commitment".to_string(),
        settle_window_ms: 86_400_000,
        acl_snapshot: "f9ac289c45e5e277cf0ecee22616a46b07d5ff92b83df0b13cacf8a9b5097449".to_string(),
        status_auth_pub: Some("sea-status-pub".to_string()),
    };
    let epoch_bytes = epoch_revision_bytes(&epoch).unwrap();
    let epoch_id = epoch_revision_id(&epoch).unwrap();
    expect_hash("epoch-status-auth", &epoch_bytes, &epoch_id);
    let mut absent = epoch.clone();
    absent.status_auth_pub = None;
    assert_eq!(
        epoch_revision_id(&absent).unwrap(),
        "d068c39be0391bb64791839b21a21413392abe28f4e8f824d524884f07bd486f"
    );
}

#[test]
fn envelope_path_and_manifest_soul() {
    assert_eq!(
        item_revision_soul("itema", "rev1").unwrap(),
        "s3rch/items/itema/r/rev1"
    );
    assert_eq!(
        manifest_soul("itema", "rev1").unwrap(),
        "s3rch/items/itema/m/rev1"
    );
    assert_eq!(item_root_soul("itema").unwrap(), "s3rch/items/itema");
    assert_eq!(
        group_inbox_soul("gtag", "entry1").unwrap(),
        "s3rch/ginbox/gtag/entry1"
    );
    assert!(item_revision_soul("item/a", "rev1").is_err());
    assert!(item_revision_soul(".", "rev1").is_err());

    let digest = env_digest("itema", 1, "rev1", "aes-gcm", "aabb", "ccdd").unwrap();
    assert_eq!(
        accept_item_locator(2, 1, "rev1", "rev1", false),
        ConsumeDecision::Accept
    );
    assert_eq!(
        accept_item_locator(2, 1, "rev1", "rev1", true),
        ConsumeDecision::Refuse("root-ciphertext")
    );
    assert_eq!(
        accept_envelope(
            "itema",
            1,
            "rev1",
            "s3rch/items/itema/r/rev1",
            false,
            "aes-gcm",
            "aabb",
            "ccdd",
            &digest,
        ),
        ConsumeDecision::Accept
    );
    assert_eq!(
        accept_envelope(
            "itema",
            1,
            "rev1",
            "s3rch/items/itema/r/rev1",
            true,
            "aes-gcm",
            "aabb",
            "ccdd",
            &digest,
        ),
        ConsumeDecision::Refuse("root-ciphertext")
    );
    assert_eq!(
        accept_envelope(
            "itema",
            1,
            "rev1",
            "s3rch/items/itema",
            false,
            "aes-gcm",
            "aabb",
            "ccdd",
            &digest,
        ),
        ConsumeDecision::Refuse("bad-soul")
    );
    assert_eq!(
        accept_envelope(
            "itema",
            1,
            "rev1",
            "s3rch/items/itema/r/rev1",
            false,
            "aes-gcm",
            "aabb",
            "ccdd",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        ConsumeDecision::Refuse("digest-mismatch")
    );

    let soul = manifest_soul("itema", "rev1").unwrap();
    assert_eq!(
        accept_grant_manifest(Some(&soul), "itema", "rev1", false),
        ConsumeDecision::Accept
    );
    assert_eq!(
        accept_grant_manifest(None, "itema", "rev1", false),
        ConsumeDecision::Refuse("bad-soul")
    );
    assert_eq!(
        accept_grant_manifest(Some(&soul), "itema", "rev1", true),
        ConsumeDecision::Refuse("author-lane")
    );
    assert_eq!(
        accept_grant_manifest(Some("s3rch/items/itema/m/other"), "itema", "rev1", false),
        ConsumeDecision::Refuse("bad-soul")
    );
    assert_eq!(
        accept_revision_manifest(1, &manifest(&digest, None), "itema", "rev1", &digest, false),
        ConsumeDecision::Accept
    );
    assert_eq!(
        accept_revision_manifest(1, &manifest(&digest, None), "itema", "rev1", &digest, true),
        ConsumeDecision::Refuse("bad-soul")
    );
}

#[test]
fn status_authority_and_group_inbox() {
    let binding = StatusAuthorityBinding {
        account: "provider:acct".to_string(),
        account_pub: "sea-account".to_string(),
        status_auth_pub: "sea-status".to_string(),
        seq: 4,
    };
    assert_eq!(
        accept_status_signer(
            "sea-account",
            "sea-account",
            None,
            None,
            None,
            false,
            "status"
        ),
        ConsumeDecision::Accept
    );
    assert_eq!(
        accept_status_signer(
            "sea-status",
            "sea-account",
            None,
            None,
            None,
            false,
            "status"
        ),
        ConsumeDecision::Refuse("missing-binding")
    );
    assert_eq!(
        accept_status_signer(
            "sea-status",
            "sea-account",
            Some(&binding),
            Some("sea-status"),
            Some(4),
            true,
            "status",
        ),
        ConsumeDecision::Accept
    );
    assert_eq!(
        accept_status_signer(
            "sea-status",
            "sea-account",
            Some(&binding),
            Some("sea-status"),
            Some(3),
            true,
            "status",
        ),
        ConsumeDecision::Refuse("authority-key")
    );
    for purpose in ["manifest", "grant", "binding"] {
        assert_eq!(
            accept_status_signer(
                "sea-status",
                "sea-account",
                Some(&binding),
                Some("sea-status"),
                Some(4),
                true,
                purpose,
            ),
            ConsumeDecision::Refuse("authority-key"),
            "{purpose}"
        );
        assert_eq!(
            accept_status_signer(
                "sea-account",
                "sea-account",
                Some(&binding),
                Some("sea-status"),
                Some(4),
                true,
                purpose,
            ),
            ConsumeDecision::Accept,
            "{purpose}"
        );
    }

    assert_eq!(
        accept_group_inbox_sender("sea-sender", "sea-sender", true, true, false),
        ConsumeDecision::Accept
    );
    assert_eq!(
        accept_group_inbox_sender("sea-sender", "sea-sender", true, true, true),
        ConsumeDecision::Refuse("group-writer-key")
    );
    assert_eq!(
        accept_group_inbox_sender("sea-sender", "sea-sender", false, true, false),
        ConsumeDecision::Refuse("not-member")
    );
    assert_eq!(
        accept_group_inbox_sender("sea-old", "sea-sender", true, true, false),
        ConsumeDecision::Refuse("superseded")
    );
}

#[test]
fn current_key_fails_closed() {
    let genesis = genesis();
    let genesis_hash = account_key_entry_hash(&genesis).unwrap();
    let next = next(&genesis_hash);
    let next_hash = account_key_entry_hash(&next).unwrap();
    let head = AccountKeyLogHead {
        account: "provider:acct".to_string(),
        seq: 1,
        entry_hash: next_hash.clone(),
    };
    let entries = [genesis.clone(), next.clone()];
    match accept_current_key(Some(&head), &entries, None, true, "sea-next") {
        CurrentKeyDecision::Accept { key_pub } => assert_eq!(key_pub, "sea-next"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        accept_current_key(Some(&head), &entries, None, false, "sea-next"),
        CurrentKeyDecision::Refuse("no-answer")
    ));
    assert!(matches!(
        accept_current_key(None, &entries, None, true, "sea-next"),
        CurrentKeyDecision::Refuse("missing-head")
    ));
    assert!(matches!(
        accept_current_key(Some(&head), &entries, None, true, "sea-current"),
        CurrentKeyDecision::Refuse("superseded")
    ));
    let mut broken_parent = genesis.clone();
    broken_parent.key_pub = "sea-forged".to_string();
    assert!(matches!(
        accept_current_key(
            Some(&head),
            &[broken_parent, next.clone()],
            None,
            true,
            "sea-next"
        ),
        CurrentKeyDecision::Refuse("prev-mismatch")
    ));
    let anchored = AccountKeyLogHead {
        account: "provider:acct".to_string(),
        seq: 1,
        entry_hash: next_hash,
    };
    match accept_current_key(
        Some(&anchored),
        &[next.clone()],
        Some(&genesis_hash),
        true,
        "sea-next",
    ) {
        CurrentKeyDecision::Accept { key_pub } => assert_eq!(key_pub, "sea-next"),
        other => panic!("{other:?}"),
    }
    let higher = AccountKeyLogEntry {
        account: "provider:acct".to_string(),
        key_pub: "sea-later".to_string(),
        seq: 9,
        prev: genesis_hash,
    };
    match accept_current_key(
        Some(&head),
        &[genesis, next, higher],
        None,
        true,
        "sea-next",
    ) {
        CurrentKeyDecision::Accept { key_pub } => assert_eq!(key_pub, "sea-next"),
        other => panic!("{other:?}"),
    }
    for kind in [
        "hop", "status", "chat", "manifest", "binding", "ssig", "log", "envelope",
    ] {
        assert!(!consume_statement_mints(kind), "{kind}");
    }
}
