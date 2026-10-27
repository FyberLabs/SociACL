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
    sha256_hex, sign_sea, status_authority_bytes, AccountKeyAnchor, AccountKeyLogEntry,
    AccountKeyLogHead, ConsumeDecision, CurrentKeyDecision, EpochManifestBody, GroupInboxWriteSig,
    RevisionManifest, StatusAuthorityBinding, ACCOUNT_KEY_HEAD_MAX_AGE_MS, KEYRING_HISTORY_MAX,
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

fn provider_keys() -> (String, String) {
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vectors/encrypted-discovery/sea-fixture.json"
    ))
    .unwrap();
    let signing = &document["signing"];
    (
        signing["pub"].as_str().unwrap().to_string(),
        signing["priv"].as_str().unwrap().to_string(),
    )
}

const ISSUED_AT: u64 = 1_700_000_000_000;
const MAX_AGE_MS: u64 = 60_000;
const SKEW_MS: u64 = 5_000;

fn head_for(account: &str, seq: u64, entry_hash: impl Into<String>) -> AccountKeyLogHead {
    AccountKeyLogHead {
        account: account.to_string(),
        seq,
        entry_hash: entry_hash.into(),
        issued_at: ISSUED_AT,
        max_age_ms: MAX_AGE_MS,
    }
}

fn anchor_of(entry: AccountKeyLogEntry) -> AccountKeyAnchor {
    AccountKeyAnchor { entry }
}

fn sign_head(head: &AccountKeyLogHead) -> (String, String) {
    let (provider_pub, provider_priv) = provider_keys();
    let signature = sign_sea(&provider_priv, &account_key_head_bytes(head).unwrap()).unwrap();
    (provider_pub, signature)
}

fn check(
    head: Option<&AccountKeyLogHead>,
    entries: &[AccountKeyLogEntry],
    anchor: Option<&AccountKeyAnchor>,
    answered: bool,
    provider_pub: &str,
    signature: &str,
    expected: &str,
    statement: &str,
) -> CurrentKeyDecision {
    accept_current_key(
        head,
        entries,
        anchor,
        answered,
        provider_pub,
        signature,
        expected,
        statement,
        ISSUED_AT,
        SKEW_MS,
        MAX_AGE_MS,
    )
}

fn decide(
    head: Option<&AccountKeyLogHead>,
    entries: &[AccountKeyLogEntry],
    anchor: Option<&AccountKeyAnchor>,
    answered: bool,
    statement: &str,
) -> CurrentKeyDecision {
    let (provider_pub, signature) = match head {
        Some(head) => sign_head(head),
        None => (String::new(), String::new()),
    };
    check(
        head,
        entries,
        anchor,
        answered,
        &provider_pub,
        &signature,
        "provider:acct",
        statement,
    )
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
    let head = head_for("provider:acct", 1, next_hash);
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
    let mut empty_epoch = absent.clone();
    empty_epoch.status_auth_pub = Some(String::new());
    assert!(epoch_revision_bytes(&empty_epoch).is_err());
    let mut empty_manifest = plain;
    empty_manifest.status_auth_pub = Some(String::new());
    assert!(revision_manifest_bytes(&empty_manifest).is_err());
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
            Some("provider:acct"),
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
            Some("provider:acct"),
            Some(3),
            true,
            "status",
        ),
        ConsumeDecision::Refuse("authority-key")
    );
    assert_eq!(
        accept_status_signer(
            "sea-status",
            "sea-account",
            Some(&binding),
            Some("sea-status"),
            Some("provider:other"),
            Some(4),
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
                Some("provider:acct"),
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
                Some("provider:acct"),
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
    let head = head_for("provider:acct", 1, next_hash.clone());
    let entries = [genesis.clone(), next.clone()];
    let (provider_pub, signature) = sign_head(&head);
    let document: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(
        provider_pub,
        document["inputs"]["providerPub"].as_str().unwrap()
    );
    assert_eq!(
        signature,
        document["inputs"]["headSignature"].as_str().unwrap()
    );
    match check(
        Some(&head),
        &entries,
        None,
        true,
        &provider_pub,
        &signature,
        "provider:acct",
        "sea-next",
    ) {
        CurrentKeyDecision::Accept { key_pub } => assert_eq!(key_pub, "sea-next"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        check(
            Some(&head),
            &entries,
            None,
            false,
            &provider_pub,
            &signature,
            "provider:acct",
            "sea-next"
        ),
        CurrentKeyDecision::Refuse("no-answer")
    ));
    assert!(matches!(
        check(
            None,
            &entries,
            None,
            true,
            &provider_pub,
            &signature,
            "provider:acct",
            "sea-next"
        ),
        CurrentKeyDecision::Refuse("missing-head")
    ));
    assert!(matches!(
        decide(Some(&head), &entries, None, true, "sea-current"),
        CurrentKeyDecision::Refuse("superseded")
    ));
    assert!(matches!(
        check(
            Some(&head),
            &entries,
            None,
            true,
            &provider_pub,
            "00",
            "provider:acct",
            "sea-next"
        ),
        CurrentKeyDecision::Refuse("head-mismatch")
    ));
    let mut broken_parent = genesis.clone();
    broken_parent.key_pub = "sea-forged".to_string();
    assert!(matches!(
        decide(
            Some(&head),
            &[broken_parent, next.clone()],
            None,
            true,
            "sea-next"
        ),
        CurrentKeyDecision::Refuse("prev-mismatch")
    ));
    let anchor = anchor_of(genesis.clone());
    match decide(
        Some(&head),
        &[next.clone()],
        Some(&anchor),
        true,
        "sea-next",
    ) {
        CurrentKeyDecision::Accept { key_pub } => assert_eq!(key_pub, "sea-next"),
        other => panic!("{other:?}"),
    }
    let jumped = AccountKeyLogEntry {
        account: "provider:acct".to_string(),
        key_pub: "sea-nine".to_string(),
        seq: 9,
        prev: genesis_hash.clone(),
    };
    let jumped_head = head_for("provider:acct", 9, account_key_entry_hash(&jumped).unwrap());
    assert!(matches!(
        decide(
            Some(&jumped_head),
            &[genesis.clone(), jumped],
            Some(&anchor),
            true,
            "sea-nine"
        ),
        CurrentKeyDecision::Refuse("unlinked")
    ));
    let other = AccountKeyLogEntry {
        account: "provider:other".to_string(),
        key_pub: "sea-b".to_string(),
        seq: 0,
        prev: "none".to_string(),
    };
    let other_hash = account_key_entry_hash(&other).unwrap();
    let crossed = AccountKeyLogEntry {
        account: "provider:acct".to_string(),
        key_pub: "sea-a".to_string(),
        seq: 1,
        prev: other_hash.clone(),
    };
    let crossed_head = head_for(
        "provider:acct",
        1,
        account_key_entry_hash(&crossed).unwrap(),
    );
    let other_anchor = anchor_of(other.clone());
    assert!(matches!(
        decide(
            Some(&crossed_head),
            &[other, crossed],
            Some(&other_anchor),
            true,
            "sea-a"
        ),
        CurrentKeyDecision::Refuse("unlinked")
    ));
    let sea_entry = AccountKeyLogEntry {
        account: "provider:acct".to_string(),
        key_pub: provider_pub.clone(),
        seq: 0,
        prev: "none".to_string(),
    };
    let sea_head = head_for(
        "provider:acct",
        0,
        account_key_entry_hash(&sea_entry).unwrap(),
    );
    let (sea_pub, sea_sig) = sign_head(&sea_head);
    assert!(matches!(
        check(
            Some(&sea_head),
            &[sea_entry],
            None,
            true,
            &sea_pub,
            &sea_sig,
            "provider:acct",
            &provider_pub
        ),
        CurrentKeyDecision::Refuse("head-mismatch")
    ));
    let attacker_genesis = AccountKeyLogEntry {
        account: "provider:other".to_string(),
        key_pub: "sea-attacker-0".to_string(),
        seq: 0,
        prev: "none".to_string(),
    };
    let attacker_next = AccountKeyLogEntry {
        account: "provider:other".to_string(),
        key_pub: "sea-attacker".to_string(),
        seq: 1,
        prev: account_key_entry_hash(&attacker_genesis).unwrap(),
    };
    let attacker_head = head_for(
        "provider:other",
        1,
        account_key_entry_hash(&attacker_next).unwrap(),
    );
    let (attacker_pub, attacker_sig) = sign_head(&attacker_head);
    let attacker_entries = [attacker_genesis, attacker_next];
    assert!(matches!(
        check(
            Some(&attacker_head),
            &attacker_entries,
            None,
            true,
            &attacker_pub,
            &attacker_sig,
            "provider:acct",
            "sea-attacker",
        ),
        CurrentKeyDecision::Refuse("head-mismatch")
    ));
    match check(
        Some(&attacker_head),
        &attacker_entries,
        None,
        true,
        &attacker_pub,
        &attacker_sig,
        "provider:other",
        "sea-attacker",
    ) {
        CurrentKeyDecision::Accept { key_pub } => assert_eq!(key_pub, "sea-attacker"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        check(
            Some(&head),
            &entries,
            None,
            true,
            &provider_pub,
            &signature,
            "",
            "sea-next",
        ),
        CurrentKeyDecision::Refuse("head-mismatch")
    ));
    let higher = AccountKeyLogEntry {
        account: "provider:acct".to_string(),
        key_pub: "sea-later".to_string(),
        seq: 9,
        prev: genesis_hash,
    };
    match decide(
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

#[test]
fn account_key_log_accepts_the_keyring_limit() {
    let mut prev = "none".to_string();
    let mut entries = Vec::new();
    for seq in 0..=KEYRING_HISTORY_MAX as u64 {
        let entry = AccountKeyLogEntry {
            account: "provider:acct".to_string(),
            key_pub: format!("sea-{seq}"),
            seq,
            prev,
        };
        prev = account_key_entry_hash(&entry).unwrap();
        entries.push(entry);
    }
    let head = head_for("provider:acct", KEYRING_HISTORY_MAX as u64, prev);
    let statement = format!("sea-{KEYRING_HISTORY_MAX}");
    match decide(Some(&head), &entries, None, true, &statement) {
        CurrentKeyDecision::Accept { key_pub } => assert_eq!(key_pub, statement),
        other => panic!("{other:?}"),
    }
}

fn log_entry(key_pub: &str, seq: u64, prev: &str) -> AccountKeyLogEntry {
    AccountKeyLogEntry {
        account: "provider:acct".to_string(),
        key_pub: key_pub.to_string(),
        seq,
        prev: prev.to_string(),
    }
}

#[test]
fn account_key_anchor_is_a_floor() {
    let genesis = log_entry("k0", 0, "none");
    let genesis_hash = account_key_entry_hash(&genesis).unwrap();
    let first = log_entry("k1", 1, &genesis_hash);
    let first_hash = account_key_entry_hash(&first).unwrap();
    let second = log_entry("k2", 2, &first_hash);
    let second_hash = account_key_entry_hash(&second).unwrap();
    let fork_first = log_entry("kf1", 1, &genesis_hash);
    let fork_second = log_entry("kf2", 2, &account_key_entry_hash(&fork_first).unwrap());
    let floor = anchor_of(second.clone());
    let old_head = head_for("provider:acct", 1, first_hash.clone());
    assert!(matches!(
        decide(
            Some(&old_head),
            &[genesis.clone(), first.clone(), second.clone()],
            Some(&floor),
            true,
            "k1",
        ),
        CurrentKeyDecision::Refuse("superseded")
    ));
    let real_floor = anchor_of(first.clone());
    let fork_head = head_for(
        "provider:acct",
        2,
        account_key_entry_hash(&fork_second).unwrap(),
    );
    assert!(matches!(
        decide(
            Some(&fork_head),
            &[genesis.clone(), fork_first, fork_second.clone()],
            Some(&real_floor),
            true,
            "kf2",
        ),
        CurrentKeyDecision::Refuse("unlinked")
    ));
    let current = head_for("provider:acct", 2, second_hash);
    match decide(Some(&current), &[second], Some(&floor), true, "k2") {
        CurrentKeyDecision::Accept { key_pub } => assert_eq!(key_pub, "k2"),
        other => panic!("{other:?}"),
    }
    match decide(
        Some(&fork_head),
        &[fork_second],
        Some(&real_floor),
        true,
        "kf2",
    ) {
        CurrentKeyDecision::Refuse(reason) => assert_eq!(reason, "unlinked"),
        other => panic!("{other:?}"),
    }
}

fn entry_from(value: &serde_json::Value) -> AccountKeyLogEntry {
    AccountKeyLogEntry {
        account: value["account"].as_str().unwrap().to_string(),
        key_pub: value["keyPub"].as_str().unwrap().to_string(),
        seq: value["seq"].as_u64().unwrap(),
        prev: value["prev"].as_str().unwrap().to_string(),
    }
}

fn head_from(value: &serde_json::Value) -> AccountKeyLogHead {
    AccountKeyLogHead {
        account: value["account"].as_str().unwrap().to_string(),
        seq: value["seq"].as_u64().unwrap(),
        entry_hash: value["entryHash"].as_str().unwrap().to_string(),
        issued_at: value["issuedAt"].as_u64().unwrap(),
        max_age_ms: value["maxAgeMs"].as_u64().unwrap(),
    }
}

fn chain_from(spec: &serde_json::Value) -> Vec<AccountKeyLogEntry> {
    let account = spec["account"].as_str().unwrap();
    let last = spec["lastSeq"].as_u64().unwrap();
    let pattern = spec["keyPub"].as_str().unwrap();
    assert_eq!(last, KEYRING_HISTORY_MAX as u64);
    let mut prev = "none".to_string();
    let mut entries = Vec::new();
    for seq in 0..=last {
        let entry = AccountKeyLogEntry {
            account: account.to_string(),
            key_pub: pattern.replace("{seq}", &seq.to_string()),
            seq,
            prev,
        };
        prev = account_key_entry_hash(&entry).unwrap();
        entries.push(entry);
    }
    entries
}

#[test]
fn shared_consume_checks() {
    let document: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(
        document["inputs"]["headMaxAgeMs"].as_u64().unwrap(),
        ACCOUNT_KEY_HEAD_MAX_AGE_MS
    );
    let provider_pub = document["inputs"]["providerPub"].as_str().unwrap();
    for row in document["checks"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let (entries, head) = if row.get("chain").is_some() {
            let entries = chain_from(&row["chain"]);
            let last = entries.last().unwrap();
            let head = AccountKeyLogHead {
                account: last.account.clone(),
                seq: last.seq,
                entry_hash: account_key_entry_hash(last).unwrap(),
                issued_at: row["issuedAt"].as_u64().unwrap(),
                max_age_ms: row["maxAgeMs"].as_u64().unwrap(),
            };
            assert_eq!(
                head.entry_hash,
                row["entryHash"].as_str().unwrap(),
                "{name}"
            );
            (entries, head)
        } else {
            let entries = row["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(entry_from)
                .collect();
            (entries, head_from(&row["head"]))
        };
        let anchor = row.get("anchor").map(|value| anchor_of(entry_from(value)));
        if name == "account-key-head-signature" {
            assert_eq!(
                row["headSignature"].as_str().unwrap(),
                document["inputs"]["headSignature"].as_str().unwrap()
            );
        }
        let decision = accept_current_key(
            Some(&head),
            &entries,
            anchor.as_ref(),
            row["providerAnswered"].as_bool().unwrap(),
            provider_pub,
            row["headSignature"].as_str().unwrap(),
            row["expectedAccount"].as_str().unwrap(),
            row["statementKeyPub"].as_str().unwrap(),
            row["now"].as_u64().unwrap(),
            row["skewAllowanceMs"].as_u64().unwrap(),
            row["policyMaxAgeMs"].as_u64().unwrap(),
        );
        match row["decision"].as_str().unwrap() {
            "accept" => match decision {
                CurrentKeyDecision::Accept { key_pub } => {
                    assert_eq!(key_pub, row["keyPub"].as_str().unwrap(), "{name}");
                }
                other => panic!("{name}: {other:?}"),
            },
            reason => match decision {
                CurrentKeyDecision::Refuse(got) => assert_eq!(got, reason, "{name}"),
                other => panic!("{name}: {other:?}"),
            },
        }
    }
}
