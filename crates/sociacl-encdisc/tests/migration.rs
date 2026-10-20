#![allow(deprecated)]

use serde::Deserialize;
use sociacl_encdisc::{
    accept_migration, apply_protocol_migration, open_migrated_item, open_reader_wrap,
    prepare_protocol_migration, seal_blinded_row, sign_sea, sign_wrap_receipt, wrap_receipt_sha256,
    AccountSeaSecret, AclSnapshotBody, EnrolledSeaPub, EpochReplicaView, GrantStated, GrantStorage,
    MeshSeeGrant, MigrationAdmissionInput, MigrationEpoch, MigrationGrant, MigrationReader,
    PreparedMigration, ProtocolMigration, ReaderMigration, ReaderVersion, SignedGrantPayload,
    WrapReceipt, WrapScope, WrapTarget, WrappedKey, SETTLE_WINDOW_DEFAULT_MS,
};

const MIGRATION: &str = include_str!("../../../vectors/encrypted-discovery/migration.json");
const CANONICAL: &str = include_str!("../../../vectors/encrypted-discovery/canonical.json");
const REV: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[derive(Deserialize)]
struct Document {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    owner: String,
    caller: String,
    now: u64,
    storage: String,
    object: String,
    from_version: u64,
    to_version: u64,
    version_gate: u64,
    soul_ham_state: u64,
    grants: Vec<GrantJson>,
    payloads: Vec<PayloadJson>,
    wraps: Vec<WrapJson>,
    readers: Vec<ReaderJson>,
    reader_versions: Vec<VersionJson>,
    receipts: Vec<ReceiptJson>,
    expect: ExpectJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantJson {
    #[serde(default)]
    soul: Option<String>,
    owner: String,
    object: String,
    accessor: String,
    from: u64,
    until: u64,
    stated: u64,
    ham_state: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayloadJson {
    object: String,
    accessor: String,
    from: u64,
    until: u64,
    stated: u64,
    epoch: u64,
    owner: String,
    grant_revision: u64,
    item_ciphertext_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapJson {
    epoch: u64,
    target_id: String,
    object: String,
    revision_id: String,
    wrapped_key: String,
}

#[derive(Deserialize)]
struct ReaderJson {
    accessor: String,
    acknowledged: bool,
    #[serde(rename = "atGate")]
    at_gate: bool,
}

#[derive(Deserialize)]
struct VersionJson {
    accessor: String,
    version: u64,
    epub: String,
}

#[derive(Deserialize)]
struct ReceiptJson {
    accessor: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectJson {
    ok: bool,
    plaintext_retained: Option<Vec<String>>,
    plaintext_dropped: Option<Vec<String>>,
    soul_replaced: Option<bool>,
    skipped_public: Option<bool>,
    ciphertext_published: Option<bool>,
    soul_ham_state: Option<u64>,
    cancelled: Option<Vec<CancelJson>>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancelJson {
    accessor: String,
    ham_state: u64,
    stated: u64,
    from: u64,
    until: u64,
}

#[test]
fn migration_vectors_match_the_shared_fixture() {
    let document: Document = serde_json::from_str(MIGRATION).unwrap();
    let names: Vec<&str> = document
        .cases
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    for required in [
        "migration-wrap-receipt",
        "migration-per-reader",
        "migration-soul-replaces",
        "migration-no-widen",
        "migration-privilege-down",
        "migration-public-skipped",
        "migration-reader-cannot-issue",
    ] {
        assert!(names.contains(&required), "{required}");
    }
    for case in &document.cases {
        let migration = ProtocolMigration {
            object: case.object.clone(),
            from_version: case.from_version,
            to_version: case.to_version,
            rewrapped: case
                .wraps
                .iter()
                .map(|wrap| WrappedKey {
                    scope: WrapScope::ItemDek,
                    epoch: wrap.epoch,
                    target: WrapTarget::ReaderEpub,
                    target_id: wrap.target_id.clone(),
                    object: Some(wrap.object.clone()),
                    group: None,
                    revision_id: wrap.revision_id.clone(),
                    wrapped_key: wrap.wrapped_key.clone(),
                })
                .collect(),
            readers: case
                .readers
                .iter()
                .map(|reader| ReaderMigration {
                    accessor: reader.accessor.clone(),
                    acknowledged: reader.acknowledged,
                    at_gate: reader.at_gate,
                })
                .collect(),
            version_gate: case.version_gate,
        };
        let grants: Vec<MigrationGrant> = case
            .grants
            .iter()
            .map(|grant| MigrationGrant {
                soul: grant.soul.clone().unwrap_or_else(|| {
                    let owner = sociacl_ids::parse_principal_id(&grant.owner).unwrap();
                    let object = sociacl_ids::parse_object_id(&grant.object).unwrap();
                    let accessor = sociacl_ids::parse_principal_id(&grant.accessor).unwrap();
                    sociacl_ids::grant_soul(&owner, &object, &accessor).to_string()
                }),
                owner: grant.owner.clone(),
                grant: MeshSeeGrant {
                    object: grant.object.clone(),
                    accessor: grant.accessor.clone(),
                    from: grant.from,
                    until: grant.until,
                    stated: GrantStated::from_u64(grant.stated).unwrap(),
                },
                ham_state: grant.ham_state,
            })
            .collect();
        let payloads: Vec<SignedGrantPayload> = case
            .payloads
            .iter()
            .map(|payload| SignedGrantPayload {
                object: payload.object.clone(),
                accessor: payload.accessor.clone(),
                from: payload.from,
                until: payload.until,
                stated: GrantStated::from_u64(payload.stated).unwrap(),
                epoch: payload.epoch,
                owner: payload.owner.clone(),
                grant_revision: payload.grant_revision,
                item_ciphertext_digest: payload.item_ciphertext_digest.clone(),
            })
            .collect();
        let versions: Vec<ReaderVersion> = case
            .reader_versions
            .iter()
            .map(|version| ReaderVersion {
                accessor: version.accessor.clone(),
                version: version.version,
                epub: version.epub.clone(),
            })
            .collect();
        let receipts: Vec<WrapReceipt> = case
            .receipts
            .iter()
            .map(|receipt| WrapReceipt {
                accessor: receipt.accessor.clone(),
                signature: receipt.signature.clone(),
            })
            .collect();
        let storage = match case.storage.as_str() {
            "public-plain" => GrantStorage::PublicPlain,
            "private-row" => GrantStorage::PrivateRow,
            other => panic!("{other}"),
        };
        let result = apply_protocol_migration(&MigrationAdmissionInput {
            migration: &migration,
            owner: &case.owner,
            caller: &case.caller,
            now: case.now,
            storage,
            grants: &grants,
            payloads: &payloads,
            receipts: &receipts,
            reader_versions: &versions,
            soul_ham_state: case.soul_ham_state,
        });
        if !case.expect.ok {
            assert!(result.is_err(), "{}", case.name);
            continue;
        }
        let outcome = result.unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert!(!outcome.grants_see(), "{}", case.name);
        assert!(!outcome.delays_privilege_down(), "{}", case.name);
        assert!(!outcome.version_gate_drops_plaintext(), "{}", case.name);
        assert!(!outcome.widened(), "{}", case.name);
        assert!(outcome.historical_replica_remains(), "{}", case.name);
        assert!(!outcome.claws_back_historical_replica(), "{}", case.name);
        assert_eq!(outcome.object, case.object, "{}", case.name);
        assert_eq!(
            outcome.plaintext_retained,
            case.expect.plaintext_retained.clone().unwrap(),
            "{}",
            case.name
        );
        assert_eq!(
            outcome.plaintext_dropped,
            case.expect.plaintext_dropped.clone().unwrap(),
            "{}",
            case.name
        );
        assert_eq!(
            outcome.soul_replaced,
            case.expect.soul_replaced.unwrap(),
            "{}",
            case.name
        );
        assert_eq!(
            outcome.skipped_public,
            case.expect.skipped_public.unwrap(),
            "{}",
            case.name
        );
        assert_eq!(
            outcome.ciphertext_published,
            case.expect.ciphertext_published.unwrap(),
            "{}",
            case.name
        );
        assert_eq!(
            outcome.soul_ham_state,
            case.expect.soul_ham_state.unwrap(),
            "{}",
            case.name
        );
        let cancelled = case.expect.cancelled.clone().unwrap();
        assert_eq!(outcome.cancelled.len(), cancelled.len(), "{}", case.name);
        for (actual, expected) in outcome.cancelled.iter().zip(&cancelled) {
            assert_eq!(actual.grant.accessor, expected.accessor, "{}", case.name);
            assert_eq!(
                actual.grant.stated.as_u64(),
                expected.stated,
                "{}",
                case.name
            );
            assert_eq!(actual.ham_state, expected.ham_state, "{}", case.name);
            assert_eq!(actual.grant.from, expected.from, "{}", case.name);
            assert_eq!(actual.grant.until, expected.until, "{}", case.name);
            assert_eq!(actual.grant.object, case.object, "{}", case.name);
        }
    }
}

#[test]
fn accessor_order_is_utf8_bytes() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/encrypted-discovery/accessor-order.json"))
            .unwrap();
    let mut input: Vec<String> = document["input"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect();
    input.sort();
    let expected: Vec<&str> = document["utf8"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect();
    assert_eq!(input, expected);
}

#[test]
fn wrap_receipt_bytes_match_the_canonical_vector() {
    let document: serde_json::Value = serde_json::from_str(CANONICAL).unwrap();
    let case = document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "wrap-receipt")
        .unwrap();
    let fields = case["fields"].as_array().unwrap();
    let hash = wrap_receipt_sha256(
        fields[1].as_str().unwrap(),
        fields[2].as_str().unwrap(),
        fields[3].as_str().unwrap().parse().unwrap(),
        fields[4].as_str().unwrap(),
        fields[5].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(hash, case["sha256"].as_str().unwrap());
}

#[test]
fn owner_migration_drops_plaintext_per_reader_and_does_not_grant() {
    let owner = principal_account("0xalice");
    let bob = principal_account("0xbob");
    let carol = principal_account("0xcarol");
    let dave = principal_account("0xdave");
    let plaintext = b"existing-body";
    let (view, snapshot) = settled_view("item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", 1, REV);
    let epoch_view = migration_epoch(&view, &snapshot);
    let grants = vec![
        edge(&owner, bob.account(), GrantStated::Live, 2),
        edge(&owner, carol.account(), GrantStated::Live, 3),
    ];
    let readers = vec![migration_reader(&bob, 2), migration_reader(&carol, 1)];
    let prepared = match prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &grants,
        &readers,
        &[],
        &epoch_view,
    )
    .unwrap()
    {
        PreparedMigration::Encrypted(prepared) => prepared,
        PreparedMigration::SkippedPublic { .. } => panic!("private row was skipped"),
    };
    assert_eq!(prepared.migration.object, "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111");
    assert_eq!(prepared.migration.to_version, 2);
    assert!(prepared
        .migration
        .readers
        .iter()
        .all(|reader| !reader.acknowledged));
    assert!(prepared
        .migration
        .readers
        .iter()
        .any(|reader| reader.accessor == carol.account() && !reader.at_gate));
    assert_eq!(prepared.rows.len(), 2);
    assert!(prepared.rows.iter().all(|row| row.wrap.is_some()));
    let dek = prepared.author.open("item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", REV).unwrap();
    assert!(prepared.author.open("item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", &"22".repeat(32)).is_err());
    let opened = open_migrated_item(
        &prepared.item_blob,
        &sociacl_encdisc::ItemDek::from_bytes(decode_key(&dek)),
        owner.sea_pub(),
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
    )
    .unwrap();
    assert_eq!(opened, plaintext);
    let bob_wrap = prepared
        .migration
        .rewrapped
        .iter()
        .find(|wrap| wrap.target_id == bob.epub())
        .unwrap();
    let opened_wrap = open_reader_wrap(bob_wrap, bob.local_epriv(), bob.epub()).unwrap();
    assert!(!opened_wrap.grants_see());
    assert_eq!(opened_wrap.key_bytes(), &decode_key(&dek));

    let waiting = accept_migration(
        &owner,
        &prepared,
        &prepared.migration,
        &[],
        &grants,
        1_000,
        4,
        plaintext,
        &epoch_view,
    )
    .unwrap();
    assert_eq!(waiting.plaintext_retained.len(), 2);
    assert!(!waiting.soul_replaced);
    assert!(waiting.ciphertext_published);
    assert!(!waiting.grants_see());

    let bob_row = prepared
        .rows
        .iter()
        .find(|row| row.lane_id == bob.inbox().lane_id)
        .unwrap();
    let bob_receipt = WrapReceipt {
        accessor: bob.account().to_string(),
        signature: sign_wrap_receipt(&bob, "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", 2, REV, &bob_row.entry_id).unwrap(),
    };
    let mut one = prepared.migration.clone();
    one.readers
        .iter_mut()
        .find(|reader| reader.accessor == bob.account())
        .unwrap()
        .acknowledged = true;
    let partial = accept_migration(
        &owner,
        &prepared,
        &one,
        &[bob_receipt.clone()],
        &grants,
        1_000,
        4,
        plaintext,
        &epoch_view,
    )
    .unwrap();
    assert_eq!(partial.plaintext_dropped, vec![bob.account().to_string()]);
    assert_eq!(
        partial.plaintext_retained,
        vec![carol.account().to_string()]
    );
    assert!(!partial.soul_replaced);
    assert!(partial.cancelled.is_empty());
    assert!(partial.historical_replica_remains());

    let concatenated = format!(
        "s3rch-wrap-receipt-v1item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111{}2{REV}{}",
        bob.account(),
        bob_row.entry_id
    );
    let bad = WrapReceipt {
        accessor: bob.account().to_string(),
        signature: sign_sea(bob.local_priv(), concatenated.as_bytes()).unwrap(),
    };
    assert!(accept_migration(
        &owner,
        &prepared,
        &one,
        &[bad],
        &grants,
        1_000,
        4,
        plaintext,
        &epoch_view,
    )
    .is_err());
    let foreign = WrapReceipt {
        accessor: bob.account().to_string(),
        signature: sign_wrap_receipt(&carol, "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", 2, REV, &bob_row.entry_id).unwrap(),
    };
    assert!(accept_migration(
        &owner,
        &prepared,
        &one,
        &[foreign],
        &grants,
        1_000,
        4,
        plaintext,
        &epoch_view,
    )
    .is_err());

    let carol_row = prepared
        .rows
        .iter()
        .find(|row| row.lane_id == carol.inbox().lane_id)
        .unwrap();
    let carol_receipt = WrapReceipt {
        accessor: carol.account().to_string(),
        signature: sign_wrap_receipt(&carol, "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", 2, REV, &carol_row.entry_id).unwrap(),
    };
    let mut both = one.clone();
    both.readers
        .iter_mut()
        .find(|reader| reader.accessor == carol.account())
        .unwrap()
        .acknowledged = true;
    let settled = accept_migration(
        &owner,
        &prepared,
        &both,
        &[bob_receipt, carol_receipt],
        &grants,
        1_000,
        4,
        plaintext,
        &epoch_view,
    )
    .unwrap();
    assert!(settled.soul_replaced);
    assert_eq!(settled.soul_ham_state, 5);
    assert!(settled.plaintext_retained.is_empty());
    assert_eq!(settled.cancelled.len(), 2);
    assert!(settled.cancelled.iter().all(|grant| {
        grant.grant.stated == GrantStated::Cancelled && grant.grant.object == "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111"
    }));
    assert!(!settled.claws_back_historical_replica());
    assert!(!settled.grants_see());

    assert!(prepare_protocol_migration(
        &bob,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &grants,
        &readers,
        &[],
        &epoch_view,
    )
    .is_err());
    let mut extra = readers.clone();
    extra.push(migration_reader(&dave, 2));
    assert!(prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &grants,
        &extra,
        &[],
        &epoch_view,
    )
    .is_err());

    let skipped = prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PublicPlain,
        &grants,
        &[],
        &[],
        &epoch_view,
    )
    .unwrap();
    assert!(matches!(skipped, PreparedMigration::SkippedPublic { .. }));

    let cancelled = vec![
        edge(&owner, bob.account(), GrantStated::Cancelled, 4),
        edge(&owner, carol.account(), GrantStated::Live, 1),
    ];
    let only_carol = vec![migration_reader(&carol, 2)];
    let revoked = match prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &cancelled,
        &only_carol,
        &[],
        &epoch_view,
    )
    .unwrap()
    {
        PreparedMigration::Encrypted(prepared) => prepared,
        PreparedMigration::SkippedPublic { .. } => panic!("cancel path skipped"),
    };
    assert!(revoked
        .migration
        .rewrapped
        .iter()
        .all(|wrap| wrap.target_id != bob.epub()));
    let outcome = accept_migration(
        &owner,
        &revoked,
        &revoked.migration,
        &[],
        &cancelled,
        1_000,
        4,
        plaintext,
        &epoch_view,
    )
    .unwrap();
    assert_eq!(
        outcome.plaintext_retained,
        vec![carol.account().to_string()]
    );
    assert!(!outcome.soul_replaced);
    assert!(!outcome.delays_privilege_down());
    assert_eq!(cancelled[0].grant.stated, GrantStated::Cancelled);
}

#[test]
fn stale_soul_epoch_wrap_and_future_grant_fail_closed() {
    let owner = principal_account("0xalice");
    let bob = principal_account("0xbob");
    let dave = principal_account("0xdave");
    let plaintext = b"existing-body";
    let (view, snapshot) = settled_view("item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", 1, REV);
    let epoch_view = migration_epoch(&view, &snapshot);
    let grants = vec![edge(&owner, bob.account(), GrantStated::Live, 2)];
    let readers = vec![migration_reader(&bob, 2)];
    let prepared = match prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &grants,
        &readers,
        &[],
        &epoch_view,
    )
    .unwrap()
    {
        PreparedMigration::Encrypted(prepared) => prepared,
        PreparedMigration::SkippedPublic { .. } => panic!("private row was skipped"),
    };
    let row = &prepared.rows[0];
    let receipt = WrapReceipt {
        accessor: bob.account().to_string(),
        signature: sign_wrap_receipt(&bob, "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", 2, REV, &row.entry_id).unwrap(),
    };
    let mut acknowledged = prepared.migration.clone();
    acknowledged.readers[0].acknowledged = true;

    assert!(accept_migration(
        &owner,
        &prepared,
        &acknowledged,
        &[receipt.clone()],
        &grants,
        1_000,
        10,
        plaintext,
        &epoch_view,
    )
    .is_err());
    assert!(accept_migration(
        &owner,
        &prepared,
        &acknowledged,
        &[receipt.clone()],
        &grants,
        1_000,
        4,
        b"changed-body",
        &epoch_view,
    )
    .is_err());
    let mut moved = view.clone();
    moved.settled_revision_id = "33".repeat(32);
    let moved_epoch = migration_epoch(&moved, &snapshot);
    assert!(accept_migration(
        &owner,
        &prepared,
        &acknowledged,
        &[receipt.clone()],
        &grants,
        1_000,
        4,
        plaintext,
        &moved_epoch,
    )
    .is_err());
    let replaced = accept_migration(
        &owner,
        &prepared,
        &acknowledged,
        &[receipt.clone()],
        &grants,
        1_000,
        4,
        plaintext,
        &epoch_view,
    )
    .unwrap();
    assert!(replaced.soul_replaced);
    assert_eq!(replaced.soul_ham_state, 5);

    assert!(prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        &"22".repeat(32),
        1_000,
        4,
        GrantStorage::PrivateRow,
        &grants,
        &readers,
        &[],
        &epoch_view,
    )
    .is_err());
    let other = "22".repeat(32);
    let mut pending = view.clone();
    pending.seen = vec![sociacl_encdisc::EpochFinalization::seal(
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        0,
        1,
        &other,
        vec![other.clone()],
        "",
        "sig",
    )
    .unwrap()];
    pending.winner_seen_at = 0;
    let pending_epoch = migration_epoch(&pending, &snapshot);
    assert!(prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &grants,
        &readers,
        &[],
        &pending_epoch,
    )
    .is_err());

    let mut mismatched = grants.clone();
    mismatched[0].soul = "s3rch/acl/0xalice/elsewhere/0xbob".to_string();
    assert!(prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &mismatched,
        &readers,
        &[],
        &epoch_view,
    )
    .is_err());

    let mut future = edge(&owner, dave.account(), GrantStated::Live, 1);
    future.grant.from = 2_000;
    let with_future = vec![grants[0].clone(), future];
    assert!(prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &with_future,
        &readers,
        &[],
        &epoch_view,
    )
    .is_err());
    let including = vec![migration_reader(&bob, 2), migration_reader(&dave, 2)];
    let future_prepared = match prepare_protocol_migration(
        &owner,
        "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        plaintext,
        1,
        2,
        2,
        1,
        REV,
        1_000,
        4,
        GrantStorage::PrivateRow,
        &with_future,
        &including,
        &[],
        &epoch_view,
    )
    .unwrap()
    {
        PreparedMigration::Encrypted(prepared) => prepared,
        PreparedMigration::SkippedPublic { .. } => panic!("future reader was skipped"),
    };
    assert!(future_prepared
        .migration
        .rewrapped
        .iter()
        .any(|wrap| wrap.target_id == dave.epub()));

    let mut tampered = prepared.clone();
    let mut wrap = tampered.rows[0].wrap.clone().unwrap();
    let last = wrap.wrapped_key.pop().unwrap();
    wrap.wrapped_key.push(if last == 'a' { 'b' } else { 'a' });
    let row = &tampered.rows[0];
    tampered.rows[0] = seal_blinded_row(
        &row.lane_id,
        &row.grant_ciphertext,
        row.commitment.clone(),
        Some(wrap),
    )
    .unwrap();
    let swapped = WrapReceipt {
        accessor: bob.account().to_string(),
        signature: sign_wrap_receipt(&bob, "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111", 2, REV, &tampered.rows[0].entry_id).unwrap(),
    };
    assert!(accept_migration(
        &owner,
        &tampered,
        &acknowledged,
        &[swapped],
        &grants,
        1_000,
        4,
        plaintext,
        &epoch_view,
    )
    .is_err());
}

fn settled_view(object: &str, epoch: u64, revision: &str) -> (EpochReplicaView, AclSnapshotBody) {
    (
        EpochReplicaView {
            object: object.to_string(),
            epoch,
            previous_finalization_id: String::new(),
            seen: Vec::new(),
            winner_seen_at: 0,
            settle_window_ms: SETTLE_WINDOW_DEFAULT_MS,
            settled_revision_id: revision.to_string(),
            settled_epoch: epoch,
        },
        AclSnapshotBody {
            object_set: None,
            entries: Vec::new(),
        },
    )
}

fn migration_epoch<'a>(
    view: &'a EpochReplicaView,
    snapshot: &'a AclSnapshotBody,
) -> MigrationEpoch<'a> {
    MigrationEpoch {
        view,
        winning: snapshot,
        settled: snapshot,
        current: snapshot,
    }
}


fn principal_account(label: &str) -> AccountSeaSecret {
    let secret = AccountSeaSecret::generate(label).unwrap();
    AccountSeaSecret::import_local(
        secret.sea_pub(),
        secret.lane_id(),
        secret.sea_pub(),
        secret.local_priv(),
        secret.epub(),
        secret.local_epriv(),
    )
    .unwrap()
}

fn edge(
    owner: &AccountSeaSecret,
    accessor: &str,
    stated: GrantStated,
    ham_state: u64,
) -> MigrationGrant {
    let owner_id = sociacl_ids::parse_principal_id(owner.account()).unwrap();
    let accessor_id = sociacl_ids::parse_principal_id(accessor).unwrap();
    let object = sociacl_ids::parse_object_id("item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111").unwrap();
    MigrationGrant {
        soul: sociacl_ids::grant_soul(&owner_id, &object, &accessor_id).to_string(),
        owner: owner.account().to_string(),
        grant: MeshSeeGrant {
            object: "item_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111".to_string(),
            accessor: accessor.to_string(),
            from: 0,
            until: 5_000,
            stated,
        },
        ham_state,
    }
}

fn migration_reader(secret: &AccountSeaSecret, version: u64) -> MigrationReader {
    MigrationReader {
        enrolled: EnrolledSeaPub::from_account(secret),
        lane_id: secret.inbox().lane_id,
        version,
    }
}

#[test]
fn migration_grant_soul_is_ids_grant_soul() {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vectors/mesh/pr6.json"
    ))
    .unwrap();
    let row = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "migration-grant-soul-is-ids-grantSoul")
        .unwrap();
    assert_eq!(row["name"], "migration-grant-soul-is-ids-grantSoul");
    let owner = sociacl_ids::parse_principal_id(row["owner"].as_str().unwrap()).unwrap();
    let object = sociacl_ids::parse_object_id(row["object"].as_str().unwrap()).unwrap();
    let accessor = sociacl_ids::parse_principal_id(row["accessor"].as_str().unwrap()).unwrap();
    assert_eq!(
        sociacl_ids::grant_soul(&owner, &object, &accessor).as_ref(),
        row["soul"].as_str().unwrap()
    );
}

fn decode_key(hex_key: &str) -> [u8; 32] {
    let decoded = hex_key.as_bytes();
    assert_eq!(decoded.len(), 64);
    let mut out = [0u8; 32];
    for index in 0..32 {
        out[index] = u8::from_str_radix(
            std::str::from_utf8(&decoded[index * 2..index * 2 + 2]).unwrap(),
            16,
        )
        .unwrap();
    }
    out
}
