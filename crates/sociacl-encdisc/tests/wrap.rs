use sociacl_encdisc::{
    open_group_epoch_wrap, open_reader_wrap, wrap_group_key_to_members,
    wrap_item_dek_to_group_epoch, wrap_item_dek_to_readers, wrap_item_dek_to_readers_with,
    AccountSeaSecret, DetachedEphemeral, EncDiscError, EnrolledSeaPub, GroupEpochKey, ItemDek,
    NamedSet, WrapScope, WrapTarget,
};

const FIXTURE: &str = include_str!("../../../vectors/encrypted-discovery/sea-fixture.json");

fn alice() -> AccountSeaSecret {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    AccountSeaSecret::import_local(
        "0xalice",
        fixture["laneId"].as_str().unwrap(),
        fixture["signing"]["pub"].as_str().unwrap(),
        fixture["signing"]["priv"].as_str().unwrap(),
        fixture["encryption"]["epub"].as_str().unwrap(),
        fixture["encryption"]["epriv"].as_str().unwrap(),
    )
    .unwrap()
}

fn revision() -> String {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    fixture["revisionId"].as_str().unwrap().to_string()
}

fn other_revision() -> String {
    "ab".repeat(32)
}

#[test]
fn item_dek_wraps_to_a_named_reader_epub_and_is_not_a_grant() {
    let alice = alice();
    let laptop = alice.enroll("laptop").unwrap();
    let dek = ItemDek::from_bytes([4u8; 32]);
    let granted = NamedSet::try_from_accessors([alice.account()]).unwrap();
    let wraps = wrap_item_dek_to_readers(
        &dek,
        3,
        "s3rch/items/post",
        &revision(),
        &[EnrolledSeaPub::from_account(&alice)],
        &granted,
    )
    .unwrap();
    assert_eq!(wraps.len(), 1);
    assert_eq!(wraps[0].scope, WrapScope::ItemDek);
    assert_eq!(wraps[0].target, WrapTarget::ReaderEpub);
    assert_eq!(wraps[0].target_id, alice.epub());
    assert!(wraps[0].group.is_none());
    let opened = open_reader_wrap(
        &wraps[0],
        laptop.secret().local_epriv(),
        laptop.secret().epub(),
    )
    .unwrap();
    assert_eq!(opened.key_bytes(), dek.as_bytes());
    assert_eq!(opened.revision_id(), revision());
    assert!(!opened.grants_see());
    assert!(opened.group_key().is_err());

    let again = wrap_item_dek_to_readers(
        &dek,
        3,
        "s3rch/items/post",
        &revision(),
        &[EnrolledSeaPub::from_account(&alice)],
        &granted,
    )
    .unwrap();
    assert_ne!(wraps[0].wrapped_key, again[0].wrapped_key);
    assert_eq!(
        open_reader_wrap(&again[0], alice.local_epriv(), alice.epub())
            .unwrap()
            .key_bytes(),
        dek.as_bytes()
    );
}

#[test]
fn a_swapped_revision_label_does_not_open() {
    let alice = alice();
    let dek = ItemDek::generate();
    let granted = NamedSet::try_from_accessors([alice.account()]).unwrap();
    let mut wrapped = wrap_item_dek_to_readers(
        &dek,
        3,
        "s3rch/items/post",
        &revision(),
        &[EnrolledSeaPub::from_account(&alice)],
        &granted,
    )
    .unwrap()
    .remove(0);
    wrapped.revision_id = other_revision();
    assert_eq!(
        open_reader_wrap(&wrapped, alice.local_epriv(), alice.epub()).unwrap_err(),
        EncDiscError::WrapRejected
    );
    let mut epoch_swap = wrap_item_dek_to_readers(
        &dek,
        3,
        "s3rch/items/post",
        &revision(),
        &[EnrolledSeaPub::from_account(&alice)],
        &granted,
    )
    .unwrap()
    .remove(0);
    epoch_swap.epoch = 9;
    assert!(open_reader_wrap(&epoch_swap, alice.local_epriv(), alice.epub()).is_err());
}

#[test]
fn unnamed_reader_fails_the_whole_call() {
    let alice = alice();
    let bob = AccountSeaSecret::generate("0xbob").unwrap();
    let dek = ItemDek::generate();
    let granted = NamedSet::try_from_accessors([alice.account()]).unwrap();
    let readers = [
        EnrolledSeaPub::from_account(&alice),
        EnrolledSeaPub::from_account(&bob),
    ];
    assert_eq!(
        wrap_item_dek_to_readers(&dek, 1, "s3rch/items/post", &revision(), &readers, &granted)
            .unwrap_err(),
        EncDiscError::UnnamedReader
    );
    assert_eq!(
        NamedSet::try_from_accessors(["0xalice", "0xalice"]).unwrap_err(),
        EncDiscError::DuplicateName
    );
    let mut corrupt = EnrolledSeaPub::from_account(&alice);
    corrupt.identity_pub = bob.sea_pub().to_string();
    assert_eq!(
        wrap_item_dek_to_readers(
            &dek,
            1,
            "s3rch/items/post",
            &revision(),
            &[corrupt],
            &granted,
        )
        .unwrap_err(),
        EncDiscError::PubMismatch
    );
}

#[test]
fn group_epoch_key_wraps_per_member_and_the_item_dek_wraps_once() {
    let alice = alice();
    let bob = AccountSeaSecret::generate("0xbob").unwrap();
    let carol = AccountSeaSecret::generate("0xcarol").unwrap();
    let group_key = GroupEpochKey::from_bytes([8u8; 32]);
    let dek = ItemDek::from_bytes([5u8; 32]);
    let members = [
        EnrolledSeaPub::from_account(&alice),
        EnrolledSeaPub::from_account(&bob),
    ];
    let named = NamedSet::try_from_accessors([alice.account(), bob.account()]).unwrap();
    let member_wraps =
        wrap_group_key_to_members(&group_key, 2, "circle-1", &revision(), &members, &named)
            .unwrap();
    assert_eq!(member_wraps.len(), 2);
    assert!(member_wraps.iter().all(|wrap| {
        wrap.scope == WrapScope::GroupKey
            && wrap.target == WrapTarget::ReaderEpub
            && wrap.object.is_none()
            && wrap.group.as_deref() == Some("circle-1")
            && wrap.revision_id == revision()
    }));
    let opened = open_reader_wrap(&member_wraps[1], bob.local_epriv(), bob.epub()).unwrap();
    assert!(!opened.grants_see());
    let got = opened.group_key().unwrap();
    assert_eq!(got.as_bytes(), group_key.as_bytes());
    assert!(open_reader_wrap(&member_wraps[0], carol.local_epriv(), carol.epub()).is_err());

    let mut extra = members.to_vec();
    extra.push(EnrolledSeaPub::from_account(&carol));
    assert_eq!(
        wrap_group_key_to_members(&group_key, 2, "circle-1", &revision(), &extra, &named)
            .unwrap_err(),
        EncDiscError::UnnamedReader
    );

    let item = wrap_item_dek_to_group_epoch(
        &dek,
        &group_key,
        2,
        "s3rch/items/post",
        "circle-1",
        &revision(),
    )
    .unwrap();
    assert_eq!(item.target, WrapTarget::GroupEpoch);
    assert_eq!(item.target_id, "circle-1");
    assert_eq!(item.scope, WrapScope::ItemDek);
    let opened_item = open_group_epoch_wrap(&item, "circle-1", &got).unwrap();
    assert_eq!(opened_item.key_bytes(), dek.as_bytes());
    assert!(!opened_item.grants_see());
    assert!(open_reader_wrap(&item, alice.local_epriv(), alice.epub()).is_err());
    assert!(
        open_group_epoch_wrap(&item, "circle-1", &GroupEpochKey::from_bytes([1u8; 32])).is_err()
    );

    let mut label = item.clone();
    label.revision_id = other_revision();
    assert!(open_group_epoch_wrap(&label, "circle-1", &got).is_err());
}

#[test]
fn deterministic_reader_wrap_matches_the_shared_vector() {
    let alice = alice();
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vectors/encrypted-discovery/wrap.json"
    ))
    .unwrap();
    let dek = ItemDek::from_bytes([0x11; 32]);
    assert_eq!(vector["dekHex"].as_str().unwrap(), "11".repeat(32));
    assert_eq!(dek.as_bytes(), &[0x11; 32]);
    let granted = NamedSet::try_from_accessors([alice.account()]).unwrap();
    let wraps = wrap_item_dek_to_readers_with(
        &dek,
        3,
        "s3rch/items/post",
        &revision(),
        &[EnrolledSeaPub::from_account(&alice)],
        &granted,
        &[DetachedEphemeral {
            epriv: fixture["signing"]["priv"].as_str().unwrap().to_string(),
            nonce: [0x22; 12],
        }],
    )
    .unwrap();
    assert_eq!(wraps.len(), 1);
    assert_eq!(wraps[0].wrapped_key, vector["wrappedKey"].as_str().unwrap());
    assert_eq!(wraps[0].epoch, vector["epoch"].as_u64().unwrap());
    assert_eq!(wraps[0].object.as_deref(), vector["object"].as_str());
    let opened = open_reader_wrap(&wraps[0], alice.local_epriv(), alice.epub()).unwrap();
    assert_eq!(opened.key_bytes(), dek.as_bytes());
    assert_eq!(opened.revision_id(), revision());
    assert!(!opened.grants_see());
}
