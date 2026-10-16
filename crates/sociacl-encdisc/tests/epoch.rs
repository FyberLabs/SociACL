//! Epoch admission, revocation freshness, and rotation on revoke.
//!
//! A manifest, a finalization, a status proof, and a wrap are not grants.
//! Privilege-down does not wait for the settle window.

use sociacl_encdisc::{
    acl_snapshot_id, epoch_finalization_id, epoch_finalization_sig_bytes, epoch_manifest_sig_bytes,
    epoch_revision_id, epoch_step_current, epoch_winner, group_epoch_config_bytes,
    group_epoch_config_digest, open_reader_wrap, rebuild_grant_revision, rotate_on_revoke,
    select_group_epoch_config, settle_window_or_default, settled_key_open, sha256_hex, sign_sea,
    wrap_item_dek_to_group_epoch, wrap_item_dek_to_readers, write_disposition, AccountSeaSecret,
    AclObjectSet, AclScope, AclSnapshotBody, AclSnapshotEntry, EnrolledSeaPub, EpochChain,
    EpochFinalization, EpochManifest, EpochManifestBody, EpochReplicaView, EpochRotation,
    EpochStatusProof, GrantStated, GrantStorage, GroupEpochConfig, GroupPredicate, ItemDek,
    LightZookie, MeshSeeGrant, NamedSet, PlainGrant, PriorRevision, RevokeCipherMode,
    RotationCancel, RotationContext, SignedGrantPayload, WrapScope, WrapTarget, WriteDisposition,
    JS_SAFE_INTEGER_MAX, SETTLE_WINDOW_DEFAULT_MS, SETTLE_WINDOW_MAX_MS, SETTLE_WINDOW_MIN_MS,
};

const CANONICAL: &str = include_str!("../../../vectors/encrypted-discovery/canonical.json");
const FAR: u64 = 4_000_000_000_000;
const REV: &str = "abababababababababababababababababababababababababababababababab";

fn vector_hash(name: &str) -> String {
    let document: serde_json::Value = serde_json::from_str(CANONICAL).unwrap();
    document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap()["sha256"]
        .as_str()
        .unwrap()
        .to_string()
}

fn empty_acl() -> AclSnapshotBody {
    AclSnapshotBody {
        object_set: None,
        entries: Vec::new(),
    }
}

fn direct_entry(accessor: &str, revision: u64, stated: GrantStated) -> AclSnapshotEntry {
    AclSnapshotEntry {
        accessor: accessor.to_string(),
        grant_revision: revision,
        stated,
        from: 0,
        until: FAR,
        scope: AclScope::Direct,
        set_id: String::new(),
        ham_state: 0,
    }
}

fn manifest_for(
    owner: &AccountSeaSecret,
    object: &str,
    epoch: u64,
    previous: u64,
    device: &str,
    commitment: &str,
    window: u64,
    snapshot: &AclSnapshotBody,
) -> EpochManifest {
    let acl = acl_snapshot_id(snapshot).unwrap();
    let revision_id = epoch_revision_id(&EpochManifestBody {
        object: object.to_string(),
        epoch,
        previous_epoch: previous,
        device_id: device.to_string(),
        key_commitment: commitment.to_string(),
        settle_window_ms: window,
        acl_snapshot: acl.clone(),
    })
    .unwrap();
    EpochManifest {
        object: object.to_string(),
        previous_epoch: previous,
        epoch,
        device_id: device.to_string(),
        revision_id: revision_id.clone(),
        key_commitment: commitment.to_string(),
        settle_window_ms: window,
        acl_snapshot: acl,
        signature: owner.sign_epoch_manifest(&revision_id).unwrap(),
    }
}

fn fin_for(
    owner: &AccountSeaSecret,
    object: &str,
    previous_epoch: u64,
    epoch: u64,
    revision: &str,
    previous_fin: &str,
) -> EpochFinalization {
    let mut fin = EpochFinalization::seal(
        object,
        previous_epoch,
        epoch,
        revision,
        vec![revision.to_string()],
        previous_fin,
        "",
    )
    .unwrap();
    fin.signature = owner.sign_epoch_finalization(&fin.finalization_id).unwrap();
    fin
}

fn chain_with(
    owner: &AccountSeaSecret,
    manifest: &EpochManifest,
    snapshot: &AclSnapshotBody,
) -> EpochChain {
    let mut chain = EpochChain::new(&manifest.object).unwrap();
    chain
        .insert_manifest(manifest.clone(), snapshot.clone(), owner.sea_pub())
        .unwrap();
    chain
}

#[test]
fn canonical_epoch_bodies_match_the_shared_fixture() {
    let direct = AclSnapshotBody {
        object_set: None,
        entries: vec![AclSnapshotEntry {
            accessor: "bob".to_string(),
            grant_revision: 4,
            stated: GrantStated::Cancelled,
            from: 10,
            until: 20,
            scope: AclScope::Direct,
            set_id: String::new(),
            ham_state: 0,
        }],
    };
    assert_eq!(
        acl_snapshot_id(&direct).unwrap(),
        vector_hash("acl-snapshot-direct")
    );
    let group = AclSnapshotBody {
        object_set: Some(AclObjectSet {
            predicate: GroupPredicate::SameGroup,
            set_id: "crew".to_string(),
            stated: GrantStated::Live,
            ham_state: 3,
        }),
        entries: vec![AclSnapshotEntry {
            accessor: "ada".to_string(),
            grant_revision: 2,
            stated: GrantStated::Live,
            from: 0,
            until: 99,
            scope: AclScope::SameGroup,
            set_id: "crew".to_string(),
            ham_state: 5,
        }],
    };
    assert_eq!(
        acl_snapshot_id(&group).unwrap(),
        vector_hash("acl-snapshot-group")
    );
    assert_eq!(
        epoch_finalization_id("item-1", 3, 2, REV, "", &[REV.to_string()]).unwrap(),
        vector_hash("epoch-finalization-body")
    );
    assert_eq!(
        sha256_hex(&epoch_manifest_sig_bytes(REV).unwrap()),
        vector_hash("epoch-manifest-sig")
    );
    assert_eq!(
        sha256_hex(&epoch_finalization_sig_bytes(REV).unwrap()),
        vector_hash("epoch-finalization-sig")
    );
    assert_eq!(
        group_epoch_config_digest("alice", "crew", "named-circle", 7_200_000, 2).unwrap(),
        vector_hash("group-epoch-config")
    );
    assert_eq!(
        sha256_hex(
            &group_epoch_config_bytes("alice", "crew", "named-circle", 86_400_000, 2).unwrap()
        ),
        vector_hash("group-epoch-config-tie")
    );
    let mut unsorted = direct.clone();
    unsorted
        .entries
        .push(direct_entry("amy", 1, GrantStated::Live));
    let low_accessor = "\u{E000}";
    let high_accessor = "\u{10000}";
    assert!(low_accessor.as_bytes() < high_accessor.as_bytes());
    assert!(
        high_accessor.encode_utf16().next().unwrap() < low_accessor.encode_utf16().next().unwrap()
    );
    let utf8_order = AclSnapshotBody {
        object_set: None,
        entries: vec![
            direct_entry(low_accessor, 1, GrantStated::Live),
            direct_entry(high_accessor, 2, GrantStated::Cancelled),
        ],
    };
    assert_eq!(
        acl_snapshot_id(&utf8_order).unwrap(),
        vector_hash("acl-snapshot-utf8-order")
    );
    let utf16_order = AclSnapshotBody {
        object_set: None,
        entries: vec![
            direct_entry(high_accessor, 2, GrantStated::Cancelled),
            direct_entry(low_accessor, 1, GrantStated::Live),
        ],
    };
    assert!(acl_snapshot_id(&utf16_order).is_err());
    assert!(acl_snapshot_id(&unsorted).is_err());
    assert!(acl_snapshot_id(&AclSnapshotBody {
        object_set: None,
        entries: vec![direct_entry(
            "bob",
            JS_SAFE_INTEGER_MAX + 1,
            GrantStated::Live
        )],
    })
    .is_err());
}

#[test]
fn settle_window_defaults_to_one_day_inside_the_bounds() {
    assert_eq!(settle_window_or_default(None), SETTLE_WINDOW_DEFAULT_MS);
    assert_eq!(SETTLE_WINDOW_MIN_MS, 3_600_000);
    assert_eq!(SETTLE_WINDOW_DEFAULT_MS, 86_400_000);
    assert_eq!(SETTLE_WINDOW_MAX_MS, 259_200_000);
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let snapshot = empty_acl();
    for window in [SETTLE_WINDOW_MIN_MS - 1, SETTLE_WINDOW_MAX_MS + 1, 0] {
        let manifest =
            unsigned_manifest(&owner, "item-1", 1, 0, "laptop", "key", window, &snapshot);
        let mut chain = EpochChain::new("item-1").unwrap();
        assert!(chain
            .insert_manifest(manifest, snapshot.clone(), owner.sea_pub())
            .is_err());
    }
    let manifest = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "laptop",
        "key",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    assert!(!manifest.grants_see());
    chain_with(&owner, &manifest, &snapshot);
}

fn unsigned_manifest(
    owner: &AccountSeaSecret,
    object: &str,
    epoch: u64,
    previous: u64,
    device: &str,
    commitment: &str,
    window: u64,
    snapshot: &AclSnapshotBody,
) -> EpochManifest {
    let mut manifest = manifest_for(
        owner,
        object,
        epoch,
        previous,
        device,
        commitment,
        SETTLE_WINDOW_DEFAULT_MS,
        snapshot,
    );
    manifest.settle_window_ms = window;
    if (SETTLE_WINDOW_MIN_MS..=SETTLE_WINDOW_MAX_MS).contains(&window) {
        manifest.acl_snapshot = acl_snapshot_id(snapshot).unwrap();
        manifest.revision_id = epoch_revision_id(&manifest.body()).unwrap();
        manifest.signature = owner.sign_epoch_manifest(&manifest.revision_id).unwrap();
    }
    manifest
}

#[test]
fn two_devices_converge_on_the_smaller_finalization_id() {
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let snapshot = empty_acl();
    let laptop = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "laptop",
        "key-laptop",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let phone = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "phone",
        "key-phone",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    assert_ne!(laptop.revision_id, phone.revision_id);
    assert_ne!(laptop.device_id, phone.device_id);
    let left = fin_for(&owner, "item-1", 0, 1, &laptop.revision_id, "");
    let right = fin_for(&owner, "item-1", 0, 1, &phone.revision_id, "");
    assert!(!left.grants_see());
    let mut forward = chain_with(&owner, &laptop, &snapshot);
    forward
        .insert_manifest(phone.clone(), snapshot.clone(), owner.sea_pub())
        .unwrap();
    forward
        .insert_finalization(left.clone(), 10, owner.sea_pub())
        .unwrap();
    forward
        .insert_finalization(right.clone(), 20, owner.sea_pub())
        .unwrap();
    let mut reverse = chain_with(&owner, &phone, &snapshot);
    reverse
        .insert_manifest(laptop.clone(), snapshot.clone(), owner.sea_pub())
        .unwrap();
    reverse
        .insert_finalization(right.clone(), 1, owner.sea_pub())
        .unwrap();
    reverse
        .insert_finalization(left.clone(), 2, owner.sea_pub())
        .unwrap();
    let forward_winner = forward.on_chain_winners(&snapshot, 30, None);
    let reverse_winner = reverse.on_chain_winners(&snapshot, 30, None);
    assert_eq!(forward_winner.len(), 1);
    assert_eq!(
        forward_winner[0].finalization_id,
        reverse_winner[0].finalization_id
    );
    let smaller = if left.finalization_id < right.finalization_id {
        &left
    } else {
        &right
    };
    assert_eq!(forward_winner[0].finalization_id, smaller.finalization_id);

    let (early, late) = if left.finalization_id > right.finalization_id {
        (left, right)
    } else {
        (right, left)
    };
    let mut late_chain = chain_with(&owner, &laptop, &snapshot);
    late_chain
        .insert_manifest(phone, snapshot.clone(), owner.sea_pub())
        .unwrap();
    late_chain
        .insert_finalization(early, 10, owner.sea_pub())
        .unwrap();
    let pending = late_chain.replica_view(1, &snapshot, 10, None, "");
    assert_eq!(pending.winner_seen_at, 10);
    assert!(!epoch_step_current(&pending, &snapshot, &snapshot, 10));
    late_chain
        .insert_finalization(late, 4_000, owner.sea_pub())
        .unwrap();
    let replaced = late_chain.replica_view(1, &snapshot, 4_000, None, "");
    assert_eq!(replaced.winner_seen_at, 4_000);
    assert!(!epoch_step_current(&replaced, &snapshot, &snapshot, 4_000));
    let ready_at = 4_000 + SETTLE_WINDOW_DEFAULT_MS;
    let ready = late_chain.replica_view(1, &snapshot, ready_at, None, "");
    assert!(epoch_step_current(&ready, &snapshot, &snapshot, ready_at));
}

#[test]
fn a_smaller_parent_drops_descendants_and_needs_a_higher_grant_revision() {
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let snapshot = empty_acl();
    let first = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "laptop",
        "key-a",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let second = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "phone",
        "key-b",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let child_manifest = manifest_for(
        &owner,
        "item-1",
        2,
        1,
        "laptop",
        "key-child",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let left = fin_for(&owner, "item-1", 0, 1, &first.revision_id, "");
    let right = fin_for(&owner, "item-1", 0, 1, &second.revision_id, "");
    let (loser, winner) = if left.finalization_id > right.finalization_id {
        (left, right)
    } else {
        (right, left)
    };
    let child = fin_for(
        &owner,
        "item-1",
        1,
        2,
        &child_manifest.revision_id,
        &loser.finalization_id,
    );
    let mut chain = chain_with(&owner, &first, &snapshot);
    chain
        .insert_manifest(second, snapshot.clone(), owner.sea_pub())
        .unwrap();
    chain
        .insert_manifest(child_manifest, snapshot.clone(), owner.sea_pub())
        .unwrap();
    chain
        .insert_finalization(loser.clone(), 1, owner.sea_pub())
        .unwrap();
    chain
        .insert_finalization(child.clone(), 2, owner.sea_pub())
        .unwrap();
    assert!(chain.revision_on_chain(&child.revision_id, &snapshot, 3, None));
    chain
        .insert_finalization(winner.clone(), 4, owner.sea_pub())
        .unwrap();
    assert!(!chain.revision_on_chain(&loser.revision_id, &snapshot, 5, None));
    assert!(!chain.revision_on_chain(&child.revision_id, &snapshot, 5, None));
    assert!(chain.revision_on_chain(&winner.revision_id, &snapshot, 5, None));
    let displaced = chain.displaced_finalizations(&snapshot, 5, None);
    assert_eq!(displaced.len(), 1);
    assert_eq!(displaced[0].finalization_id, child.finalization_id);
    let view = chain.replica_view(1, &snapshot, 5, None, &loser.revision_id);
    assert!(view.settled_revision_id.is_empty());
    assert_eq!(view.settled_epoch, 0);
    let settled = chain.replica_view(2, &snapshot, 5, None, &winner.revision_id);
    assert_eq!(settled.settled_revision_id, winner.revision_id);
    assert_eq!(settled.settled_epoch, winner.epoch);
    assert_ne!(settled.epoch, settled.settled_epoch);
    assert!(rebuild_grant_revision(4, 4).is_err());
    assert_eq!(rebuild_grant_revision(4, 5).unwrap(), 5);
}

#[test]
fn manifest_and_finalization_signatures_cover_the_ids() {
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let snapshot = empty_acl();
    let mut manifest = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "laptop",
        "key-a",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    manifest.signature = sign_sea(owner.local_priv(), manifest.key_commitment.as_bytes()).unwrap();
    let mut chain = EpochChain::new("item-1").unwrap();
    assert!(chain
        .insert_manifest(manifest.clone(), snapshot.clone(), owner.sea_pub())
        .is_err());
    manifest.signature = owner.sign_epoch_manifest(&manifest.revision_id).unwrap();
    chain
        .insert_manifest(manifest.clone(), snapshot.clone(), owner.sea_pub())
        .unwrap();
    let mut fin = fin_for(&owner, "item-1", 0, 1, &manifest.revision_id, "");
    fin.signature = sign_sea(owner.local_priv(), fin.revision_id.as_bytes()).unwrap();
    assert!(chain
        .insert_finalization(fin.clone(), 1, owner.sea_pub())
        .is_err());
    fin.signature = owner.sign_epoch_finalization(&fin.finalization_id).unwrap();
    chain.insert_finalization(fin, 1, owner.sea_pub()).unwrap();

    let other = manifest_for(
        &owner,
        "item-2",
        1,
        0,
        "laptop",
        "key-b",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let foreign = fin_for(&owner, "item-1", 0, 1, &other.revision_id, "");
    assert!(chain
        .insert_finalization(foreign, 2, owner.sea_pub())
        .is_err());
}

#[test]
fn group_window_follows_the_highest_config_revision() {
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let other = AccountSeaSecret::generate("0xbob").unwrap();
    let low = signed_config(&owner, 1, SETTLE_WINDOW_DEFAULT_MS);
    let high = signed_config(&owner, 2, 7_200_000);
    let stale = signed_config(&owner, 1, 7_200_000);
    let mut short = signed_config(&owner, 9, SETTLE_WINDOW_MIN_MS);
    short.settle_window_ms = SETTLE_WINDOW_MIN_MS - 1;
    short.signature = owner
        .sign_group_epoch_config("crew", "same-group", short.settle_window_ms, 9)
        .unwrap();
    let wrong_owner = GroupEpochConfig {
        owner: "0xelse".to_string(),
        signature: owner
            .sign_group_epoch_config("crew", "same-group", 7_200_000, 4)
            .unwrap(),
        ..signed_config(&owner, 4, 7_200_000)
    };
    let wrong_key = GroupEpochConfig {
        signature: other
            .sign_group_epoch_config("crew", "same-group", 7_200_000, 3)
            .unwrap(),
        ..signed_config(&owner, 3, 7_200_000)
    };
    let configs = [
        low.clone(),
        high.clone(),
        stale,
        short,
        wrong_owner,
        wrong_key,
    ];
    let selected = select_group_epoch_config(
        &configs,
        GroupPredicate::SameGroup,
        "crew",
        owner.sea_pub(),
        Some(owner.account()),
    )
    .unwrap();
    assert_eq!(selected.config_revision, 2);
    assert_eq!(selected.settle_window_ms, 7_200_000);
    assert!(!selected.grants_see());
    let reversed: Vec<_> = configs.clone().into_iter().rev().collect();
    assert_eq!(
        select_group_epoch_config(
            &reversed,
            GroupPredicate::SameGroup,
            "crew",
            owner.sea_pub(),
            Some(owner.account()),
        )
        .unwrap()
        .config_revision,
        2
    );
    assert!(select_group_epoch_config(
        &configs,
        GroupPredicate::SameGroup,
        "crew",
        owner.sea_pub(),
        None,
    )
    .is_none());
    assert!(select_group_epoch_config(
        &configs,
        GroupPredicate::SameGroup,
        "crew",
        other.sea_pub(),
        Some(owner.account()),
    )
    .is_none());
    let foreign = GroupEpochConfig {
        owner: owner.account().to_string(),
        set_id: "other".to_string(),
        predicate: GroupPredicate::SameGroup,
        settle_window_ms: SETTLE_WINDOW_DEFAULT_MS,
        config_revision: 99,
        signature: owner
            .sign_group_epoch_config("other", "same-group", SETTLE_WINDOW_DEFAULT_MS, 99)
            .unwrap(),
    };
    let circle = GroupEpochConfig {
        owner: owner.account().to_string(),
        set_id: "crew".to_string(),
        predicate: GroupPredicate::NamedCircle,
        settle_window_ms: SETTLE_WINDOW_DEFAULT_MS,
        config_revision: 99,
        signature: owner
            .sign_group_epoch_config("crew", "named-circle", SETTLE_WINDOW_DEFAULT_MS, 99)
            .unwrap(),
    };
    let mixed = [high.clone(), foreign, circle];
    assert_eq!(
        select_group_epoch_config(
            &mixed,
            GroupPredicate::SameGroup,
            "crew",
            owner.sea_pub(),
            Some(owner.account()),
        )
        .unwrap()
        .config_revision,
        2
    );

    let tie_a = signed_config(&owner, 5, 7_200_000);
    let tie_b = signed_config(&owner, 5, SETTLE_WINDOW_DEFAULT_MS);
    let forward_configs = [tie_a.clone(), tie_b.clone()];
    let backward_configs = [tie_b.clone(), tie_a.clone()];
    let forward = select_group_epoch_config(
        &forward_configs,
        GroupPredicate::SameGroup,
        "crew",
        owner.sea_pub(),
        Some(owner.account()),
    )
    .unwrap();
    let backward = select_group_epoch_config(
        &backward_configs,
        GroupPredicate::SameGroup,
        "crew",
        owner.sea_pub(),
        Some(owner.account()),
    )
    .unwrap();
    assert_eq!(forward.digest().unwrap(), backward.digest().unwrap());
    let smaller = if tie_a.digest().unwrap() < tie_b.digest().unwrap() {
        &tie_a
    } else {
        &tie_b
    };
    assert_eq!(forward.settle_window_ms, smaller.settle_window_ms);

    let snapshot = group_snapshot(owner.account(), GrantStated::Live, 2);
    let matching = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "laptop",
        "key-group",
        7_200_000,
        &snapshot,
    );
    let other_window = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "phone",
        "key-other",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let mut chain = chain_with(&owner, &matching, &snapshot);
    chain
        .insert_manifest(other_window.clone(), snapshot.clone(), owner.sea_pub())
        .unwrap();
    let matching_fin = fin_for(&owner, "item-1", 0, 1, &matching.revision_id, "");
    let other_fin = fin_for(&owner, "item-1", 0, 1, &other_window.revision_id, "");
    chain
        .insert_finalization(matching_fin, 1, owner.sea_pub())
        .unwrap();
    chain
        .insert_finalization(other_fin, 1, owner.sea_pub())
        .unwrap();
    let winners = chain.on_chain_winners(&snapshot, 10, Some(7_200_000));
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].revision_id, matching.revision_id);
    let mut raised = snapshot.clone();
    raised.object_set.as_mut().unwrap().ham_state = 4;
    assert!(chain
        .on_chain_winners(&raised, 10, Some(7_200_000))
        .is_empty());
}

fn signed_config(owner: &AccountSeaSecret, revision: u64, window: u64) -> GroupEpochConfig {
    GroupEpochConfig {
        owner: owner.account().to_string(),
        set_id: "crew".to_string(),
        predicate: GroupPredicate::SameGroup,
        settle_window_ms: window,
        config_revision: revision,
        signature: owner
            .sign_group_epoch_config("crew", "same-group", window, revision)
            .unwrap(),
    }
}

fn group_snapshot(accessor: &str, stated: GrantStated, ham: u64) -> AclSnapshotBody {
    AclSnapshotBody {
        object_set: Some(AclObjectSet {
            predicate: GroupPredicate::SameGroup,
            set_id: "crew".to_string(),
            stated: GrantStated::Live,
            ham_state: 2,
        }),
        entries: vec![AclSnapshotEntry {
            accessor: accessor.to_string(),
            grant_revision: 1,
            stated,
            from: 0,
            until: FAR,
            scope: AclScope::SameGroup,
            set_id: "crew".to_string(),
            ham_state: ham,
        }],
    }
}

#[test]
fn settled_key_closes_on_expiry_cancel_pending_and_a_tighter_window() {
    let revision = REV.to_string();
    let mut view = EpochReplicaView {
        object: "item-1".to_string(),
        epoch: 2,
        previous_finalization_id: String::new(),
        seen: Vec::new(),
        winner_seen_at: 0,
        settle_window_ms: SETTLE_WINDOW_DEFAULT_MS,
        settled_revision_id: revision.clone(),
        settled_epoch: 2,
    };
    let now = 50_000;
    let mut settled = AclSnapshotBody {
        object_set: None,
        entries: vec![direct_entry("0xbob", 1, GrantStated::Live)],
    };
    settled.entries[0].until = now;
    assert!(!settled_key_open(&view, &settled, &settled, now));
    assert!(!epoch_step_current(&view, &settled, &settled, now));

    let settled = AclSnapshotBody {
        object_set: None,
        entries: vec![direct_entry("0xbob", 1, GrantStated::Live)],
    };
    let mut current = settled.clone();
    current.entries[0].stated = GrantStated::Cancelled;
    current.entries[0].grant_revision = 2;
    assert!(!settled_key_open(&view, &settled, &current, now));
    assert_eq!(
        write_disposition(&view, &settled, &settled, &current, now),
        WriteDisposition::Buffer
    );

    current.entries[0].stated = GrantStated::Live;
    current.entries[0].grant_revision = 3;
    current.entries[0].until = settled.entries[0].until - 1;
    assert!(!epoch_step_current(&view, &settled, &current, now));
    assert!(!settled_key_open(&view, &settled, &current, now));

    let pending_revision = "cd".repeat(32);
    view.seen = vec![EpochFinalization::seal(
        "item-1",
        1,
        2,
        &pending_revision,
        vec![pending_revision.clone()],
        "",
        "sig",
    )
    .unwrap()];
    view.winner_seen_at = now;
    view.settled_revision_id = revision.clone();
    let open = AclSnapshotBody {
        object_set: None,
        entries: vec![direct_entry("0xbob", 1, GrantStated::Live)],
    };
    assert!(!settled_key_open(&view, &open, &open, now));
    assert_eq!(
        write_disposition(&view, &open, &open, &open, now),
        WriteDisposition::Buffer
    );
    assert!(epoch_winner(&view).is_some());

    view.seen.clear();
    view.settled_revision_id = revision;
    assert!(settled_key_open(&view, &open, &open, now));
    match write_disposition(&view, &open, &open, &open, now) {
        WriteDisposition::Settled { revision_id, epoch } => {
            assert_eq!(revision_id, REV);
            assert_eq!(epoch, 2);
        }
        other => panic!("expected the settled key, got {other:?}"),
    }
}

#[test]
fn rotate_on_revoke_is_immediate_for_both_cipher_modes() {
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let bob = AccountSeaSecret::generate("0xbob").unwrap();
    let carol = AccountSeaSecret::generate("0xcarol").unwrap();
    let mut entries = vec![
        direct_entry(bob.account(), 2, GrantStated::Cancelled),
        direct_entry(carol.account(), 1, GrantStated::Live),
    ];
    entries.sort_by(|left, right| left.accessor.cmp(&right.accessor));
    let snapshot = AclSnapshotBody {
        object_set: None,
        entries,
    };
    let manifest = manifest_for(
        &owner,
        "item-1",
        3,
        2,
        "laptop",
        "key-next",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let dek = ItemDek::from_bytes([9u8; 32]);
    let old_revision = "11".repeat(32);
    let old = wrap_item_dek_to_readers(
        &dek,
        2,
        "item-1",
        &old_revision,
        &[EnrolledSeaPub::from_account(&bob)],
        &NamedSet::try_from_accessors([bob.account()]).unwrap(),
    )
    .unwrap();
    let opened = open_reader_wrap(&old[0], bob.local_epriv(), bob.epub()).unwrap();
    assert_eq!(opened.key_bytes(), dek.as_bytes());
    assert!(!opened.grants_see());

    let fresh = wrap_item_dek_to_readers(
        &ItemDek::from_bytes([4u8; 32]),
        3,
        "item-1",
        &manifest.revision_id,
        &[EnrolledSeaPub::from_account(&carol)],
        &NamedSet::try_from_accessors([carol.account()]).unwrap(),
    )
    .unwrap();
    let readers = vec![
        EnrolledSeaPub::from_account(&bob),
        EnrolledSeaPub::from_account(&carol),
    ];
    let cancel = RotationCancel::Plain {
        grant: sociacl_encdisc::CancelledGrant {
            grant: PlainGrant::See(MeshSeeGrant {
                object: "item-1".to_string(),
                accessor: bob.account().to_string(),
                from: 0,
                until: FAR,
                stated: GrantStated::Cancelled,
            }),
            ham_state: 3,
        },
    };
    let prior = [PriorRevision {
        accessor: bob.account().to_string(),
        grant_revision: 1,
        ham_state: 1,
    }];
    for cipher in [RevokeCipherMode::ForwardOnly, RevokeCipherMode::ReEncrypt] {
        let rotation = EpochRotation {
            object: "item-1".to_string(),
            revoked_epoch: 2,
            next_epoch: 3,
            revision_id: manifest.revision_id.clone(),
            cancelled: vec![cancel.clone()],
            rewrapped: fresh.clone(),
            cipher,
        };
        let outcome = rotate_on_revoke(
            &rotation,
            &context(&owner, &manifest, &snapshot, &readers, &prior, 1_000),
        )
        .unwrap();
        assert!(!outcome.grants_see());
        assert!(outcome.privilege_down_immediate());
        assert!(!outcome.delays_privilege_down());
        assert!(!outcome.encrypts_new_writes_under_settled_key());
        assert!(outcome.unwrapped_bytes_remain_readable);
        assert_eq!(
            outcome.old_ciphertext_stays,
            cipher == RevokeCipherMode::ForwardOnly
        );
        assert_eq!(outcome.revoked_accessors, vec![bob.account().to_string()]);
        assert_eq!(outcome.wrapped_accessors, vec![carol.account().to_string()]);
        assert_eq!(outcome.cipher, cipher);
    }

    let mut with_bob = fresh.clone();
    with_bob.extend(
        wrap_item_dek_to_readers(
            &dek,
            3,
            "item-1",
            &manifest.revision_id,
            &[EnrolledSeaPub::from_account(&bob)],
            &NamedSet::try_from_accessors([bob.account()]).unwrap(),
        )
        .unwrap(),
    );
    let rotation = EpochRotation {
        object: "item-1".to_string(),
        revoked_epoch: 2,
        next_epoch: 3,
        revision_id: manifest.revision_id.clone(),
        cancelled: vec![cancel.clone()],
        rewrapped: with_bob,
        cipher: RevokeCipherMode::ReEncrypt,
    };
    assert!(rotate_on_revoke(
        &rotation,
        &context(&owner, &manifest, &snapshot, &readers, &prior, 1_000),
    )
    .is_err());

    let stale = [PriorRevision {
        accessor: bob.account().to_string(),
        grant_revision: 1,
        ham_state: 10,
    }];
    let kept = EpochRotation {
        object: "item-1".to_string(),
        revoked_epoch: 2,
        next_epoch: 3,
        revision_id: manifest.revision_id.clone(),
        cancelled: vec![cancel],
        rewrapped: fresh.clone(),
        cipher: RevokeCipherMode::ForwardOnly,
    };
    assert!(rotate_on_revoke(
        &kept,
        &context(&owner, &manifest, &snapshot, &readers, &stale, 1_000),
    )
    .is_err());
    assert!(rotate_on_revoke(
        &kept,
        &context(&owner, &manifest, &snapshot, &readers, &[], 1_000),
    )
    .is_err());
    let mut group_key = fresh[0].clone();
    group_key.scope = WrapScope::GroupKey;
    let group_key_rotation = EpochRotation {
        rewrapped: vec![group_key],
        ..kept.clone()
    };
    assert!(rotate_on_revoke(
        &group_key_rotation,
        &context(&owner, &manifest, &snapshot, &readers, &prior, 1_000),
    )
    .is_err());
    let mut group_epoch = fresh[0].clone();
    group_epoch.scope = WrapScope::GroupKey;
    group_epoch.target = WrapTarget::GroupEpoch;
    let group_epoch_rotation = EpochRotation {
        rewrapped: vec![group_epoch],
        ..kept
    };
    assert!(rotate_on_revoke(
        &group_epoch_rotation,
        &context(&owner, &manifest, &snapshot, &readers, &prior, 1_000),
    )
    .is_err());
}

#[test]
fn a_plaintext_edge_does_not_cancel_a_private_row() {
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let bob = AccountSeaSecret::generate("0xbob").unwrap();
    let snapshot = AclSnapshotBody {
        object_set: None,
        entries: vec![direct_entry(bob.account(), 5, GrantStated::Cancelled)],
    };
    let manifest = manifest_for(
        &owner,
        "item-1",
        3,
        2,
        "laptop",
        "key-next",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let readers = vec![EnrolledSeaPub::from_account(&bob)];
    let plain = RotationCancel::Plain {
        grant: sociacl_encdisc::CancelledGrant {
            grant: PlainGrant::See(MeshSeeGrant {
                object: "item-1".to_string(),
                accessor: bob.account().to_string(),
                from: 0,
                until: FAR,
                stated: GrantStated::Cancelled,
            }),
            ham_state: 2,
        },
    };
    let rotation = EpochRotation {
        object: "item-1".to_string(),
        revoked_epoch: 2,
        next_epoch: 3,
        revision_id: manifest.revision_id.clone(),
        cancelled: vec![plain],
        rewrapped: Vec::new(),
        cipher: RevokeCipherMode::ForwardOnly,
    };
    let mut private = context(&owner, &manifest, &snapshot, &readers, &[], 1_000);
    private.storage = GrantStorage::PrivateRow;
    assert!(rotate_on_revoke(&rotation, &private).is_err());

    let payload = SignedGrantPayload {
        object: "item-1".to_string(),
        accessor: bob.account().to_string(),
        from: 0,
        until: FAR,
        stated: GrantStated::Cancelled,
        epoch: 2,
        owner: owner.account().to_string(),
        grant_revision: 5,
        item_ciphertext_digest: String::new(),
    };
    let signature = owner.sign_grant(&payload).unwrap();
    let mut status = EpochStatusProof {
        object: "item-1".to_string(),
        epoch: 2,
        revision_id: "22".repeat(32),
        accessor: bob.account().to_string(),
        grant_revision: 5,
        stated: GrantStated::Cancelled,
        signed_at: 1_000,
        max_age_ms: 60_000,
        signature: String::new(),
        zookie: LightZookie {
            object: "item-1".to_string(),
            object_version: 4,
            snapshot_hash: "aa".repeat(32),
        },
    };
    status.signature = owner.sign_epoch_status(&status.body()).unwrap();
    assert!(!status.grants_see());
    let rotation = EpochRotation {
        cancelled: vec![RotationCancel::PrivateRow {
            payload: payload.clone(),
            signature: signature.clone(),
            status: status.clone(),
        }],
        rewrapped: Vec::new(),
        ..rotation
    };
    let prior = [PriorRevision {
        accessor: bob.account().to_string(),
        grant_revision: 4,
        ham_state: 1,
    }];
    let mut private = context(&owner, &manifest, &snapshot, &readers, &prior, 1_000);
    private.storage = GrantStorage::PrivateRow;
    let outcome = rotate_on_revoke(&rotation, &private).unwrap();
    assert_eq!(outcome.revoked_accessors, vec![bob.account().to_string()]);
    assert!(outcome.wrapped_accessors.is_empty());
    assert!(!outcome.delays_privilege_down());

    let mut stale = status.clone();
    stale.signed_at = 0;
    stale.max_age_ms = 10;
    stale.signature = owner.sign_epoch_status(&stale.body()).unwrap();
    let rotation = EpochRotation {
        cancelled: vec![RotationCancel::PrivateRow {
            payload,
            signature,
            status: stale,
        }],
        ..rotation
    };
    assert!(rotate_on_revoke(&rotation, &private).is_err());
}

#[test]
fn a_group_epoch_wrap_follows_the_signed_window_and_skips_the_revoked_member() {
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let bob = AccountSeaSecret::generate("0xbob").unwrap();
    let carol = AccountSeaSecret::generate("0xcarol").unwrap();
    let mut entries = vec![
        AclSnapshotEntry {
            accessor: bob.account().to_string(),
            grant_revision: 2,
            stated: GrantStated::Cancelled,
            from: 0,
            until: FAR,
            scope: AclScope::SameGroup,
            set_id: "crew".to_string(),
            ham_state: 4,
        },
        AclSnapshotEntry {
            accessor: carol.account().to_string(),
            grant_revision: 1,
            stated: GrantStated::Live,
            from: 0,
            until: FAR,
            scope: AclScope::SameGroup,
            set_id: "crew".to_string(),
            ham_state: 2,
        },
    ];
    entries.sort_by(|left, right| left.accessor.cmp(&right.accessor));
    let snapshot = AclSnapshotBody {
        object_set: Some(AclObjectSet {
            predicate: GroupPredicate::SameGroup,
            set_id: "crew".to_string(),
            stated: GrantStated::Live,
            ham_state: 2,
        }),
        entries,
    };
    let manifest = manifest_for(
        &owner,
        "item-1",
        2,
        1,
        "laptop",
        "key-group",
        7_200_000,
        &snapshot,
    );
    let config = signed_config(&owner, 2, 7_200_000);
    let readers = vec![
        EnrolledSeaPub::from_account(&bob),
        EnrolledSeaPub::from_account(&carol),
    ];
    let member = wrap_item_dek_to_readers(
        &ItemDek::from_bytes([3u8; 32]),
        2,
        "item-1",
        &manifest.revision_id,
        &[EnrolledSeaPub::from_account(&carol)],
        &NamedSet::try_from_accessors([carol.account()]).unwrap(),
    )
    .unwrap();
    let group = wrap_item_dek_to_group_epoch(
        &ItemDek::from_bytes([3u8; 32]),
        &sociacl_encdisc::GroupEpochKey::from_bytes([8u8; 32]),
        2,
        "item-1",
        "crew",
        &manifest.revision_id,
    )
    .unwrap();
    let mut rewrapped = member;
    rewrapped.push(group);
    let rotation = EpochRotation {
        object: "item-1".to_string(),
        revoked_epoch: 1,
        next_epoch: 2,
        revision_id: manifest.revision_id.clone(),
        cancelled: vec![RotationCancel::Plain {
            grant: sociacl_encdisc::CancelledGrant {
                grant: PlainGrant::Membership(sociacl_encdisc::MeshMembership {
                    predicate: GroupPredicate::SameGroup,
                    set_id: "crew".to_string(),
                    accessor: bob.account().to_string(),
                    stated: GrantStated::Cancelled,
                    ham_state: 4,
                }),
                ham_state: 4,
            },
        }],
        rewrapped,
        cipher: RevokeCipherMode::ForwardOnly,
    };
    let prior = [PriorRevision {
        accessor: bob.account().to_string(),
        grant_revision: 1,
        ham_state: 2,
    }];
    let mut ctx = context(&owner, &manifest, &snapshot, &readers, &prior, 1_000);
    ctx.group_config = Some(&config);
    ctx.owner_of_set = Some(owner.account());
    let outcome = rotate_on_revoke(&rotation, &ctx).unwrap();
    assert_eq!(outcome.wrapped_accessors, vec![carol.account().to_string()]);
    assert!(!outcome.delays_privilege_down());
    assert_eq!(outcome.cipher.as_str(), "forward-only");
}

#[test]
fn every_candidate_resolves_and_a_child_names_the_parent_epoch() {
    let owner = AccountSeaSecret::generate("0xalice").unwrap();
    let snapshot = empty_acl();
    let first = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "laptop",
        "key-a",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let second = manifest_for(
        &owner,
        "item-1",
        1,
        0,
        "phone",
        "key-b",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let child_manifest = manifest_for(
        &owner,
        "item-1",
        2,
        1,
        "tablet",
        "key-c",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let skipped_manifest = manifest_for(
        &owner,
        "item-1",
        3,
        2,
        "desk",
        "key-d",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let jumped_manifest = manifest_for(
        &owner,
        "item-1",
        3,
        1,
        "radio",
        "key-e",
        SETTLE_WINDOW_DEFAULT_MS,
        &snapshot,
    );
    let mut chain = chain_with(&owner, &first, &snapshot);
    for manifest in [
        &second,
        &child_manifest,
        &skipped_manifest,
        &jumped_manifest,
    ] {
        chain
            .insert_manifest(manifest.clone(), snapshot.clone(), owner.sea_pub())
            .unwrap();
    }
    let (low, high) = if first.revision_id < second.revision_id {
        (&first, &second)
    } else {
        (&second, &first)
    };
    let mut both = EpochFinalization::seal(
        "item-1",
        0,
        1,
        &low.revision_id,
        vec![low.revision_id.clone(), high.revision_id.clone()],
        "",
        "",
    )
    .unwrap();
    both.signature = owner
        .sign_epoch_finalization(&both.finalization_id)
        .unwrap();
    chain
        .insert_finalization(both.clone(), 1, owner.sea_pub())
        .unwrap();

    let ghost = "f".repeat(64);
    assert!(ghost.as_str() > low.revision_id.as_str());
    let mut unresolved = EpochFinalization::seal(
        "item-1",
        0,
        1,
        &low.revision_id,
        vec![low.revision_id.clone(), ghost],
        "",
        "",
    )
    .unwrap();
    unresolved.signature = owner
        .sign_epoch_finalization(&unresolved.finalization_id)
        .unwrap();
    assert!(chain
        .insert_finalization(unresolved, 2, owner.sea_pub())
        .is_err());

    let mut crossed_ids = vec![low.revision_id.clone(), child_manifest.revision_id.clone()];
    crossed_ids.sort();
    let named = crossed_ids[0].clone();
    let mut crossed = EpochFinalization::seal("item-1", 0, 1, &named, crossed_ids, "", "").unwrap();
    crossed.signature = owner
        .sign_epoch_finalization(&crossed.finalization_id)
        .unwrap();
    assert!(chain
        .insert_finalization(crossed, 3, owner.sea_pub())
        .is_err());

    let skip = fin_for(
        &owner,
        "item-1",
        2,
        3,
        &skipped_manifest.revision_id,
        &both.finalization_id,
    );
    assert!(chain
        .insert_finalization(skip.clone(), 4, owner.sea_pub())
        .is_err());
    let jump = fin_for(
        &owner,
        "item-1",
        1,
        3,
        &jumped_manifest.revision_id,
        &both.finalization_id,
    );
    assert!(chain.insert_finalization(jump, 5, owner.sea_pub()).is_err());
    let child = fin_for(
        &owner,
        "item-1",
        1,
        2,
        &child_manifest.revision_id,
        &both.finalization_id,
    );
    chain
        .insert_finalization(child, 6, owner.sea_pub())
        .unwrap();
    assert!(chain.revision_on_chain(&child_manifest.revision_id, &snapshot, 7, None));
    assert!(!chain.revision_on_chain(&skipped_manifest.revision_id, &snapshot, 7, None));

    let mut early = EpochChain::new("item-1").unwrap();
    for manifest in [&first, &second, &skipped_manifest] {
        early
            .insert_manifest(manifest.clone(), snapshot.clone(), owner.sea_pub())
            .unwrap();
    }
    early.insert_finalization(skip, 1, owner.sea_pub()).unwrap();
    early.insert_finalization(both, 2, owner.sea_pub()).unwrap();
    assert!(early.revision_on_chain(&low.revision_id, &snapshot, 3, None));
    assert!(!early.revision_on_chain(&skipped_manifest.revision_id, &snapshot, 3, None));
}

#[test]
fn stale_acl_membership_and_object_set_do_not_settle() {
    let revision = REV.to_string();
    let view = EpochReplicaView {
        object: "item-1".to_string(),
        epoch: 2,
        previous_finalization_id: String::new(),
        seen: vec![EpochFinalization::seal(
            "item-1",
            1,
            2,
            &revision,
            vec![revision.clone()],
            "",
            "sig",
        )
        .unwrap()],
        winner_seen_at: 0,
        settle_window_ms: SETTLE_WINDOW_DEFAULT_MS,
        settled_revision_id: revision,
        settled_epoch: 1,
    };
    let now = SETTLE_WINDOW_DEFAULT_MS;
    let live = AclSnapshotBody {
        object_set: None,
        entries: vec![
            direct_entry("0xada", 1, GrantStated::Live),
            direct_entry("0xbob", 2, GrantStated::Cancelled),
        ],
    };
    assert!(epoch_step_current(&view, &live, &live, now));

    let mut lists_ada_live = live.clone();
    lists_ada_live.entries[0].stated = GrantStated::Live;
    lists_ada_live.entries[0].grant_revision = 1;
    let mut current = live.clone();
    current.entries[0].stated = GrantStated::Cancelled;
    current.entries[0].grant_revision = 10;
    current.entries[1].grant_revision = 2;
    assert!(!epoch_step_current(&view, &lists_ada_live, &current, now));

    let omits_bob = AclSnapshotBody {
        object_set: None,
        entries: vec![direct_entry("0xada", 10, GrantStated::Cancelled)],
    };
    assert!(!epoch_step_current(&view, &omits_bob, &current, now));

    let mut cancels_bob_low = current.clone();
    cancels_bob_low.entries[1].grant_revision = 2;
    let mut snapshot_low = current.clone();
    snapshot_low.entries[1].grant_revision = 1;
    assert!(!epoch_step_current(
        &view,
        &snapshot_low,
        &cancels_bob_low,
        now
    ));

    let set_a = AclSnapshotBody {
        object_set: Some(AclObjectSet {
            predicate: GroupPredicate::SameGroup,
            set_id: "crew-a".to_string(),
            stated: GrantStated::Live,
            ham_state: 2,
        }),
        entries: vec![AclSnapshotEntry {
            accessor: "0xcarol".to_string(),
            grant_revision: 1,
            stated: GrantStated::Live,
            from: 0,
            until: FAR,
            scope: AclScope::SameGroup,
            set_id: "crew-a".to_string(),
            ham_state: 2,
        }],
    };
    let set_b = AclSnapshotBody {
        object_set: Some(AclObjectSet {
            predicate: GroupPredicate::SameGroup,
            set_id: "crew-b".to_string(),
            stated: GrantStated::Live,
            ham_state: 4,
        }),
        entries: vec![AclSnapshotEntry {
            accessor: "0xcarol".to_string(),
            grant_revision: 1,
            stated: GrantStated::Live,
            from: 0,
            until: FAR,
            scope: AclScope::SameGroup,
            set_id: "crew-b".to_string(),
            ham_state: 2,
        }],
    };
    assert!(!epoch_step_current(&view, &set_a, &set_b, now));

    let mut removed = set_a.clone();
    removed.entries[0].stated = GrantStated::Cancelled;
    removed.entries[0].ham_state = 4;
    assert!(!epoch_step_current(&view, &set_a, &removed, now));
    assert!(!settled_key_open(&view, &set_a, &removed, now));
}

fn context<'a>(
    owner: &'a AccountSeaSecret,
    manifest: &'a EpochManifest,
    snapshot: &'a AclSnapshotBody,
    readers: &'a [EnrolledSeaPub],
    prior: &'a [PriorRevision],
    now: u64,
) -> RotationContext<'a> {
    RotationContext {
        owner: owner.account(),
        owner_pub: owner.sea_pub(),
        storage: GrantStorage::PublicPlain,
        manifest,
        snapshot,
        readers,
        prior_revision: prior,
        now,
        skew_allowance_ms: 5_000,
        policy_max_age_ms: 60_000,
        group_config: None,
        owner_of_set: None,
    }
}
