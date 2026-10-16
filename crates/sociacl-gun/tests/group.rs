//! Plaintext same-group and named-circle on the mesh.
//! Hopcap 1. A hop or a hint never mints. A lower ham state
//! does not hide a removal.

use sociacl_core::{AttestationChannel, Timestamp};
use sociacl_gun::{
    membership_soul, object_set_soul, DecodedGroupPayload, GroupPredicate, GroupSnapshotMember,
    GroupSnapshotObjectSet, GunError, GunSoul, HandoffHint, HopFactor, MeshSeeGrant, MeshSeeGraph,
    PresentedGroup, MESH_REASON_ACL, MESH_REASON_CANCELLED, MESH_REASON_DELEGATE, MESH_REASON_META,
    MESH_REASON_MISSING, MESH_REASON_OWNER, MESH_REASON_URL_LEAF,
};

fn payload(stated: u8, from: u64, until: u64) -> DecodedGroupPayload {
    DecodedGroupPayload {
        stated,
        from,
        until,
    }
}

fn live_payload() -> DecodedGroupPayload {
    payload(1, 10, 20)
}

fn hop() -> HopFactor {
    HopFactor::Structured {
        channel: AttestationChannel::ConventionBadge,
        attestation_bytes: None,
        share_token: None,
    }
}

fn hint(accessor: &str, object: &str) -> HandoffHint {
    HandoffHint::parse(accessor, object, Some("see"), None).unwrap()
}

fn group_graph() -> MeshSeeGraph {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .name_object_set("0xalice", "doc", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .state_membership("0xbob", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    graph
        .state_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    graph
}

fn presented(predicate: GroupPredicate, set_id: &str) -> PresentedGroup {
    PresentedGroup {
        predicate,
        set_id: set_id.to_string(),
    }
}

#[test]
fn same_group_requires_both_live_edges() {
    let graph = group_graph();
    let now = Timestamp(1);
    let allowed = graph.check_group_see(GroupPredicate::SameGroup, "doc", "0xbob", now, None, None);
    assert!(allowed.allowed);
    assert_eq!(allowed.reason, GroupPredicate::SameGroup.as_str());
    assert!(allowed.hop.is_none());

    let owner = graph.check_group_see(GroupPredicate::SameGroup, "doc", "0xalice", now, None, None);
    assert!(owner.allowed);
    assert_eq!(owner.reason, MESH_REASON_OWNER);

    assert!(
        !graph
            .check_group_see(
                GroupPredicate::SameGroup,
                "doc",
                "0xcarol",
                Timestamp(u64::MAX),
                None,
                None,
            )
            .allowed
    );
}

#[test]
fn named_circle_is_direct_and_not_a_group() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("album", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::NamedCircle, "friends")
        .unwrap();
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "friends")
        .unwrap();
    graph
        .name_object_set("0xalice", "album", GroupPredicate::NamedCircle, "friends")
        .unwrap();
    graph
        .state_membership("0xbob", GroupPredicate::NamedCircle, "friends", "0xbob")
        .unwrap();
    graph
        .state_membership("0xalice", GroupPredicate::NamedCircle, "friends", "0xbob")
        .unwrap();
    graph
        .state_membership("0xbob", GroupPredicate::SameGroup, "friends", "0xbob")
        .unwrap();
    graph
        .state_membership("0xalice", GroupPredicate::SameGroup, "friends", "0xbob")
        .unwrap();

    let circle = graph.check_group_see(
        GroupPredicate::NamedCircle,
        "album",
        "0xbob",
        Timestamp(0),
        None,
        None,
    );
    assert!(circle.allowed);
    assert_eq!(circle.reason, "named-circle");

    let wrong = graph.check_group_see(
        GroupPredicate::SameGroup,
        "album",
        "0xbob",
        Timestamp(0),
        None,
        None,
    );
    assert!(!wrong.allowed);
    assert_eq!(wrong.reason, MESH_REASON_MISSING);
}

#[test]
fn one_sided_membership_is_stored_and_is_not_a_grant() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .name_object_set("0xalice", "doc", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .state_membership("0xbob", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    let row = graph
        .membership(GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    assert_eq!(row.stated, 0);
    assert_eq!(row.ham_state, 1);
    let denied = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(5),
        None,
        None,
    );
    assert!(!denied.allowed);
    assert_eq!(denied.reason, MESH_REASON_MISSING);
}

#[test]
fn cancel_bumps_ham_and_the_next_check_denies() {
    let mut graph = group_graph();
    let live = graph
        .membership(GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    assert_eq!(live.stated, 1);
    let ham = live.ham_state;
    graph
        .cancel_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    let cancelled = graph
        .membership(GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    assert_eq!(cancelled.stated, 0);
    assert!(cancelled.ham_state > ham);
    let denied = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(5),
        None,
        None,
    );
    assert!(!denied.allowed);
    assert_eq!(denied.reason, MESH_REASON_CANCELLED);
}

#[test]
fn cleared_object_edge_denies_a_live_member() {
    let mut graph = group_graph();
    graph.clear_object_set("0xalice", "doc").unwrap();
    let edge = graph.object_set("doc").unwrap();
    assert_eq!(edge.stated, 0);
    assert!(edge.ham_state > 1);
    let denied = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(5),
        None,
        None,
    );
    assert!(!denied.allowed);
    assert_eq!(denied.reason, MESH_REASON_CANCELLED);
}

#[test]
fn hop_and_hint_never_mint() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("doc", "0xalice");
    let hinted = hint("0xcarol", "doc");
    let factor = hop();
    let alone = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xcarol",
        Timestamp(1),
        Some(&hinted),
        Some(&factor),
    );
    assert!(!alone.allowed);
    assert!(!alone.hop_is_grant());
    assert!(!alone.hint_is_grant());
    assert!(!alone.hop_factored());

    let mut graph = group_graph();
    let hinted = hint("0xbob", "doc");
    let factor = hop();
    let factored = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(1),
        Some(&hinted),
        Some(&factor),
    );
    assert!(factored.allowed);
    assert!(factored.hop_factored());
    assert!(!factored.hop_is_grant());

    graph
        .cancel_membership("0xbob", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    let after = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(1),
        Some(&hinted),
        Some(&factor),
    );
    assert!(!after.allowed);
    assert!(!after.hop_factored());
}

#[test]
fn no_transitive_membership_and_no_friend_walk() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("doc", "0xalice");
    graph.put_object("other", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "ops-core")
        .unwrap();
    graph
        .name_object_set("0xalice", "doc", GroupPredicate::SameGroup, "ops-core")
        .unwrap();
    graph
        .name_object_set("0xalice", "other", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .state_membership("0xbob", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    graph
        .state_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    graph.state_friend("0xbob", "0xcarol");

    assert!(
        !graph
            .check_group_see(
                GroupPredicate::SameGroup,
                "doc",
                "0xbob",
                Timestamp(1),
                None,
                None,
            )
            .allowed,
        "membership in ops does not grant ops-core"
    );
    assert!(
        graph
            .check_group_see(
                GroupPredicate::SameGroup,
                "other",
                "0xbob",
                Timestamp(1),
                None,
                None,
            )
            .allowed
    );
    assert!(
        !graph
            .check_group_see(
                GroupPredicate::SameGroup,
                "other",
                "0xcarol",
                Timestamp(1),
                None,
                None,
            )
            .allowed,
        "a friend of a member is not a member"
    );
}

#[test]
fn a_see_grant_does_not_satisfy_the_group_predicate() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .name_object_set("0xalice", "doc", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("doc", "0xbob", 0, 80))
        .unwrap();
    assert!(
        graph
            .check_see("doc", "0xbob", Timestamp(1), None, None)
            .allowed
    );
    let group = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(1),
        None,
        None,
    );
    assert!(!group.allowed);
    assert_eq!(group.reason, MESH_REASON_MISSING);
}

#[test]
fn closed_objects_fail_on_group_check() {
    let graph = MeshSeeGraph::new();
    let now = Timestamp(1);
    assert_eq!(
        graph
            .check_group_see(
                GroupPredicate::SameGroup,
                "s3rch/meta",
                "0xalice",
                now,
                None,
                None,
            )
            .reason,
        MESH_REASON_META
    );
    assert_eq!(
        graph
            .check_group_see(
                GroupPredicate::NamedCircle,
                "s3rch/acl/0xalice",
                "0xalice",
                now,
                None,
                None,
            )
            .reason,
        MESH_REASON_ACL
    );
    assert_eq!(
        graph
            .check_group_see(
                GroupPredicate::SameGroup,
                "https://gi.rss3.io/decentralized/0xalice",
                "0xalice",
                now,
                None,
                None,
            )
            .reason,
        MESH_REASON_URL_LEAF
    );
    assert_eq!(
        graph
            .check_group_see(
                GroupPredicate::SameGroup,
                "missing",
                "0xbob",
                now,
                None,
                None
            )
            .reason,
        MESH_REASON_MISSING
    );
}

#[test]
fn group_rows_are_not_grant_souls() {
    let graph = group_graph();
    let member = graph
        .membership_row_soul(GroupPredicate::SameGroup, "ops", "s3rch/users/0xbob")
        .unwrap();
    let expected = membership_soul("0xalice", GroupPredicate::SameGroup, "ops", "0xbob");
    assert_eq!(member, expected);
    assert!(member.starts_with("s3rch/acl/"));
    assert!(member.contains("/membership/"));
    let member_soul = GunSoul::parse(member).unwrap();
    assert!(member_soul.is_s3rch_acl());
    assert!(!member_soul.is_s3rch_acl_grant());

    let edge = graph.object_set_row_soul("doc").unwrap();
    assert_eq!(edge, object_set_soul("0xalice", "doc"));
    assert!(edge.contains("/object-set/"));
    let edge_soul = GunSoul::parse(edge).unwrap();
    assert!(edge_soul.is_s3rch_acl());
    assert!(!edge_soul.is_s3rch_acl_grant());
    assert_eq!(
        graph
            .check_see(member, "0xbob", Timestamp(1), None, None)
            .reason,
        MESH_REASON_ACL
    );
    assert_eq!(
        graph.owner_of_set(GroupPredicate::SameGroup, "ops"),
        Some("0xalice")
    );
    assert_eq!(graph.owner_of_set(GroupPredicate::NamedCircle, "ops"), None);
}

#[test]
fn writers_are_the_object_owner_and_the_set_parties() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("doc", "0xalice");
    assert_eq!(
        graph.record_set_owner("0xalice", GroupPredicate::SameGroup, ""),
        Err(GunError::EmptyGroupName)
    );
    assert_eq!(
        graph.record_set_owner("", GroupPredicate::SameGroup, "ops"),
        Err(GunError::EmptyGroupName)
    );
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .record_set_owner("s3rch/users/0xalice", GroupPredicate::SameGroup, "ops")
        .unwrap();
    assert_eq!(
        graph.record_set_owner("0xbob", GroupPredicate::SameGroup, "ops"),
        Err(GunError::SetOwnerConflict)
    );
    assert_eq!(
        graph.name_object_set("0xbob", "doc", GroupPredicate::SameGroup, "ops"),
        Err(GunError::AclOwnerOnly)
    );
    assert_eq!(
        graph.name_object_set("0xalice", "nope", GroupPredicate::SameGroup, "ops"),
        Err(GunError::ObjectNotInGraph)
    );
    assert_eq!(
        graph.name_object_set("0xalice", "doc", GroupPredicate::SameGroup, " "),
        Err(GunError::EmptyGroupName)
    );
    assert_eq!(
        graph.state_membership("0xcarol", GroupPredicate::SameGroup, "ops", "0xbob"),
        Err(GunError::MembershipSpeaker)
    );
    assert_eq!(
        graph.state_membership("0xbob", GroupPredicate::NamedCircle, "missing", "0xbob"),
        Err(GunError::SetUnknown)
    );
    assert_eq!(
        graph.state_membership("0xbob", GroupPredicate::SameGroup, "ops", ""),
        Err(GunError::EmptyGroupName)
    );
    graph.clear_object_set("0xalice", "doc").unwrap();
    assert!(graph.object_set("doc").is_none());
}

#[test]
fn peer_merge_keeps_the_higher_removal() {
    let mut current = group_graph();
    current
        .cancel_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    current
        .cancel_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    let ham = current
        .membership(GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap()
        .ham_state;
    current
        .name_object_set("0xalice", "doc", GroupPredicate::SameGroup, "labs")
        .unwrap();

    let stale = group_graph();
    current.merge_from(&stale);
    let row = current
        .membership(GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    assert_eq!(row.stated, 0);
    assert_eq!(row.ham_state, ham);
    assert_eq!(current.object_set("doc").unwrap().set_id, "labs");
    assert!(
        !current
            .check_group_see(
                GroupPredicate::SameGroup,
                "doc",
                "0xbob",
                Timestamp(1),
                None,
                None,
            )
            .allowed
    );
}

#[test]
fn presented_group_allows_only_a_live_payload_inside_the_window() {
    let graph = group_graph();
    let group = presented(GroupPredicate::SameGroup, "ops");
    let now = Timestamp(10);
    let allowed = graph.check_group_presentation(
        Some(&group),
        "doc",
        "0xbob",
        &live_payload(),
        now,
        None,
        None,
    );
    assert!(allowed.allowed);
    assert_eq!(allowed.reason, "same-group");
    assert!(!allowed.store_cancel);

    let owner = graph.check_group_presentation(
        Some(&group),
        "doc",
        "0xalice",
        &live_payload(),
        now,
        None,
        None,
    );
    assert!(owner.allowed);
    assert_eq!(owner.reason, MESH_REASON_OWNER);
    let owner_cancel = graph.check_group_presentation(
        Some(&group),
        "doc",
        "0xalice",
        &payload(0, 10, 20),
        now,
        None,
        None,
    );
    assert!(!owner_cancel.allowed);
    assert!(owner_cancel.store_cancel);

    let outsider = graph.check_group_presentation(
        Some(&group),
        "doc",
        "0xcarol",
        &live_payload(),
        now,
        None,
        None,
    );
    assert!(!outsider.allowed);
    assert_eq!(outsider.reason, MESH_REASON_MISSING);
    assert!(!outsider.store_cancel);

    let at_until = graph.check_group_presentation(
        Some(&group),
        "doc",
        "0xbob",
        &live_payload(),
        Timestamp(20),
        None,
        None,
    );
    assert!(!at_until.allowed);
    assert_eq!(at_until.reason, MESH_REASON_CANCELLED);

    let before = graph.check_group_presentation(
        Some(&group),
        "doc",
        "0xbob",
        &payload(1, 10, 20),
        Timestamp(9),
        None,
        None,
    );
    assert!(!before.allowed);

    let cancel = graph.check_group_presentation(
        Some(&group),
        "doc",
        "0xbob",
        &payload(0, 10, 20),
        now,
        None,
        Some(&hop()),
    );
    assert!(!cancel.allowed, "a live edge does not override stated 0");
    assert!(cancel.store_cancel);
    assert!(!cancel.hop_factored());
    assert!(!cancel.hop_is_grant());
}

#[test]
fn a_group_object_without_presented_group_fails_closed() {
    let mut graph = group_graph();
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("doc", "0xbob", 0, 80))
        .unwrap();
    let denied = graph.check_group_presentation(
        None,
        "doc",
        "0xbob",
        &live_payload(),
        Timestamp(10),
        None,
        None,
    );
    assert!(!denied.allowed);
    assert_eq!(denied.reason, MESH_REASON_MISSING);

    let wrong_set = presented(GroupPredicate::SameGroup, "other");
    let mismatch = graph.check_group_presentation(
        Some(&wrong_set),
        "doc",
        "0xbob",
        &live_payload(),
        Timestamp(10),
        None,
        None,
    );
    assert!(!mismatch.allowed);
}

#[test]
fn an_ordinary_see_grant_omits_the_group_argument() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("claim-1", "0xalice");
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("claim-1", "0xbob", 0, 80))
        .unwrap();
    let allowed = graph.check_group_presentation(
        None,
        "claim-1",
        "0xbob",
        &payload(1, 0, 80),
        Timestamp(10),
        None,
        None,
    );
    assert!(allowed.allowed);
    assert_eq!(allowed.reason, MESH_REASON_DELEGATE);

    let hinted = hint("0xcarol", "claim-1");
    let stranger = graph.check_group_presentation(
        None,
        "claim-1",
        "0xcarol",
        &payload(1, 0, 80),
        Timestamp(10),
        Some(&hinted),
        Some(&hop()),
    );
    assert!(!stranger.allowed);
    assert!(!stranger.hop_is_grant());
    assert!(!stranger.hint_is_grant());

    let cancel = graph.check_group_presentation(
        None,
        "claim-1",
        "0xbob",
        &payload(0, 0, 80),
        Timestamp(10),
        None,
        None,
    );
    assert!(!cancel.allowed);
    assert!(cancel.store_cancel);
    assert_eq!(cancel.reason, MESH_REASON_CANCELLED);
}

#[test]
fn snapshot_ham_does_not_hide_a_membership_removal() {
    let mut graph = group_graph();
    graph
        .cancel_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    graph
        .cancel_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    let ham = graph
        .membership(GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap()
        .ham_state;
    assert!(ham >= 4);

    let edge = GroupSnapshotObjectSet {
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 1,
        ham_state: graph.object_set("doc").unwrap().ham_state,
    };
    let live_low = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 1,
        ham_state: 2,
    };
    assert!(graph.snapshot_understates_group("doc", &[live_low], Some(&edge)));

    let omitted = graph.snapshot_understates_group("doc", &[], Some(&edge));
    assert!(omitted);

    let low_cancel = GroupSnapshotMember {
        accessor: "s3rch/users/0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 0,
        ham_state: ham - 1,
    };
    assert!(graph.snapshot_understates_group("doc", &[low_cancel], Some(&edge)));

    let current = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 0,
        ham_state: ham,
    };
    assert!(!graph.snapshot_understates_group("doc", &[current.clone()], Some(&edge)));

    let newer_cancel = GroupSnapshotMember {
        ham_state: ham + 1,
        ..current
    };
    assert!(!graph.snapshot_understates_group("doc", &[newer_cancel], Some(&edge)));

    let live_tie = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 1,
        ham_state: ham,
    };
    let cancel_tie = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 0,
        ham_state: ham,
    };
    assert!(
        !graph.snapshot_understates_group("doc", &[live_tie, cancel_tie], Some(&edge)),
        "at one ham state, stated 0 is the removal"
    );
}

#[test]
fn rejoin_needs_both_sides_again() {
    let mut graph = group_graph();
    graph
        .cancel_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    graph
        .state_membership("0xbob", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    let half = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(1),
        None,
        None,
    );
    assert!(!half.allowed);
    assert_eq!(half.reason, MESH_REASON_CANCELLED);
    graph
        .state_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();
    assert!(
        graph
            .check_group_see(
                GroupPredicate::SameGroup,
                "doc",
                "0xbob",
                Timestamp(1),
                None,
                None,
            )
            .allowed
    );
}

#[test]
fn owner_membership_is_joint_in_one_statement() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .name_object_set("0xalice", "doc", GroupPredicate::SameGroup, "ops")
        .unwrap();
    graph
        .state_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xalice")
        .unwrap();
    let row = graph
        .membership(GroupPredicate::SameGroup, "ops", "0xalice")
        .unwrap();
    assert_eq!(row.stated, 1);
    assert_eq!(row.ham_state, 1);
}

#[test]
fn snapshot_object_set_ham_is_not_the_member_ham() {
    let mut graph = group_graph();
    graph
        .name_object_set("0xalice", "doc", GroupPredicate::SameGroup, "labs")
        .unwrap();
    let edge = graph.object_set("doc").unwrap();
    assert_eq!(edge.set_id, "labs");
    let ham = edge.ham_state;

    graph
        .cancel_membership("0xalice", GroupPredicate::SameGroup, "ops", "0xbob")
        .unwrap();

    let stale = GroupSnapshotObjectSet {
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 1,
        ham_state: ham - 1,
    };
    assert!(
        graph.snapshot_understates_group("doc", &[], Some(&stale)),
        "a member row does not stand in for the object-set edge"
    );

    let current = GroupSnapshotObjectSet {
        predicate: GroupPredicate::SameGroup,
        set_id: "labs".into(),
        stated: 1,
        ham_state: ham,
    };
    assert!(!graph.snapshot_understates_group("doc", &[], Some(&current)));

    let dropped = graph.snapshot_understates_group("doc", &[], None);
    assert!(dropped);

    let mut plain = MeshSeeGraph::new();
    plain.put_object("claim-1", "0xalice");
    let extra = GroupSnapshotObjectSet {
        predicate: GroupPredicate::NamedCircle,
        set_id: "friends".into(),
        stated: 1,
        ham_state: 1,
    };
    assert!(plain.snapshot_understates_group("claim-1", &[], Some(&extra)));
    assert!(!plain.snapshot_understates_group("claim-1", &[], None));
}

#[test]
fn a_cancel_in_another_set_does_not_stale_this_object() {
    let mut graph = group_graph();
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "labs")
        .unwrap();
    graph
        .state_membership("0xcarol", GroupPredicate::SameGroup, "labs", "0xcarol")
        .unwrap();
    graph
        .cancel_membership("0xalice", GroupPredicate::SameGroup, "labs", "0xcarol")
        .unwrap();
    let edge = GroupSnapshotObjectSet {
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 1,
        ham_state: 1,
    };
    let bob = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "ops".into(),
        stated: 1,
        ham_state: 2,
    };
    assert!(!graph.snapshot_understates_group("doc", &[bob], Some(&edge)));
}
