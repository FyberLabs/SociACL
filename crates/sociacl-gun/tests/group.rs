//! Plaintext same-group and named-circle on the mesh.
//! Hopcap 1. A hop or a hint never mints. A lower ham state
//! does not hide a removal.

use sociacl_core::{AttestationChannel, IssuerSecret, Timestamp};
use sociacl_gun::{
    membership_soul, object_set_soul, DecodedGroupPayload, GroupPredicate, GroupSnapshotMember,
    GroupSnapshotObjectSet, GunError, GunSoul, HandoffHint, HopFactor, MeshSeeGrant, MeshSeeGraph,
    PresentedGroup, MESH_REASON_ACL, MESH_REASON_CANCELLED, MESH_REASON_DELEGATE, MESH_REASON_META,
    MESH_REASON_MISSING, MESH_REASON_OWNER, MESH_REASON_URL_LEAF,
};

fn signer(name: &str) -> IssuerSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in name.as_bytes().iter().enumerate() {
        bytes[i % 32] ^= b.wrapping_add((i as u8).wrapping_mul(17));
    }
    bytes[0] ^= name.len() as u8;
    bytes[31] |= 1;
    IssuerSecret::from_bytes(bytes)
}

fn enroll_fixture(graph: &mut MeshSeeGraph) {
    for name in ["0xalice", "0xbob", "0xcarol", "0xmallory", "0xdave"] {
        graph
            .enroll_signer(name, signer(name).verify_key())
            .unwrap();
    }
}

fn new_graph() -> MeshSeeGraph {
    let mut graph = MeshSeeGraph::new();
    enroll_fixture(&mut graph);
    graph
}

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
    let mut graph = new_graph();
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    graph
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
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

#[derive(serde::Deserialize)]
struct PrincipalVectorFile {
    groups: GroupObjectVectors,
}

#[derive(serde::Deserialize)]
struct GroupObjectVectors {
    predicate: String,
    #[serde(rename = "setId")]
    set_id: String,
    accessor: String,
    queries: Vec<GroupObjectQuery>,
}

#[derive(serde::Deserialize)]
struct GroupObjectQuery {
    name: String,
    object: String,
    #[serde(default)]
    accessor: Option<String>,
    allowed: bool,
    reason: String,
}

#[test]
fn a_spaced_object_id_does_not_see_the_stored_group() {
    let file: PrincipalVectorFile =
        serde_json::from_str(include_str!("../../../vectors/mesh/principals.json")).unwrap();
    let vectors = file.groups;
    assert_eq!(vectors.predicate, GroupPredicate::SameGroup.as_str());
    let graph = group_graph();
    let group = presented(GroupPredicate::SameGroup, &vectors.set_id);
    for row in &vectors.queries {
        let accessor = row.accessor.as_deref().unwrap_or(vectors.accessor.as_str());
        let see = graph.check_group_see(
            GroupPredicate::SameGroup,
            &row.object,
            accessor,
            Timestamp(1),
            None,
            None,
        );
        assert_eq!(see.allowed, row.allowed, "{}", row.name);
        assert_eq!(see.reason, row.reason, "{}", row.name);
        if !row.allowed {
            assert!(
                !graph
                    .check_see(&row.object, accessor, Timestamp(1), None, None)
                    .allowed,
                "{}",
                row.name
            );
        }
        let presentation = graph.check_group_presentation(
            Some(&group),
            &row.object,
            accessor,
            &live_payload(),
            Timestamp(10),
            None,
            None,
        );
        assert_eq!(presentation.allowed, row.allowed, "{}", row.name);
        assert_eq!(presentation.reason, row.reason, "{}", row.name);
    }
}

#[test]
fn named_circle_is_direct_and_not_a_group() {
    let mut graph = new_graph();
    graph.put_object("album", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::NamedCircle, "0xalice/friends")
        .unwrap();
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/friends")
        .unwrap();
    graph
        .name_object_set(
            "0xalice",
            "album",
            GroupPredicate::NamedCircle,
            "0xalice/friends",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xbob",
            GroupPredicate::NamedCircle,
            "0xalice/friends",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xalice",
            GroupPredicate::NamedCircle,
            "0xalice/friends",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/friends",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/friends",
            "0xbob",
            &signer("0xalice"),
        )
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
    let mut graph = new_graph();
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    graph
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    let row = graph
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
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
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .unwrap();
    assert_eq!(live.stated, 1);
    let ham = live.ham_state;
    graph
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    let cancelled = graph
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
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
    graph
        .clear_object_set("0xalice", "doc", &signer("0xalice"))
        .unwrap();
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
    let mut graph = new_graph();
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
        .cancel_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
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
    let mut graph = new_graph();
    graph.put_object("doc", "0xalice");
    graph.put_object("other", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops-core")
        .unwrap();
    graph
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops-core",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .name_object_set(
            "0xalice",
            "other",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
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
    let mut graph = new_graph();
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    graph
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
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
    let graph = new_graph();
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
        .membership_row_soul(
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "s3rch/users/0xbob",
        )
        .unwrap();
    let expected = membership_soul("0xalice", GroupPredicate::SameGroup, "0xalice/ops", "0xbob");
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
        graph.owner_of_set(GroupPredicate::SameGroup, "0xalice/ops"),
        Some("0xalice")
    );
    assert_eq!(
        graph.owner_of_set(GroupPredicate::NamedCircle, "0xalice/ops"),
        None
    );
}

#[test]
fn writers_are_the_object_owner_and_the_set_parties() {
    let mut graph = new_graph();
    graph.put_object("doc", "0xalice");
    assert_eq!(
        graph.record_set_owner("0xalice", GroupPredicate::SameGroup, ""),
        Err(GunError::EmptyGroupName)
    );
    assert_eq!(
        graph.record_set_owner("", GroupPredicate::SameGroup, "0xalice/ops"),
        Err(GunError::EmptyGroupName)
    );
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    graph
        .record_set_owner(
            "s3rch/users/0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
        )
        .unwrap();
    assert_eq!(
        graph.record_set_owner("0xbob", GroupPredicate::SameGroup, "0xalice/ops"),
        Err(GunError::SetOwnerConflict)
    );
    assert_eq!(
        graph.name_object_set(
            "0xbob",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xbob")
        ),
        Err(GunError::AclOwnerOnly)
    );
    assert_eq!(
        graph.name_object_set(
            "0xalice",
            "nope",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice")
        ),
        Err(GunError::ObjectNotInGraph)
    );
    assert_eq!(
        graph.name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            " ",
            &signer("0xalice")
        ),
        Err(GunError::EmptyGroupName)
    );
    assert_eq!(
        graph.state_membership(
            "0xcarol",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xcarol")
        ),
        Err(GunError::MembershipSpeaker)
    );
    assert_eq!(
        graph.state_membership(
            "0xbob",
            GroupPredicate::NamedCircle,
            "missing",
            "0xbob",
            &signer("0xbob")
        ),
        Err(GunError::SetUnknown)
    );
    assert_eq!(
        graph.state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "",
            &signer("0xbob")
        ),
        Err(GunError::EmptyGroupName)
    );
    graph
        .clear_object_set("0xalice", "doc", &signer("0xalice"))
        .unwrap();
    let tombstone = graph.object_set("doc").unwrap();
    assert_eq!(tombstone.stated, 0);
    assert_eq!(tombstone.ham_state, 1);
}

#[test]
fn peer_merge_keeps_the_higher_removal() {
    let mut current = group_graph();
    current
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    current
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    let ham = current
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .unwrap()
        .ham_state;
    current
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/labs",
            &signer("0xalice"),
        )
        .unwrap();

    let stale = group_graph();
    current.merge_from(&stale);
    let row = current
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .unwrap();
    assert_eq!(row.stated, 0);
    assert_eq!(row.ham_state, ham);
    assert_eq!(current.object_set("doc").unwrap().set_id, "0xalice/labs");
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
    let group = presented(GroupPredicate::SameGroup, "0xalice/ops");
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
    let mut graph = new_graph();
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
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    let ham = graph
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .unwrap()
        .ham_state;
    assert!(ham >= 4);

    let edge = GroupSnapshotObjectSet {
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/ops".into(),
        stated: 1,
        ham_state: graph.object_set("doc").unwrap().ham_state,
    };
    let live_low = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/ops".into(),
        stated: 1,
        ham_state: 2,
    };
    assert!(graph.snapshot_understates_group("doc", &[live_low], Some(&edge)));

    let omitted = graph.snapshot_understates_group("doc", &[], Some(&edge));
    assert!(omitted);

    let low_cancel = GroupSnapshotMember {
        accessor: "s3rch/users/0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/ops".into(),
        stated: 0,
        ham_state: ham - 1,
    };
    assert!(graph.snapshot_understates_group("doc", &[low_cancel], Some(&edge)));

    let current = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/ops".into(),
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
        set_id: "0xalice/ops".into(),
        stated: 1,
        ham_state: ham,
    };
    let cancel_tie = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/ops".into(),
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
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
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
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
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
    let mut graph = new_graph();
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    graph
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    graph
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xalice",
            &signer("0xalice"),
        )
        .unwrap();
    let row = graph
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xalice")
        .unwrap();
    assert_eq!(row.stated, 1);
    assert_eq!(row.ham_state, 1);
}

#[test]
fn snapshot_object_set_ham_is_not_the_member_ham() {
    let mut graph = group_graph();
    graph
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/labs",
            &signer("0xalice"),
        )
        .unwrap();
    let edge = graph.object_set("doc").unwrap();
    assert_eq!(edge.set_id, "0xalice/labs");
    let ham = edge.ham_state;

    graph
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();

    let stale = GroupSnapshotObjectSet {
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/ops".into(),
        stated: 1,
        ham_state: ham - 1,
    };
    assert!(
        graph.snapshot_understates_group("doc", &[], Some(&stale)),
        "a member row does not stand in for the object-set edge"
    );

    let current = GroupSnapshotObjectSet {
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/labs".into(),
        stated: 1,
        ham_state: ham,
    };
    assert!(!graph.snapshot_understates_group("doc", &[], Some(&current)));

    let dropped = graph.snapshot_understates_group("doc", &[], None);
    assert!(dropped);

    let mut plain = new_graph();
    plain.put_object("claim-1", "0xalice");
    let extra = GroupSnapshotObjectSet {
        predicate: GroupPredicate::NamedCircle,
        set_id: "0xalice/friends".into(),
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
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/labs")
        .unwrap();
    graph
        .state_membership(
            "0xcarol",
            GroupPredicate::SameGroup,
            "0xalice/labs",
            "0xcarol",
            &signer("0xcarol"),
        )
        .unwrap();
    graph
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/labs",
            "0xcarol",
            &signer("0xalice"),
        )
        .unwrap();
    let edge = GroupSnapshotObjectSet {
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/ops".into(),
        stated: 1,
        ham_state: 1,
    };
    let bob = GroupSnapshotMember {
        accessor: "0xbob".into(),
        predicate: GroupPredicate::SameGroup,
        set_id: "0xalice/ops".into(),
        stated: 1,
        ham_state: 2,
    };
    assert!(!graph.snapshot_understates_group("doc", &[bob], Some(&edge)));
}

fn state_both(graph: &mut MeshSeeGraph, predicate: GroupPredicate, set_id: &str, accessor: &str) {
    graph
        .state_membership(accessor, predicate, set_id, accessor, &signer(accessor))
        .unwrap();
    graph
        .state_membership("0xalice", predicate, set_id, accessor, &signer("0xalice"))
        .unwrap();
}

#[test]
fn merge_drops_membership_from_a_conflicting_set_owner() {
    let mut alice = new_graph();
    alice.put_object("doc", "0xalice");
    alice
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    alice
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();

    let mut mallory = new_graph();
    assert_eq!(
        mallory.record_set_owner("0xmallory", GroupPredicate::SameGroup, "0xalice/ops"),
        Err(GunError::UnboundSetOwner)
    );
    mallory
        .record_set_owner("0xmallory", GroupPredicate::SameGroup, "0xmallory/ops")
        .unwrap();
    mallory
        .state_membership(
            "0xmallory",
            GroupPredicate::SameGroup,
            "0xmallory/ops",
            "0xmallory",
            &signer("0xmallory"),
        )
        .unwrap();

    alice.merge_from(&mallory);
    assert_eq!(
        alice.owner_of_set(GroupPredicate::SameGroup, "0xalice/ops"),
        Some("0xalice")
    );
    assert!(alice
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .is_none());
    assert!(
        !alice
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

    let mut same_owner = new_graph();
    same_owner
        .record_set_owner(
            "s3rch/users/0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
        )
        .unwrap();
    state_both(
        &mut same_owner,
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
    );
    alice.merge_from(&same_owner);
    assert_eq!(
        alice
            .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap()
            .stated,
        1
    );
}

#[test]
fn equal_ham_membership_merge_keeps_the_cancel() {
    let mut cancelled = group_graph();
    cancelled
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    let mut restated = group_graph();
    restated
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    assert_eq!(
        cancelled
            .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap()
            .ham_state,
        restated
            .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap()
            .ham_state
    );

    let mut from_cancel = cancelled.clone();
    from_cancel.merge_from(&restated);
    let mut from_restate = restated.clone();
    from_restate.merge_from(&cancelled);
    for graph in [&from_cancel, &from_restate] {
        let row = graph
            .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap();
        assert_eq!(row.stated, 0);
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
                .allowed
        );
    }
}

#[test]
fn equal_ham_object_set_merge_keeps_privilege_down() {
    let mut cleared = group_graph();
    cleared
        .clear_object_set("0xalice", "doc", &signer("0xalice"))
        .unwrap();
    let mut renamed = group_graph();
    renamed
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/labs",
            &signer("0xalice"),
        )
        .unwrap();
    assert_eq!(
        cleared.object_set("doc").unwrap().ham_state,
        renamed.object_set("doc").unwrap().ham_state
    );
    assert_eq!(cleared.object_set("doc").unwrap().stated, 0);
    assert_eq!(renamed.object_set("doc").unwrap().stated, 1);

    let mut from_clear = cleared.clone();
    from_clear.merge_from(&renamed);
    let mut from_rename = renamed.clone();
    from_rename.merge_from(&cleared);
    for graph in [&from_clear, &from_rename] {
        assert_eq!(graph.object_set("doc").unwrap().stated, 0);
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
                .allowed
        );
    }
}

#[test]
fn merge_drops_an_object_set_from_a_conflicting_object_owner() {
    let mut alice = new_graph();
    alice.put_object("doc", "0xalice");
    alice
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    state_both(
        &mut alice,
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
    );

    let mut mallory = new_graph();
    mallory.put_object("doc", "0xmallory");
    mallory
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    mallory
        .name_object_set(
            "0xmallory",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xmallory"),
        )
        .unwrap();

    alice.merge_from(&mallory);
    assert_eq!(alice.owner_of("doc"), Some("0xalice"));
    assert!(alice.object_set("doc").is_none());
    assert!(
        !alice
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
fn clear_of_an_unseen_object_set_tombstones_the_edge() {
    let mut clearer = new_graph();
    clearer.put_object("doc", "0xalice");
    clearer
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    state_both(
        &mut clearer,
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
    );
    clearer
        .clear_object_set("0xalice", "doc", &signer("0xalice"))
        .unwrap();
    let tombstone = clearer.object_set("doc").unwrap();
    assert_eq!(tombstone.stated, 0);
    assert_eq!(tombstone.ham_state, 1);

    let mut peer = new_graph();
    peer.put_object("doc", "0xalice");
    peer.record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    peer.name_object_set(
        "0xalice",
        "doc",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        &signer("0xalice"),
    )
    .unwrap();
    state_both(&mut peer, GroupPredicate::SameGroup, "0xalice/ops", "0xbob");
    assert_eq!(peer.object_set("doc").unwrap().stated, 1);
    assert_eq!(peer.object_set("doc").unwrap().ham_state, 1);

    clearer.merge_from(&peer);
    assert_eq!(clearer.object_set("doc").unwrap().stated, 0);
    let denied = clearer.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(1),
        None,
        None,
    );
    assert!(!denied.allowed);
    assert_eq!(denied.reason, MESH_REASON_CANCELLED);

    peer.merge_from(&clearer);
    assert_eq!(peer.object_set("doc").unwrap().stated, 0);
    assert!(
        !peer
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
fn one_party_cannot_advance_a_stale_live_membership_past_a_cancel() {
    let mut owner_peer = group_graph();
    owner_peer
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    let mut member_peer = group_graph();
    member_peer
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    member_peer
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    assert_eq!(
        member_peer
            .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap()
            .stated,
        1
    );
    assert!(
        member_peer
            .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap()
            .ham_state
            > owner_peer
                .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
                .unwrap()
                .ham_state
    );

    let mut from_owner = owner_peer.clone();
    from_owner.merge_from(&member_peer);
    let mut from_member = member_peer.clone();
    from_member.merge_from(&owner_peer);
    for graph in [&from_owner, &from_member] {
        let row = graph
            .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap();
        assert_eq!(row.stated, 0);
        let denied = graph.check_group_see(
            GroupPredicate::SameGroup,
            "doc",
            "0xbob",
            Timestamp(1),
            None,
            None,
        );
        assert!(!denied.allowed);
        assert_eq!(denied.reason, MESH_REASON_CANCELLED);
    }
}

#[test]
fn cancel_of_an_unseen_membership_dominates_a_higher_restate() {
    let mut clearer = new_graph();
    clearer.put_object("doc", "0xalice");
    clearer
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    clearer
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    clearer
        .cancel_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();

    let mut peer = new_graph();
    peer.put_object("doc", "0xalice");
    peer.record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    peer.name_object_set(
        "0xalice",
        "doc",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        &signer("0xalice"),
    )
    .unwrap();
    state_both(&mut peer, GroupPredicate::SameGroup, "0xalice/ops", "0xbob");
    peer.state_membership(
        "0xbob",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
        &signer("0xbob"),
    )
    .unwrap();
    peer.state_membership(
        "0xbob",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
        &signer("0xbob"),
    )
    .unwrap();
    peer.state_membership(
        "0xalice",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
        &signer("0xalice"),
    )
    .unwrap();
    peer.state_membership(
        "0xalice",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
        &signer("0xalice"),
    )
    .unwrap();
    assert_eq!(
        peer.membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap()
            .stated,
        1
    );
    assert!(
        peer.membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap()
            .ham_state
            > clearer
                .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
                .unwrap()
                .ham_state
    );

    let mut from_clear = clearer.clone();
    from_clear.merge_from(&peer);
    let mut from_peer = peer.clone();
    from_peer.merge_from(&clearer);
    for graph in [&from_clear, &from_peer] {
        assert_eq!(
            graph
                .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
                .unwrap()
                .stated,
            0
        );
        let denied = graph.check_group_see(
            GroupPredicate::SameGroup,
            "doc",
            "0xbob",
            Timestamp(1),
            None,
            None,
        );
        assert!(!denied.allowed);
        assert_eq!(denied.reason, MESH_REASON_CANCELLED);
    }

    from_clear
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    from_clear
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    assert!(
        from_clear
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
fn a_predictable_set_id_is_not_owned_by_the_first_peer() {
    let mut early = new_graph();
    assert_eq!(
        early.record_set_owner("0xmallory", GroupPredicate::SameGroup, "ops"),
        Err(GunError::UnboundSetOwner)
    );

    let mut verifier = new_graph();
    verifier.put_object("doc", "0xalice");
    let mut mallory = new_graph();
    mallory
        .record_set_owner("0xmallory", GroupPredicate::SameGroup, "0xmallory/ops")
        .unwrap();
    mallory
        .state_membership(
            "0xmallory",
            GroupPredicate::SameGroup,
            "0xmallory/ops",
            "0xmallory",
            &signer("0xmallory"),
        )
        .unwrap();
    verifier.merge_from(&mallory);
    verifier
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    verifier
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    assert_eq!(
        verifier.owner_of_set(GroupPredicate::SameGroup, "0xalice/ops"),
        Some("0xalice")
    );
    assert_eq!(
        verifier.owner_of_set(GroupPredicate::SameGroup, "ops"),
        None
    );
    assert!(
        !verifier
            .check_group_see(
                GroupPredicate::SameGroup,
                "doc",
                "0xmallory",
                Timestamp(1),
                None,
                None,
            )
            .allowed
    );
}

#[test]
fn merge_canonicalizes_object_keys_before_taking_an_object_set() {
    let mut alice = new_graph();
    alice.put_object("foo/bar", "0xalice");
    alice
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    state_both(
        &mut alice,
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
    );

    let mut mallory = new_graph();
    mallory.put_object("foo_bar", "0xmallory");
    mallory
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    mallory
        .name_object_set(
            "0xmallory",
            "foo_bar",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xmallory"),
        )
        .unwrap();

    alice.merge_from(&mallory);
    assert_eq!(alice.owner_of("foo/bar"), Some("0xalice"));
    assert_eq!(alice.owner_of("foo_bar"), Some("0xmallory"));
    assert!(alice.object_set("foo/bar").is_none());
    assert!(
        !alice
            .check_group_see(
                GroupPredicate::SameGroup,
                "foo/bar",
                "0xbob",
                Timestamp(1),
                None,
                None,
            )
            .allowed
    );
}

#[test]
fn merge_drops_a_see_grant_from_a_conflicting_object_owner() {
    let mut alice = new_graph();
    alice.put_object("doc", "0xalice");
    let mut mallory = new_graph();
    mallory.put_object("doc", "0xmallory");
    mallory
        .state_see_grant("0xmallory", MeshSeeGrant::live("doc", "0xbob", 0, 80))
        .unwrap();
    alice.merge_from(&mallory);
    assert_eq!(alice.owner_of("doc"), Some("0xalice"));
    assert!(
        !alice
            .check_see("doc", "0xbob", Timestamp(1), None, None)
            .allowed
    );
    let ordinary = alice.check_group_presentation(
        None,
        "doc",
        "0xbob",
        &payload(1, 0, 80),
        Timestamp(1),
        None,
        None,
    );
    assert!(!ordinary.allowed);
}

#[test]
fn a_stated_zero_object_set_does_not_block_an_ordinary_see_grant() {
    let mut graph = group_graph();
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("doc", "0xcarol", 0, 80))
        .unwrap();
    graph
        .clear_object_set("0xalice", "doc", &signer("0xalice"))
        .unwrap();
    assert_eq!(graph.object_set("doc").unwrap().stated, 0);
    let ordinary = graph.check_group_presentation(
        None,
        "doc",
        "0xcarol",
        &payload(1, 0, 80),
        Timestamp(1),
        None,
        None,
    );
    assert!(ordinary.allowed);
    assert_eq!(ordinary.reason, MESH_REASON_DELEGATE);
}

#[test]
fn unseen_object_set_clear_dominates_a_remote_edge_advanced_twice() {
    let mut peer = group_graph();
    peer.name_object_set(
        "0xalice",
        "doc",
        GroupPredicate::SameGroup,
        "0xalice/labs",
        &signer("0xalice"),
    )
    .unwrap();
    peer.name_object_set(
        "0xalice",
        "doc",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        &signer("0xalice"),
    )
    .unwrap();
    let remote = peer.object_set("doc").unwrap();
    assert_eq!(remote.stated, 1);
    assert!(remote.ham_state >= 3);

    let mut clearer = new_graph();
    clearer.put_object("doc", "0xalice");
    clearer
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    state_both(
        &mut clearer,
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
    );
    clearer
        .clear_object_set("0xalice", "doc", &signer("0xalice"))
        .unwrap();
    let tombstone = clearer.object_set("doc").unwrap();
    assert_eq!(tombstone.stated, 0);
    assert!(tombstone.ham_state < remote.ham_state);

    let mut from_clear = clearer.clone();
    from_clear.merge_from(&peer);
    let mut from_peer = peer.clone();
    from_peer.merge_from(&clearer);
    for graph in [&from_clear, &from_peer] {
        assert_eq!(graph.object_set("doc").unwrap().stated, 0);
        let denied = graph.check_group_see(
            GroupPredicate::SameGroup,
            "doc",
            "0xbob",
            Timestamp(1),
            None,
            None,
        );
        assert!(!denied.allowed);
        assert_eq!(denied.reason, MESH_REASON_CANCELLED);
    }

    from_clear
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    assert_eq!(from_clear.object_set("doc").unwrap().stated, 1);
    assert!(
        from_clear
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
fn concurrent_membership_cancels_stay_cancelled_in_both_directions() {
    let mut left = group_graph();
    let mut right = group_graph();
    left.cancel_membership(
        "0xalice",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
        &signer("0xalice"),
    )
    .unwrap();
    right
        .cancel_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    left.state_membership(
        "0xbob",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
        &signer("0xbob"),
    )
    .unwrap();
    left.state_membership(
        "0xalice",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
        &signer("0xalice"),
    )
    .unwrap();
    assert_eq!(
        left.membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
            .unwrap()
            .stated,
        1
    );

    let mut from_left = left.clone();
    from_left.merge_from(&right);
    let mut from_right = right.clone();
    from_right.merge_from(&left);
    for graph in [&from_left, &from_right] {
        assert_eq!(
            graph
                .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
                .unwrap()
                .stated,
            0
        );
        let denied = graph.check_group_see(
            GroupPredicate::SameGroup,
            "doc",
            "0xbob",
            Timestamp(1),
            None,
            None,
        );
        assert!(!denied.allowed);
        assert_eq!(denied.reason, MESH_REASON_CANCELLED);
    }

    from_left
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xbob"),
        )
        .unwrap();
    from_left
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &signer("0xalice"),
        )
        .unwrap();
    assert!(
        from_left
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
fn concurrent_object_set_clears_stay_cleared_in_both_directions() {
    let mut left = group_graph();
    let mut right = group_graph();
    left.clear_object_set("0xalice", "doc", &signer("0xalice"))
        .unwrap();
    right
        .clear_object_set("0xalice", "doc", &signer("0xalice"))
        .unwrap();
    left.name_object_set(
        "0xalice",
        "doc",
        GroupPredicate::SameGroup,
        "0xalice/ops",
        &signer("0xalice"),
    )
    .unwrap();
    assert_eq!(left.object_set("doc").unwrap().stated, 1);

    let mut from_left = left.clone();
    from_left.merge_from(&right);
    let mut from_right = right.clone();
    from_right.merge_from(&left);
    for graph in [&from_left, &from_right] {
        assert_eq!(graph.object_set("doc").unwrap().stated, 0);
        let denied = graph.check_group_see(
            GroupPredicate::SameGroup,
            "doc",
            "0xbob",
            Timestamp(1),
            None,
            None,
        );
        assert!(!denied.allowed);
        assert_eq!(denied.reason, MESH_REASON_CANCELLED);
    }

    from_left
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    assert_eq!(from_left.object_set("doc").unwrap().stated, 1);
    assert!(
        from_left
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
fn replacing_the_object_owner_drops_the_previous_edge() {
    let mut graph = group_graph();
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
    graph.put_object("doc", "s3rch/users/0xalice");
    assert!(graph.object_set("doc").is_some());
    graph.put_object("doc", "0xcarol");
    assert_eq!(graph.owner_of("doc"), Some("0xcarol"));
    assert!(graph.object_set("doc").is_none());
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
            .allowed
    );
}

#[test]
fn colliding_set_ids_are_rejected_and_check_uses_the_canonical_id() {
    let mut graph = new_graph();
    assert_eq!(
        graph.record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops/core"),
        Err(GunError::UnboundSetOwner)
    );
    assert_eq!(
        graph.record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops_core"),
        Err(GunError::UnboundSetOwner)
    );
    graph.put_object("doc", "0xalice");
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    state_both(
        &mut graph,
        GroupPredicate::SameGroup,
        "0xalice/ops",
        "0xbob",
    );
    let row = graph
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .unwrap();
    assert_eq!(row.set_id, "0xalice/ops");
    let soul = graph
        .membership_row_soul(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .unwrap();
    assert!(soul.contains("/0xalice~6ops/"));
    assert!(!soul.contains("ops/core"));
    assert!(!soul.contains("ops_core"));
}

#[test]
fn merge_rejects_rows_that_do_not_verify_under_the_enrolled_key() {
    let sender = group_graph();
    let mut receiver = MeshSeeGraph::new();
    receiver.put_object("doc", "0xalice");
    receiver
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    receiver
        .enroll_signer("0xalice", signer("not-alice").verify_key())
        .unwrap();
    receiver
        .enroll_signer("0xbob", signer("0xbob").verify_key())
        .unwrap();
    receiver.merge_from(&sender);
    assert!(receiver.object_set("doc").is_none());
    let kept = receiver
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .unwrap();
    assert_eq!(kept.stated, 0);
    assert!(
        !receiver
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

    let mut unsigned = MeshSeeGraph::new();
    unsigned.put_object("doc", "0xalice");
    unsigned
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    unsigned.merge_from(&sender);
    assert!(unsigned.object_set("doc").is_none());
    assert!(unsigned
        .membership(GroupPredicate::SameGroup, "0xalice/ops", "0xbob")
        .is_none());
}

#[test]
fn check_fails_closed_when_the_set_owner_record_is_absent() {
    let mut graph = new_graph();
    graph.put_object("doc", "0xalice");
    graph
        .name_object_set(
            "0xalice",
            "doc",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &signer("0xalice"),
        )
        .unwrap();
    let denied = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(1),
        None,
        None,
    );
    assert!(!denied.allowed);
    assert_eq!(denied.reason, MESH_REASON_MISSING);
}
