//! Shared post-grant vectors. The TypeScript contract loads the same file.

use sociacl_core::{AttestationChannel, IssuerSecret, Timestamp};
use sociacl_gun::{
    factor_grants, post_grant_signing_bytes, post_soul, GroupPredicate, GunError, GunPostEdge,
    GunSoul, HandoffHint, HopFactor, MeshPostGrant, MeshSeeGrant, MeshSeeGraph, MESH_REASON_ACL,
    MESH_REASON_CANCELLED, MESH_REASON_META, MESH_REASON_MISSING, MESH_REASON_OWNER,
    MESH_REASON_POST, MESH_REASON_URL_LEAF, POST_GRANT_DOMAIN, POST_GRANT_SCOPE,
};

const VECTORS: &str = include_str!("../../../vectors/mesh/post-grant.json");

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    domain: String,
    scope: String,
    factors: Vec<String>,
    signing: Vec<SigningCase>,
    graphs: Vec<GraphCase>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningCase {
    name: String,
    object: String,
    accessor: String,
    stated: u8,
    from: u64,
    until: u64,
    ham_state: u64,
    hex: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphCase {
    name: String,
    object: String,
    owner: String,
    accessor: String,
    now: u64,
    #[serde(default)]
    hint: bool,
    #[serde(default)]
    hop: bool,
    see: Option<Window>,
    post: Option<Window>,
    merge: Option<Vec<MergeEdge>>,
    #[serde(default)]
    either_order: bool,
    #[serde(default)]
    write_object: Option<String>,
    #[serde(default)]
    write_accessor: Option<String>,
    #[serde(default)]
    check_object: Option<String>,
    #[serde(default)]
    check_accessor: Option<String>,
    #[serde(default)]
    cancel_see_object: Option<String>,
    #[serde(default)]
    cancel_see_accessor: Option<String>,
    #[serde(default)]
    reassign_object: Option<String>,
    #[serde(default)]
    reassign_owner: Option<String>,
    #[serde(default)]
    presented_object: Option<String>,
    #[serde(default)]
    presented_accessor: Option<String>,
    #[serde(default)]
    see_grant_allowed: Option<bool>,
    allowed: bool,
    reason: String,
    winner: Option<Window>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Window {
    from: u64,
    until: u64,
    stated: u8,
}

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MergeEdge {
    from: u64,
    until: u64,
    stated: u8,
    ham_state: u64,
}

fn signer(name: &str) -> IssuerSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in name.as_bytes().iter().enumerate() {
        bytes[i % 32] ^= b.wrapping_add((i as u8).wrapping_mul(17));
    }
    bytes[0] ^= name.len() as u8;
    bytes[31] |= 1;
    IssuerSecret::from_bytes(bytes)
}

fn apply_window_see(
    graph: &mut MeshSeeGraph,
    case: &GraphCase,
    window: &Window,
    object: &str,
    accessor: &str,
) {
    graph
        .state_see_grant(
            &case.owner,
            MeshSeeGrant::live(object, accessor, window.from, window.until),
        )
        .unwrap();
    if window.stated == 0 {
        graph
            .unstate_see_grant(&case.owner, accessor, object)
            .unwrap();
    }
}

fn apply_window_post(
    graph: &mut MeshSeeGraph,
    case: &GraphCase,
    window: &Window,
    object: &str,
    accessor: &str,
) {
    graph
        .state_post_grant(
            &case.owner,
            MeshPostGrant::live(object, accessor, window.from, window.until),
        )
        .unwrap();
    if window.stated == 0 {
        graph
            .unstate_post_grant(&case.owner, accessor, object)
            .unwrap();
    }
}

fn apply_merge(graph: &mut MeshSeeGraph, case: &GraphCase, edges: &[MergeEdge]) {
    for edge in edges {
        graph.merge_post_edge(
            GunPostEdge::new(
                &case.owner,
                MeshPostGrant {
                    object: case.object.clone(),
                    accessor: case.accessor.clone(),
                    from: Timestamp(edge.from),
                    until: Timestamp(edge.until),
                    stated: edge.stated,
                },
                edge.ham_state,
            )
            .unwrap(),
        );
    }
}

fn check_case(case: &GraphCase, merge: Option<&[MergeEdge]>) {
    let mut graph = MeshSeeGraph::new();
    let write_object = case.write_object.as_deref().unwrap_or(&case.object);
    let write_accessor = case.write_accessor.as_deref().unwrap_or(&case.accessor);
    let check_object = case.check_object.as_deref().unwrap_or(&case.object);
    let check_accessor = case.check_accessor.as_deref().unwrap_or(&case.accessor);
    graph.put_object(&case.object, &case.owner);
    if let Some(see) = &case.see {
        apply_window_see(&mut graph, case, see, write_object, write_accessor);
    }
    if let Some(post) = &case.post {
        apply_window_post(&mut graph, case, post, write_object, write_accessor);
    }
    if let Some(cancel_object) = &case.cancel_see_object {
        let cancel_accessor = case
            .cancel_see_accessor
            .as_deref()
            .unwrap_or(write_accessor);
        graph
            .unstate_see_grant(&case.owner, cancel_accessor, cancel_object)
            .unwrap();
    }
    if let Some(reassign_object) = &case.reassign_object {
        graph.put_object(
            reassign_object,
            case.reassign_owner.as_deref().unwrap_or(&case.owner),
        );
    }
    if let Some(edges) = merge {
        apply_merge(&mut graph, case, edges);
    }
    let hint = case
        .hint
        .then(|| HandoffHint::parse(check_accessor, check_object, Some("see"), None).unwrap());
    let hop = case.hop.then(|| HopFactor::Structured {
        channel: AttestationChannel::ConventionBadge,
        attestation_bytes: None,
        share_token: None,
    });
    let got = graph.check_post(
        check_object,
        check_accessor,
        Timestamp(case.now),
        hint.as_ref(),
        hop.as_ref(),
    );
    assert_eq!(got.allowed, case.allowed, "{}", case.name);
    assert_eq!(got.reason, case.reason, "{}", case.name);
    let see = graph.check_see(
        check_object,
        check_accessor,
        Timestamp(case.now),
        hint.as_ref(),
        hop.as_ref(),
    );
    if got.allowed {
        assert!(see.allowed, "{} check_see", case.name);
    }
    if let Some(presented_accessor) = &case.presented_accessor {
        let presented_object = case.presented_object.as_deref().unwrap_or(write_object);
        let window = case.see.as_ref().expect("presented grant needs see");
        let grant = MeshSeeGrant::live(
            presented_object,
            presented_accessor,
            window.from,
            window.until,
        );
        let grant_check = graph.check_see_grant(
            &grant,
            check_object,
            check_accessor,
            Timestamp(case.now),
            hint.as_ref(),
            hop.as_ref(),
        );
        assert_eq!(
            grant_check.allowed,
            case.see_grant_allowed.unwrap_or(false),
            "{} check_see_grant",
            case.name
        );
    }
    assert!(!got.hint_is_grant(), "{}", case.name);
    assert!(!got.hop_is_grant(), "{}", case.name);
    assert!(!got.wrap_is_grant(), "{}", case.name);
    assert!(!got.inbox_is_grant(), "{}", case.name);
    if case.post.is_none() && merge.is_none() {
        assert!(
            graph.post_edge(&case.object, &case.accessor).is_none(),
            "{} must not invent a post row",
            case.name
        );
    }
    if let Some(winner) = &case.winner {
        let edge = graph
            .post_edge(&case.object, &case.accessor)
            .unwrap_or_else(|| panic!("{} missing post row", case.name));
        assert_eq!(edge.grant.from.0, winner.from, "{}", case.name);
        assert_eq!(edge.grant.until.0, winner.until, "{}", case.name);
        assert_eq!(edge.grant.stated, winner.stated, "{}", case.name);
    }
}

#[test]
fn post_grant_vectors_match_the_shared_fixture() {
    let fixture: Fixture = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(fixture.domain, POST_GRANT_DOMAIN);
    assert_eq!(fixture.scope, POST_GRANT_SCOPE);
    for kind in &fixture.factors {
        assert!(!factor_grants(kind), "{kind}");
    }
    for row in &fixture.signing {
        let grant = MeshPostGrant {
            object: row.object.clone(),
            accessor: row.accessor.clone(),
            from: Timestamp(row.from),
            until: Timestamp(row.until),
            stated: row.stated,
        };
        let bytes = post_grant_signing_bytes(&grant, row.ham_state).unwrap();
        assert_eq!(hex(&bytes), row.hex, "{}", row.name);
        assert!(
            !String::from_utf8_lossy(&bytes).contains("0xalice"),
            "{} signing bytes omit the owner",
            row.name
        );
    }
    for case in &fixture.graphs {
        check_case(case, case.merge.as_deref());
        if case.either_order {
            let mut reversed = case.merge.clone().unwrap();
            reversed.reverse();
            check_case(case, Some(&reversed));
        }
    }
}

#[test]
fn post_row_is_not_a_see_row() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    graph
        .state_post_grant("0xalice", MeshPostGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    assert!(graph.grant_edge("room:alpha", "0xbob").is_none());
    assert!(
        !graph
            .check_see("room:alpha", "0xbob", Timestamp(1), None, None)
            .allowed
    );
    let soul = post_soul("0xalice", "room:alpha", "0xbob").unwrap();
    assert_eq!(soul.as_str(), "s3rch/acl/0xalice/post/room:alpha/0xbob");
    let parsed = GunSoul::parse(soul.as_str()).unwrap();
    assert!(parsed.is_s3rch_acl());
    assert!(!parsed.is_s3rch_acl_grant());
    assert_ne!(
        soul.as_str(),
        sociacl_gun::grant_soul("0xalice", "room:alpha", "0xbob")
            .unwrap()
            .as_str()
    );
}

#[test]
fn foreign_owner_cannot_write_a_post_grant() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    assert_eq!(
        graph
            .state_post_grant("0xbob", MeshPostGrant::live("room:alpha", "0xbob", 0, 80))
            .unwrap_err(),
        GunError::AclOwnerOnly
    );
}

#[test]
fn cancel_then_restate_and_a_stale_peer_does_not_restore() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    graph
        .state_post_grant("0xalice", MeshPostGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    assert!(
        graph
            .check_post("room:alpha", "0xbob", Timestamp(1), None, None)
            .allowed
    );
    let stale = graph.clone();
    graph
        .unstate_post_grant("0xalice", "0xbob", "room:alpha")
        .unwrap();
    let denied = graph.check_post("room:alpha", "0xbob", Timestamp(1), None, None);
    assert!(!denied.allowed);
    assert_eq!(denied.reason, MESH_REASON_CANCELLED);
    graph.merge_post_edge(stale.post_edge("room:alpha", "0xbob").unwrap().clone());
    assert_eq!(
        graph
            .check_post("room:alpha", "0xbob", Timestamp(1), None, None)
            .reason,
        MESH_REASON_CANCELLED
    );
    graph
        .state_post_grant("0xalice", MeshPostGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    let again = graph.check_post("room:alpha", "0xbob", Timestamp(1), None, None);
    assert!(again.allowed);
    assert_eq!(again.reason, MESH_REASON_POST);
}

#[test]
fn friend_hop_and_closed_objects_do_not_grant_post() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    graph.state_friend("0xalice", "0xbob");
    let hint = HandoffHint::parse("0xbob", "room:alpha", Some("see"), None).unwrap();
    let hop = HopFactor::Structured {
        channel: AttestationChannel::ConventionBadge,
        attestation_bytes: Some(b"not-a-grant".to_vec()),
        share_token: None,
    };
    let denied = graph.check_post("room:alpha", "0xbob", Timestamp(1), Some(&hint), Some(&hop));
    assert!(!denied.allowed);
    assert_eq!(denied.reason, MESH_REASON_MISSING);
    assert!(!denied.hop_factored());
    assert_eq!(
        graph
            .check_post("s3rch/meta", "0xalice", Timestamp(1), None, None)
            .reason,
        MESH_REASON_META
    );
    assert_eq!(
        graph
            .check_post(
                "s3rch/acl/0xalice/post/room:alpha/0xbob",
                "0xalice",
                Timestamp(1),
                None,
                None
            )
            .reason,
        MESH_REASON_ACL
    );
    assert_eq!(
        graph
            .check_post(
                "https://gi.rss3.io/decentralized/0xalice",
                "0xalice",
                Timestamp(1),
                None,
                None
            )
            .reason,
        MESH_REASON_URL_LEAF
    );
}

#[test]
fn group_see_does_not_satisfy_check_post() {
    let mut graph = MeshSeeGraph::new();
    let alice = signer("0xalice");
    let bob = signer("0xbob");
    graph.enroll_signer("0xalice", alice.verify_key()).unwrap();
    graph.enroll_signer("0xbob", bob.verify_key()).unwrap();
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
            &alice,
        )
        .unwrap();
    graph
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &bob,
        )
        .unwrap();
    graph
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &alice,
        )
        .unwrap();
    graph
        .state_post_grant("0xalice", MeshPostGrant::live("doc", "0xbob", 0, 80))
        .unwrap();
    let grouped = graph.check_group_see(
        GroupPredicate::SameGroup,
        "doc",
        "0xbob",
        Timestamp(1),
        None,
        None,
    );
    assert!(grouped.allowed);
    let post = graph.check_post("doc", "0xbob", Timestamp(1), None, None);
    assert!(!post.allowed);
    assert_eq!(post.reason, MESH_REASON_MISSING);
    let owner = graph.check_post("doc", "0xalice", Timestamp(1), None, None);
    assert!(owner.allowed);
    assert_eq!(owner.reason, MESH_REASON_OWNER);
}

#[test]
fn post_grant_on_a_feed_id_matches_the_item_soul() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("rss3:act/1#x", "0xalice");
    graph
        .state_see_grant(
            "0xalice",
            MeshSeeGrant::live("rss3:act/1#x", "0xbob", 0, 80),
        )
        .unwrap();
    graph
        .state_post_grant(
            "0xalice",
            MeshPostGrant::live("rss3:act/1#x", "0xbob", 0, 80),
        )
        .unwrap();
    let got = graph.check_post("rss3:act/1#x", "0xbob", Timestamp(1), None, None);
    assert!(got.allowed, "{}", got.reason);
    assert_eq!(got.reason, MESH_REASON_POST);
}

#[test]
fn check_post_uses_the_current_owners_rows() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    graph
        .state_post_grant(
            "0xalice",
            MeshPostGrant::live("room:alpha", "s3rch/users/0xbob", 0, 80),
        )
        .unwrap();
    graph.put_object("room:alpha", "0xcarol");
    graph
        .state_see_grant("0xcarol", MeshSeeGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    graph
        .state_post_grant("0xcarol", MeshPostGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    let edge = graph.post_edge("room:alpha", "s3rch/users/0xbob").unwrap();
    assert_eq!(edge.owner, "0xcarol");
    let got = graph.check_post("room:alpha", "s3rch/users/0xbob", Timestamp(10), None, None);
    assert!(got.allowed, "{}", got.reason);
    assert_eq!(got.reason, MESH_REASON_POST);
}

#[test]
fn an_out_of_range_post_integer_does_not_restore_a_cancel() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    graph
        .state_post_grant("0xalice", MeshPostGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    graph
        .unstate_post_grant("0xalice", "0xbob", "room:alpha")
        .unwrap();
    graph.merge_post_edge(
        GunPostEdge::new(
            "0xalice",
            MeshPostGrant::live("room:alpha", "0xbob", 0, 80),
            u64::MAX,
        )
        .unwrap(),
    );
    let past_safe = (1_u64 << 53) - 1;
    graph.merge_post_edge(
        GunPostEdge::new(
            "0xalice",
            MeshPostGrant {
                object: "room:alpha".into(),
                accessor: "0xbob".into(),
                from: Timestamp(past_safe + 1),
                until: Timestamp(past_safe + 2),
                stated: 1,
            },
            9,
        )
        .unwrap(),
    );
    let got = graph.check_post("room:alpha", "0xbob", Timestamp(10), None, None);
    assert!(!got.allowed, "{}", got.reason);
    assert_eq!(got.reason, MESH_REASON_CANCELLED);
}

#[test]
fn a_raw_id_and_its_item_soul_share_one_post_row() {
    let mut graph = MeshSeeGraph::new();
    let raw = "room:alpha";
    let soul = "s3rch/items/room:alpha";
    graph.put_object(raw, "0xalice");
    assert_eq!(graph.owner_of(soul), Some("0xalice"));
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live(raw, "0xbob", 0, 80))
        .unwrap();
    graph
        .state_post_grant("0xalice", MeshPostGrant::live(raw, "0xbob", 0, 80))
        .unwrap();
    graph
        .state_post_grant(
            "0xalice",
            MeshPostGrant::live(soul, "s3rch/users/0xbob", 0, 80),
        )
        .unwrap();
    graph.unstate_post_grant("0xalice", "0xbob", soul).unwrap();
    for object in [raw, soul] {
        let got = graph.check_post(object, "s3rch/users/0xbob", Timestamp(10), None, None);
        assert!(!got.allowed, "{object} {}", got.reason);
        assert_eq!(got.reason, MESH_REASON_CANCELLED, "{object}");
    }
    assert!(graph.post_edge(raw, "0xbob").unwrap().grant.stated != 1);
    assert!(graph.post_edge(soul, "s3rch/users/0xbob").is_some());
}

#[test]
fn a_cancel_at_the_ham_ceiling_stays_representable() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    let max = (1_u64 << 53) - 1;
    graph.merge_post_edge(
        GunPostEdge::new(
            "0xalice",
            MeshPostGrant::live("room:alpha", "0xbob", 0, 80),
            max,
        )
        .unwrap(),
    );
    graph
        .unstate_post_grant("0xalice", "0xbob", "room:alpha")
        .unwrap();
    let edge = graph.post_edge("room:alpha", "0xbob").unwrap();
    assert_eq!(edge.ham_state, max);
    assert_ne!(edge.grant.stated, 1);
    let got = graph.check_post("room:alpha", "0xbob", Timestamp(10), None, None);
    assert!(!got.allowed, "{}", got.reason);
    assert_eq!(got.reason, MESH_REASON_CANCELLED);
    graph.merge_post_edge(
        GunPostEdge::new(
            "0xalice",
            MeshPostGrant::live("room:alpha", "0xbob", 0, 80),
            max,
        )
        .unwrap(),
    );
    let again = graph.check_post("room:alpha", "0xbob", Timestamp(10), None, None);
    assert_eq!(again.reason, MESH_REASON_CANCELLED);
    assert_eq!(
        graph.post_edge("room:alpha", "0xbob").unwrap().ham_state,
        max
    );
    let err = graph
        .state_post_grant("0xalice", MeshPostGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap_err();
    assert!(matches!(err, GunError::PostGrantField));
    assert_eq!(
        graph
            .check_post("room:alpha", "0xbob", Timestamp(10), None, None)
            .reason,
        MESH_REASON_CANCELLED
    );
}

#[test]
fn a_post_merge_waits_for_the_current_owner() {
    let mut graph = MeshSeeGraph::new();
    graph.merge_post_edge(
        GunPostEdge::new(
            "0xalice",
            MeshPostGrant::live("room:alpha", "0xbob", 0, 80),
            4,
        )
        .unwrap(),
    );
    graph.put_object("room:alpha", "0xalice");
    graph
        .state_see_grant("0xalice", MeshSeeGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();
    let staged = graph.check_post("room:alpha", "0xbob", Timestamp(10), None, None);
    assert!(!staged.allowed, "{}", staged.reason);
    assert_eq!(staged.reason, MESH_REASON_MISSING);
    graph.merge_post_edge(
        GunPostEdge::new(
            "0xcarol",
            MeshPostGrant::live("room:alpha", "0xbob", 0, 80),
            9,
        )
        .unwrap(),
    );
    assert_eq!(
        graph
            .check_post("room:alpha", "0xbob", Timestamp(10), None, None)
            .reason,
        MESH_REASON_MISSING
    );
    graph.merge_post_edge(
        GunPostEdge::new(
            "0xalice",
            MeshPostGrant::live("room:alpha", "0xbob", 0, 80),
            2,
        )
        .unwrap(),
    );
    assert_eq!(
        graph
            .check_post("room:alpha", "0xbob", Timestamp(10), None, None)
            .reason,
        MESH_REASON_POST
    );
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}
