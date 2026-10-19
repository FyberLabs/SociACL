//! Mesh dest ACL + Social Light hop factor locks.

use crate::legacy::{acl_key, acl_principal_key, acl_soul, encode_key, grant_soul};
use crate::{
    accept_hop, add_claim, add_item, add_wallet, apply_see_grant, cancel, check, check_see,
    check_see_hop, decode_hop, has_held_claim_prefix, FeedItem, FeedSource, GunAclEdge, GunError,
    GunNode, GunSoul, GunUserNode, HandoffHint, HopFactor, IdentitySeeGrant, MeshSeeGrant,
    MeshSeeGraph, HELD_CLAIM_PREFIXES, MESH_REASON_ACL, MESH_REASON_CANCELLED,
    MESH_REASON_DELEGATE, MESH_REASON_META, MESH_REASON_MISSING, MESH_REASON_OWNER,
    MESH_REASON_URL_LEAF, S3RCH_ACL, S3RCH_ROOT, SEE,
};
use sociacl_core::{
    ActionMask, AttestationChannel, EnrollmentKind, HopFrame, IssuerSecret, PredicateId, Timestamp,
    HOP_VERSION,
};

fn sample_feed_item() -> FeedItem {
    FeedItem {
        id: "rss3:act/1#x".into(),
        source: FeedSource::Rss3,
        kind: "social".into(),
        author: "0xalice".into(),
        body: "hello".into(),
        ts: 1,
        permalink: "https://gi.rss3.io/decentralized/0xalice".into(),
        tags: vec!["social".into()],
        provenance: "rss3:gi".into(),
    }
}

fn slhp(channel: AttestationChannel, att: &[u8], token: Option<&str>) -> Vec<u8> {
    HopFrame::accept(
        HOP_VERSION,
        channel,
        att.to_vec(),
        token.map(str::to_string),
    )
    .unwrap()
    .encode()
}

#[test]
fn dest_acl_soul_does_not_fork_items_or_users() {
    assert_eq!(acl_key("rss3:act/1#x"), "rss3:act~61~2x");
    assert_eq!(
        acl_key("s3rch/items/rss3:act/1_x"),
        "s3rch~6items~6rss3:act~61_x"
    );
    assert_eq!(acl_principal_key("0xalice").as_deref(), Some("0xalice"));
    assert_eq!(
        acl_principal_key("s3rch/users/0xalice").as_deref(),
        Some("0xalice")
    );
    assert_eq!(
        grant_soul("0xalice", "rss3:act/1#x", "0xbob")
            .unwrap()
            .as_str(),
        "s3rch/acl/0xalice/rss3:act~61~2x/0xbob"
    );
    assert_eq!(
        acl_soul("s3rch/users/0xalice").unwrap().as_str(),
        "s3rch/acl/0xalice"
    );

    let soul = GunSoul::s3rch_acl_grant("0xalice", "rss3:act/1#x", "0xbob");
    assert!(soul.is_s3rch_acl());
    assert!(soul.is_s3rch_acl_grant());
    assert_eq!(soul.segments()[0], S3RCH_ROOT);
    assert_eq!(soul.segments()[1], S3RCH_ACL);
    assert_eq!(soul.segments().len(), 5);

    assert!(!soul.is_s3rch_item());
    assert!(!soul.is_s3rch_user());
    assert_eq!(
        GunSoul::s3rch_item("rss3:act/1#x").as_node_id().as_str(),
        "s3rch/items/rss3:act/1~2x"
    );
    assert_eq!(
        GunSoul::s3rch_user("0xalice").as_node_id().as_str(),
        "s3rch/users/0xalice"
    );
    assert_eq!(encode_key("rss3:act/1#x"), "rss3:act/1~2x");
}

#[test]
fn held_claim_id_is_the_claim_id_itself() {
    let claims = [
        "ens:alice.eth",
        "unstoppable:alice.crypto",
        "fc:alice",
        "lens:alice",
        "rss3:0xalice",
    ];
    assert_eq!(HELD_CLAIM_PREFIXES.len(), claims.len());
    let user = GunUserNode {
        id: "0xalice".into(),
        indicators: claims.iter().map(|s| (*s).to_string()).collect(),
        provenance: "overlay".into(),
        ts: 1,
    };
    assert_eq!(user.as_node_id().as_str(), "s3rch/users/0xalice");
    assert_eq!(user.linked_claim_ids(), &claims.map(str::to_string));

    for claim in claims {
        assert!(has_held_claim_prefix(claim), "{claim}");
        let node = GunNode::claim(claim);
        assert_eq!(
            node.as_node_id().as_str(),
            claim,
            "claim id is the object id"
        );
        assert!(
            !node.as_node_id().as_str().contains("/claims/"),
            "do not invent s3rch/users/<wallet>/claims/"
        );
        assert_eq!(
            grant_soul("0xalice", claim, "0xbob")
                .unwrap()
                .as_str()
                .matches('/')
                .count(),
            4,
            "dest ACL stays five segments"
        );
    }
}

#[test]
fn mesh_check_treats_held_claims_like_feed_items() {
    let mut graph = MeshSeeGraph::new();
    let item = sample_feed_item();
    let item_soul = item.as_node_id().unwrap();
    graph.group.put_object(item_soul.as_str(), "0xalice");

    let claims = [
        "ens:alice.eth",
        "unstoppable:alice.crypto",
        "fc:alice",
        "lens:alice",
        "rss3:0xalice",
    ];
    for claim in claims {
        graph.group.put_object(claim, "0xalice");
    }

    let now = Timestamp(10);
    graph
        .group
        .state_see_grant(
            "0xalice",
            MeshSeeGrant::live(item_soul.as_str(), "0xbob", 0, 80),
        )
        .unwrap();
    for claim in claims {
        graph
            .group
            .state_see_grant("0xalice", MeshSeeGrant::live(claim, "0xbob", 0, 80))
            .unwrap();
    }

    let feed = graph
        .group
        .check_see_label(item_soul.as_str(), "0xbob", now, None, None);
    assert!(feed.allowed);
    assert_eq!(feed.reason, MESH_REASON_DELEGATE);

    for claim in claims {
        let see = graph.group.check_see_label(claim, "0xbob", now, None, None);
        assert!(see.allowed, "{claim} mesh see");
        assert_eq!(see.reason, feed.reason, "{claim} same Check path as feed");
        assert!(!see.hop_is_grant());
        assert!(
            !graph
                .group
                .has_object(&format!("s3rch/users/0xalice/claims/{claim}")),
            "{claim} is not nested under users/…/claims/"
        );
        assert!(
            !graph
                .group
                .has_object(&format!("s3rch/items/{}", encode_key(claim))),
            "{claim} must not rewrite into an item soul"
        );
    }

    graph
        .group
        .unstate_see_grant("0xalice", "0xbob", "ens:alice.eth")
        .unwrap();
    assert!(
        !graph
            .group
            .check_see_label("ens:alice.eth", "0xbob", now, None, None)
            .allowed
    );
    assert!(
        graph
            .group
            .check_see_label(item_soul.as_str(), "0xbob", now, None, None)
            .allowed,
        "cancel one claim does not drop the feed grant"
    );
}

#[test]
fn overlay_held_claims_stay_off_mesh_until_share() {
    let user = GunUserNode {
        id: "0xalice".into(),
        indicators: vec!["ens:alice.eth".into(), "fc:alice".into()],
        provenance: "overlay".into(),
        ts: 1,
    };
    let mut graph = MeshSeeGraph::new();
    assert!(
        !graph.group.has_object("ens:alice.eth"),
        "overlay indicators are not in-graph until share"
    );
    graph.group.put_object("ens:alice.eth", &user.id);
    assert!(graph.group.has_object("ens:alice.eth"));
    assert_eq!(graph.group.owner_of("ens:alice.eth"), Some("0xalice"));
}

#[test]
fn hop_factors_held_claim_id_the_same_as_a_feed_item() {
    let mut graph = MeshSeeGraph::new();
    let item_soul = sample_feed_item().as_node_id().unwrap();
    graph.group.put_object(item_soul.as_str(), "0xalice");
    graph.group.put_object("ens:alice.eth", "0xalice");
    graph
        .group
        .state_see_grant(
            "0xalice",
            MeshSeeGrant::live(item_soul.as_str(), "0xbob", 0, 80),
        )
        .unwrap();
    graph
        .group
        .state_see_grant(
            "0xalice",
            MeshSeeGrant::live("ens:alice.eth", "0xbob", 0, 80),
        )
        .unwrap();

    let hop = accept_hop(
        decode_hop(&slhp(
            AttestationChannel::ConventionBadge,
            b"opaque-attestation",
            None,
        ))
        .unwrap(),
    );
    let now = Timestamp(1);
    let feed = graph
        .group
        .check_see_label(item_soul.as_str(), "0xbob", now, None, Some(&hop));
    let claim = graph
        .group
        .check_see_label("ens:alice.eth", "0xbob", now, None, Some(&hop));
    assert!(feed.allowed && claim.allowed);
    assert_eq!(feed.reason, claim.reason);
    assert!(feed.hop_factored() && claim.hop_factored());
    assert!(!claim.hop_is_grant());
    assert!(!graph
        .group
        .has_object("s3rch/users/0xalice/claims/ens:alice.eth"));
}

#[test]
fn mesh_grant_allows_gun_shaped_objects() {
    let mut graph = MeshSeeGraph::new();
    let item = sample_feed_item();
    let item_soul = item.as_node_id().unwrap();
    graph.group.put_object(item_soul.as_str(), "0xalice");
    graph.group.put_object("claim-1", "0xalice");
    graph.group.put_object("room:alpha", "0xalice");

    graph
        .group
        .state_see_grant(
            "0xalice",
            MeshSeeGrant::live(item_soul.as_str(), "0xbob", 0, 80),
        )
        .unwrap();
    graph
        .group
        .state_see_grant("0xalice", MeshSeeGrant::live("claim-1", "0xbob", 0, 80))
        .unwrap();
    graph
        .group
        .state_see_grant("0xalice", MeshSeeGrant::live("room:alpha", "0xbob", 0, 80))
        .unwrap();

    let now = Timestamp(10);
    for object in [item_soul.as_str(), "claim-1", "room:alpha"] {
        let owner = graph
            .group
            .check_see_label(object, "0xalice", now, None, None);
        assert!(owner.allowed, "{object} owner");
        assert_eq!(owner.reason, MESH_REASON_OWNER);

        let bob = graph
            .group
            .check_see_label(object, "0xbob", now, None, None);
        assert!(bob.allowed, "{object} mesh grant");
        assert_eq!(bob.reason, MESH_REASON_DELEGATE);
        assert!(!bob.hop_is_grant());
    }

    assert!(
        !graph
            .group
            .check_see_label("room:alpha", "0xcarol", now, None, None)
            .allowed
    );
}

#[test]
fn mine_overlay_stays_off_mesh_until_share() {
    let mut graph = MeshSeeGraph::new();
    let grant = MeshSeeGrant::live("rss3:act/1#x", "0xbob", 0, 80);
    assert_eq!(
        graph.group.state_see_grant("0xalice", grant).unwrap_err(),
        GunError::ObjectNotInGraph
    );
    assert!(
        !graph
            .group
            .check_see_label("rss3:act/1#x", "0xbob", Timestamp(1), None, None)
            .allowed
    );

    graph.group.put_object("rss3:act/1#x", "0xalice");
    graph
        .group
        .state_see_grant(
            "0xalice",
            MeshSeeGrant::live("rss3:act/1#x", "0xbob", 0, 80),
        )
        .unwrap();
    assert!(
        graph
            .group
            .check_see_label("rss3:act/1#x", "0xbob", Timestamp(1), None, None)
            .allowed,
        "share-into-mesh put then dest ACL grant"
    );
}

#[test]
fn cancel_denies_next_check_after_merge() {
    let mut alice_peer = MeshSeeGraph::new();
    let mut bob_peer = MeshSeeGraph::new();
    alice_peer.group.put_object("claim-1", "0xalice");
    bob_peer.group.merge_from(&alice_peer.group);

    alice_peer
        .group
        .state_see_grant("0xalice", MeshSeeGrant::live("claim-1", "0xbob", 0, 80))
        .unwrap();
    assert!(
        !bob_peer
            .group
            .check_see_label("claim-1", "0xbob", Timestamp(1), None, None)
            .allowed,
        "bob has not merged yet"
    );

    bob_peer.group.merge_from(&alice_peer.group);
    let allowed = bob_peer
        .group
        .check_see_label("claim-1", "0xbob", Timestamp(1), None, None);
    assert!(allowed.allowed);
    assert_eq!(allowed.reason, MESH_REASON_DELEGATE);

    alice_peer
        .group
        .unstate_see_grant("0xalice", "0xbob", "claim-1")
        .unwrap();
    bob_peer.group.merge_from(&alice_peer.group);
    let denied = bob_peer
        .group
        .check_see_label("claim-1", "0xbob", Timestamp(1), None, None);
    assert!(
        !denied.allowed,
        "privilege-down after merge; no cached allow"
    );
    assert_eq!(denied.reason, MESH_REASON_CANCELLED);
    assert!(!denied.hint_is_grant());
    assert!(!denied.hop_is_grant());
}

#[test]
fn cancel_is_owner_only() {
    let mut graph = MeshSeeGraph::new();
    graph.group.put_object("claim-1", "0xalice");
    graph
        .group
        .state_see_grant("0xalice", MeshSeeGrant::live("claim-1", "0xbob", 0, 80))
        .unwrap();
    assert_eq!(
        graph
            .group
            .unstate_see_grant("0xbob", "0xbob", "claim-1")
            .unwrap_err(),
        GunError::AclOwnerOnly
    );
    assert!(
        graph
            .group
            .check_see_label("claim-1", "0xbob", Timestamp(1), None, None)
            .allowed
    );
}

#[test]
fn hop_factors_but_does_not_mint() {
    let mut graph = MeshSeeGraph::new();
    graph.group.put_object("claim-1", "0xalice");
    let bytes = slhp(
        AttestationChannel::ConventionBadge,
        b"opaque-attestation",
        Some("booth"),
    );
    let hop = accept_hop(decode_hop(&bytes).unwrap());
    assert!(!hop.is_grant());
    assert_eq!(hop.channel(), Some(AttestationChannel::ConventionBadge));

    let hinted = HandoffHint::parse("0xbob", "claim-1", Some(SEE), None).unwrap();
    let closed =
        graph
            .group
            .check_see_label("claim-1", "0xbob", Timestamp(1), Some(&hinted), Some(&hop));
    assert!(!closed.allowed, "hint+hop fail closed without dest ACL");
    assert!(!closed.hop_is_grant());
    assert!(!closed.hop_factored());

    graph
        .group
        .state_see_grant("0xalice", MeshSeeGrant::live("claim-1", "0xbob", 0, 80))
        .unwrap();
    let factored =
        graph
            .group
            .check_see_label("claim-1", "0xbob", Timestamp(1), Some(&hinted), Some(&hop));
    assert!(factored.allowed);
    assert!(factored.hop_factored(), "hop factors a named grant");
    assert!(!factored.hop_is_grant());
    assert_eq!(factored.reason, MESH_REASON_DELEGATE);
}

#[test]
fn hop_missing_does_not_fail_and_decode_does_not_verify() {
    let mut graph = MeshSeeGraph::new();
    graph.group.put_object("claim-1", "0xalice");
    graph
        .group
        .state_see_grant("0xalice", MeshSeeGrant::live("claim-1", "0xbob", 0, 80))
        .unwrap();
    let missing = graph
        .group
        .check_see_label("claim-1", "0xbob", Timestamp(1), None, None);
    assert!(missing.allowed);
    assert!(missing.hop.is_none());

    let garbage = slhp(AttestationChannel::EnrolledStation, &[0u8; 8], None);
    let decoded = decode_hop(&garbage).unwrap();
    match &decoded {
        HopFactor::Structured {
            attestation_bytes: Some(bytes),
            ..
        } => assert_eq!(bytes, &vec![0u8; 8]),
        other => panic!("expected opaque structured hop, got {other:?}"),
    }
    assert!(!accept_hop(decoded).is_grant());
}

#[test]
fn hopcap_1_friend_of_friend_is_not_see() {
    let mut graph = MeshSeeGraph::new();
    graph.group.put_object("claim-1", "0xalice");
    graph.group.state_friend("0xalice", "0xbob");
    graph.group.state_friend("0xbob", "0xcarol");
    assert!(graph.group.has_friend("0xalice", "0xbob"));

    assert!(
        graph
            .group
            .check_see_label("claim-1", "0xalice", Timestamp(1), None, None)
            .allowed
    );
    assert!(
        !graph
            .group
            .check_see_label("claim-1", "0xbob", Timestamp(1), None, None)
            .allowed,
        "a friend edge is not a see grant"
    );
    assert!(
        !graph
            .group
            .check_see_label("claim-1", "0xcarol", Timestamp(1), None, None)
            .allowed,
        "hopcap 1: no friend-of-friend"
    );
}

#[test]
fn meta_acl_and_url_fail_closed() {
    let mut graph = MeshSeeGraph::new();
    graph.group.put_object("claim-1", "0xalice");
    let now = Timestamp(1);
    assert_eq!(
        graph
            .group
            .check_see_label("s3rch/meta", "0xalice", now, None, None)
            .reason,
        MESH_REASON_META
    );
    assert_eq!(
        graph
            .group
            .check_see_label("s3rch/acl/0xalice", "0xalice", now, None, None)
            .reason,
        MESH_REASON_ACL
    );
    assert_eq!(
        graph
            .group
            .check_see_label(
                "https://gi.rss3.io/decentralized/0xalice",
                "0xalice",
                now,
                None,
                None
            )
            .reason,
        MESH_REASON_URL_LEAF
    );
    assert!(
        !graph
            .group
            .check_see_label("s3rch/meta", "0xalice", now, None, None)
            .allowed
    );
}

#[test]
fn ham_merge_higher_state_wins() {
    let older =
        GunAclEdge::new("0xalice", MeshSeeGrant::live("claim-1", "0xbob", 0, 80), 1).unwrap();
    let newer = GunAclEdge::new(
        "0xalice",
        MeshSeeGrant {
            object: "claim-1".into(),
            accessor: "0xbob".into(),
            from: Timestamp(0),
            until: Timestamp(80),
            stated: 0,
        },
        2,
    )
    .unwrap();
    let merged = older.ham_merge(newer);
    assert_eq!(merged.ham_state, 2);
    assert_eq!(merged.grant.stated, 0);
}

#[test]
fn equal_ham_see_grants_keep_the_narrower_window() {
    let mut wide = MeshSeeGraph::new();
    wide.group.put_object("doc", "0xalice");
    wide.group
        .state_see_grant("0xalice", MeshSeeGrant::live("doc", "0xbob", 0, 100))
        .unwrap();
    let mut narrow = MeshSeeGraph::new();
    narrow.group.put_object("doc", "0xalice");
    narrow
        .group
        .state_see_grant("0xalice", MeshSeeGrant::live("doc", "0xbob", 0, 5))
        .unwrap();

    let mut from_wide = wide.clone();
    from_wide.group.merge_from(&narrow.group);
    let mut from_narrow = narrow.clone();
    from_narrow.group.merge_from(&wide.group);
    for graph in [&from_wide, &from_narrow] {
        assert!(
            !graph
                .group
                .check_see_label("doc", "0xbob", Timestamp(10), None, None)
                .allowed
        );
        assert!(
            graph
                .group
                .check_see_label("doc", "0xbob", Timestamp(1), None, None)
                .allowed
        );
        assert_eq!(
            graph.group.grant_edge("doc", "0xbob").unwrap().grant.until,
            Timestamp(5)
        );
    }
}

#[test]
fn merge_edge_uses_the_grant_identity_not_the_soul() {
    let mut edge =
        GunAclEdge::new("0xalice", MeshSeeGrant::live("doc", "0xbob", 0, 80), 1).unwrap();
    edge.soul = GunSoul::s3rch_acl_grant("0xalice", "doc", "0xcarol");
    let mut graph = MeshSeeGraph::new();
    graph.group.put_object("doc", "0xalice");
    graph.group.merge_edge(edge);
    assert!(graph.group.grant_edge("doc", "0xcarol").is_none());
    assert!(
        graph
            .group
            .check_see_label("doc", "0xbob", Timestamp(1), None, None)
            .allowed
    );
}

#[test]
fn plane_hop_factors_named_grant_and_still_cannot_mint() {
    let mut plane = sociacl_core::Plane::new();
    let alice = add_wallet(&mut plane, "0xalice");
    let bob = add_wallet(&mut plane, "0xbob");
    let claim = add_claim(&mut plane, "claim-1", &alice);
    plane
        .set_object_property(&claim, "predicate", PredicateId::DELEGATE)
        .unwrap();

    let secret = IssuerSecret::generate();
    plane
        .enroll(&bob, EnrollmentKind::Principal, secret.verify_key())
        .unwrap();
    let hint = HandoffHint::parse(bob.as_str(), claim.as_str(), Some(SEE), None).unwrap();
    let hop_before = sociacl_core::SocialLightStatement::convention_badge(
        plane
            .identity_attestation(&bob, &bob, &claim)
            .unwrap()
            .sign(&secret),
    );

    let closed = check_see_hop(&plane, &claim, &bob, Some(&hint), Some(&hop_before)).unwrap();
    assert!(!closed.allowed);
    assert!(!closed.hop_is_grant());
    assert!(closed.attestation_factor.is_some());

    apply_see_grant(
        &mut plane,
        &alice,
        &IdentitySeeGrant {
            claim_id: claim.as_str().to_string(),
            accessor: bob.clone(),
            from: Timestamp(0),
            until: Timestamp(80),
        },
    )
    .unwrap();
    let hop = sociacl_core::SocialLightStatement::convention_badge(
        plane
            .identity_attestation(&bob, &bob, &claim)
            .unwrap()
            .sign(&secret),
    );
    let factored = check_see_hop(&plane, &claim, &bob, Some(&hint), Some(&hop)).unwrap();
    assert!(factored.allowed, "hop factors an already-named grant");
    assert!(!factored.hop_is_grant());
    assert_eq!(factored.reason.as_str(), PredicateId::DELEGATE);

    cancel(&mut plane, &alice, &bob, &claim).unwrap();
    let hop_after = sociacl_core::SocialLightStatement::convention_badge(
        plane
            .identity_attestation(&bob, &bob, &claim)
            .unwrap()
            .sign(&secret),
    );
    let after = check(&plane, SEE, &claim, &bob, Some(&hint), Some(&hop_after)).unwrap();
    assert!(!after.allowed);
    assert!(!after.hop_is_grant());
}

#[test]
fn mesh_grant_on_plane_feed_item_matches_claim() {
    let mut plane = sociacl_core::Plane::new();
    let alice = add_wallet(&mut plane, "0xalice");
    let bob = add_wallet(&mut plane, "0xbob");
    let item = sample_feed_item();
    let object = add_item(&mut plane, &item, &alice).unwrap();
    plane
        .set_object_property(&object, "predicate", PredicateId::DELEGATE)
        .unwrap();
    apply_see_grant(
        &mut plane,
        &alice,
        &IdentitySeeGrant {
            claim_id: object.as_str().to_string(),
            accessor: bob.clone(),
            from: Timestamp(0),
            until: Timestamp(80),
        },
    )
    .unwrap();
    assert!(check_see(&plane, &object, &bob, None).unwrap().allowed);
    assert_eq!(object.as_str(), "s3rch/items/rss3:act/1~2x");
}

#[test]
fn check_see_grant_ands_the_window() {
    let mut graph = MeshSeeGraph::new();
    graph.group.put_object("claim-1", "0xalice");
    let grant = MeshSeeGrant::live("claim-1", "0xbob", 40, 80);
    graph
        .group
        .state_see_grant("0xalice", grant.clone())
        .unwrap();
    assert!(
        !graph
            .group
            .check_see_grant(&grant, "claim-1", "0xbob", Timestamp(10), None, None)
            .allowed
    );
    assert!(
        graph
            .group
            .check_see_grant(&grant, "claim-1", "0xbob", Timestamp(40), None, None)
            .allowed
    );
}

#[test]
fn identity_see_grant_projects_to_mesh() {
    let grant = IdentitySeeGrant {
        claim_id: "claim-1".into(),
        accessor: "0xbob".into(),
        from: Timestamp(0),
        until: Timestamp(80),
    };
    let mesh = MeshSeeGrant::from(&grant);
    assert_eq!(mesh.stated, 1);
    assert!(mesh.live_at(Timestamp(0)));
    assert!(!mesh.live_at(Timestamp(80)));
}

#[test]
fn missing_object_reason() {
    let graph = MeshSeeGraph::new();
    assert_eq!(
        graph
            .group
            .check_see_label("nope", "0xalice", Timestamp(1), None, None)
            .reason,
        MESH_REASON_MISSING
    );
}

#[test]
fn execute_mask_stays_on_plane_not_mesh_see() {
    let mut plane = sociacl_core::Plane::new();
    let alice = add_wallet(&mut plane, "0xalice");
    let bob = add_wallet(&mut plane, "0xbob");
    let claim = add_claim(&mut plane, "claim-1", &alice);
    plane
        .set_object_property(&claim, "predicate", PredicateId::DELEGATE)
        .unwrap();
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::execute(), None)
        .unwrap();
    assert!(!check_see(&plane, &claim, &bob, None).unwrap().allowed);
}
