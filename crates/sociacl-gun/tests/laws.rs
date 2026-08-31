use sociacl_core::{
    ActionMask, CheckRequest, EnrollmentKind, HolderSecret, IssuerSecret, Plane, PredicateId,
    Relation, Timestamp, VerbError,
};
use sociacl_gun::{
    accept_hint, accept_hint_bytes, add_claim, add_wallet, cancel, check, check_execute, check_see,
    client_check, client_elect_from_hint, client_mint_grant, client_remint, elect_from_delegate,
    elect_from_hint, remint, GunError, GunNode, GunSoul, HandoffHint, ItemShape, UrlLeaf,
    HINT_MAGIC, S3RCH_ROOT, S3RCH_USERS, SEE,
};

fn wallet_plane() -> (
    Plane,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
) {
    let mut plane = Plane::new();
    let alice = add_wallet(&mut plane, "0xalice");
    let bob = add_wallet(&mut plane, "0xbob");
    let claim = add_claim(&mut plane, "claim-1", &alice);
    (plane, alice, bob, claim)
}

fn delegate_claim() -> (
    Plane,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
) {
    let (mut plane, alice, bob, claim) = wallet_plane();
    plane
        .set_object_property(&claim, "predicate", PredicateId::DELEGATE)
        .unwrap();
    (plane, alice, bob, claim)
}

#[test]
fn hint_is_not_a_grant() {
    let (plane, _, bob, claim) = delegate_claim();
    let hint = HandoffHint::parse(bob.as_str(), claim.as_str(), Some(SEE), None).unwrap();
    let accepted = accept_hint(hint.clone());
    assert_eq!(accepted.principal, bob);
    let result = check_see(&plane, &claim, &bob, Some(&hint)).unwrap();
    assert!(!result.allowed, "a hint alone fails closed");
    assert!(!result.hint_is_grant());
    assert!(result.hint.is_some());
    assert!(plane
        .edges()
        .iter()
        .all(|e| e.relation != Relation::Delegate));
}

#[test]
fn dest_recheck_issues_the_grant() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    let hint = HandoffHint::parse(bob.as_str(), claim.as_str(), Some(SEE), None).unwrap();
    assert!(
        !check_see(&plane, &claim, &bob, Some(&hint))
            .unwrap()
            .allowed
    );

    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::read(), None)
        .unwrap();
    let result = check_see(&plane, &claim, &bob, Some(&hint)).unwrap();
    assert!(result.allowed, "destination Check issues the grant");
    assert!(!result.hint_is_grant());
    assert_eq!(result.reason.as_str(), PredicateId::DELEGATE);
    assert_eq!(plane.object(&claim).unwrap().owner, alice);
}

#[test]
fn hop_and_hint_cannot_mint() {
    let (mut plane, _, bob, claim) = delegate_claim();
    let secret = IssuerSecret::generate();
    plane
        .enroll(&bob, EnrollmentKind::Principal, secret.verify_key())
        .unwrap();
    let att = plane
        .identity_attestation(&bob, &bob, &claim)
        .unwrap()
        .sign(&secret);
    let hop = sociacl_core::SocialLightStatement::convention_badge(att);
    let hint = HandoffHint::parse(bob.as_str(), claim.as_str(), Some(SEE), None).unwrap();
    let edges_before = plane.edges().len();
    let owner_before = plane.object(&claim).unwrap().owner.clone();

    let result = check(&plane, SEE, &claim, &bob, Some(&hint), Some(&hop)).unwrap();
    assert!(!result.allowed, "hop plus hint do not mint");
    assert!(result.attestation_factor.is_some());
    assert_eq!(plane.edges().len(), edges_before);
    assert_eq!(plane.object(&claim).unwrap().owner, owner_before);
}

#[test]
fn missing_hop_does_not_fail_check() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::read(), None)
        .unwrap();
    let result = check_see(&plane, &claim, &bob, None).unwrap();
    assert!(result.allowed);
    assert!(result.attestation_factor.is_none());
    assert!(result.hint.is_none());
}

#[test]
fn cancel_is_dest_acl() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::read(), None)
        .unwrap();
    let before = plane.object(&claim).unwrap().version;
    cancel(&mut plane, &alice, &bob, &claim).unwrap();
    assert!(!check_see(&plane, &claim, &bob, None).unwrap().allowed);
    assert!(plane.object(&claim).unwrap().version > before);
    assert_eq!(plane.object(&claim).unwrap().owner, alice);
}

#[test]
fn url_leaf_is_not_an_in_graph_node() {
    let leaf = UrlLeaf::parse("https://Example.COM/item/1/#frag").unwrap();
    assert_eq!(leaf.normalized(), "https://example.com/item/1");
    assert!(!leaf.is_gun_node());
    assert!(leaf.as_node_id().is_none());

    let mut item = ItemShape::default();
    item.permalink = Some(leaf);
    item.tags = ItemShape::tags_from_csv("mesh, notes");
    assert_eq!(item.tags_as_csv(), "mesh,notes");
    assert_eq!(
        item.dedup_key().as_deref(),
        Some("https://example.com/item/1")
    );
    item.id = Some("claim-1".into());
    assert_eq!(item.dedup_key().as_deref(), Some("claim-1"));

    assert_eq!(
        UrlLeaf::parse("gun://s3rch/users/0xalice").unwrap_err(),
        GunError::InvalidUrl
    );
    assert_eq!(
        UrlLeaf::parse("s3rch/users/0xalice").unwrap_err(),
        GunError::InvalidUrl
    );
}

#[test]
fn elect_from_hint_and_delegate_fails() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::execute(), None)
        .unwrap();
    let hint = HandoffHint::parse(bob.as_str(), claim.as_str(), Some("execute"), None).unwrap();
    assert_eq!(
        elect_from_hint(&mut plane, &claim, &hint).unwrap_err(),
        GunError::ElectFromHint
    );
    assert_eq!(
        elect_from_delegate(&mut plane, &claim).unwrap_err(),
        VerbError::KeepOperatingSuffices(claim.clone())
    );
    assert_eq!(plane.object(&claim).unwrap().owner, alice);
}

#[test]
fn execute_without_read_works() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::execute(), None)
        .unwrap();
    assert!(check_execute(&plane, &claim, &bob, None).unwrap().allowed);
    assert!(
        !check_see(&plane, &claim, &bob, None).unwrap().allowed,
        "execute-without-read denies see/read"
    );
    assert_eq!(plane.object(&claim).unwrap().owner, alice);
}

#[test]
fn hopcap_1_no_transitive_friend_grant() {
    let (mut plane, alice, bob, claim) = wallet_plane();
    let carol = add_wallet(&mut plane, "0xcarol");
    plane.jointly_state(&alice, &bob, Relation::Friend);
    plane.jointly_state(&bob, &carol, Relation::Friend);

    assert!(
        check_see(&plane, &claim, &alice, None).unwrap().allowed,
        "holder sees their own claim"
    );
    assert!(
        !check_see(&plane, &claim, &bob, None).unwrap().allowed,
        "a friend edge is not a see grant"
    );
    assert!(
        !check_see(&plane, &claim, &carol, None).unwrap().allowed,
        "hopcap 1: no friends-of-friends"
    );
}

#[test]
fn expired_until_denies_without_changing_owner() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    plane
        .jointly_delegate(
            &alice,
            &bob,
            &claim,
            ActionMask::read(),
            Some(Timestamp(50)),
        )
        .unwrap();
    assert!(check_see(&plane, &claim, &bob, None).unwrap().allowed);
    plane.set_now(Timestamp(50));
    assert!(!check_see(&plane, &claim, &bob, None).unwrap().allowed);
    assert_eq!(plane.object(&claim).unwrap().owner, alice);
    assert!(!plane.acl_names(&claim, &bob));
}

#[test]
fn remint_requires_acl_name() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    let hint = HandoffHint::parse(bob.as_str(), claim.as_str(), Some(SEE), None).unwrap();
    assert!(matches!(
        remint(&plane, &claim, &bob, Some(&hint)).unwrap_err(),
        VerbError::AclDoesNotNamePrincipal(_, _)
    ));
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::read(), None)
        .unwrap();
    let cap = remint(&plane, &claim, &bob, Some(&hint)).unwrap();
    assert_eq!(cap.principal, bob);
}

#[test]
fn case_c_client_has_no_mint_path_for_new_gun_grants() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    plane.set_now(Timestamp(20));
    plane.set_cut(Timestamp(10));
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::read(), None)
        .unwrap();
    assert!(!check_see(&plane, &claim, &bob, None).unwrap().allowed);

    let secret = HolderSecret::generate();
    let bytes = plane.export_bundle_bytes(&alice, &secret).unwrap();
    let mut client = sociacl_core::Client::from_bytes(&bytes, &secret).unwrap();
    assert!(
        !client_check(&client, SEE, &claim, &bob, None, None)
            .unwrap()
            .allowed
    );
    assert_eq!(
        client_mint_grant(&mut client, &alice, &bob, &claim, ActionMask::read(), None).unwrap_err(),
        GunError::ClientHasNoMintPath
    );
    let hint = HandoffHint::parse(bob.as_str(), claim.as_str(), Some(SEE), None).unwrap();
    assert_eq!(
        client_elect_from_hint(&mut client, &claim, &hint).unwrap_err(),
        GunError::ElectFromHint
    );
    assert_eq!(client.object(&claim).unwrap().owner, alice);
}

#[test]
fn precut_delegate_survives_client_check_and_remint() {
    let (mut plane, alice, bob, claim) = delegate_claim();
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::execute(), None)
        .unwrap();
    let secret = HolderSecret::generate();
    let bytes = plane.export_bundle_bytes(&bob, &secret).unwrap();
    let client = sociacl_core::Client::from_bytes(&bytes, &secret).unwrap();
    assert!(
        client_check(&client, "execute", &claim, &bob, None, None)
            .unwrap()
            .allowed
    );
    assert!(
        !client_check(&client, SEE, &claim, &bob, None, None)
            .unwrap()
            .allowed
    );
    let cap = client_remint(&client, &claim, &bob).unwrap();
    assert_eq!(cap.principal, bob);
}

#[test]
fn locked_user_soul_is_the_only_user_node() {
    let mut plane = Plane::new();
    let alice = add_wallet(&mut plane, "0xalice");
    assert_eq!(alice.as_str(), "s3rch/users/0xalice");
    let soul = GunSoul::parse("gun.get('s3rch').get('users').get('0xalice')").unwrap();
    assert!(soul.is_s3rch_user());
    assert_eq!(soul.wallet(), Some("0xalice"));
    assert_eq!(soul.as_node_id(), alice);
    assert_eq!(GunSoul::s3rch_user("0xalice").segments()[0], S3RCH_ROOT);
    assert_eq!(GunSoul::s3rch_user("0xalice").segments()[1], S3RCH_USERS);
    assert_eq!(GunNode::user("0xalice").as_node_id(), alice);
    assert_eq!(
        plane.node_kind(&alice),
        Some(sociacl_core::NodeKind::Person)
    );
}

#[test]
fn hint_decode_does_not_verify_or_mint() {
    let hint = HandoffHint::parse("0xbob", "claim-1", Some(SEE), Some("edge-handoff")).unwrap();
    let bytes = hint.encode().unwrap();
    assert_eq!(&bytes[..4], HINT_MAGIC);
    let decoded = accept_hint_bytes(&bytes).unwrap();
    assert_eq!(decoded.principal.as_str(), "0xbob");
    assert_eq!(decoded.verb.as_deref(), Some(SEE));
    assert_eq!(
        accept_hint_bytes(b"nope").unwrap_err(),
        GunError::HintCorrupt
    );
}

#[test]
fn hint_does_not_mint_a_missing_accessor() {
    let (plane, alice, _, claim) = wallet_plane();
    let hint = HandoffHint::parse("stranger", claim.as_str(), Some(SEE), None).unwrap();
    assert!(
        plane
            .check(CheckRequest {
                action: "read".into(),
                object: claim.clone(),
                accessor: alice.clone(),
                predicate: None,
                zookie: None,
                attestation: None,
            })
            .unwrap()
            .allowed,
        "owner see still uses dest Check"
    );
    assert!(matches!(
        check_see(&plane, &claim, "stranger", Some(&hint)).unwrap_err(),
        sociacl_core::CheckError::AccessorNotFound(_)
    ));
}
