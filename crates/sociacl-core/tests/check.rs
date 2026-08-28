use sociacl_core::{CheckError, CheckRequest, NodeId, Plane, PredicateId, Relation, Zookie};

fn group_doc() -> (Plane, NodeId, NodeId, NodeId, NodeId) {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let carol = plane.add_person("carol").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane.jointly_state(&alice, &ops, Relation::MemberOf);
    plane.jointly_state(&bob, &ops, Relation::MemberOf);
    plane.jointly_state(&doc, &ops, Relation::ObjectGroup);
    (plane, alice, bob, carol, doc)
}

#[test]
fn check_owner_allow() {
    let (plane, alice, _, _, doc) = group_doc();
    let result = plane
        .check_named("read", &doc, &alice, PredicateId::owner())
        .unwrap();
    assert!(result.allowed);
    assert_eq!(result.reason, PredicateId::owner());
}

#[test]
fn check_owner_deny_non_owner() {
    let (plane, _, bob, _, doc) = group_doc();
    let result = plane
        .check_named("read", &doc, &bob, PredicateId::owner())
        .unwrap();
    assert!(!result.allowed);
    assert_eq!(result.reason, PredicateId::owner());
}

#[test]
fn check_same_group_allow() {
    let (plane, _, bob, _, doc) = group_doc();
    let result = plane
        .check_named("read", &doc, &bob, PredicateId::same_group())
        .unwrap();
    assert!(result.allowed);
}

#[test]
fn check_same_group_deny_outsider() {
    let (plane, _, _, carol, doc) = group_doc();
    let result = plane
        .check_named("read", &doc, &carol, PredicateId::same_group())
        .unwrap();
    assert!(!result.allowed);
}

#[test]
fn check_unknown_predicate_fails_closed() {
    let (plane, alice, _, _, doc) = group_doc();
    let err = plane
        .check_named("read", &doc, &alice, "heir-template")
        .unwrap_err();
    assert_eq!(
        err,
        CheckError::UnknownPredicate(PredicateId::new("heir-template"))
    );
}

#[test]
fn new_enemy_revoke_then_write_denies_old_zookie() {
    let (mut plane, _, bob, _, doc) = group_doc();
    let allowed = plane
        .check_named("read", &doc, &bob, PredicateId::same_group())
        .unwrap();
    assert!(allowed.allowed);
    let old_zookie: Zookie = allowed.zookie;
    let old_version = old_zookie.object_version;

    plane.unstate_edge(&bob, &bob, "ops", Relation::MemberOf);
    plane.write_object(&doc);

    let after = plane
        .check(CheckRequest {
            action: "read".into(),
            object: doc.clone(),
            accessor: bob.clone(),
            predicate: PredicateId::same_group(),
            zookie: Some(old_zookie),
        })
        .unwrap();
    assert!(
        !after.allowed,
        "revoked accessor must not see the new write"
    );
    assert!(after.zookie.object_version > old_version);
}

#[test]
fn privilege_down_is_immediate_without_write() {
    let (mut plane, _, bob, _, doc) = group_doc();
    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed
    );
    plane.unstate_edge(&bob, &bob, "ops", Relation::MemberOf);
    assert!(
        !plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed
    );
}

#[test]
fn hopcap_one_named_circle_no_friend_walk() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let eng = plane.add_circle("eng");
    let friends = plane.add_circle("friends-of-bob");
    let secret = plane.add_object("secret", &bob).id;

    plane.jointly_state(&bob, &eng, Relation::InCircle);
    plane.jointly_state(&alice, &friends, Relation::InCircle);
    plane.jointly_state(&secret, &eng, Relation::ObjectCircle);

    let bob_ok = plane
        .check_named("read", &secret, &bob, PredicateId::named_circle())
        .unwrap();
    assert!(bob_ok.allowed);

    let alice_denied = plane
        .check_named("read", &secret, &alice, PredicateId::named_circle())
        .unwrap();
    assert!(
        !alice_denied.allowed,
        "hopcap 1: membership in a different circle is not a walk to eng"
    );
}

#[test]
fn privilege_up_waits_for_joint_statement() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane.jointly_state(&doc, &ops, Relation::ObjectGroup);
    plane.state_edge(&bob, &bob, &ops, Relation::MemberOf);
    assert!(
        !plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed,
        "one-sided statement is not a grant"
    );
    plane.state_edge(&ops, &bob, &ops, Relation::MemberOf);
    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed
    );
}

#[test]
fn device_is_a_first_class_node() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let radio = plane.add_device("radio-1");
    let obj = plane.add_object(&radio.id, &alice);
    let result = plane
        .check_named("read", &obj.id, &alice, PredicateId::owner())
        .unwrap();
    assert!(result.allowed);
}
