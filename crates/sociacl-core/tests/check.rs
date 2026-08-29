use sociacl_core::{
    CheckError, CheckRequest, EnrollmentKind, NodeId, Plane, PredicateId, Relation, Timestamp,
    Zookie, DEFAULT_PRIVILEGE_UP_DELAY,
};

fn owned_doc() -> (Plane, NodeId, NodeId, NodeId) {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    (plane, alice, bob, doc)
}

fn group_doc() -> (Plane, NodeId, NodeId, NodeId, NodeId) {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let carol = plane.add_person("carol").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .set_object_property(&doc, "predicate", PredicateId::SAME_GROUP)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();
    plane.jointly_state(&alice, &ops, Relation::MemberOf);
    plane.jointly_state(&bob, &ops, Relation::MemberOf);
    plane.jointly_state(&doc, &ops, Relation::ObjectGroup);
    (plane, alice, bob, carol, doc)
}

#[test]
fn check_owner_allow() {
    let (plane, alice, _, doc) = owned_doc();
    let result = plane
        .check_named("read", &doc, &alice, PredicateId::owner())
        .unwrap();
    assert!(result.allowed);
    assert_eq!(result.reason, PredicateId::owner());
}

#[test]
fn check_owner_deny_non_owner() {
    let (plane, _, bob, doc) = owned_doc();
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
fn object_properties_pick_predicate_mismatch_fails_closed() {
    let (plane, alice, _, _, doc) = group_doc();
    let via_object = plane.check_object("read", &doc, &alice).unwrap();
    assert!(via_object.allowed);
    assert_eq!(via_object.reason, PredicateId::same_group());

    let err = plane
        .check_named("read", &doc, &alice, PredicateId::named_circle())
        .unwrap_err();
    assert_eq!(
        err,
        CheckError::PredicateMismatch {
            requested: PredicateId::named_circle(),
            named: PredicateId::same_group(),
        }
    );
}

#[test]
fn check_unknown_predicate_fails_closed() {
    let (plane, alice, _, doc) = owned_doc();
    let err = plane
        .check_named("read", &doc, &alice, "heir-template")
        .unwrap_err();
    assert_eq!(
        err,
        CheckError::UnknownPredicate(PredicateId::new("heir-template"))
    );
}

#[test]
fn object_heir_template_predicate_fails_closed() {
    let (mut plane, alice, _, doc) = owned_doc();
    plane
        .set_object_property(&doc, "predicate", "heir-template")
        .unwrap();
    let err = plane.check_object("read", &doc, &alice).unwrap_err();
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
            predicate: Some(PredicateId::same_group()),
            zookie: Some(old_zookie),
            attestation: None,
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
fn privilege_up_delayed_privilege_down_immediate() {
    let mut plane = Plane::new();
    assert_eq!(plane.privilege_up_delay(), DEFAULT_PRIVILEGE_UP_DELAY);
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .set_object_property(&doc, "predicate", PredicateId::SAME_GROUP)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();
    plane.jointly_state(&doc, &ops, Relation::ObjectGroup);

    plane.state_edge(&bob, &bob, &ops, Relation::MemberOf);
    plane.state_edge(&ops, &bob, &ops, Relation::MemberOf);
    assert!(
        !plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed,
        "privilege-up waits for the delay after the second statement"
    );

    plane.set_now(Timestamp(plane.now().0 + plane.privilege_up_delay().0));
    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed,
        "privilege-up grants only after the delay"
    );

    plane.unstate_edge(&bob, &bob, &ops, Relation::MemberOf);
    assert!(
        !plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed,
        "privilege-down is immediate; the up-delay is not reused as a TTL"
    );
}

#[test]
fn one_sided_friend_is_not_a_grant() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let friends = plane.add_circle("friends");
    let secret = plane.add_object("secret", &alice).id;
    plane
        .set_object_property(&secret, "predicate", PredicateId::NAMED_CIRCLE)
        .unwrap();
    plane
        .set_object_property(&secret, "circle", "friends")
        .unwrap();
    plane.jointly_state(&secret, &friends, Relation::ObjectCircle);

    plane.state_edge(&alice, &alice, &bob, Relation::Friend);
    let friend = plane
        .edges()
        .iter()
        .find(|e| e.relation == Relation::Friend)
        .expect("one-sided friend is stored");
    assert_eq!(friend.direction(), (&alice, &bob));
    assert!(friend.is_one_sided());
    assert!(!friend.is_jointly_stated());

    let stored = plane.check_object("read", &secret, &bob).unwrap();
    assert!(
        !stored.allowed,
        "one-sided friend does not pass named-circle"
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
    plane
        .set_object_property(&secret, "predicate", PredicateId::NAMED_CIRCLE)
        .unwrap();
    plane.set_object_property(&secret, "circle", "eng").unwrap();

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
fn hopcap_one_two_hop_path_denied() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let carol = plane.add_person("carol").id;
    let eng = plane.add_circle("eng");
    let secret = plane.add_object("secret", &bob).id;
    plane
        .set_object_property(&secret, "predicate", PredicateId::NAMED_CIRCLE)
        .unwrap();
    plane.set_object_property(&secret, "circle", "eng").unwrap();
    plane.jointly_state(&secret, &eng, Relation::ObjectCircle);
    plane.jointly_state(&bob, &eng, Relation::InCircle);
    plane.jointly_state(&alice, &bob, Relation::Friend);
    plane.jointly_state(&bob, &carol, Relation::Friend);

    let bob_ok = plane.check_object("read", &secret, &bob).unwrap();
    assert!(bob_ok.allowed);
    assert!(
        !plane.check_object("read", &secret, &alice).unwrap().allowed,
        "hopcap 1: alice-friend-bob-in-eng is two hops"
    );
    assert!(
        !plane.check_object("read", &secret, &carol).unwrap().allowed,
        "hopcap 1: carol-friend-bob-in-eng is two hops"
    );
}

#[test]
fn privilege_up_waits_for_joint_statement() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .set_object_property(&doc, "predicate", PredicateId::SAME_GROUP)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();
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
        !plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed,
        "joint but still inside the privilege-up delay"
    );
    plane.set_now(Timestamp(plane.now().0 + plane.privilege_up_delay().0));
    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed
    );
}

#[test]
fn posix_mode_owner_group_other() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let carol = plane.add_person("carol").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .set_object_property(&doc, "predicate", PredicateId::POSIX_MODE)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();
    plane.set_object_property(&doc, "mode", "0640").unwrap();
    plane.jointly_state(&bob, &ops, Relation::MemberOf);

    assert!(
        plane
            .check_named("read", &doc, &alice, PredicateId::posix_mode())
            .unwrap()
            .allowed,
        "owner bits"
    );
    assert!(
        !plane
            .check_named("write", &doc, &bob, PredicateId::posix_mode())
            .unwrap()
            .allowed,
        "group has read only"
    );
    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::posix_mode())
            .unwrap()
            .allowed,
        "group bits, hop 1 jointly stated"
    );
    assert!(
        !plane
            .check_named("read", &doc, &carol, PredicateId::posix_mode())
            .unwrap()
            .allowed,
        "other bits"
    );
}

#[test]
fn trustee_only_when_object_names_it() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let owned = plane.add_object("owned", &alice).id;
    let trust = plane.add_object("trust", &alice).id;
    plane
        .set_object_property(&trust, "predicate", PredicateId::TRUSTEE)
        .unwrap();
    plane.jointly_state(&bob, &owned, Relation::Trustee);
    plane.jointly_state(&bob, &trust, Relation::Trustee);

    let err = plane
        .check_named("read", &owned, &bob, PredicateId::trustee())
        .unwrap_err();
    assert!(matches!(err, CheckError::PredicateMismatch { .. }));
    assert!(
        !plane.check_object("read", &owned, &bob).unwrap().allowed,
        "trustee edge is ignored when the object names owner"
    );
    assert!(
        plane.check_object("read", &trust, &bob).unwrap().allowed,
        "trustee holds only when the object names it"
    );
    assert!(
        !plane
            .check_named("read", &trust, &alice, PredicateId::trustee())
            .unwrap()
            .allowed,
        "owner is not implied by trustee"
    );
}

#[test]
fn attestation_is_a_factor_not_a_grant() {
    let (mut plane, _, bob, doc) = owned_doc();
    plane.enroll(&bob, EnrollmentKind::Principal).unwrap();
    let att = plane.identity_attestation(&bob, &bob, &doc).unwrap();
    let edges_before = plane.effective_edges().count();
    let owner_before = plane.object(&doc).unwrap().owner.clone();

    let result = plane
        .check(CheckRequest {
            action: "read".into(),
            object: doc.clone(),
            accessor: bob.clone(),
            predicate: Some(PredicateId::owner()),
            zookie: None,
            attestation: Some(att),
        })
        .unwrap();
    assert!(!result.allowed, "identity factor does not mint owner");
    assert!(result.attestation_factor.is_some());
    assert_eq!(plane.effective_edges().count(), edges_before);
    assert_eq!(plane.object(&doc).unwrap().owner, owner_before);
    assert!(plane.will(&doc).is_none());
}

#[test]
fn cache_hit_same_snapshot_miss_after_privilege_down() {
    let (mut plane, _, bob, _, doc) = group_doc();
    assert_eq!(plane.cache_hits(), 0);
    assert_eq!(plane.cache_misses(), 0);

    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed
    );
    assert_eq!(plane.cache_misses(), 1);
    assert_eq!(plane.cache_hits(), 0);

    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed
    );
    assert_eq!(plane.cache_hits(), 1);
    assert_eq!(plane.cache_misses(), 1);

    plane.unstate_edge(&bob, &bob, "ops", Relation::MemberOf);
    assert!(
        !plane
            .check_named("read", &doc, &bob, PredicateId::same_group())
            .unwrap()
            .allowed
    );
    assert_eq!(plane.cache_misses(), 2);
    assert_eq!(plane.cache_hits(), 1);
}

#[test]
fn device_is_a_first_class_node() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let radio = plane.add_device("radio-1");
    let obj = plane.add_object(&radio.id, &alice);
    assert_eq!(obj.kind, sociacl_core::ObjectKind::Device);
    let result = plane
        .check_named("read", &obj.id, &alice, PredicateId::owner())
        .unwrap();
    assert!(result.allowed);
}
