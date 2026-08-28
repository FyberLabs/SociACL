use sociacl_core::{
    AuthnState, Clock, DiscoverResult, Plane, PredicateId, Relation, Timestamp, VerbError, Will,
    WillDisposition, WillTemplate,
};

fn will(object: &str, testator: &str, disposition: WillDisposition) -> Will {
    Will {
        object: object.into(),
        testator: testator.into(),
        template: WillTemplate::CorporateSuccession,
        disposition,
        written_at: Timestamp(1),
        cancelable_by: vec!["executor".into()],
        canceled: false,
    }
}

#[test]
fn remint_when_acl_names_principal() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane.jointly_state(&bob, &ops, Relation::MemberOf);
    plane.jointly_state(&doc, &ops, Relation::ObjectGroup);

    let cap = plane.remint(&doc, &bob).unwrap();
    assert_eq!(cap.principal, bob);
    assert_eq!(cap.object, doc);
}

#[test]
fn remint_fails_if_acl_no_longer_names_principal() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane.jointly_state(&bob, &ops, Relation::MemberOf);
    plane.jointly_state(&doc, &ops, Relation::ObjectGroup);
    plane.unstate_edge(&bob, &bob, &ops, Relation::MemberOf);

    let err = plane.remint(&doc, &bob).unwrap_err();
    assert!(matches!(err, VerbError::AclDoesNotNamePrincipal(_, _)));
}

#[test]
fn remint_requires_live_authn() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    plane.set_authn(&alice, AuthnState::Gone);
    let err = plane.remint(&doc, &alice).unwrap_err();
    assert_eq!(err, VerbError::AuthnNotLive(alice));
}

#[test]
fn elect_refuses_without_prewritten_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    plane.set_authn(&alice, AuthnState::Gone);
    let err = plane.elect(&doc).unwrap_err();
    assert_eq!(err, VerbError::NoWill(doc));
}

#[test]
fn elect_refuses_when_keep_operating_would_suffice() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob)))
        .unwrap();
    let err = plane.elect(&doc).unwrap_err();
    assert_eq!(err, VerbError::KeepOperatingSuffices(doc));
}

#[test]
fn elect_installs_heir_from_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob.clone())))
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);

    let result = plane.elect(&doc).unwrap();
    assert_eq!(result.new_owner, bob);
    assert_eq!(result.clock, Clock::Elect);
    assert!(result.notify.iter().any(|n| n.as_str() == "executor"));
    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::owner())
            .unwrap()
            .allowed
    );
}

#[test]
fn discover_reports_heir_without_electing() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob.clone())))
        .unwrap();
    assert_eq!(plane.discover(&doc).unwrap(), DiscoverResult::Heir(bob));
    assert!(
        plane
            .check_named("read", &doc, &alice, PredicateId::owner())
            .unwrap()
            .allowed
    );
}

#[test]
fn destroy_fails_closed_without_a_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let err = plane.destroy(&doc).unwrap_err();
    assert_eq!(err, VerbError::NoWill(doc));
    assert!(plane.object(&"doc".into()).unwrap().content_key.is_some());
}

#[test]
fn destroy_erases_when_will_says_stay_secret() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::StaySecret))
        .unwrap();
    let result = plane.destroy(&doc).unwrap();
    assert!(result.erased);
    assert!(plane.object(&doc).unwrap().destroyed);
    assert!(plane.object(&doc).unwrap().content_key.is_none());
}

#[test]
fn destroy_refuses_when_will_names_heir() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob)))
        .unwrap();
    let err = plane.destroy(&doc).unwrap_err();
    assert_eq!(err, VerbError::HasHeir(doc));
}

#[test]
fn will_must_be_written_while_alive() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_object("doc", &alice);
    plane.set_authn(&alice, AuthnState::Gone);
    let err = plane
        .write_will(will("doc", "alice", WillDisposition::StaySecret))
        .unwrap_err();
    assert_eq!(err, VerbError::TestatorNotAlive);
}
