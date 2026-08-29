use sociacl_core::{
    AuthnState, CheckError, Clock, DiscoverResult, ElectState, EnrollmentKind, Plane, PredicateId,
    Relation, Timestamp, VerbError, Will, WillDisposition,
};

fn will(object: &str, testator: &str, disposition: WillDisposition) -> Will {
    match disposition {
        WillDisposition::Heir(heir) => Will::heir(
            object,
            testator,
            heir,
            Timestamp(1),
            vec!["executor".into()],
        ),
        WillDisposition::StaySecret => Will::stay_secret(object, testator, Timestamp(1)),
    }
}

fn advance_elect_wait(plane: &mut Plane) {
    plane.set_now(Timestamp(plane.now().0 + plane.elect_wait().0));
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
    plane
        .set_object_property(&doc, "predicate", PredicateId::SAME_GROUP)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();

    let cap = plane.remint(&doc, &bob).unwrap();
    assert_eq!(cap.principal, bob);
    assert_eq!(cap.object, doc);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
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
    plane
        .set_object_property(&doc, "predicate", PredicateId::SAME_GROUP)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();
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
fn remint_does_not_pick_an_owner_from_a_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob.clone())))
        .unwrap();
    let cap = plane.remint(&doc, &alice).unwrap();
    assert_eq!(cap.principal, alice);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
    assert!(matches!(
        plane.remint(&doc, &bob).unwrap_err(),
        VerbError::AclDoesNotNamePrincipal(_, _)
    ));
}

#[test]
fn remint_attestation_restricted_to_will_issuers() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let named = plane.add_device("station-a").id;
    let other = plane.add_device("station-b").id;
    let doc = plane.add_object("doc", &alice).id;
    plane.enroll(&named, EnrollmentKind::Station).unwrap();
    plane.enroll(&other, EnrollmentKind::Station).unwrap();
    plane
        .write_will_src("will radio for object doc\nwritten-by alice\nremint issuers station-a\n")
        .unwrap();

    let bad = plane
        .station_liveness_attestation(&other, &alice, &doc)
        .unwrap();
    assert_eq!(
        plane
            .remint_with_attestation(&doc, &alice, &bad)
            .unwrap_err(),
        VerbError::RemintIssuerNotNamed(other)
    );

    let good = plane
        .station_liveness_attestation(&named, &alice, &doc)
        .unwrap();
    let cap = plane.remint_with_attestation(&doc, &alice, &good).unwrap();
    assert_eq!(cap.principal, alice);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn remint_without_attestation_still_works_when_will_names_issuers() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let sta = plane.add_device("station-a").id;
    let doc = plane.add_object("doc", &alice).id;
    plane.enroll(&sta, EnrollmentKind::Station).unwrap();
    plane
        .write_will_src("will radio for object doc\nwritten-by alice\nremint issuers station-a\n")
        .unwrap();
    let cap = plane.remint(&doc, &alice).unwrap();
    assert_eq!(cap.principal, alice);
}

#[test]
fn discover_reports_named_heir_without_electing() {
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
fn discover_reports_first_successor_name() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    plane.add_person("carol");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will_src(
            "will desk for object doc\nwritten-by alice\nnamed-successor-list bob carol\n",
        )
        .unwrap();
    assert_eq!(
        plane.discover(&doc).unwrap(),
        DiscoverResult::Heir("bob".into())
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn discover_reports_elect_among_for_rank_circle() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let ops = plane.add_circle("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will_src(
            "will desk for object doc\nwritten-by alice\nhighest-still-attesting-rank circle ops\n",
        )
        .unwrap();
    assert_eq!(
        plane.discover(&doc).unwrap(),
        DiscoverResult::ElectAmong { circle: ops }
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn discover_reports_stay_secret() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::StaySecret))
        .unwrap();
    assert_eq!(plane.discover(&doc).unwrap(), DiscoverResult::StaySecret);
}

#[test]
fn discover_fails_closed_without_a_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    assert_eq!(plane.discover(&doc).unwrap_err(), VerbError::NoWill(doc));
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
fn elect_refuses_stay_secret() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::StaySecret))
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);
    assert_eq!(
        plane.elect(&doc).unwrap_err(),
        VerbError::WillPrescribesDestroy(doc)
    );
}

#[test]
fn elect_is_pending_until_commit_after_wait() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    let version = plane.object(&doc).unwrap().version;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob.clone())))
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);

    let started = plane.elect(&doc).unwrap();
    assert_eq!(started.clock, Clock::Elect);
    assert!(started.state.is_pending());
    assert_eq!(started.state.heir(), &bob);
    assert!(started.notify.iter().any(|n| n.as_str() == "executor"));
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
    assert_eq!(plane.object(&doc).unwrap().version, version);
    assert!(plane.pending_elect(&doc).is_some());
    assert!(
        !plane
            .check_named("read", &doc, &bob, PredicateId::owner())
            .unwrap()
            .allowed
    );

    assert_eq!(
        plane.elect(&doc).unwrap_err(),
        VerbError::ElectPending(doc.clone())
    );
    let too_soon = plane.commit_elect(&doc).unwrap_err();
    assert_eq!(too_soon, VerbError::ElectWaitNotElapsed(doc.clone()));
    assert_eq!(plane.object(&doc).unwrap().owner, alice);

    advance_elect_wait(&mut plane);
    let committed = plane.commit_elect(&doc).unwrap();
    assert!(committed.state.is_installed());
    assert_eq!(
        committed.state,
        ElectState::Installed {
            new_owner: bob.clone()
        }
    );
    assert_eq!(plane.object(&doc).unwrap().owner, bob);
    assert!(plane.object(&doc).unwrap().version.0 > version.0);
    assert!(plane.pending_elect(&doc).is_none());
    assert!(
        plane
            .check_named("read", &doc, &bob, PredicateId::owner())
            .unwrap()
            .allowed
    );
}

#[test]
fn elect_pending_is_canceled_by_a_live_principal() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let executor = plane.add_person("executor").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob)))
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);

    plane.elect(&doc).unwrap();
    plane.cancel_will(&doc, &executor).unwrap();
    advance_elect_wait(&mut plane);
    let err = plane.commit_elect(&doc).unwrap_err();
    assert_eq!(err, VerbError::WillCanceled(doc.clone()));
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
    assert!(plane.pending_elect(&doc).is_none());
}

#[test]
fn elect_does_not_share_a_timeout_with_keep_operating() {
    let mut plane = Plane::new();
    plane.set_privilege_up_delay(Timestamp(1));
    plane.set_elect_wait(Timestamp(10));
    assert_ne!(plane.privilege_up_delay(), plane.elect_wait());
}

#[test]
fn elect_from_attestation_does_not_run_a_valid_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob)))
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);
    plane.enroll(&alice, EnrollmentKind::Principal).unwrap();
    let att = plane.identity_attestation(&alice, &alice, &doc).unwrap();
    assert_eq!(
        plane.elect_from_attestation(&doc, &att).unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
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
fn destroy_refuses_when_a_circle_member_is_still_attesting() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let carol = plane.add_person("carol").id;
    let ops = plane.add_circle("ops");
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane.jointly_state(&carol, &ops, Relation::InCircle);
    plane.enroll(&carol, EnrollmentKind::Principal).unwrap();
    let att = plane.identity_attestation(&carol, &carol, &doc).unwrap();
    plane.submit_attestation(att).unwrap();
    plane
        .write_will_src(
            "will desk for object doc\nwritten-by alice\ncancelable-by executor\nhighest-still-attesting-rank circle ops\ndestroy if-no-heir keys\n",
        )
        .unwrap();
    assert_eq!(plane.destroy(&doc).unwrap_err(), VerbError::HasHeir(doc));
}

#[test]
fn destroy_erases_when_nobody_still_attesting() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let ops = plane.add_circle("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane.jointly_state(&bob, &ops, Relation::InCircle);
    plane.enroll(&bob, EnrollmentKind::Principal).unwrap();
    plane
        .write_will_src(
            "will desk for object doc\nwritten-by alice\nhighest-still-attesting-rank circle ops\ndestroy if-no-heir keys\n",
        )
        .unwrap();
    let result = plane.destroy(&doc).unwrap();
    assert!(result.erased);
    assert!(plane.object(&doc).unwrap().destroyed);
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

#[test]
fn cut_refuses_post_cut_will_and_leaves_keep_operating() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob.clone())))
        .unwrap();

    plane.set_now(Timestamp(20));
    plane.set_cut(Timestamp(10));

    let cap = plane.remint(&doc, &alice).unwrap();
    assert_eq!(cap.principal, alice);
    assert!(plane.check_object("read", &doc, &alice).unwrap().allowed);

    let late = Will::heir(&doc, &alice, &bob, Timestamp(21), vec!["executor".into()]);
    assert_eq!(
        plane.write_will(late).unwrap_err(),
        VerbError::PostCutWill(doc.clone())
    );

    plane.set_authn(&alice, AuthnState::Gone);
    let started = plane.elect(&doc).unwrap();
    assert!(started.state.is_pending());
}

#[test]
fn post_cut_edges_do_not_grant() {
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

    plane.set_now(Timestamp(20));
    plane.set_cut(Timestamp(10));
    plane.jointly_state(&bob, &ops, Relation::MemberOf);

    assert!(!plane.check_object("read", &doc, &bob).unwrap().allowed);
    assert!(matches!(
        plane.remint(&doc, &bob).unwrap_err(),
        VerbError::AclDoesNotNamePrincipal(_, _)
    ));
}

#[test]
fn check_still_cannot_evaluate_a_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(will("doc", "alice", WillDisposition::Heir(bob.clone())))
        .unwrap();

    let bob_check = plane.check_object("read", &doc, &bob).unwrap();
    assert!(
        !bob_check.allowed,
        "heir named in a will must not pass Check"
    );
    assert_eq!(bob_check.reason, PredicateId::owner());

    plane
        .set_object_property(&doc, "predicate", "heir-template")
        .unwrap();
    assert_eq!(
        plane.check_object("read", &doc, &bob).unwrap_err(),
        CheckError::UnknownPredicate(PredicateId::new("heir-template"))
    );
}
