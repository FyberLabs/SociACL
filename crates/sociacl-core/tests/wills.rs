use sociacl_core::{
    AuthnState, CheckError, Clock, DiscoverResult, EnrollmentKind, IssuerSecret, Plane,
    PredicateId, Relation, Timestamp, VerbError, Will, WillClause, WillError,
};

const POSIX_POOR: &str = include_str!("../../../examples/wills/posix-poor.will");
const NAMED_SUCCESSION: &str = include_str!("../../../examples/wills/named-succession.will");
const DEVICE_WILL: &str = include_str!("../../../examples/wills/device-will.will");

#[test]
fn parse_posix_poor_object_template() {
    let will = Will::parse(POSIX_POOR).unwrap();
    assert_eq!(will.name, "posix-doc");
    assert!(matches!(will.body.clauses[0], WillClause::Discover { .. }));
    assert!(will.body.has_destroy());
}

#[test]
fn parse_named_succession_template() {
    let will = Will::parse(NAMED_SUCCESSION).unwrap();
    assert!(will.body.successor_list().is_some());
    assert!(
        matches!(will.body.elect(), Some(WillClause::Elect { clock, .. }) if *clock == Clock::Elect)
    );
}

#[test]
fn parse_device_will_template() {
    let will = Will::parse(DEVICE_WILL).unwrap();
    assert!(will
        .body
        .clauses
        .iter()
        .any(|c| matches!(c, WillClause::Remint { .. })));
    assert!(will
        .body
        .clauses
        .iter()
        .any(|c| matches!(c, WillClause::Elect { .. })));
    assert!(will.body.has_destroy());
}

#[test]
fn military_rank_alias_is_named_template_not_doctrine() {
    let will =
        Will::parse("will desk for object desk\nwritten-by alice\nmilitary-rank circle ops\n")
            .unwrap();
    assert!(matches!(
        will.body.clauses[0],
        WillClause::HighestStillAttestingRank { .. }
    ));
}

#[test]
fn corporate_succession_alias_is_named_successor_list() {
    let will = Will::parse(
        "will desk for object desk\nwritten-by alice\ncorporate-succession bob carol\n",
    )
    .unwrap();
    assert!(matches!(
        will.body.clauses[0],
        WillClause::NamedSuccessorList { .. }
    ));
}

#[test]
fn unnamed_verb_fails_closed() {
    let err = Will::parse("will x for object doc\nwritten-by alice\nfly-away now\n").unwrap_err();
    assert_eq!(err, WillError::UnnamedVerb("fly-away".into()));
}

#[test]
fn dead_hand_shapes_fail_closed() {
    for src in [
        "will x for object doc\nwritten-by alice\nelect if-silent-for 30\n",
        "will x for object doc\nwritten-by alice\ndestroy if-inactive 7 keys\n",
        "will x for object doc\nwritten-by alice\nelect on-silence circle ops\n",
        "will x for object doc\nwritten-by alice\ndead-hand elect bob\n",
    ] {
        let err = Will::parse(src).unwrap_err();
        assert!(
            matches!(err, WillError::DeadHand(_)),
            "expected dead-hand, got {err:?} for {src}"
        );
    }
}

#[test]
fn one_timeout_for_both_clocks_fails_closed() {
    let err =
        Will::parse("will x for object doc\nwritten-by alice\nremint issuers sta timeout 30\n")
            .unwrap_err();
    assert!(matches!(err, WillError::ClockMix(_)));
}

#[test]
fn elect_on_keep_operating_clock_fails_closed() {
    let err = Will::parse(
        "will x for object doc\nwritten-by alice\nelect circle ops clock keep-operating notify alice wait cancel\n",
    )
    .unwrap_err();
    assert!(matches!(err, WillError::ClockMix(_)));
}

#[test]
fn remint_on_elect_clock_fails_closed() {
    let err =
        Will::parse("will x for object doc\nwritten-by alice\nremint issuers sta clock elect\n")
            .unwrap_err();
    assert!(matches!(err, WillError::ClockMix(_)));
}

#[test]
fn elect_without_cancel_fails_closed() {
    let err = Will::parse(
        "will x for object doc\nwritten-by alice\nelect circle ops clock elect notify alice wait\n",
    )
    .unwrap_err();
    assert_eq!(err, WillError::ElectRequiresCancel);
}

#[test]
fn heir_template_token_fails_closed() {
    let err =
        Will::parse("will x for object doc\nwritten-by alice\nheir-template bob\n").unwrap_err();
    assert_eq!(err, WillError::HeirTemplate);
}

#[test]
fn vacancy_ad_fails_closed() {
    let err = Will::parse("will x for object doc\nwritten-by alice\nvacancy-ad ops\n").unwrap_err();
    assert_eq!(err, WillError::VacancyAd);
}

#[test]
fn remint_issuers_must_be_enrolled() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_object("doc", &alice);
    let will =
        Will::parse("will x for object doc\nwritten-by alice\nremint issuers station-a\n").unwrap();
    let err = plane.write_will(will).unwrap_err();
    assert!(matches!(
        err,
        VerbError::InvalidWill(WillError::MissingEnrollment(_))
    ));
}

#[test]
fn write_will_validates_and_jointly_states() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    plane.add_object("doc", &alice);
    plane
        .write_will_src(
            "will posix-doc for object doc\nwritten-by alice\ndiscover heir bob\ndestroy if-no-heir keys\n",
        )
        .unwrap();
    let will = plane.will(&"doc".into()).unwrap();
    assert_eq!(will.joint_at, plane.now());
    assert_eq!(will.testator, alice);
}

#[test]
fn check_never_consults_a_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(Will::heir(
            &doc,
            &alice,
            &bob,
            plane.now(),
            vec![alice.clone()],
        ))
        .unwrap();

    let bob_check = plane.check_object("read", &doc, &bob).unwrap();
    assert!(
        !bob_check.allowed,
        "heir named in a will must not pass Check"
    );
    assert_eq!(bob_check.reason, PredicateId::owner());
    assert!(
        plane.check_object("read", &doc, &alice).unwrap().allowed,
        "owner Check still holds"
    );
}

#[test]
fn will_macro_names_are_unknown_check_predicates() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    for name in [
        "keep-operating",
        "remint",
        "discover",
        "elect",
        "destroy",
        "highest-still-attesting-rank",
        "named-successor-list",
        "heir-template",
        "military-rank",
        "corporate-succession",
    ] {
        plane.set_object_property(&doc, "predicate", name).unwrap();
        let err = plane.check_object("read", &doc, &alice).unwrap_err();
        assert_eq!(
            err,
            CheckError::UnknownPredicate(PredicateId::new(name)),
            "{name}"
        );
    }
}

#[test]
fn elect_refuses_on_silence_in_a_rank_circle() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let ops = plane.add_circle("ops");
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane.jointly_state(&bob, &ops, Relation::InCircle);
    plane
        .enroll(
            &bob,
            EnrollmentKind::Principal,
            IssuerSecret::generate().verify_key(),
        )
        .unwrap();
    plane
        .write_will_src(
            "will desk for object doc\nwritten-by alice\ncancelable-by executor\nhighest-still-attesting-rank circle ops\ndestroy if-no-heir keys\n",
        )
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);

    let err = plane.elect(&doc).unwrap_err();
    assert_eq!(
        err,
        VerbError::NoElectPath(doc.clone()),
        "silence is not a vote"
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn elect_picks_still_attesting_rank_member() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let carol = plane.add_person("carol").id;
    let ops = plane.add_circle("ops");
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane.jointly_state(&bob, &ops, Relation::InCircle);
    plane.jointly_state(&carol, &ops, Relation::InCircle);
    plane
        .enroll(
            &bob,
            EnrollmentKind::Principal,
            IssuerSecret::generate().verify_key(),
        )
        .unwrap();
    let carol_secret = IssuerSecret::generate();
    plane
        .enroll(&carol, EnrollmentKind::Principal, carol_secret.verify_key())
        .unwrap();
    let att = plane
        .identity_attestation(&carol, &carol, &doc)
        .unwrap()
        .sign(&carol_secret);
    plane.submit_attestation(att).unwrap();
    plane
        .write_will_src(
            "will desk for object doc\nwritten-by alice\ncancelable-by executor\nhighest-still-attesting-rank circle ops\n",
        )
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);

    assert_eq!(
        plane.discover(&doc).unwrap(),
        DiscoverResult::ElectAmong { circle: ops }
    );
    let result = plane.elect(&doc).unwrap();
    assert_eq!(result.state.heir(), &carol);
    assert!(result.state.is_pending());
    assert_eq!(result.clock, Clock::Elect);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
    plane.set_now(Timestamp(plane.now().0 + plane.elect_wait().0));
    let committed = plane.commit_elect(&doc).unwrap();
    assert_eq!(committed.state.heir(), &carol);
    assert!(committed.state.is_installed());
}

#[test]
fn elect_from_attestation_does_not_run_a_valid_will() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(Will::heir(
            &doc,
            &alice,
            &bob,
            plane.now(),
            vec!["executor".into()],
        ))
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);
    let bob_secret = IssuerSecret::generate();
    plane
        .enroll(&bob, EnrollmentKind::Principal, bob_secret.verify_key())
        .unwrap();
    let att = plane
        .identity_attestation(&bob, &bob, &doc)
        .unwrap()
        .sign(&bob_secret);
    assert_eq!(
        plane.elect_from_attestation(&doc, &att).unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn both_clocks_in_one_will_is_not_a_mix() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let radio = plane.add_device("radio-1");
    plane.add_object(&radio.id, &alice);
    let ops = plane.add_circle("operators");
    let sta = plane.add_device("station-alpha").id;
    plane.add_device("station-beta");
    plane.add_person("bob");
    plane
        .enroll(
            &sta,
            EnrollmentKind::Station,
            IssuerSecret::generate().verify_key(),
        )
        .unwrap();
    plane
        .enroll(
            "station-beta",
            EnrollmentKind::Station,
            IssuerSecret::generate().verify_key(),
        )
        .unwrap();
    plane.jointly_state(&alice, &ops, Relation::InCircle);
    plane.write_will_src(DEVICE_WILL).unwrap();
    let will = plane.will(&radio.id).unwrap();
    assert!(will
        .body
        .clauses
        .iter()
        .any(|c| c.clock() == Some(Clock::KeepOperating)));
    assert!(will
        .body
        .clauses
        .iter()
        .any(|c| matches!(c, WillClause::Elect { clock, .. } if *clock == Clock::Elect)));
}
