use sociacl_core::{
    AttestationChannel, AttestationError, CheckRequest, Client, EnrollmentKind, HolderSecret,
    IssuerSecret, Plane, PredicateId, SocialLightStatement, SocialLightView, VerbError,
};

fn enroll(plane: &mut Plane, issuer: &str, kind: EnrollmentKind) -> IssuerSecret {
    let secret = IssuerSecret::generate();
    plane.enroll(issuer, kind, secret.verify_key()).unwrap();
    secret
}

#[test]
fn named_channels_only() {
    assert_eq!(
        AttestationChannel::parse("convention-badge").unwrap(),
        AttestationChannel::ConventionBadge
    );
    assert_eq!(
        AttestationChannel::parse("enrolled-station").unwrap(),
        AttestationChannel::EnrolledStation
    );
    for s in [
        "lightiff",
        "field-iff",
        "waveform",
        "flash",
        "ping",
        "nearby",
    ] {
        assert!(
            matches!(
                AttestationChannel::parse(s),
                Err(AttestationError::ForbiddenChannel(_))
            ),
            "{s}"
        );
    }
    assert!(matches!(
        AttestationChannel::parse("friend-now"),
        Err(AttestationError::UnnamedChannel(_))
    ));
}

#[test]
fn convention_badge_discover_reports_person_not_heir() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let att = plane
        .identity_attestation(&alice, &bob, &doc)
        .unwrap()
        .sign(&secret);
    let light = SocialLightStatement::convention_badge(att).with_share_token("booth-12");

    let view = plane.discover_social_light(&light).unwrap();
    assert_eq!(
        view,
        SocialLightView::LivingPerson {
            principal: bob.clone(),
            share_token: Some("booth-12".into()),
        }
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
    assert!(!plane.acl_names(&doc, &bob));
}

#[test]
fn enrolled_station_is_a_remint_and_check_factor() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let station = plane.add_device("station-hall").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "station-hall", EnrollmentKind::Station);

    let live = plane
        .identity_attestation(&station, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let check_light = SocialLightStatement::enrolled_station(live);
    let checked = plane
        .check_social_light(
            CheckRequest {
                action: "read".into(),
                object: doc.clone(),
                accessor: alice.clone(),
                predicate: None,
                zookie: None,
                attestation: None,
            },
            &check_light,
        )
        .unwrap();
    assert!(checked.allowed);
    assert!(checked.attestation_factor.is_some());
    assert_eq!(checked.reason, PredicateId::owner());

    let station_live = plane
        .station_liveness_attestation(&station, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let remint_light = SocialLightStatement::enrolled_station(station_live);
    let cap = plane
        .remint_social_light(&doc, &alice, &remint_light)
        .unwrap();
    assert_eq!(cap.principal, alice);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn convention_badge_does_not_remint() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let light = SocialLightStatement::convention_badge(att);
    let err = plane.remint_social_light(&doc, &alice, &light).unwrap_err();
    assert!(matches!(
        err,
        VerbError::AttestationRejected(AttestationError::ChannelMustNotConsume(_))
    ));
}

#[test]
fn elect_from_a_flash_always_fails() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let light = SocialLightStatement::convention_badge(att.clone());
    assert_eq!(
        plane.elect_from_social_light(&doc, &light).unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );

    let secret = HolderSecret::generate();
    let mut client = Client::from_bytes(
        &plane.export_bundle_bytes(&alice, &secret).unwrap(),
        &secret,
    )
    .unwrap();
    assert_eq!(
        client.elect_from_social_light(&doc, &light).unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
}

#[test]
fn unenrolled_or_forbidden_claim_fails_closed() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = IssuerSecret::generate();
    let att = plane
        .identity_attestation(&bob, &bob, &doc)
        .unwrap()
        .sign(&secret);
    let light = SocialLightStatement::convention_badge(att);
    assert_eq!(
        plane.discover_social_light(&light).unwrap_err(),
        VerbError::AttestationRejected(AttestationError::NotEnrolled(bob))
    );
}

#[test]
fn sealed_client_still_consumes_a_precut_badge() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let att = plane
        .identity_attestation(&alice, &bob, &doc)
        .unwrap()
        .sign(&secret);
    let light = SocialLightStatement::convention_badge(att).with_share_token("opt-in");
    plane.submit_attestation(light.attestation.clone()).unwrap();

    let holder = HolderSecret::generate();
    let client = Client::from_bytes(
        &plane.export_bundle_bytes(&alice, &holder).unwrap(),
        &holder,
    )
    .unwrap();
    let view = client.discover_social_light(&light).unwrap();
    assert_eq!(
        view,
        SocialLightView::LivingPerson {
            principal: bob,
            share_token: Some("opt-in".into()),
        }
    );
    assert_eq!(client.object(&doc).unwrap().owner, alice);
}
