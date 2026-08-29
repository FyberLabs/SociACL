use sociacl_core::{
    Attestation, AttestationBinding, AttestationClaim, AttestationError, AttestationSig,
    CheckError, CheckRequest, EnrollmentKind, IssuerSecret, Plane, PredicateId, Timestamp,
    VerbError, VerifyKey,
};

fn enroll(plane: &mut Plane, issuer: &str, kind: EnrollmentKind) -> IssuerSecret {
    let secret = IssuerSecret::generate();
    plane.enroll(issuer, kind, secret.verify_key()).unwrap();
    secret
}

#[test]
fn enroll_without_a_valid_key_fails_closed() {
    let mut plane = Plane::new();
    plane.add_person("alice");
    assert_eq!(
        plane.enroll("alice", EnrollmentKind::Principal, VerifyKey([0; 32])),
        Err(AttestationError::InvalidVerifyKey)
    );
    assert!(plane.enrollment(&"alice".into()).is_none());
}

#[test]
fn oracle_refuses_unenrolled_issuer() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = IssuerSecret::generate();
    let att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    assert_eq!(
        plane.accept_attestation(&att),
        Err(AttestationError::NotEnrolled(alice))
    );
}

#[test]
fn oracle_accepts_pre_enrolled_issuer() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    plane.accept_attestation(&att).unwrap();
}

#[test]
fn silence_and_loud_claims_are_unnamed_or_forbidden() {
    for s in ["silence", "loud", "vacancy", "flash", "ping", "death"] {
        assert!(
            matches!(
                AttestationClaim::parse(s),
                Err(AttestationError::ForbiddenClaim(_))
            ),
            "{s}"
        );
    }
    assert!(matches!(
        AttestationClaim::parse("friend-now"),
        Err(AttestationError::UnnamedClaim(_))
    ));
}

#[test]
fn check_may_consume_identity_not_station_liveness() {
    assert!(AttestationClaim::IdentityLive.check_may_consume());
    assert!(AttestationClaim::DeviceLive.check_may_consume());
    assert!(!AttestationClaim::StationLiveness.check_may_consume());
    assert!(AttestationClaim::StationLiveness.remint_may_consume());
}

#[test]
fn check_rejects_station_liveness_factor() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let station = plane.add_device("station-a").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "station-a", EnrollmentKind::Station);
    let att = plane
        .station_liveness_attestation(&station, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let err = plane
        .check(CheckRequest {
            action: "read".into(),
            object: doc,
            accessor: alice,
            predicate: None,
            zookie: None,
            attestation: Some(att),
        })
        .unwrap_err();
    assert!(matches!(
        err,
        CheckError::AttestationRejected(AttestationError::CheckMustNotConsume(_))
    ));
}

#[test]
fn missing_attestation_does_not_fail_check() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let result = plane.check_object("read", &doc, &alice).unwrap();
    assert!(result.allowed);
    assert!(result.attestation_factor.is_none());
}

#[test]
fn post_cut_enrollment_and_attestation_do_not_grant() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    let alice_secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let pre = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&alice_secret);
    plane.submit_attestation(pre.clone()).unwrap();

    plane.set_now(Timestamp(10));
    plane.set_cut(Timestamp(5));
    let bob_secret = IssuerSecret::generate();
    assert_eq!(
        plane.enroll(&bob, EnrollmentKind::Principal, bob_secret.verify_key()),
        Err(AttestationError::PostCutEnrollment(bob.clone()))
    );
    let post = Attestation::new(
        &bob,
        &bob,
        AttestationClaim::IdentityLive,
        Timestamp(11),
        AttestationBinding::ObjectVersion {
            object: doc.clone(),
            version: plane.object(&doc).unwrap().version,
        },
    )
    .sign(&bob_secret);
    assert_eq!(
        plane.accept_attestation(&post),
        Err(AttestationError::NotEnrolled(bob))
    );

    let late_alice = Attestation::new(
        &alice,
        &alice,
        AttestationClaim::IdentityLive,
        Timestamp(11),
        AttestationBinding::ObjectVersion {
            object: doc.clone(),
            version: plane.object(&doc).unwrap().version,
        },
    )
    .sign(&alice_secret);
    assert_eq!(
        plane.accept_attestation(&late_alice),
        Err(AttestationError::PostCutAttestation)
    );
    plane.accept_attestation(&pre).unwrap();
}

#[test]
fn remint_uses_station_liveness_without_naming_a_new_principal() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let station = plane.add_device("station-a").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "station-a", EnrollmentKind::Station);
    let att = plane
        .station_liveness_attestation(&station, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let cap = plane.remint_with_attestation(&doc, &alice, &att).unwrap();
    assert_eq!(cap.principal, alice);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn remint_without_acl_name_fails_even_with_station_liveness() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let station = plane.add_device("station-a").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "station-a", EnrollmentKind::Station);
    let att = plane
        .station_liveness_attestation(&station, &bob, &doc)
        .unwrap()
        .sign(&secret);
    let err = plane.remint_with_attestation(&doc, &bob, &att).unwrap_err();
    assert!(matches!(err, VerbError::AclDoesNotNamePrincipal(_, _)));
}

#[test]
fn forged_signature_is_refused() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let mut att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    att.signature.0[0] ^= 0xff;
    assert_eq!(
        plane.accept_attestation(&att),
        Err(AttestationError::BadSignature)
    );
}

#[test]
fn unsigned_digest_is_not_a_signature() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let mut att = plane.identity_attestation(&alice, &alice, &doc).unwrap();
    let digest = att.digest();
    att.signature.0[..32].copy_from_slice(&digest);
    assert_eq!(
        plane.accept_attestation(&att),
        Err(AttestationError::BadSignature)
    );
    att.signature = AttestationSig::empty();
    assert_eq!(
        plane.accept_attestation(&att),
        Err(AttestationError::BadSignature)
    );
}

#[test]
fn swapped_issuer_is_refused() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    let alice_secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    enroll(&mut plane, "bob", EnrollmentKind::Principal);
    let mut att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&alice_secret);
    att.issuer = bob.clone();
    att.enrollment = bob;
    assert_eq!(
        plane.accept_attestation(&att),
        Err(AttestationError::BadSignature)
    );
}

#[test]
fn post_cut_key_does_not_grant() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let late = plane.add_person("late").id;
    let doc = plane.add_object("doc", &alice).id;
    let alice_secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    plane.set_now(Timestamp(10));
    plane.set_cut(Timestamp(5));
    let late_secret = IssuerSecret::generate();
    assert_eq!(
        plane.enroll(&late, EnrollmentKind::Principal, late_secret.verify_key()),
        Err(AttestationError::PostCutEnrollment(late.clone()))
    );
    let att = Attestation::new(
        &late,
        &alice,
        AttestationClaim::IdentityLive,
        Timestamp(4),
        AttestationBinding::ObjectVersion {
            object: doc.clone(),
            version: plane.object(&doc).unwrap().version,
        },
    )
    .sign(&late_secret);
    assert_eq!(
        plane.accept_attestation(&att),
        Err(AttestationError::NotEnrolled(late))
    );
    let ok = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&alice_secret);
    // issued_at is now (10), after the cut
    assert_eq!(
        plane.accept_attestation(&ok),
        Err(AttestationError::PostCutAttestation)
    );
}

#[test]
fn identity_factor_on_owner_check_records_without_changing_allow() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let result = plane
        .check(CheckRequest {
            action: "read".into(),
            object: doc,
            accessor: alice,
            predicate: None,
            zookie: None,
            attestation: Some(att),
        })
        .unwrap();
    assert!(result.allowed);
    assert_eq!(result.reason, PredicateId::owner());
    assert!(result.attestation_factor.is_some());
}

#[test]
fn elect_from_attestation_always_refuses() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let err = plane.elect_from_attestation(&doc, &att).unwrap_err();
    assert_eq!(err, VerbError::ElectDoesNotFireOnAttestation);
}
