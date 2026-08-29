use sociacl_core::{
    is_lightiff_shaped_id, Attestation, AttestationBinding, AttestationChannel, AttestationClaim,
    AttestationError, AttestationSig, CheckRequest, EnrollmentKind, HolderSecret, HopFrame,
    IssuerSecret, Plane, PredicateId, SocialLightStatement, SocialLightView, Timestamp, VerbError,
    HOP_MAGIC, HOP_VERSION,
};

fn enroll(plane: &mut Plane, issuer: &str, kind: EnrollmentKind) -> IssuerSecret {
    let secret = IssuerSecret::generate();
    plane.enroll(issuer, kind, secret.verify_key()).unwrap();
    secret
}

fn signed_badge(plane: &Plane, secret: &IssuerSecret) -> SocialLightStatement {
    let att = plane
        .identity_attestation("alice", "bob", &"doc".into())
        .unwrap()
        .sign(secret);
    SocialLightStatement::convention_badge(att).with_share_token("booth-12")
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// SLHP v1 as published by socialight-hop. Attestation stays opaque.
fn slhp_frame(channel: &str, attestation: &[u8], share_token: Option<&str>) -> Vec<u8> {
    let mut payload = Vec::new();
    put_str(&mut payload, channel);
    put_bytes(&mut payload, attestation);
    match share_token {
        Some(token) => {
            payload.push(1);
            put_str(&mut payload, token);
        }
        None => payload.push(0),
    }
    let mut out = Vec::new();
    out.extend_from_slice(HOP_MAGIC);
    out.extend_from_slice(&HOP_VERSION.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

fn att_bytes(issuer: &str, claim: &str) -> Vec<u8> {
    let mut w = Vec::new();
    put_str(&mut w, issuer);
    put_str(&mut w, "bob");
    put_str(&mut w, claim);
    w.extend_from_slice(&0u64.to_le_bytes());
    put_str(&mut w, issuer);
    put_str(&mut w, "object-version");
    put_str(&mut w, "doc");
    w.extend_from_slice(&1u64.to_le_bytes());
    put_bytes(&mut w, &[1u8; 64]);
    w
}

#[test]
fn hop_frame_round_trip() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    plane.add_object("doc", &alice);
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let light = signed_badge(&plane, &secret);

    let bytes = light.encode().unwrap();
    assert!(bytes.starts_with(b"SLHP"));
    assert_eq!(&bytes[4..6], &HOP_VERSION.to_le_bytes());
    let back = SocialLightStatement::decode(&bytes).unwrap();
    assert_eq!(back, light);

    let accepted = plane.accept_social_light_bytes(&bytes).unwrap();
    assert_eq!(accepted.share_token.as_deref(), Some("booth-12"));
}

#[test]
fn slhp_opaque_roundtrip_matches_socialight() {
    let hop = HopFrame::accept(
        HOP_VERSION,
        AttestationChannel::ConventionBadge,
        b"opaque-attestation".to_vec(),
        Some("booth-12".into()),
    )
    .unwrap();
    let bytes = hop.encode();
    assert_eq!(
        bytes,
        slhp_frame("convention-badge", b"opaque-attestation", Some("booth-12"))
    );
    let again = HopFrame::decode(&bytes).unwrap();
    assert_eq!(again, hop);
    // Decode does not verify. Garbage attestation bytes stay opaque.
    assert_eq!(again.attestation, b"opaque-attestation");
}

#[test]
fn hop_decode_does_not_verify() {
    let hop = HopFrame::accept(
        HOP_VERSION,
        AttestationChannel::EnrolledStation,
        vec![0u8; 8],
        None,
    )
    .unwrap();
    let again = HopFrame::decode(&hop.encode()).unwrap();
    assert_eq!(again.attestation, vec![0u8; 8]);
}

#[test]
fn unsigned_and_forged_frames_fail() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    plane.add_object("doc", &alice);
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let att = plane
        .identity_attestation("alice", "bob", &"doc".into())
        .unwrap();
    let unsigned = SocialLightStatement::convention_badge(att.clone());
    assert_eq!(
        unsigned.encode().unwrap_err(),
        AttestationError::UnsignedHopFrame
    );

    let signed = signed_badge(&plane, &secret);
    let mut hop = HopFrame::decode(&signed.encode().unwrap()).unwrap();
    hop.attestation = encode_unsigned_att();
    assert_eq!(
        SocialLightStatement::decode(&hop.encode()).unwrap_err(),
        AttestationError::UnsignedHopFrame
    );

    let mut forged_hop = HopFrame::decode(&signed.encode().unwrap()).unwrap();
    let last = forged_hop.attestation.len() - 1;
    forged_hop.attestation[last] ^= 0xff;
    let forged = forged_hop.encode();
    let decoded = SocialLightStatement::decode(&forged).unwrap();
    assert_eq!(
        plane.accept_social_light(&decoded).unwrap_err(),
        AttestationError::BadSignature
    );
    assert!(matches!(
        plane.accept_social_light_bytes(&forged).unwrap_err(),
        AttestationError::BadSignature
    ));
}

fn encode_unsigned_att() -> Vec<u8> {
    let att = Attestation {
        issuer: "alice".into(),
        subject: "bob".into(),
        claim: AttestationClaim::IdentityLive,
        issued_at: Timestamp(0),
        enrollment: "alice".into(),
        binding: AttestationBinding::ObjectVersion {
            object: "doc".into(),
            version: sociacl_core::ObjectVersion(1),
        },
        signature: AttestationSig::empty(),
    };
    let mut w = Vec::new();
    put_str(&mut w, att.issuer.as_str());
    put_str(&mut w, att.subject.as_str());
    put_str(&mut w, att.claim.as_str());
    w.extend_from_slice(&att.issued_at.0.to_le_bytes());
    put_str(&mut w, att.enrollment.as_str());
    put_str(&mut w, "object-version");
    put_str(&mut w, "doc");
    w.extend_from_slice(&1u64.to_le_bytes());
    put_bytes(&mut w, &att.signature.0);
    w
}

#[test]
fn forbidden_claim_and_unnamed_channel_fail() {
    assert!(matches!(
        SocialLightStatement::decode(&slhp_frame(
            "convention-badge",
            &att_bytes("alice", "flash"),
            None
        ))
        .unwrap_err(),
        AttestationError::ForbiddenClaim(_)
    ));
    assert!(matches!(
        HopFrame::decode(&slhp_frame("friend-now", b"opaque", None)).unwrap_err(),
        AttestationError::UnnamedChannel(_)
    ));
    assert!(matches!(
        HopFrame::decode(&slhp_frame("ping", b"opaque", None)).unwrap_err(),
        AttestationError::ForbiddenChannel(_)
    ));
    assert!(matches!(
        HopFrame::decode(&slhp_frame("lightiff", b"opaque", None)).unwrap_err(),
        AttestationError::ForbiddenChannel(_)
    ));
}

#[test]
fn lightiff_shaped_ids_fail_closed() {
    for id in [
        "lightiff",
        "light-iff",
        "field-iff",
        "iff",
        "alice-lightiff",
        "iff-station",
        "badge-iff",
    ] {
        assert!(is_lightiff_shaped_id(id), "{id}");
    }
    assert!(!is_lightiff_shaped_id("alice"));
    assert!(!is_lightiff_shaped_id("station-hall"));

    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    plane.add_object("doc", &alice);
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let mut att = plane
        .identity_attestation("alice", "bob", &"doc".into())
        .unwrap()
        .sign(&secret);
    att.issuer = "lightiff".into();
    att.enrollment = "lightiff".into();
    let light = SocialLightStatement::convention_badge(att);
    assert!(matches!(
        light.encode().unwrap_err(),
        AttestationError::ForbiddenChannel(_)
    ));

    assert!(matches!(
        SocialLightStatement::decode(&slhp_frame(
            "convention-badge",
            &att_bytes("field-iff", "identity-live"),
            None
        ))
        .unwrap_err(),
        AttestationError::ForbiddenChannel(_)
    ));
}

#[test]
fn convention_badge_bytes_discover_does_not_elect() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let bytes = signed_badge(&plane, &secret).encode().unwrap();

    let view = plane.discover_social_light_bytes(&bytes).unwrap();
    assert_eq!(
        view,
        SocialLightView::LivingPerson {
            principal: bob,
            share_token: Some("booth-12".into()),
        }
    );
    assert_eq!(view.as_reason(), "living-person bob share booth-12");
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
    assert_eq!(
        plane
            .elect_from_social_light_bytes(&doc, &bytes)
            .unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
}

#[test]
fn enrolled_station_bytes_remint_requires_acl_name() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let station = plane.add_device("station-hall").id;
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "station-hall", EnrollmentKind::Station);

    let live = plane
        .station_liveness_attestation(&station, &alice, &doc)
        .unwrap()
        .sign(&secret);
    let alice_bytes = SocialLightStatement::enrolled_station(live)
        .encode()
        .unwrap();
    let cap = plane
        .remint_social_light_bytes(&doc, &alice, &alice_bytes)
        .unwrap();
    assert_eq!(cap.principal, alice);

    let bob_live = plane
        .station_liveness_attestation(&station, &bob, &doc)
        .unwrap()
        .sign(&secret);
    let bob_bytes = SocialLightStatement::enrolled_station(bob_live)
        .encode()
        .unwrap();
    let err = plane
        .remint_social_light_bytes(&doc, &bob, &bob_bytes)
        .unwrap_err();
    assert_eq!(err, VerbError::AclDoesNotNamePrincipal(bob, doc.clone()));

    let checked = plane
        .check_social_light_bytes(
            CheckRequest {
                action: "read".into(),
                object: doc,
                accessor: alice.clone(),
                predicate: None,
                zookie: None,
                attestation: None,
            },
            &SocialLightStatement::enrolled_station(
                plane
                    .identity_attestation(&station, &alice, &"doc".into())
                    .unwrap()
                    .sign(&secret),
            )
            .encode()
            .unwrap(),
        )
        .unwrap();
    assert!(checked.allowed);
    assert_eq!(checked.reason, PredicateId::owner());
}

#[test]
fn sealed_client_consumes_hop_bytes() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    let doc = plane.add_object("doc", &alice).id;
    let secret = enroll(&mut plane, "alice", EnrollmentKind::Principal);
    let light = signed_badge(&plane, &secret);
    let bytes = light.encode().unwrap();
    plane.submit_attestation(light.attestation.clone()).unwrap();

    let holder = HolderSecret::generate();
    let mut client = sociacl_core::Client::from_bytes(
        &plane.export_bundle_bytes(&alice, &holder).unwrap(),
        &holder,
    )
    .unwrap();
    let view = client.discover_social_light_bytes(&bytes).unwrap();
    assert_eq!(view.as_reason(), "living-person bob share booth-12");
    assert_eq!(
        client
            .elect_from_social_light_bytes(&doc, &bytes)
            .unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
}

#[test]
fn empty_signature_is_not_a_signature() {
    let att = Attestation {
        issuer: "alice".into(),
        subject: "bob".into(),
        claim: AttestationClaim::IdentityLive,
        issued_at: Timestamp(0),
        enrollment: "alice".into(),
        binding: AttestationBinding::ObjectVersion {
            object: "doc".into(),
            version: sociacl_core::ObjectVersion(1),
        },
        signature: AttestationSig::empty(),
    };
    assert_eq!(
        SocialLightStatement::convention_badge(att)
            .encode()
            .unwrap_err(),
        AttestationError::UnsignedHopFrame
    );
}

#[test]
fn unknown_version_fails_closed() {
    let mut bytes = slhp_frame("convention-badge", b"x", None);
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        HopFrame::decode(&bytes).unwrap_err(),
        AttestationError::UnsupportedHopVersion(2)
    );
}
