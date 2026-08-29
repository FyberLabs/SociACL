use sociacl_core::{
    AuthnState, Client, CutBundle, DiscoverResult, EnrollmentKind, IssuerSecret, Plane,
    PredicateId, Relation, Timestamp, VerbError, Will,
};

fn heir_will(object: &str, testator: &str, heir: &str) -> Will {
    Will::heir(
        object,
        testator,
        heir,
        Timestamp(1),
        vec!["executor".into()],
    )
}

fn group_plane() -> (
    Plane,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
) {
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
fn offline_check_allows_on_a_precut_share() {
    let (plane, alice, _, _, doc) = group_plane();
    let live = plane.check_object("read", &doc, &alice).unwrap();
    assert!(live.allowed);

    let bundle = plane.export_bundle(&alice).unwrap();
    let share = bundle.share(&doc).expect("alice already held a share");
    assert_eq!(share.holder, alice);
    let key = share.reconstruct().unwrap();
    assert_eq!(key, plane.object(&doc).unwrap().content_key.unwrap());

    let client = bundle.open().unwrap();
    assert_eq!(client.reconstruct_share(&doc).unwrap(), key);
    let offline = client.check_object("read", &doc, &alice).unwrap();
    assert!(offline.allowed);
    assert_eq!(offline.reason, PredicateId::same_group());
    let zookie = client.exported_zookie(&doc).unwrap();
    assert_eq!(zookie.object_version, offline.zookie.object_version);
    assert_eq!(zookie.snapshot_hash, offline.zookie.snapshot_hash);
}

#[test]
fn offline_check_denies_principal_not_on_the_snapshot() {
    let (plane, alice, _, carol, doc) = group_plane();
    let client = plane.export_bundle(&alice).unwrap().open().unwrap();
    let denied = client.check_object("read", &doc, &carol).unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.reason, PredicateId::same_group());
}

#[test]
fn post_cut_edge_does_not_grant_on_the_client() {
    let (mut plane, alice, bob, _, doc) = group_plane();
    plane.unstate_edge(&bob, &bob, "ops", Relation::MemberOf);
    assert!(!plane.check_object("read", &doc, &bob).unwrap().allowed);

    plane.set_now(Timestamp(20));
    plane.set_cut(Timestamp(10));
    plane.jointly_state(&bob, "ops", Relation::MemberOf);
    assert!(
        !plane.check_object("read", &doc, &bob).unwrap().allowed,
        "live plane already refuses the post-cut edge"
    );

    let client = plane.export_bundle(&alice).unwrap().open().unwrap();
    assert!(!client.check_object("read", &doc, &bob).unwrap().allowed);
    assert!(!client.acl_names(&doc, &bob));
}

#[test]
fn remint_works_for_acl_named_principal_from_the_bundle() {
    let (plane, _, bob, _, doc) = group_plane();
    let client = plane.export_bundle(&bob).unwrap().open().unwrap();
    let cap = client.remint(&doc, &bob).unwrap();
    assert_eq!(cap.principal, bob);
    assert_eq!(cap.object, doc);
    assert_eq!(
        cap.zookie.object_version,
        client.exported_zookie(&doc).unwrap().object_version
    );
}

#[test]
fn elect_and_commit_elect_refuse_on_the_client() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane.write_will(heir_will("doc", "alice", "bob")).unwrap();
    plane.set_authn(&alice, AuthnState::Gone);

    let mut client = plane.export_bundle(&alice).unwrap().open().unwrap();
    assert_eq!(
        client.elect(&doc).unwrap_err(),
        VerbError::ClientRefusesElect
    );
    assert_eq!(
        client.commit_elect(&doc).unwrap_err(),
        VerbError::ClientRefusesElect
    );
    assert_eq!(client.object(&doc).unwrap().owner, alice);
    assert_ne!(client.object(&doc).unwrap().owner, bob);
}

#[test]
fn silence_and_missing_plane_do_not_elect() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane.write_will(heir_will("doc", "alice", "bob")).unwrap();

    let bundle = plane.export_bundle(&alice).unwrap();
    drop(plane);

    let mut client = bundle.open().unwrap();
    assert_eq!(client.authn(&alice), AuthnState::Live);
    assert_eq!(
        client.elect(&doc).unwrap_err(),
        VerbError::ClientRefusesElect
    );
    assert_eq!(
        client
            .elect_from_attestation(
                &doc,
                &sociacl_core::Attestation::new(
                    "alice",
                    "alice",
                    sociacl_core::AttestationClaim::IdentityLive,
                    Timestamp(0),
                    sociacl_core::AttestationBinding::ObjectVersion {
                        object: doc.clone(),
                        version: sociacl_core::ObjectVersion(1),
                    },
                )
            )
            .unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
    assert_eq!(client.object(&doc).unwrap().owner, alice);
    let _ = bob;
}

#[test]
fn discover_reports_only() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    plane.add_person("executor");
    let doc = plane.add_object("doc", &alice).id;
    plane.write_will(heir_will("doc", "alice", "bob")).unwrap();

    let client = plane.export_bundle(&alice).unwrap().open().unwrap();
    assert_eq!(
        client.discover(&doc).unwrap(),
        DiscoverResult::Heir(bob.clone())
    );
    assert_eq!(client.object(&doc).unwrap().owner, alice);
    assert!(
        client
            .check_named("read", &doc, &alice, PredicateId::owner())
            .unwrap()
            .allowed
    );

    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("executor");
    let ops = plane.add_circle("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will_src(
            "will desk for object doc\nwritten-by alice\ncancelable-by executor\nhighest-still-attesting-rank circle ops\n",
        )
        .unwrap();
    let client = plane.export_bundle(&alice).unwrap().open().unwrap();
    assert_eq!(
        client.discover(&doc).unwrap(),
        DiscoverResult::ElectAmong { circle: ops }
    );
    assert_eq!(client.object(&doc).unwrap().owner, alice);
}

#[test]
fn destroy_stay_secret_erases_local_key_and_does_not_install_an_owner() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .write_will(Will::stay_secret(&doc, &alice, Timestamp(1)))
        .unwrap();
    let key = plane.object(&doc).unwrap().content_key.unwrap();

    let mut client = plane.export_bundle(&alice).unwrap().open().unwrap();
    assert_eq!(client.local_key(&doc), Some(key));
    let owner_before = client.object(&doc).unwrap().owner.clone();

    let result = client.destroy(&doc).unwrap();
    assert!(result.erased);
    assert!(client.object(&doc).unwrap().destroyed);
    assert!(client.object(&doc).unwrap().content_key.is_none());
    assert!(client.local_key(&doc).is_none());
    assert_eq!(
        client.reconstruct_share(&doc).unwrap_err(),
        VerbError::ShareReconstruct(doc.clone())
    );
    assert_eq!(client.object(&doc).unwrap().owner, owner_before);
    assert_eq!(
        client.elect(&doc).unwrap_err(),
        VerbError::ClientRefusesElect
    );
}

#[test]
fn bundle_does_not_include_post_cut_material() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let station = plane.add_person("station").id;
    plane.add_person("executor");
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane.write_will(heir_will("doc", "alice", "bob")).unwrap();
    plane
        .enroll(
            &station,
            EnrollmentKind::Station,
            IssuerSecret::generate().verify_key(),
        )
        .unwrap();

    plane.set_now(Timestamp(20));
    plane.set_cut(Timestamp(10));
    plane.jointly_state(&bob, &ops, Relation::MemberOf);
    let late_key = IssuerSecret::generate().verify_key();
    assert!(matches!(
        plane.enroll("late", EnrollmentKind::Principal, late_key),
        Err(_)
    ));
    plane.add_person("late");
    assert!(plane
        .enroll("late", EnrollmentKind::Principal, late_key)
        .is_err());
    let late_will = Will::heir(&doc, &alice, &bob, Timestamp(21), vec!["executor".into()]);
    assert_eq!(
        plane.write_will(late_will).unwrap_err(),
        VerbError::PostCutWill(doc.clone())
    );

    let bundle = plane.export_bundle(&alice).unwrap();
    assert!(bundle
        .edges
        .iter()
        .all(|e| e.joint_at.map(|t| t.0 <= 10).unwrap_or(true)));
    assert!(!bundle
        .edges
        .iter()
        .any(|e| e.from == bob && e.to.as_str() == "ops"));
    assert!(bundle.enrollments.iter().all(|e| e.enrolled_at.0 <= 10));
    assert!(bundle.attestations.iter().all(|a| a.issued_at.0 <= 10));
    assert!(bundle
        .wills
        .iter()
        .all(|w| w.written_at.0 <= 10 && w.joint_at.0 <= 10));
    assert!(bundle.shares.iter().all(|s| s.held_at.0 <= 10));
}

#[test]
fn presented_post_cut_edge_is_refused() {
    let (plane, alice, bob, _, doc) = group_plane();
    let mut bundle = plane.export_bundle(&alice).unwrap();
    bundle.edges.push(sociacl_core::Edge {
        from: bob,
        to: doc,
        relation: Relation::Owns,
        from_stated: true,
        to_stated: true,
        joint_at: Some(Timestamp(99)),
        effective_at: Some(Timestamp(99)),
    });
    assert_eq!(bundle.open().unwrap_err(), VerbError::PostCutMaterial);
}

#[test]
fn rejoin_refuses_union_of_post_cut_clients() {
    let (plane, alice, bob, _, _) = group_plane();
    let left = plane.export_bundle(&alice).unwrap().open().unwrap();
    let right = plane.export_bundle(&bob).unwrap().open().unwrap();
    assert_eq!(
        left.rejoin(&right).unwrap_err(),
        VerbError::RejoinUnionRefused
    );
    assert!(left.check_object("read", "doc", &alice).unwrap().allowed);
    assert!(right.check_object("read", "doc", &bob).unwrap().allowed);
}

#[test]
fn live_check_still_allows_owner_after_export() {
    let (plane, alice, _, _, doc) = group_plane();
    let _bundle = plane.export_bundle(&alice).unwrap();
    let live = plane
        .check_named("read", &doc, &alice, PredicateId::same_group())
        .unwrap();
    assert!(live.allowed);
}

#[test]
fn export_refuses_a_principal_with_no_precut_right() {
    let (plane, _, _, carol, _) = group_plane();
    assert_eq!(
        plane.export_bundle(&carol).unwrap_err(),
        VerbError::NothingToExport(carol)
    );
}

#[test]
fn new_share_is_not_minted_after_the_cut() {
    let (mut plane, alice, bob, _, doc) = group_plane();
    plane.unstate_edge(&bob, &bob, "ops", Relation::MemberOf);
    plane.set_now(Timestamp(20));
    plane.set_cut(Timestamp(10));
    plane.jointly_state(&bob, "ops", Relation::MemberOf);
    assert_eq!(
        plane.export_bundle(&bob).unwrap_err(),
        VerbError::NothingToExport(bob.clone())
    );
    let bundle = plane.export_bundle(&alice).unwrap();
    assert!(bundle.share(&doc).is_some());
    assert!(!bundle.shares.iter().any(|s| s.holder == bob));
}

#[test]
fn durable_bytes_and_file_round_trip() {
    let (plane, alice, bob, _, doc) = group_plane();
    let bundle = plane.export_bundle(&alice).unwrap();
    let bytes = bundle.to_bytes();
    assert!(bytes.starts_with(b"SACL"));
    assert_eq!(
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        CutBundle::ENCODING_VERSION
    );

    let loaded = CutBundle::from_bytes(&bytes).unwrap();
    assert_eq!(loaded, bundle);

    let client = Client::from_bytes(&bytes).unwrap();
    assert!(client.check_object("read", &doc, &alice).unwrap().allowed);
    assert!(client.check_object("read", &doc, &bob).unwrap().allowed);
    let cap = client.remint(&doc, &bob).unwrap();
    assert_eq!(cap.principal, bob);

    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "sociacl-bundle-{}-{}.bin",
        std::process::id(),
        alice.as_str()
    ));
    bundle.write_path(&path).unwrap();
    let from_file = Client::from_path(&path).unwrap();
    assert!(
        from_file
            .check_object("read", &doc, &alice)
            .unwrap()
            .allowed
    );
    let _ = std::fs::remove_file(&path);

    let live = plane.check_object("read", &doc, &alice).unwrap();
    assert!(live.allowed);
}

#[test]
fn signed_attestation_survives_durable_round_trip() {
    let (mut plane, alice, _, _, doc) = group_plane();
    let secret = IssuerSecret::generate();
    plane
        .enroll(&alice, EnrollmentKind::Principal, secret.verify_key())
        .unwrap();
    let att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    plane.submit_attestation(att.clone()).unwrap();

    let bundle = plane.export_bundle(&alice).unwrap();
    assert_eq!(bundle.attestations.len(), 1);
    assert!(bundle.attestations[0].verify(&secret.verify_key()));
    assert!(bundle.enrollments.iter().all(|e| e.public_key.is_valid()));

    let bytes = bundle.to_bytes();
    assert_eq!(
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        CutBundle::ENCODING_VERSION
    );
    assert_eq!(CutBundle::ENCODING_VERSION, 2);

    let loaded = CutBundle::from_bytes(&bytes).unwrap();
    assert_eq!(loaded.attestations, bundle.attestations);
    assert_eq!(loaded.enrollments, bundle.enrollments);

    let mut client = Client::from_bytes(&bytes).unwrap();
    let result = client
        .check(sociacl_core::CheckRequest {
            action: "read".into(),
            object: doc.clone(),
            accessor: alice.clone(),
            predicate: None,
            zookie: None,
            attestation: Some(loaded.attestations[0].clone()),
        })
        .unwrap();
    assert!(result.allowed);
    assert!(result.attestation_factor.is_some());
    assert_eq!(
        client.elect_from_attestation(&doc, &att).unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
}

#[test]
fn unsigned_or_v1_bundle_is_refused() {
    let (mut plane, alice, _, _, doc) = group_plane();
    let secret = IssuerSecret::generate();
    plane
        .enroll(&alice, EnrollmentKind::Principal, secret.verify_key())
        .unwrap();
    let att = plane
        .identity_attestation(&alice, &alice, &doc)
        .unwrap()
        .sign(&secret);
    plane.submit_attestation(att).unwrap();
    let bundle = plane.export_bundle(&alice).unwrap();

    let mut v1 = bundle.to_bytes();
    v1[4] = 1;
    v1[5] = 0;
    assert_eq!(
        CutBundle::from_bytes(&v1).unwrap_err(),
        VerbError::UnsupportedBundleVersion(1)
    );

    let mut unsigned = bundle.clone();
    unsigned.attestations[0].signature = sociacl_core::AttestationSig::empty();
    assert!(matches!(
        unsigned.open().unwrap_err(),
        VerbError::AttestationRejected(sociacl_core::AttestationError::BadSignature)
    ));
}

#[test]
fn tampered_or_post_cut_payload_is_refused() {
    let (plane, alice, bob, _, doc) = group_plane();
    let bundle = plane.export_bundle(&alice).unwrap();
    let mut bytes = bundle.to_bytes();

    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    assert_eq!(
        CutBundle::from_bytes(&bytes).unwrap_err(),
        VerbError::BundleCorrupt
    );
    assert_eq!(
        Client::from_bytes(&bytes).unwrap_err(),
        VerbError::BundleCorrupt
    );

    assert_eq!(
        CutBundle::from_bytes(b"XXXX").unwrap_err(),
        VerbError::BundleCorrupt
    );

    let mut bad_ver = bundle.to_bytes();
    bad_ver[4] = 99;
    bad_ver[5] = 0;
    assert_eq!(
        CutBundle::from_bytes(&bad_ver).unwrap_err(),
        VerbError::UnsupportedBundleVersion(99)
    );

    let mut post = bundle.clone();
    post.edges.push(sociacl_core::Edge {
        from: bob,
        to: doc,
        relation: Relation::Owns,
        from_stated: true,
        to_stated: true,
        joint_at: Some(Timestamp(99)),
        effective_at: Some(Timestamp(99)),
    });
    let post_bytes = post.to_bytes();
    assert_eq!(
        CutBundle::from_bytes(&post_bytes).unwrap_err(),
        VerbError::PostCutMaterial
    );
    assert_eq!(
        Client::from_bytes(&post_bytes).unwrap_err(),
        VerbError::PostCutMaterial
    );
}
