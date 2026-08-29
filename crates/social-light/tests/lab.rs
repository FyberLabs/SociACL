use sociacl_core::{
    CheckRequest, HolderSecret, NodeKind, Plane, PredicateId, Relation, SocialLightStatement,
    VerbError,
};
use social_light::{EnrollmentKind, IssuerSecret, Lab, SocialLightView};

fn graph(station: &IssuerSecret) -> Plane {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    plane.add_device("quiet");
    let hall = plane.add_device("station-hall").id;
    plane
        .enroll(&hall, EnrollmentKind::Station, station.verify_key())
        .unwrap();
    plane
        .enroll("alice", EnrollmentKind::Principal, station.verify_key())
        .unwrap();
    let ops = plane.add_group("ops");
    let doc = plane.add_object("desk-notes", &alice).id;
    plane
        .set_object_property(&doc, "predicate", PredicateId::SAME_GROUP)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();
    plane.jointly_state(&alice, &ops, Relation::MemberOf);
    plane.jointly_state("bob", &ops, Relation::MemberOf);
    plane.jointly_state(&doc, &ops, Relation::ObjectGroup);
    plane
}

#[test]
fn flash_is_not_a_friend_and_quiet_is_not_owner() {
    let station = IssuerSecret::generate();
    let mut lab = Lab::new();
    lab.add_plane("alice-phone", NodeKind::Device, graph(&station));
    lab.add_plane("bob-badge", NodeKind::Device, graph(&station));
    lab.add_plane("quiet-laptop", NodeKind::Device, graph(&station));
    lab.reach("alice-phone", "bob-badge").unwrap();

    let att = lab
        .node(&"bob-badge".into())
        .unwrap()
        .live()
        .unwrap()
        .identity_attestation("alice", "bob", &"desk-notes".into())
        .unwrap()
        .sign(&station);
    let flash = SocialLightStatement::convention_badge(att).with_share_token("booth-12");
    assert_eq!(lab.emit("bob-badge", flash.clone()).unwrap(), 1);

    let inbox = lab.take_inbox("alice-phone").unwrap();
    let view = lab.discover("alice-phone", &inbox[0]).unwrap();
    assert_eq!(
        view,
        SocialLightView::LivingPerson {
            principal: "bob".into(),
            share_token: Some("booth-12".into()),
        }
    );

    let alice_plane = lab.node(&"alice-phone".into()).unwrap().live().unwrap();
    assert!(!alice_plane
        .edges()
        .iter()
        .any(|e| { e.relation == sociacl_core::Relation::Friend && e.from.as_str() == "bob" }));
    assert_eq!(
        alice_plane
            .object(&"desk-notes".into())
            .unwrap()
            .owner
            .as_str(),
        "alice"
    );
    assert!(lab.node(&"quiet-laptop".into()).unwrap().inbox().is_empty());
    assert_eq!(
        lab.elect_from_flash("quiet-laptop", "desk-notes", &flash)
            .unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
}

#[test]
fn partition_keeps_bundle_and_same_cut_rejoin() {
    let station = IssuerSecret::generate();
    let mut lab = Lab::new();
    lab.add_plane("alice-phone", NodeKind::Device, graph(&station));
    lab.add_plane("quiet-laptop", NodeKind::Device, graph(&station));

    let a = HolderSecret::generate();
    let q = HolderSecret::generate();
    lab.cut("alice-phone", "alice", &a).unwrap();
    lab.cut("quiet-laptop", "alice", &q).unwrap();

    let checked = lab
        .check(
            "alice-phone",
            CheckRequest {
                action: "read".into(),
                object: "desk-notes".into(),
                accessor: "alice".into(),
                predicate: None,
                zookie: None,
                attestation: None,
            },
            None,
        )
        .unwrap();
    assert!(checked.allowed);

    lab.rejoin("alice-phone", "quiet-laptop").unwrap();
    assert_eq!(
        lab.node_mut(&"alice-phone".into())
            .unwrap()
            .client_mut()
            .unwrap()
            .elect("desk-notes")
            .unwrap_err(),
        VerbError::ClientRefusesElect
    );
}
