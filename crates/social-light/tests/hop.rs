use sociacl_core::{
    CheckRequest, NodeKind, Plane, PredicateId, Relation, SocialLightStatement, VerbError,
};
use social_light::{EnrollmentKind, IssuerSecret, Lab, LocalHop, SocialLightView};

fn graph(station: &IssuerSecret) -> Plane {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
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
fn two_socket_hop_through_discover_and_remint() {
    let station = IssuerSecret::generate();
    let mut lab = Lab::new();
    lab.add_plane("alice-phone", NodeKind::Device, graph(&station));
    lab.add_plane("bob-badge", NodeKind::Device, graph(&station));

    let badge = lab
        .node(&"bob-badge".into())
        .unwrap()
        .live()
        .unwrap()
        .identity_attestation("alice", "bob", &"desk-notes".into())
        .unwrap()
        .sign(&station);
    let flash = SocialLightStatement::convention_badge(badge).with_share_token("booth-12");
    let bytes = flash.encode().unwrap();

    let alice_hop = LocalHop::bind().unwrap();
    let bob_hop = LocalHop::bind().unwrap();
    bob_hop
        .send(&flash, alice_hop.local_addr().unwrap())
        .unwrap();
    let (heard, from) = alice_hop.recv().unwrap();
    assert_eq!(from, bob_hop.local_addr().unwrap());
    assert_eq!(heard, flash);

    let accepted = lab.accept_bytes("alice-phone", &bytes).unwrap();
    assert_eq!(accepted.channel, flash.channel);
    let view = lab.discover_bytes("alice-phone", &bytes).unwrap();
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

    let remint = lab
        .node(&"alice-phone".into())
        .unwrap()
        .live()
        .unwrap()
        .station_liveness_attestation("station-hall", "alice", &"desk-notes".into())
        .unwrap()
        .sign(&station);
    let remint_bytes = SocialLightStatement::enrolled_station(remint)
        .encode()
        .unwrap();
    alice_hop
        .send_bytes(&remint_bytes, bob_hop.local_addr().unwrap())
        .unwrap();
    let (remint_heard, _) = bob_hop.recv().unwrap();
    let cap = lab
        .remint_bytes(
            "bob-badge",
            "desk-notes",
            "alice",
            &remint_heard.encode().unwrap(),
        )
        .unwrap();
    assert_eq!(cap.principal.as_str(), "alice");

    let check_bytes = SocialLightStatement::enrolled_station(
        lab.node(&"alice-phone".into())
            .unwrap()
            .live()
            .unwrap()
            .identity_attestation("station-hall", "alice", &"desk-notes".into())
            .unwrap()
            .sign(&station),
    )
    .encode()
    .unwrap();
    let checked = lab
        .check_bytes(
            "alice-phone",
            CheckRequest {
                action: "read".into(),
                object: "desk-notes".into(),
                accessor: "alice".into(),
                predicate: None,
                zookie: None,
                attestation: None,
            },
            &check_bytes,
        )
        .unwrap();
    assert!(checked.allowed);

    assert_eq!(
        lab.elect_from_flash("alice-phone", "desk-notes", &flash)
            .unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );
}

#[test]
fn emit_bytes_is_still_not_a_friend() {
    let station = IssuerSecret::generate();
    let mut lab = Lab::new();
    lab.add_plane("alice-phone", NodeKind::Device, graph(&station));
    lab.add_plane("bob-badge", NodeKind::Device, graph(&station));
    lab.reach("alice-phone", "bob-badge").unwrap();

    let att = lab
        .node(&"bob-badge".into())
        .unwrap()
        .live()
        .unwrap()
        .identity_attestation("alice", "bob", &"desk-notes".into())
        .unwrap()
        .sign(&station);
    let bytes = SocialLightStatement::convention_badge(att)
        .with_share_token("opt-in")
        .encode()
        .unwrap();
    assert_eq!(lab.emit_bytes("bob-badge", &bytes).unwrap(), 1);
    let inbox = lab.take_inbox("alice-phone").unwrap();
    let view = lab.discover("alice-phone", &inbox[0]).unwrap();
    assert_eq!(
        view,
        SocialLightView::LivingPerson {
            principal: "bob".into(),
            share_token: Some("opt-in".into()),
        }
    );
    assert!(!lab
        .node(&"alice-phone".into())
        .unwrap()
        .live()
        .unwrap()
        .edges()
        .iter()
        .any(|e| e.relation == sociacl_core::Relation::Friend));
}
