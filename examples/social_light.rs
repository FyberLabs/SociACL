//! Three devices, one enrolled station, a voluntary convention badge,
//! and a quiet node that does not become owner.
//!
//! In-process only. A flash is a channel. SociACL is the authority.

use sociacl_core::{
    CheckRequest, HolderSecret, NodeKind, Plane, PredicateId, Relation, SocialLightStatement,
    VerbError,
};
use social_light::{
    AttestationChannel, EnrollmentKind, IssuerSecret, Lab, SocialLightView, Statement,
};

fn device_plane(station_secret: &IssuerSecret) -> Plane {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    plane.add_device("quiet");
    let station = plane.add_device("station-hall").id;
    plane
        .enroll(
            &station,
            EnrollmentKind::Station,
            station_secret.verify_key(),
        )
        .unwrap();
    plane
        .enroll(
            "alice",
            EnrollmentKind::Principal,
            station_secret.verify_key(),
        )
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

fn main() {
    let station_secret = IssuerSecret::generate();
    let mut lab = Lab::new();
    lab.add_plane(
        "alice-phone",
        NodeKind::Device,
        device_plane(&station_secret),
    );
    lab.add_plane("bob-badge", NodeKind::Device, device_plane(&station_secret));
    lab.add_plane(
        "quiet-laptop",
        NodeKind::Device,
        device_plane(&station_secret),
    );
    lab.reach("alice-phone", "bob-badge").unwrap();
    lab.reach("alice-phone", "quiet-laptop").unwrap();

    let bob_plane = lab.node(&"bob-badge".into()).unwrap().live().unwrap();
    let badge = bob_plane
        .identity_attestation("alice", "bob", &"desk-notes".into())
        .unwrap()
        .sign(&station_secret);
    let flash = SocialLightStatement::convention_badge(badge).with_share_token("booth-12");

    assert_eq!(lab.emit("bob-badge", flash.clone()).unwrap(), 1);
    let inbox = lab.take_inbox("alice-phone").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].channel, AttestationChannel::ConventionBadge);

    let view = lab.discover("alice-phone", &inbox[0]).unwrap();
    assert_eq!(
        view,
        SocialLightView::LivingPerson {
            principal: "bob".into(),
            share_token: Some("booth-12".into()),
        }
    );

    let quiet = lab.node(&"quiet-laptop".into()).unwrap();
    assert!(quiet.inbox().is_empty());
    let quiet_doc = quiet.live().unwrap().object(&"desk-notes".into()).unwrap();
    assert_eq!(quiet_doc.owner.as_str(), "alice");

    let station_live = lab
        .node(&"alice-phone".into())
        .unwrap()
        .live()
        .unwrap()
        .station_liveness_attestation("station-hall", "alice", &"desk-notes".into())
        .unwrap()
        .sign(&station_secret);
    let station = Statement::enrolled_station(station_live);
    let cap = lab
        .remint("alice-phone", "desk-notes", "alice", &station)
        .unwrap();
    assert_eq!(cap.principal.as_str(), "alice");

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
            Some(&SocialLightStatement::enrolled_station(
                lab.node(&"alice-phone".into())
                    .unwrap()
                    .live()
                    .unwrap()
                    .identity_attestation("station-hall", "alice", &"desk-notes".into())
                    .unwrap()
                    .sign(&station_secret),
            )),
        )
        .unwrap();
    assert!(checked.allowed);
    assert!(checked.attestation_factor.is_some());

    assert_eq!(
        lab.elect_from_flash("alice-phone", "desk-notes", &flash)
            .unwrap_err(),
        VerbError::ElectDoesNotFireOnAttestation
    );

    let alice_secret = HolderSecret::generate();
    let quiet_secret = HolderSecret::generate();
    lab.cut("alice-phone", "alice", &alice_secret).unwrap();
    lab.cut("quiet-laptop", "alice", &quiet_secret).unwrap();

    assert_eq!(
        lab.node_mut(&"quiet-laptop".into())
            .unwrap()
            .client_mut()
            .unwrap()
            .elect("desk-notes")
            .unwrap_err(),
        VerbError::ClientRefusesElect
    );
    assert_eq!(
        lab.node(&"quiet-laptop".into())
            .unwrap()
            .client()
            .unwrap()
            .object(&"desk-notes".into())
            .unwrap()
            .owner
            .as_str(),
        "alice"
    );

    lab.rejoin("alice-phone", "quiet-laptop").unwrap();
    println!("social-light lab: badge reported, quiet stayed quiet, rejoin kept the pre-cut owner");
}
