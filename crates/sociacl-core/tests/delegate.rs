use sociacl_core::{
    ActionMask, AuthnState, CheckRequest, EnrollmentKind, IssuerSecret, Plane, PredicateId,
    Relation, Timestamp, VerbError, Will,
};

fn delegate_doc() -> (
    Plane,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
) {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let doc = plane.add_object("doc", &alice).id;
    plane
        .set_object_property(&doc, "predicate", PredicateId::DELEGATE)
        .unwrap();
    (plane, alice, bob, doc)
}

#[test]
fn view_allows_read_not_execute() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::read(), None)
        .unwrap();
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
    assert!(
        plane.check_object("read", &doc, &bob).unwrap().allowed,
        "view grant allows read"
    );
    assert!(
        !plane.check_object("execute", &doc, &bob).unwrap().allowed,
        "read-only mask denies execute"
    );
    assert!(!plane.check_object("write", &doc, &bob).unwrap().allowed);
    assert!(
        plane.check_object("read", &doc, &alice).unwrap().allowed == false,
        "owner is not implied by the delegate predicate"
    );
}

#[test]
fn authority_allows_write_owner_stays_owner() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::write(), None)
        .unwrap();
    assert!(plane.check_object("write", &doc, &bob).unwrap().allowed);
    assert!(!plane.check_object("read", &doc, &bob).unwrap().allowed);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn execute_without_view_allows_execute_denies_read() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::execute(), None)
        .unwrap();
    assert!(
        plane.check_object("execute", &doc, &bob).unwrap().allowed,
        "POSIX x-without-r: execute allows"
    );
    assert!(
        !plane.check_object("read", &doc, &bob).unwrap().allowed,
        "POSIX x-without-r: read denies"
    );
    assert!(!plane.check_object("write", &doc, &bob).unwrap().allowed);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn cancel_drops_immediately() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::read(), None)
        .unwrap();
    let before = plane.object(&doc).unwrap().version;
    plane.undelegate(&alice, &bob, &doc).unwrap();
    assert!(!plane.check_object("read", &doc, &bob).unwrap().allowed);
    assert!(plane.object(&doc).unwrap().version > before);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn until_elapsed_denies_owner_unchanged() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::read(), Some(Timestamp(50)))
        .unwrap();
    assert!(plane.check_object("read", &doc, &bob).unwrap().allowed);
    plane.set_now(Timestamp(50));
    assert!(
        !plane.check_object("read", &doc, &bob).unwrap().allowed,
        "until elapsed is grant expiry, not dead-hand ownership"
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
    assert!(
        !plane.acl_names(&doc, &bob),
        "expired grant no longer names the principal"
    );
}

#[test]
fn remint_refreshes_live_delegate_only() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::execute(), None)
        .unwrap();
    let cap = plane.remint(&doc, &bob).unwrap();
    assert_eq!(cap.principal, bob);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);

    plane.undelegate(&alice, &bob, &doc).unwrap();
    assert!(matches!(
        plane.remint(&doc, &bob).unwrap_err(),
        VerbError::AclDoesNotNamePrincipal(_, _)
    ));
}

#[test]
fn elect_from_a_delegate_grant_always_fails() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane.add_person("executor");
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::write(), None)
        .unwrap();
    plane
        .write_will(Will::heir(
            "doc",
            "alice",
            "bob",
            Timestamp(1),
            vec!["executor".into()],
        ))
        .unwrap();

    assert_eq!(
        plane.elect(&doc).unwrap_err(),
        VerbError::KeepOperatingSuffices(doc.clone())
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);

    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::write(), None)
        .unwrap();
    plane.set_authn(&alice, AuthnState::Gone);
    assert_eq!(
        plane.elect(&doc).unwrap_err(),
        VerbError::NoWill(doc.clone())
    );
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn hop_attestation_does_not_mint_a_delegate() {
    let (mut plane, _, bob, doc) = delegate_doc();
    let secret = IssuerSecret::generate();
    plane
        .enroll(&bob, EnrollmentKind::Principal, secret.verify_key())
        .unwrap();
    let att = plane
        .identity_attestation(&bob, &bob, &doc)
        .unwrap()
        .sign(&secret);
    let edges_before = plane.edges().len();
    let owner_before = plane.object(&doc).unwrap().owner.clone();

    let result = plane
        .check(CheckRequest {
            action: "read".into(),
            object: doc.clone(),
            accessor: bob.clone(),
            predicate: None,
            zookie: None,
            attestation: Some(att),
        })
        .unwrap();
    assert!(!result.allowed, "a hop is a factor, not a grant");
    assert!(result.attestation_factor.is_some());
    assert_eq!(plane.edges().len(), edges_before);
    assert_eq!(plane.object(&doc).unwrap().owner, owner_before);
    assert!(plane
        .edges()
        .iter()
        .all(|e| e.relation != Relation::Delegate));
}

#[test]
fn missing_hop_does_not_fail_check() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::read(), None)
        .unwrap();
    let result = plane.check_object("read", &doc, &bob).unwrap();
    assert!(result.allowed);
    assert!(result.attestation_factor.is_none());
}

#[test]
fn privilege_up_waits_for_accept_and_delay() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .delegate(&alice, &bob, &doc, ActionMask::read(), None)
        .unwrap();
    assert!(
        !plane.check_object("read", &doc, &bob).unwrap().allowed,
        "owner-only statement is not a grant"
    );
    plane.state_edge(&bob, &bob, &doc, Relation::Delegate);
    assert!(
        !plane.check_object("read", &doc, &bob).unwrap().allowed,
        "privilege-up waits for the delay"
    );
    plane.set_now(Timestamp(plane.now().0 + plane.privilege_up_delay().0));
    assert!(plane.check_object("read", &doc, &bob).unwrap().allowed);
    assert_eq!(plane.object(&doc).unwrap().owner, alice);
}

#[test]
fn non_owner_cannot_create_or_cancel() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    let carol = plane.add_person("carol").id;
    assert_eq!(
        plane
            .delegate(&carol, &bob, &doc, ActionMask::read(), None)
            .unwrap_err(),
        VerbError::CannotDelegate(carol.clone())
    );
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::read(), None)
        .unwrap();
    assert_eq!(
        plane.undelegate(&carol, &bob, &doc).unwrap_err(),
        VerbError::CannotDelegate(carol)
    );
    assert!(plane.check_object("read", &doc, &bob).unwrap().allowed);
}

#[test]
fn empty_mask_refused() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    assert_eq!(
        plane
            .delegate(&alice, &bob, &doc, ActionMask::none(), None)
            .unwrap_err(),
        VerbError::InvalidDelegateMask
    );
}

#[test]
fn posix_mode_is_not_merged() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .set_object_property(&doc, "predicate", PredicateId::POSIX_MODE)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();
    plane.set_object_property(&doc, "mode", "0640").unwrap();
    plane.jointly_state(&bob, &ops, Relation::MemberOf);
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::execute(), None)
        .unwrap();

    assert!(
        plane.check_object("read", &doc, &bob).unwrap().allowed,
        "posix-mode group read still holds"
    );
    assert!(
        !plane.check_object("execute", &doc, &bob).unwrap().allowed,
        "delegate execute is not mixed into posix-mode"
    );
}

#[test]
fn trustee_is_not_overloaded() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let trust = plane.add_object("trust", &alice).id;
    plane
        .set_object_property(&trust, "predicate", PredicateId::TRUSTEE)
        .unwrap();
    plane
        .jointly_delegate(&alice, &bob, &trust, ActionMask::read(), None)
        .unwrap();
    assert!(
        !plane.check_object("read", &trust, &bob).unwrap().allowed,
        "delegate edge is ignored when the object names trustee"
    );
    plane.jointly_state(&bob, &trust, Relation::Trustee);
    assert!(plane.check_object("read", &trust, &bob).unwrap().allowed);
}

#[test]
fn post_cut_new_delegate_does_not_grant_on_client() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane.set_now(Timestamp(20));
    plane.set_cut(Timestamp(10));
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::read(), None)
        .unwrap();
    assert!(
        !plane.check_object("read", &doc, &bob).unwrap().allowed,
        "live plane refuses a post-cut delegate"
    );

    let mut client = plane.export_bundle(&alice).unwrap().open().unwrap();
    assert!(!client.check_object("read", &doc, &bob).unwrap().allowed);
    assert!(!client.acl_names(&doc, &bob));
    assert_eq!(
        client.elect(&doc).unwrap_err(),
        VerbError::ClientRefusesElect
    );
    assert_eq!(client.object(&doc).unwrap().owner, alice);
}

#[test]
fn precut_delegate_survives_export_and_remint() {
    let (mut plane, alice, bob, doc) = delegate_doc();
    plane
        .jointly_delegate(&alice, &bob, &doc, ActionMask::execute(), None)
        .unwrap();
    let secret = sociacl_core::HolderSecret::generate();
    let bytes = plane.export_bundle_bytes(&bob, &secret).unwrap();
    let mut client = sociacl_core::Client::from_bytes(&bytes, &secret).unwrap();
    assert!(client.check_object("execute", &doc, &bob).unwrap().allowed);
    assert!(!client.check_object("read", &doc, &bob).unwrap().allowed);
    let cap = client.remint(&doc, &bob).unwrap();
    assert_eq!(cap.principal, bob);
    assert_eq!(client.object(&doc).unwrap().owner, alice);
    assert_eq!(
        client.elect(&doc).unwrap_err(),
        VerbError::ClientRefusesElect
    );
}
