use sociacl_core::{AuthnState, CensureReason, Plane, PredicateId, Relation, VerbError};

fn mesh() -> (
    Plane,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
    sociacl_core::NodeId,
) {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let mallory = plane.add_person("mallory").id;
    let net = plane.add_network("panopticon");
    plane.add_object(&net, &alice);
    plane
        .set_object_property(&net, "predicate", PredicateId::SAME_NETWORK)
        .unwrap();
    plane.admit_member(&alice, &net).unwrap();
    plane.admit_member(&bob, &net).unwrap();
    (plane, alice, bob, mallory, net)
}

#[test]
fn same_network_allows_member() {
    let (plane, _, bob, _, net) = mesh();
    let result = plane
        .check_named("read", &net, &bob, PredicateId::same_network())
        .unwrap();
    assert!(result.allowed);
    assert_eq!(result.reason, PredicateId::same_network());
    assert!(plane.is_member(&bob, &net));
}

#[test]
fn same_network_denies_outsider() {
    let (plane, _, _, mallory, net) = mesh();
    let result = plane
        .check_named("read", &net, &mallory, PredicateId::same_network())
        .unwrap();
    assert!(!result.allowed);
    assert!(!plane.is_member(&mallory, &net));
}

#[test]
fn owner_predicate_still_holds_on_the_network_object() {
    let (mut plane, alice, bob, _, net) = mesh();
    plane
        .set_object_property(&net, "predicate", PredicateId::OWNER)
        .unwrap();
    let owner = plane
        .check_named("write", &net, &alice, PredicateId::owner())
        .unwrap();
    assert!(owner.allowed);
    let member = plane
        .check_named("write", &net, &bob, PredicateId::owner())
        .unwrap();
    assert!(!member.allowed);
}

#[test]
fn one_sided_in_network_is_not_a_grant() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let net = plane.add_network("mesh");
    plane.add_object(&net, &alice);
    plane
        .set_object_property(&net, "predicate", PredicateId::SAME_NETWORK)
        .unwrap();
    plane.state_edge(&bob, &bob, &net, Relation::InNetwork);
    let result = plane
        .check_named("read", &net, &bob, PredicateId::same_network())
        .unwrap();
    assert!(!result.allowed);
}

#[test]
fn object_naming_a_network_uses_same_membership() {
    let (mut plane, alice, bob, mallory, _net) = mesh();
    let share = plane.add_object("share", &alice).id;
    plane
        .set_object_property(&share, "predicate", PredicateId::SAME_NETWORK)
        .unwrap();
    plane
        .set_object_property(&share, "network", "panopticon")
        .unwrap();
    assert!(
        plane
            .check_named("read", &share, &bob, PredicateId::same_network())
            .unwrap()
            .allowed
    );
    assert!(
        !plane
            .check_named("read", &share, &mallory, PredicateId::same_network())
            .unwrap()
            .allowed
    );
}

#[test]
fn remint_names_a_live_member() {
    let (plane, _, bob, mallory, net) = mesh();
    let cap = plane.remint(&net, &bob).unwrap();
    assert_eq!(cap.principal, bob);
    let err = plane.remint(&net, &mallory).unwrap_err();
    assert!(matches!(err, VerbError::AclDoesNotNamePrincipal(_, _)));
}

#[test]
fn owner_censures_sabotage_and_check_denies() {
    let (mut plane, alice, bob, _, net) = mesh();
    let record = plane
        .censure(&alice, &net, &bob, CensureReason::ActiveSabotage)
        .unwrap();
    assert_eq!(record.reason, CensureReason::ActiveSabotage);
    assert!(
        !plane
            .check_named("read", &net, &bob, PredicateId::same_network())
            .unwrap()
            .allowed
    );
    assert_eq!(plane.audit(&net).len(), 1);
    assert_eq!(plane.audit(&net)[0].member, bob);
}

#[test]
fn member_may_self_leave() {
    let (mut plane, _, bob, _, net) = mesh();
    plane
        .censure(&bob, &net, &bob, CensureReason::SelfLeave)
        .unwrap();
    assert!(!plane.is_member(&bob, &net));
}

#[test]
fn member_cannot_censure_another() {
    let (mut plane, _, bob, mallory, net) = mesh();
    plane.admit_member(&mallory, &net).unwrap();
    let err = plane
        .censure(&bob, &net, &mallory, CensureReason::PolicyViolation)
        .unwrap_err();
    assert_eq!(err, VerbError::CannotCensure(bob));
    assert!(plane.is_member(&mallory, &net));
}

#[test]
fn owner_cannot_record_self_leave_for_another() {
    let (mut plane, alice, bob, _, net) = mesh();
    let err = plane
        .censure(&alice, &net, &bob, CensureReason::SelfLeave)
        .unwrap_err();
    assert_eq!(err, VerbError::CannotCensure(alice));
}

#[test]
fn outsider_cannot_censure() {
    let (mut plane, _, bob, mallory, net) = mesh();
    let err = plane
        .censure(&mallory, &net, &bob, CensureReason::PolicyViolation)
        .unwrap_err();
    assert_eq!(err, VerbError::CannotCensure(mallory));
}

#[test]
fn gone_authn_cannot_censure() {
    let (mut plane, alice, bob, _, net) = mesh();
    plane.set_authn(&alice, AuthnState::Gone);
    let err = plane
        .censure(&alice, &net, &bob, CensureReason::UnintentionalFailure)
        .unwrap_err();
    assert_eq!(err, VerbError::AuthnNotLive(alice));
}

#[test]
fn censure_is_not_a_grant() {
    let (mut plane, alice, _, mallory, net) = mesh();
    plane
        .censure(&alice, &net, &mallory, CensureReason::PolicyViolation)
        .unwrap();
    assert!(
        !plane
            .check_named("read", &net, &mallory, PredicateId::same_network())
            .unwrap()
            .allowed
    );
}

#[test]
fn elect_refuses_while_owner_authn_is_live() {
    let (mut plane, _, _, _, net) = mesh();
    let err = plane.elect(&net).unwrap_err();
    assert!(matches!(err, VerbError::KeepOperatingSuffices(_)));
}
