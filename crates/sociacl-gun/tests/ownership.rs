use serde_json::Value;
use sociacl_gun::{accept_hint, HandoffHint, MeshSeeGraph};
use sociacl_ids::{history_state, ObjectId, PrincipalId, Reason, ResolutionContext};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn core_owner_and_unsigned_records_cannot_establish_mesh_ownership() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../vectors/mesh/v2/see.json")).unwrap();
    let case = fixture["accept"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "owner-path-needs-exact-principal")
        .unwrap();
    let record = &case["steps"][0]["record"];
    let owner: PrincipalId = record["owner"].as_str().unwrap().parse().unwrap();
    let object: ObjectId = record["object"].as_str().unwrap().parse().unwrap();
    let accessor: PrincipalId = fixture["context"]["authenticatedAccounts"][1]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mut core = sociacl_core::Plane::new();
    core.add_person(owner.as_ref());
    core.add_object(object.as_ref(), owner.as_ref());
    let mut graph = MeshSeeGraph::new();
    let hint = accept_hint(
        HandoffHint::parse(owner.as_ref(), object.as_ref(), Some("see"), None).unwrap(),
    );
    assert!(
        !graph
            .check_see(&object, &owner, 10, Some(&hint), None)
            .allowed
    );

    let raw = &fixture["context"];
    let jwks = serde_json::from_value(raw["jwks"].clone()).unwrap();
    let policy = serde_json::from_value(raw["policy"].clone()).unwrap();
    let links = BTreeMap::new();
    let pinned = BTreeSet::new();
    let history = |principal: &PrincipalId, at, until| {
        if principal != &owner {
            return Err(Reason::MissingHistory);
        }
        Ok(history_state(principal, &[], at, until))
    };
    let resolver = |principal: &PrincipalId| (principal == &owner).then(Vec::new);
    let ctx = ResolutionContext {
        jwks: &jwks,
        links: &links,
        revocations: &[],
        now: raw["now"].as_u64().unwrap(),
        policy: &policy,
        pinned_iss: &pinned,
        history: &history,
        genesis_epub_bindings: &[],
    };
    let mut unsigned = record.clone();
    unsigned.as_object_mut().unwrap().remove("sig");
    assert_eq!(
        graph.put_object(&unsigned, &resolver, &ctx),
        Err(Reason::BadSignature)
    );
    let mut forged = record.clone();
    forged["issuedAt"] = (record["issuedAt"].as_u64().unwrap() + 1).into();
    assert_eq!(
        graph.put_object(&forged, &resolver, &ctx),
        Err(Reason::BadSignature)
    );
    assert!(
        !graph
            .check_see(&object, &owner, ctx.now, Some(&hint), None)
            .allowed
    );
    assert_eq!(
        graph.put_object(record, &|_| None, &ctx),
        Err(Reason::MissingHistory)
    );
    assert_eq!(graph.put_object(record, &resolver, &ctx), Ok(true));
    assert!(
        graph
            .check_see(&object, &owner, ctx.now, None, None)
            .allowed
    );
    assert!(
        !graph
            .check_see(&object, &accessor, ctx.now, None, None)
            .allowed
    );
    // A rejected overwrite must not replace the verified owner.
    let mut wrong_owner = record.clone();
    wrong_owner["owner"] = accessor.as_ref().into();
    assert!(graph.put_object(&wrong_owner, &resolver, &ctx).is_err());
    assert!(
        graph
            .check_see(&object, &owner, ctx.now, None, None)
            .allowed
    );
    assert!(
        !graph
            .check_see(&object, &accessor, ctx.now, None, None)
            .allowed
    );
}
