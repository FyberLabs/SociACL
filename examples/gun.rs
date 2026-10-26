//! Signed Gun ownership. Run: `cargo run -p sociacl-gun --example gun`.
//! The public test fixture supplies a signed object and authenticated genesis
//! history. A product must supply its own records and trusted current history.

use serde_json::Value;
use sociacl_gun::{accept_hint, HandoffHint, MeshSeeGraph, UrlLeaf, SEE};
use sociacl_ids::{history_state, ObjectId, PrincipalId, Reason, ResolutionContext};
use std::collections::{BTreeMap, BTreeSet};

fn main() {
    let fixture: Value = serde_json::from_str(include_str!("../vectors/mesh/v2/see.json")).unwrap();
    let case = fixture["accept"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "owner-path-needs-exact-principal")
        .unwrap();
    let record = &case["steps"][0]["record"];
    let owner: PrincipalId = record["owner"].as_str().unwrap().parse().unwrap();
    let object: ObjectId = record["object"].as_str().unwrap().parse().unwrap();
    let raw = &fixture["context"];
    let jwks = serde_json::from_value(raw["jwks"].clone()).unwrap();
    let policy = serde_json::from_value(raw["policy"].clone()).unwrap();
    let links = BTreeMap::new();
    let pinned = BTreeSet::new();
    // This fixture authenticates only the owner's genesis history.
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
    let mut graph = MeshSeeGraph::new();
    let hint =
        accept_hint(HandoffHint::parse(owner.as_ref(), object.as_ref(), Some(SEE), None).unwrap());
    assert!(
        !graph
            .check_see(&object, &owner, ctx.now, Some(&hint), None)
            .allowed
    );
    graph.put_object(record, &resolver, &ctx).unwrap();
    let checked = graph.check_see(&object, &owner, ctx.now, Some(&hint), None);
    assert!(checked.allowed);
    assert!(!checked.hint_is_grant());
    println!(
        "signed object: allowed={} reason={}",
        checked.allowed, checked.reason
    );
    let leaf = UrlLeaf::parse("https://Example.COM/item/1/#fragment").unwrap();
    assert!(!leaf.is_gun_node());
    println!("URL leaf: {}", leaf.normalized());
}
