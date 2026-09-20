//! Network membership and owner censure.
//!
//! SociACL proves who owns and who is a member. It does not elect a
//! leader, run BFT, or discover peers.
//!
//! Run: `cargo run -p sociacl-core --example network`

use sociacl_core::{CensureReason, Plane, PredicateId};

fn main() {
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

    for (name, accessor) in [("alice", &alice), ("bob", &bob), ("mallory", &mallory)] {
        let result = plane
            .check_named("read", &net, accessor, PredicateId::same_network())
            .expect("named predicate");
        println!(
            "member {name}: allowed={} reason={}",
            result.allowed, result.reason
        );
    }

    plane
        .censure(&alice, &net, &bob, CensureReason::ActiveSabotage)
        .unwrap();
    let after = plane
        .check_named("read", &net, &bob, PredicateId::same_network())
        .unwrap();
    println!(
        "after sabotage censure bob: allowed={} audit={}",
        after.allowed,
        plane.audit(&net)[0].as_reason()
    );
}
