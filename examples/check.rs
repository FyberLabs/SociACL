//! 3-node POSIX-shaped group Check.
//!
//! alice owns `doc`. alice and bob are in group `ops`. carol is not.
//! Run: `cargo run -p sociacl-core --example check`

use sociacl_core::{Plane, PredicateId, Relation};

fn main() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let carol = plane.add_person("carol").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;

    plane.jointly_state(&alice, &ops, Relation::MemberOf);
    plane.jointly_state(&bob, &ops, Relation::MemberOf);
    plane.jointly_state(&doc, &ops, Relation::ObjectGroup);

    for (name, accessor, predicate) in [
        ("alice owner", &alice, PredicateId::owner()),
        ("bob same-group", &bob, PredicateId::same_group()),
        ("carol same-group", &carol, PredicateId::same_group()),
    ] {
        let result = plane
            .check_named("read", &doc, accessor, predicate)
            .expect("named predicate");
        println!(
            "{name}: allowed={} reason={}",
            result.allowed, result.reason
        );
    }
}
