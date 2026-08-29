//! 3-node POSIX-mode Check.
//!
//! alice owns `doc` (mode 0640, group ops). bob is in ops. carol is not.
//! Run: `cargo run -p sociacl-core --example check`

use sociacl_core::{Plane, PredicateId, Relation};

fn main() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let carol = plane.add_person("carol").id;
    let ops = plane.add_group("ops");
    let doc = plane.add_object("doc", &alice).id;
    plane
        .set_object_property(&doc, "predicate", PredicateId::POSIX_MODE)
        .unwrap();
    plane.set_object_property(&doc, "group", "ops").unwrap();
    plane.set_object_property(&doc, "mode", "0640").unwrap();

    plane.jointly_state(&bob, &ops, Relation::MemberOf);

    for (name, accessor) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let result = plane
            .check_named("read", &doc, accessor, PredicateId::posix_mode())
            .expect("named predicate");
        println!(
            "{name}: allowed={} reason={}",
            result.allowed, result.reason
        );
    }
}
