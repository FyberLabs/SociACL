//! Parse and validate the example will templates.
//!
//! Run: `cargo run -p sociacl-core --example wills`

use sociacl_core::{EnrollmentKind, Plane, Relation, Will};

const TEMPLATES: &[(&str, &str)] = &[
    ("posix-poor.will", include_str!("wills/posix-poor.will")),
    (
        "named-succession.will",
        include_str!("wills/named-succession.will"),
    ),
    ("device-will.will", include_str!("wills/device-will.will")),
];

fn main() {
    for (name, src) in TEMPLATES {
        let will = Will::parse(src).unwrap_or_else(|e| panic!("{name}: {e}"));
        println!(
            "{name}: name={} subject={} clauses={}",
            will.name,
            will.subject.kind_str(),
            will.body.clauses.len()
        );
        for c in &will.body.clauses {
            println!("  {}", c.name());
        }
    }

    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    plane.add_person("bob");
    plane.add_person("carol");
    plane.add_person("executor");
    plane.add_circle("operators");
    plane.add_circle("desk-ops");
    plane.add_device("station-alpha");
    plane.add_device("station-beta");
    plane.add_object("doc", &alice);
    plane.add_object("desk", &alice);
    let radio = plane.add_device("radio-1");
    plane.add_object(&radio.id, &alice);
    plane
        .enroll("station-alpha", EnrollmentKind::Station)
        .unwrap();
    plane
        .enroll("station-beta", EnrollmentKind::Station)
        .unwrap();
    plane.jointly_state(&alice, "operators", Relation::InCircle);
    plane.jointly_state("bob", "desk-ops", Relation::InCircle);

    for (name, src) in TEMPLATES {
        plane
            .write_will_src(src)
            .unwrap_or_else(|e| panic!("write {name}: {e}"));
        println!("wrote {name}");
    }
}
