//! Live Elect ceremony. Keep-operating refuses. A live canceler can stop
//! a pending Elect. Commit installs only after the wait.
//!
//! Run: `cargo run -p sociacl-core --example elect`

use sociacl_core::{AuthnState, Plane, PredicateId, VerbError};

fn main() {
    let mut plane = Plane::new();
    let alice = plane.add_person("alice").id;
    let bob = plane.add_person("bob").id;
    let executor = plane.add_person("executor").id;
    let doc = plane.add_object("doc", &alice).id;
    let desk = plane.add_object("desk", &alice).id;
    plane
        .write_will_src(
            "will heir-doc for object doc\nwritten-by alice\ncancelable-by executor\ndiscover heir bob\n",
        )
        .unwrap();
    plane
        .write_will_src(
            "will heir-desk for object desk\nwritten-by alice\ncancelable-by executor\ndiscover heir bob\n",
        )
        .unwrap();

    match plane.elect(&doc) {
        Err(VerbError::KeepOperatingSuffices(_)) => {
            println!("elect while alice is live: keep-operating suffices")
        }
        other => panic!("expected keep-operating refuse, got {other:?}"),
    }

    plane.set_authn(&alice, AuthnState::Gone);
    let pending = plane.elect(&doc).unwrap();
    println!("elect started: {} (owner still alice)", pending.as_reason());
    assert_eq!(plane.object(&doc).unwrap().owner, alice);

    match plane.commit_elect(&doc) {
        Err(VerbError::ElectWaitNotElapsed(_)) => println!("commit before wait: refused"),
        other => panic!("expected wait, got {other:?}"),
    }

    plane.set_now(sociacl_core::Timestamp(
        plane.now().0 + plane.elect_wait().0,
    ));
    plane.cancel_will(&doc, &executor).unwrap();
    match plane.commit_elect(&doc) {
        Err(VerbError::WillCanceled(_)) => {
            println!("executor canceled; owner is still alice")
        }
        other => panic!("expected canceled, got {other:?}"),
    }

    plane.elect(&desk).unwrap();
    plane.set_now(sociacl_core::Timestamp(
        plane.now().0 + plane.elect_wait().0,
    ));
    let installed = plane.commit_elect(&desk).unwrap();
    println!("commit after wait: {}", installed.as_reason());
    let check = plane
        .check_named("read", &desk, &bob, PredicateId::owner())
        .unwrap();
    println!("bob owns desk: allowed={}", check.allowed);
}
