//! Gun adapter: hint is not a grant. Destination Check is.
//!
//! alice holds a claim. bob presents a handoff hint. Dest re-check
//! issues a `delegate` read. Execute-without-read is the existing
//! mask. Elect from a hint fails. A permalink is a URL leaf.
//!
//! Run: `cargo run --locked -p sociacl-gun --example gun`

use sociacl_core::{ActionMask, PredicateId};
use sociacl_gun::{
    accept_hint, add_claim, add_wallet, cancel, check_execute, check_see, elect_from_hint,
    HandoffHint, UrlLeaf, SEE,
};

fn main() {
    let mut plane = sociacl_core::Plane::new();
    let alice = add_wallet(&mut plane, "0xalice");
    let bob = add_wallet(&mut plane, "0xbob");
    let claim = add_claim(&mut plane, "claim-1", &alice);
    plane
        .set_object_property(&claim, "predicate", PredicateId::DELEGATE)
        .unwrap();

    let hint = HandoffHint::parse(bob.as_str(), claim.as_str(), Some(SEE), Some("edge")).unwrap();
    let accepted = accept_hint(hint.clone());
    let hinted = check_see(&plane, &claim, &bob, Some(&accepted)).unwrap();
    println!(
        "hint alone: allowed={} hint_is_grant={}",
        hinted.allowed,
        hinted.hint_is_grant()
    );

    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::read(), None)
        .unwrap();
    let granted = check_see(&plane, &claim, &bob, Some(&hint)).unwrap();
    println!(
        "dest re-check: allowed={} reason={}",
        granted.allowed, granted.reason
    );

    cancel(&mut plane, &alice, &bob, &claim).unwrap();
    plane
        .jointly_delegate(&alice, &bob, &claim, ActionMask::execute(), None)
        .unwrap();
    let exec = check_execute(&plane, &claim, &bob, None).unwrap();
    let see = check_see(&plane, &claim, &bob, None).unwrap();
    println!(
        "execute-without-read: execute={} see={}",
        exec.allowed, see.allowed
    );

    match elect_from_hint(&mut plane, &claim, &hint) {
        Ok(_) => println!("elect-must-not-succeed"),
        Err(e) => println!("elect from hint: {e}"),
    }

    let leaf = UrlLeaf::parse("https://Example.COM/item/1/#x").unwrap();
    println!(
        "url leaf: normalized={} gun_node={}",
        leaf.normalized(),
        leaf.is_gun_node()
    );
}
