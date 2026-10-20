//! Gun adapter: hint is not a grant. Destination Check is.
//!
//! alice holds a claim. bob presents a handoff hint. Dest re-check
//! issues a `delegate` read. A Social Light hop may factor Check;
//! it cannot mint. Execute-without-read is the existing mask.
//! Elect from a hint fails. A permalink is a URL leaf.
//!
//! Run: `cargo run --locked -p sociacl-gun --example gun`

use sociacl_core::{ActionMask, PredicateId};
use sociacl_gun::{
    accept_hint, add_claim, add_item, add_principal, cancel, check_execute, check_see,
    elect_from_hint, FeedItem, FeedSource, HandoffHint, UrlLeaf, SEE,
};
use sociacl_ids::{PrincipalId, SourceKey};

fn principal(text: &str) -> PrincipalId {
    text.parse().expect("principal")
}

fn main() {
    let mut plane = sociacl_core::Plane::new();
    let alice = add_principal(
        &mut plane,
        &principal("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"),
    );
    let bob = add_principal(
        &mut plane,
        &principal("fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg.B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E"),
    );
    let claim = add_claim(&mut plane, "claim-1", &alice).unwrap();
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

    let leaf = UrlLeaf::parse("https://gi.rss3.io/decentralized/0xalice").unwrap();
    println!(
        "url leaf: normalized={} gun_node={}",
        leaf.normalized(),
        leaf.is_gun_node()
    );

    let item = FeedItem {
        id: "rss3:act/1#x".into(),
        source: FeedSource::Rss3,
        kind: "social".into(),
        author: "0xalice".into(),
        body: "hello".into(),
        ts: 1,
        permalink: leaf.normalized().to_string(),
        tags: vec!["social".into()],
        provenance: "rss3:gi".into(),
    };
    let source: SourceKey = "sr1:rss/https%3A%2F%2Fs3r.ch/feed%2F%CE%B1%231/feed"
        .parse()
        .unwrap();
    let feed = add_item(&mut plane, &item, &source, &alice).unwrap();
    plane
        .set_object_property(&feed, "predicate", PredicateId::OWNER)
        .unwrap();
    let feed_see = check_see(&plane, &feed, &alice, None).unwrap();
    println!("feed item: soul={} see={}", feed, feed_see.allowed);
}
