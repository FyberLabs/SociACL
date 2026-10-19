//! Group predicate checks. Shared vectors cover admission.
//! A hop is echoed and is not a grant.

use crate::{GroupPredicate, GroupPresentation};

#[test]
fn hop_is_not_a_grant() {
    let presentation = GroupPresentation {
        allowed: true,
        reason: GroupPredicate::SameGroup.as_str().into(),
        hint: None,
        hop: None,
        store_cancel: false,
    };
    assert!(!presentation.hop_is_grant());
    assert!(!presentation.hint_is_grant());
    assert!(!presentation.hop_factored());
}
