use sociacl_core::Action;

use crate::{GunError, HandoffHint, SEE};

/// `see` is Check `read` on a Gun-native object (feed item or claim).
pub fn map_action(verb: &str) -> Action {
    match verb.trim() {
        SEE | "read" | "r" => Action::new("read"),
        "execute" | "exec" | "x" => Action::new("execute"),
        "write" | "w" => Action::new("write"),
        other => Action::new(other),
    }
}

/// Decode / accept an untrusted hint. Does not verify. Does not mint.
pub fn accept_hint(hint: HandoffHint) -> HandoffHint {
    hint
}

/// Decode hint bytes. Does not verify. Does not mint.
pub fn accept_hint_bytes(bytes: &[u8]) -> Result<HandoffHint, GunError> {
    HandoffHint::decode(bytes)
}
