//! Seal-time passphrase strength.
//!
//! Open does not call this. A copy sealed before the gate, or under a
//! passphrase this gate would now refuse, still opens.
//!
//! The length and hidden-character rules are the same in both languages.
//! The zxcvbn score is advisory: the Rust crate and `@zxcvbn-ts/core` can
//! disagree near the threshold. The shared vector pins clear pass and fail
//! rows only.
//!
//! The error carries the score and feedback for the UI. It does not carry
//! the passphrase. Callers must not log the passphrase.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use sociacl_ids::PrincipalId;

use crate::error::EncDiscError;

const MIN_VISIBLE: usize = 12;
const MIN_SCORE: u8 = 3;

pub fn check_recovery_passphrase(
    passphrase: &[u8],
    principal: &PrincipalId,
    handle: Option<&str>,
) -> Result<(), EncDiscError> {
    let text = match std::str::from_utf8(passphrase) {
        Ok(text) => text,
        Err(_) => return Err(weak(0, "passphrase must be Unicode text", Vec::new())),
    };
    let mut nfc = Zeroizing::new(String::new());
    for ch in text.nfc() {
        nfc.push(ch);
    }
    if nfc
        .chars()
        .any(|ch| crate::unicode16::passphrase_hidden(ch as u32))
    {
        return Err(weak(
            0,
            "passphrase contains a hidden character",
            Vec::new(),
        ));
    }
    let visible = nfc.chars().count();
    if visible < MIN_VISIBLE {
        return Err(weak(
            0,
            "passphrase needs at least 12 visible characters",
            Vec::new(),
        ));
    }
    let principal_text = principal.as_ref();
    let mut inputs = vec![principal_text];
    if let Some(handle) = handle {
        if !handle.is_empty() && !handle.eq_ignore_ascii_case(principal_text) {
            inputs.push(handle);
        }
    }
    let entropy = zxcvbn::zxcvbn(nfc.as_str(), &inputs);
    let score = u8::from(entropy.score());
    if score >= MIN_SCORE {
        return Ok(());
    }
    let (warning, suggestions) = match entropy.feedback() {
        Some(feedback) => {
            let warning = feedback
                .warning()
                .map(|warning| warning.to_string())
                .unwrap_or_default();
            let suggestions = feedback
                .suggestions()
                .iter()
                .map(|suggestion| suggestion.to_string())
                .collect();
            (warning, suggestions)
        }
        None => (String::new(), Vec::new()),
    };
    Err(weak(score, warning, suggestions))
}

fn weak(score: u8, warning: impl Into<String>, suggestions: Vec<String>) -> EncDiscError {
    EncDiscError::RecoveryWeakPassphrase {
        score,
        warning: warning.into(),
        suggestions,
    }
}
