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
    let mut scoring_text = Zeroizing::new(String::new());
    let mut visible = 0;
    let mut previous = None;
    for ch in nfc.chars() {
        let cp = ch as u32;
        // Presentation selectors change rendering, not strength or visible length.
        if cp == 0xfe0f && previous.is_some_and(crate::emoji_variation::emoji_variation_base) {
            previous = Some(cp);
            continue;
        }
        if crate::unicode16::passphrase_hidden(cp) {
            return Err(weak(0, "passphrase contains a hidden character", Vec::new()));
        }
        scoring_text.push(ch);
        visible += 1;
        previous = Some(cp);
    }
    if visible < MIN_VISIBLE {
        return Err(weak(
            0,
            "passphrase needs at least 12 visible characters",
            Vec::new(),
        ));
    }
    let inputs = strength_inputs(principal.as_ref(), handle);
    let entropy = zxcvbn::zxcvbn(scoring_text.as_str(), &inputs);
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

// ASCII-only comparison matches TypeScript; retain distinct Unicode handles verbatim.
fn strength_inputs<'a>(principal: &'a str, handle: Option<&'a str>) -> Vec<&'a str> {
    let mut inputs = vec![principal];
    if let Some(handle) = handle {
        if !handle.is_empty() && !handle.eq_ignore_ascii_case(principal) {
            inputs.push(handle);
        }
    }
    inputs
}

#[cfg(test)]
mod tests {
    use super::strength_inputs;

    #[test]
    fn shared_strength_inputs_use_ascii_handle_deduplication() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../vectors/encrypted-discovery/strength-inputs.json"
        ))
        .unwrap();
        let principal = fixture["principal"].as_str().unwrap();
        for row in fixture["cases"].as_array().unwrap() {
            let expected: Vec<&str> = row["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            assert_eq!(
                strength_inputs(principal, row["handle"].as_str()),
                expected,
                "{}",
                row["name"]
            );
        }
    }
}
