//! Canonical identity boundaries. Stored input is never normalized or repaired.
mod ids;
mod records;
mod uri;
pub use ids::*;
pub use records::*;

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Reason {
    NotString,
    Empty,
    TooLong,
    ControlChar,
    InvisibleChar,
    UnpairedSurrogate,
    Whitespace,
    BadAlphabet,
    BadLength,
    NonCanonical,
    BadChecksum,
    NotOnCurve,
    ReservedKind,
    UnknownNetwork,
    BadHost,
    BadPort,
    GunChain,
    BadTemplate,
    BadRecord,
    BadSignature,
    BadAttestation,
    UntrustedIssuer,
    Expired,
    FutureRecord,
    BadSequence,
    RotationFork,
    RotationConflict,
    UnknownLink,
    RevokedLink,
    AmbiguousLink,
    UnsupportedWallet,
    RngFailure,
    MissingHistory,
    UnretainedLink,
    WalletRequired,
    UnwitnessedRetiredKey,
    BadKey,
    LegacyRow,
    /// No admitted object record for this id.
    Unknown,
    /// The request status is withdrawn.
    Withdrawn,
    /// The caller is not the admitted object owner.
    OwnerMismatch,
    /// Members auto-approve did not allow this requester.
    NotMember,
    /// The next see ham state is not a safe integer.
    SeeCeiling,
    /// The next post ham state is not a safe integer.
    PostCeiling,
    /// The new row would not replace the stored row, or a cancel would be revived.
    NotKept,
}
impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self).map_err(|_| fmt::Error)?;
        f.write_str(s.as_str().ok_or(fmt::Error)?)
    }
}
impl std::error::Error for Reason {}

pub(crate) fn text(s: &str, max: usize) -> Result<&str, Reason> {
    if s.contains('\\')
        || s.contains("['get']")
        || s.contains("[\"get\"]")
        || s.match_indices("get").any(|(at, _)| {
            s[at + 3..].chars().find(|c| {
                !(matches!(
                    c,
                    ' ' | '\t' | '\r' | '\n' | '\u{b}' | '\u{c}' | '\u{a0}' | '\u{feff}'
                ) || ('\u{2000}'..='\u{200a}').contains(c)
                    || matches!(
                        c,
                        '\u{1680}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
                    ))
            }) == Some('(')
        })
    {
        return Err(Reason::GunChain);
    }
    if s.is_empty() {
        return Err(Reason::Empty);
    }
    if s.encode_utf16().count() > max {
        return Err(Reason::TooLong);
    }
    if s.chars()
        .any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c))
    {
        return Err(Reason::ControlChar);
    }
    if s.chars().any(|c| {
        matches!(c, '\u{feff}' | '\u{2028}' | '\u{2029}' | '\u{fffd}')
            || ('\u{200b}'..='\u{200f}').contains(&c)
    }) {
        return Err(Reason::InvisibleChar);
    }
    if s.starts_with(' ') || s.ends_with(' ') {
        return Err(Reason::Whitespace);
    }
    let unicode_space = |c: char| {
        matches!(
            c,
            '\u{a0}' | '\u{1680}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
        ) || ('\u{2000}'..='\u{200a}').contains(&c)
    };
    if s.chars().next().is_some_and(unicode_space)
        || s.chars().next_back().is_some_and(unicode_space)
    {
        return Err(Reason::BadAlphabet);
    }
    Ok(s)
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub(crate) fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) fn unhex(s: &str) -> Result<Vec<u8>, Reason> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err(Reason::BadAlphabet);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Reason::BadAlphabet))
        .collect()
}
pub(crate) fn b64(b: &[u8]) -> String {
    use base64ct::Encoding;
    base64ct::Base64UrlUnpadded::encode_string(b)
}
pub(crate) fn unb64(s: &str) -> Result<Vec<u8>, Reason> {
    use base64ct::Encoding;
    let b = base64ct::Base64UrlUnpadded::decode_vec(s).map_err(|_| Reason::NonCanonical)?;
    if b64(&b) != s {
        return Err(Reason::NonCanonical);
    }
    Ok(b)
}
/// Little-endian UTF-8 length prefix. Integer fields are decimal strings.
/// A field of 4 GiB or more is [`Reason::TooLong`] instead of a truncated length.
pub fn length_prefixed(fields: &[&str]) -> Result<Vec<u8>, Reason> {
    let mut out = Vec::new();
    for s in fields {
        let len = u32::try_from(s.len()).map_err(|_| Reason::TooLong)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    Ok(out)
}
pub(crate) fn lp(fields: &[&str]) -> Vec<u8> {
    length_prefixed(fields).expect("ids field lengths fit in u32")
}

// Every textual newtype validates deserialization too; serde cannot bypass FromStr.
macro_rules! id_type {
    ($name:ident, $parser:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl FromStr for $name {
            type Err = Reason;
            fn from_str(s: &str) -> Result<Self, Reason> {
                $parser(s)
            }
        }
        impl TryFrom<&str> for $name {
            type Error = Reason;
            fn try_from(s: &str) -> Result<Self, Reason> {
                s.parse()
            }
        }
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
pub(crate) use id_type;
