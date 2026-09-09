//! Social Light hop factor on Gun Check.
//!
//! Reuses [`sociacl_core::HopFrame`] / SLHP. Does not reimplement the
//! wire. Decode does not verify and does not mint — same as
//! [`crate::accept_hint`].

use sociacl_core::{AttestationChannel, AttestationError, HopFrame};

/// Optional Check factor. Opaque SLHP bytes or the structured hop
/// `sociacl-core` already names. Missing hop does not fail Check.
/// A hop alone never allows. A hop never mints a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HopFactor {
    /// Opaque SLHP v1 bytes. Decode does not verify.
    Slhp(Vec<u8>),
    Structured {
        channel: AttestationChannel,
        attestation_bytes: Option<Vec<u8>>,
        share_token: Option<String>,
    },
}

impl HopFactor {
    pub fn from_frame(frame: HopFrame) -> Self {
        Self::Structured {
            channel: frame.channel,
            attestation_bytes: Some(frame.attestation),
            share_token: frame.share_token,
        }
    }

    pub fn channel(&self) -> Option<AttestationChannel> {
        match self {
            Self::Slhp(_) => None,
            Self::Structured { channel, .. } => Some(*channel),
        }
    }

    /// Always false. A hop is a factor at most.
    pub fn is_grant(&self) -> bool {
        false
    }
}

/// Identity. Does not verify. Does not mint. Mirror [`crate::accept_hint`].
pub fn accept_hop(hop: HopFactor) -> HopFactor {
    hop
}

/// SLHP decode. Does not verify. Does not mint. Mirror hint decode.
pub fn decode_hop(bytes: &[u8]) -> Result<HopFactor, AttestationError> {
    let frame = HopFrame::decode(bytes)?;
    Ok(HopFactor::from_frame(frame))
}

/// Decode bytes if needed, otherwise identity. Does not verify. Does
/// not mint.
pub fn accept_hop_bytes(bytes: &[u8]) -> Result<HopFactor, AttestationError> {
    decode_hop(bytes)
}
