//! Authority-side consume of FyberLabs/socialight hop frame v1.
//!
//! Exact wire published by `socialight-hop` (`SLHP`). Do not invent a
//! second magic or layout. Decode does not verify. This crate verifies
//! the attestation bytes and evaluates Check / Remint / Discover.
//!
//! Payload is channel, opaque attestation bytes, optional share-token.
//! Named channels only. Same refuse list as [`AttestationChannel`].

use crate::attestation::{Attestation, AttestationBinding, AttestationClaim, AttestationSig};
use crate::cache::SnapshotHash;
use crate::channel::{AttestationChannel, SocialLightStatement};
use crate::error::AttestationError;
use crate::types::{NodeId, ObjectVersion, Timestamp};

/// Same magic as `socialight-hop`. Distinct from the Case C `SACL` bundle.
pub const MAGIC: &[u8; 4] = b"SLHP";
/// Hop frame version socialight published. Bump only with that crate.
pub const VERSION: u16 = 1;

const HEADER_LEN: usize = 4 + 2 + 4;
const MAX_STR: u32 = 4096;
const MAX_ATTESTATION: u32 = 65_536;

/// Delivery frame. Attestation bytes stay opaque until SociACL parses
/// them. Matches `socialight_hop::Hop`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HopFrame {
    pub version: u16,
    pub channel: AttestationChannel,
    pub attestation: Vec<u8>,
    pub share_token: Option<String>,
}

/// Ids that look like LightIFF, field IFF, or a waveform token.
/// Those products are not this channel.
pub fn is_lightiff_shaped_id(id: &str) -> bool {
    let s = id.trim().to_ascii_lowercase();
    if s.is_empty() {
        return false;
    }
    matches!(
        s.as_str(),
        "lightiff"
            | "light-iff"
            | "light_iff"
            | "field-iff"
            | "fieldiff"
            | "field_iff"
            | "iff"
            | "waveform"
            | "frequency"
            | "challenge-response"
            | "challengeresponse"
    ) || s.contains("lightiff")
        || s.contains("light-iff")
        || s.contains("light_iff")
        || s.contains("field-iff")
        || s.starts_with("iff-")
        || s.ends_with("-iff")
}

fn reject_lightiff_id(id: &NodeId) -> Result<(), AttestationError> {
    if is_lightiff_shaped_id(id.as_str()) {
        Err(AttestationError::ForbiddenChannel(id.as_str().to_string()))
    } else {
        Ok(())
    }
}

fn reject_statement_ids(statement: &SocialLightStatement) -> Result<(), AttestationError> {
    let att = &statement.attestation;
    reject_lightiff_id(&att.issuer)?;
    reject_lightiff_id(&att.subject)?;
    reject_lightiff_id(&att.enrollment)?;
    match &att.binding {
        AttestationBinding::ObjectVersion { object, .. }
        | AttestationBinding::Snapshot { object, .. } => reject_lightiff_id(object)?,
    }
    Ok(())
}

fn reject_unsigned(att: &Attestation) -> Result<(), AttestationError> {
    if att.signature.0 == [0u8; AttestationSig::LEN] {
        Err(AttestationError::UnsignedHopFrame)
    } else {
        Ok(())
    }
}

impl HopFrame {
    pub fn accept(
        version: u16,
        channel: AttestationChannel,
        attestation: Vec<u8>,
        share_token: Option<String>,
    ) -> Result<Self, AttestationError> {
        if version != VERSION {
            return Err(AttestationError::UnsupportedHopVersion(version));
        }
        if attestation.len() > MAX_ATTESTATION as usize {
            return Err(AttestationError::HopFrameCorrupt);
        }
        if let Some(token) = &share_token {
            if token.len() > MAX_STR as usize {
                return Err(AttestationError::HopFrameCorrupt);
            }
        }
        Ok(Self {
            version,
            channel,
            attestation,
            share_token,
        })
    }

    /// Frame for delivery. Does not sign or verify. Same bytes
    /// `socialight-hop` emits.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        write_str(&mut payload, self.channel.as_str());
        write_bytes(&mut payload, &self.attestation);
        match &self.share_token {
            Some(token) => {
                payload.push(1);
                write_str(&mut payload, token);
            }
            None => payload.push(0),
        }
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Consume a versioned hop frame. Does not verify the attestation.
    pub fn decode(bytes: &[u8]) -> Result<Self, AttestationError> {
        if bytes.len() < HEADER_LEN {
            return Err(AttestationError::HopFrameCorrupt);
        }
        if &bytes[..4] != MAGIC {
            return Err(AttestationError::HopFrameCorrupt);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        if version != VERSION {
            return Err(AttestationError::UnsupportedHopVersion(version));
        }
        let payload_len = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
        let end = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(AttestationError::HopFrameCorrupt)?;
        if bytes.len() != end {
            return Err(AttestationError::HopFrameCorrupt);
        }
        let mut r = Reader::new(&bytes[HEADER_LEN..end]);
        let channel = AttestationChannel::parse(r.str()?)?;
        let attestation = r.attestation_bytes()?;
        let share_token = if r.flag()? {
            Some(r.str()?.to_string())
        } else {
            None
        };
        r.finish()?;
        Self::accept(version, channel, attestation, share_token)
    }
}

impl SocialLightStatement {
    /// Encode a hop frame another process or FyberLabs/socialight can
    /// send. Inner attestation is packed as opaque bytes. Does not
    /// verify the signature against an enrollment.
    pub fn encode(&self) -> Result<Vec<u8>, AttestationError> {
        AttestationChannel::parse(self.channel.as_str())?;
        reject_statement_ids(self)?;
        reject_unsigned(&self.attestation)?;
        let hop = HopFrame::accept(
            VERSION,
            self.channel,
            encode_attestation_bytes(&self.attestation),
            self.share_token.clone(),
        )?;
        Ok(hop.encode())
    }

    /// Decode a hop frame, then parse the attestation bytes. Verify
    /// still belongs to the plane.
    pub fn decode(bytes: &[u8]) -> Result<Self, AttestationError> {
        let hop = HopFrame::decode(bytes)?;
        let attestation = decode_attestation_bytes(&hop.attestation)?;
        let statement = SocialLightStatement {
            channel: hop.channel,
            attestation,
            share_token: hop.share_token,
        };
        reject_statement_ids(&statement)?;
        reject_unsigned(&statement.attestation)?;
        Ok(statement)
    }
}

fn encode_attestation_bytes(att: &Attestation) -> Vec<u8> {
    let mut w = Vec::new();
    write_str(&mut w, att.issuer.as_str());
    write_str(&mut w, att.subject.as_str());
    write_str(&mut w, att.claim.as_str());
    w.extend_from_slice(&att.issued_at.0.to_le_bytes());
    write_str(&mut w, att.enrollment.as_str());
    match &att.binding {
        AttestationBinding::ObjectVersion { object, version } => {
            write_str(&mut w, "object-version");
            write_str(&mut w, object.as_str());
            w.extend_from_slice(&version.0.to_le_bytes());
        }
        AttestationBinding::Snapshot { object, hash } => {
            write_str(&mut w, "snapshot");
            write_str(&mut w, object.as_str());
            w.extend_from_slice(&hash.0);
        }
    }
    write_bytes(&mut w, &att.signature.0);
    w
}

fn decode_attestation_bytes(bytes: &[u8]) -> Result<Attestation, AttestationError> {
    let mut r = Reader::new(bytes);
    let issuer = NodeId::new(r.str()?);
    let subject = NodeId::new(r.str()?);
    let claim = AttestationClaim::parse(r.str()?)?;
    let issued_at = Timestamp(r.u64()?);
    let enrollment = NodeId::new(r.str()?);
    let binding = match r.str()? {
        "object-version" => AttestationBinding::ObjectVersion {
            object: NodeId::new(r.str()?),
            version: ObjectVersion(r.u64()?),
        },
        "snapshot" => AttestationBinding::Snapshot {
            object: NodeId::new(r.str()?),
            hash: SnapshotHash(r.fixed32()?),
        },
        _ => return Err(AttestationError::HopFrameCorrupt),
    };
    let signature = AttestationSig::from_slice(&r.bytes()?)?;
    r.finish()?;
    Ok(Attestation {
        issuer,
        subject,
        claim,
        issued_at,
        enrollment,
        binding,
        signature,
    })
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    write_bytes(out, s.as_bytes());
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    buf: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, i: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AttestationError> {
        let end = self
            .i
            .checked_add(n)
            .ok_or(AttestationError::HopFrameCorrupt)?;
        if end > self.buf.len() {
            return Err(AttestationError::HopFrameCorrupt);
        }
        let slice = &self.buf[self.i..end];
        self.i = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, AttestationError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, AttestationError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    fn flag(&mut self) -> Result<bool, AttestationError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AttestationError::HopFrameCorrupt),
        }
    }

    fn fixed32(&mut self) -> Result<[u8; 32], AttestationError> {
        let b = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn attestation_bytes(&mut self) -> Result<Vec<u8>, AttestationError> {
        let len = self.u32()?;
        if len > MAX_ATTESTATION {
            return Err(AttestationError::HopFrameCorrupt);
        }
        Ok(self.take(len as usize)?.to_vec())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, AttestationError> {
        let len = self.u32()?;
        if len > AttestationSig::LEN as u32 {
            return Err(AttestationError::HopFrameCorrupt);
        }
        Ok(self.take(len as usize)?.to_vec())
    }

    fn str(&mut self) -> Result<&'a str, AttestationError> {
        let len = self.u32()?;
        if len > MAX_STR {
            return Err(AttestationError::HopFrameCorrupt);
        }
        let bytes = self.take(len as usize)?;
        std::str::from_utf8(bytes).map_err(|_| AttestationError::HopFrameCorrupt)
    }

    fn finish(&self) -> Result<(), AttestationError> {
        if self.i == self.buf.len() {
            Ok(())
        } else {
            Err(AttestationError::HopFrameCorrupt)
        }
    }
}
