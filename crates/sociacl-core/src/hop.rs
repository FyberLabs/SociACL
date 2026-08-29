//! Authority-side Social Light hop frame.
//!
//! Versioned, length-prefixed bytes. Not JSON-as-policy. The frame
//! carries a named channel, an existing attestation, and an optional
//! voluntary share-token. [FyberLabs/socialight](https://github.com/FyberLabs/socialight)
//! speaks this on a hop. This crate verifies and evaluates. socialight
//! owns delivery.
//!
//! Fail closed on an unnamed or forbidden channel, a forbidden claim,
//! an unsigned statement, or a LightIFF-shaped id.

use crate::attestation::{Attestation, AttestationBinding, AttestationClaim, AttestationSig};
use crate::cache::SnapshotHash;
use crate::channel::{AttestationChannel, SocialLightStatement};
use crate::error::AttestationError;
use crate::types::{NodeId, ObjectVersion, Timestamp};

/// Wire magic. Distinct from the Case C `SACL` bundle.
pub const MAGIC: &[u8; 4] = b"SLHF";
/// First hop-frame version. Bump when fields change.
pub const VERSION: u16 = 1;

const HEADER_LEN: usize = 4 + 2 + 4;
const MAX_STR: u32 = 4096;
const MAX_BYTES: u32 = 256;

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

impl SocialLightStatement {
    /// Encode a hop frame another process or FyberLabs/socialight can
    /// send. Does not verify the signature against an enrollment.
    pub fn encode(&self) -> Result<Vec<u8>, AttestationError> {
        AttestationChannel::parse(self.channel.as_str())?;
        reject_statement_ids(self)?;
        reject_unsigned(&self.attestation)?;
        if let Some(token) = &self.share_token {
            if token.len() as u32 > MAX_STR {
                return Err(AttestationError::HopFrameCorrupt);
            }
        }

        let mut w = Writer::new();
        w.str(self.channel.as_str());
        encode_attestation(&mut w, &self.attestation);
        match &self.share_token {
            Some(token) => {
                w.bool(true);
                w.str(token);
            }
            None => w.bool(false),
        }
        let payload = w.0;
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decode a hop frame. Verify still belongs to the plane.
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
        let attestation = decode_attestation(&mut r)?;
        let share_token = if r.bool()? {
            Some(r.str()?.to_string())
        } else {
            None
        };
        r.finish()?;
        let statement = SocialLightStatement {
            channel,
            attestation,
            share_token,
        };
        reject_statement_ids(&statement)?;
        reject_unsigned(&statement.attestation)?;
        Ok(statement)
    }
}

fn encode_attestation(w: &mut Writer, att: &Attestation) {
    w.str(att.issuer.as_str());
    w.str(att.subject.as_str());
    w.str(att.claim.as_str());
    w.u64(att.issued_at.0);
    w.str(att.enrollment.as_str());
    match &att.binding {
        AttestationBinding::ObjectVersion { object, version } => {
            w.str("object-version");
            w.str(object.as_str());
            w.u64(version.0);
        }
        AttestationBinding::Snapshot { object, hash } => {
            w.str("snapshot");
            w.str(object.as_str());
            w.fixed32(&hash.0);
        }
    }
    w.bytes(&att.signature.0);
}

fn decode_attestation(r: &mut Reader<'_>) -> Result<Attestation, AttestationError> {
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

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn bool(&mut self, v: bool) {
        self.0.push(if v { 1 } else { 0 });
    }

    fn fixed32(&mut self, bytes: &[u8; 32]) {
        self.0.extend_from_slice(bytes);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.u32(bytes.len() as u32);
        self.0.extend_from_slice(bytes);
    }

    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
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

    fn bool(&mut self) -> Result<bool, AttestationError> {
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

    fn bytes(&mut self) -> Result<Vec<u8>, AttestationError> {
        let len = self.u32()?;
        if len > MAX_BYTES {
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
