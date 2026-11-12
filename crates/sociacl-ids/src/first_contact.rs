//! Signed inner first-contact payload. Transport encryption and replay storage
//! are caller responsibilities; verification never creates a lane or a grant.
use crate::{length_prefixed, parse_principal_id, verify_signed_at, PrincipalId, Reason, ResolutionContext};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const FIRST_CONTACT_DOMAIN: &str = "sociacl-first-contact-request-v1";
pub const FIRST_CONTACT_REPLAY_DOMAIN: &str = "sociacl-first-contact-replay-v1";
pub const FIRST_CONTACT_MAX_MESSAGE_BYTES: usize = 4096;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstContactRequest {
    pub channel_id: String,
    pub descriptor_revision: u64,
    pub sender: PrincipalId,
    pub reply_epub: PrincipalId,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub message: String,
    pub sig: String,
}

/// Independently obtained recipient policy; immutable within a revision.
#[derive(Clone, Debug)]
pub struct FirstContactDescriptor {
    pub channel_id: String,
    pub revision: u64,
    pub expires_at: u64,
    pub max_lifetime_seconds: u64,
    pub max_message_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFirstContact {
    pub request: FirstContactRequest,
    pub request_id: String,
    pub replay_key: String,
    /// Atomically reserve replay_key through this exclusive descriptor deadline.
    pub replay_until: u64,
}

fn hex32(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn number(v: &Value) -> Result<u64, Reason> {
    let n = v.as_f64().ok_or(Reason::BadRecord)?;
    if n.is_finite() && !n.is_sign_negative() && n.fract() == 0.0 && n <= MAX_SAFE as f64 {
        Ok(n as u64)
    } else {
        Err(Reason::BadRecord)
    }
}
fn string(v: &Value) -> Result<&str, Reason> {
    v.as_str().ok_or(Reason::BadRecord)
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Canonical v1 bytes. Message whitespace and Unicode normalization are preserved.
pub fn first_contact_request_bytes(r: &FirstContactRequest) -> Result<Vec<u8>, Reason> {
    length_prefixed(&[FIRST_CONTACT_DOMAIN, "1", &r.channel_id,
        &r.descriptor_revision.to_string(), r.sender.as_ref(), r.reply_epub.as_ref(),
        &r.nonce, &r.issued_at.to_string(), &r.expires_at.to_string(), &r.message])
}

pub fn parse_first_contact_request(row: &Value) -> Result<FirstContactRequest, Reason> {
    const FIELDS: [&str; 10] = ["v", "channelId", "descriptorRevision", "sender", "replyEpub",
        "nonce", "issuedAt", "expiresAt", "message", "sig"];
    let map = row.as_object().ok_or(Reason::BadRecord)?;
    if map.len() != FIELDS.len() || !FIELDS.iter().all(|k| map.contains_key(*k)) || number(&row["v"])? != 1 {
        return Err(Reason::BadRecord);
    }
    let channel_id = string(&row["channelId"])?;
    let nonce = string(&row["nonce"])?;
    let descriptor_revision = number(&row["descriptorRevision"])?;
    let issued_at = number(&row["issuedAt"])?;
    let expires_at = number(&row["expiresAt"])?;
    if !hex32(channel_id) || !hex32(nonce) || descriptor_revision == 0 || expires_at <= issued_at {
        return Err(Reason::BadRecord);
    }
    let sender = parse_principal_id(row["sender"].as_str().ok_or(Reason::NotString)?)?;
    let reply_epub = parse_principal_id(row["replyEpub"].as_str().ok_or(Reason::NotString)?)?;
    let sig = string(&row["sig"])?;
    let message = string(&row["message"])?;
    if sig.len() != 86 || !sig.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || message.len() > FIRST_CONTACT_MAX_MESSAGE_BYTES {
        return Err(Reason::BadRecord);
    }
    Ok(FirstContactRequest { channel_id: channel_id.into(), descriptor_revision, sender, reply_epub,
        nonce: nonce.into(), issued_at, expires_at, message: message.into(), sig: sig.into() })
}

/// Pure authentication after decryption. Before display/acceptance the caller
/// must durably reserve replay_key until replay_until; missing state fails closed.
pub fn verify_first_contact_request(row: &Value, rotations: &[Value], ctx: &ResolutionContext<'_>,
    descriptor: &FirstContactDescriptor) -> Result<VerifiedFirstContact, Reason> {
    let r = parse_first_contact_request(row)?;
    if ctx.now > MAX_SAFE || !hex32(&descriptor.channel_id) || descriptor.revision == 0
        || descriptor.revision > MAX_SAFE || descriptor.expires_at > MAX_SAFE
        || descriptor.max_lifetime_seconds == 0 || descriptor.max_lifetime_seconds > MAX_SAFE
        || descriptor.max_message_bytes == 0 || descriptor.max_message_bytes > FIRST_CONTACT_MAX_MESSAGE_BYTES {
        return Err(Reason::BadRecord);
    }
    if r.channel_id != descriptor.channel_id || r.descriptor_revision != descriptor.revision
        || r.expires_at > descriptor.expires_at || r.expires_at - r.issued_at > descriptor.max_lifetime_seconds
        || r.message.len() > descriptor.max_message_bytes {
        return Err(Reason::BadRecord);
    }
    if ctx.now < r.issued_at { return Err(Reason::FutureRecord); }
    if ctx.now >= r.expires_at || ctx.now >= descriptor.expires_at { return Err(Reason::Expired); }
    let bytes = first_contact_request_bytes(&r)?;
    let proof = verify_signed_at(&r.sender, rotations, ctx, &bytes, &r.sig, r.issued_at)?;
    let history = (ctx.history)(&r.sender, r.issued_at, ctx.now)?;
    if history.key != proof.key || history.current_key != proof.key { return Err(Reason::MissingHistory); }
    let replay = length_prefixed(&[FIRST_CONTACT_REPLAY_DOMAIN, &r.channel_id,
        &r.descriptor_revision.to_string(), r.sender.as_ref(), &r.nonce])?;
    Ok(VerifiedFirstContact { request: r, request_id: digest(&bytes), replay_key: digest(&replay),
        replay_until: descriptor.expires_at })
}
