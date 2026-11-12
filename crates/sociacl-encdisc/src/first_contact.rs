//! Confidential first-contact requests. Decryption never grants a lane.
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use p256::elliptic_curve::Generate;
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sociacl_ids::{FirstContactDescriptor, FirstContactRequest, Reason, ResolutionContext,
    VerifiedFirstContact, first_contact_request_bytes, parse_first_contact_request,
    verify_first_contact_request, FIRST_CONTACT_DOMAIN};
use zeroize::Zeroizing;
use crate::{canonical, sea};

pub const FIRST_CONTACT_SEAL_DOMAIN: &str = "sociacl-first-contact-seal-v1";
pub const FIRST_CONTACT_ENVELOPE_MAX_BYTES: usize = 8192;

/// Authenticated recipient configuration, immutable within each revision.
#[derive(Clone, Debug)]
pub struct FirstContactSealDescriptor {
    pub policy: FirstContactDescriptor,
    pub encryption_epub: String,
}
fn bad<T>(_: T) -> Reason { Reason::BadRecord }
fn aad(d: &FirstContactSealDescriptor, point: &p256::PublicKey) -> Result<Vec<u8>, Reason> {
    let p = &d.policy;
    sociacl_ids::parse_principal_id(&d.encryption_epub)?;
    if p.channel_id.len() != 64 || !p.channel_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || p.revision == 0 || p.revision > 9_007_199_254_740_991 { return Err(Reason::BadRecord); }
    canonical::length_prefixed(&[FIRST_CONTACT_SEAL_DOMAIN, "1", &p.channel_id,
        &p.revision.to_string(), &d.encryption_epub, &sea::sea_pub_from_point(point).map_err(bad)?]).map_err(bad)
}
fn plaintext(r: &FirstContactRequest) -> Result<Zeroizing<Vec<u8>>, Reason> {
    let mut bytes = Zeroizing::new(first_contact_request_bytes(r)?);
    bytes.extend(canonical::length_prefixed(&[&r.sig]).map_err(bad)?);
    Ok(bytes)
}
/// A fresh random ephemeral key and nonce for every seal. This does not authenticate
/// the sender; the opener verifies the inner signature against independent history.
pub fn seal_first_contact_request(row: &Value, descriptor: &FirstContactSealDescriptor) -> Result<Vec<u8>, Reason> {
    let r = parse_first_contact_request(row)?;
    if r.channel_id != descriptor.policy.channel_id || r.descriptor_revision != descriptor.policy.revision {
        return Err(Reason::BadRecord);
    }
    let ephemeral = p256::SecretKey::generate();
    let mut nonce = [0u8; 12]; OsRng.fill_bytes(&mut nonce);
    let aad = aad(descriptor, &ephemeral.public_key())?;
    let peer = sea::parse_sea_point(&descriptor.encryption_epub).map_err(bad)?;
    let shared = sea::ecdh_x(&ephemeral, &peer).map_err(bad)?;
    let key = crate::contact_lane::hkdf_sha256(&shared[..], &aad).map_err(bad)?;
    let plain = plaintext(&r)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(bad)?;
    let body = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad }).map_err(bad)?;
    let mut blob = vec![1];
    blob.extend(sea::uncompressed_point(&ephemeral.public_key()).map_err(bad)?);
    blob.extend(nonce); blob.extend(body);
    if blob.len() > FIRST_CONTACT_ENVELOPE_MAX_BYTES { return Err(Reason::BadRecord); }
    Ok(blob)
}
/// Decrypt and authenticate. Caller must durably reserve replay_key through
/// replay_until before display or acceptance. Invalid envelopes yield no plaintext.
pub fn open_first_contact_request(blob: &[u8], recipient_epriv: &str,
    descriptor: &FirstContactSealDescriptor, rotations: &[Value],
    ctx: &ResolutionContext<'_>) -> Result<VerifiedFirstContact, Reason> {
    if blob.len() < 94 || blob.len() > FIRST_CONTACT_ENVELOPE_MAX_BYTES || blob[0] != 1 || blob[1] != 4 {
        return Err(Reason::BadRecord);
    }
    let secret = sea::ecdh_secret(recipient_epriv).map_err(bad)?;
    if sea::sea_pub_from_secret(&secret).map_err(bad)? != descriptor.encryption_epub { return Err(Reason::BadRecord); }
    let point = p256::PublicKey::from_sec1_bytes(&blob[1..66]).map_err(bad)?;
    let aad = aad(descriptor, &point)?;
    let shared = sea::ecdh_x(&secret, &point).map_err(bad)?;
    let key = crate::contact_lane::hkdf_sha256(&shared[..], &aad).map_err(bad)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(bad)?;
    let plain = Zeroizing::new(cipher.decrypt(Nonce::from_slice(&blob[66..78]),
        Payload { msg: &blob[78..], aad: &aad }).map_err(bad)?);
    let f = canonical::decode_length_prefixed(&plain).map_err(bad)?;
    if f.len() != 11 || f[0] != FIRST_CONTACT_DOMAIN || f[1] != "1" { return Err(Reason::BadRecord); }
    let row = json!({"v": 1, "channelId": f[2], "descriptorRevision": f[3].parse::<u64>().map_err(bad)?,
        "sender": f[4], "replyEpub": f[5], "nonce": f[6], "issuedAt": f[7].parse::<u64>().map_err(bad)?,
        "expiresAt": f[8].parse::<u64>().map_err(bad)?, "message": f[9], "sig": f[10]});
    let parsed = parse_first_contact_request(&row)?;
    if plaintext(&parsed)?.as_slice() != plain.as_slice() { return Err(Reason::BadRecord); }
    verify_first_contact_request(&row, rotations, ctx, &descriptor.policy)
}
