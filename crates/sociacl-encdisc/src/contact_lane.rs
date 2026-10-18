//! Per-contact inbox lanes.
//!
//! The HKDF input is the keyring contact-lane secret, 32 random bytes.
//! It is not the disclosed base `lane_id`. The recipient signs the lane id
//! and then encrypts that signature. The outer envelope is the ciphertext.
//! Recipient and sender ids that the opener already knows are associated
//! data. They are not a public signature. A lane is delivery only.
//!
//! There is no Gun user-encryption fallback. This module does not wire
//! Panopticon or Gun, and it does not open a first-contact channel. Those
//! are SociACL#71 and SociACL#70.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::digest::Mac;
use hmac::Hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use sociacl_ids::{parse_principal_id, PrincipalId};
use zeroize::Zeroize;

use crate::account::require_lane;
use crate::canonical::{self, canonical_decimal};
use crate::error::EncDiscError;
use crate::hexutil::{self, encode_hex};
use crate::keyring::AccountKeyring;
use crate::sea::{self, ecdh_x, uncompressed_point};

/// HKDF info label. Version is a separate length-prefixed field.
const CONTACT_LANE_DOMAIN: &str = "sociacl-contact-lane-v1";
/// Canonical decimal version inside the HKDF info.
const CONTACT_LANE_VERSION: &str = "1";
/// KDF, associated data, and plaintext domain for a contact-lane grant.
const CONTACT_LANE_GRANT_DOMAIN: &str = "sociacl-contact-lane-grant-v1";
/// Signature domain. The signature is inside the ciphertext.
const CONTACT_LANE_GRANT_SIG_DOMAIN: &str = "sociacl-contact-lane-grant-sig-v1";

const VER_GRANT: u8 = 1;
const GRANT_BLOB_MAX: usize = 4096;

/// Outer envelope. The lane id and the recipient signature are inside.
/// `priv`, `epriv`, and the contact-lane secret are not fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactLaneGrant {
    pub ciphertext_hex: String,
}

/// What the sender learns. `lookup_key` is the lane id hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedContactLane {
    pub lane_id: String,
    pub lookup_key: String,
    pub recipient: PrincipalId,
    pub sender: PrincipalId,
    pub rotation_seq: u64,
}

/// One contact to re-grant after the contact-lane secret rotates.
pub struct ContactTarget<'a> {
    pub principal: &'a str,
    pub rotations: &'a [serde_json::Value],
    pub context: &'a sociacl_ids::ResolutionContext<'a>,
}

/// HKDF info. Length-prefixed UTF-8, little-endian uint32 lengths, in this
/// order: domain, version, recipient PrincipalId, sender PrincipalId.
/// The ids are not sorted. Direction is the order of the arguments.
fn contact_lane_info(recipient: &str, sender: &str) -> Result<Vec<u8>, EncDiscError> {
    let owner = require_principal(recipient)?;
    let from = require_principal(sender)?;
    canonical::length_prefixed(&[
        CONTACT_LANE_DOMAIN,
        CONTACT_LANE_VERSION,
        owner.as_ref(),
        from.as_ref(),
    ])
}

/// HKDF-SHA256. IKM is the 32-byte contact-lane secret. Salt is 32 zero
/// bytes. Info is [`contact_lane_info`]. Output is 32 bytes, lowercase hex.
/// HKDF of the disclosed base lane id is a different value.
pub fn derive_contact_lane(
    contact_secret_hex: &str,
    recipient: &str,
    sender: &str,
) -> Result<String, EncDiscError> {
    let mut ikm = lane_secret_bytes(contact_secret_hex)?;
    let info = contact_lane_info(recipient, sender)?;
    let okm = hkdf_sha256(&ikm, &info)?;
    ikm.zeroize();
    Ok(encode_hex(&okm[..]))
}

/// Contact lane at `seq`. `prior_contact_secrets[seq]` is the secret that
/// was current at that sequence, and `prior_contact_secrets.len()` is
/// `rotation_seq`. The current secret is `contact_lane_secret`. A sequence
/// above `rotation_seq` is [`EncDiscError::BadLane`]. A derived id that
/// equals a disclosed base lane or a contact-lane secret is
/// [`EncDiscError::BadLane`].
pub fn resolve_contact_lane(
    keyring: &AccountKeyring,
    sender: &str,
    seq: u64,
) -> Result<String, EncDiscError> {
    let prior = keyring.prior_contact_secrets();
    if prior.len() as u64 != keyring.rotation_seq() || seq > keyring.rotation_seq() {
        return Err(EncDiscError::BadLane);
    }
    let secret = if seq == keyring.rotation_seq() {
        keyring.contact_lane_secret()
    } else {
        prior
            .get(seq as usize)
            .map(|held| held.as_str())
            .ok_or(EncDiscError::BadLane)?
    };
    let lane = derive_contact_lane(secret, keyring.principal().as_ref(), sender)?;
    if contact_lane_collides(&lane, keyring) {
        return Err(EncDiscError::BadLane);
    }
    Ok(lane)
}

/// Opaque storage key. It is the lane id hex. It is not a PrincipalId and
/// not a `~pub` path. Callers index by this string alone.
pub fn lane_lookup_key(lane_id: &str) -> Result<String, EncDiscError> {
    require_lane(lane_id)?;
    Ok(lane_id.to_string())
}

/// Length-prefixed grant plaintext: domain, lane id, recipient, decimal
/// sequence, and the signature that was made before encryption.
fn contact_lane_grant_plaintext(
    lane_id: &str,
    recipient: &str,
    rotation_seq: u64,
    signature: &str,
) -> Result<Vec<u8>, EncDiscError> {
    require_lane(lane_id)?;
    if signature.len() != 128
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(EncDiscError::BadKey);
    }
    let owner = require_principal(recipient)?;
    let seq = canonical_decimal(rotation_seq)?;
    canonical::length_prefixed(&[
        CONTACT_LANE_GRANT_DOMAIN,
        lane_id,
        owner.as_ref(),
        seq.as_str(),
        signature,
    ])
}

/// Associated data for the grant wrap. The shared secret is not a field.
fn contact_lane_grant_aad(
    recipient: &str,
    sender: &str,
    sender_epub: &str,
    ephemeral_pub: &str,
    rotation_seq: u64,
) -> Result<Vec<u8>, EncDiscError> {
    let owner = require_principal(recipient)?;
    let from = require_principal(sender)?;
    let epub = require_principal(sender_epub)?;
    let ephemeral = require_principal(ephemeral_pub)?;
    let seq = canonical_decimal(rotation_seq)?;
    canonical::length_prefixed(&[
        CONTACT_LANE_GRANT_DOMAIN,
        owner.as_ref(),
        from.as_ref(),
        epub.as_ref(),
        ephemeral.as_ref(),
        seq.as_str(),
    ])
}

/// Signature message. Signed before encryption. It does not cover the blob.
fn contact_lane_signature_message(
    lane_id: &str,
    recipient: &str,
    sender: &str,
    sender_epub: &str,
    rotation_seq: u64,
) -> Result<Vec<u8>, EncDiscError> {
    require_lane(lane_id)?;
    let owner = require_principal(recipient)?;
    let from = require_principal(sender)?;
    let epub = require_principal(sender_epub)?;
    let seq = canonical_decimal(rotation_seq)?;
    canonical::length_prefixed(&[
        CONTACT_LANE_GRANT_SIG_DOMAIN,
        lane_id,
        owner.as_ref(),
        from.as_ref(),
        epub.as_ref(),
        seq.as_str(),
    ])
}

/// Seal the current contact lane to the sender's resolved `current_epub`.
/// A null `current_epub` is [`EncDiscError::EpubUnknown`]. There is no Gun
/// user-encryption fallback.
pub fn seal_contact_lane_grant(
    keyring: &AccountKeyring,
    sender_principal: &str,
    sender_rotations: &[serde_json::Value],
    sender_context: &sociacl_ids::ResolutionContext<'_>,
    recipient_rotations: &[serde_json::Value],
    recipient_context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<ContactLaneGrant, EncDiscError> {
    let sender = require_principal(sender_principal)?;
    let resolved = sociacl_ids::resolve_current_key(&sender, sender_rotations, sender_context);
    let account = resolved.result.map_err(reject)?;
    let sender_epub = crate::epub_for_new_seal(account.current_epub.as_ref(), None)?;
    let ephemeral = p256::SecretKey::random(&mut OsRng);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let grant = seal_grant(
        keyring,
        sender.as_ref(),
        sender_epub.as_ref(),
        &ephemeral,
        &nonce,
        recipient_rotations,
        recipient_context,
    );
    nonce.zeroize();
    grant
}

/// Caller-chosen ephemeral and nonce. Tests and the `deterministic-wrap`
/// feature call this. It is not a public export.
#[cfg(any(test, feature = "deterministic-wrap"))]
pub(crate) fn seal_contact_lane_grant_with(
    keyring: &AccountKeyring,
    sender_principal: &str,
    sender_epub: &str,
    ephemeral: &p256::SecretKey,
    nonce: &[u8; 12],
    recipient_rotations: &[serde_json::Value],
    recipient_context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<ContactLaneGrant, EncDiscError> {
    seal_grant(
        keyring,
        sender_principal,
        sender_epub,
        ephemeral,
        nonce,
        recipient_rotations,
        recipient_context,
    )
}

fn seal_grant(
    keyring: &AccountKeyring,
    sender_principal: &str,
    sender_epub: &str,
    ephemeral: &p256::SecretKey,
    nonce: &[u8; 12],
    recipient_rotations: &[serde_json::Value],
    recipient_context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<ContactLaneGrant, EncDiscError> {
    let sender = require_principal(sender_principal)?;
    let epub = require_principal(sender_epub)?;
    keyring.confirm(recipient_rotations, recipient_context)?;
    let lane_id = resolve_contact_lane(keyring, sender.as_ref(), keyring.rotation_seq())?;
    let message = contact_lane_signature_message(
        &lane_id,
        keyring.principal().as_ref(),
        sender.as_ref(),
        epub.as_ref(),
        keyring.rotation_seq(),
    )?;
    let signature = sea::sign_sea(keyring.current_priv(), &message)?;
    let mut plain = contact_lane_grant_plaintext(
        &lane_id,
        keyring.principal().as_ref(),
        keyring.rotation_seq(),
        &signature,
    )?;
    let peer = sea::parse_sea_point(epub.as_ref())?;
    let ephemeral_pub = sea::sea_pub_from_secret(ephemeral)?;
    let shared = ecdh_x(ephemeral, &peer)?;
    let aes_key = grant_kdf(
        &shared[..],
        keyring.principal().as_ref(),
        sender.as_ref(),
        epub.as_ref(),
        &ephemeral_pub,
        keyring.rotation_seq(),
    )?;
    let aad = contact_lane_grant_aad(
        keyring.principal().as_ref(),
        sender.as_ref(),
        epub.as_ref(),
        &ephemeral_pub,
        keyring.rotation_seq(),
    )?;
    let ciphertext = encrypt(&aes_key[..], nonce, &aad, &plain)?;
    plain.zeroize();
    let point = uncompressed_point(&ephemeral.public_key())?;
    let mut blob = Vec::with_capacity(1 + 65 + 12 + ciphertext.len());
    blob.push(VER_GRANT);
    blob.extend_from_slice(&point);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext);
    if blob.len() > GRANT_BLOB_MAX {
        return Err(EncDiscError::LaneGrantRejected);
    }
    Ok(ContactLaneGrant {
        ciphertext_hex: encode_hex(&blob),
    })
}

/// After the contact-lane secret rotates, seal a fresh grant for each
/// contact. A contact whose `current_epub` is null fails the whole call
/// with [`EncDiscError::EpubUnknown`] before any grant is returned.
pub fn regrant_contact_lanes(
    keyring: &AccountKeyring,
    contacts: &[ContactTarget<'_>],
    recipient_rotations: &[serde_json::Value],
    recipient_context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<Vec<ContactLaneGrant>, EncDiscError> {
    let mut ready = Vec::with_capacity(contacts.len());
    for contact in contacts {
        let sender = require_principal(contact.principal)?;
        let resolved =
            sociacl_ids::resolve_current_key(&sender, contact.rotations, contact.context);
        let account = resolved.result.map_err(reject)?;
        let epub = crate::epub_for_new_seal(account.current_epub.as_ref(), None)?;
        ready.push((sender, epub));
    }
    let mut grants = Vec::with_capacity(ready.len());
    for (sender, epub) in &ready {
        let ephemeral = p256::SecretKey::random(&mut OsRng);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let grant = seal_grant(
            keyring,
            sender.as_ref(),
            epub.as_ref(),
            &ephemeral,
            &nonce,
            recipient_rotations,
            recipient_context,
        );
        nonce.zeroize();
        grants.push(grant?);
    }
    Ok(grants)
}

/// Open a grant. The caller supplies the sender, the sender's `epriv`, and
/// the recipient chain. The sequence is that chain's length, so a stale
/// grant fails authenticated decryption. A forged grant, a tampered blob,
/// the wrong sender, and the wrong recipient are all
/// [`EncDiscError::LaneGrantRejected`].
pub fn open_contact_lane_grant(
    sender_principal: &str,
    sender_epriv: &str,
    grant: &ContactLaneGrant,
    expected_recipient: &str,
    recipient_rotations: &[serde_json::Value],
    recipient_context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<OpenedContactLane, EncDiscError> {
    match open_inner(
        sender_principal,
        sender_epriv,
        grant,
        expected_recipient,
        recipient_rotations,
        recipient_context,
    ) {
        Ok(opened) => Ok(opened),
        Err(_) => Err(EncDiscError::LaneGrantRejected),
    }
}

fn open_inner(
    sender_principal: &str,
    sender_epriv: &str,
    grant: &ContactLaneGrant,
    expected_recipient: &str,
    recipient_rotations: &[serde_json::Value],
    recipient_context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<OpenedContactLane, EncDiscError> {
    let sender = require_principal(sender_principal)?;
    let expected = require_principal(expected_recipient)?;
    if grant.ciphertext_hex.len() > GRANT_BLOB_MAX * 2 {
        return Err(EncDiscError::LaneGrantRejected);
    }
    let secret = sea::ecdh_secret(sender_epriv).map_err(|_| EncDiscError::LaneGrantRejected)?;
    let sender_epub = sea::sea_pub_from_secret(&secret)?;
    let resolved =
        sociacl_ids::resolve_current_key(&expected, recipient_rotations, recipient_context);
    let account = resolved
        .result
        .map_err(|_| EncDiscError::LaneGrantRejected)?;
    let seq = account.rotations.len() as u64;
    let blob =
        hexutil::decode_hex(&grant.ciphertext_hex).map_err(|_| EncDiscError::LaneGrantRejected)?;
    if blob.len() > GRANT_BLOB_MAX
        || blob.first().copied() != Some(VER_GRANT)
        || blob.len() < 1 + 65 + 12 + 16
    {
        return Err(EncDiscError::LaneGrantRejected);
    }
    let ephemeral = p256::PublicKey::from_sec1_bytes(&blob[1..66])
        .map_err(|_| EncDiscError::LaneGrantRejected)?;
    let nonce: [u8; 12] = blob[66..78]
        .try_into()
        .map_err(|_| EncDiscError::LaneGrantRejected)?;
    let ephemeral_pub = sea::sea_pub_from_point(&ephemeral)?;
    let shared = ecdh_x(&secret, &ephemeral)?;
    let aes_key = grant_kdf(
        &shared[..],
        expected.as_ref(),
        sender.as_ref(),
        &sender_epub,
        &ephemeral_pub,
        seq,
    )?;
    let aad = contact_lane_grant_aad(
        expected.as_ref(),
        sender.as_ref(),
        &sender_epub,
        &ephemeral_pub,
        seq,
    )?;
    let plain = decrypt(&aes_key[..], &nonce, &aad, &blob[78..])?;
    let fields = canonical::decode_length_prefixed(&plain)?;
    let seq_text = canonical_decimal(seq)?;
    if fields.len() != 5
        || fields[0] != CONTACT_LANE_GRANT_DOMAIN
        || require_lane(&fields[1]).is_err()
        || fields[2] != expected.as_ref()
        || fields[3] != seq_text
        || fields[4].len() != 128
    {
        return Err(EncDiscError::LaneGrantRejected);
    }
    let lane_id = fields[1].clone();
    let signature = fields[4].clone();
    let message = contact_lane_signature_message(
        &lane_id,
        expected.as_ref(),
        sender.as_ref(),
        &sender_epub,
        seq,
    )?;
    sea::verify_sea(account.current_key.as_ref(), &message, &signature)?;
    Ok(OpenedContactLane {
        lookup_key: lane_lookup_key(&lane_id)?,
        lane_id,
        recipient: expected,
        sender,
        rotation_seq: seq,
    })
}

fn contact_lane_collides(lane: &str, keyring: &AccountKeyring) -> bool {
    require_lane(lane).is_err()
        || lane == keyring.lane_id()
        || keyring.prior_lanes().iter().any(|held| held == lane)
        || lane == keyring.contact_lane_secret()
        || keyring
            .prior_contact_secrets()
            .iter()
            .any(|held| held.as_str() == lane)
}

fn require_principal(value: &str) -> Result<PrincipalId, EncDiscError> {
    let parsed = parse_principal_id(value).map_err(reject)?;
    if parsed.as_ref() != value {
        return Err(EncDiscError::IdentityRejected("non-canonical".into()));
    }
    Ok(parsed)
}

fn reject(reason: sociacl_ids::Reason) -> EncDiscError {
    EncDiscError::IdentityRejected(reason.to_string())
}

fn lane_secret_bytes(hex_text: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, EncDiscError> {
    require_lane(hex_text)?;
    hexutil::decode_secret_vec(hex_text).map_err(|_| EncDiscError::BadLane)
}

/// RFC 5869 HKDF-SHA256, L = 32. Salt is HashLen zero bytes. One expand block.
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, EncDiscError> {
    let salt = [0u8; 32];
    let mut prk = zeroize::Zeroizing::new([0u8; 32]);
    {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&salt).map_err(|_| EncDiscError::BadKey)?;
        mac.update(ikm);
        prk.copy_from_slice(&mac.finalize().into_bytes());
    }
    let mut okm = zeroize::Zeroizing::new([0u8; 32]);
    {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk[..])
            .map_err(|_| EncDiscError::BadKey)?;
        mac.update(info);
        mac.update(&[1]);
        okm.copy_from_slice(&mac.finalize().into_bytes());
    }
    Ok(okm)
}

fn grant_kdf(
    shared_x: &[u8],
    recipient: &str,
    sender: &str,
    sender_epub: &str,
    ephemeral_pub: &str,
    rotation_seq: u64,
) -> Result<zeroize::Zeroizing<[u8; 32]>, EncDiscError> {
    let hex = hexutil::encode_secret_hex(shared_x);
    let seq = canonical_decimal(rotation_seq)?;
    let mut material = canonical::length_prefixed(&[
        CONTACT_LANE_GRANT_DOMAIN,
        hex.as_str(),
        recipient,
        sender,
        sender_epub,
        ephemeral_pub,
        seq.as_str(),
    ])?;
    let key = zeroize::Zeroizing::new(canonical::sha256(&material));
    material.zeroize();
    Ok(key)
}

fn encrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::BadKey)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| EncDiscError::LaneGrantRejected)
}

fn decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    body: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::BadKey)?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: body, aad })
        .map_err(|_| EncDiscError::LaneGrantRejected)?;
    Ok(zeroize::Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::{self, encode_hex};
    use crate::keyring::{rotate_keyring, RotationMint};
    use crate::GenesisAccount;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use p256::ecdsa::signature::Signer;
    use serde_json::Value;
    use sociacl_ids::{
        history_state, HistoryResolver, Jwks, KeyState, PrincipalId, Reason, ResolutionContext,
        Rotate, SiwePolicy,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use zeroize::Zeroizing;

    const VECTOR: &str = include_str!("../../../vectors/encrypted-discovery/contact-lane.json");
    const RING: &str = include_str!("../../../vectors/encrypted-discovery/account-keyring.json");
    const RECORDS: &str = include_str!("../../../vectors/ids/records.json");

    fn vector() -> Value {
        serde_json::from_str(VECTOR).unwrap()
    }
    fn ring() -> Value {
        serde_json::from_str(RING).unwrap()
    }
    fn records() -> Value {
        serde_json::from_str(RECORDS).unwrap()
    }

    fn scalar_sea(n: u16) -> (String, Zeroizing<String>) {
        let mut bytes = [0u8; 32];
        bytes[30] = (n >> 8) as u8;
        bytes[31] = n as u8;
        let secret = p256::SecretKey::from_slice(&bytes).unwrap();
        bytes.zeroize();
        (
            sea::sea_pub_from_secret(&secret).unwrap(),
            sea::sea_priv_from_secret(&secret).unwrap(),
        )
    }

    fn b64url(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    fn sign_scalar(message: &[u8], n: u16) -> String {
        let mut raw = [0u8; 32];
        raw[30] = (n >> 8) as u8;
        raw[31] = n as u8;
        let secret = p256::SecretKey::from_slice(&raw).unwrap();
        raw.zeroize();
        let key = p256::ecdsa::SigningKey::from(secret);
        let sig: p256::ecdsa::Signature = key.sign(message);
        b64url(&sig.to_bytes())
    }

    fn genesis_keyring() -> AccountKeyring {
        let g = &ring()["genesis"];
        let account = GenesisAccount::import(
            g["laneId"].as_str().unwrap(),
            g["signingPub"].as_str().unwrap(),
            g["signingPriv"].as_str().unwrap(),
            g["epub"].as_str().unwrap(),
            g["epriv"].as_str().unwrap(),
        )
        .unwrap();
        AccountKeyring::from_genesis_with_contact_secret(
            &account,
            g["contactLaneSecret"].as_str().unwrap(),
        )
        .unwrap()
    }

    struct Owned {
        jwks: Jwks,
        policy: SiwePolicy,
        pinned: BTreeSet<String>,
        links: BTreeMap<String, Value>,
        revocations: Vec<Value>,
        bindings: Vec<Value>,
        now: u64,
        authenticated: Vec<String>,
    }

    fn owned(bindings: Vec<Value>, oidc_only: bool) -> Owned {
        let records = records();
        let ctx = &records["context"];
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let pinned = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        let links = ctx["links"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|pair| !oidc_only || pair[1]["kind"] == "oidc")
            .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
            .collect();
        let authenticated = ctx["authenticatedAccounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        Owned {
            jwks,
            policy,
            pinned,
            links,
            revocations: Vec::new(),
            bindings,
            now: ctx["now"].as_u64().unwrap(),
            authenticated,
        }
    }

    fn context<'a>(owned: &'a Owned, history: &'a HistoryResolver<'a>) -> ResolutionContext<'a> {
        ResolutionContext {
            jwks: &owned.jwks,
            links: &owned.links,
            revocations: &owned.revocations,
            now: owned.now,
            policy: &owned.policy,
            pinned_iss: &owned.pinned,
            history,
            genesis_epub_bindings: &owned.bindings,
        }
    }

    fn history_of<'a>(
        authenticated: &'a [String],
    ) -> impl Fn(&PrincipalId, u64, u64) -> Result<KeyState, Reason> + 'a {
        move |principal, at, until| {
            if authenticated.iter().any(|item| item == principal.as_ref()) {
                Ok(history_state(principal, &Vec::<Rotate>::new(), at, until))
            } else {
                Err(Reason::MissingHistory)
            }
        }
    }

    fn binding_rows() -> Vec<Value> {
        records()["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "binding-valid-no-rotation")
            .unwrap()["genesisEpubBindings"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn empty_owned() -> Owned {
        Owned {
            jwks: Jwks { keys: Vec::new() },
            policy: SiwePolicy {
                allowed_domains: Vec::new(),
                allowed_uris: Vec::new(),
                allowed_chain_ids: Vec::new(),
                clock_skew_seconds: 0,
            },
            pinned: BTreeSet::new(),
            links: BTreeMap::new(),
            revocations: Vec::new(),
            bindings: Vec::new(),
            now: records()["context"]["now"].as_u64().unwrap(),
            authenticated: Vec::new(),
        }
    }

    fn sign_genesis_epub(principal: &str, epub: &str, issued_at: u64, signer: u16) -> Value {
        let unsigned = serde_json::json!({
            "v": 1,
            "kind": "genesis-epub",
            "principal": principal,
            "epub": epub,
            "issuedAt": issued_at,
            "keySig": "",
            "attest": "",
        });
        let message = sociacl_ids::parse_signing_bytes(&unsigned).unwrap();
        let key_sig = sign_scalar(&message, signer);
        let claims = serde_json::json!({
            "typ": "sociacl-genesis-epub-attest-v1",
            "principal": principal,
            "epub": epub,
            "iat": issued_at,
            "exp": issued_at + 600,
        });
        let header = b64url(br#"{"alg":"ES256","kid":"fixture-1","typ":"JWT"}"#);
        let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
        let body = format!("{header}.{payload}");
        let sig = sign_scalar(body.as_bytes(), 5);
        serde_json::json!({
            "v": 1,
            "kind": "genesis-epub",
            "principal": principal,
            "epub": epub,
            "issuedAt": issued_at,
            "keySig": key_sig,
            "attest": format!("{body}.{sig}"),
        })
    }

    fn sign_oidc_rotation(
        principal: &str,
        seq: u64,
        prev: &str,
        next: &str,
        epub: &str,
        issued_at: u64,
        next_scalar: u16,
        link: &str,
    ) -> Value {
        let unsigned = serde_json::json!({
            "v": 1,
            "kind": "rotate",
            "principal": principal,
            "seq": seq,
            "prevKey": prev,
            "nextKey": next,
            "nextEpub": epub,
            "issuedAt": issued_at,
            "retainedLinks": [link],
            "authorizer": {"kind": "oidc-fresh-login", "link": link},
        });
        let message = sociacl_ids::parse_signing_bytes(&unsigned).unwrap();
        let next_sig = sign_scalar(&message, next_scalar);
        let claims = serde_json::json!({
            "typ": "sociacl-rotate-attest-v3",
            "principal": principal,
            "nextKey": next,
            "nextEpub": epub,
            "seq": seq,
            "iat": issued_at,
            "exp": issued_at + 600,
            "auth": "oidc-fresh-login",
            "linkId": link,
            "retainedLinks": [link],
        });
        let header = b64url(br#"{"alg":"ES256","kid":"fixture-1","typ":"JWT"}"#);
        let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
        let body = format!("{header}.{payload}");
        let sig = sign_scalar(body.as_bytes(), 5);
        let mut signed = unsigned;
        signed["nextSig"] = Value::String(next_sig);
        signed["attest"] = Value::String(format!("{body}.{sig}"));
        signed
    }

    fn trusted<'a>(v: &'a Value) -> Vec<&'a str> {
        v["trusted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect()
    }

    #[test]
    fn shared_vectors_pin_hkdf_and_the_grant() {
        let v = vector();
        let info = contact_lane_info(
            v["recipient"].as_str().unwrap(),
            v["sender"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(encode_hex(&info), v["infoHex"].as_str().unwrap());
        assert_eq!(info.len(), v["infoLength"].as_u64().unwrap() as usize);
        let fields = canonical::decode_length_prefixed(&info).unwrap();
        assert_eq!(
            fields,
            vec![
                v["domain"].as_str().unwrap().to_string(),
                v["version"].as_str().unwrap().to_string(),
                v["recipient"].as_str().unwrap().to_string(),
                v["sender"].as_str().unwrap().to_string(),
            ]
        );
        let secret = v["contactLaneSecretHex"].as_str().unwrap();
        let base = v["baseLaneId"].as_str().unwrap();
        assert_ne!(secret, base);
        assert_eq!(
            derive_contact_lane(
                secret,
                v["recipient"].as_str().unwrap(),
                v["sender"].as_str().unwrap()
            )
            .unwrap(),
            v["laneId"].as_str().unwrap()
        );
        assert_eq!(
            derive_contact_lane(
                base,
                v["recipient"].as_str().unwrap(),
                v["sender"].as_str().unwrap()
            )
            .unwrap(),
            v["baseLaneHkdf"].as_str().unwrap()
        );
        assert_ne!(v["laneId"], v["baseLaneHkdf"]);
        assert_eq!(
            derive_contact_lane(
                secret,
                v["sender"].as_str().unwrap(),
                v["recipient"].as_str().unwrap()
            )
            .unwrap(),
            v["swappedLaneId"].as_str().unwrap()
        );
        assert_ne!(v["laneId"], v["swappedLaneId"]);
        assert_eq!(
            derive_contact_lane(
                secret,
                v["recipient"].as_str().unwrap(),
                v["otherSender"].as_str().unwrap(),
            )
            .unwrap(),
            v["otherLaneId"].as_str().unwrap()
        );
        assert_eq!(
            derive_contact_lane(
                v["priorSecretHex"].as_str().unwrap(),
                v["recipient"].as_str().unwrap(),
                v["sender"].as_str().unwrap(),
            )
            .unwrap(),
            v["priorLaneId"].as_str().unwrap()
        );
        assert_eq!(
            derive_contact_lane(
                v["wrongSecretHex"].as_str().unwrap(),
                v["recipient"].as_str().unwrap(),
                v["sender"].as_str().unwrap(),
            )
            .unwrap(),
            v["wrongSecretLaneId"].as_str().unwrap()
        );
        let owned = owned(vec![ring()["genesisBinding"].clone()], false);
        let authenticated = owned.authenticated.clone();
        let history = history_of(&authenticated);
        let resolver: &HistoryResolver<'_> = &history;
        let ctx = context(&owned, resolver);
        let keyring = genesis_keyring();
        let scalar =
            hexutil::decode_hex(v["grant"]["ephemeralScalarHex"].as_str().unwrap()).unwrap();
        let ephemeral = p256::SecretKey::from_slice(&scalar).unwrap();
        let nonce_bytes = hexutil::decode_hex(v["grant"]["nonceHex"].as_str().unwrap()).unwrap();
        let nonce: [u8; 12] = nonce_bytes.as_slice().try_into().unwrap();
        let grant = seal_contact_lane_grant_with(
            &keyring,
            v["sender"].as_str().unwrap(),
            v["grant"]["senderEpub"].as_str().unwrap(),
            &ephemeral,
            &nonce,
            &[],
            &ctx,
        )
        .unwrap();
        assert_eq!(
            grant.ciphertext_hex,
            v["grant"]["ciphertextHex"].as_str().unwrap()
        );
        assert!(!grant.ciphertext_hex.contains(keyring.lane_id()));
        assert!(!grant.ciphertext_hex.contains(keyring.contact_lane_secret()));
        assert!(!format!("{grant:?}").contains("signature"));
        let plain = contact_lane_grant_plaintext(
            v["laneId"].as_str().unwrap(),
            v["recipient"].as_str().unwrap(),
            0,
            v["grant"]["signatureHex"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            encode_hex(&plain),
            v["grant"]["plaintextHex"].as_str().unwrap()
        );
        let ephemeral_pub = sea::sea_pub_from_secret(&ephemeral).unwrap();
        let aad = contact_lane_grant_aad(
            v["recipient"].as_str().unwrap(),
            v["sender"].as_str().unwrap(),
            v["grant"]["senderEpub"].as_str().unwrap(),
            &ephemeral_pub,
            0,
        )
        .unwrap();
        assert_eq!(encode_hex(&aad), v["grant"]["aadHex"].as_str().unwrap());
        let opened = open_contact_lane_grant(
            v["sender"].as_str().unwrap(),
            ring()["mint"]["epriv"].as_str().unwrap(),
            &grant,
            v["recipient"].as_str().unwrap(),
            &[],
            &ctx,
        )
        .unwrap();
        assert_eq!(opened.lane_id, v["laneId"].as_str().unwrap());
        assert_eq!(opened.lookup_key, opened.lane_id);
        assert_ne!(
            derive_contact_lane(
                keyring.lane_id(),
                keyring.principal().as_ref(),
                v["sender"].as_str().unwrap()
            )
            .unwrap(),
            opened.lane_id
        );
    }

    #[test]
    fn lane_ids_do_not_embed_a_principal_or_the_base_lane() {
        let v = vector();
        let lane = v["laneId"].as_str().unwrap();
        assert!(lane
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(lane.len(), 64);
        assert!(!lane.contains('.'));
        assert!(!lane.contains(v["recipient"].as_str().unwrap()));
        assert!(!lane.contains(v["sender"].as_str().unwrap()));
        assert_ne!(lane, v["contactLaneSecretHex"].as_str().unwrap());
        assert_ne!(lane, v["baseLaneId"].as_str().unwrap());
        assert_ne!(lane, v["baseLaneHkdf"].as_str().unwrap());
        assert_ne!(lane, v["otherLaneId"].as_str().unwrap());
        assert_ne!(lane, v["swappedLaneId"].as_str().unwrap());
        let source = include_str!("contact_lane.rs");
        let library = source.split("#[cfg(test)]").next().unwrap();
        assert!(!library.contains("gunUserEpub"));
        assert!(!library.contains("user.epub"));
    }

    #[test]
    fn null_epub_is_refused_and_a_bad_id_does_not_derive() {
        let v = vector();
        let keyring = genesis_keyring();
        let owned = owned(vec![ring()["genesisBinding"].clone()], false);
        let authenticated = owned.authenticated.clone();
        let history = history_of(&authenticated);
        let resolver: &HistoryResolver<'_> = &history;
        let ctx = context(&owned, resolver);
        let empty = empty_owned();
        let missing = |_principal: &PrincipalId, _at, _until| Err(Reason::MissingHistory);
        let missing_resolver: &HistoryResolver<'_> = &missing;
        let bare = context(&empty, missing_resolver);
        let err = seal_contact_lane_grant(
            &keyring,
            v["sender"].as_str().unwrap(),
            &[],
            &bare,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(err, EncDiscError::EpubUnknown);
        assert_eq!(
            derive_contact_lane(
                "ab",
                v["recipient"].as_str().unwrap(),
                v["sender"].as_str().unwrap()
            )
            .unwrap_err(),
            EncDiscError::BadLane
        );
        match derive_contact_lane(
            v["contactLaneSecretHex"].as_str().unwrap(),
            "not-a-principal",
            v["sender"].as_str().unwrap(),
        )
        .unwrap_err()
        {
            EncDiscError::IdentityRejected(reason) => assert_eq!(reason, "bad-length"),
            other => panic!("{other}"),
        }
        assert_eq!(lane_lookup_key("zz").unwrap_err(), EncDiscError::BadLane);
    }

    #[test]
    fn prior_sequence_resolves_and_the_reuse_guard_holds() {
        let v = vector();
        let ring = ring();
        let owned = owned(binding_rows(), true);
        let link = owned.links.keys().next().unwrap().clone();
        let authenticated = owned.authenticated.clone();
        let history = history_of(&authenticated);
        let resolver: &HistoryResolver<'_> = &history;
        let ctx = context(&owned, resolver);
        let (signing_pub, signing_priv) = scalar_sea(1);
        let (epub, epriv) = scalar_sea(9);
        let base0 = "ab".repeat(32);
        let base1 = v["priorSecretHex"].as_str().unwrap().to_string();
        let secret0 = "c0".repeat(32);
        let secret1 = "d1".repeat(32);
        let current = AccountKeyring::import_with_contact_secrets(
            &signing_pub,
            &epub,
            &signing_pub,
            signing_priv.as_str(),
            &epub,
            epriv.as_str(),
            &[],
            &base0,
            0,
            0,
            &[],
            &ctx,
            &[],
            &secret0,
            &[],
        )
        .unwrap();
        let sender = v["sender"].as_str().unwrap();
        let at_zero = resolve_contact_lane(&current, sender, 0).unwrap();
        assert_eq!(
            at_zero,
            derive_contact_lane(&secret0, current.principal().as_ref(), sender).unwrap()
        );
        assert_ne!(
            at_zero,
            derive_contact_lane(&base0, current.principal().as_ref(), sender).unwrap()
        );
        let names = trusted(&ring);
        let (next_pub, next_priv) = scalar_sea(20);
        let (next_epub, next_epriv) = scalar_sea(21);
        let lane_one = base1.clone();
        let next_secret = secret1.clone();
        let rotated = rotate_keyring(
            &current,
            &names,
            ring["lost"].as_str().unwrap(),
            &[],
            &ctx,
            || {
                Ok(RotationMint {
                    signing_pub: next_pub.clone(),
                    signing_priv: next_priv.clone(),
                    epub: next_epub.clone(),
                    epriv: next_epriv.clone(),
                    lane_id: lane_one.clone(),
                    contact_lane_secret: next_secret,
                })
            },
        )
        .unwrap();
        let current = rotated.keyring;
        assert_eq!(current.prior_lanes().len() as u64, current.rotation_seq());
        assert_eq!(
            current.prior_contact_secrets().len() as u64,
            current.rotation_seq()
        );
        assert_eq!(resolve_contact_lane(&current, sender, 0).unwrap(), at_zero);
        assert_eq!(
            resolve_contact_lane(&current, sender, 1).unwrap(),
            derive_contact_lane(
                current.contact_lane_secret(),
                current.principal().as_ref(),
                sender
            )
            .unwrap()
        );
        assert_ne!(
            resolve_contact_lane(&current, sender, 1).unwrap(),
            derive_contact_lane(current.lane_id(), current.principal().as_ref(), sender).unwrap()
        );
        assert_ne!(resolve_contact_lane(&current, sender, 1).unwrap(), at_zero);
        let (bad_pub, bad_priv) = scalar_sea(30);
        let (bad_epub, bad_epriv) = scalar_sea(31);
        let reused = current.lane_id().to_string();
        assert_eq!(
            rotate_keyring(
                &current,
                &names,
                ring["lost"].as_str().unwrap(),
                &[],
                &ctx,
                || {
                    Ok(RotationMint {
                        signing_pub: bad_pub,
                        signing_priv: bad_priv,
                        epub: bad_epub,
                        epriv: bad_epriv,
                        lane_id: reused,
                        contact_lane_secret:
                            "0202020202020202020202020202020202020202020202020202020202020202"
                                .to_string(),
                    })
                }
            )
            .unwrap_err(),
            EncDiscError::BadLane
        );
        let (bad_pub, bad_priv) = scalar_sea(32);
        let (bad_epub, bad_epriv) = scalar_sea(33);
        let prior = current.prior_lanes()[0].clone();
        assert_eq!(
            rotate_keyring(
                &current,
                &names,
                ring["lost"].as_str().unwrap(),
                &[],
                &ctx,
                || {
                    Ok(RotationMint {
                        signing_pub: bad_pub,
                        signing_priv: bad_priv,
                        epub: bad_epub,
                        epriv: bad_epriv,
                        lane_id: prior,
                        contact_lane_secret:
                            "0303030303030303030303030303030303030303030303030303030303030303"
                                .to_string(),
                    })
                }
            )
            .unwrap_err(),
            EncDiscError::BadLane
        );
        let (bad_pub, bad_priv) = scalar_sea(34);
        let (bad_epub, bad_epriv) = scalar_sea(35);
        let secret_as_lane = current.contact_lane_secret().to_string();
        assert_eq!(
            rotate_keyring(
                &current,
                &names,
                ring["lost"].as_str().unwrap(),
                &[],
                &ctx,
                || {
                    Ok(RotationMint {
                        signing_pub: bad_pub,
                        signing_priv: bad_priv,
                        epub: bad_epub,
                        epriv: bad_epriv,
                        lane_id: secret_as_lane,
                        contact_lane_secret: "44".repeat(32),
                    })
                }
            )
            .unwrap_err(),
            EncDiscError::BadLane
        );
        let (bad_pub, bad_priv) = scalar_sea(36);
        let (bad_epub, bad_epriv) = scalar_sea(37);
        let lane_as_secret = current.lane_id().to_string();
        assert_eq!(
            rotate_keyring(
                &current,
                &names,
                ring["lost"].as_str().unwrap(),
                &[],
                &ctx,
                || {
                    Ok(RotationMint {
                        signing_pub: bad_pub,
                        signing_priv: bad_priv,
                        epub: bad_epub,
                        epriv: bad_epriv,
                        lane_id: "55".repeat(32),
                        contact_lane_secret: lane_as_secret,
                    })
                }
            )
            .unwrap_err(),
            EncDiscError::BadLane
        );
        assert_eq!(
            resolve_contact_lane(&current, sender, 2).unwrap_err(),
            EncDiscError::BadLane
        );
        let _ = link;
    }

    #[test]
    fn grant_open_rejects_the_wrong_party_tamper_and_a_stale_grant() {
        let v = vector();
        let ring = ring();
        let recipient_owned = owned(binding_rows(), true);
        let link = recipient_owned.links.keys().next().unwrap().clone();
        let authenticated = recipient_owned.authenticated.clone();
        let history = history_of(&authenticated);
        let resolver: &HistoryResolver<'_> = &history;
        let recipient_ctx = context(&recipient_owned, resolver);
        let (signing_pub, signing_priv) = scalar_sea(1);
        let (epub, epriv) = scalar_sea(9);
        let (sender_pub, sender_priv) = scalar_sea(3);
        let (sender_epub, sender_epriv) = scalar_sea(4);
        let sender_binding =
            sign_genesis_epub(&sender_pub, &sender_epub, recipient_owned.now - 40, 3);
        let sender_owned = owned(vec![sender_binding], false);
        let sender_auth = sender_owned.authenticated.clone();
        let sender_history = history_of(&sender_auth);
        let sender_resolver: &HistoryResolver<'_> = &sender_history;
        let sender_ctx = context(&sender_owned, sender_resolver);
        let recipient_lane = "ab".repeat(32);
        let sender_lane = "44".repeat(32);
        let recipient_secret = "c0".repeat(32);
        let sender_secret = "d2".repeat(32);
        let recipient = AccountKeyring::import_with_contact_secrets(
            &signing_pub,
            &epub,
            &signing_pub,
            signing_priv.as_str(),
            &epub,
            epriv.as_str(),
            &[],
            &recipient_lane,
            0,
            0,
            &[],
            &recipient_ctx,
            &[],
            &recipient_secret,
            &[],
        )
        .unwrap();
        let sender = AccountKeyring::import_with_contact_secrets(
            &sender_pub,
            &sender_epub,
            &sender_pub,
            sender_priv.as_str(),
            &sender_epub,
            sender_epriv.as_str(),
            &[],
            &sender_lane,
            0,
            0,
            &[],
            &sender_ctx,
            &[],
            &sender_secret,
            &[],
        )
        .unwrap();
        let grant = seal_contact_lane_grant(
            &recipient,
            &sender_pub,
            &[],
            &sender_ctx,
            &[],
            &recipient_ctx,
        )
        .unwrap();
        let opened = open_contact_lane_grant(
            &sender_pub,
            sender.current_epriv(),
            &grant,
            recipient.principal().as_ref(),
            &[],
            &recipient_ctx,
        )
        .unwrap();
        assert_eq!(
            opened.lane_id,
            resolve_contact_lane(&recipient, &sender_pub, 0).unwrap()
        );
        assert_eq!(opened.lookup_key, lane_lookup_key(&opened.lane_id).unwrap());
        let dumped = format!("{grant:?}");
        assert!(!dumped.contains(recipient.lane_id()));
        assert!(!dumped.contains(recipient.contact_lane_secret()));
        assert!(!dumped.contains(recipient.principal().as_ref()));
        assert!(!dumped.contains(recipient.current_priv()));
        assert!(!dumped.contains(sender.current_epriv()));
        assert_ne!(
            derive_contact_lane(
                recipient.lane_id(),
                recipient.principal().as_ref(),
                &sender_pub
            )
            .unwrap(),
            opened.lane_id
        );
        let wrong_sender = open_contact_lane_grant(
            &sender_pub,
            scalar_sea(6).1.as_str(),
            &grant,
            recipient.principal().as_ref(),
            &[],
            &recipient_ctx,
        )
        .unwrap_err();
        let wrong_recipient = open_contact_lane_grant(
            &sender_pub,
            sender.current_epriv(),
            &grant,
            &sender_pub,
            &[],
            &sender_ctx,
        )
        .unwrap_err();
        let mut tampered = grant.clone();
        let last = tampered.ciphertext_hex.pop().unwrap();
        tampered
            .ciphertext_hex
            .push(if last == '0' { '1' } else { '0' });
        let tamper = open_contact_lane_grant(
            &sender_pub,
            sender.current_epriv(),
            &tampered,
            recipient.principal().as_ref(),
            &[],
            &recipient_ctx,
        )
        .unwrap_err();
        assert_eq!(wrong_sender, EncDiscError::LaneGrantRejected);
        assert_eq!(wrong_recipient, EncDiscError::LaneGrantRejected);
        assert_eq!(tamper, EncDiscError::LaneGrantRejected);
        let names = trusted(&ring);
        let (next_pub, next_priv) = scalar_sea(20);
        let (next_epub, next_epriv) = scalar_sea(21);
        let lane = v["priorSecretHex"].as_str().unwrap().to_string();
        let rotated = rotate_keyring(
            &recipient,
            &names,
            ring["lost"].as_str().unwrap(),
            &[],
            &recipient_ctx,
            || {
                Ok(RotationMint {
                    signing_pub: next_pub.clone(),
                    signing_priv: next_priv.clone(),
                    epub: next_epub.clone(),
                    epriv: next_epriv.clone(),
                    lane_id: lane.clone(),
                    contact_lane_secret:
                        "0404040404040404040404040404040404040404040404040404040404040404"
                            .to_string(),
                })
            },
        )
        .unwrap();
        let chain = vec![sign_oidc_rotation(
            &signing_pub,
            1,
            &signing_pub,
            &next_pub,
            &next_epub,
            recipient_owned.now - 20,
            20,
            &link,
        )];
        let stale = open_contact_lane_grant(
            &sender_pub,
            sender.current_epriv(),
            &grant,
            rotated.keyring.principal().as_ref(),
            &chain,
            &recipient_ctx,
        )
        .unwrap_err();
        assert_eq!(stale, EncDiscError::LaneGrantRejected);
        let targets = [ContactTarget {
            principal: &sender_pub,
            rotations: &[],
            context: &sender_ctx,
        }];
        let fresh =
            regrant_contact_lanes(&rotated.keyring, &targets, &chain, &recipient_ctx).unwrap();
        assert_eq!(fresh.len(), 1);
        let reopened = open_contact_lane_grant(
            &sender_pub,
            sender.current_epriv(),
            &fresh[0],
            rotated.keyring.principal().as_ref(),
            &chain,
            &recipient_ctx,
        )
        .unwrap();
        assert_eq!(
            reopened.lane_id,
            resolve_contact_lane(&rotated.keyring, &sender_pub, 1).unwrap()
        );
        assert_eq!(reopened.rotation_seq, 1);
        assert_ne!(reopened.lane_id, opened.lane_id);
        assert!(!reopened.lookup_key.contains('~'));
    }

    #[test]
    fn builders_and_the_deterministic_seal_are_not_exported() {
        let lib = include_str!("lib.rs");
        for name in [
            "seal_contact_lane_grant_with",
            "contact_lane_info",
            "contact_lane_grant_plaintext",
            "contact_lane_grant_aad",
            "contact_lane_signature_message",
            "contact_lane_reuses_base",
            "contact_lane_mints_grant",
            "CONTACT_LANE_DOMAIN",
            "CONTACT_LANE_GRANT_DOMAIN",
            "CONTACT_LANE_GRANT_SIG_DOMAIN",
            "CONTACT_LANE_VERSION",
        ] {
            assert!(!lib.contains(name), "{name}");
        }
        let source = include_str!("contact_lane.rs");
        let library = source.split("#[cfg(test)]").next().unwrap();
        assert!(library.contains("pub(crate) fn seal_contact_lane_grant_with"));
        assert!(library.contains("feature = \"deterministic-wrap\""));
    }
}
