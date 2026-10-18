//! Deliver an account keyring to a device. The outer domains are
//! `sociacl-keyring-delivery-v1` and `sociacl-keyring-delivery-sig-v1`,
//! separate from the genesis backup.
//!
//! The transport public key arrives out of band. The ciphertext goes to a
//! [`KeyWrapStore`]. The device inherits the account keypair and does not
//! mint an identity. The serialized keyring is refused when it is larger
//! than [`KEYRING_SERIAL_MAX`], before seal and before decrypt.
//!
//! [`deliver_keyring_with`] takes a caller-chosen ephemeral and nonce for
//! tests and is not re-exported.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sociacl_ids::{parse_principal_id, ObjectId, PrincipalId};
use zeroize::{Zeroize, Zeroizing};

use crate::canonical;
use crate::error::EncDiscError;
use crate::hexutil::{self, encode_hex};
use crate::identity::{
    aad_backup, current_signing_key, kdf_backup, signature_message, KeyWrapStore, TransportKey,
    WrapClass, WrapIndex,
};
use crate::keyring::AccountKeyring;
use crate::limits::{DELIVERY_BLOB_MAX, KEYRING_SERIAL_MAX};
use crate::recovery::{decode_keyring, encode_keyring};
use crate::sea::{self, ecdh_x, uncompressed_point};
use crate::EncryptedAccountWrap;

const VER_BACKUP: u8 = 1;

/// KDF info and AES-GCM associated data for a delivered keyring. Not the #63 backup domain.
pub(crate) const DOMAIN_DELIVERY_BIND: &str = "sociacl-keyring-delivery-v1";
/// Signature domain for a delivered keyring. Not the #63 wrap signature domain.
pub(crate) const DOMAIN_DELIVERY_SIG: &str = "sociacl-keyring-delivery-sig-v1";

/// Seal the keyring to `transport_pub` and store the wrap.
///
/// The ephemeral key and nonce are drawn here. `rotations` and `context`
/// are the trusted checkpoint (sociacl-ids §4.6).
pub fn deliver_keyring(
    keyring: &AccountKeyring,
    transport_pub: &str,
    wrap_id: &ObjectId,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    store: &mut impl KeyWrapStore,
) -> Result<EncryptedAccountWrap, EncDiscError> {
    let ephemeral = p256::SecretKey::random(&mut OsRng);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    deliver_keyring_with(
        keyring,
        transport_pub,
        &ephemeral,
        &nonce,
        wrap_id,
        rotations,
        context,
        store,
    )
}

/// Caller-chosen ephemeral and nonce. Tests only. Not a public export.
pub(crate) fn deliver_keyring_with(
    keyring: &AccountKeyring,
    transport_pub: &str,
    ephemeral: &p256::SecretKey,
    nonce: &[u8; 12],
    wrap_id: &ObjectId,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    store: &mut impl KeyWrapStore,
) -> Result<EncryptedAccountWrap, EncDiscError> {
    let plain = encode_keyring(keyring)?;
    if plain.len() > KEYRING_SERIAL_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let current = current_signing_key(keyring.principal(), rotations, context)?;
    if current.as_ref() != keyring.current_pub().as_ref() {
        return Err(EncDiscError::IdentityRejected("current-key".into()));
    }
    let peer = transport_peer(keyring, transport_pub)?;
    let ephemeral_pub = sea::sea_pub_from_secret(ephemeral)?;
    let shared = ecdh_x(ephemeral, &peer)?;
    let aes_key = kdf_backup(
        DOMAIN_DELIVERY_BIND,
        &shared,
        keyring.principal().as_ref(),
        wrap_id.as_ref(),
        transport_pub,
        &ephemeral_pub,
    )?;
    let aad = aad_backup(
        DOMAIN_DELIVERY_BIND,
        keyring.principal().as_ref(),
        wrap_id.as_ref(),
        transport_pub,
        &ephemeral_pub,
    )?;
    let ciphertext = encrypt(&aes_key, nonce, &aad, &plain)?;
    let point = uncompressed_point(&ephemeral.public_key())?;
    let mut blob = Vec::with_capacity(1 + 65 + 12 + ciphertext.len());
    blob.push(VER_BACKUP);
    blob.extend_from_slice(&point);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext);
    if blob.len() > DELIVERY_BLOB_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let message = signature_message(DOMAIN_DELIVERY_SIG, &blob, transport_pub, wrap_id.as_ref())?;
    let signature = sea::sign_sea(keyring.current_priv(), &message)?;
    let wrap = EncryptedAccountWrap {
        principal: keyring.principal().clone(),
        wrap_id: wrap_id.clone(),
        epub: keyring.current_epub().as_ref().to_string(),
        ciphertext_hex: encode_hex(&blob),
        signature,
        class: WrapClass::Delivery,
    };
    let index = WrapIndex {
        principal: wrap.principal.clone(),
        wrap_id: wrap.wrap_id.clone(),
        epub: wrap.epub.clone(),
    };
    let hash = crate::store_write::wrap_ciphertext_hash(&wrap.ciphertext_hex)?;
    let account = store.published_account(&wrap.principal)?;
    let head = account.rotations.len() as u64;
    let generation = store.write_generation(&wrap.principal);
    let replaced = match store.get_wrap(&wrap.principal, &wrap.wrap_id)? {
        Some(existing) => crate::store_write::wrap_ciphertext_hash(&existing.ciphertext_hex)?,
        None => crate::store_write::REPLACED_NONE.to_string(),
    };
    let store_signature = crate::store_write::sign_store_write(
        keyring.current_priv(),
        &wrap.principal,
        "put",
        wrap.wrap_id.as_ref(),
        &hash,
        &crate::store_write::decimal(head)?,
        &replaced,
        crate::store_write::STORE_CLASS_DELIVERY,
        &crate::store_write::decimal(generation)?,
    )?;
    store.put_wrap(&index, &wrap, &store_signature)?;
    Ok(wrap)
}

/// Open a delivered keyring. The device does not mint a new identity.
///
/// A blob longer than [`DELIVERY_BLOB_MAX`] is rejected before decrypt.
/// The current-key signature is checked before the plaintext is parsed.
/// `recovery-stale` is returned only when the plaintext sequence is older
/// and the signature also verifies under the key that was valid at that
/// sequence. That result is not proof the delivery is authentic: a copy
/// signed by a key the rotation was meant to cut off, including the lost
/// device's sequence-0 key, still returns `recovery-stale`. No key material
/// is accepted. A codec failure on this path is `wrap-rejected`.
pub fn open_delivered_keyring(
    transport: &TransportKey,
    wrap: &EncryptedAccountWrap,
    expected: &PrincipalId,
    expected_rotation_seq: u64,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<AccountKeyring, EncDiscError> {
    if transport.is_account() {
        return Err(EncDiscError::IdentityRejected("transport".into()));
    }
    if wrap.ciphertext_hex.len() > DELIVERY_BLOB_MAX * 2 {
        return Err(EncDiscError::KeyringTooLarge);
    }
    if wrap.principal.as_ref() != expected.as_ref() {
        return Err(EncDiscError::WrapRejected);
    }
    let blob = hexutil::decode_hex(&wrap.ciphertext_hex).map_err(|_| EncDiscError::WrapRejected)?;
    if blob.len() > DELIVERY_BLOB_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    if blob.first().copied() != Some(VER_BACKUP) || blob.len() < 1 + 65 + 12 + 16 {
        return Err(EncDiscError::WrapRejected);
    }
    // Parse the attacker-chosen point before copying the transport scalar.
    let ephemeral =
        p256::PublicKey::from_sec1_bytes(&blob[1..66]).map_err(|_| EncDiscError::WrapRejected)?;
    let nonce: [u8; 12] = blob[66..78]
        .try_into()
        .map_err(|_| EncDiscError::WrapRejected)?;
    let wrap_id = crate::parse_wrap_object(wrap.wrap_id.as_ref())?;
    let ephemeral_sea = sea::sea_pub_from_point(&ephemeral)?;
    let message = signature_message(
        DOMAIN_DELIVERY_SIG,
        &blob,
        transport.sea_pub(),
        wrap_id.as_ref(),
    )?;
    // The caller's checkpoint. A forger does not choose this chain, so a
    // resolution failure here still propagates.
    let current = current_signing_key(expected, rotations, context)?;
    let current_ok = sea::verify_sea(current.as_ref(), &message, &wrap.signature).is_ok();
    let shared = {
        let secret = transport.secret_key()?;
        ecdh_x(&secret, &ephemeral)?
    };
    let aes_key = kdf_backup(
        DOMAIN_DELIVERY_BIND,
        &shared,
        expected.as_ref(),
        wrap_id.as_ref(),
        transport.sea_pub(),
        &ephemeral_sea,
    )?;
    let aad = aad_backup(
        DOMAIN_DELIVERY_BIND,
        expected.as_ref(),
        wrap_id.as_ref(),
        transport.sea_pub(),
        &ephemeral_sea,
    )?;
    let mut plain = decrypt(&aes_key, &nonce, &aad, &blob[78..])?;
    if plain.len() > KEYRING_SERIAL_MAX {
        plain.zeroize();
        return Err(EncDiscError::KeyringTooLarge);
    }
    let opened = if current_ok {
        open_authenticated_delivery(
            &plain,
            wrap,
            expected,
            expected_rotation_seq,
            rotations,
            context,
            &message,
        )
    } else {
        Err(stale_or_rejected(
            &plain,
            expected,
            expected_rotation_seq,
            rotations,
            context,
            &message,
            &wrap.signature,
        ))
    };
    plain.zeroize();
    opened
}

fn open_authenticated_delivery(
    plain: &[u8],
    wrap: &EncryptedAccountWrap,
    expected: &PrincipalId,
    expected_rotation_seq: u64,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    message: &[u8],
) -> Result<AccountKeyring, EncDiscError> {
    let fields = decode_keyring(plain).map_err(|error| match error {
        EncDiscError::KeyringTooLarge => EncDiscError::KeyringTooLarge,
        _ => EncDiscError::WrapRejected,
    })?;
    if fields.rotation_seq != expected_rotation_seq {
        if fields.rotation_seq < expected_rotation_seq
            && historical_signature_ok(
                expected,
                rotations,
                fields.rotation_seq,
                context,
                message,
                &wrap.signature,
            )
        {
            return Err(EncDiscError::RecoveryStale);
        }
        return Err(EncDiscError::WrapRejected);
    }
    let parsed =
        parse_principal_id(fields.principal.as_str()).map_err(|_| EncDiscError::WrapRejected)?;
    if parsed.as_ref() != fields.principal.as_str() || parsed.as_ref() != expected.as_ref() {
        return Err(EncDiscError::WrapRejected);
    }
    let retired: Vec<(&str, &str)> = fields
        .retired
        .iter()
        .map(|(epub, epriv)| (epub.as_str(), epriv.as_str()))
        .collect();
    let prior: Vec<&str> = fields
        .prior_lanes
        .iter()
        .map(|lane| lane.as_str())
        .collect();
    let prior_contact: Vec<&str> = fields
        .prior_contact_secrets
        .iter()
        .map(|secret| secret.as_str())
        .collect();
    let keyring = AccountKeyring::import_with_contact_secrets(
        fields.principal.as_str(),
        fields.genesis_epub.as_str(),
        fields.current_pub.as_str(),
        fields.current_priv.as_str(),
        fields.current_epub.as_str(),
        fields.current_epriv.as_str(),
        &retired,
        fields.lane_id.as_str(),
        fields.content_epoch,
        fields.rotation_seq,
        rotations,
        context,
        &prior,
        fields.contact_lane_secret.as_str(),
        &prior_contact,
    )?;
    if keyring.current_epub().as_ref() != wrap.epub {
        return Err(EncDiscError::WrapRejected);
    }
    Ok(keyring)
}

/// Unauthenticated plaintext. Read only the trailing sequence. `recovery-stale`
/// requires a signature under the key that was current at that older sequence.
/// That result is not proof the delivery is genuine: a key the rotation was
/// meant to cut off can still produce it, and no key material is accepted.
fn stale_or_rejected(
    plain: &[u8],
    expected: &PrincipalId,
    expected_rotation_seq: u64,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    message: &[u8],
    signature: &str,
) -> EncDiscError {
    let Some(seq) = trailing_rotation_seq(plain) else {
        return EncDiscError::WrapRejected;
    };
    if seq < expected_rotation_seq
        && historical_signature_ok(expected, rotations, seq, context, message, signature)
    {
        return EncDiscError::RecoveryStale;
    }
    EncDiscError::WrapRejected
}

/// Rotation records whose own `seq` is at most `seq`. Array position is not a sequence.
fn rotations_through(rotations: &[serde_json::Value], seq: u64) -> Vec<serde_json::Value> {
    rotations
        .iter()
        .filter(|row| {
            let Some(object) = row.as_object() else {
                return false;
            };
            if object.get("kind").and_then(|kind| kind.as_str()) != Some("rotate") {
                return false;
            }
            object
                .get("seq")
                .and_then(|value| value.as_u64())
                .is_some_and(|record_seq| record_seq <= seq)
        })
        .cloned()
        .collect()
}

fn historical_signature_ok(
    expected: &PrincipalId,
    rotations: &[serde_json::Value],
    seq: u64,
    context: &sociacl_ids::ResolutionContext<'_>,
    message: &[u8],
    signature: &str,
) -> bool {
    let through = rotations_through(rotations, seq);
    let Ok(key) = current_signing_key(expected, &through, context) else {
        return false;
    };
    sea::verify_sea(key.as_ref(), message, signature).is_ok()
}

/// Last length-prefixed field, read as a canonical decimal. A walker failure
/// is not a codec error the caller can observe.
fn trailing_rotation_seq(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > KEYRING_SERIAL_MAX {
        return None;
    }
    let mut offset = 0usize;
    let mut last: Option<&[u8]> = None;
    while offset < bytes.len() {
        let len_bytes: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;
        let end = offset.checked_add(len)?;
        last = Some(bytes.get(offset..end)?);
        offset = end;
    }
    let text = std::str::from_utf8(last?).ok()?;
    canonical::parse_canonical_decimal(text).ok()
}

fn transport_peer(
    keyring: &AccountKeyring,
    transport_pub: &str,
) -> Result<p256::PublicKey, EncDiscError> {
    if transport_pub == keyring.principal().as_ref()
        || transport_pub == keyring.genesis_epub().as_ref()
        || transport_pub == keyring.current_pub().as_ref()
        || transport_pub == keyring.current_epub().as_ref()
        || keyring
            .retired()
            .iter()
            .any(|row| row.epub().as_ref() == transport_pub)
    {
        return Err(EncDiscError::IdentityRejected("transport".into()));
    }
    sea::parse_sea_point(transport_pub).map_err(|_| EncDiscError::BadKey)
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::WrapRejected)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| EncDiscError::WrapRejected)
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::WrapRejected)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| EncDiscError::WrapRejected)?;
    Ok(Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::DELIVERY_BLOB_MAX;
    use crate::recovery::MemoryRecoveryStore;
    use crate::{GenesisAccount, MemoryKeyWrapStore};
    use serde_json::Value;
    use sociacl_ids::{
        history_state, parse_object_id, resolve_current_key, HistoryResolver, Jwks, KeyState,
        PrincipalId, Reason, ResolutionContext, Rotate, SiwePolicy,
    };
    use std::collections::{BTreeMap, BTreeSet};

    const RING: &str = include_str!("../../../vectors/encrypted-discovery/account-keyring.json");
    const RECOVERY: &str = include_str!("../../../vectors/encrypted-discovery/recovery-copy.json");
    const RECORDS: &str = include_str!("../../../vectors/ids/records.json");

    fn recovery() -> Value {
        serde_json::from_str(RECOVERY).unwrap()
    }

    fn ring() -> Value {
        serde_json::from_str(RING).unwrap()
    }

    #[test]
    fn delivery_oversize_is_rejected_before_decrypt() {
        let v = recovery();
        let row = v["rejects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "delivery-above-cap")
            .unwrap();
        let bytes = row["blobBytes"].as_u64().unwrap() as usize;
        assert_eq!(bytes, DELIVERY_BLOB_MAX + 1);
        let g = &ring()["genesis"];
        let principal = sociacl_ids::parse_principal_id(g["principal"].as_str().unwrap()).unwrap();
        let wrap_id = parse_object_id(v["delivery"]["wrapId"].as_str().unwrap()).unwrap();
        let wrap = EncryptedAccountWrap {
            principal: principal.clone(),
            wrap_id,
            epub: g["epub"].as_str().unwrap().to_string(),
            ciphertext_hex: "aa".repeat(bytes),
            signature: "ab".repeat(64),
            class: WrapClass::Delivery,
        };
        let transport =
            TransportKey::from_scalar_hex(v["delivery"]["transportScalarHex"].as_str().unwrap())
                .unwrap();
        let held = hold();
        let ctx = context_of(&held);
        let error =
            open_delivered_keyring(&transport, &wrap, &principal, 0, &[], &ctx).unwrap_err();
        assert!(matches!(error, EncDiscError::KeyringTooLarge));
        assert_eq!(row["error"].as_str().unwrap(), "keyring-too-large");
    }

    #[test]
    fn delivered_keyring_matches_the_shared_vector() {
        let v = recovery();
        let delivery = &v["delivery"];
        let keyring = genesis_keyring();
        let held = hold();
        let ctx = context_of(&held);
        let mut store = MemoryKeyWrapStore::new(watch(&[], &ctx));
        let ephemeral = p256::SecretKey::from_slice(
            &hexutil::decode_hex(delivery["ephemeralScalarHex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let nonce_bytes = hexutil::decode_hex(delivery["nonceHex"].as_str().unwrap()).unwrap();
        let nonce: [u8; 12] = nonce_bytes.as_slice().try_into().unwrap();
        let wrap_id = parse_object_id(delivery["wrapId"].as_str().unwrap()).unwrap();
        let wrap = deliver_keyring_with(
            &keyring,
            delivery["transportPub"].as_str().unwrap(),
            &ephemeral,
            &nonce,
            &wrap_id,
            &[],
            &ctx,
            &mut store,
        )
        .unwrap();
        if delivery["ciphertextHex"].as_str().unwrap().is_empty() {
            panic!(
                "ciphertext {}\nsignature {}",
                wrap.ciphertext_hex, wrap.signature
            );
        }
        assert_eq!(
            wrap.ciphertext_hex,
            delivery["ciphertextHex"].as_str().unwrap()
        );
        assert_eq!(wrap.signature, delivery["signature"].as_str().unwrap());
        assert!(!store.is_authority());
        assert!(!store.mints_grant());
        assert!(!wrap.ciphertext_hex.contains(keyring.current_priv()));
        assert!(!wrap.ciphertext_hex.contains(keyring.current_epriv()));
        assert!(!wrap.ciphertext_hex.contains(keyring.lane_id()));
        let transport =
            TransportKey::from_scalar_hex(delivery["transportScalarHex"].as_str().unwrap())
                .unwrap();
        assert!(!transport.is_account());
        let opened =
            open_delivered_keyring(&transport, &wrap, keyring.principal(), 0, &[], &ctx).unwrap();
        assert_eq!(opened.principal(), keyring.principal());
        assert_eq!(opened.current_priv(), keyring.current_priv());
        assert_eq!(opened.current_epriv(), keyring.current_epriv());
        assert_eq!(opened.contact_lane_secret(), keyring.contact_lane_secret());
        assert_eq!(opened.lane_id(), keyring.lane_id());
        let ring_vector = ring();
        let sender = ring_vector["mint"]["signingPub"].as_str().unwrap();
        assert_eq!(
            crate::derive_contact_lane(
                opened.contact_lane_secret(),
                opened.principal().as_ref(),
                sender
            )
            .unwrap(),
            crate::derive_contact_lane(
                keyring.contact_lane_secret(),
                keyring.principal().as_ref(),
                sender
            )
            .unwrap()
        );
        let stale = open_delivered_keyring(&transport, &wrap, keyring.principal(), 1, &[], &ctx)
            .unwrap_err();
        assert!(matches!(stale, EncDiscError::RecoveryStale));
        let mut bad = wrap.clone();
        let mut signature = bad.signature.into_bytes();
        let last = signature.len() - 1;
        signature[last] = if signature[last] == b'0' { b'1' } else { b'0' };
        bad.signature = String::from_utf8(signature).unwrap();
        let stale_bad = open_delivered_keyring(&transport, &bad, keyring.principal(), 1, &[], &ctx)
            .unwrap_err();
        assert!(matches!(stale_bad, EncDiscError::WrapRejected));
        let mut forged = wrap.clone();
        forged.signature = "00".repeat(64);
        let forged_stale =
            open_delivered_keyring(&transport, &forged, keyring.principal(), 2, &[], &ctx)
                .unwrap_err();
        assert!(matches!(forged_stale, EncDiscError::WrapRejected));
        let garbage = forged_plaintext(
            &transport,
            keyring.principal(),
            keyring.current_epub().as_ref(),
            b"xyz",
            &"00".repeat(64),
        );
        let garbage_open =
            open_delivered_keyring(&transport, &garbage, keyring.principal(), 2, &[], &ctx)
                .unwrap_err();
        assert!(matches!(garbage_open, EncDiscError::WrapRejected));
        let seq_field = crate::canonical::length_prefixed(&["2"]).unwrap();
        let at_expected = forged_plaintext(
            &transport,
            keyring.principal(),
            keyring.current_epub().as_ref(),
            &seq_field,
            &"00".repeat(64),
        );
        let at_expected_open =
            open_delivered_keyring(&transport, &at_expected, keyring.principal(), 2, &[], &ctx)
                .unwrap_err();
        assert!(matches!(at_expected_open, EncDiscError::WrapRejected));
        let signed_garbage = {
            let mut row = forged_plaintext(
                &transport,
                keyring.principal(),
                keyring.current_epub().as_ref(),
                b"xyz",
                &"00".repeat(64),
            );
            let blob = hexutil::decode_hex(&row.ciphertext_hex).unwrap();
            let message = signature_message(
                DOMAIN_DELIVERY_SIG,
                &blob,
                transport.sea_pub(),
                row.wrap_id.as_ref(),
            )
            .unwrap();
            row.signature = sea::sign_sea(keyring.current_priv(), &message).unwrap();
            row
        };
        let codec = open_delivered_keyring(
            &transport,
            &signed_garbage,
            keyring.principal(),
            0,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert!(matches!(codec, EncDiscError::WrapRejected));
        let rejected = open_delivered_keyring(&transport, &bad, keyring.principal(), 0, &[], &ctx)
            .unwrap_err();
        assert!(matches!(rejected, EncDiscError::WrapRejected));
        let gun = opened.gun_document();
        assert!(!gun.contains(opened.current_priv()));
        assert!(!gun.contains(opened.lane_id()));
        let backup = crate::open_account_backup(&transport, &wrap, keyring.principal(), &[], &ctx)
            .unwrap_err();
        assert!(matches!(backup, EncDiscError::SignatureRejected));
        let wrong_scalar = TransportKey::from_scalar_hex(&format!("{:064x}", 5u32)).unwrap();
        let wrong_device =
            open_delivered_keyring(&wrong_scalar, &wrap, keyring.principal(), 0, &[], &ctx)
                .unwrap_err();
        assert!(matches!(wrong_device, EncDiscError::WrapRejected));
        let mut wrong_id = wrap.clone();
        wrong_id.wrap_id = parse_object_id("wrap_00112233445566778899aabbccddee00").unwrap();
        let wrong_wrap =
            open_delivered_keyring(&transport, &wrong_id, keyring.principal(), 0, &[], &ctx)
                .unwrap_err();
        assert!(matches!(wrong_wrap, EncDiscError::WrapRejected));
        let mut wrong_principal = wrap.clone();
        wrong_principal.principal =
            sociacl_ids::parse_principal_id(ring()["mint"]["signingPub"].as_str().unwrap())
                .unwrap();
        let wrong_account = open_delivered_keyring(
            &transport,
            &wrong_principal,
            keyring.principal(),
            0,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert!(matches!(wrong_account, EncDiscError::WrapRejected));
        let mut wrong_epub = wrap.clone();
        wrong_epub.epub = ring()["mint"]["epub"].as_str().unwrap().to_string();
        let epub =
            open_delivered_keyring(&transport, &wrong_epub, keyring.principal(), 0, &[], &ctx)
                .unwrap_err();
        assert!(matches!(epub, EncDiscError::WrapRejected));
        let _unused = MemoryRecoveryStore::new(watch(&[], &ctx));
    }

    #[test]
    fn two_devices_and_the_genesis_backup_share_the_store() {
        let v = recovery();
        let keyring = genesis_keyring();
        let held = hold();
        let ctx = context_of(&held);
        let mut store = MemoryKeyWrapStore::new(watch(&[], &ctx));
        let g = &ring()["genesis"];
        let account = GenesisAccount::import(
            g["laneId"].as_str().unwrap(),
            g["signingPub"].as_str().unwrap(),
            g["signingPriv"].as_str().unwrap(),
            g["epub"].as_str().unwrap(),
            g["epriv"].as_str().unwrap(),
        )
        .unwrap();
        let delivery = &v["delivery"];
        let transport_pub = delivery["transportPub"].as_str().unwrap();
        let genesis_id = parse_object_id("wrap_00112233445566778899aabbccddee01").unwrap();
        let first_id = parse_object_id(delivery["wrapId"].as_str().unwrap()).unwrap();
        let second_id = parse_object_id("wrap_00112233445566778899aabbccddee02").unwrap();
        let genesis =
            crate::seal_account_backup(&account, transport_pub, &genesis_id, &[], &ctx, &mut store)
                .unwrap();
        let ephemeral = p256::SecretKey::from_slice(
            &hexutil::decode_hex(delivery["ephemeralScalarHex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let nonce_bytes = hexutil::decode_hex(delivery["nonceHex"].as_str().unwrap()).unwrap();
        let nonce: [u8; 12] = nonce_bytes.as_slice().try_into().unwrap();
        let first = deliver_keyring_with(
            &keyring,
            transport_pub,
            &ephemeral,
            &nonce,
            &first_id,
            &[],
            &ctx,
            &mut store,
        )
        .unwrap();
        let second_transport = TransportKey::from_scalar_hex(&format!("{:064x}", 4u32)).unwrap();
        let second_ephemeral =
            p256::SecretKey::from_slice(&hexutil::decode_hex(&format!("{:064x}", 7u32)).unwrap())
                .unwrap();
        let second_nonce = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ];
        let second = deliver_keyring_with(
            &keyring,
            second_transport.sea_pub(),
            &second_ephemeral,
            &second_nonce,
            &second_id,
            &[],
            &ctx,
            &mut store,
        )
        .unwrap();
        assert_eq!(store.list_wraps(keyring.principal()).unwrap().len(), 3);
        assert_eq!(
            store
                .get_wrap(keyring.principal(), &genesis_id)
                .unwrap()
                .unwrap()
                .ciphertext_hex,
            genesis.ciphertext_hex
        );
        assert_eq!(
            store
                .get_wrap(keyring.principal(), &first_id)
                .unwrap()
                .unwrap()
                .ciphertext_hex,
            first.ciphertext_hex
        );
        let replacement = deliver_keyring_with(
            &keyring,
            second_transport.sea_pub(),
            &second_ephemeral,
            &[
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
            ],
            &second_id,
            &[],
            &ctx,
            &mut store,
        )
        .unwrap();
        assert_ne!(replacement.ciphertext_hex, second.ciphertext_hex);
        assert_eq!(store.list_wraps(keyring.principal()).unwrap().len(), 3);
        assert_eq!(
            store
                .get_wrap(keyring.principal(), &first_id)
                .unwrap()
                .unwrap()
                .ciphertext_hex,
            first.ciphertext_hex
        );
        assert_eq!(
            store
                .get_wrap(keyring.principal(), &second_id)
                .unwrap()
                .unwrap()
                .ciphertext_hex,
            replacement.ciphertext_hex
        );
        let crossed = deliver_keyring_with(
            &keyring,
            second_transport.sea_pub(),
            &second_ephemeral,
            &second_nonce,
            &genesis_id,
            &[],
            &ctx,
            &mut store,
        );
        assert!(matches!(crossed, Err(EncDiscError::StoreRejected)));
        assert_eq!(
            store
                .get_wrap(keyring.principal(), &genesis_id)
                .unwrap()
                .unwrap()
                .ciphertext_hex,
            genesis.ciphertext_hex
        );
        assert_eq!(store.list_wraps(keyring.principal()).unwrap().len(), 3);
    }

    #[test]
    fn wrap_rows_are_capped_and_a_class_sticks_to_its_id() {
        let principal =
            sociacl_ids::parse_principal_id(ring()["genesis"]["principal"].as_str().unwrap())
                .unwrap();
        let epub = ring()["genesis"]["epub"].as_str().unwrap().to_string();
        let held = hold();
        let ctx = context_of(&held);
        let records = ring();
        let signer = records["genesis"]["signingPriv"].as_str().unwrap();
        let mut store = MemoryKeyWrapStore::new(watch(&[], &ctx));
        let mut ids = Vec::new();
        for n in 0..crate::limits::MAX_WRAPS_PER_PRINCIPAL {
            let wrap_id = parse_object_id(&format!("wrap_{n:032x}")).unwrap();
            ids.push(wrap_id.clone());
            let class = if n == 0 {
                WrapClass::Genesis
            } else {
                WrapClass::Delivery
            };
            put_dummy(
                &mut store,
                &principal,
                &wrap_id,
                &epub,
                class,
                &format!("{n:02x}"),
                signer,
            )
            .unwrap();
        }
        assert_eq!(
            recovery()["limits"]["wrapsPerPrincipal"].as_u64().unwrap() as usize,
            crate::limits::MAX_WRAPS_PER_PRINCIPAL
        );
        let extra = parse_object_id(&format!("wrap_{:032x}", 80u32)).unwrap();
        let capped = put_dummy(
            &mut store,
            &principal,
            &extra,
            &epub,
            WrapClass::Delivery,
            "bb",
            signer,
        );
        assert!(matches!(capped, Err(EncDiscError::StoreRejected)));
        let unsigned = store.put_wrap(
            &WrapIndex {
                principal: principal.clone(),
                wrap_id: extra.clone(),
                epub: epub.clone(),
            },
            &dummy_wrap(&principal, &extra, &epub, WrapClass::Delivery, "ee"),
            "00",
        );
        assert!(matches!(unsigned, Err(EncDiscError::StoreRejected)));
        let first = ids[0].clone();
        let stuck = put_dummy(
            &mut store,
            &principal,
            &first,
            &epub,
            WrapClass::Delivery,
            "cc",
            signer,
        );
        assert!(matches!(stuck, Err(EncDiscError::StoreRejected)));
        let genesis_delete = crate::delete_account_wrap(&principal, &first, signer, &mut store);
        assert!(matches!(genesis_delete, Err(EncDiscError::StoreRejected)));
        assert_eq!(
            store
                .get_wrap(&principal, &first)
                .unwrap()
                .unwrap()
                .ciphertext_hex,
            "00"
        );
        let delivery = ids[1].clone();
        crate::delete_account_wrap(&principal, &delivery, signer, &mut store).unwrap();
        assert!(store.get_wrap(&principal, &delivery).unwrap().is_none());
        put_dummy(
            &mut store,
            &principal,
            &extra,
            &epub,
            WrapClass::Delivery,
            "bb",
            signer,
        )
        .unwrap();
        assert_eq!(
            store.list_wraps(&principal).unwrap().len(),
            crate::limits::MAX_WRAPS_PER_PRINCIPAL
        );
    }

    #[test]
    fn a_rotated_delivery_needs_its_chain_and_a_stale_seq_wins() {
        let ring = ring();
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let rotation = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == ring["witnessed"]["rotationName"].as_str().unwrap())
            .unwrap()["input"]
            .clone();
        let (genesis_pub, _genesis_priv) =
            scalar_sea(ring["witnessed"]["genesisScalar"].as_u64().unwrap() as u16);
        let (genesis_epub, genesis_epriv) =
            scalar_sea(ring["witnessed"]["genesisEpubScalar"].as_u64().unwrap() as u16);
        let (current_pub, current_priv) =
            scalar_sea(ring["witnessed"]["currentScalar"].as_u64().unwrap() as u16);
        let (current_epub, current_epriv) =
            scalar_sea(ring["witnessed"]["epubScalar"].as_u64().unwrap() as u16);
        let ctx = &records["context"];
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let pinned: BTreeSet<String> = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        let links: BTreeMap<String, Value> = ctx["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
            .collect();
        let authenticated = ctx["authenticatedAccounts"].clone();
        let history = |principal: &PrincipalId, at, until| {
            if !authenticated
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str() == Some(principal.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            let empty: Vec<Rotate> = Vec::new();
            Ok(history_state(principal, &empty, at, until))
        };
        let resolver: &HistoryResolver<'_> = &history;
        let revocations = Vec::new();
        let base = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &revocations,
            now: ctx["now"].as_u64().unwrap(),
            policy: &policy,
            pinned_iss: &pinned,
            history: resolver,
            genesis_epub_bindings: &[],
        };
        let retired = [(genesis_epub.as_str(), genesis_epriv.as_str())];
        let rotations = [rotation];
        let prior = ring["importPriorLanes"]["priorLane"].as_str().unwrap();
        let contact = ring["witnessContact"]["secret"].as_str().unwrap();
        let prior_contact = ring["witnessContact"]["prior"][0].as_str().unwrap();
        let keyring = AccountKeyring::import_with_contact_secrets(
            &genesis_pub,
            &genesis_epub,
            &current_pub,
            current_priv.as_str(),
            &current_epub,
            current_epriv.as_str(),
            &retired,
            ring["witnessed"]["laneId"].as_str().unwrap(),
            ring["witnessed"]["contentEpoch"].as_u64().unwrap(),
            ring["witnessed"]["rotationSeq"].as_u64().unwrap(),
            &rotations,
            &base,
            &[prior],
            contact,
            &[prior_contact],
        )
        .unwrap();
        let mut store = MemoryKeyWrapStore::new(watch(&rotations, &base));
        let transport = TransportKey::from_scalar_hex(&format!("{:064x}", 4u32)).unwrap();
        let ephemeral =
            p256::SecretKey::from_slice(&hexutil::decode_hex(&format!("{:064x}", 7u32)).unwrap())
                .unwrap();
        let nonce = [9u8; 12];
        let wrap_id = parse_object_id("wrap_00112233445566778899aabbccddee03").unwrap();
        let wrap = deliver_keyring_with(
            &keyring,
            transport.sea_pub(),
            &ephemeral,
            &nonce,
            &wrap_id,
            &rotations,
            &base,
            &mut store,
        )
        .unwrap();
        let opened =
            open_delivered_keyring(&transport, &wrap, keyring.principal(), 1, &rotations, &base)
                .unwrap();
        assert_eq!(opened.rotation_seq(), 1);
        let truncated =
            open_delivered_keyring(&transport, &wrap, keyring.principal(), 1, &[], &base)
                .unwrap_err();
        assert!(matches!(truncated, EncDiscError::WrapRejected));
        let not_older =
            open_delivered_keyring(&transport, &wrap, keyring.principal(), 0, &[], &base)
                .unwrap_err();
        assert!(matches!(not_older, EncDiscError::WrapRejected));
        let genuine =
            open_delivered_keyring(&transport, &wrap, keyring.principal(), 2, &rotations, &base)
                .unwrap_err();
        assert!(matches!(genuine, EncDiscError::RecoveryStale));
        let mut padded = vec![serde_json::json!({"kind": "nope", "seq": 0})];
        padded.extend(rotations.iter().cloned());
        let reordered =
            open_delivered_keyring(&transport, &wrap, keyring.principal(), 2, &padded, &base)
                .unwrap_err();
        assert!(matches!(reordered, EncDiscError::RecoveryStale));
        let mut zero = wrap.clone();
        zero.signature = "00".repeat(64);
        let forged =
            open_delivered_keyring(&transport, &zero, keyring.principal(), 2, &rotations, &base)
                .unwrap_err();
        assert!(matches!(forged, EncDiscError::WrapRejected));
    }

    #[test]
    fn a_retired_key_cannot_fill_or_relabel_wraps() {
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let chain: Vec<Value> = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "probe-v3-then-v3")
            .unwrap()["input"]
            .as_array()
            .unwrap()
            .clone();
        let (k0_pub, k0_priv) = scalar_sea(1);
        let (_k2_pub, k2_priv) = scalar_sea(3);
        let ctx = &records["context"];
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let pinned: BTreeSet<String> = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        let links: BTreeMap<String, Value> = ctx["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
            .collect();
        let authenticated = ctx["authenticatedAccounts"].clone();
        let history = |principal: &PrincipalId, at, until| {
            if !authenticated
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str() == Some(principal.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            let empty: Vec<Rotate> = Vec::new();
            Ok(history_state(principal, &empty, at, until))
        };
        let resolver: &HistoryResolver<'_> = &history;
        let revocations = Vec::new();
        let base = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &revocations,
            now: ctx["now"].as_u64().unwrap(),
            policy: &policy,
            pinned_iss: &pinned,
            history: resolver,
            genesis_epub_bindings: &[],
        };
        let principal = sociacl_ids::parse_principal_id(&k0_pub).unwrap();
        let ring = ring();
        let epub = ring["genesis"]["epub"].as_str().unwrap();
        let mut store = MemoryKeyWrapStore::new(watch(&chain, &base));
        for n in 0..crate::limits::MAX_WRAPS_PER_PRINCIPAL {
            let wrap_id = parse_object_id(&format!("wrap_{n:032x}")).unwrap();
            let refused = put_dummy(
                &mut store,
                &principal,
                &wrap_id,
                epub,
                WrapClass::Delivery,
                &format!("{n:02x}"),
                k0_priv.as_str(),
            );
            assert!(matches!(refused, Err(EncDiscError::StoreRejected)));
        }
        assert!(store.list_wraps(&principal).unwrap().is_empty());
        let wrap_id = parse_object_id("wrap_00112233445566778899aabbccddee11").unwrap();
        put_dummy(
            &mut store,
            &principal,
            &wrap_id,
            epub,
            WrapClass::Delivery,
            "aa",
            k2_priv.as_str(),
        )
        .unwrap();
        assert_eq!(store.list_wraps(&principal).unwrap().len(), 1);
        assert!(matches!(
            crate::delete_account_wrap(&principal, &wrap_id, k0_priv.as_str(), &mut store)
                .unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(
            store
                .get_wrap(&principal, &wrap_id)
                .unwrap()
                .unwrap()
                .ciphertext_hex,
            "aa"
        );

        let mut labeled = MemoryKeyWrapStore::new(watch(&chain, &base));
        let delivery = dummy_wrap(&principal, &wrap_id, epub, WrapClass::Delivery, "aa");
        let hash = crate::store_write::wrap_ciphertext_hash(&delivery.ciphertext_hex).unwrap();
        let signature = crate::store_write::sign_store_write(
            k2_priv.as_str(),
            &principal,
            "put",
            wrap_id.as_ref(),
            &hash,
            "2",
            crate::store_write::REPLACED_NONE,
            crate::store_write::STORE_CLASS_DELIVERY,
            "0",
        )
        .unwrap();
        let mut as_genesis = delivery.clone();
        as_genesis.class = WrapClass::Genesis;
        assert!(matches!(
            labeled
                .put_wrap(
                    &WrapIndex {
                        principal: principal.clone(),
                        wrap_id: wrap_id.clone(),
                        epub: epub.to_string(),
                    },
                    &as_genesis,
                    &signature,
                )
                .unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert!(labeled.get_wrap(&principal, &wrap_id).unwrap().is_none());
        labeled
            .put_wrap(
                &WrapIndex {
                    principal: principal.clone(),
                    wrap_id: wrap_id.clone(),
                    epub: epub.to_string(),
                },
                &delivery,
                &signature,
            )
            .unwrap();
        assert_eq!(
            labeled
                .get_wrap(&principal, &wrap_id)
                .unwrap()
                .unwrap()
                .class,
            WrapClass::Delivery
        );
        crate::delete_account_wrap(&principal, &wrap_id, k2_priv.as_str(), &mut labeled).unwrap();
        assert!(labeled.get_wrap(&principal, &wrap_id).unwrap().is_none());
    }

    fn put_dummy<C: crate::store_write::PublishedChain>(
        store: &mut MemoryKeyWrapStore<C>,
        principal: &PrincipalId,
        wrap_id: &sociacl_ids::ObjectId,
        epub: &str,
        class: WrapClass,
        ciphertext_hex: &str,
        signer: &str,
    ) -> Result<(), EncDiscError> {
        let wrap = dummy_wrap(principal, wrap_id, epub, class, ciphertext_hex);
        let hash = crate::store_write::wrap_ciphertext_hash(&wrap.ciphertext_hex)?;
        let account = store.published_account(principal)?;
        let head = account.rotations.len() as u64;
        let generation = store.write_generation(principal);
        let replaced = match store.get_wrap(principal, wrap_id)? {
            Some(existing) => crate::store_write::wrap_ciphertext_hash(&existing.ciphertext_hex)?,
            None => crate::store_write::REPLACED_NONE.to_string(),
        };
        let signature = crate::store_write::sign_store_write(
            signer,
            principal,
            "put",
            wrap_id.as_ref(),
            &hash,
            &crate::store_write::decimal(head)?,
            &replaced,
            crate::identity::wrap_class_label(class),
            &crate::store_write::decimal(generation)?,
        )?;
        store.put_wrap(
            &WrapIndex {
                principal: principal.clone(),
                wrap_id: wrap_id.clone(),
                epub: epub.to_string(),
            },
            &wrap,
            &signature,
        )
    }

    fn dummy_wrap(
        principal: &PrincipalId,
        wrap_id: &sociacl_ids::ObjectId,
        epub: &str,
        class: WrapClass,
        ciphertext_hex: &str,
    ) -> EncryptedAccountWrap {
        EncryptedAccountWrap {
            principal: principal.clone(),
            wrap_id: wrap_id.clone(),
            epub: epub.to_string(),
            ciphertext_hex: ciphertext_hex.to_string(),
            signature: "ab".repeat(64),
            class,
        }
    }

    fn forged_plaintext(
        transport: &TransportKey,
        principal: &PrincipalId,
        epub: &str,
        plain: &[u8],
        signature: &str,
    ) -> EncryptedAccountWrap {
        let ephemeral =
            p256::SecretKey::from_slice(&hexutil::decode_hex(&format!("{:064x}", 7u32)).unwrap())
                .unwrap();
        let nonce = [9u8; 12];
        let peer = ephemeral.public_key();
        let shared = {
            let secret = transport.secret_key().unwrap();
            ecdh_x(&secret, &peer).unwrap()
        };
        let ephemeral_sea = sea::sea_pub_from_point(&peer).unwrap();
        let wrap_id = parse_object_id("wrap_00112233445566778899aabbccddee09").unwrap();
        let aes_key = kdf_backup(
            DOMAIN_DELIVERY_BIND,
            &shared,
            principal.as_ref(),
            wrap_id.as_ref(),
            transport.sea_pub(),
            &ephemeral_sea,
        )
        .unwrap();
        let aad = aad_backup(
            DOMAIN_DELIVERY_BIND,
            principal.as_ref(),
            wrap_id.as_ref(),
            transport.sea_pub(),
            &ephemeral_sea,
        )
        .unwrap();
        let ciphertext = encrypt(&aes_key, &nonce, &aad, plain).unwrap();
        let point = uncompressed_point(&peer).unwrap();
        let mut blob = Vec::new();
        blob.push(VER_BACKUP);
        blob.extend_from_slice(&point);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        EncryptedAccountWrap {
            principal: principal.clone(),
            wrap_id,
            epub: epub.to_string(),
            ciphertext_hex: encode_hex(&blob),
            signature: signature.to_string(),
            class: WrapClass::Delivery,
        }
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

    fn scalar_sea(n: u16) -> (String, Zeroizing<String>) {
        let mut bytes = [0u8; 32];
        bytes[30] = (n >> 8) as u8;
        bytes[31] = n as u8;
        let secret = p256::SecretKey::from_slice(&bytes).unwrap();
        bytes.zeroize();
        (
            crate::sea::sea_pub_from_secret(&secret).unwrap(),
            crate::sea::sea_priv_from_secret(&secret).unwrap(),
        )
    }

    struct Hold {
        jwks: Jwks,
        policy: SiwePolicy,
        pinned: BTreeSet<String>,
        links: BTreeMap<String, Value>,
        binding: Vec<Value>,
        revocations: Vec<Value>,
        now: u64,
    }

    fn hold() -> Hold {
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let ctx = &records["context"];
        Hold {
            jwks: serde_json::from_value(ctx["jwks"].clone()).unwrap(),
            policy: serde_json::from_value(ctx["policy"].clone()).unwrap(),
            pinned: ctx["pinnedIss"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect(),
            links: ctx["links"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
                .collect(),
            binding: vec![ring()["genesisBinding"].clone()],
            revocations: Vec::new(),
            now: ctx["now"].as_u64().unwrap(),
        }
    }

    fn missing_history(_: &PrincipalId, _: u64, _: u64) -> Result<KeyState, Reason> {
        Err(Reason::MissingHistory)
    }

    fn context_of(hold: &Hold) -> ResolutionContext<'_> {
        ResolutionContext {
            jwks: &hold.jwks,
            links: &hold.links,
            revocations: &hold.revocations,
            now: hold.now,
            policy: &hold.policy,
            pinned_iss: &hold.pinned,
            history: &missing_history,
            genesis_epub_bindings: &hold.binding,
        }
    }

    fn watch<'a>(
        rotations: &'a [Value],
        context: &'a ResolutionContext<'a>,
    ) -> impl Fn(&PrincipalId) -> Result<sociacl_ids::ResolvedAccount, EncDiscError> + 'a {
        move |principal: &PrincipalId| {
            resolve_current_key(principal, rotations, context)
                .result
                .map_err(|_| EncDiscError::StoreRejected)
        }
    }
}
