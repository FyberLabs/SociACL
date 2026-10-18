//! Deliver an account keyring to a device through the #63 sealed wrap.
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
    current_signing_key, KeyWrapStore, TransportKey, WrapIndex, DOMAIN_ACCOUNT_BIND,
    DOMAIN_ACCOUNT_SIG,
};
use crate::keyring::AccountKeyring;
use crate::limits::{DELIVERY_BLOB_MAX, KEYRING_SERIAL_MAX};
use crate::recovery::{decode_keyring, encode_keyring, keyring_ciphertext_hides_secrets};
use crate::sea::{self, ecdh_x, uncompressed_point};
use crate::EncryptedAccountWrap;

const VER_BACKUP: u8 = 1;

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
    let aes_key = kdf(
        &shared,
        keyring.principal().as_ref(),
        wrap_id.as_ref(),
        transport_pub,
        &ephemeral_pub,
    )?;
    let aad = aad(
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
    keyring_ciphertext_hides_secrets(&blob, keyring)?;
    let message = signature_message(&blob, transport_pub, wrap_id.as_ref())?;
    let signature = sea::sign_sea(keyring.current_priv(), &message)?;
    let wrap = EncryptedAccountWrap {
        principal: keyring.principal().clone(),
        wrap_id: wrap_id.clone(),
        epub: keyring.current_epub().as_ref().to_string(),
        ciphertext_hex: encode_hex(&blob),
        signature,
    };
    let index = WrapIndex {
        principal: wrap.principal.clone(),
        wrap_id: wrap.wrap_id.clone(),
        epub: wrap.epub.clone(),
    };
    store.put_wrap(&index, &wrap)?;
    Ok(wrap)
}

/// Open a delivered keyring. The device does not mint a new identity.
///
/// A blob longer than [`DELIVERY_BLOB_MAX`] is rejected before decrypt.
/// `expected_rotation_seq` makes a copy of an older keyring version stale.
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
    let ephemeral =
        p256::PublicKey::from_sec1_bytes(&blob[1..66]).map_err(|_| EncDiscError::WrapRejected)?;
    let nonce: [u8; 12] = blob[66..78]
        .try_into()
        .map_err(|_| EncDiscError::WrapRejected)?;
    let current = current_signing_key(expected, rotations, context)?;
    let wrap_id = crate::parse_wrap_object(wrap.wrap_id.as_ref())?;
    let message = signature_message(&blob, transport.sea_pub(), wrap_id.as_ref())?;
    sea::verify_sea(current.as_ref(), &message, &wrap.signature)?;
    let ephemeral_sea = sea::sea_pub_from_point(&ephemeral)?;
    let secret = transport.secret_key()?;
    let shared = ecdh_x(&secret, &ephemeral)?;
    let aes_key = kdf(
        &shared,
        expected.as_ref(),
        wrap_id.as_ref(),
        transport.sea_pub(),
        &ephemeral_sea,
    )?;
    let aad = aad(
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
    let fields = match decode_keyring(&plain) {
        Ok(fields) => fields,
        Err(error) => {
            plain.zeroize();
            return Err(error);
        }
    };
    plain.zeroize();
    let parsed =
        parse_principal_id(fields.principal.as_str()).map_err(|_| EncDiscError::WrapRejected)?;
    if parsed.as_ref() != fields.principal.as_str() || parsed.as_ref() != expected.as_ref() {
        return Err(EncDiscError::WrapRejected);
    }
    if fields.rotation_seq != expected_rotation_seq {
        return Err(EncDiscError::RecoveryStale);
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
    let keyring = AccountKeyring::import_with_prior_lanes(
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
    )?;
    if keyring.current_epub().as_ref() != wrap.epub {
        return Err(EncDiscError::WrapRejected);
    }
    Ok(keyring)
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

fn kdf(
    shared_x: &[u8; 32],
    principal: &str,
    wrap_id: &str,
    transport_pub: &str,
    ephemeral_pub: &str,
) -> Result<Zeroizing<[u8; 32]>, EncDiscError> {
    let hex = hexutil::encode_secret_hex(shared_x);
    let bytes = Zeroizing::new(canonical::length_prefixed(&[
        DOMAIN_ACCOUNT_BIND,
        hex.as_str(),
        principal,
        wrap_id,
        transport_pub,
        ephemeral_pub,
    ])?);
    Ok(Zeroizing::new(canonical::sha256(&bytes)))
}

fn aad(
    principal: &str,
    wrap_id: &str,
    transport_pub: &str,
    ephemeral_pub: &str,
) -> Result<Vec<u8>, EncDiscError> {
    canonical::length_prefixed(&[
        DOMAIN_ACCOUNT_BIND,
        principal,
        wrap_id,
        transport_pub,
        ephemeral_pub,
    ])
}

fn signature_message(
    blob: &[u8],
    transport_pub: &str,
    wrap_id: &str,
) -> Result<Vec<u8>, EncDiscError> {
    let digest = canonical::sha256_hex(blob);
    canonical::length_prefixed(&[DOMAIN_ACCOUNT_SIG, digest.as_str(), transport_pub, wrap_id])
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
        parse_object_id, Jwks, KeyState, PrincipalId, Reason, ResolutionContext, SiwePolicy,
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
        let mut store = MemoryKeyWrapStore::default();
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
        let stale = open_delivered_keyring(&transport, &wrap, keyring.principal(), 1, &[], &ctx)
            .unwrap_err();
        assert!(matches!(stale, EncDiscError::RecoveryStale));
        let gun = opened.gun_document();
        assert!(!gun.contains(opened.current_priv()));
        assert!(!gun.contains(opened.lane_id()));
        let _unused = MemoryRecoveryStore::default();
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
        AccountKeyring::from_genesis(&account).unwrap()
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
}
