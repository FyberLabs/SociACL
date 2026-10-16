//! SEA-compatible P-256 keys.
//!
//! `pub` and `epub` are the SEA JWK coordinate form: base64url (no
//! padding) of the 32-byte big-endian x coordinate, `.`, then the same
//! for y. `priv` and `epriv` are base64url of the 32-byte scalar.
//!
//! Signatures are P-256 ECDSA over SHA-256 of the caller-supplied
//! bytes. The hash runs once, inside ECDSA. This is not SEA.sign's
//! JSON envelope and not a second pre-hash. The signature string is
//! lowercase hex of IEEE P1363 `r || s` (64 bytes), low-s. A DER
//! encoding or a high-s encoding does not verify.

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::error::EncDiscError;
use crate::hexutil::encode_hex;

pub fn sign_sea(sea_priv: &str, message: &[u8]) -> Result<String, EncDiscError> {
    let signing = signing_key(sea_priv)?;
    let signature: Signature = signing
        .try_sign(message)
        .map_err(|_| EncDiscError::SignatureRejected)?;
    // RFC 6979 can emit a high s. Low-s is the only encoding we accept.
    let signature = signature.normalize_s().unwrap_or(signature);
    Ok(encode_hex(signature.to_bytes().as_slice()))
}

pub fn verify_sea(sea_pub: &str, message: &[u8], signature_hex: &str) -> Result<(), EncDiscError> {
    if signature_hex.len() != 128 {
        return Err(EncDiscError::SignatureRejected);
    }
    let bytes =
        crate::hexutil::decode_hex(signature_hex).map_err(|_| EncDiscError::SignatureRejected)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| EncDiscError::SignatureRejected)?;
    if signature.normalize_s().is_some() {
        return Err(EncDiscError::SignatureRejected);
    }
    let verifying = verifying_key(sea_pub)?;
    verifying
        .verify(message, &signature)
        .map_err(|_| EncDiscError::SignatureRejected)
}

pub fn sea_pub_from_signing(signing: &SigningKey) -> Result<String, EncDiscError> {
    point_to_sea(&signing.verifying_key().to_encoded_point(false))
}

pub fn sea_priv_from_signing(signing: &SigningKey) -> Result<String, EncDiscError> {
    scalar_to_sea(signing.to_bytes().as_slice())
}

pub fn sea_pub_from_secret(secret: &SecretKey) -> Result<String, EncDiscError> {
    point_to_sea(&secret.public_key().to_encoded_point(false))
}

pub fn sea_priv_from_secret(secret: &SecretKey) -> Result<String, EncDiscError> {
    scalar_to_sea(secret.to_bytes().as_slice())
}

pub fn signing_key(sea_priv: &str) -> Result<SigningKey, EncDiscError> {
    let scalar = decode_scalar(sea_priv)?;
    SigningKey::from_slice(scalar.as_slice()).map_err(|_| EncDiscError::BadKey)
}

pub fn ecdh_secret(sea_epriv: &str) -> Result<SecretKey, EncDiscError> {
    let scalar = decode_scalar(sea_epriv)?;
    SecretKey::from_slice(scalar.as_slice()).map_err(|_| EncDiscError::BadKey)
}

pub fn parse_sea_point(sea_pub: &str) -> Result<PublicKey, EncDiscError> {
    let (x_text, y_text) = sea_pub.split_once('.').ok_or(EncDiscError::BadKey)?;
    if y_text.contains('.') {
        return Err(EncDiscError::BadKey);
    }
    let x = decode_coord(x_text)?;
    let y = decode_coord(y_text)?;
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&x);
    uncompressed[33..].copy_from_slice(&y);
    PublicKey::from_sec1_bytes(&uncompressed).map_err(|_| EncDiscError::BadKey)
}

pub fn ecdh_x(secret: &SecretKey, peer: &PublicKey) -> Result<[u8; 32], EncDiscError> {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), *peer.as_affine());
    let raw = shared.raw_secret_bytes();
    if raw.len() != 32 {
        return Err(EncDiscError::BadKey);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

pub fn uncompressed_point(public: &PublicKey) -> Result<[u8; 65], EncDiscError> {
    let encoded = public.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(EncDiscError::BadKey);
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn verifying_key(sea_pub: &str) -> Result<VerifyingKey, EncDiscError> {
    let public = parse_sea_point(sea_pub)?;
    VerifyingKey::from_sec1_bytes(public.to_encoded_point(false).as_bytes())
        .map_err(|_| EncDiscError::BadKey)
}

fn point_to_sea(encoded: &p256::EncodedPoint) -> Result<String, EncDiscError> {
    let x = encoded.x().ok_or(EncDiscError::BadKey)?;
    let y = encoded.y().ok_or(EncDiscError::BadKey)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(EncDiscError::BadKey);
    }
    Ok(format!("{}.{}", encode_b64(x)?, encode_b64(y)?))
}

fn scalar_to_sea(scalar: &[u8]) -> Result<String, EncDiscError> {
    encode_b64(scalar)
}

fn encode_b64(bytes: &[u8]) -> Result<String, EncDiscError> {
    let len = Base64UrlUnpadded::encoded_len(bytes);
    let mut buf = vec![0u8; len];
    let encoded = Base64UrlUnpadded::encode(bytes, &mut buf).map_err(|_| EncDiscError::BadKey)?;
    Ok(encoded.to_string())
}

fn decode_scalar(text: &str) -> Result<Zeroizing<[u8; 32]>, EncDiscError> {
    let bytes = decode_b64(text)?;
    if bytes.len() != 32 {
        return Err(EncDiscError::BadKey);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_coord(text: &str) -> Result<[u8; 32], EncDiscError> {
    let scalar = decode_scalar(text)?;
    Ok(*scalar)
}

#[cfg(test)]
mod tests {
    use super::{decode_b64, decode_scalar, sign_sea, signing_key, verify_sea};
    use serde::Deserialize;
    use zeroize::Zeroizing;

    #[derive(Deserialize)]
    struct Fixture {
        signing: Signing,
    }

    #[derive(Deserialize)]
    struct Signing {
        #[serde(rename = "priv")]
        sea_priv: String,
        #[serde(rename = "pub")]
        sea_pub: String,
        #[serde(rename = "sampleMessage")]
        sample_message: String,
        #[serde(rename = "sampleSignatureLowS")]
        low_s: String,
        #[serde(rename = "sampleSignatureHighS")]
        high_s: String,
    }

    #[test]
    fn rfc6979_sample_is_low_s() {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../vectors/encrypted-discovery/sea-fixture.json"
        ))
        .unwrap();
        let signing = &fixture.signing;
        let signature = sign_sea(&signing.sea_priv, signing.sample_message.as_bytes()).unwrap();
        assert_eq!(signature, signing.low_s);
        verify_sea(
            &signing.sea_pub,
            signing.sample_message.as_bytes(),
            &signature,
        )
        .unwrap();
        assert!(verify_sea(
            &signing.sea_pub,
            signing.sample_message.as_bytes(),
            &signing.high_s
        )
        .is_err());
    }

    #[test]
    fn decoded_private_scalar_stays_in_zeroizing_storage() {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../vectors/encrypted-discovery/sea-fixture.json"
        ))
        .unwrap();
        let scalar = decode_scalar(&fixture.signing.sea_priv).unwrap();
        let held: &Zeroizing<[u8; 32]> = &scalar;
        assert_eq!(held.len(), 32);
        assert_ne!(held.as_slice(), &[0u8; 32]);
        let signing = signing_key(&fixture.signing.sea_priv).unwrap();
        assert_eq!(signing.to_bytes().as_slice(), held.as_slice());
        let decoded = decode_b64(&fixture.signing.sea_priv).unwrap();
        let _: &Zeroizing<Vec<u8>> = &decoded;
        assert_eq!(decoded.as_slice(), held.as_slice());
    }
}

fn decode_b64(text: &str) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    let mut buf = Zeroizing::new(vec![0u8; text.len()]);
    let decoded_len = {
        let decoded =
            Base64UrlUnpadded::decode(text, &mut buf).map_err(|_| EncDiscError::BadKey)?;
        decoded.len()
    };
    buf.truncate(decoded_len);
    Ok(buf)
}
