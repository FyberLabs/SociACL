//! Authentication of exact-byte Panopticon exports, not installation of trust.
use crate::{parse_principal_id, records::unique_json, Jwks, Reason};
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const MAX_WITNESS_POLICY_BYTES: usize = 262144;
pub const MAX_WITNESS_ENVELOPE_BYTES: usize = 360448;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
const DOMAIN: &[u8] = b"sociacl-witness-policy-v1\n";

/// Authenticated transport document only; not installed trust or freshness proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessPolicy {
    #[serde(rename = "type")]
    pub kind: String,
    pub audience: String,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub jwks: Jwks,
}
fn exact(v: &Value, fields: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)))
}
fn integer(v: &Value) -> Result<u64, Reason> {
    v.as_u64()
        .filter(|n| *n <= MAX_INTEGER)
        .ok_or(Reason::BadAttestation)
}
fn decode(v: &Value) -> Result<Vec<u8>, Reason> {
    let s = v.as_str().ok_or(Reason::BadAttestation)?;
    let b = Base64UrlUnpadded::decode_vec(s).map_err(|_| Reason::BadAttestation)?;
    if b.is_empty() || Base64UrlUnpadded::encode_string(&b) != s {
        return Err(Reason::BadAttestation);
    }
    Ok(b)
}
/// Authenticate an export with an independently pinned administrative root and
/// audience and trusted current clock (no skew). This does not install JWKS.
/// Before use, an adapter must atomically enforce durable revision/key-history
/// rules and independently trusted bootstrap freshness. Input is JSON text so
/// duplicate envelope and payload members cannot be collapsed before verification.
pub fn verify_witness_policy_envelope(
    envelope: &str,
    root: &str,
    audience: &str,
    now: u64,
) -> Result<WitnessPolicy, Reason> {
    let bad = Reason::BadAttestation;
    if envelope.len() > MAX_WITNESS_ENVELOPE_BYTES || audience.is_empty() || now > MAX_INTEGER {
        return Err(bad);
    }
    let pinned = parse_principal_id(root).map_err(|_| bad)?;
    let outer = unique_json(envelope).map_err(|_| bad)?;
    if !exact(&outer, &["type", "payload", "signature"])
        || outer["type"] != "sociacl-witness-policy-envelope-v1"
    {
        return Err(bad);
    }
    let payload = decode(&outer["payload"])?;
    let raw_sig = decode(&outer["signature"])?;
    if payload.len() > MAX_WITNESS_POLICY_BYTES || raw_sig.len() != 64 {
        return Err(bad);
    }
    let signature = Signature::from_slice(&raw_sig).map_err(|_| bad)?;
    if signature.normalize_s().is_some() {
        return Err(bad);
    }
    let key =
        VerifyingKey::from_sec1_bytes(&crate::ids::principal_bytes(&pinned)).map_err(|_| bad)?;
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    key.verify(&message, &signature).map_err(|_| bad)?;
    let doc = unique_json(std::str::from_utf8(&payload).map_err(|_| bad)?).map_err(|_| bad)?;
    if !exact(
        &doc,
        &[
            "type",
            "audience",
            "revision",
            "issuedAt",
            "expiresAt",
            "jwks",
        ],
    ) || doc["type"] != "sociacl-witness-policy-v1"
        || doc["audience"] != audience
        || integer(&doc["revision"])? == 0
    {
        return Err(bad);
    }
    let start = integer(&doc["issuedAt"])?;
    let end = integer(&doc["expiresAt"])?;
    if end <= start
        || end - start > 86400
        || now < start
        || now >= end
        || !exact(&doc["jwks"], &["keys"])
    {
        return Err(bad);
    }
    let keys = doc["jwks"]["keys"].as_array().ok_or(bad)?;
    let mut kids = BTreeSet::new();
    let mut points = BTreeSet::new();
    for k in keys {
        if !exact(
            k,
            &[
                "kid",
                "kty",
                "crv",
                "alg",
                "use",
                "key_ops",
                "x",
                "y",
                "notBefore",
                "notAfter",
            ],
        ) || k["kty"] != "EC"
            || k["crv"] != "P-256"
            || k["alg"] != "ES256"
            || k["use"] != "sig"
            || k["key_ops"] != serde_json::json!(["verify"])
            || integer(&k["notBefore"])? >= integer(&k["notAfter"])?
        {
            return Err(bad);
        }
        let kid = k["kid"].as_str().ok_or(bad)?;
        if kid.is_empty() || kid.chars().count() > 128 || !kids.insert(kid) {
            return Err(bad);
        }
        let point = parse_principal_id(&format!(
            "{}.{}",
            k["x"].as_str().ok_or(bad)?,
            k["y"].as_str().ok_or(bad)?
        ))
        .map_err(|_| bad)?;
        if point == pinned || !points.insert(point) {
            return Err(bad);
        }
    }
    serde_json::from_value(doc).map_err(|_| bad)
}
