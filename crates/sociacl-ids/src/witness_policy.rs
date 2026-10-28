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
    validate_keys(doc["jwks"]["keys"].as_array().ok_or(bad)?, &pinned)?;
    serde_json::from_value(doc).map_err(|_| bad)
}

fn validate_keys(keys: &[Value], pinned: &crate::PrincipalId) -> Result<(), Reason> {
    let bad = Reason::BadAttestation;
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
        if &point == pinned || !points.insert(point) {
            return Err(bad);
        }
    }
    Ok(())
}

pub const MAX_WITNESS_POLICY_HISTORY: usize = 1024;
pub const MAX_WITNESS_STATE_BYTES: usize = 2097152;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPolicyHistoryEntry {
    pub jwk: crate::Jwk,
    pub removed: bool,
}
/// Candidate for atomic durable commit, never untrusted transport state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPolicyState {
    #[serde(rename = "type")]
    pub kind: String,
    pub root: String,
    pub audience: String,
    pub revision: u64,
    pub jwks: Jwks,
    pub history: Vec<WitnessPolicyHistoryEntry>,
}
fn same_registry(a: &Jwks, b: &Jwks) -> bool {
    let keys: std::collections::BTreeMap<_, _> = a.keys.iter().map(|k| (&k.kid, k)).collect();
    a.keys.len() == b.keys.len()
        && b.keys.iter().all(|k| {
            keys.get(&k.kid).is_some_and(|old| {
                old.x == k.x
                    && old.y == k.y
                    && old.not_before == k.not_before
                    && old.not_after == k.not_after
            })
        })
}
/// Calculate the next snapshot inside an adapter's serialized update. Previous
/// JSON must come from trusted rollback-protected storage; None is only for an
/// independently authorized initial bootstrap. Re-run on current state/clock
/// after lock waits or CAS conflicts, and atomically persist the whole result
/// before exposing its JWKS. This pure function provides no persistence or proof
/// that the supplied previous state is fresh. minimum_revision is a trusted,
/// positive bootstrap floor, not a hint from the envelope or network.
pub fn advance_witness_policy(
    envelope: &str,
    previous_json: Option<&str>,
    root: &str,
    audience: &str,
    minimum_revision: u64,
    now: u64,
) -> Result<WitnessPolicyState, Reason> {
    let bad = Reason::BadAttestation;
    if minimum_revision == 0 || minimum_revision > MAX_INTEGER {
        return Err(bad);
    }
    let mut policy = verify_witness_policy_envelope(envelope, root, audience, now)?;
    if policy.revision < minimum_revision {
        return Err(bad);
    }
    let pinned = parse_principal_id(root).map_err(|_| bad)?;
    let mut history = std::collections::BTreeMap::new();
    if let Some(source) = previous_json {
        if source.len() > MAX_WITNESS_STATE_BYTES {
            return Err(bad);
        }
        let raw = unique_json(source).map_err(|_| bad)?;
        if !exact(
            &raw,
            &["type", "root", "audience", "revision", "jwks", "history"],
        ) || raw["type"] != "sociacl-witness-policy-state-v1"
            || raw["root"] != root
            || raw["audience"] != audience
            || integer(&raw["revision"])? == 0
            || !exact(&raw["jwks"], &["keys"])
        {
            return Err(bad);
        }
        let entries = raw["history"].as_array().ok_or(bad)?;
        if entries.len() > MAX_WITNESS_POLICY_HISTORY {
            return Err(bad);
        }
        for e in entries {
            if !exact(e, &["jwk", "removed"]) || !e["removed"].is_boolean() {
                return Err(bad);
            }
        }
        validate_keys(raw["jwks"]["keys"].as_array().ok_or(bad)?, &pinned)?;
        validate_keys(
            &entries.iter().map(|e| e["jwk"].clone()).collect::<Vec<_>>(),
            &pinned,
        )?;
        let previous: WitnessPolicyState = serde_json::from_value(raw).map_err(|_| bad)?;
        let active = Jwks {
            keys: previous
                .history
                .iter()
                .filter(|e| !e.removed)
                .map(|e| e.jwk.clone())
                .collect(),
        };
        if !same_registry(&previous.jwks, &active)
            || policy.revision < previous.revision
            || (policy.revision == previous.revision
                && !same_registry(&policy.jwks, &previous.jwks))
        {
            return Err(bad);
        }
        history.extend(previous.history.into_iter().map(|e| (e.jwk.kid.clone(), e)));
    }
    let material: BTreeSet<_> = history
        .values()
        .map(|e| (e.jwk.x.clone(), e.jwk.y.clone()))
        .collect();
    let mut present = BTreeSet::new();
    for k in &policy.jwks.keys {
        present.insert(k.kid.clone());
        if let Some(old) = history.get(&k.kid) {
            if old.removed
                || k.x != old.jwk.x
                || k.y != old.jwk.y
                || k.not_before < old.jwk.not_before
                || k.not_after > old.jwk.not_after
            {
                return Err(bad);
            }
        } else if material.contains(&(k.x.clone(), k.y.clone())) {
            return Err(bad);
        }
        history.insert(
            k.kid.clone(),
            WitnessPolicyHistoryEntry {
                jwk: k.clone(),
                removed: false,
            },
        );
    }
    if history.len() > MAX_WITNESS_POLICY_HISTORY {
        return Err(bad);
    }
    for (kid, entry) in &mut history {
        if !present.contains(kid) {
            entry.removed = true;
        }
    }
    policy.jwks.keys.sort_by(|a, b| a.kid.cmp(&b.kid));
    let result = WitnessPolicyState {
        kind: "sociacl-witness-policy-state-v1".into(),
        root: root.into(),
        audience: audience.into(),
        revision: policy.revision,
        jwks: policy.jwks,
        history: history.into_values().collect(),
    };
    if serde_json::to_vec(&result).map_err(|_| bad)?.len() > MAX_WITNESS_STATE_BYTES {
        return Err(bad);
    }
    Ok(result)
}
