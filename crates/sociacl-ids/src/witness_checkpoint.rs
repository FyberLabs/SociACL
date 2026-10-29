//! Authentication only: adapters own one-use challenges, durable continuity and leases.
use crate::{
    advance_witness_policy, parse_principal_id, records::unique_json, Reason, WitnessPolicyState,
    MAX_WITNESS_STATE_BYTES,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

pub const MAX_WITNESS_CHECKPOINT_BYTES: usize = MAX_WITNESS_STATE_BYTES + 8192;
pub const MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES: usize = 3145728;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
const DOMAIN: &[u8] = b"sociacl-witness-checkpoint-v1\n";

/// Independently provisioned expectations; never fill these from the response.
/// Challenge is canonical unpadded base64url for 32 fresh unpredictable bytes.
pub struct WitnessCheckpointExpectations<'a> {
    pub management_root: &'a str,
    pub root: &'a str,
    pub root_epoch: u64,
    pub audience: &'a str,
    pub client: &'a str,
    pub challenge: &'a str,
    pub minimum_revision: u64,
    pub now: u64,
}
/// Authenticated candidate only. Successful verification is NOT durable installation.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessCheckpoint {
    #[serde(rename = "type")]
    pub kind: String,
    pub audience: String,
    pub client: String,
    pub challenge: String,
    pub root_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: WitnessPolicyState,
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
/// Verify both exact-byte signatures, context and expiry at the supplied trusted
/// UTC time. Does not consume a challenge, reconcile protected local history,
/// install trust, authorize root migration/recovery or track a monotonic lease.
pub fn verify_witness_checkpoint(
    envelope: &str,
    policy_envelope: &str,
    expected: &WitnessCheckpointExpectations<'_>,
) -> Result<WitnessCheckpoint, Reason> {
    let bad = Reason::BadAttestation;
    if envelope.len() > MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES
        || expected.management_root == expected.root
        || expected.root_epoch == 0
        || expected.root_epoch > MAX_INTEGER
        || expected.minimum_revision == 0
        || expected.minimum_revision > MAX_INTEGER
        || expected.now > MAX_INTEGER
        || expected.audience.is_empty()
        || expected.audience.len() > 1024
        || expected.client.is_empty()
        || expected.client.len() > 1024
        || expected.challenge.len() != 43
        || decode(&Value::String(expected.challenge.into()))?.len() != 32
    {
        return Err(bad);
    }
    let management = parse_principal_id(expected.management_root).map_err(|_| bad)?;
    parse_principal_id(expected.root).map_err(|_| bad)?;
    let outer = unique_json(envelope).map_err(|_| bad)?;
    if !exact(&outer, &["type", "payload", "signature"])
        || outer["type"] != "sociacl-witness-checkpoint-envelope-v1"
    {
        return Err(bad);
    }
    let payload = decode(&outer["payload"])?;
    let signature = decode(&outer["signature"])?;
    if payload.len() > MAX_WITNESS_CHECKPOINT_BYTES || signature.len() != 64 {
        return Err(bad);
    }
    let signature = Signature::from_slice(&signature).map_err(|_| bad)?;
    if signature.normalize_s() != signature {
        return Err(bad);
    }
    let key = VerifyingKey::from_sec1_bytes(&crate::ids::principal_bytes(&management))
        .map_err(|_| bad)?;
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    key.verify(&message, &signature).map_err(|_| bad)?;
    let doc = unique_json(std::str::from_utf8(&payload).map_err(|_| bad)?).map_err(|_| bad)?;
    if !exact(
        &doc,
        &[
            "type",
            "audience",
            "client",
            "challenge",
            "rootEpoch",
            "issuedAt",
            "expiresAt",
            "state",
        ],
    ) || doc["type"] != "sociacl-witness-checkpoint-v1"
        || doc["audience"] != expected.audience
        || doc["client"] != expected.client
        || doc["challenge"] != expected.challenge
        || integer(&doc["rootEpoch"])? != expected.root_epoch
    {
        return Err(bad);
    }
    let start = integer(&doc["issuedAt"])?;
    let end = integer(&doc["expiresAt"])?;
    if end <= start || end - start > 300 || expected.now < start || expected.now >= end {
        return Err(bad);
    }
    let state_json = serde_json::to_string(&doc["state"]).map_err(|_| bad)?;
    let state = advance_witness_policy(
        policy_envelope,
        Some(&state_json),
        expected.root,
        expected.audience,
        expected.minimum_revision,
        expected.now,
    )?;
    if state.revision != integer(&doc["state"]["revision"])?
        || state
            .history
            .iter()
            .any(|e| format!("{}.{}", e.jwk.x, e.jwk.y) == expected.management_root)
    {
        return Err(bad);
    }
    Ok(WitnessCheckpoint {
        kind: "sociacl-witness-checkpoint-v1".into(),
        audience: expected.audience.into(),
        client: expected.client.into(),
        challenge: expected.challenge.into(),
        root_epoch: expected.root_epoch,
        issued_at: start,
        expires_at: end,
        state,
    })
}

/// Authenticate and reconcile against existing trusted continuity. No reset or
/// bootstrap is provided. Run against the latest state inside the adapter lock.
pub fn advance_witness_checkpoint(
    envelope: &str,
    policy_envelope: &str,
    previous_json: &str,
    expected: &WitnessCheckpointExpectations<'_>,
) -> Result<WitnessCheckpoint, Reason> {
    let checkpoint = verify_witness_checkpoint(envelope, policy_envelope, expected)?;
    let required = advance_witness_policy(
        policy_envelope,
        Some(previous_json),
        expected.root,
        expected.audience,
        expected.minimum_revision,
        expected.now,
    )?;
    let offered: std::collections::BTreeMap<_, _> = checkpoint
        .state
        .history
        .iter()
        .map(|entry| (&entry.jwk.kid, entry))
        .collect();
    for old in &required.history {
        let next = offered.get(&old.jwk.kid).ok_or(Reason::BadAttestation)?;
        if (old.removed && !next.removed)
            || next.jwk.x != old.jwk.x
            || next.jwk.y != old.jwk.y
            || next.jwk.not_before < old.jwk.not_before
            || next.jwk.not_after > old.jwk.not_after
        {
            return Err(Reason::BadAttestation);
        }
    }
    Ok(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    #[test]
    fn checkpoint_transport_byte_boundaries() {
        let f: Value =
            serde_json::from_str(include_str!("../../../vectors/ids/witness-checkpoint.json"))
                .unwrap();
        let c = &f["context"];
        let expected = WitnessCheckpointExpectations {
            management_root: c["managementRoot"].as_str().unwrap(),
            root: c["root"].as_str().unwrap(),
            root_epoch: c["rootEpoch"].as_u64().unwrap(),
            audience: c["audience"].as_str().unwrap(),
            client: c["client"].as_str().unwrap(),
            challenge: c["challenge"].as_str().unwrap(),
            minimum_revision: c["minimumRevision"].as_u64().unwrap(),
            now: c["now"].as_u64().unwrap(),
        };
        let wire = f["accept"][0]["input"]["checkpoint"].as_str().unwrap();
        let policy = f["accept"][0]["input"]["policy"].as_str().unwrap();
        let padded = format!(
            "{}{}",
            wire,
            " ".repeat(MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES - wire.len())
        );
        assert!(verify_witness_checkpoint(&padded, policy, &expected).is_ok());
        assert!(verify_witness_checkpoint(&(padded + " "), policy, &expected).is_err());
        let mut outer: Value = serde_json::from_str(wire).unwrap();
        let mut payload = decode(&outer["payload"]).unwrap();
        // Public fixture scalar 18, not production key material.
        let mut scalar = [0u8; 32];
        scalar[31] = 18;
        let signing = SigningKey::from_slice(&scalar).unwrap();
        for length in [
            MAX_WITNESS_CHECKPOINT_BYTES,
            MAX_WITNESS_CHECKPOINT_BYTES + 1,
        ] {
            payload.resize(length, b' ');
            let mut message = DOMAIN.to_vec();
            message.extend_from_slice(&payload);
            let signature: Signature = signing.sign(&message);
            outer["payload"] = Base64UrlUnpadded::encode_string(&payload).into();
            outer["signature"] =
                Base64UrlUnpadded::encode_string(&signature.normalize_s().to_bytes()).into();
            assert_eq!(
                verify_witness_checkpoint(&outer.to_string(), policy, &expected).is_ok(),
                length == MAX_WITNESS_CHECKPOINT_BYTES
            );
        }
    }
}
