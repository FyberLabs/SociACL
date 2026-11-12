//! Experimental timestamp receipts, not account rotation or grant authority.
use crate::{length_prefixed, parse_principal_id, verify_key_signature, verify_signed_at, PrincipalId, Reason, ResolutionContext};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
const MAX_SAFE: u64 = 9_007_199_254_740_991;
pub const WITNESS_REQUEST_DOMAIN: &str = "sociacl-independent-witness-request-v1";
pub const WITNESS_RECEIPT_DOMAIN: &str = "sociacl-independent-witness-receipt-v1";
#[derive(Clone, Debug)]
pub struct WitnessRequest {
    pub principal: PrincipalId, pub operation: String, pub record_digest: String,
    pub policy_id: String, pub epoch: u64, pub issued_at: u64, pub expires_at: u64, pub sig: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all="camelCase")]
pub struct IndependentWitnessObservation {
    pub request_id: String, pub record_digest: String, pub policy_id: String,
    pub epoch: u64, pub operators: Vec<String>, pub timestamp_upper_bound: u64,
}
fn fields(v: &Value, expected: &[&str]) -> Result<(), Reason> {
    let map = v.as_object().ok_or(Reason::BadAttestation)?;
    if map.len() != expected.len() || !expected.iter().all(|k| map.contains_key(*k)) { return Err(Reason::BadAttestation); }
    Ok(())
}
fn number(v: &Value) -> Result<u64, Reason> {
    let n = v.as_f64().ok_or(Reason::BadAttestation)?;
    if !n.is_finite() || n.is_sign_negative() || n.fract() != 0.0 || n > MAX_SAFE as f64 { return Err(Reason::BadAttestation); }
    Ok(n as u64)
}
fn text(v: &Value, max: usize) -> Result<&str, Reason> {
    let s = v.as_str().ok_or(Reason::BadAttestation)?;
    if s.len() > max { return Err(Reason::BadAttestation); } Ok(s)
}
fn hash(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn digest(b: &[u8]) -> String { Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect() }
fn array(v: &Value, max: usize) -> Result<&[Value], Reason> {
    let a = v.as_array().ok_or(Reason::BadAttestation)?;
    if a.len() > max { return Err(Reason::BadAttestation); } Ok(a)
}
fn operator(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn parse_witness_request(v: &Value) -> Result<WitnessRequest, Reason> {
    fields(v, &["v","principal","operation","recordDigest","policyId","epoch","issuedAt","expiresAt","sig"])?;
    let op = text(&v["operation"], 6)?;
    let record = text(&v["recordDigest"],64)?; let policy = text(&v["policyId"],64)?;
    let epoch = number(&v["epoch"])?; let issued_at = number(&v["issuedAt"])?; let expires_at = number(&v["expiresAt"])?;
    if number(&v["v"])? != 1 || !matches!(op,"rotate"|"revoke") || !hash(record) || !hash(policy)
        || epoch == 0 || expires_at <= issued_at || expires_at-issued_at > 600 { return Err(Reason::BadAttestation); }
    Ok(WitnessRequest { principal: parse_principal_id(text(&v["principal"],87)?)?, operation: op.into(),
        record_digest: record.into(), policy_id: policy.into(), epoch, issued_at, expires_at, sig: text(&v["sig"],128)?.into() })
}
pub fn witness_request_bytes(r: &WitnessRequest) -> Result<Vec<u8>, Reason> {
    length_prefixed(&[WITNESS_REQUEST_DOMAIN,"1",r.principal.as_ref(),&r.operation,&r.record_digest,&r.policy_id,
        &r.epoch.to_string(),&r.issued_at.to_string(),&r.expires_at.to_string()])
}
pub fn witness_receipt_bytes(r: &WitnessRequest, operator: &str, observed_at: u64) -> Result<Vec<u8>, Reason> {
    length_prefixed(&[WITNESS_RECEIPT_DOMAIN,&digest(&witness_request_bytes(r)?),operator,&observed_at.to_string()])
}
/// Policy and expected record digest must come from independent authenticated
/// state. Every included receipt must verify; no single-witness fallback exists.
/// Quorum arithmetic does not implement durable anti-equivocation or consensus.
pub fn verify_independent_witnesses(request: &Value, receipts: &Value, policy: &Value,
    expected_record_digest: &str, rotations: &[Value], ctx: &ResolutionContext<'_>) -> Result<IndependentWitnessObservation, Reason> {
    let r = parse_witness_request(request)?;
    fields(policy,&["id","epoch","threshold","maxFaulty","operators"])?;
    let ops = array(&policy["operators"],16)?; let rows = array(receipts,16)?;
    let id = text(&policy["id"],64)?; let epoch = number(&policy["epoch"])?;
    let q = number(&policy["threshold"])?; let f = number(&policy["maxFaulty"])?; let n = ops.len() as u64;
    if !hash(id) || epoch == 0 || n == 0 || f >= n || q <= f || q > n-f ||
        !hash(expected_record_digest) || r.record_digest != expected_record_digest || r.policy_id != id || r.epoch != epoch ||
        ctx.now > MAX_SAFE || ctx.now < r.issued_at || ctx.now >= r.expires_at ||
        (r.operation == "rotate" && 2*q <= n+f) { return Err(Reason::BadAttestation); }
    let mut operators = BTreeMap::new(); let mut keys = BTreeSet::new();
    for op in ops {
        fields(op,&["id","keys"])?; let name = text(&op["id"],64)?;
        let entries = array(&op["keys"],4)?;
        if !operator(name) || operators.contains_key(name) || entries.is_empty() { return Err(Reason::BadAttestation); }
        let mut parsed = Vec::new();
        for k in entries {
            fields(k,&["key","notBefore","notAfter"])?;
            let key = parse_principal_id(text(&k["key"],87)?)?;
            let before = number(&k["notBefore"])?; let after = number(&k["notAfter"])?;
            if key == r.principal || before >= after || !keys.insert(key.as_ref().to_owned()) { return Err(Reason::BadAttestation); }
            parsed.push((key,before,after));
        }
        operators.insert(name,parsed);
    }
    let bytes = witness_request_bytes(&r)?;
    let account = verify_signed_at(&r.principal,rotations,ctx,&bytes,&r.sig,r.issued_at)?;
    let history = (ctx.history)(&r.principal,r.issued_at,ctx.now)?;
    if history.key != account.key || history.current_key != account.key || keys.contains(account.key.as_ref()) { return Err(Reason::MissingHistory); }
    let mut seen = BTreeSet::new(); let mut upper = r.issued_at;
    for row in rows {
        fields(row,&["operator","observedAt","sig"])?;
        let op = text(&row["operator"],64)?; let at = number(&row["observedAt"])?;
        let keys = operators.get(op).ok_or(Reason::BadAttestation)?;
        if !seen.insert(op.to_owned()) || at < r.issued_at || at >= r.expires_at || at > ctx.now { return Err(Reason::BadAttestation); }
        let bytes = witness_receipt_bytes(&r,op,at)?; let sig = text(&row["sig"],128)?;
        if !keys.iter().any(|(key,before,after)| *before <= at && at < *after && verify_key_signature(key,sig,&bytes).is_ok()) { return Err(Reason::BadAttestation); }
        upper = upper.max(at);
    }
    if seen.len() < q as usize { return Err(Reason::BadAttestation); }
    Ok(IndependentWitnessObservation { request_id: digest(&bytes), record_digest:r.record_digest,
        policy_id:r.policy_id,epoch:r.epoch,operators:seen.into_iter().collect(),timestamp_upper_bound:upper })
}

/// Canonical membership transcript; semantic authorization is checked by the verifier.
pub fn independent_witness_policy_bytes(policy: &Value) -> Result<Vec<u8>, Reason> {
    fields(policy, &["id","epoch","threshold","maxFaulty","operators"])?;
    let id = text(&policy["id"],64)?;
    if !hash(id) { return Err(Reason::BadAttestation); }
    let mut out = vec!["sociacl-independent-witness-policy-v1".to_owned(), id.to_owned(),
        number(&policy["epoch"])?.to_string(), number(&policy["threshold"])?.to_string(), number(&policy["maxFaulty"])?.to_string()];
    let mut ops = Vec::new();
    for op in array(&policy["operators"],16)? {
        fields(op, &["id","keys"])?;
        let name = text(&op["id"],64)?;
        if !operator(name) { return Err(Reason::BadAttestation); }
        let mut keys = Vec::new();
        for key in array(&op["keys"],4)? {
            fields(key, &["key","notBefore","notAfter"])?;
            let principal = parse_principal_id(text(&key["key"],87)?)?;
            keys.push((principal.to_string(),number(&key["notBefore"])?,number(&key["notAfter"])?));
        }
        keys.sort_by(|a,b| a.0.cmp(&b.0));
        ops.push((name.to_owned(),keys));
    }
    ops.sort_by(|a,b| a.0.cmp(&b.0)); out.push(ops.len().to_string());
    for (name,keys) in ops {
        out.push(name); out.push(keys.len().to_string());
        for (key,before,after) in keys { out.extend([key,before.to_string(),after.to_string()]); }
    }
    length_prefixed(&out.iter().map(String::as_str).collect::<Vec<_>>())
}
pub fn independent_witness_transition_digest(previous: &Value, next: &Value) -> Result<String, Reason> {
    Ok(digest(&length_prefixed(&["sociacl-independent-witness-transition-v1",
        &digest(&independent_witness_policy_bytes(previous)?), &digest(&independent_witness_policy_bytes(next)?)])?))
}
/// Independently trusted previous policy, exact next epoch, account intent and
/// both rotation quorums. Returns a candidate for caller-owned durable CAS only.
pub fn advance_independent_witness_policy(previous: &Value, next: &Value, principal: &PrincipalId,
    old_request: &Value, old_receipts: &Value, new_request: &Value, new_receipts: &Value,
    rotations: &[Value], ctx: &ResolutionContext<'_>) -> Result<Value, Reason> {
    let digest = independent_witness_transition_digest(previous,next)?;
    let old = parse_witness_request(old_request)?; let fresh = parse_witness_request(new_request)?;
    if previous["id"] != next["id"] || number(&next["epoch"])? != number(&previous["epoch"])? + 1 ||
        old.principal != *principal || fresh.principal != *principal || old.operation != "rotate" || fresh.operation != "rotate" {
        return Err(Reason::BadAttestation);
    }
    verify_independent_witnesses(old_request,old_receipts,previous,&digest,rotations,ctx)?;
    verify_independent_witnesses(new_request,new_receipts,next,&digest,rotations,ctx)?;
    Ok(next.clone())
}
