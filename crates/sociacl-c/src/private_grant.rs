//! Match the existing confidential grant transcript against trusted owner state.
use serde::Deserialize;
use sociacl_encdisc::{decode_grant_bytes, grant_payload_bytes, verify_sea, GrantStated, SignedGrantPayload};

const MAX_DOCUMENT: usize = 65_536;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proof {
    grant_bytes: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    owner_pub: String,
    object: String,
    accessor: String,
    from: u64,
    until: u64,
    stated: u8,
    epoch: u64,
    owner: String,
    grant_revision: u64,
    item_ciphertext_digest: String,
}

fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn object(data: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(data).is_ok_and(|value| value.is_object())
}

fn verify(proof: &[u8], expected: &[u8]) -> bool {
    // Check object shapes, but deserialize original bytes to retain duplicates.
    if !object(proof) || !object(expected) { return false; }
    let (Ok(proof), Ok(expected)) = (serde_json::from_slice::<Proof>(proof), serde_json::from_slice::<Expected>(expected)) else {
        return false;
    };
    if [&expected.owner_pub, &expected.object, &expected.accessor, &expected.owner].iter().any(|v| !text(v))
        || [expected.from, expected.until, expected.epoch, expected.grant_revision].iter().any(|n| *n > MAX_SAFE)
        || expected.stated > 1 || !hex(&proof.signature, 128)
        || (!expected.item_ciphertext_digest.is_empty() && !hex(&expected.item_ciphertext_digest, 64)) {
        return false;
    }
    let expected_payload = SignedGrantPayload {
        object: expected.object, accessor: expected.accessor, from: expected.from, until: expected.until,
        stated: if expected.stated == 1 { GrantStated::Live } else { GrantStated::Cancelled },
        epoch: expected.epoch, owner: expected.owner, grant_revision: expected.grant_revision,
        item_ciphertext_digest: expected.item_ciphertext_digest,
    };
    let Ok(payload) = decode_grant_bytes(&proof.grant_bytes) else { return false; };
    if payload != expected_payload { return false; }
    // The Rust reference owns the transcript and P-256 verification.
    let Ok(message) = grant_payload_bytes(&payload.body()) else { return false; };
    verify_sea(&expected.owner_pub, &message, &proof.signature).is_ok()
}

/// Verify one existing private-grant signature and exact expected payload.
/// A cancellation also matches. Current Check, enrollment, complete history,
/// settlement, presenter binding and independent rollback protection are separate.
///
/// # Safety
/// Non-null pointers must be readable for their supplied lengths. No pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn sociacl_verify_private_grant(
    proof: *const u8, proof_len: usize, expected: *const u8, expected_len: usize,
) -> std::os::raw::c_int {
    if proof.is_null() || expected.is_null() || proof_len == 0 || expected_len == 0
        || proof_len > MAX_DOCUMENT || expected_len > MAX_DOCUMENT { return 0; }
    let proof = unsafe { std::slice::from_raw_parts(proof, proof_len) };
    let expected = unsafe { std::slice::from_raw_parts(expected, expected_len) };
    i32::from(verify(proof, expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sociacl_encdisc::{encode_grant_bytes, GenesisAccount};

    fn fixture(stated: GrantStated, item: bool) -> (Value, Value) {
        let owner = GenesisAccount::generate().unwrap().into_secret();
        let payload = SignedGrantPayload {
            object: "media-object".into(), accessor: "reader".into(), from: 100, until: 200,
            stated, epoch: 3, owner: owner.account().into(), grant_revision: 7,
            item_ciphertext_digest: if item { "a".repeat(64) } else { String::new() },
        };
        let proof = json!({"grantBytes":encode_grant_bytes(&payload).unwrap(), "signature":owner.sign_grant(&payload).unwrap()});
        let expected = json!({"ownerPub":owner.sea_pub(), "object":payload.object,"accessor":payload.accessor,
            "from":payload.from,"until":payload.until,"stated":payload.stated.as_u64(),"epoch":payload.epoch,
            "owner":payload.owner,"grantRevision":payload.grant_revision,"itemCiphertextDigest":payload.item_ciphertext_digest});
        (proof, expected)
    }

    fn call(proof: &Value, expected: &Value) -> i32 {
        let (proof, expected) = (serde_json::to_vec(proof).unwrap(), serde_json::to_vec(expected).unwrap());
        unsafe { sociacl_verify_private_grant(proof.as_ptr(), proof.len(), expected.as_ptr(), expected.len()) }
    }

    #[test]
    fn live_cancelled_and_non_item_signatures_match_without_minting_access() {
        for stated in [GrantStated::Live, GrantStated::Cancelled] {
            for item in [false, true] {
                let (proof, expected) = fixture(stated, item);
                assert_eq!(call(&proof, &expected), 1);
            }
        }
    }

    #[test]
    fn every_expected_field_is_bound_and_signatures_are_verified() {
        let (proof, expected) = fixture(GrantStated::Live, true);
        for (key, value) in [("ownerPub",json!(GenesisAccount::generate().unwrap().into_secret().sea_pub())),
            ("object",json!("other")),("accessor",json!("other")),("from",json!(101)),("until",json!(201)),
            ("stated",json!(0)),("epoch",json!(4)),("owner",json!("other")),("grantRevision",json!(8)),
            ("itemCiphertextDigest",json!("b".repeat(64)))] {
            let mut changed = expected.clone(); changed[key] = value;
            assert_eq!(call(&proof, &changed), 0, "{key}");
        }
        for (key, value) in [("grantBytes",json!("00")),("signature",json!("0".repeat(128))),
                              ("signature",json!("F".repeat(128))), ("signature",json!("bad"))] {
            let mut changed = proof.clone(); changed[key] = value;
            assert_eq!(call(&changed, &expected), 0);
        }
    }

    #[test]
    fn strict_json_shapes_fields_and_safe_bounds() {
        let (proof, expected) = fixture(GrantStated::Live, true);
        for (key, value) in [("object",json!("")),("owner",json!("a".repeat(1025))),
            ("accessor",json!("a\nb")),("ownerPub",json!("bad-point")),("stated",json!(2)),
            ("itemCiphertextDigest",json!("G".repeat(64))), ("itemCiphertextDigest",json!("bad")),
            ("from",json!(MAX_SAFE+1)),("until",json!(MAX_SAFE+1)),("epoch",json!(MAX_SAFE+1)),
            ("grantRevision",json!(MAX_SAFE+1)),("extra",json!(true))] {
            let mut changed=expected.clone(); changed[key]=value;
            assert_eq!(call(&proof,&changed),0,"{key}");
        }
        for value in [json!([]), json!(null), json!({}), json!({"grantBytes":"00","signature":"00","extra":1})] {
            assert_eq!(call(&value,&expected),0);
            assert_eq!(call(&proof,&value),0);
        }
        let p=serde_json::to_vec(&proof).unwrap(); let e=serde_json::to_vec(&expected).unwrap();
        for invalid in [b"{".to_vec(), b"\xff".to_vec(), b"{\"grantBytes\":\"00\",\"grantBytes\":\"00\",\"signature\":\"00\"}".to_vec()] {
            assert!(!verify(&invalid,&e));
        }
        let duplicate = String::from_utf8(e.clone()).unwrap().replacen('{', "{\"epoch\":3,", 1);
        assert!(!verify(&p,duplicate.as_bytes()));
        unsafe {
            assert_eq!(sociacl_verify_private_grant(std::ptr::null(),1,e.as_ptr(),e.len()),0);
            assert_eq!(sociacl_verify_private_grant(p.as_ptr(),p.len(),std::ptr::null(),1),0);
            for len in [0,MAX_DOCUMENT+1] {
                assert_eq!(sociacl_verify_private_grant(p.as_ptr(),len,e.as_ptr(),e.len()),0);
                assert_eq!(sociacl_verify_private_grant(p.as_ptr(),p.len(),e.as_ptr(),len),0);
            }
        }
    }
}
