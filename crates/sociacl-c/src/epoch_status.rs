//! Bounded transport to the Rust epoch-status verifier. A verified status is
//! evidence, never a Check grant. Expected state belongs to the trusted caller.
use serde::Deserialize;
use sociacl_encdisc::{epoch_status_bytes, status_is_fresh, verify_sea, EpochStatusProof, GrantStated, LightZookie};

const MAX_DOCUMENT: usize = 16_384;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Zookie {
    object: String,
    object_version: u64,
    snapshot_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proof {
    object: String,
    epoch: u64,
    revision_id: String,
    accessor: String,
    grant_revision: u64,
    stated: u8,
    signed_at: u64,
    max_age_ms: u64,
    signature: String,
    zookie: Zookie,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    owner_pub: String,
    object: String,
    epoch: u64,
    revision_id: String,
    accessor: String,
    grant_revision: u64,
    stated: u8,
    zookie: Zookie,
}

fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn object_shape(document: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(document) else { return false; };
    value.is_object() && value.get("zookie").is_some_and(serde_json::Value::is_object)
}

fn verify(proof: &[u8], expected: &[u8], now: u64, skew: u64, max_age: u64) -> bool {
    if [now, skew, max_age].iter().any(|n| *n > MAX_SAFE) {
        return false;
    }
    // Derived Serde structs accept positional arrays. Check the object shape,
    // then deserialize the ORIGINAL bytes so duplicate fields still fail.
    if !object_shape(proof) || !object_shape(expected) {
        return false;
    }
    let (Ok(proof), Ok(expected)) = (serde_json::from_slice::<Proof>(proof), serde_json::from_slice::<Expected>(expected)) else {
        return false;
    };
    if !text(&proof.object) || !text(&proof.accessor) || !digest(&proof.revision_id)
        || !digest(&proof.zookie.snapshot_hash) || proof.zookie.object != proof.object
        || proof.stated > 1 || proof.signature.is_empty() || proof.signature.len() > 4096
        || !text(&expected.owner_pub)
        || [proof.epoch, proof.grant_revision, proof.signed_at, proof.max_age_ms, proof.zookie.object_version].iter().any(|n| *n > MAX_SAFE)
        || proof.object != expected.object || proof.accessor != expected.accessor
        || proof.epoch != expected.epoch || proof.revision_id != expected.revision_id
        || proof.grant_revision != expected.grant_revision || proof.stated != expected.stated
        || proof.zookie != expected.zookie
    {
        return false;
    }
    let status = EpochStatusProof {
        object: proof.object, epoch: proof.epoch, revision_id: proof.revision_id,
        accessor: proof.accessor, grant_revision: proof.grant_revision,
        stated: if proof.stated == 0 { GrantStated::Cancelled } else { GrantStated::Live },
        signed_at: proof.signed_at, max_age_ms: proof.max_age_ms, signature: proof.signature,
        zookie: LightZookie { object: proof.zookie.object, object_version: proof.zookie.object_version, snapshot_hash: proof.zookie.snapshot_hash },
    };
    let Ok(bytes) = epoch_status_bytes(&status.body()) else { return false; };
    verify_sea(&expected.owner_pub, &bytes, &status.signature).is_ok()
        && status_is_fresh(&status, now, skew, max_age)
}

/// Verify signature, freshness and exact binding to independently trusted state.
/// Returns 1 for matching evidence, 0 for any refusal. Neither value grants access.
///
/// # Safety
/// Non-null pointers must reference readable buffers of their supplied lengths
/// for this call. Buffers need not have trailing NUL bytes and are not retained.
#[no_mangle]
pub unsafe extern "C" fn sociacl_verify_epoch_status(
    proof: *const u8, proof_len: usize, expected: *const u8, expected_len: usize,
    now_ms: u64, skew_ms: u64, policy_max_age_ms: u64,
) -> std::os::raw::c_int {
    if proof.is_null() || expected.is_null() || proof_len == 0 || expected_len == 0
        || proof_len > MAX_DOCUMENT || expected_len > MAX_DOCUMENT {
        return 0;
    }
    let proof = unsafe { std::slice::from_raw_parts(proof, proof_len) };
    let expected = unsafe { std::slice::from_raw_parts(expected, expected_len) };
    i32::from(verify(proof, expected, now_ms, skew_ms, policy_max_age_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sociacl_encdisc::GenesisAccount;

    fn fixture(stated: GrantStated) -> (Value, Value) {
        let owner = GenesisAccount::generate().unwrap().into_secret();
        let mut proof = EpochStatusProof {
            object: "media-object".into(), epoch: 3, revision_id: "a".repeat(64),
            accessor: "reader".into(), grant_revision: 7, stated,
            signed_at: 10_000, max_age_ms: 2000, signature: String::new(),
            zookie: LightZookie { object: "media-object".into(), object_version: 4, snapshot_hash: "b".repeat(64) },
        };
        proof.signature = owner.sign_epoch_status(&proof.body()).unwrap();
        let row = json!({"object":proof.object,"epoch":proof.epoch,"revisionId":proof.revision_id,
            "accessor":proof.accessor,"grantRevision":proof.grant_revision,"stated":proof.stated.as_u64(),
            "signedAt":proof.signed_at,"maxAgeMs":proof.max_age_ms,"signature":proof.signature,
            "zookie":{"object":proof.zookie.object,"objectVersion":proof.zookie.object_version,"snapshotHash":proof.zookie.snapshot_hash}});
        let mut expected = row.clone();
        for field in ["signedAt", "maxAgeMs", "signature"] { expected.as_object_mut().unwrap().remove(field); }
        expected["ownerPub"] = json!(owner.sea_pub());
        (row, expected)
    }

    fn call(proof: &Value, expected: &Value, now: u64, skew: u64, max_age: u64) -> i32 {
        let proof = serde_json::to_vec(proof).unwrap();
        let expected = serde_json::to_vec(expected).unwrap();
        unsafe { sociacl_verify_epoch_status(proof.as_ptr(), proof.len(), expected.as_ptr(), expected.len(), now, skew, max_age) }
    }

    #[test]
    fn rust_signed_live_and_cancelled_evidence_verify_but_do_not_grant() {
        for stated in [GrantStated::Live, GrantStated::Cancelled] {
            let (proof, expected) = fixture(stated);
            assert_eq!(call(&proof, &expected, 10_000, 0, 1000), 1);
            assert_eq!(call(&proof, &expected, 11_000, 0, 1000), 1);
            assert_eq!(call(&proof, &expected, 11_001, 0, 1000), 0);
            assert_eq!(call(&proof, &expected, 12_001, 0, 5000), 0);
            assert_eq!(call(&proof, &expected, 9999, 0, 1000), 0);
            assert_eq!(call(&proof, &expected, 9999, 1, 1000), 1);
        }
    }

    #[test]
    fn every_expected_binding_and_signature_must_match() {
        let (proof, expected) = fixture(GrantStated::Live);
        for (field, value) in [("object", json!("another-object")), ("accessor", json!("other-reader")),
            ("epoch", json!(4)), ("revisionId", json!("c".repeat(64))), ("grantRevision", json!(8)),
            ("stated", json!(0)), ("ownerPub", json!(GenesisAccount::generate().unwrap().into_secret().sea_pub()))] {
            let mut changed = expected.clone(); changed[field] = value;
            assert_eq!(call(&proof, &changed, 10_000, 0, 1000), 0, "{field}");
        }
        for (field, value) in [("object", json!("another-object")), ("objectVersion", json!(5)), ("snapshotHash", json!("c".repeat(64)))] {
            let mut changed = expected.clone(); changed["zookie"][field] = value;
            assert_eq!(call(&proof, &changed, 10_000, 0, 1000), 0, "{field}");
        }
        let mut changed = proof.clone(); changed["signedAt"] = json!(10_001);
        assert_eq!(call(&changed, &expected, 10_001, 0, 1000), 0);
        changed["signature"] = json!("bad signature");
        assert_eq!(call(&changed, &expected, 10_001, 0, 1000), 0);
    }

    #[test]
    fn malformed_and_ambiguous_documents_are_refused() {
        let (proof, expected) = fixture(GrantStated::Live);
        for (field, value) in [("extra", json!(true)), ("epoch", json!(-1)), ("epoch", json!(1.5)),
            ("epoch", json!(MAX_SAFE + 1)), ("stated", json!(2)), ("signature", json!("x".repeat(4097))),
            ("object", json!("")), ("accessor", json!("line\nbreak")), ("revisionId", json!("a")),
            ("maxAgeMs", json!("2000"))] {
            let mut changed = proof.clone(); changed[field] = value;
            assert_eq!(call(&changed, &expected, 10_000, 0, 1000), 0, "{field}");
        }
        let mut changed = expected.clone(); changed["extra"] = json!(true);
        assert_eq!(call(&proof, &changed, 10_000, 0, 1000), 0);
        for field in ["object", "epoch", "signature", "zookie"] {
            let mut changed = proof.clone(); changed.as_object_mut().unwrap().remove(field);
            assert_eq!(call(&changed, &expected, 10_000, 0, 1000), 0);
        }
        assert_eq!(call(&proof, &expected, MAX_SAFE + 1, 0, 1000), 0);
        assert_eq!(call(&proof, &expected, 10_000, MAX_SAFE + 1, 1000), 0);
        assert_eq!(call(&proof, &expected, 10_000, 0, MAX_SAFE + 1), 0);
        let expected = serde_json::to_vec(&expected).unwrap();
        for raw in [b"{".to_vec(), vec![0xff], format!("{{\"epoch\":3,{}", &proof.to_string()[1..]).into_bytes()] {
            assert!(!verify(&raw, &expected, 10_000, 0, 1000));
        }
    }

    #[test]
    fn positional_struct_arrays_are_not_the_json_object_contract() {
        let (proof, expected) = fixture(GrantStated::Live);
        let positional = |row: &Value, fields: &[&str]| Value::Array(fields.iter().map(|field| row[*field].clone()).collect());
        let proof_array = positional(&proof, &["object", "epoch", "revisionId", "accessor", "grantRevision", "stated", "signedAt", "maxAgeMs", "signature", "zookie"]);
        let expected_array = positional(&expected, &["ownerPub", "object", "epoch", "revisionId", "accessor", "grantRevision", "stated", "zookie"]);
        assert_eq!(call(&proof_array, &expected, 10_000, 0, 1000), 0);
        assert_eq!(call(&proof, &expected_array, 10_000, 0, 1000), 0);
        let mut proof_array = proof.clone();
        let mut expected_array = expected.clone();
        let zookie = positional(&proof["zookie"], &["object", "objectVersion", "snapshotHash"]);
        proof_array["zookie"] = zookie.clone();
        expected_array["zookie"] = zookie;
        assert_eq!(call(&proof_array, &expected, 10_000, 0, 1000), 0);
        assert_eq!(call(&proof, &expected_array, 10_000, 0, 1000), 0);
        assert_eq!(call(&proof_array, &expected_array, 10_000, 0, 1000), 0);
    }

    #[test]
    fn ffi_refuses_null_empty_and_oversized_buffers_before_reading() {
        let byte = b'{';
        for (pointer, length) in [(std::ptr::null(), 1), (&byte as *const u8, 0), (&byte, MAX_DOCUMENT + 1)] {
            assert_eq!(unsafe { sociacl_verify_epoch_status(pointer, length, &byte, 1, 0, 0, 0) }, 0);
            assert_eq!(unsafe { sociacl_verify_epoch_status(&byte, 1, pointer, length, 0, 0, 0) }, 0);
        }
    }
}
