//! Authenticate existing group settlement policy against independently trusted scope.
use serde::Deserialize;
use sociacl_encdisc::{GroupEpochConfig, GroupPredicate};
const MAX_DOCUMENT: usize = 16_384;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proof {
    owner: String, set_id: String, predicate: String,
    settle_window_ms: u64, config_revision: u64, signature: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    owner: String, owner_pub: String, set_id: String, predicate: String,
    settle_window_ms: u64, config_revision: u64,
}
fn text(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
}
fn verify(proof: &[u8], expected: &[u8]) -> bool {
    if ![proof, expected].iter().all(|raw| serde_json::from_slice::<serde_json::Value>(raw).is_ok_and(|v| v.is_object())) { return false; }
    let (Ok(p), Ok(e)) = (serde_json::from_slice::<Proof>(proof), serde_json::from_slice::<Expected>(expected)) else { return false; };
    if p.owner != e.owner || p.set_id != e.set_id || p.predicate != e.predicate
        || p.settle_window_ms != e.settle_window_ms || p.config_revision != e.config_revision
        || [p.settle_window_ms, p.config_revision].iter().any(|n| *n > MAX_SAFE)
        || [&p.owner, &p.set_id, &e.owner_pub].iter().any(|v| !text(v))
        || p.signature.len() != 128 || !p.signature.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return false; }
    let predicate = match p.predicate.as_str() {
        "same-group" => GroupPredicate::SameGroup,
        "named-circle" => GroupPredicate::NamedCircle,
        _ => return false,
    };
    let config = GroupEpochConfig { owner: p.owner, set_id: p.set_id, predicate,
        settle_window_ms: p.settle_window_ms, config_revision: p.config_revision, signature: p.signature };
    config.verify(&e.owner_pub, Some(&e.owner)).is_ok()
}
/// Verify exact signed policy fields and the independently resolved current set-owner key.
/// Does not select the latest policy, enroll an owner, grant access or settle an epoch.
///
/// # Safety
/// Non-null pointers must be readable for their supplied lengths. No pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn sociacl_verify_group_epoch_config(
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
    use sociacl_encdisc::GenesisAccount;
    fn fixture(predicate: &str) -> (Value, Value) {
        let key = GenesisAccount::generate().unwrap().into_secret();
        let proof = json!({"owner":key.account(),"setId":"crew","predicate":predicate,"settleWindowMs":3_600_000,
            "configRevision":2,"signature":key.sign_group_epoch_config("crew",predicate,3_600_000,2).unwrap()});
        let mut expected = proof.clone();expected.as_object_mut().unwrap().remove("signature");expected["ownerPub"] = json!(key.sea_pub());
        (proof, expected)
    }
    fn call(p: &Value, e: &Value) -> i32 {
        let (p,e) = (serde_json::to_vec(p).unwrap(),serde_json::to_vec(e).unwrap());
        unsafe { sociacl_verify_group_epoch_config(p.as_ptr(),p.len(),e.as_ptr(),e.len()) }
    }
    #[test]
    fn native_config_matches_both_predicates_and_every_expected_field() {
        for predicate in ["same-group", "named-circle"] {
            let (p,e) = fixture(predicate);assert_eq!(call(&p,&e),1);
            for (field,value) in [("owner",json!("other")),("ownerPub",json!("wrong")),("setId",json!("other")),
                ("predicate",json!("other")),("settleWindowMs",json!(7_200_000)),("configRevision",json!(3))] {
                let mut changed=e.clone();changed[field]=value;assert_eq!(call(&p,&changed),0);
            }
            let mut changed=p.clone();changed["signature"]=json!("0".repeat(128));assert_eq!(call(&changed,&e),0);
        }
    }
    #[test]
    fn shapes_numbers_and_missing_trusted_fields_fail_closed() {
        let (p,e)=fixture("same-group");
        for bad in [json!(null),json!([]),json!(1),json!({}),json!("bad")] {
            assert_eq!(call(&bad,&e),0);assert_eq!(call(&p,&bad),0);
        }
        for (field,value) in [("owner",json!("")),("setId",json!("x\n")),("setId",json!("x".repeat(1025))),
            ("predicate",json!("direct")),("settleWindowMs",json!(1)),("configRevision",json!(MAX_SAFE+1))] {
            let mut a=p.clone();let mut b=e.clone();a[field]=value.clone();b[field]=value;assert_eq!(call(&a,&b),0);
        }
        let mut bad=p.clone();bad["signature"]=json!("bad");assert_eq!(call(&bad,&e),0);
        let mut bad=p.clone();bad["extra"]=json!(1);assert_eq!(call(&bad,&e),0);
        let raw=serde_json::to_vec(&e).unwrap();
        assert!(!verify(b"{",&raw));assert!(!verify(b"{\"owner\":\"a\",\"owner\":\"b\"}",&raw));
        let p=serde_json::to_vec(&p).unwrap();
        unsafe {
            assert_eq!(sociacl_verify_group_epoch_config(std::ptr::null(),1,raw.as_ptr(),raw.len()),0);
            assert_eq!(sociacl_verify_group_epoch_config(p.as_ptr(),p.len(),std::ptr::null(),1),0);
            for length in [0,MAX_DOCUMENT+1,usize::MAX] {
                assert_eq!(sociacl_verify_group_epoch_config(p.as_ptr(),length,raw.as_ptr(),raw.len()),0);
                assert_eq!(sociacl_verify_group_epoch_config(p.as_ptr(),p.len(),raw.as_ptr(),length),0);
            }
        }
    }
}
