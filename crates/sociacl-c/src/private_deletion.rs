//! Explicit owner deletion intent. A valid signature does not delete or grant.
use serde::Deserialize;
use sociacl_encdisc::verify_sea;
const MAX_DOCUMENT: usize = 8192;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proof { deletion_bytes: String, signature: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    tenant: String, object: String, owner: String, owner_pub: String,
    object_version: u64, fence: String, issued_at: u64, expires_at: u64,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && value.bytes().all(|b| (33..=126).contains(&b))
}
fn uuid(value: &str) -> bool {
    value.len() == 36 && value != "00000000-0000-0000-0000-000000000000" &&
        value.bytes().enumerate().all(|(i,b)| if [8,13,18,23].contains(&i) { b == b'-' }
        else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) })
}
fn message(e: &Expected) -> Vec<u8> {
    let fields = serde_json::json!([e.tenant,e.object,e.owner,e.object_version,e.fence,e.issued_at,e.expires_at]);
    [b"SOCIACL_PRIVATE_MEDIA_DELETE_V1\n".as_slice(),fields.to_string().as_bytes()].concat()
}
fn verify(proof: &[u8], expected: &[u8], now: u64) -> bool {
    // Struct parsing rejects duplicate/unknown fields; explicitly refuse arrays.
    if ![proof,expected].iter().all(|raw| serde_json::from_slice::<serde_json::Value>(raw).is_ok_and(|v| v.is_object())) { return false; }
    let (Ok(p),Ok(e))=(serde_json::from_slice::<Proof>(proof),serde_json::from_slice::<Expected>(expected)) else { return false; };
    if !uuid(&e.tenant) || !e.object.starts_with("media_") || [&e.object,&e.owner,&e.owner_pub].iter().any(|s| !text(s))
        || !hex(&e.fence,64) || !hex(&p.signature,128) || [e.object_version,e.issued_at,e.expires_at,now].iter().any(|n| *n>MAX_SAFE)
        || e.expires_at<=e.issued_at || e.expires_at-e.issued_at>60000 || now<e.issued_at || now>=e.expires_at { return false; }
    let bytes=message(&e);
    let encoded: String=bytes.iter().map(|b| format!("{b:02x}")).collect();
    p.deletion_bytes==encoded && verify_sea(&e.owner_pub,&bytes,&p.signature).is_ok()
}
/// Match a deletion command to independently resolved current owner state.
/// Time is in milliseconds; validity is half-open and at most sixty seconds.
/// The caller must enforce the current version/fence and durable non-resurrection.
/// # Safety
/// Non-null pointers must be readable for their lengths. Nothing is retained.
#[no_mangle]
pub unsafe extern "C" fn sociacl_verify_private_deletion(proof:*const u8,proof_len:usize,expected:*const u8,expected_len:usize,now_ms:u64)->std::os::raw::c_int {
    if proof.is_null() || expected.is_null() || proof_len==0 || expected_len==0 || proof_len>MAX_DOCUMENT || expected_len>MAX_DOCUMENT { return 0; }
    let p=unsafe {std::slice::from_raw_parts(proof,proof_len)};
    let e=unsafe {std::slice::from_raw_parts(expected,expected_len)};
    i32::from(verify(p,e,now_ms))
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json,Value};
    use sociacl_encdisc::{GenesisAccount,sign_sea};
    fn fixture()->(Value,Value) {
        let owner=GenesisAccount::generate().unwrap().into_secret();
        let e=json!({"tenant":"11111111-1111-4111-8111-111111111111","object":"media_test","owner":owner.sea_pub(),"ownerPub":owner.sea_pub(),"objectVersion":3,"fence":"a".repeat(64),"issuedAt":1000,"expiresAt":61000});
        let bytes=message(&serde_json::from_value(e.clone()).unwrap());
        let p=json!({"deletionBytes":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"signature":sign_sea(owner.local_priv(),&bytes).unwrap()});
        (p,e)
    }
    fn call(p:&Value,e:&Value,now:u64)->i32 {
        let p=p.to_string();let e=e.to_string();
        unsafe{sociacl_verify_private_deletion(p.as_ptr(),p.len(),e.as_ptr(),e.len(),now)}
    }
    #[test]
    fn exact_scope_signature_and_half_open_window() {
        let(p,e)=fixture();assert_eq!(call(&p,&e,1000),1);assert_eq!(call(&p,&e,61000),0);assert_eq!(call(&p,&e,999),0);
        for (field,value) in [("tenant",json!("22222222-2222-4222-8222-222222222222")),("object",json!("media_other")),("owner",json!("other")),("objectVersion",json!(4)),("fence",json!("b".repeat(64))),("issuedAt",json!(1001)),("expiresAt",json!(60000)),("ownerPub",json!("invalid"))] {
            let mut changed=e.clone();changed[field]=value;assert_eq!(call(&p,&changed,2000),0,"{field}");
        }
        for field in ["deletionBytes","signature"] {let mut changed=p.clone();changed[field]=json!("0".repeat(128));assert_eq!(call(&changed,&e,2000),0);}
    }
    #[test]
    fn malformed_inputs_and_ffi_bounds() {
        let(p,e)=fixture();
        for (field,value) in [("tenant",json!("bad")),("tenant",json!("00000000-0000-0000-0000-000000000000")),("object",json!("room_other")),("owner",json!("")),("owner",json!("a\nb")),("fence",json!("A".repeat(64))),("objectVersion",json!(MAX_SAFE+1)),("issuedAt",json!(0)),("expiresAt",json!(1000)),("extra",json!(1))] {
            let mut changed=e.clone();changed[field]=value;assert_eq!(call(&p,&changed,2000),0,"{field}");
        }
        assert_eq!(call(&p,&e,MAX_SAFE+1),0);
        for value in [json!([]),json!(null),json!({})] {assert_eq!(call(&value,&e,2000),0);assert_eq!(call(&p,&value,2000),0);}
        let pb=p.to_string();let eb=e.to_string();
        assert!(!verify(b"{",eb.as_bytes(),2000));
        let duplicate=eb.replacen('{',"{\"objectVersion\":3,",1);assert!(!verify(pb.as_bytes(),duplicate.as_bytes(),2000));
        unsafe {
            assert_eq!(sociacl_verify_private_deletion(std::ptr::null(),1,eb.as_ptr(),eb.len(),2000),0);
            assert_eq!(sociacl_verify_private_deletion(pb.as_ptr(),pb.len(),std::ptr::null(),1,2000),0);
            for n in [0,MAX_DOCUMENT+1] {assert_eq!(sociacl_verify_private_deletion(pb.as_ptr(),n,eb.as_ptr(),eb.len(),2000),0);assert_eq!(sociacl_verify_private_deletion(pb.as_ptr(),pb.len(),eb.as_ptr(),n,2000),0);}
        }
    }
}
