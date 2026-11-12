use serde_json::{json, Value};
use sociacl_ids::*;
use std::collections::{BTreeMap, BTreeSet};
fn scalar(n:u8)->[u8;32]{let mut key=[0;32];key[31]=n;key}
fn public(n:u8)->PrincipalId {
    let key=p256::ecdsa::SigningKey::from_slice(&scalar(n)).unwrap();
    principal_from_sec1(key.verifying_key().to_sec1_point(false).as_bytes()).unwrap()
}
fn sign_request(mut r:Value)->Value {
    let parsed=parse_witness_request(&r).unwrap();
    r["sig"]=json!(sign_with_keyring(&scalar(1),&witness_request_bytes(&parsed).unwrap(),&parsed.principal).unwrap());r
}
fn receipt(r:&Value,n:u8,at:u64)->Value {
    let op=format!("operator-{n}");let parsed=parse_witness_request(r).unwrap();
    json!({"operator":op,"observedAt":at,"sig":sign_with_keyring(&scalar(n),&witness_receipt_bytes(&parsed,&op,at).unwrap(),&public(n)).unwrap()})
}
#[test]
fn shared_transcripts_quorum_refusals_and_cross_language_signatures(){
    let v:Value=serde_json::from_str(include_str!("../../../vectors/independent-witness/v1.json")).unwrap();
    let r=sign_request(v["request"].clone());
    let policy=json!({"id":r["policyId"],"epoch":1,"threshold":v["threshold"],"maxFaulty":v["maxFaulty"],
        "operators":v["operators"].as_array().unwrap().iter().map(|n|{let n=n.as_u64().unwrap() as u8;
            json!({"id":format!("operator-{n}"),"keys":[{"key":public(n),"notBefore":v["notBefore"],"notAfter":v["notAfter"]}]})}).collect::<Vec<_>>()});
    let rows=json!([receipt(&r,2,1700000010),receipt(&r,3,1700000010),receipt(&r,4,1700000010)]);
    let jwks=Jwks{keys:vec![]};let links=BTreeMap::new();let issuers=BTreeSet::new();
    let siwe=SiwePolicy{allowed_domains:vec![],allowed_uris:vec![],allowed_chain_ids:vec![],clock_skew_seconds:0};
    let history=|p:&PrincipalId,at,until|Ok(history_state(p,&[],at,until));
    let mut ctx=ResolutionContext{jwks:&jwks,links:&links,revocations:&[],now:v["now"].as_u64().unwrap(),policy:&siwe,
        pinned_iss:&issuers,history:&history,genesis_epub_bindings:&[]};
    let expected=r["recordDigest"].as_str().unwrap();
    let result=verify_independent_witnesses(&r,&rows,&policy,expected,&[],&ctx).unwrap();
    assert_eq!(result.operators,vec!["operator-2","operator-3","operator-4"]);
    let fields:Vec<&str>=v["requestFields"].as_array().unwrap().iter().map(|x|x.as_str().unwrap()).collect();
    assert_eq!(witness_request_bytes(&parse_witness_request(&r).unwrap()).unwrap(),length_prefixed(&fields).unwrap());
    for patch in v["rejectRequestPatches"].as_array().unwrap(){let mut bad=r.clone();for (k,value) in patch.as_object().unwrap(){bad[k]=value.clone();}
        assert!(verify_independent_witnesses(&bad,&rows,&policy,expected,&[],&ctx).is_err(),"{patch}");}
    for patch in v["rejectPolicyPatches"].as_array().unwrap(){let mut bad=policy.clone();for (k,value) in patch.as_object().unwrap(){bad[k]=value.clone();}
        assert!(verify_independent_witnesses(&r,&rows,&bad,expected,&[],&ctx).is_err(),"{patch}");}
    for bad in [json!([rows[0],rows[1]]),json!([rows[0],rows[0],rows[2]]),
        json!([rows[0],rows[1],receipt(&r,4,1700000021)])]{assert!(verify_independent_witnesses(&r,&bad,&policy,expected,&[],&ctx).is_err());}
    let mut alias=policy.clone();alias["operators"][3]["keys"]=policy["operators"][0]["keys"].clone();
    assert!(verify_independent_witnesses(&r,&rows,&alias,expected,&[],&ctx).is_err());
    let mut bad_name=policy.clone();bad_name["operators"][0]["id"]=json!("operator-2\n");
    assert!(verify_independent_witnesses(&r,&rows,&bad_name,expected,&[],&ctx).is_err());
    let mut expired=policy.clone();expired["operators"][0]["keys"][0]["notAfter"]=json!(1700000010);
    assert!(verify_independent_witnesses(&r,&rows,&expired,expected,&[],&ctx).is_err());
    let mut revoke=r.clone();revoke["operation"]=json!("revoke");let revoke=sign_request(revoke);
    let mut two=policy.clone();two["threshold"]=json!(2);two["operators"].as_array_mut().unwrap().pop();
    assert!(verify_independent_witnesses(&revoke,&json!([receipt(&revoke,2,1700000010),receipt(&revoke,3,1700000010)]),&two,expected,&[],&ctx).is_ok());
    if let Ok(path)=std::env::var("WITNESS_RUST_VECTOR"){
        std::fs::write(path,serde_json::to_vec(&json!({"request":r,"receipts":rows,"policy":policy,"result":result})).unwrap()).unwrap();
    }
    if let Ok(path)=std::env::var("WITNESS_TS_VECTOR"){
        let other:Value=serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let observed=verify_independent_witnesses(&other["request"],&other["receipts"],&policy,expected,&[],&ctx).unwrap();
        assert_eq!(serde_json::to_value(observed).unwrap(),other["result"]);
    }
    let missing=|_:&PrincipalId,_,_|Err(Reason::MissingHistory);ctx.history=&missing;
    assert_eq!(verify_independent_witnesses(&r,&rows,&policy,expected,&[],&ctx),Err(Reason::MissingHistory));
}
