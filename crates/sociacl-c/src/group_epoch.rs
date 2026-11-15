//! Strict bounded adapter for independent group epoch inputs. The service owns
//! authenticated histories, current cohort, trusted clocks and rollback state.
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::value::RawValue;
use sociacl_encdisc::{EpochChain, EpochManifest, EpochFinalization, GroupKeySnapshot, GroupKeyMember,
    GroupEpochConfig, GroupPredicate, group_key_snapshot_id};
const MAX_BYTES: usize=4*1024*1024;
const MAX_DOCUMENT: usize=65_536;
const MAX_SAFE:u64=9_007_199_254_740_991;
fn object<T:DeserializeOwned>(raw:&str)->Option<T>{
    if !serde_json::from_str::<serde_json::Value>(raw).ok()?.is_object(){return None;}
    serde_json::from_str(raw).ok()
}
fn digest(value:&str)->bool{value.len()==64&&value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn text(value:&str)->bool{!value.is_empty()&&value.len()<=1024&&!value.chars().any(char::is_control)}
fn predicate(value:&str)->Option<GroupPredicate>{match value{"same-group"=>Some(GroupPredicate::SameGroup),"named-circle"=>Some(GroupPredicate::NamedCircle),_=>None}}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Member{accessor:String,stated:u64,ham_state:u64,signing_pub:String,encryption_pub:String,identity_head:u64}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Snapshot{predicate:String,set_id:String,set_owner:String,owner_signing_pub:String,owner_encryption_pub:String,owner_identity_head:u64,members:Vec<Box<RawValue>>}
fn snapshot(raw:&str)->Option<GroupKeySnapshot>{
    let s:Snapshot=object(raw)?;if s.members.len()>64{return None;}
    let members=s.members.iter().map(|raw|{
        let m:Member=object(raw.get())?;
        Some(GroupKeyMember{accessor:m.accessor,stated:m.stated,ham_state:m.ham_state,signing_pub:m.signing_pub,encryption_pub:m.encryption_pub,identity_head:m.identity_head})
    }).collect::<Option<Vec<_>>>()?;
    let result=GroupKeySnapshot{predicate:predicate(&s.predicate)?,set_id:s.set_id,set_owner:s.set_owner,owner_signing_pub:s.owner_signing_pub,
        owner_encryption_pub:s.owner_encryption_pub,owner_identity_head:s.owner_identity_head,members};
    group_key_snapshot_id(&result).ok()?;Some(result)
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Manifest{object:String,previous_epoch:u64,epoch:u64,device_id:String,revision_id:String,key_commitment:String,
    settle_window_ms:u64,acl_snapshot:String,signature:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document{manifest:Box<RawValue>,snapshot:Box<RawValue>}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Expected{object:String,owner_pub:String,epoch:u64,revision_id:String}
fn document(raw:&str,expected:&str)->Option<(EpochManifest,GroupKeySnapshot,String)>{
    if raw.len()>MAX_DOCUMENT||expected.len()>MAX_DOCUMENT{return None;}
    let d:Document=object(raw)?;let e:Expected=object(expected)?;let m:Manifest=object(d.manifest.get())?;
    if m.object!=e.object||m.epoch!=e.epoch||m.revision_id!=e.revision_id||!text(&m.device_id)||!text(&e.owner_pub)
        ||[m.epoch,m.previous_epoch,m.settle_window_ms].iter().any(|n|*n>MAX_SAFE){return None;}
    let s=snapshot(d.snapshot.get())?;
    let m=EpochManifest{object:m.object,previous_epoch:m.previous_epoch,epoch:m.epoch,device_id:m.device_id,revision_id:m.revision_id,
        key_commitment:m.key_commitment,settle_window_ms:m.settle_window_ms,acl_snapshot:m.acl_snapshot,status_auth_pub:None,signature:m.signature};
    let mut chain=EpochChain::new(&m.object).ok()?;
    chain.insert_group_manifest(m.clone(),s.clone(),&e.owner_pub).ok()?;Some((m,s,e.owner_pub))
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Config{owner:String,set_id:String,predicate:String,settle_window_ms:u64,config_revision:u64,signature:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRow{document:Box<RawValue>,expected:Box<RawValue>}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct FinalizationRow{proof:Box<RawValue>,owner_pub:String,seen_at:u64}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Finalization{object:String,previous_epoch:u64,epoch:u64,revision_id:String,candidate_revision_ids:Vec<String>,previous_finalization_id:String,finalization_id:String,signature:String}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Input{object:String,current:Box<RawValue>,config:Box<RawValue>,manifests:Vec<Box<RawValue>>,finalizations:Vec<Box<RawValue>>,
    now_ms:u64,anchor_finalization_id:String,minimum_epoch:u64,expected_epoch:u64,expected_revision_id:String}
fn history(raw:&str,select:bool)->Option<()>{
    let i:Input=object(raw)?;
    if !text(&i.object)||!digest(&i.anchor_finalization_id)||!digest(&i.expected_revision_id)
        ||[i.now_ms,i.minimum_epoch,i.expected_epoch].iter().any(|n|*n>MAX_SAFE)
        ||i.manifests.is_empty()||i.manifests.len()>64||i.finalizations.is_empty()||i.finalizations.len()>64{return None;}
    let current=snapshot(i.current.get())?;if current.set_id!=i.object{return None;}
    let c:Config=object(i.config.get())?;
    if c.set_id!=current.set_id||c.owner!=current.set_owner||predicate(&c.predicate)?!=current.predicate
        ||c.config_revision>MAX_SAFE{return None;}
    let config=GroupEpochConfig{owner:c.owner,set_id:c.set_id,predicate:current.predicate,settle_window_ms:c.settle_window_ms,config_revision:c.config_revision,signature:c.signature};
    config.verify(&current.owner_signing_pub,Some(&current.set_owner)).ok()?;
    let mut chain=EpochChain::new(&i.object).ok()?;let mut revisions=std::collections::BTreeSet::new();
    for raw in i.manifests{
        let row:ManifestRow=object(raw.get())?;let (m,s,key)=document(row.document.get(),row.expected.get())?;
        if !revisions.insert(m.revision_id.clone()){return None;}
        chain.insert_group_manifest(m,s,&key).ok()?;
    }
    let mut ids=std::collections::BTreeSet::new();
    for raw in i.finalizations{
        let row:FinalizationRow=object(raw.get())?;let f:Finalization=object(row.proof.get())?;
        if !text(&row.owner_pub)||row.seen_at>i.now_ms||[f.epoch,f.previous_epoch].iter().any(|n|*n>MAX_SAFE)
            ||f.candidate_revision_ids.is_empty()||f.candidate_revision_ids.len()>64||!ids.insert(f.finalization_id.clone()){return None;}
        chain.insert_finalization(EpochFinalization{object:f.object,previous_epoch:f.previous_epoch,epoch:f.epoch,revision_id:f.revision_id,
            candidate_revision_ids:f.candidate_revision_ids,previous_finalization_id:f.previous_finalization_id,finalization_id:f.finalization_id,signature:f.signature},row.seen_at,&row.owner_pub).ok()?;
    }
    if select{
        let selected=chain.settled_group_key(&current,i.now_ms,&config,&i.anchor_finalization_id,i.minimum_epoch)?;
        if selected.epoch!=i.expected_epoch||selected.revision_id!=i.expected_revision_id{return None;}
    }
    Some(())
}
/// Authenticate one group manifest against independently trusted owner context.
/// # Safety
/// Both non-null buffers must be readable for their lengths; no pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn sociacl_verify_group_epoch_manifest(doc:*const u8,len:usize,expected:*const u8,expected_len:usize)->std::os::raw::c_int{
    if doc.is_null()||expected.is_null()||len==0||expected_len==0||len>MAX_DOCUMENT||expected_len>MAX_DOCUMENT{return 0;}
    let doc=unsafe{std::slice::from_raw_parts(doc,len)};let expected=unsafe{std::slice::from_raw_parts(expected,expected_len)};
    let (Ok(doc),Ok(expected))=(std::str::from_utf8(doc),std::str::from_utf8(expected))else{return 0;};
    i32::from(document(doc,expected).is_some())
}
unsafe fn call(input:*const u8,len:usize,select:bool)->std::os::raw::c_int{
    if input.is_null()||len==0||len>MAX_BYTES{return 0;}
    let raw=unsafe{std::slice::from_raw_parts(input,len)};
    let Ok(raw)=std::str::from_utf8(raw)else{return 0;};i32::from(history(raw,select).is_some())
}
/// Match the latest settled independent group key. Does not authorize media reads.
/// # Safety
/// The non-null input must be readable for its length; no pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn sociacl_match_settled_group_epoch(input:*const u8,len:usize)->std::os::raw::c_int{unsafe{call(input,len,true)}}
/// Authenticate group history before retaining a pending successor. Completeness,
/// enrollment, observation clocks and rollback protection remain service-owned.
/// # Safety
/// The non-null input must be readable for its length; no pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn sociacl_verify_group_epoch_history(input:*const u8,len:usize)->std::os::raw::c_int{unsafe{call(input,len,false)}}

#[cfg(test)]
mod tests{
    use super::*;
    use serde_json::{json,Value};
    use sociacl_encdisc::{GenesisAccount,EpochManifestBody,epoch_revision_id};
    fn fixture()->Value{
        let owner=GenesisAccount::generate().unwrap().into_secret();
        let group=sociacl_ids::mint_object_id("set",&owner.account().parse().unwrap()).unwrap();
        let group=group.as_ref();
        let s=json!({"predicate":"same-group","setId":group,"setOwner":owner.account(),"ownerSigningPub":owner.sea_pub(),
            "ownerEncryptionPub":owner.epub(),"ownerIdentityHead":0,"members":[{"accessor":owner.account(),"stated":1,"hamState":1,
                "signingPub":owner.sea_pub(),"encryptionPub":owner.epub(),"identityHead":0}]});
        let hash=group_key_snapshot_id(&snapshot(&s.to_string()).unwrap()).unwrap();
        let body=EpochManifestBody{object:group.into(),epoch:1,previous_epoch:0,device_id:"browser".into(),key_commitment:"a".repeat(64),
            settle_window_ms:3_600_000,acl_snapshot:hash.clone(),status_auth_pub:None};
        let revision=epoch_revision_id(&body).unwrap();
        let m=json!({"object":group,"epoch":1,"previousEpoch":0,"deviceId":"browser","keyCommitment":"a".repeat(64),
            "settleWindowMs":3_600_000,"aclSnapshot":hash,"revisionId":revision,"signature":owner.sign_epoch_manifest(&revision).unwrap()});
        let f=EpochFinalization::seal(group,0,1,&revision,vec![revision.clone()],"","").unwrap();
        json!({"object":group,"current":s,"config":{"owner":owner.account(),"setId":group,"predicate":"same-group","settleWindowMs":3_600_000,
            "configRevision":0,"signature":owner.sign_group_epoch_config(group,"same-group",3_600_000,0).unwrap()},
            "manifests":[{"document":{"manifest":m,"snapshot":s},"expected":{"object":group,"ownerPub":owner.sea_pub(),"epoch":1,"revisionId":revision}}],
            "finalizations":[{"ownerPub":owner.sea_pub(),"seenAt":100,"proof":{"object":group,"epoch":1,"previousEpoch":0,"revisionId":revision,
                "candidateRevisionIds":[revision],"previousFinalizationId":"","finalizationId":f.finalization_id,
                "signature":owner.sign_epoch_finalization(&f.finalization_id).unwrap()}}],
            "nowMs":3_600_100,"anchorFinalizationId":f.finalization_id,"minimumEpoch":1,"expectedEpoch":1,"expectedRevisionId":revision})
    }
    fn selected(v:&Value)->i32{let raw=v.to_string();unsafe{sociacl_match_settled_group_epoch(raw.as_ptr(),raw.len())}}
    #[test]
    fn authenticate_manifest_history_and_settled_group_with_no_media_edge(){
        let mut v=fixture();assert_eq!(selected(&v),1);
        let d=v["manifests"][0]["document"].to_string();let e=v["manifests"][0]["expected"].to_string();
        assert_eq!(unsafe{sociacl_verify_group_epoch_manifest(d.as_ptr(),d.len(),e.as_ptr(),e.len())},1);
        v["nowMs"]=json!(3_600_099);assert_eq!(selected(&v),0);
        let raw=v.to_string();assert_eq!(unsafe{sociacl_verify_group_epoch_history(raw.as_ptr(),raw.len())},1);
        v["current"]["members"][0]["stated"]=json!(0);assert_eq!(selected(&v),0);
        v["finalizations"][0]["proof"]["signature"]=json!("0".repeat(128));let raw=v.to_string();
        assert_eq!(unsafe{sociacl_verify_group_epoch_history(raw.as_ptr(),raw.len())},0);
    }
    #[test]
    fn scope_binding_clock_policy_and_duplicate_history_refuse(){
        let base=fixture();
        for (path,value) in [
            ("/object",json!("other")),("/current/setOwner",json!("bad")),("/current/predicate",json!("direct")),
            ("/current/members/0/identityHead",json!(1)),("/current/members/0/hamState",json!(2)),
            ("/config/signature",json!("0".repeat(128))),("/config/configRevision",json!(MAX_SAFE+1)),("/config/setId",json!("other")),
            ("/manifests/0/expected/ownerPub",json!("wrong")),("/manifests/0/expected/epoch",json!(2)),
            ("/manifests/0/document/manifest/deviceId",json!("")),("/manifests/0/document/manifest/epoch",json!(MAX_SAFE+1)),
            ("/finalizations/0/seenAt",json!(3_600_101)),("/finalizations/0/ownerPub",json!("")),
            ("/finalizations/0/proof/epoch",json!(MAX_SAFE+1)),("/finalizations/0/proof/candidateRevisionIds",json!([])),
            ("/anchorFinalizationId",json!("a".repeat(64))),("/minimumEpoch",json!(2)),("/expectedEpoch",json!(2)),
            ("/expectedRevisionId",json!("b".repeat(64))),("/nowMs",json!(MAX_SAFE+1))]{
            let mut v=base.clone();*v.pointer_mut(path).unwrap()=value;assert_eq!(selected(&v),0,"{path}");
        }
        for field in ["manifests","finalizations"]{
            for rows in [vec![],vec![base[field][0].clone();2],vec![base[field][0].clone();65]]{
                let mut v=base.clone();v[field]=json!(rows);assert_eq!(selected(&v),0);
            }
        }
    }
    #[test]
    fn original_json_objects_duplicates_and_ffi_bounds_are_strict(){
        let base=fixture();
        for path in ["/current","/config","/current/members/0","/manifests/0","/manifests/0/document","/manifests/0/document/manifest",
            "/manifests/0/document/snapshot","/manifests/0/expected","/finalizations/0","/finalizations/0/proof"]{
            let mut v=base.clone();let field=v.pointer_mut(path).unwrap();
            *field=Value::Array(field.as_object().unwrap().values().cloned().collect());assert_eq!(selected(&v),0,"{path}");
        }
        let raw=base.to_string();let duplicate=raw.replace("\"epoch\":1","\"epoch\":1,\"epoch\":1");
        for bad in [b"{".as_slice(),b"[]",b"\xff",duplicate.as_bytes()]{
            assert_eq!(unsafe{sociacl_match_settled_group_epoch(bad.as_ptr(),bad.len())},0);
        }
        let mut too_many=base.clone();too_many["current"]["members"]=json!(vec![base["current"]["members"][0].clone();65]);assert_eq!(selected(&too_many),0);
        let mut extra=base.clone();extra["manifests"][0]["document"]["manifest"]["statusAuthPub"]=json!(null);assert_eq!(selected(&extra),0);
        let d=base["manifests"][0]["document"].to_string();let e=base["manifests"][0]["expected"].to_string();
        assert!(document(&"x".repeat(MAX_DOCUMENT+1),&e).is_none());
        unsafe{
            assert_eq!(sociacl_match_settled_group_epoch(std::ptr::null(),1),0);
            assert_eq!(sociacl_verify_group_epoch_history(raw.as_ptr(),MAX_BYTES+1),0);
            assert_eq!(sociacl_match_settled_group_epoch(raw.as_ptr(),0),0);
            assert_eq!(sociacl_verify_group_epoch_manifest(std::ptr::null(),1,e.as_ptr(),e.len()),0);
            assert_eq!(sociacl_verify_group_epoch_manifest(d.as_ptr(),d.len(),std::ptr::null(),1),0);
            assert_eq!(sociacl_verify_group_epoch_manifest(d.as_ptr(),MAX_DOCUMENT+1,e.as_ptr(),e.len()),0);
            assert_eq!(sociacl_verify_group_epoch_manifest(b"\xff".as_ptr(),1,e.as_ptr(),e.len()),0);
            assert_eq!(sociacl_verify_group_epoch_manifest(b"{".as_ptr(),1,e.as_ptr(),e.len()),0);
        }
    }
}
