use serde_json::{json, Value};
use sociacl_encdisc::{open_reader_wrap, wrap_group_key_to_members, GenesisAccount, EnrolledSeaPub,
    GroupEpochKey, NamedSet, WrapScope, WrapTarget, WrappedKey};

#[test]
fn group_member_wrap_cross_language_contract() {
    let f:Value=serde_json::from_str(include_str!("../../../vectors/encrypted-discovery/sea-fixture.json")).unwrap();
    let v:Value=serde_json::from_str(include_str!("../../../vectors/encrypted-discovery/wrap.json")).unwrap();
    let group=v["object"].as_str().unwrap().replacen("item_","set_",1);
    let revision=f["revisionId"].as_str().unwrap();
    let account=GenesisAccount::import(f["laneId"].as_str().unwrap(),f["signing"]["pub"].as_str().unwrap(),
        f["signing"]["priv"].as_str().unwrap(),f["encryption"]["epub"].as_str().unwrap(),
        f["encryption"]["epriv"].as_str().unwrap()).unwrap().into_secret();
    let named=NamedSet::try_from_accessors([account.account()]).unwrap();
    let key=GroupEpochKey::from_bytes([0x33;32]);
    let wrapped=wrap_group_key_to_members(&key,3,&group,revision,&[EnrolledSeaPub::from_account(&account)],&named).unwrap();
    let wrap=&wrapped[0];
    if let Ok(path)=std::env::var("GROUP_MEMBER_RUST_VECTOR") {
        std::fs::write(path,serde_json::to_vec(&json!({"group":group,"epoch":3,"revisionId":revision,
            "scope":"group-key","target":"reader-epub","targetId":wrap.target_id,"wrappedKey":wrap.wrapped_key})).unwrap()).unwrap();
    }
    if let Ok(path)=std::env::var("GROUP_MEMBER_TS_VECTOR") {
        let raw:Value=serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(raw["group"],group);assert_eq!(raw["revisionId"],revision);assert_eq!(raw["epoch"],3);
        assert_eq!(raw["scope"],"group-key");assert_eq!(raw["target"],"reader-epub");assert_eq!(raw["targetId"],account.epub());
        let wrap=WrappedKey{scope:WrapScope::GroupKey,epoch:3,target:WrapTarget::ReaderEpub,
            target_id:account.epub().to_string(),object:None,group:Some(group),revision_id:revision.to_string(),
            wrapped_key:raw["wrappedKey"].as_str().unwrap().to_string()};
        let opened=open_reader_wrap(&wrap,f["encryption"]["epriv"].as_str().unwrap(),account.epub()).unwrap();
        assert_eq!(opened.key_bytes(),key.as_bytes());
        let mut changed=wrap.clone();changed.revision_id="ab".repeat(32);
        assert!(open_reader_wrap(&changed,f["encryption"]["epriv"].as_str().unwrap(),account.epub()).is_err());
    }
}
