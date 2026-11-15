//! Independent group key contracts run in CI; no media edge or grant is minted.
use sociacl_encdisc::*;

fn snapshot(owner: &AccountSeaSecret) -> GroupKeySnapshot {
    let principal=owner.account().parse().unwrap();
    let group=sociacl_ids::mint_object_id("set",&principal).unwrap();
    GroupKeySnapshot { predicate:GroupPredicate::SameGroup,set_id:group.as_ref().to_string(),
        set_owner:owner.account().to_string(),owner_signing_pub:owner.sea_pub().to_string(),
        owner_encryption_pub:owner.epub().to_string(),owner_identity_head:0,members:vec![] }
}
fn policy(owner: &AccountSeaSecret,s:&GroupKeySnapshot)->GroupEpochConfig {
    GroupEpochConfig {owner:s.set_owner.clone(),set_id:s.set_id.clone(),predicate:s.predicate,
        settle_window_ms:3_600_000,config_revision:0,
        signature:owner.sign_group_epoch_config(&s.set_id,s.predicate.as_str(),3_600_000,0).unwrap()}
}
fn manifest(owner:&AccountSeaSecret,s:&GroupKeySnapshot,epoch:u64)->EpochManifest {
    let body=EpochManifestBody {object:s.set_id.clone(),epoch,previous_epoch:epoch-1,device_id:"browser".into(),
        key_commitment:"a".repeat(64),settle_window_ms:3_600_000,acl_snapshot:group_key_snapshot_id(s).unwrap(),status_auth_pub:None};
    let id=epoch_revision_id(&body).unwrap();
    EpochManifest {object:body.object,epoch,previous_epoch:epoch-1,device_id:body.device_id,key_commitment:body.key_commitment,
        settle_window_ms:body.settle_window_ms,acl_snapshot:body.acl_snapshot,status_auth_pub:None,
        signature:owner.sign_epoch_manifest(&id).unwrap(),revision_id:id}
}
fn finalize(owner:&AccountSeaSecret,m:&EpochManifest,parent:&str)->EpochFinalization {
    let mut fin=EpochFinalization::seal(&m.object,m.previous_epoch,m.epoch,&m.revision_id,vec![m.revision_id.clone()],parent,"").unwrap();
    fin.signature=owner.sign_epoch_finalization(&fin.finalization_id).unwrap();fin
}
#[test]
fn independent_group_settles_without_any_media_edge_and_refuses_changed_authority() {
    let owner=GenesisAccount::generate().unwrap().into_secret();let mut s=snapshot(&owner);
    let member=GenesisAccount::generate().unwrap().into_secret();
    s.members.push(GroupKeyMember{accessor:member.account().into(),stated:1,ham_state:1,
        signing_pub:member.sea_pub().into(),encryption_pub:member.epub().into(),identity_head:0});
    let config=policy(&owner,&s);let m=manifest(&owner,&s,1);let f=finalize(&owner,&m,"");
    let mut chain=EpochChain::new(&s.set_id).unwrap();
    chain.insert_group_manifest(m.clone(),s.clone(),owner.sea_pub()).unwrap();
    chain.insert_group_manifest(m.clone(),s.clone(),owner.sea_pub()).unwrap();
    chain.insert_finalization(f.clone(),100,owner.sea_pub()).unwrap();
    assert!(chain.settled_group_key(&s,3_600_099,&config,&f.finalization_id,1).is_none());
    assert_eq!(chain.settled_group_key(&s,3_600_100,&config,&f.finalization_id,1).unwrap().revision_id,m.revision_id);
    assert!(chain.settled_group_key(&s,3_600_100,&config,"wrong",1).is_none());
    assert!(chain.settled_group_key(&s,3_600_100,&config,&f.finalization_id,2).is_none());
    for change in 0..7 {
        let mut current=s.clone();
        match change {0=>current.members[0].stated=0,1=>current.members[0].ham_state+=1,
            2=>current.members[0].encryption_pub=owner.epub().into(),3=>current.members[0].signing_pub=owner.sea_pub().into(),
            4=>current.members[0].identity_head+=1,5=>current.owner_identity_head+=1,_=>current.members.clear()}
        assert!(chain.settled_group_key(&current,3_600_100,&config,&f.finalization_id,1).is_none());
    }
    let mut changed=config.clone();changed.settle_window_ms*=2;
    assert!(chain.settled_group_key(&s,9_000_000,&changed,&f.finalization_id,1).is_none());
    // A valid successor blocks fallback to the old settled key until it settles.
    let second=manifest(&owner,&s,2);let next=finalize(&owner,&second,&f.finalization_id);
    chain.insert_group_manifest(second.clone(),s.clone(),owner.sea_pub()).unwrap();
    chain.insert_finalization(next,3_600_100,owner.sea_pub()).unwrap();
    assert!(chain.settled_group_key(&s,3_600_101,&config,&f.finalization_id,1).is_none());
    assert_eq!(chain.settled_group_key(&s,7_200_100,&config,&f.finalization_id,1).unwrap().epoch,2);
    assert!(chain.settled_current_key(&AclSnapshotBody{object_set:None,entries:vec![]},7_200_100,None,&f.finalization_id,1).is_none());
}
#[test]
fn snapshot_scope_keys_order_and_safe_integers_are_canonical() {
    let owner=GenesisAccount::generate().unwrap().into_secret();let s=snapshot(&owner);
    let digest=group_key_snapshot_id(&s).unwrap();assert_eq!(digest.len(),64);
    let mut circle=s.clone();circle.predicate=GroupPredicate::NamedCircle;
    assert_ne!(group_key_snapshot_id(&circle).unwrap(),digest);
    let row=GroupKeyMember{accessor:owner.account().into(),stated:0,ham_state:1,signing_pub:owner.sea_pub().into(),
        encryption_pub:owner.epub().into(),identity_head:0};
    let mut joined=s.clone();joined.members.push(row.clone());assert_ne!(group_key_snapshot_id(&joined).unwrap(),digest);
    for change in 0..10 {
        let mut bad=joined.clone();
        match change {0=>bad.set_id="set_bad".into(),1=>bad.set_owner="bad".into(),2=>bad.owner_signing_pub="bad".into(),
            3=>bad.owner_identity_head=u64::MAX,4=>bad.members=vec![row.clone();65],5=>bad.members.push(row.clone()),
            6=>bad.members[0].stated=2,7=>bad.members[0].ham_state=u64::MAX,8=>bad.members[0].signing_pub="bad".into(),
            _=>bad.members[0].identity_head=1}
        assert!(group_key_snapshot_id(&bad).is_err());
    }
}
#[test]
fn malformed_or_cross_scope_manifests_never_enter_the_group_chain() {
    let owner=GenesisAccount::generate().unwrap().into_secret();let s=snapshot(&owner);let m=manifest(&owner,&s,1);
    for change in 0..8 {
        let mut bad=m.clone();match change {0=>bad.object="other".into(),1=>bad.device_id.clear(),2=>bad.status_auth_pub=Some(owner.sea_pub().into()),
            3=>bad.settle_window_ms=0,4=>bad.key_commitment="bad".into(),5=>bad.revision_id="bad".into(),
            6=>bad.acl_snapshot="b".repeat(64),_=>bad.signature="0".repeat(128)}
        let mut chain=EpochChain::new(&s.set_id).unwrap();assert!(chain.insert_group_manifest(bad,s.clone(),owner.sea_pub()).is_err());
    }
    let mut chain=EpochChain::new(&s.set_id).unwrap();assert!(chain.insert_group_manifest(m,s.clone(),"wrong").is_err());
    let config=policy(&owner,&s);assert!(chain.settled_group_key(&s,u64::MAX,&config,"",0).is_none());
}
