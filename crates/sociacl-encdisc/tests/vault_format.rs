use serde_json::Value;
use sociacl_encdisc::*;
fn vector() -> Value { serde_json::from_str(include_str!("../../../vectors/vault/v1.json")).unwrap() }
fn version(v: &Value) -> VaultVersion {
    VaultVersion { item_id:v["itemId"].as_str().unwrap().into(),version_id:v["versionId"].as_str().unwrap().into(),
        owner:v["owner"].as_str().unwrap().into(),parents:v["parents"].as_array().unwrap().iter().map(|p|p.as_str().unwrap().into()).collect(),
        epoch:v["epoch"].as_u64().unwrap(),revision_id:v["revisionId"].as_str().unwrap().into(),
        ciphertext_digest:v["ciphertextDigest"].as_str().unwrap().into(),sensitive:v["sensitive"].as_bool().unwrap(),issued_at:v["issuedAt"].as_u64().unwrap() }
}
#[test]
fn shared_vault_transcripts() {
    let fixture=vector(); let v=version(&fixture["version"]);
    let bytes=vault_version_signing_bytes(&v).unwrap();
    assert_eq!(serde_json::to_value(decode_length_prefixed(&bytes).unwrap()).unwrap(),fixture["versionFields"]);
    let a=&fixture["audit"];
    let audit=VaultAudit { event_id:a["eventId"].as_str().unwrap().into(),item_id:a["itemId"].as_str().unwrap().into(),
        version_id:a["versionId"].as_str().unwrap().into(),actor:a["actor"].as_str().unwrap().into(),device_id:a["deviceId"].as_str().unwrap().into(),
        operation:a["operation"].as_str().unwrap().into(),outcome:a["outcome"].as_str().unwrap().into(),issued_at:a["issuedAt"].as_u64().unwrap(),
        previous_digest:a["previousDigest"].as_str().unwrap().into() };
    assert_eq!(serde_json::to_value(decode_length_prefixed(&vault_audit_signing_bytes(&audit).unwrap()).unwrap()).unwrap(),fixture["auditFields"]);
    let mut invalid=audit.clone();invalid.operation="execute-unchecked".into();assert!(vault_audit_signing_bytes(&invalid).is_err());
    invalid=audit.clone();invalid.outcome="yes".into();assert!(vault_audit_signing_bytes(&invalid).is_err());
    invalid=audit.clone();invalid.previous_digest.push('\n');assert!(vault_audit_signing_bytes(&invalid).is_err());
    let mut changed=v.clone();changed.sensitive=false;assert_ne!(vault_version_signing_bytes(&changed).unwrap(),bytes);
    changed=v.clone();changed.epoch+=1;assert_ne!(vault_version_signing_bytes(&changed).unwrap(),bytes);
}
#[test]
fn vault_parents_and_boundaries_fail_closed() {
    let v=version(&vector()["version"]);
    for parents in [vec![v.version_id.clone()],vec![v.parents[0].clone(),v.parents[0].clone()],
        vec![v.parents[1].clone(),v.parents[0].clone()],(0..17).map(|n|format!("{n:064x}")).collect()] {
        let mut invalid=v.clone();invalid.parents=parents;assert!(vault_version_signing_bytes(&invalid).is_err());
    }
    let mut invalid=v.clone();invalid.issued_at=9_007_199_254_740_992;assert!(vault_version_signing_bytes(&invalid).is_err());
    invalid=v.clone();invalid.owner="https://login.example/user".into();assert!(vault_version_signing_bytes(&invalid).is_err());
    invalid=v.clone();invalid.item_id="AB".repeat(32);assert!(vault_version_signing_bytes(&invalid).is_err());
    invalid=v.clone();invalid.version_id.push('\n');assert!(vault_version_signing_bytes(&invalid).is_err());
    let mut genesis=v;genesis.parents.clear();assert!(vault_version_signing_bytes(&genesis).is_ok());
}
