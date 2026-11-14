use serde_json::{json, Value};
use sociacl_encdisc::{open_group_epoch_wrap, wrap_item_dek_to_group_epoch, GroupEpochKey, ItemDek, WrapScope, WrapTarget, WrappedKey};

fn context() -> (String, String, String) {
    let wrap: Value = serde_json::from_str(include_str!("../../../vectors/encrypted-discovery/wrap.json")).unwrap();
    let identity: Value = serde_json::from_str(include_str!("../../../vectors/encrypted-discovery/sea-fixture.json")).unwrap();
    let object = wrap["object"].as_str().unwrap().to_string();
    (object.clone(), object.replacen("item_", "set_", 1), identity["revisionId"].as_str().unwrap().to_string())
}

#[test]
fn rust_group_wrap_for_browser() {
    let (object, group, revision) = context();
    let key = GroupEpochKey::from_bytes([0x33; 32]);
    let dek = ItemDek::from_bytes([0x11; 32]);
    let wrap = wrap_item_dek_to_group_epoch(&dek, &key, 3, &object, &group, &revision).unwrap();
    assert_eq!(open_group_epoch_wrap(&wrap, &group, &key).unwrap().key_bytes(), dek.as_bytes());
    if let Ok(path) = std::env::var("GROUP_WRAP_RUST_VECTOR") {
        std::fs::write(path, serde_json::to_vec(&json!({"epoch":3,"object":object,"group":group,
            "revisionId":revision,"scope":"item-dek","target":"group-epoch","targetId":wrap.target_id,
            "wrappedKey":wrap.wrapped_key})).unwrap()).unwrap();
    }
}

#[test]
fn rust_opens_browser_group_wrap() {
    let Ok(path) = std::env::var("GROUP_WRAP_TS_VECTOR") else { return; };
    let raw: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let (object, group, revision) = context();
    assert_eq!(raw["object"],object);assert_eq!(raw["group"],group);assert_eq!(raw["targetId"],group);
    assert_eq!(raw["revisionId"],revision);assert_eq!(raw["epoch"],3);
    assert_eq!(raw["scope"],"item-dek");assert_eq!(raw["target"],"group-epoch");
    let wrap = WrappedKey { scope:WrapScope::ItemDek, epoch:3, target:WrapTarget::GroupEpoch,
        target_id:group.clone(), object:Some(object), group:Some(group.clone()), revision_id:revision,
        wrapped_key:raw["wrappedKey"].as_str().unwrap().to_string() };
    let key = GroupEpochKey::from_bytes([0x33;32]);
    assert_eq!(open_group_epoch_wrap(&wrap,&group,&key).unwrap().key_bytes(), &[0x11;32]);
    let mut changed=wrap.clone();changed.revision_id="ab".repeat(32);
    assert!(open_group_epoch_wrap(&changed,&group,&key).is_err());
    assert!(open_group_epoch_wrap(&wrap,&group,&GroupEpochKey::from_bytes([0x44;32])).is_err());
}
