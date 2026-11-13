//! Authenticate a manifest and its snapshot with the existing Rust reference.
//! This does not select a current epoch or establish an access grant.
use serde::Deserialize;
use sociacl_encdisc::{AclObjectSet, AclScope, AclSnapshotBody, AclSnapshotEntry,
    EpochManifest, GrantStated, GroupPredicate};

const MAX_DOCUMENT: usize = 65_536;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    object: String, previous_epoch: u64, epoch: u64, device_id: String,
    revision_id: String, key_commitment: String, settle_window_ms: u64,
    acl_snapshot: String, status_auth_pub: Option<String>, signature: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    accessor: String, grant_revision: u64, stated: u8, from: u64, until: u64,
    scope: String, set_id: String, ham_state: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObjectSet { predicate: String, set_id: String, stated: u8, ham_state: u64 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot { object_set: Option<ObjectSet>, entries: Vec<Entry> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document { manifest: Manifest, snapshot: Snapshot }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected { owner_pub: String, object: String, epoch: u64, revision_id: String }

fn text(s: &str, empty: bool) -> bool {
    (empty || !s.is_empty()) && s.len() <= 1024 && !s.chars().any(char::is_control)
}
fn stated(n: u8) -> Option<GrantStated> {
    match n { 0 => Some(GrantStated::Cancelled), 1 => Some(GrantStated::Live), _ => None }
}
fn shape(raw: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) else { return false; };
    if !v.is_object() || !v["manifest"].is_object() || !v["snapshot"].is_object() {
        return false;
    }
    let Some(entries) = v["snapshot"]["entries"].as_array() else { return false; };
    entries.len() <= 128 && entries.iter().all(serde_json::Value::is_object)
        && (v["snapshot"]["objectSet"].is_null() || v["snapshot"]["objectSet"].is_object())
}
fn verify(document: &[u8], expected: &[u8]) -> Option<()> {
    // Validate shape, then deserialize the original bytes to reject duplicates.
    if !shape(document) || !serde_json::from_slice::<serde_json::Value>(expected).ok()?.is_object() {
        return None;
    }
    let Document { manifest: m, snapshot: s } = serde_json::from_slice(document).ok()?;
    let e: Expected = serde_json::from_slice(expected).ok()?;
    if m.object != e.object || m.epoch != e.epoch || m.revision_id != e.revision_id
        || !text(&e.owner_pub, false) || !text(&m.object, false) || !text(&m.device_id, false)
        || !text(&m.key_commitment, false) || !text(&m.signature, false)
        || m.status_auth_pub.as_ref().is_some_and(|p| !text(p, false))
        || [m.previous_epoch, m.epoch, m.settle_window_ms].iter().any(|n| *n > MAX_SAFE) {
        return None;
    }
    let mut entries = Vec::with_capacity(s.entries.len());
    for row in s.entries {
        if !text(&row.accessor, false) || !text(&row.set_id, true)
            || [row.grant_revision, row.from, row.until, row.ham_state].iter().any(|n| *n > MAX_SAFE) {
            return None;
        }
        entries.push(AclSnapshotEntry {
            accessor: row.accessor, grant_revision: row.grant_revision,
            stated: stated(row.stated)?, from: row.from, until: row.until,
            scope: AclScope::parse(&row.scope).ok()?, set_id: row.set_id, ham_state: row.ham_state,
        });
    }
    let object_set = match s.object_set {
        None => None,
        Some(row) => {
            if !text(&row.set_id, false) || row.ham_state > MAX_SAFE { return None; }
            let predicate = match row.predicate.as_str() {
                "same-group" => GroupPredicate::SameGroup,
                "named-circle" => GroupPredicate::NamedCircle,
                _ => return None,
            };
            Some(AclObjectSet { predicate, set_id: row.set_id,
                stated: stated(row.stated)?, ham_state: row.ham_state })
        }
    };
    let manifest = EpochManifest {
        object: m.object, previous_epoch: m.previous_epoch, epoch: m.epoch,
        device_id: m.device_id, revision_id: m.revision_id, key_commitment: m.key_commitment,
        settle_window_ms: m.settle_window_ms, acl_snapshot: m.acl_snapshot,
        status_auth_pub: m.status_auth_pub, signature: m.signature,
    };
    manifest.verify(&AclSnapshotBody { object_set, entries }, &e.owner_pub).ok()
}

/// Match an owner-signed manifest and snapshot to independently trusted context.
/// Returns 1 on match, 0 otherwise. Neither establishes currentness or access.
///
/// # Safety
/// Non-null pointers must be readable for their supplied lengths during this
/// call. No pointers are retained; buffers do not require NUL termination.
#[no_mangle]
pub unsafe extern "C" fn sociacl_verify_epoch_manifest(
    document: *const u8, document_len: usize, expected: *const u8, expected_len: usize,
) -> std::os::raw::c_int {
    if document.is_null() || expected.is_null() || document_len == 0 || expected_len == 0
        || document_len > MAX_DOCUMENT || expected_len > MAX_DOCUMENT { return 0; }
    let document = unsafe { std::slice::from_raw_parts(document, document_len) };
    let expected = unsafe { std::slice::from_raw_parts(expected, expected_len) };
    i32::from(verify(document, expected).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sociacl_encdisc::{acl_snapshot_id, epoch_revision_id, GenesisAccount, EpochManifestBody};

    fn fixture(group: Option<GroupPredicate>) -> (Value, Value) {
        let owner = GenesisAccount::generate().unwrap().into_secret();
        let scope = match group {
            Some(GroupPredicate::SameGroup) => AclScope::SameGroup,
            Some(GroupPredicate::NamedCircle) => AclScope::NamedCircle,
            None => AclScope::Direct,
        };
        let set_id = if group.is_some() { "set" } else { "" };
        let snapshot = AclSnapshotBody {
            object_set: group.map(|predicate| AclObjectSet {
                predicate, set_id: set_id.into(), stated: GrantStated::Live, ham_state: 0,
            }),
            entries: vec![AclSnapshotEntry {
                accessor: "reader".into(), grant_revision: 1, stated: GrantStated::Live,
                from: 0, until: 4_000_000_000_000, scope, set_id: set_id.into(), ham_state: 0,
            }],
        };
        let acl = acl_snapshot_id(&snapshot).unwrap();
        let body = EpochManifestBody {
            object: "media".into(), previous_epoch: 0, epoch: 1, device_id: "device".into(),
            key_commitment: "commitment".into(), settle_window_ms: 3_600_000,
            acl_snapshot: acl.clone(), status_auth_pub: None,
        };
        let revision = epoch_revision_id(&body).unwrap();
        let doc = json!({"manifest": {
            "object":"media", "previousEpoch":0, "epoch":1, "deviceId":"device",
            "revisionId":revision, "keyCommitment":"commitment", "settleWindowMs":3_600_000,
            "aclSnapshot":acl, "signature":owner.sign_epoch_manifest(&revision).unwrap()
        }, "snapshot": {"objectSet":group.map(|p| json!({"predicate":p.as_str(),
            "setId":"set","stated":1,"hamState":0})), "entries":[{
            "accessor":"reader","grantRevision":1,"stated":1,"from":0,"until":4_000_000_000_000u64,
            "scope":scope.as_str(),"setId":set_id,"hamState":0
        }]}});
        let expected = json!({"ownerPub":owner.sea_pub(),"object":"media","epoch":1,"revisionId":revision});
        (doc, expected)
    }
    fn call_raw(doc: &[u8], expected: &[u8]) -> i32 {
        unsafe { sociacl_verify_epoch_manifest(doc.as_ptr(), doc.len(), expected.as_ptr(), expected.len()) }
    }
    fn call(doc: &Value, expected: &Value) -> i32 {
        call_raw(&serde_json::to_vec(doc).unwrap(), &serde_json::to_vec(expected).unwrap())
    }
    #[test]
    fn reference_signed_direct_and_group_manifests_match() {
        for group in [None, Some(GroupPredicate::SameGroup), Some(GroupPredicate::NamedCircle)] {
            let (doc, expected) = fixture(group);
            assert_eq!(call(&doc, &expected), 1);
            let mut absent_set = doc.clone();
            absent_set["snapshot"].as_object_mut().unwrap().remove("objectSet");
            assert_eq!(call(&absent_set, &expected), if group.is_none() { 1 } else { 0 });
        }
        assert_eq!(stated(0), Some(GrantStated::Cancelled));
        assert_eq!(stated(2), None);
    }
    #[test]
    fn wrong_expected_context_and_manifest_tampering_refuse() {
        let (doc, expected) = fixture(None);
        for (key, value) in [("ownerPub",json!("wrong")),("object",json!("other")),
            ("epoch",json!(2)),("revisionId",json!("a".repeat(64)))] {
            let mut changed = expected.clone(); changed[key] = value;
            assert_eq!(call(&doc, &changed), 0);
        }
        for (key, value) in [("signature",json!("bad")),("aclSnapshot",json!("a".repeat(64))),
            ("previousEpoch",json!(MAX_SAFE+1)),("deviceId",json!("")),("keyCommitment",json!("\n")),
            ("settleWindowMs",json!(1)),("statusAuthPub",json!("")),("unknown",json!(true))] {
            let mut changed = doc.clone(); changed["manifest"][key] = value;
            assert_eq!(call(&changed, &expected), 0, "{key}");
        }
        for (key, value) in [("accessor",json!("")),("grantRevision",json!(MAX_SAFE+1)),
            ("stated",json!(2)),("scope",json!("bogus")),("setId",json!("wrong")),("until",json!(1))] {
            let mut changed = doc.clone(); changed["snapshot"]["entries"][0][key] = value;
            assert_eq!(call(&changed, &expected), 0, "{key}");
        }
        let (doc, expected) = fixture(Some(GroupPredicate::SameGroup));
        for (key, value) in [("predicate",json!("bogus")),("setId",json!("")),
            ("stated",json!(2)),("hamState",json!(MAX_SAFE+1))] {
            let mut changed = doc.clone(); changed["snapshot"]["objectSet"][key] = value;
            assert_eq!(call(&changed, &expected), 0);
        }
    }
    #[test]
    fn strict_objects_bounds_and_duplicate_fields() {
        let (doc, expected) = fixture(Some(GroupPredicate::SameGroup));
        for path in ["/manifest","/snapshot","/snapshot/entries/0","/snapshot/objectSet"] {
            let mut changed = doc.clone();
            let row = changed.pointer_mut(path).unwrap();
            *row = Value::Array(row.as_object().unwrap().values().cloned().collect());
            assert_eq!(call(&changed, &expected), 0, "{path}");
        }
        let raw = serde_json::to_vec(&doc).unwrap();
        let expected_raw = serde_json::to_vec(&expected).unwrap();
        for bad in [b"{".as_slice(), b"\xff", b"[]", b"null"] {
            assert_eq!(call_raw(bad, &expected_raw), 0);
            assert_eq!(call_raw(&raw, bad), 0);
        }
        let duplicated = String::from_utf8(raw.clone()).unwrap().replace("\"epoch\":1", "\"epoch\":1,\"epoch\":1");
        assert_eq!(call_raw(duplicated.as_bytes(), &expected_raw), 0);
        let duplicated = String::from_utf8(expected_raw.clone()).unwrap().replace("\"epoch\":1", "\"epoch\":1,\"epoch\":1");
        assert_eq!(call_raw(&raw, duplicated.as_bytes()), 0);
        let mut changed = doc.clone(); changed["snapshot"]["entries"] = json!(null);
        assert_eq!(call(&changed, &expected), 0);
        changed["snapshot"]["entries"] = json!(vec![doc["snapshot"]["entries"][0].clone();129]);
        assert_eq!(call(&changed, &expected), 0);
        unsafe {
            assert_eq!(sociacl_verify_epoch_manifest(std::ptr::null(),1,expected_raw.as_ptr(),expected_raw.len()),0);
            assert_eq!(sociacl_verify_epoch_manifest(raw.as_ptr(),raw.len(),std::ptr::null(),1),0);
            for len in [0, MAX_DOCUMENT+1] {
                assert_eq!(sociacl_verify_epoch_manifest(raw.as_ptr(),len,expected_raw.as_ptr(),expected_raw.len()),0);
                assert_eq!(sociacl_verify_epoch_manifest(raw.as_ptr(),raw.len(),expected_raw.as_ptr(),len),0);
            }
        }
    }
}
