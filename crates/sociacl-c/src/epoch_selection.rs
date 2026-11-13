//! Bounded adapter to the reference epoch chain. All history, clock, owner-key
//! bindings and current ACL inputs belong to the trusted service, not a client.
use serde::Deserialize;
use serde_json::value::RawValue;
use sociacl_encdisc::{epoch_step_current, EpochChain, EpochFinalization};
use crate::epoch_manifest::{parse_snapshot, verified_document};

const MAX_BYTES: usize = 524_288;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRow { document: Box<RawValue>, expected: Box<RawValue> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Finalization {
    object: String, previous_epoch: u64, epoch: u64, revision_id: String,
    candidate_revision_ids: Vec<String>, previous_finalization_id: String,
    finalization_id: String, signature: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalizationRow { proof: Finalization, owner_pub: String, seen_at: u64 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    object: String, manifests: Vec<ManifestRow>, finalizations: Vec<FinalizationRow>,
    current: Box<RawValue>, now_ms: u64, group_window_ms: Option<u64>,
    anchor_finalization_id: String, minimum_epoch: u64,
    expected_epoch: u64, expected_revision_id: String,
}
fn digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn shape(raw: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) else { return false; };
    if !v.is_object() { return false; }
    for name in ["manifests", "finalizations"] {
        let Some(rows) = v[name].as_array() else { return false; };
        if rows.is_empty() || rows.len() > 64 || !rows.iter().all(serde_json::Value::is_object) {
            return false;
        }
    }
    v["finalizations"].as_array().unwrap().iter().all(|row| row["proof"].is_object())
}
fn matches(raw: &[u8]) -> Option<()> {
    if !shape(raw) { return None; }
    let input: Input = serde_json::from_slice(raw).ok()?;
    if input.object.is_empty() || input.object.len() > 1024 || input.object.chars().any(char::is_control)
        || !digest(&input.anchor_finalization_id) || !digest(&input.expected_revision_id)
        || [input.now_ms, input.minimum_epoch, input.expected_epoch].iter().any(|n| *n > MAX_SAFE)
        || input.group_window_ms.is_some_and(|n| n > MAX_SAFE) { return None; }
    let current = parse_snapshot(input.current.get().as_bytes())?;
    let mut chain = EpochChain::new(&input.object).ok()?;
    let mut snapshots = std::collections::BTreeMap::new();
    for row in input.manifests {
        if row.document.get().len() > 65_536 || row.expected.get().len() > 65_536 { return None; }
        let (manifest, snapshot) = verified_document(row.document.get().as_bytes(), row.expected.get().as_bytes())?;
        if snapshots.contains_key(&manifest.revision_id) { return None; }
        snapshots.insert(manifest.revision_id.clone(), snapshot.clone());
        // The strict helper already matched and authenticated this owner key.
        let expected: serde_json::Value = serde_json::from_str(row.expected.get()).ok()?;
        chain.insert_manifest(manifest, snapshot, expected["ownerPub"].as_str()?).ok()?;
    }
    let mut ids = std::collections::BTreeSet::new();
    for row in input.finalizations {
        let p = row.proof;
        if row.owner_pub.is_empty() || row.owner_pub.len() > 1024 || row.seen_at > input.now_ms
            || [p.epoch, p.previous_epoch].iter().any(|n| *n > MAX_SAFE)
            || p.candidate_revision_ids.is_empty() || p.candidate_revision_ids.len() > 64
            || p.signature.len() != 128 || !ids.insert(p.finalization_id.clone()) { return None; }
        chain.insert_finalization(EpochFinalization {
            object: p.object, previous_epoch: p.previous_epoch, epoch: p.epoch,
            revision_id: p.revision_id, candidate_revision_ids: p.candidate_revision_ids,
            previous_finalization_id: p.previous_finalization_id, finalization_id: p.finalization_id,
            signature: p.signature,
        }, row.seen_at, &row.owner_pub).ok()?;
    }
    let winners = chain.on_chain_winners(&current, input.now_ms, input.group_window_ms);
    if winners.first()?.finalization_id != input.anchor_finalization_id { return None; }
    let winner = *winners.last()?;
    if winner.epoch < input.minimum_epoch || winner.epoch != input.expected_epoch
        || winner.revision_id != input.expected_revision_id { return None; }
    let view = chain.replica_view(winner.epoch, &current, input.now_ms, input.group_window_ms, "");
    if !epoch_step_current(&view, snapshots.get(&winner.revision_id)?, &current, input.now_ms) {
        return None;
    }
    Some(())
}

/// Match the latest settled reference-chain winner. Pending or mismatched state
/// refuses; there is no fallback to an older key. This is not a Check grant.
///
/// # Safety
/// The input pointer must be readable for input_len bytes throughout this call.
/// Input is bounded UTF-8 JSON; no pointer is retained or NUL terminator needed.
#[no_mangle]
pub unsafe extern "C" fn sociacl_match_settled_epoch(input: *const u8, input_len: usize) -> std::os::raw::c_int {
    if input.is_null() || input_len == 0 || input_len > MAX_BYTES { return 0; }
    let raw = unsafe { std::slice::from_raw_parts(input, input_len) };
    i32::from(matches(raw).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sociacl_encdisc::{GenesisAccount, GroupPredicate};

    fn fixture(group: Option<GroupPredicate>) -> Value {
        let owner = GenesisAccount::generate().unwrap().into_secret();
        let (mut doc, mut expected) = crate::epoch_manifest::tests::fixture(group);
        let revision = doc["manifest"]["revisionId"].as_str().unwrap().to_owned();
        doc["manifest"]["signature"] = json!(owner.sign_epoch_manifest(&revision).unwrap());
        expected["ownerPub"] = json!(owner.sea_pub());
        let mut fin = EpochFinalization::seal("media", 0, 1, &revision, vec![revision.clone()], "", "").unwrap();
        fin.signature = owner.sign_epoch_finalization(&fin.finalization_id).unwrap();
        json!({"object":"media","manifests":[{"document":doc,"expected":expected}],
            "finalizations":[{"ownerPub":owner.sea_pub(),"seenAt":100,"proof":{
                "object":"media","previousEpoch":0,"epoch":1,"revisionId":revision,
                "candidateRevisionIds":[revision],"previousFinalizationId":"",
                "finalizationId":fin.finalization_id,"signature":fin.signature}}],
            "current":doc["snapshot"],"nowMs":3_600_100,"groupWindowMs":group.map(|_| 3_600_000),
            "anchorFinalizationId":fin.finalization_id,"minimumEpoch":1,
            "expectedEpoch":1,"expectedRevisionId":revision})
    }
    fn call(value: &Value) -> i32 {
        let raw = serde_json::to_vec(value).unwrap();
        unsafe { sociacl_match_settled_epoch(raw.as_ptr(), raw.len()) }
    }
    #[test]
    fn direct_and_group_settlement_matches_reference() {
        for group in [None, Some(GroupPredicate::SameGroup), Some(GroupPredicate::NamedCircle)] {
            let doc = fixture(group);
            assert_eq!(call(&doc), 1);
            let mut pending = doc.clone(); pending["nowMs"] = json!(3_600_099);
            assert_eq!(call(&pending), 0);
        }
    }
    #[test]
    fn binding_floors_clock_and_current_acl_refuse() {
        let doc = fixture(None);
        for (path, value) in [
            ("/object",json!("other")),("/object",json!("")),
            ("/anchorFinalizationId",json!("a".repeat(64))),
            ("/anchorFinalizationId",json!("bad")),("/minimumEpoch",json!(2)),
            ("/expectedEpoch",json!(2)),("/expectedRevisionId",json!("b".repeat(64))),
            ("/nowMs",json!(MAX_SAFE+1)),("/groupWindowMs",json!(MAX_SAFE+1)),
            ("/current/entries/0/stated",json!(0)),("/current/entries/0/until",json!(100)),
            ("/finalizations/0/seenAt",json!(3_600_101)),("/finalizations/0/ownerPub",json!("")),
            ("/finalizations/0/proof/epoch",json!(MAX_SAFE+1)),
            ("/finalizations/0/proof/signature",json!("0".repeat(128))),
            ("/finalizations/0/proof/signature",json!("bad")),
            ("/finalizations/0/proof/candidateRevisionIds",json!([])),
        ] {
            let mut changed = doc.clone(); *changed.pointer_mut(path).unwrap() = value;
            assert_eq!(call(&changed), 0, "{path}");
        }
        for name in ["manifests","finalizations"] {
            let mut changed = doc.clone();
            changed[name].as_array_mut().unwrap().push(doc[name][0].clone());
            assert_eq!(call(&changed), 0);
        }
        let mut changed = fixture(Some(GroupPredicate::SameGroup));
        changed["groupWindowMs"] = json!(null); assert_eq!(call(&changed),0);
    }
    #[test]
    fn original_json_parsing_bounds_and_shapes_are_strict() {
        let doc = fixture(None);
        for path in ["/manifests/0","/finalizations/0","/finalizations/0/proof","/current",
                     "/current/entries/0","/manifests/0/document","/manifests/0/expected"] {
            let mut changed = doc.clone();
            let row = changed.pointer_mut(path).unwrap();
            *row = Value::Array(row.as_object().unwrap().values().cloned().collect());
            assert_eq!(call(&changed),0,"{path}");
        }
        for name in ["manifests","finalizations"] {
            for value in [json!(null),json!([]),json!(vec![doc[name][0].clone();65])] {
                let mut changed=doc.clone(); changed[name]=value; assert_eq!(call(&changed),0);
            }
        }
        let mut changed=doc.clone(); changed["current"]["entries"]=json!(null); assert_eq!(call(&changed),0);
        changed["current"]["entries"]=json!(vec![doc["current"]["entries"][0].clone();129]); assert_eq!(call(&changed),0);
        changed=doc.clone(); changed["current"]["entries"][0]["scope"]=json!("invalid"); assert_eq!(call(&changed),0);
        changed=doc.clone(); changed["manifests"][0]["document"]["padding"]=json!("x".repeat(65_536)); assert_eq!(call(&changed),0);
        let raw=serde_json::to_vec(&doc).unwrap();
        let duplicates=String::from_utf8(raw.clone()).unwrap().replace("\"epoch\":1", "\"epoch\":1,\"epoch\":1");
        for bad in [b"{".as_slice(),b"[]",b"\xff",duplicates.as_bytes()] {
            assert_eq!(unsafe{sociacl_match_settled_epoch(bad.as_ptr(),bad.len())},0);
        }
        unsafe {
            assert_eq!(sociacl_match_settled_epoch(std::ptr::null(),1),0);
            assert_eq!(sociacl_match_settled_epoch(raw.as_ptr(),0),0);
            assert_eq!(sociacl_match_settled_epoch(raw.as_ptr(),MAX_BYTES+1),0);
        }
    }
}
