use serde_json::{json, Value};
use sociacl_ids::*;
use std::collections::{BTreeMap, BTreeSet};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../vectors/first-contact/v1.json")).unwrap()
}
fn descriptor(v: &Value) -> FirstContactDescriptor {
    let d = &v["descriptor"];
    FirstContactDescriptor { channel_id: d["channelId"].as_str().unwrap().into(),
        revision: d["revision"].as_u64().unwrap(), expires_at: d["expiresAt"].as_u64().unwrap(),
        max_lifetime_seconds: d["maxLifetimeSeconds"].as_u64().unwrap(),
        max_message_bytes: d["maxMessageBytes"].as_u64().unwrap() as usize }
}
fn signed(mut row: Value) -> Value {
    row["sig"] = json!("A".repeat(86));
    let request = parse_first_contact_request(&row).unwrap();
    let mut key = [0; 32]; key[31] = 1;
    row["sig"] = json!(sign_with_keyring(&key, &first_contact_request_bytes(&request).unwrap(), &request.sender).unwrap());
    row
}
fn context<'a>(jwks: &'a Jwks, links: &'a BTreeMap<String, Value>, policy: &'a SiwePolicy,
    issuers: &'a BTreeSet<String>, history: &'a HistoryResolver<'a>) -> ResolutionContext<'a> {
    ResolutionContext { jwks, links, revocations: &[], now: 1700000020, policy,
        pinned_iss: issuers, history, genesis_epub_bindings: &[] }
}

#[test]
fn canonical_vectors_and_fail_closed_admission() {
    let v = fixture(); let d = descriptor(&v); let row = signed(v["request"].clone());
    let jwks = Jwks { keys: vec![] }; let links = BTreeMap::new(); let issuers = BTreeSet::new();
    let policy = SiwePolicy { allowed_domains: vec![], allowed_uris: vec![], allowed_chain_ids: vec![], clock_skew_seconds: 0 };
    let history = |p: &PrincipalId, at, until| Ok(history_state(p, &[], at, until));
    let mut ctx = context(&jwks, &links, &policy, &issuers, &history);
    let verified = verify_first_contact_request(&row, &[], &ctx, &d).unwrap();
    let bytes = first_contact_request_bytes(&verified.request).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, v["signingBytesHex"].as_str().unwrap());
    assert_eq!(verified.request_id, v["requestId"].as_str().unwrap());
    assert_eq!(verified.replay_key, v["replayKey"].as_str().unwrap());
    assert_eq!(verified.replay_until, d.expires_at);
    assert_eq!(verified.request.message, v["request"]["message"].as_str().unwrap());
    for (field, value) in [("message", json!("changed")), ("nonce", json!("ef".repeat(32))),
        ("replyEpub", row["sender"].clone()), ("sender", row["replyEpub"].clone()),
        ("channelId", json!("cd".repeat(32))), ("descriptorRevision", json!(2)),
        ("issuedAt", json!(1700000001)), ("expiresAt", json!(1700000299))] {
        let mut altered = row.clone(); altered[field] = value;
        assert!(verify_first_contact_request(&altered, &[], &ctx, &d).is_err(), "{field}");
    }
    let mut short = row.clone(); short["expiresAt"] = json!(ctx.now + 1);
    let short = verify_first_contact_request(&signed(short), &[], &ctx, &d).unwrap();
    ctx.now += 2;
    let mut changed = row.clone(); changed["message"] = json!("new message");
    let later = verify_first_contact_request(&signed(changed), &[], &ctx, &d).unwrap();
    assert_eq!(short.replay_key, later.replay_key);
    assert_ne!(short.request_id, later.request_id);
    assert!(short.replay_until > ctx.now);
    assert_eq!(short.replay_until, later.replay_until);
    let mut limit = d.clone(); limit.max_message_bytes = 1;
    assert_eq!(verify_first_contact_request(&row, &[], &ctx, &limit), Err(Reason::BadRecord));
    limit = d.clone(); limit.max_lifetime_seconds = 1;
    assert_eq!(verify_first_contact_request(&row, &[], &ctx, &limit), Err(Reason::BadRecord));
    ctx.now = 1700000300;
    assert_eq!(verify_first_contact_request(&row, &[], &ctx, &d), Err(Reason::Expired));
    ctx.now = 1699999999;
    assert_eq!(verify_first_contact_request(&row, &[], &ctx, &d), Err(Reason::FutureRecord));
    ctx.now = 1700000020;
    let missing = |_: &PrincipalId, _, _| Err(Reason::MissingHistory);
    ctx.history = &missing;
    assert_eq!(verify_first_contact_request(&row, &[], &ctx, &d), Err(Reason::MissingHistory));
}

#[test]
fn parser_rejects_extra_fields_coercion_and_utf8_overflow() {
    let row = signed(fixture()["request"].clone());
    for (field, value) in [("extra", json!(true)), ("descriptorRevision", json!("1")),
        ("issuedAt", json!(-0.0)), ("expiresAt", json!(9007199254740992u64)),
        ("nonce", json!("AB".repeat(32))), ("message", json!("é".repeat(2049))),
        ("replyEpub", json!("https://attacker.example")), ("sig", json!("")),
        ("channelId", json!(format!("{}\n", row["channelId"].as_str().unwrap()))),
        ("nonce", json!(format!("{}\n", row["nonce"].as_str().unwrap()))),
        ("sig", json!(format!("{}\n", row["sig"].as_str().unwrap())))] {
        let mut altered = row.clone(); altered[field] = value;
        assert!(parse_first_contact_request(&altered).is_err(), "{field}");
    }
    // serde_json rejects unpaired Unicode before a Value can enter the parser.
    assert!(serde_json::from_str::<Value>(r#""\ud800""#).is_err());
}

#[test]
fn retired_key_and_omitted_rotation_fail_closed() {
    let records: Value = serde_json::from_str(include_str!("../../../vectors/ids/records.json")).unwrap();
    let c = &records["context"];
    let jwks: Jwks = serde_json::from_value(c["jwks"].clone()).unwrap();
    let links = c["links"].as_array().unwrap().iter()
        .map(|pair| (pair[0].as_str().unwrap().to_owned(), pair[1].clone())).collect();
    let issuers = serde_json::from_value(c["pinnedIss"].clone()).unwrap();
    let policy = serde_json::from_value(c["policy"].clone()).unwrap();
    let v = fixture(); let d = descriptor(&v); let row = signed(v["request"].clone());
    let next = parse_principal_id(row["replyEpub"].as_str().unwrap()).unwrap();
    let history = |p: &PrincipalId, at, until| {
        let mut state = history_state(p, &[], at, until);
        state.current_key = next.clone();
        Ok(state)
    };
    let mut ctx = context(&jwks, &links, &policy, &issuers, &history);
    ctx.now = c["now"].as_u64().unwrap();
    assert_eq!(verify_first_contact_request(&row, &[], &ctx, &d), Err(Reason::MissingHistory));
    let rotation = records["accept"].as_array().unwrap().iter()
        .find(|r| r["name"] == "wallet-rotate").unwrap()["input"].clone();
    assert_eq!(verify_first_contact_request(&row, &[rotation], &ctx, &d), Err(Reason::UnwitnessedRetiredKey));
}
