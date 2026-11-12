use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{json, Value};
use sociacl_encdisc::{FirstContactSealDescriptor, seal_first_contact_request, open_first_contact_request};
use sociacl_ids::*;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn confidential_first_contact_and_cross_language() {
    let v: Value = serde_json::from_str(include_str!("../../../vectors/first-contact/v1.json")).unwrap();
    let mut row = v["request"].clone(); row["sig"] = json!("A".repeat(86));
    let r = parse_first_contact_request(&row).unwrap();
    let mut scalar = [0u8; 32]; scalar[31] = 1;
    row["sig"] = json!(sign_with_keyring(&scalar, &first_contact_request_bytes(&r).unwrap(), &r.sender).unwrap());
    scalar[31] = 2;
    let private = Base64UrlUnpadded::encode_string(&scalar);
    let d = &v["descriptor"];
    let descriptor = FirstContactSealDescriptor {
        policy: FirstContactDescriptor { channel_id: d["channelId"].as_str().unwrap().into(),
            revision: 1, expires_at: d["expiresAt"].as_u64().unwrap(),
            max_lifetime_seconds: 300, max_message_bytes: 1024 },
        encryption_epub: r.reply_epub.as_ref().into(),
    };
    let jwks = Jwks { keys: vec![] }; let links = BTreeMap::new(); let issuers = BTreeSet::new();
    let policy = SiwePolicy { allowed_domains: vec![], allowed_uris: vec![], allowed_chain_ids: vec![], clock_skew_seconds: 0 };
    let history = |p: &PrincipalId, at, until| Ok(history_state(p, &[], at, until));
    let mut ctx = ResolutionContext { jwks: &jwks, links: &links, revocations: &[], now: 1700000020,
        policy: &policy, pinned_iss: &issuers, history: &history, genesis_epub_bindings: &[] };
    let blob = seal_first_contact_request(&row, &descriptor).unwrap();
    assert_ne!(blob, seal_first_contact_request(&row, &descriptor).unwrap());
    let expected = verify_first_contact_request(&row, &[], &ctx, &descriptor.policy).unwrap();
    assert_eq!(open_first_contact_request(&blob, &private, &descriptor, &[], &ctx).unwrap(), expected);
    for offset in [0, 1, 20, 66, 78, blob.len() - 1] {
        let mut changed = blob.clone(); changed[offset] ^= 1;
        assert!(open_first_contact_request(&changed, &private, &descriptor, &[], &ctx).is_err());
    }
    for changed in [&blob[..blob.len() - 1], &[0u8; 93], &[0u8; 8193]] {
        assert!(open_first_contact_request(changed, &private, &descriptor, &[], &ctx).is_err());
    }
    let mut other = descriptor.clone(); other.policy.revision = 2;
    assert!(open_first_contact_request(&blob, &private, &other, &[], &ctx).is_err());
    other = descriptor.clone(); other.policy.channel_id = "ab".repeat(32);
    assert!(open_first_contact_request(&blob, &private, &other, &[], &ctx).is_err());
    scalar[31] = 3;
    assert!(open_first_contact_request(&blob, &Base64UrlUnpadded::encode_string(&scalar), &descriptor, &[], &ctx).is_err());
    let mut bom = row.clone(); bom["message"] = json!("\u{feff}hello");
    let bom_request = parse_first_contact_request(&bom).unwrap();
    scalar[31] = 1;
    bom["sig"] = json!(sign_with_keyring(&scalar, &first_contact_request_bytes(&bom_request).unwrap(), &r.sender).unwrap());
    assert_eq!(open_first_contact_request(&seal_first_contact_request(&bom, &descriptor).unwrap(),
        &private, &descriptor, &[], &ctx).unwrap().request.message, "\u{feff}hello");
    let mut forged = row.clone(); forged["message"] = json!("forged");
    assert!(open_first_contact_request(&seal_first_contact_request(&forged, &descriptor).unwrap(),
        &private, &descriptor, &[], &ctx).is_err());
    ctx.now = r.expires_at;
    assert_eq!(open_first_contact_request(&blob, &private, &descriptor, &[], &ctx), Err(Reason::Expired));
    ctx.now = 1700000020;
    // CI exchanges actual randomized ciphertext in both directions, never locally.
    if let Ok(path) = std::env::var("FIRST_CONTACT_RUST_VECTOR") {
        std::fs::write(path, &blob).unwrap();
    }
    if let Ok(path) = std::env::var("FIRST_CONTACT_TS_VECTOR") {
        let input = std::fs::read(path).unwrap();
        let opened = open_first_contact_request(&input, &private, &descriptor, &[], &ctx).unwrap();
        assert_eq!(opened.request_id, expected.request_id);
        assert_eq!(opened.replay_key, expected.replay_key);
        assert_eq!(opened.replay_until, expected.replay_until);
        assert_eq!(opened.request.message, expected.request.message);
    }
}
