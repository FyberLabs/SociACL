use serde_json::{json, Value};
use sociacl_encdisc::*;
use sociacl_ids::{history_state, parse_principal_id, sign_with_keyring, Jwks, PrincipalId, Reason, ResolutionContext, SiwePolicy};

fn vector() -> Value {
    serde_json::from_str(include_str!("../../../vectors/vault/sync-head.json")).unwrap()
}

#[test]
fn shared_sync_head_transcript_and_parser_boundaries() {
    let v = vector();
    let head = parse_vault_sync_head(&v["head"]).unwrap();
    let bytes = vault_sync_head_signing_bytes(&head).unwrap();
    assert_eq!(serde_json::to_value(decode_length_prefixed(&bytes).unwrap()).unwrap(), v["fields"]);
    assert_eq!(vault_sync_head_floor(&head).unwrap().digest, sha256_hex(&bytes));
    for patch in v["invalidPatches"].as_array().unwrap() {
        let mut invalid = v["head"].clone();
        invalid.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
        assert!(parse_vault_sync_head(&invalid).is_err(), "accepted {patch}");
    }
    let mut missing = v["head"].clone();
    missing.as_object_mut().unwrap().remove("sig");
    assert!(parse_vault_sync_head(&missing).is_err());
    let mut too_large = head.clone();
    too_large.issued_at = u64::MAX;
    assert!(vault_sync_head_signing_bytes(&too_large).is_err());
    let mut changed_signature = head.clone();
    changed_signature.sig = "B".repeat(86);
    assert_eq!(vault_sync_head_floor(&head).unwrap(), vault_sync_head_floor(&changed_signature).unwrap());
}

#[test]
fn authenticated_head_requires_current_history_and_expected_namespace() {
    let mut head = parse_vault_sync_head(&vector()["head"]).unwrap();
    let owner = parse_principal_id(&head.owner).unwrap();
    let mut scalar = [0u8; 32]; scalar[31] = 1;
    head.sig = sign_with_keyring(&scalar, &vault_sync_head_signing_bytes(&head).unwrap(), &owner).unwrap();
    let jwks = Jwks { keys: vec![] };
    let links = Default::default();
    let issuers = Default::default();
    let policy = SiwePolicy { allowed_domains: vec![], allowed_uris: vec![], allowed_chain_ids: vec![], clock_skew_seconds: 0 };
    let history = |p: &PrincipalId, at, until| Ok(history_state(p, &[], at, until));
    let mut ctx = ResolutionContext { jwks: &jwks, links: &links, revocations: &[], now: 20, policy: &policy,
        pinned_iss: &issuers, history: &history, genesis_epub_bindings: &[] };
    assert!(verify_vault_sync_head(&head, &head.owner, &head.vault_id, &[], &ctx).is_ok());
    assert!(verify_vault_sync_head(&head, &head.owner, &"56".repeat(32), &[], &ctx).is_err());
    assert!(verify_vault_sync_head(&head, "wrong-owner", &head.vault_id, &[], &ctx).is_err());
    for patch in [json!({"indexDigest":"45".repeat(32)}), json!({"keybagDigest":"45".repeat(32)}),
        json!({"minimumProfile":2}), json!({"sig":"A".repeat(86)})] {
        let mut value = vector()["head"].clone();
        value["sig"] = json!(head.sig);
        value.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
        let forged = parse_vault_sync_head(&value).unwrap();
        assert!(verify_vault_sync_head(&forged, &head.owner, &head.vault_id, &[], &ctx).is_err());
    }
    ctx.now = 9;
    assert!(verify_vault_sync_head(&head, &head.owner, &head.vault_id, &[], &ctx).is_err());
    ctx.now = 20;
    let other = parse_principal_id("fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg.B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E").unwrap();
    let retired = |p: &PrincipalId, at, until| {
        let mut state = history_state(p, &[], at, until);
        state.current_key = other.clone();
        Ok(state)
    };
    ctx.history = &retired;
    assert!(verify_vault_sync_head(&head, &head.owner, &head.vault_id, &[], &ctx).is_err());
    let missing = |_: &PrincipalId, _, _| Err(Reason::MissingHistory);
    ctx.history = &missing;
    assert!(verify_vault_sync_head(&head, &head.owner, &head.vault_id, &[], &ctx).is_err());
}

#[test]
fn successor_refuses_forks_skips_downgrades_and_time_reversal() {
    let mut previous = parse_vault_sync_head(&vector()["head"]).unwrap();
    previous.minimum_profile = 2;
    let mut next = previous.clone();
    next.revision = 2;
    next.previous_digest = vault_sync_head_floor(&previous).unwrap().digest;
    next.issued_at += 1;
    assert!(validate_vault_sync_successor(&previous, &next).is_ok());
    let mut invalid = next.clone(); invalid.revision = 3;
    assert!(validate_vault_sync_successor(&previous, &invalid).is_err());
    invalid = next.clone(); invalid.previous_digest = "56".repeat(32);
    assert!(validate_vault_sync_successor(&previous, &invalid).is_err());
    invalid = next.clone(); invalid.minimum_profile = 1;
    assert!(validate_vault_sync_successor(&previous, &invalid).is_err());
    invalid = next.clone(); invalid.issued_at = 9;
    assert!(validate_vault_sync_successor(&previous, &invalid).is_err());
    invalid = next; invalid.vault_id = "56".repeat(32);
    assert!(validate_vault_sync_successor(&previous, &invalid).is_err());
}
