use serde::Deserialize;
use sociacl_encdisc::{
    account_binding_sha256, canonical_decimal, epoch_revision_id, inbox_entry_id, item_auth_sha256,
    length_prefixed, parse_canonical_decimal, sha256_fields, EpochManifestBody, InboxEntryBody,
    InboxWrapFields, ItemAuthFields, JS_SAFE_INTEGER_MAX,
};

const CANONICAL: &str = include_str!("../../../vectors/encrypted-discovery/canonical.json");

#[derive(Deserialize)]
struct Document {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    kind: String,
    sha256: String,
    encoded_len: usize,
    fields: Option<Vec<String>>,
    body: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InboxJson {
    lane_id: String,
    grant_ciphertext: String,
    commitment: CommitmentJson,
    wrap: Option<WrapJson>,
}

#[derive(Deserialize)]
struct CommitmentJson {
    hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapJson {
    scope: String,
    epoch: u64,
    target: String,
    target_id: String,
    object: Option<String>,
    group: Option<String>,
    revision_id: String,
    wrapped_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpochJson {
    object: String,
    epoch: u64,
    previous_epoch: u64,
    device_id: String,
    key_commitment: String,
    settle_window_ms: u64,
    acl_snapshot: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItemJson {
    object: String,
    epoch: u64,
    version: u64,
    plaintext_digest: String,
    revision_id: String,
}

#[derive(Deserialize)]
struct AccountJson {
    account: String,
    #[serde(rename = "pub")]
    sea_pub: String,
    epub: String,
}

#[test]
fn canonical_vectors_match_the_shared_fixture() {
    let document: Document = serde_json::from_str(CANONICAL).unwrap();
    assert!(document.cases.len() >= 19);
    let mut hashes = std::collections::BTreeMap::new();
    for case in &document.cases {
        let (hash, len) = match case.kind.as_str() {
            "fields" => {
                let fields = case.fields.as_ref().unwrap();
                let borrowed: Vec<&str> = fields.iter().map(String::as_str).collect();
                let bytes = length_prefixed(&borrowed).unwrap();
                (sha256_fields(&borrowed).unwrap(), bytes.len())
            }
            "inboxEntryId" => {
                let parsed: InboxJson = serde_json::from_value(case.body.clone().unwrap()).unwrap();
                let body = InboxEntryBody {
                    lane_id: parsed.lane_id,
                    grant_ciphertext: parsed.grant_ciphertext,
                    commitment_hash: parsed.commitment.hash,
                    wrap: parsed.wrap.map(|wrap| InboxWrapFields {
                        scope: wrap.scope,
                        epoch: wrap.epoch,
                        target: wrap.target,
                        target_id: wrap.target_id,
                        object: wrap.object,
                        group: wrap.group,
                        revision_id: wrap.revision_id,
                        wrapped_key: wrap.wrapped_key,
                    }),
                };
                let bytes = sociacl_encdisc::inbox_entry_bytes(&body).unwrap();
                (inbox_entry_id(&body).unwrap(), bytes.len())
            }
            "epochRevisionId" => {
                let parsed: EpochJson = serde_json::from_value(case.body.clone().unwrap()).unwrap();
                let body = EpochManifestBody {
                    object: parsed.object,
                    epoch: parsed.epoch,
                    previous_epoch: parsed.previous_epoch,
                    device_id: parsed.device_id,
                    key_commitment: parsed.key_commitment,
                    settle_window_ms: parsed.settle_window_ms,
                    acl_snapshot: parsed.acl_snapshot,
                    status_auth_pub: None,
                };
                let bytes = sociacl_encdisc::epoch_revision_bytes(&body).unwrap();
                (epoch_revision_id(&body).unwrap(), bytes.len())
            }
            "itemAuth" => {
                let parsed: ItemJson = serde_json::from_value(case.body.clone().unwrap()).unwrap();
                let fields = ItemAuthFields {
                    object: parsed.object,
                    epoch: parsed.epoch,
                    version: parsed.version,
                    plaintext_digest: parsed.plaintext_digest,
                    revision_id: parsed.revision_id,
                };
                let bytes = sociacl_encdisc::item_auth_bytes(&fields).unwrap();
                (item_auth_sha256(&fields).unwrap(), bytes.len())
            }
            "accountBinding" => {
                let parsed: AccountJson =
                    serde_json::from_value(case.body.clone().unwrap()).unwrap();
                let bytes = sociacl_encdisc::account_binding_bytes(
                    &parsed.account,
                    &parsed.sea_pub,
                    &parsed.epub,
                )
                .unwrap();
                (
                    account_binding_sha256(&parsed.account, &parsed.sea_pub, &parsed.epub).unwrap(),
                    bytes.len(),
                )
            }
            other => panic!("unknown vector kind {other}"),
        };
        assert_eq!(hash, case.sha256, "{}", case.name);
        assert_eq!(len, case.encoded_len, "{}", case.name);
        assert_eq!(hash.len(), 64, "{}", case.name);
        assert!(hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        let _ = hashes.insert(case.name.clone(), hash);
    }
    assert_ne!(hashes["fields-ab-c"], hashes["fields-a-bc"]);
    assert_ne!(
        hashes["fields-decimal-ten"],
        hashes["fields-decimal-leading-zero"]
    );
    assert_eq!(hashes["inbox-with-wrap"], hashes["inbox-group-empty"]);
    assert_ne!(hashes["inbox-with-wrap"], hashes["inbox-wrap-byte"]);
    assert_ne!(hashes["inbox-real-wrap"], hashes["inbox-with-wrap"]);
    assert_ne!(hashes["item-auth-hello"], hashes["item-auth-zero"]);
    assert_eq!(
        hashes["fields-empty"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn decimal_zero_has_no_leading_zero() {
    assert_eq!(canonical_decimal(0).unwrap(), "0");
    assert_eq!(canonical_decimal(10).unwrap(), "10");
    assert_eq!(
        canonical_decimal(JS_SAFE_INTEGER_MAX).unwrap(),
        "9007199254740991"
    );
    assert!(canonical_decimal(JS_SAFE_INTEGER_MAX + 1).is_err());
    assert_eq!(parse_canonical_decimal("0").unwrap(), 0);
    assert_eq!(
        parse_canonical_decimal("9007199254740991").unwrap(),
        JS_SAFE_INTEGER_MAX
    );
    assert!(parse_canonical_decimal("9007199254740992").is_err());
    assert!(parse_canonical_decimal("010").is_err());
    assert!(parse_canonical_decimal("").is_err());
    assert!(parse_canonical_decimal("-1").is_err());
    assert!(parse_canonical_decimal("+1").is_err());
}
