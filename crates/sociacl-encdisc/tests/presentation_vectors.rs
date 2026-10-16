//! Shared presentation vectors. The TypeScript contract loads the same file.

use sociacl_encdisc::{
    epoch_status_bytes, epoch_status_sha256, grant_commitment_bytes, grant_commitment_hash,
    grant_payload_bytes, grant_payload_digest, presenter_binding_bytes, presenter_binding_sha256,
    sha256_hex, AuthorFastUnwrap, EpochStatusBody, GrantPayloadBody,
};

const PRESENTATION: &str = include_str!("../../../vectors/encrypted-discovery/presentation.json");

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    unsalted_payload_sha256: String,
    grant: GrantJson,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantJson {
    object: String,
    accessor: String,
    from: u64,
    until: u64,
    stated: u64,
    epoch: u64,
    owner: String,
    grant_revision: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    kind: String,
    sha256: Option<String>,
    encoded_len: Option<usize>,
    blinding: Option<String>,
    item_ciphertext_digest: Option<String>,
    nonce: Option<String>,
    commitment: Option<String>,
    audience: Option<String>,
    concatenated_sha256: Option<String>,
    body: Option<StatusJson>,
    object: Option<String>,
    epoch: Option<u64>,
    revision_id: Option<String>,
    displaced_revision_id: Option<String>,
    dek: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusJson {
    object: String,
    epoch: u64,
    revision_id: String,
    accessor: String,
    grant_revision: u64,
    stated: u64,
    signed_at: u64,
    max_age_ms: u64,
    zookie: ZookieJson,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZookieJson {
    object: String,
    object_version: u64,
    snapshot_hash: String,
}

fn payload(grant: &GrantJson, item: &str) -> GrantPayloadBody {
    GrantPayloadBody {
        object: grant.object.clone(),
        accessor: grant.accessor.clone(),
        from: grant.from,
        until: grant.until,
        stated: grant.stated,
        epoch: grant.epoch,
        owner: grant.owner.clone(),
        grant_revision: grant.grant_revision,
        item_ciphertext_digest: item.to_string(),
    }
}

#[test]
fn presentation_vectors_match_the_shared_fixture() {
    let document: Document = serde_json::from_str(PRESENTATION).unwrap();
    assert!(document.cases.len() >= 7);
    let mut commitments = std::collections::BTreeMap::new();
    for case in &document.cases {
        match case.kind.as_str() {
            "grantCommitment" => {
                let body = payload(
                    &document.grant,
                    case.item_ciphertext_digest.as_deref().unwrap(),
                );
                let blinding = case.blinding.as_deref().unwrap();
                let bytes = grant_commitment_bytes(blinding, &body).unwrap();
                let hash = grant_commitment_hash(blinding, &body).unwrap();
                assert_eq!(hash, case.sha256.as_deref().unwrap(), "{}", case.name);
                assert_eq!(bytes.len(), case.encoded_len.unwrap(), "{}", case.name);
                commitments.insert(case.name.clone(), hash);
            }
            "grantPayload" => {
                let body = payload(
                    &document.grant,
                    case.item_ciphertext_digest.as_deref().unwrap(),
                );
                let bytes = grant_payload_bytes(&body).unwrap();
                let hash = grant_payload_digest(&body).unwrap();
                assert_eq!(hash, case.sha256.as_deref().unwrap(), "{}", case.name);
                assert_eq!(bytes.len(), case.encoded_len.unwrap(), "{}", case.name);
                assert_eq!(hash, document.unsalted_payload_sha256);
            }
            "presenterBinding" => {
                let nonce = case.nonce.as_deref().unwrap();
                let commitment = case.commitment.as_deref().unwrap();
                let audience = case.audience.as_deref().unwrap();
                let bytes = presenter_binding_bytes(nonce, commitment, audience).unwrap();
                let hash = presenter_binding_sha256(nonce, commitment, audience).unwrap();
                assert_eq!(hash, case.sha256.as_deref().unwrap(), "{}", case.name);
                assert_eq!(bytes.len(), case.encoded_len.unwrap(), "{}", case.name);
                let concatenated =
                    format!("s3rch-presenter-binding-v1{nonce}{commitment}{audience}");
                assert_eq!(
                    sha256_hex(concatenated.as_bytes()),
                    case.concatenated_sha256.as_deref().unwrap()
                );
                assert_ne!(hash, case.concatenated_sha256.as_deref().unwrap());
            }
            "epochStatus" => {
                let body = case.body.as_ref().unwrap();
                let status = EpochStatusBody {
                    object: body.object.clone(),
                    epoch: body.epoch,
                    revision_id: body.revision_id.clone(),
                    accessor: body.accessor.clone(),
                    grant_revision: body.grant_revision,
                    stated: body.stated,
                    signed_at: body.signed_at,
                    max_age_ms: body.max_age_ms,
                    zookie_object: body.zookie.object.clone(),
                    zookie_version: body.zookie.object_version,
                    zookie_snapshot: body.zookie.snapshot_hash.clone(),
                };
                let bytes = epoch_status_bytes(&status).unwrap();
                let hash = epoch_status_sha256(&status).unwrap();
                assert_eq!(hash, case.sha256.as_deref().unwrap(), "{}", case.name);
                assert_eq!(bytes.len(), case.encoded_len.unwrap(), "{}", case.name);
            }
            "authorFast" => {
                let local = AuthorFastUnwrap::store(
                    case.object.as_deref().unwrap(),
                    case.epoch.unwrap(),
                    case.revision_id.as_deref().unwrap(),
                    case.dek.as_deref().unwrap(),
                )
                .unwrap();
                assert_eq!(
                    local
                        .open(
                            case.object.as_deref().unwrap(),
                            case.revision_id.as_deref().unwrap()
                        )
                        .unwrap(),
                    case.dek.as_deref().unwrap()
                );
                assert!(local
                    .open(
                        case.object.as_deref().unwrap(),
                        case.displaced_revision_id.as_deref().unwrap()
                    )
                    .is_err());
                assert_eq!(local.epoch(), case.epoch.unwrap());
                assert!(!local.grants_see());
            }
            other => panic!("unknown vector kind {other}"),
        }
    }
    assert_ne!(
        commitments.get("commitment-blind-a"),
        commitments.get("commitment-blind-b")
    );
    assert_ne!(
        commitments.get("commitment-blind-a").map(String::as_str),
        Some(document.unsalted_payload_sha256.as_str())
    );
}
