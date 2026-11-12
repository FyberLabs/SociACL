//! Phase-one vault signing transcripts. No encryption, persistence or read authority.
use crate::{canonical, EncDiscError};
use sociacl_ids::parse_principal_id;

pub const VAULT_VERSION_DOMAIN: &str = "sociacl-vault-version-v1";
pub const VAULT_AUDIT_DOMAIN: &str = "sociacl-vault-audit-v1";
pub const VAULT_MAX_PARENTS: usize = 16;

#[derive(Clone, Debug)]
pub struct VaultVersion {
    pub item_id: String,
    pub version_id: String,
    pub owner: String,
    pub parents: Vec<String>,
    pub epoch: u64,
    pub revision_id: String,
    pub ciphertext_digest: String,
    pub sensitive: bool,
    pub issued_at: u64,
}
#[derive(Clone, Debug)]
pub struct VaultAudit {
    pub event_id: String,
    pub item_id: String,
    pub version_id: String,
    pub actor: String,
    pub device_id: String,
    pub operation: String,
    pub outcome: String,
    pub issued_at: u64,
    pub previous_digest: String,
}
fn opaque(s: &str) -> Result<(), EncDiscError> { canonical::require_digest_hex(s) }
fn principal(s: &str) -> Result<(), EncDiscError> {
    parse_principal_id(s).map(|_| ()).map_err(|r| EncDiscError::IdentityRejected(r.to_string()))
}
/// Parents are sorted unique version IDs, never a timestamp-based winner selection.
/// The signature and this complete manifest must be encrypted before untrusted sync.
pub fn vault_version_signing_bytes(v: &VaultVersion) -> Result<Vec<u8>, EncDiscError> {
    for id in [&v.item_id, &v.version_id, &v.revision_id, &v.ciphertext_digest] { opaque(id)?; }
    principal(&v.owner)?;
    if v.parents.len() > VAULT_MAX_PARENTS { return Err(EncDiscError::BadEncoding); }
    for (i, parent) in v.parents.iter().enumerate() {
        opaque(parent)?;
        if parent == &v.version_id || (i > 0 && v.parents[i - 1] >= *parent) { return Err(EncDiscError::BadEncoding); }
    }
    let epoch = canonical::canonical_decimal(v.epoch)?;
    let issued = canonical::canonical_decimal(v.issued_at)?;
    let count = v.parents.len().to_string();
    let mut fields = vec![VAULT_VERSION_DOMAIN, "1", &v.item_id, &v.version_id, &v.owner,
        &epoch, &v.revision_id, &v.ciphertext_digest, if v.sensitive { "1" } else { "0" }, &issued, &count];
    fields.extend(v.parents.iter().map(String::as_str));
    canonical::length_prefixed(&fields)
}
/// Audit transcripts are signed and encrypted; the predecessor is not proof that
/// every event was logged or that the server supplied the newest head.
pub fn vault_audit_signing_bytes(v: &VaultAudit) -> Result<Vec<u8>, EncDiscError> {
    for id in [&v.event_id, &v.item_id, &v.version_id, &v.device_id, &v.previous_digest] { opaque(id)?; }
    principal(&v.actor)?;
    if !["put", "share", "revoke", "read", "use", "enroll", "recover"].contains(&v.operation.as_str()) ||
        !["allowed", "denied", "failed"].contains(&v.outcome.as_str()) { return Err(EncDiscError::BadEncoding); }
    canonical::length_prefixed(&[VAULT_AUDIT_DOMAIN, "1", &v.event_id, &v.item_id, &v.version_id,
        &v.actor, &v.device_id, &v.operation, &v.outcome, &canonical::canonical_decimal(v.issued_at)?, &v.previous_digest])
}
