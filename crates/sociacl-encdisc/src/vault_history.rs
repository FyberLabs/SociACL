//! Authenticated immutable version graph. Its retained state is trusted, not sync input.
use std::collections::{BTreeMap, BTreeSet};
use serde_json::Value;
use sociacl_ids::{parse_principal_id, verify_signed_at, ResolutionContext};
use crate::{canonical, vault_version_signing_bytes, EncDiscError, SignedVaultVersion,
    VaultReadExpectation, VaultVersion};

/// Bounded history never evicts old IDs and therefore never forgets equivocation.
/// Persist this state confidentially with a protected monotonic head before use.
/// This in-memory core is not a durable ledger or proof of remote freshness.
#[derive(Clone)]
pub struct VaultVersionHistory {
    object: String,
    owner: String,
    item_id: String,
    versions: BTreeMap<String, (VaultVersion, String)>,
    heads: BTreeSet<String>,
}
fn rejected<T>(_: T) -> EncDiscError { EncDiscError::VaultRejected }
fn authenticate(signed: &SignedVaultVersion, owner: &str, item: &str, epoch: u64,
    revision: &str, rotations: &[Value], ctx: &ResolutionContext<'_>) -> Result<String, EncDiscError> {
    let v = &signed.version;
    if v.owner != owner || v.item_id != item || v.epoch != epoch || v.revision_id != revision {
        return Err(EncDiscError::VaultRejected);
    }
    let bytes = vault_version_signing_bytes(v)?;
    let principal = parse_principal_id(owner).map_err(rejected)?;
    let proof = verify_signed_at(&principal, rotations, ctx, &bytes, &signed.signature, v.issued_at).map_err(rejected)?;
    let history = (ctx.history)(&principal, v.issued_at, ctx.now).map_err(rejected)?;
    if history.key != proof.key || history.current_key != proof.key { return Err(EncDiscError::VaultRejected); }
    Ok(canonical::sha256_hex(&bytes))
}
impl VaultVersionHistory {
    /// Explicit first bootstrap only. The exact signed transcript digest must be
    /// provisioned independently; missing/corrupt retained state is never bootstrap.
    pub fn initialize(signed: &SignedVaultVersion, expected: &VaultReadExpectation,
        transcript_digest: &str, rotations: &[Value], ctx: &ResolutionContext<'_>) -> Result<Self, EncDiscError> {
        let digest = authenticate(signed, &expected.owner, &expected.item_id, expected.epoch,
            &expected.revision_id, rotations, ctx)?;
        let v = &signed.version;
        if digest != transcript_digest || v.version_id != expected.version_id ||
            v.ciphertext_digest != expected.ciphertext_digest || !v.parents.is_empty() || expected.object.is_empty() {
            return Err(EncDiscError::VaultRejected);
        }
        Ok(Self { object: expected.object.clone(), owner: expected.owner.clone(), item_id: expected.item_id.clone(),
            versions: BTreeMap::from([(v.version_id.clone(), (v.clone(), digest))]),
            heads: BTreeSet::from([v.version_id.clone()]) })
    }
    /// Returns a candidate snapshot; commit it with CAS against the original state.
    /// Epoch/revision are independently authenticated current authorization inputs.
    /// Siblings retain both heads. Only an explicit signed descendant can join them.
    pub fn advance(&self, signed: &SignedVaultVersion, epoch: u64, revision: &str,
        rotations: &[Value], ctx: &ResolutionContext<'_>) -> Result<Self, EncDiscError> {
        let digest = authenticate(signed, &self.owner, &self.item_id, epoch, revision, rotations, ctx)?;
        let v = &signed.version;
        if let Some((_, known)) = self.versions.get(&v.version_id) {
            return if known == &digest { Ok(self.clone()) } else { Err(EncDiscError::VaultRejected) };
        }
        if self.versions.len() >= 256 || v.parents.is_empty() ||
            self.versions.values().any(|(old, _)| old.epoch > epoch || (old.epoch == epoch && old.revision_id != revision)) {
            return Err(EncDiscError::VaultRejected);
        }
        for parent in &v.parents {
            let (old, _) = self.versions.get(parent).ok_or(EncDiscError::VaultRejected)?;
            if old.issued_at > v.issued_at || (old.sensitive && old.epoch < epoch && old.ciphertext_digest == v.ciphertext_digest) {
                return Err(EncDiscError::VaultRejected);
            }
        }
        let mut next = self.clone();
        for parent in &v.parents { next.heads.remove(parent); }
        next.heads.insert(v.version_id.clone());
        next.versions.insert(v.version_id.clone(), (v.clone(), digest));
        Ok(next)
    }
    pub fn heads(&self) -> impl Iterator<Item = &str> { self.heads.iter().map(String::as_str) }
    pub fn version(&self, id: &str) -> Option<&VaultVersion> { self.versions.get(id).map(|(v, _)| v) }
    /// No timestamp winner: ambiguous history cannot silently select a read version.
    /// The caller must authenticate the item/object binding independently.
    pub fn read_expectation(&self) -> Result<VaultReadExpectation, EncDiscError> {
        if self.heads.len() != 1 { return Err(EncDiscError::VaultRejected); }
        let v = &self.versions[self.heads.first().ok_or(EncDiscError::VaultRejected)?].0;
        Ok(VaultReadExpectation { object: self.object.clone(), owner: self.owner.clone(), item_id: self.item_id.clone(),
            version_id: v.version_id.clone(), ciphertext_digest: v.ciphertext_digest.clone(),
            epoch: v.epoch, revision_id: v.revision_id.clone() })
    }
}
