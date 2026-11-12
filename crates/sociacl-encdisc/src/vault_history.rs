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
    pub(crate) fn binding(&self) -> (&str, &str, &str) { (&self.object, &self.owner, &self.item_id) }
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

const HISTORY_DOMAIN: &str = "sociacl-vault-history-v1";
/// Independently retained exact encrypted checkpoint. Never obtain it from the
/// untrusted file being opened; loss is not authorization to initialize anew.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultHistoryHead {
    pub owner: String, pub object: String, pub item_id: String,
    pub ledger_item_id: String, pub ledger_version_id: String, pub ciphertext_digest: String,
}
impl VaultVersionHistory {
    pub(crate) fn encode(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, EncDiscError> {
        let mut fields=vec![HISTORY_DOMAIN.to_owned(),self.object.clone(),self.owner.clone(),self.item_id.clone()];
        for (version,_) in self.versions.values() {
            fields.push(crate::hexutil::encode_hex(&vault_version_signing_bytes(version)?));
        }
        Ok(zeroize::Zeroizing::new(serde_json::to_vec(&fields).map_err(rejected)?))
    }
    pub(crate) fn decode(bytes:&[u8]) -> Result<Self, EncDiscError> {
        if bytes.len()>crate::VAULT_ITEM_MAX_BYTES { return Err(EncDiscError::VaultRejected); }
        let fields:Vec<String>=serde_json::from_slice(bytes).map_err(rejected)?;
        if fields.len()<5 || fields.len()>260 || fields[0]!=HISTORY_DOMAIN || fields[1].is_empty() {
            return Err(EncDiscError::VaultRejected);
        }
        parse_principal_id(&fields[2]).map_err(rejected)?;
        canonical::require_digest_hex(&fields[3])?;
        let mut versions=BTreeMap::new();let mut previous=String::new();
        for encoded in &fields[4..] {
            let raw=crate::hexutil::decode_hex(encoded)?;
            let f=canonical::decode_length_prefixed(&raw)?;
            if f.len()<11 || f[0]!=crate::VAULT_VERSION_DOMAIN || f[1]!="1" || f[4]!=fields[2] || f[2]!=fields[3] ||
                !matches!(f[8].as_str(),"0"|"1") { return Err(EncDiscError::VaultRejected); }
            let v=VaultVersion{item_id:f[2].clone(),version_id:f[3].clone(),owner:f[4].clone(),
                epoch:f[5].parse().map_err(rejected)?,revision_id:f[6].clone(),ciphertext_digest:f[7].clone(),
                sensitive:f[8]=="1",issued_at:f[9].parse().map_err(rejected)?,parents:f[11..].to_vec()};
            if f[10].parse::<usize>().map_err(rejected)?!=v.parents.len() || v.version_id<=previous ||
                vault_version_signing_bytes(&v)?!=raw { return Err(EncDiscError::VaultRejected); }
            previous=v.version_id.clone();versions.insert(v.version_id.clone(),(v,canonical::sha256_hex(&raw)));
        }
        let mut heads:BTreeSet<String>=versions.keys().cloned().collect();let mut roots=0;
        for (v,_) in versions.values() {
            if v.parents.is_empty(){roots+=1;}
            for parent in &v.parents {
                let (p,_)=versions.get(parent).ok_or(EncDiscError::VaultRejected)?;
                if p.issued_at>v.issued_at || p.epoch>v.epoch || (p.epoch==v.epoch && p.revision_id!=v.revision_id) {
                    return Err(EncDiscError::VaultRejected);
                }
                heads.remove(parent);
            }
        }
        // Every node must be reachable from the unique root; cycles never restore.
        let mut reached=BTreeSet::new();
        loop {
            let before=reached.len();
            for (id,(v,_)) in &versions {
                if v.parents.iter().all(|p|reached.contains(p)){reached.insert(id.clone());}
            }
            if reached.len()==before {break;}
        }
        if roots!=1 || reached.len()!=versions.len() || heads.is_empty(){return Err(EncDiscError::VaultRejected);}
        let history=Self{object:fields[1].clone(),owner:fields[2].clone(),item_id:fields[3].clone(),versions,heads};
        if history.encode()?.as_slice()!=bytes{return Err(EncDiscError::VaultRejected);}
        Ok(history)
    }
}
/// Prepare once, then write the returned envelope using LocalVaultFileStore CAS.
/// Retain/retry the exact bytes after ambiguous writes, and retain the returned
/// head independently only after durable publication. Metadata remains encrypted.
pub fn seal_vault_history(history:&VaultVersionHistory,ledger_item_id:Option<&str>,password:&str)
    ->Result<(crate::LocalVaultEnvelope,VaultHistoryHead),EncDiscError> {
    let owner=parse_principal_id(&history.owner).map_err(rejected)?;
    let plain=history.encode()?;
    let envelope=crate::seal_local_vault_item(&owner,ledger_item_id,HISTORY_DOMAIN.as_bytes(),&plain,password)?;
    let head=VaultHistoryHead{owner:history.owner.clone(),object:history.object.clone(),item_id:history.item_id.clone(),
        ledger_item_id:envelope.item_id(),ledger_version_id:envelope.version_id(),ciphertext_digest:canonical::sha256_hex(envelope.bytes())};
    Ok((envelope,head))
}
pub fn open_vault_history(envelope:&crate::LocalVaultEnvelope,expected:&VaultHistoryHead,password:&str)
    ->Result<VaultVersionHistory,EncDiscError> {
    if envelope.item_id()!=expected.ledger_item_id || envelope.version_id()!=expected.ledger_version_id ||
        canonical::sha256_hex(envelope.bytes())!=expected.ciphertext_digest {return Err(EncDiscError::VaultRejected);}
    let owner=parse_principal_id(&expected.owner).map_err(rejected)?;
    let opened=crate::open_local_vault_item(envelope,&owner,password)?;
    if opened.metadata()!=HISTORY_DOMAIN.as_bytes(){return Err(EncDiscError::VaultRejected);}
    let history=VaultVersionHistory::decode(opened.content())?;
    if history.owner!=expected.owner || history.object!=expected.object || history.item_id!=expected.item_id {
        return Err(EncDiscError::VaultRejected);
    }
    Ok(history)
}
