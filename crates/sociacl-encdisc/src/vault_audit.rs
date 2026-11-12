//! Signed audit admission against retained version history. Audit never grants.
use std::collections::BTreeMap;
use serde_json::Value;
use sociacl_ids::{parse_principal_id, verify_signed_at, ResolutionContext};
use crate::{canonical, vault_audit_signing_bytes, EncDiscError, VaultAudit, VaultVersionHistory};

#[derive(Clone)]
pub struct SignedVaultAudit { pub event: VaultAudit, pub signature: String }
/// Immutable candidate state. Commit with the verifier nonce and item expectation
/// in one confidential durable CAS before releasing plaintext. This type does not
/// supply that backing store or prove that all events have been logged.
#[derive(Clone)]
pub struct VaultAuditHistory {
    item_id: String,
    head: String,
    events: BTreeMap<String, (VaultAudit, String)>,
}
fn reject<T>(_:T)->EncDiscError { EncDiscError::VaultRejected }
fn authenticate(signed:&SignedVaultAudit,versions:&VaultVersionHistory,expected_actor:&str,
    rotations:&[Value],ctx:&ResolutionContext<'_>)->Result<String,EncDiscError> {
    let e=&signed.event;
    let version=versions.version(&e.version_id).ok_or(EncDiscError::VaultRejected)?;
    if e.actor!=expected_actor || e.item_id!=version.item_id || e.issued_at<version.issued_at {
        return Err(EncDiscError::VaultRejected);
    }
    let bytes=vault_audit_signing_bytes(e)?;
    let actor=parse_principal_id(expected_actor).map_err(reject)?;
    let proof=verify_signed_at(&actor,rotations,ctx,&bytes,&signed.signature,e.issued_at).map_err(reject)?;
    let history=(ctx.history)(&actor,e.issued_at,ctx.now).map_err(reject)?;
    if history.key!=proof.key || history.current_key!=proof.key { return Err(EncDiscError::VaultRejected); }
    Ok(canonical::sha256_hex(&bytes))
}
impl VaultAuditHistory {
    /// Bootstrap requires an independently authenticated exact transcript digest.
    /// The zero predecessor denotes only this explicit genesis, never state loss.
    /// expected_actor is selected by the caller's authorization, not by the event.
    pub fn initialize(signed:&SignedVaultAudit,versions:&VaultVersionHistory,expected_actor:&str,
        anchor:&str,rotations:&[Value],ctx:&ResolutionContext<'_>)->Result<Self,EncDiscError> {
        let digest=authenticate(signed,versions,expected_actor,rotations,ctx)?;
        if digest!=anchor || signed.event.previous_digest!="00".repeat(32) { return Err(EncDiscError::VaultRejected); }
        Ok(Self{item_id:signed.event.item_id.clone(),head:digest.clone(),
            events:BTreeMap::from([(signed.event.event_id.clone(),(signed.event.clone(),digest))])})
    }
    pub fn head(&self)->&str { &self.head }
    pub fn event(&self,id:&str)->Option<&VaultAudit> { self.events.get(id).map(|(e,_)|e) }
    /// Exact transcript retry is idempotent; forks, ID reuse and omitted ancestors
    /// fail. All IDs are retained; capacity fails instead of forgetting replay state.
    pub fn advance(&self,signed:&SignedVaultAudit,versions:&VaultVersionHistory,expected_actor:&str,
        rotations:&[Value],ctx:&ResolutionContext<'_>)->Result<Self,EncDiscError> {
        let digest=authenticate(signed,versions,expected_actor,rotations,ctx)?;
        let e=&signed.event;
        if e.item_id!=self.item_id { return Err(EncDiscError::VaultRejected); }
        if let Some((_,known))=self.events.get(&e.event_id) {
            return if known==&digest {Ok(self.clone())}else{Err(EncDiscError::VaultRejected)};
        }
        if self.events.len()>=256 || e.previous_digest!=self.head ||
            self.events.values().any(|(old,_)|old.issued_at>e.issued_at) { return Err(EncDiscError::VaultRejected); }
        let mut next=self.clone();next.head=digest.clone();
        next.events.insert(e.event_id.clone(),(e.clone(),digest));Ok(next)
    }
    /// Bind a freshly signed read decision to this item's current unambiguous
    /// version and the independently authenticated accessor/device. "allowed"
    /// records authorization, not proof plaintext reached the caller after commit.
    pub fn record_read(&self,signed:&SignedVaultAudit,versions:&VaultVersionHistory,accessor:&str,
        device:&str,decision:&crate::PresentedGrantDecision,at:u64,rotations:&[Value],
        ctx:&ResolutionContext<'_>)->Result<Self,EncDiscError> {
        let expected=versions.read_expectation()?;
        let e=&signed.event;
        if e.operation!="read" || e.outcome!=if decision.result.allowed {"allowed"}else{"denied"} ||
            e.version_id!=expected.version_id || e.device_id!=device || e.issued_at!=at ||
            e.previous_digest!=self.head || self.events.contains_key(&e.event_id) {
            return Err(EncDiscError::VaultRejected);
        }
        self.advance(signed,versions,accessor,rotations,ctx)
    }
}
