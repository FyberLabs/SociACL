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
    object: String,
    owner: String,
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
        let (object,owner,_)=versions.binding();
        Ok(Self{object:object.into(),owner:owner.into(),item_id:signed.event.item_id.clone(),head:digest.clone(),
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
        if versions.binding()!=(self.object.as_str(),self.owner.as_str(),self.item_id.as_str()) || e.item_id!=self.item_id { return Err(EncDiscError::VaultRejected); }
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

const AUDIT_HISTORY_DOMAIN:&str="sociacl-vault-audit-history-v1";
impl VaultAuditHistory {
    pub(crate) fn encode(&self)->Result<zeroize::Zeroizing<Vec<u8>>,EncDiscError> {
        let mut fields=zeroize::Zeroizing::new(vec![AUDIT_HISTORY_DOMAIN.to_owned(),self.object.clone(),self.owner.clone(),self.item_id.clone(),self.head.clone()]);
        for (event,_) in self.events.values(){fields.push(crate::hexutil::encode_hex(&vault_audit_signing_bytes(event)?));}
        Ok(zeroize::Zeroizing::new(serde_json::to_vec(&*fields).map_err(reject)?))
    }
    /// Restore only inside an independently anchored authenticated ciphertext.
    /// This validates structure and binding, not a new network signature assertion.
    pub(crate) fn decode(bytes:&[u8],versions:&VaultVersionHistory)->Result<Self,EncDiscError> {
        if bytes.len()>crate::VAULT_ITEM_MAX_BYTES{return Err(EncDiscError::VaultRejected);}
        let fields=zeroize::Zeroizing::new(serde_json::from_slice::<Vec<String>>(bytes).map_err(reject)?);
        if fields.len()<6||fields.len()>261||fields[0]!=AUDIT_HISTORY_DOMAIN||
            versions.binding()!=(fields[1].as_str(),fields[2].as_str(),fields[3].as_str()) {return Err(EncDiscError::VaultRejected);}
        canonical::require_digest_hex(&fields[4])?;
        let mut events=BTreeMap::new();let mut successors=BTreeMap::new();let mut prior_id=String::new();
        for encoded in &fields[5..]{
            let raw=zeroize::Zeroizing::new(crate::hexutil::decode_hex(encoded)?);
            let f=zeroize::Zeroizing::new(canonical::decode_length_prefixed(&raw)?);
            if f.len()!=11||f[0]!=crate::VAULT_AUDIT_DOMAIN||f[1]!="1" {return Err(EncDiscError::VaultRejected);}
            let event=VaultAudit{event_id:f[2].clone(),item_id:f[3].clone(),version_id:f[4].clone(),actor:f[5].clone(),device_id:f[6].clone(),
                operation:f[7].clone(),outcome:f[8].clone(),issued_at:f[9].parse().map_err(reject)?,previous_digest:f[10].clone()};
            let version=versions.version(&event.version_id).ok_or(EncDiscError::VaultRejected)?;
            if event.event_id<=prior_id||event.item_id!=fields[3]||version.item_id!=event.item_id||event.issued_at<version.issued_at||
                vault_audit_signing_bytes(&event)?.as_slice()!=raw.as_slice() {return Err(EncDiscError::VaultRejected);}
            prior_id=event.event_id.clone();let digest=canonical::sha256_hex(&raw);
            if successors.insert(event.previous_digest.clone(),(digest.clone(),event.issued_at)).is_some(){return Err(EncDiscError::VaultRejected);}
            events.insert(event.event_id.clone(),(event,digest));
        }
        let mut cursor="00".repeat(32);let mut time=0;
        for _ in 0..events.len(){
            let (next,at)=successors.get(&cursor).ok_or(EncDiscError::VaultRejected)?;
            if *at<time{return Err(EncDiscError::VaultRejected);}time=*at;cursor=next.clone();
        }
        if cursor!=fields[4]||successors.contains_key(&cursor){return Err(EncDiscError::VaultRejected);}
        let result=Self{object:fields[1].clone(),owner:fields[2].clone(),item_id:fields[3].clone(),head:cursor,events};
        if result.encode()?.as_slice()!=bytes{return Err(EncDiscError::VaultRejected);}
        Ok(result)
    }
}
