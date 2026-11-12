//! One confidential checkpoint for authenticated versions and audit continuity.
use crate::{canonical, EncDiscError, LocalVaultEnvelope, VaultAuditHistory, VaultHistoryHead, VaultVersionHistory};
use sociacl_ids::parse_principal_id;
const DOMAIN:&str="sociacl-vault-journal-v1";
fn reject<T>(_:T)->EncDiscError{EncDiscError::VaultRejected}
/// Protected independently of the candidate file. Restoring this alongside an
/// attacker-rolled-back ciphertext would not provide rollback protection.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct VaultJournalHead { pub checkpoint:VaultHistoryHead, pub audit_head:String }
#[derive(Clone)]
pub struct VaultJournal { versions:VaultVersionHistory, audit:VaultAuditHistory }
impl VaultJournal {
    /// Combine already admitted state, preserving its original owner/object binding.
    pub fn new(versions:VaultVersionHistory,audit:VaultAuditHistory)->Result<Self,EncDiscError>{
        VaultAuditHistory::decode(&audit.encode()?,&versions)?;
        Ok(Self{versions,audit})
    }
    pub fn versions(&self)->&VaultVersionHistory{&self.versions}
    pub fn audit(&self)->&VaultAuditHistory{&self.audit}
}
/// Prepare once; publish using LocalVaultFileStore CAS and retry these exact bytes
/// after ambiguous results. Version and audit state cannot be torn across files.
/// This does not yet persist verifier nonces or provide the protected head store.
pub fn seal_vault_journal(journal:&VaultJournal,ledger_item_id:Option<&str>,password:&str)
    ->Result<(LocalVaultEnvelope,VaultJournalHead),EncDiscError>{
    let versions=journal.versions.encode()?;let audit=journal.audit.encode()?;
    let plain=zeroize::Zeroizing::new(serde_json::to_vec(&[DOMAIN,std::str::from_utf8(&versions).map_err(reject)?,
        std::str::from_utf8(&audit).map_err(reject)?]).map_err(reject)?);
    let (object,owner,item)=journal.versions.binding();
    let principal=parse_principal_id(owner).map_err(reject)?;
    let envelope=crate::seal_local_vault_item(&principal,ledger_item_id,DOMAIN.as_bytes(),&plain,password)?;
    let head=VaultJournalHead{checkpoint:VaultHistoryHead{object:object.into(),owner:owner.into(),item_id:item.into(),
        ledger_item_id:envelope.item_id(),ledger_version_id:envelope.version_id(),ciphertext_digest:canonical::sha256_hex(envelope.bytes())},
        audit_head:journal.audit.head().into()};
    Ok((envelope,head))
}
pub fn open_vault_journal(envelope:&LocalVaultEnvelope,expected:&VaultJournalHead,password:&str)->Result<VaultJournal,EncDiscError>{
    let h=&expected.checkpoint;
    if envelope.item_id()!=h.ledger_item_id||envelope.version_id()!=h.ledger_version_id||canonical::sha256_hex(envelope.bytes())!=h.ciphertext_digest{
        return Err(EncDiscError::VaultRejected);
    }
    let owner=parse_principal_id(&h.owner).map_err(reject)?;
    let opened=crate::open_local_vault_item(envelope,&owner,password)?;
    if opened.metadata()!=DOMAIN.as_bytes(){return Err(EncDiscError::VaultRejected);}
    let fields=zeroize::Zeroizing::new(serde_json::from_slice::<Vec<String>>(opened.content()).map_err(reject)?);
    if fields.len()!=3||fields[0]!=DOMAIN{return Err(EncDiscError::VaultRejected);}
    if serde_json::to_vec(&*fields).map_err(reject)?.as_slice()!=opened.content(){return Err(EncDiscError::VaultRejected);}
    let versions=VaultVersionHistory::decode(fields[1].as_bytes())?;
    if versions.binding()!=(h.object.as_str(),h.owner.as_str(),h.item_id.as_str()){return Err(EncDiscError::VaultRejected);}
    let audit=VaultAuditHistory::decode(fields[2].as_bytes(),&versions)?;
    if audit.head()!=expected.audit_head{return Err(EncDiscError::VaultRejected);}
    Ok(VaultJournal{versions,audit})
}
