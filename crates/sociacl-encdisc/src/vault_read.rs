//! Compose signed version admission, destination Check and local custody unlock.
use crate::{canonical, check_presented_grant, open_local_vault_item, vault_version_signing_bytes,
    EncDiscError, LocalVaultEnvelope, OpenedLocalVaultItem, PresentedGrantDecision,
    PresentedGrantInput, SeeGraph, VaultVersion};
use serde_json::Value;
use sociacl_ids::{parse_principal_id, verify_signed_at, ResolutionContext};

/// Independently authenticated item-to-object binding and current version floor.
/// Never derive this expectation from the candidate or its untrusted sync peer.
pub struct VaultReadExpectation {
    pub object: String, pub owner: String, pub item_id: String, pub version_id: String,
    pub ciphertext_digest: String, pub epoch: u64, pub revision_id: String,
}
pub struct SignedVaultVersion { pub version: VaultVersion, pub signature: String }
fn reject<T>(_: T) -> EncDiscError { EncDiscError::VaultRejected }

fn admit(signed: &SignedVaultVersion, expected: &VaultReadExpectation, envelope: &LocalVaultEnvelope,
    rotations: &[Value], identity: &ResolutionContext<'_>, input: &PresentedGrantInput,
    digest: &str, now_ms: u64) -> Result<(), EncDiscError> {
    let v=&signed.version;
    if expected.object.is_empty() || v.owner!=expected.owner || v.item_id!=expected.item_id ||
        v.version_id!=expected.version_id || v.epoch!=expected.epoch || v.revision_id!=expected.revision_id ||
        v.ciphertext_digest!=expected.ciphertext_digest || digest!=expected.ciphertext_digest ||
        envelope.item_id()!=v.item_id || envelope.version_id()!=v.version_id ||
        input.presentation.grant.object!=expected.object || input.presentation.owner!=expected.owner {
        return Err(EncDiscError::VaultRejected);
    }
    let status=input.status.as_ref().ok_or(EncDiscError::VaultRejected)?;
    if status.epoch!=v.epoch || status.revision_id!=v.revision_id { return Err(EncDiscError::VaultRejected); }
    let owner=parse_principal_id(&v.owner).map_err(reject)?;
    let ctx=ResolutionContext { now:now_ms/1000,jwks:identity.jwks,links:identity.links,
        revocations:identity.revocations,policy:identity.policy,pinned_iss:identity.pinned_iss,
        history:identity.history,genesis_epub_bindings:identity.genesis_epub_bindings };
    let proof=verify_signed_at(&owner,rotations,&ctx,&vault_version_signing_bytes(v)?,&signed.signature,v.issued_at).map_err(reject)?;
    let history=(ctx.history)(&owner,v.issued_at,ctx.now).map_err(reject)?;
    if history.key!=proof.key || history.current_key!=proof.key || proof.key.as_ref()!=input.presentation.sea_pub {
        return Err(EncDiscError::VaultRejected);
    }
    Ok(())
}

/// Headless/local consumer read. The signed manifest must remain confidential.
/// `now_ms` is the trusted Unix-millisecond clock; identity history uses seconds.
/// `commit` MUST durably CAS verifier nonce/revision state and the independent item
/// expectation against the state supplied in `input`, before returning success.
/// Commit failure or expiry across commit releases no plaintext. A successful
/// commit followed by expiry can consume a nonce without returning an item.
/// This does not implement sharing, sync, device enrollment or Visor use/sign policy.
pub fn read_authorized_local_vault(
    graph: &impl SeeGraph, envelope: &LocalVaultEnvelope, signed: &SignedVaultVersion,
    expected: &VaultReadExpectation, rotations: &[Value], identity: &ResolutionContext<'_>,
    mut input: PresentedGrantInput, password: &str, mut now_ms: impl FnMut()->u64,
    mut commit: impl FnMut(&PresentedGrantDecision)->Result<(),EncDiscError>,
) -> Result<OpenedLocalVaultItem,EncDiscError> {
    let digest=canonical::sha256_hex(envelope.bytes());
    let started=now_ms();input.now=started;input.fetched_item_digest=Some(digest.clone());
    admit(signed,expected,envelope,rotations,identity,&input,&digest,started)?;
    let initial=check_presented_grant(graph,input.clone());
    if !initial.result.allowed { commit(&initial)?;return Err(EncDiscError::VaultRejected); }
    let owner=parse_principal_id(&expected.owner).map_err(reject)?;
    let opened=open_local_vault_item(envelope,&owner,password)?;
    let authorized_at=now_ms();
    if authorized_at<started { return Err(EncDiscError::VaultRejected); }
    input.now=authorized_at;
    admit(signed,expected,envelope,rotations,identity,&input,&digest,authorized_at)?;
    let decision=check_presented_grant(graph,input.clone());
    commit(&decision)?;
    if !decision.result.allowed { return Err(EncDiscError::VaultRejected); }
    let completed=now_ms();
    if completed<authorized_at { return Err(EncDiscError::VaultRejected); }
    input.now=completed;
    admit(signed,expected,envelope,rotations,identity,&input,&digest,completed)?;
    if !check_presented_grant(graph,input).result.allowed { return Err(EncDiscError::VaultRejected); }
    Ok(opened)
}
