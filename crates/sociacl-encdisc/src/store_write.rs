//! Authorization for a recovery-copy or wrap-store write.
//!
//! Every put, commit, and delete carries a signature by the account's
//! current chain-head key, over [`DOMAIN_STORE_WRITE`], the `PrincipalId`,
//! the operation, the target sequence or wrap id, and the envelope hash.
//! The store verifies that signature against the resolved published chain.
//! Session authentication is not this check. Adapters, Panopticon included,
//! must verify before they write. Panopticon is a verifier and a witness.
//! It is never the authority.

use sociacl_ids::PrincipalId;

use crate::canonical;
use crate::error::EncDiscError;
use crate::sea;

/// Domain for an authenticated store write. Not a wrap or recovery seal domain.
pub const DOMAIN_STORE_WRITE: &str = "sociacl-store-write-v1";

pub fn store_write_message(
    principal: &str,
    operation: &str,
    target: &str,
    envelope_hash_hex: &str,
) -> Result<Vec<u8>, EncDiscError> {
    canonical::length_prefixed(&[
        DOMAIN_STORE_WRITE,
        principal,
        operation,
        target,
        envelope_hash_hex,
    ])
}

pub fn sign_store_write(
    sea_priv: &str,
    principal: &PrincipalId,
    operation: &str,
    target: &str,
    envelope_hash_hex: &str,
) -> Result<String, EncDiscError> {
    let message = store_write_message(principal.as_ref(), operation, target, envelope_hash_hex)?;
    sea::sign_sea(sea_priv, &message)
}

/// Verify `signature` under the resolved chain-head key.
///
/// A chain that does not resolve, or a signature that does not verify, is
/// [`EncDiscError::StoreRejected`]. The store must not mutate on that error.
pub fn verify_store_write(
    principal: &PrincipalId,
    operation: &str,
    target: &str,
    envelope_hash_hex: &str,
    signature: &str,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<sociacl_ids::ResolvedAccount, EncDiscError> {
    let resolved = sociacl_ids::resolve_current_key(principal, rotations, context);
    let account = resolved.result.map_err(|_| EncDiscError::StoreRejected)?;
    let message = store_write_message(principal.as_ref(), operation, target, envelope_hash_hex)?;
    sea::verify_sea(account.current_key.as_ref(), &message, signature)
        .map_err(|_| EncDiscError::StoreRejected)?;
    Ok(account)
}

/// SHA-256 of the wrap ciphertext bytes. The hex alphabet of the stored
/// string is not the hashed message.
pub fn wrap_ciphertext_hash(ciphertext_hex: &str) -> Result<String, EncDiscError> {
    let bytes =
        crate::hexutil::decode_hex(ciphertext_hex).map_err(|_| EncDiscError::StoreRejected)?;
    Ok(canonical::sha256_hex(&bytes))
}
