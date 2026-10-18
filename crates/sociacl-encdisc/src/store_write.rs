//! Authorization for a recovery-copy or wrap-store write.
//!
//! Every put, commit, and delete is a signed compare-and-swap by the
//! account's current chain-head key. The message is [`DOMAIN_STORE_WRITE`],
//! the `PrincipalId`, the operation, the target sequence or wrap id, the
//! envelope hash, the published head sequence, the hash of the row being
//! replaced or [`REPLACED_NONE`], the wrap class or [`STORE_CLASS_NONE`],
//! and the per-principal write generation.
//!
//! The store does not take that chain from the writer. It asks a
//! [`PublishedChain`], which an adapter fills from the published source.
//! Panopticon reads the Gun chain. It verifies and witnesses. It is never
//! the authority. Session authentication is not this check.
//!
//! A write whose resolved head is below the store's monotonic per-principal
//! floor is [`EncDiscError::StoreRejected`] and changes nothing. The floor
//! is the maximum of every accepted head and every stored recovery sequence.

use sociacl_ids::PrincipalId;

use crate::canonical;
use crate::error::EncDiscError;
use crate::sea;

/// Domain for an authenticated store write. Not a wrap or recovery seal domain.
pub const DOMAIN_STORE_WRITE: &str = "sociacl-store-write-v1";

/// Predecessor field when the row being replaced is absent.
pub const REPLACED_NONE: &str = "none";

/// Class field for a recovery-store write. Wrap writes use `genesis` or `delivery`.
pub const STORE_CLASS_NONE: &str = "none";

pub const STORE_CLASS_GENESIS: &str = "genesis";

pub const STORE_CLASS_DELIVERY: &str = "delivery";

/// The published account a store reads for itself. The writer does not supply it.
pub trait PublishedChain {
    fn published_account(
        &self,
        principal: &PrincipalId,
    ) -> Result<sociacl_ids::ResolvedAccount, EncDiscError>;
}

impl<F> PublishedChain for F
where
    F: Fn(&PrincipalId) -> Result<sociacl_ids::ResolvedAccount, EncDiscError>,
{
    fn published_account(
        &self,
        principal: &PrincipalId,
    ) -> Result<sociacl_ids::ResolvedAccount, EncDiscError> {
        self(principal)
    }
}

pub fn store_write_message(
    principal: &str,
    operation: &str,
    target: &str,
    envelope_hash_hex: &str,
    head: &str,
    replaced: &str,
    class: &str,
    generation: &str,
) -> Result<Vec<u8>, EncDiscError> {
    canonical::length_prefixed(&[
        DOMAIN_STORE_WRITE,
        principal,
        operation,
        target,
        envelope_hash_hex,
        head,
        replaced,
        class,
        generation,
    ])
}

#[allow(clippy::too_many_arguments)]
pub fn sign_store_write(
    sea_priv: &str,
    principal: &PrincipalId,
    operation: &str,
    target: &str,
    envelope_hash_hex: &str,
    head: &str,
    replaced: &str,
    class: &str,
    generation: &str,
) -> Result<String, EncDiscError> {
    let message = store_write_message(
        principal.as_ref(),
        operation,
        target,
        envelope_hash_hex,
        head,
        replaced,
        class,
        generation,
    )?;
    sea::sign_sea(sea_priv, &message)
}

/// Verify `signature` under `account.current_key`.
///
/// The store has already resolved `account` from its own [`PublishedChain`].
/// A signature that does not verify is [`EncDiscError::StoreRejected`].
/// The store must not mutate on that error, or on any later rejection of
/// the same call.
#[allow(clippy::too_many_arguments)]
pub fn verify_store_write(
    principal: &PrincipalId,
    operation: &str,
    target: &str,
    envelope_hash_hex: &str,
    head: &str,
    replaced: &str,
    class: &str,
    generation: &str,
    signature: &str,
    account: &sociacl_ids::ResolvedAccount,
) -> Result<(), EncDiscError> {
    let message = store_write_message(
        principal.as_ref(),
        operation,
        target,
        envelope_hash_hex,
        head,
        replaced,
        class,
        generation,
    )?;
    sea::verify_sea(account.current_key.as_ref(), &message, signature)
        .map_err(|_| EncDiscError::StoreRejected)
}

/// SHA-256 of the wrap ciphertext bytes. The hex alphabet of the stored
/// string is not the hashed message.
pub fn wrap_ciphertext_hash(ciphertext_hex: &str) -> Result<String, EncDiscError> {
    let bytes =
        crate::hexutil::decode_hex(ciphertext_hex).map_err(|_| EncDiscError::StoreRejected)?;
    Ok(canonical::sha256_hex(&bytes))
}

pub(crate) fn decimal(value: u64) -> Result<String, EncDiscError> {
    canonical::canonical_decimal(value).map_err(|_| EncDiscError::StoreRejected)
}
