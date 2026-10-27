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
//! records every head the resolver reports, including a read or a rejected
//! write, plus every stored current recovery sequence. A pending sequence
//! is not included. The recovery store and the wrap store share one floor
//! per principal.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

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

/// Monotonic per-principal head floor.
///
/// [`HeadFloor`] is cloned by sharing the map. [`MemoryRecoveryStore`] and
/// [`MemoryKeyWrapStore`] constructed with the same value enforce one floor.
///
/// [`MemoryRecoveryStore`]: crate::MemoryRecoveryStore
/// [`MemoryKeyWrapStore`]: crate::MemoryKeyWrapStore
#[derive(Clone, Debug, Default)]
pub struct HeadFloor {
    inner: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl HeadFloor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Record `head` when it is at least the floor. A smaller head is
    /// [`EncDiscError::StoreRejected`] and the floor stays where it is.
    pub fn observe(&self, principal: &str, head: u64) -> Result<(), EncDiscError> {
        let mut floors = self.inner.lock().map_err(|_| EncDiscError::StoreRejected)?;
        let floor = floors.get(principal).copied().unwrap_or(0);
        if head < floor {
            return Err(EncDiscError::StoreRejected);
        }
        if head > floor {
            floors.insert(principal.to_string(), head);
        }
        Ok(())
    }

    /// Raise the floor to `seq` when `seq` is greater. A smaller sequence
    /// leaves the floor unchanged. Stored current recovery sequences use
    /// this. Pending sequences do not.
    pub fn raise(&self, principal: &str, seq: u64) {
        let mut floors = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let floor = floors.get(principal).copied().unwrap_or(0);
        if seq > floor {
            floors.insert(principal.to_string(), seq);
        }
    }
}

/// The published account a store reads for itself. The writer does not supply it.
/// Trusted resolver boundary. Implementations must run resolve_current_key
/// over authenticated history, not construct a result from writer assertions.
/// See docs/recovery-store-operations.md for freshness and restoration rules.
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

/// Resolve untrusted records before a store observes their head. Diagnostics are
/// appended even on failure. The adapter supplies trusted policy/history context
/// and enforces snapshot freshness; this helper cannot establish completeness.
pub fn resolve_store_account(
    principal: &PrincipalId,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    diagnostics: &mut Vec<sociacl_ids::Diagnostic>,
) -> Result<sociacl_ids::ResolvedAccount, EncDiscError> {
    let resolved = sociacl_ids::resolve_current_key(principal, rotations, context);
    diagnostics.extend(resolved.diagnostics);
    resolved.result.map_err(|_| EncDiscError::StoreRejected)
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

/// Domain-separated commitment to every stored wrap field.
pub fn wrap_row_hash(wrap: &crate::identity::EncryptedAccountWrap) -> Result<String, EncDiscError> {
    let message = canonical::length_prefixed(&[
        "sociacl-wrap-row-v1",
        wrap.principal.as_ref(),
        wrap.wrap_id.as_ref(),
        &wrap.epub,
        crate::identity::wrap_class_label(wrap.class),
        &wrap.ciphertext_hex,
        &wrap.signature,
    ])?;
    Ok(canonical::sha256_hex(&message))
}

/// Legacy ciphertext digest only; use [`wrap_row_hash`] for store-write authorization.
pub fn wrap_ciphertext_hash(ciphertext_hex: &str) -> Result<String, EncDiscError> {
    let bytes =
        crate::hexutil::decode_hex(ciphertext_hex).map_err(|_| EncDiscError::StoreRejected)?;
    Ok(canonical::sha256_hex(&bytes))
}

pub(crate) fn decimal(value: u64) -> Result<String, EncDiscError> {
    canonical::canonical_decimal(value).map_err(|_| EncDiscError::StoreRejected)
}
