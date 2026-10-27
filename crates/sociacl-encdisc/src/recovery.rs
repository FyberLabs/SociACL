//! Passphrase recovery copy of an [`AccountKeyring`].
//!
//! The sealing key is Argon2id. The passphrase is an argument and is not
//! stored. The envelope goes to a [`RecoveryCopyStore`], which keeps
//! ciphertext only. Panopticon is that kind of adapter: an index, not the
//! authority. `priv` and `epriv` never go on Gun.
//!
//! The public seal draws the salt and nonce internally.
//! [`seal_recovery_copy_with`] takes caller-chosen values for tests and is
//! not re-exported.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use sociacl_ids::{parse_principal_id, PrincipalId};
use zeroize::{Zeroize, Zeroizing};

use crate::canonical::{self, JS_SAFE_INTEGER_MAX};
use crate::error::EncDiscError;
use crate::hexutil::encode_hex;
use crate::keyring::{rotate_keyring, AccountKeyring, KeyringRotation, RotationMint};
use crate::limits::{
    in_bound, ARGON2ID_LIMITS, KEYRING_HISTORY_MAX, KEYRING_SERIAL_MAX, KEYRING_SERIAL_V2_MAX,
    RECOVERY_ABSOLUTE_MAX, RECOVERY_HEADER_LEN, RECOVERY_NONCE_LEN, RECOVERY_TAG_LEN,
};
use crate::store_write::{sign_store_write, verify_store_write};
use unicode_normalization::UnicodeNormalization;
pub(crate) const DOMAIN_RECOVERY: &str = "sociacl-recovery-copy-v1";
pub(crate) const DOMAIN_KEYRING_PLAIN_V1: &str = "sociacl-keyring-plain-v1";
pub(crate) const DOMAIN_KEYRING_PLAIN: &str = "sociacl-keyring-plain-v2";
pub(crate) const DOMAIN_KEYRING_PLAIN_V3: &str = "sociacl-keyring-plain-v3";

/// Ciphertext of one keyring version. The store does not see the passphrase.
///
/// `signing_pub` and `epub` are the keyring's current public keys, in the
/// clear, and are covered by the recovery AAD and by the store-write hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryEnvelope {
    pub principal: PrincipalId,
    pub rotation_seq: u64,
    pub signing_pub: PrincipalId,
    pub epub: PrincipalId,
    pub bytes: Vec<u8>,
}

/// SHA-256 of the length-prefixed principal, decimal sequence, signing pub,
/// epub, and lowercase hex of the envelope bytes.
pub fn recovery_envelope_hash(envelope: &RecoveryEnvelope) -> Result<String, EncDiscError> {
    let seq = canonical::canonical_decimal(envelope.rotation_seq)?;
    let bytes_hex = encode_hex(&envelope.bytes);
    canonical::sha256_fields(&[
        envelope.principal.as_ref(),
        seq.as_str(),
        envelope.signing_pub.as_ref(),
        envelope.epub.as_ref(),
        bytes_hex.as_str(),
    ])
}

/// Ciphertext adapter. Not an authority, and not Gun.
///
/// The store reads the published chain from [`published_account`]. The writer
/// does not pass one. Every `put_copy`, `commit`, and `delete_copy` carries a
/// compare-and-swap signature by the head key that resolver reports.
/// Adapters, Panopticon included, must verify that signature before they
/// write. Session authentication is not this check. Panopticon reads the
/// published Gun chain. It is a verifier and a witness. It is never the
/// authority.
///
/// A put at the resolved head replaces the current copy and drops any pending
/// copy. A put at head + 1 is the only pending copy. Any other sequence is
/// `store-rejected` and changes nothing. A rejected commit leaves both copies
/// where they were. Promotion replaces the current row in place. There is
/// never a window with zero copies when a current copy already exists.
pub trait RecoveryCopyStore {
    /// The published account. Panopticon reads this from Gun.
    fn published_account(
        &self,
        principal: &PrincipalId,
    ) -> Result<sociacl_ids::ResolvedAccount, EncDiscError>;

    /// Writes already accepted for `principal`. The next write signs this value.
    fn write_generation(&self, principal: &PrincipalId) -> u64;

    fn put_copy(
        &mut self,
        envelope: &RecoveryEnvelope,
        signature: &str,
    ) -> Result<(), EncDiscError>;

    fn get_copy(
        &self,
        principal: &PrincipalId,
        rotation_seq: u64,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError>;

    /// The current copy, if one is stored.
    fn current_copy(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError>;

    /// The pending copy, if one is stored. Callers hash it before they sign a commit.
    fn pending_copy(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError>;

    /// Promote the pending copy, or reject and leave it. See [`commit_recovery_copy`].
    fn commit(&mut self, principal: &PrincipalId, signature: &str) -> Result<(), EncDiscError>;

    /// Delete the current or pending copy at `rotation_seq`. Does not promote.
    fn delete_copy(
        &mut self,
        principal: &PrincipalId,
        rotation_seq: u64,
        signature: &str,
    ) -> Result<(), EncDiscError>;

    fn is_authority(&self) -> bool {
        false
    }

    fn sees_plaintext(&self) -> bool {
        false
    }

    fn sees_passphrase(&self) -> bool {
        false
    }
}

/// Current recovery copy, plus at most one copy waiting at head + 1.
#[derive(Clone, Debug, Default)]
struct RecoverySlot {
    current: Option<RecoveryEnvelope>,
    pending: Option<RecoveryEnvelope>,
}

/// In-memory adapter. One slot per principal.
///
/// `chain` is the published source. The writer does not pass a chain into
/// put, commit, or delete. `get_copy` returns a clone, so the caller cannot
/// alias the stored bytes. Promotion assigns the pending envelope onto
/// `current` in place. A rejected commit does not clear pending.
///
/// `head_floor` is every head the resolver has reported and every stored
/// current sequence. A pending sequence is not included. `generation`
/// counts accepted writes and stays when the slot is emptied.
pub struct MemoryRecoveryStore<C> {
    by_principal: BTreeMap<String, RecoverySlot>,
    head_floor: crate::store_write::HeadFloor,
    generation: BTreeMap<String, u64>,
    chain: C,
}

impl<C> MemoryRecoveryStore<C> {
    /// Supply the same floor (or its clone) to the wrap store. Reads and
    /// rejected writes in either store must protect both against rollback.
    ///
    /// ```compile_fail,E0061
    /// use sociacl_encdisc::{EncDiscError, MemoryRecoveryStore};
    /// fn chain(_: &sociacl_ids::PrincipalId) -> Result<sociacl_ids::ResolvedAccount, EncDiscError> {
    ///     Err(EncDiscError::StoreRejected)
    /// }
    /// let store = MemoryRecoveryStore::new(chain);
    /// ```
    pub fn new(chain: C, head_floor: crate::store_write::HeadFloor) -> Self {
        Self::sharing(chain, head_floor)
    }

    /// `head_floor` is shared with a wrap store that should enforce the same
    /// per-principal floor.
    pub fn sharing(chain: C, head_floor: crate::store_write::HeadFloor) -> Self {
        Self {
            by_principal: BTreeMap::new(),
            head_floor,
            generation: BTreeMap::new(),
            chain,
        }
    }

    pub fn len(&self) -> usize {
        self.by_principal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_principal.is_empty()
    }
}

impl<C: crate::store_write::PublishedChain> MemoryRecoveryStore<C> {
    fn account(
        &self,
        principal: &PrincipalId,
    ) -> Result<(sociacl_ids::ResolvedAccount, u64, u64, u64), EncDiscError> {
        let account = self.published_account(principal)?;
        let head = account.rotations.len() as u64;
        let generation = self
            .generation
            .get(principal.as_ref())
            .copied()
            .unwrap_or(0);
        Ok((account, head, head, generation))
    }

    fn bump(&mut self, key: &str, next_generation: u64, head: u64) {
        self.head_floor.raise(key, head);
        if let Some(current) = self
            .by_principal
            .get(key)
            .and_then(|slot| slot.current.as_ref())
        {
            self.head_floor.raise(key, current.rotation_seq);
        }
        self.generation
            .insert(key.to_string(), next_generation);
    }
}

impl<C: crate::store_write::PublishedChain> RecoveryCopyStore for MemoryRecoveryStore<C> {
    fn published_account(
        &self,
        principal: &PrincipalId,
    ) -> Result<sociacl_ids::ResolvedAccount, EncDiscError> {
        let account = self.chain.published_account(principal)?;
        let head = account.rotations.len() as u64;
        self.head_floor.observe(principal.as_ref(), head)?;
        Ok(account)
    }

    fn write_generation(&self, principal: &PrincipalId) -> u64 {
        self.generation
            .get(principal.as_ref())
            .copied()
            .unwrap_or(0)
    }

    fn put_copy(
        &mut self,
        envelope: &RecoveryEnvelope,
        signature: &str,
    ) -> Result<(), EncDiscError> {
        if envelope.bytes.len() > RECOVERY_ABSOLUTE_MAX || envelope.bytes.is_empty() {
            return Err(EncDiscError::StoreRejected);
        }
        let seq = header_rotation_seq(&envelope.bytes)?;
        if seq != envelope.rotation_seq {
            return Err(EncDiscError::StoreRejected);
        }
        let (account, head, _floor, generation) = self.account(&envelope.principal)?;
        let next_generation = crate::store_write::next_store_generation(generation)?;
        let key = envelope.principal.as_ref().to_string();
        if self
            .by_principal
            .get(&key)
            .and_then(|slot| slot.current.as_ref())
            .is_some_and(|current| current.rotation_seq > head)
        {
            return Err(EncDiscError::StoreRejected);
        }
        let at_head = envelope.rotation_seq == head;
        let at_next = envelope.rotation_seq == head.saturating_add(1);
        if !at_head && !at_next {
            return Err(EncDiscError::StoreRejected);
        }
        let replaced = if at_head {
            predecessor(
                self.by_principal
                    .get(&key)
                    .and_then(|slot| slot.current.as_ref()),
            )?
        } else {
            predecessor(
                self.by_principal
                    .get(&key)
                    .and_then(|slot| slot.pending.as_ref()),
            )?
        };
        let hash = recovery_envelope_hash(envelope)?;
        let target = crate::store_write::decimal(envelope.rotation_seq)?;
        verify_store_write(
            &envelope.principal,
            "put",
            &target,
            &hash,
            &crate::store_write::decimal(head)?,
            &replaced,
            crate::store_write::STORE_CLASS_NONE,
            &crate::store_write::decimal(generation)?,
            signature,
            &account,
        )?;
        if at_head {
            if envelope.signing_pub.as_ref() != account.current_key.as_ref() {
                return Err(EncDiscError::StoreRejected);
            }
            if account
                .current_epub
                .as_ref()
                .is_some_and(|epub| epub.as_ref() != envelope.epub.as_ref())
            {
                return Err(EncDiscError::StoreRejected);
            }
            let slot = self.by_principal.entry(key.clone()).or_default();
            slot.current = Some(envelope.clone());
            slot.pending = None;
            self.bump(&key, next_generation, head);
            return Ok(());
        }
        let slot = self.by_principal.entry(key.clone()).or_default();
        slot.pending = Some(envelope.clone());
        self.bump(&key, next_generation, head);
        Ok(())
    }

    fn get_copy(
        &self,
        principal: &PrincipalId,
        rotation_seq: u64,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError> {
        let Some(slot) = self.by_principal.get(principal.as_ref()) else {
            return Ok(None);
        };
        if slot
            .current
            .as_ref()
            .is_some_and(|current| current.rotation_seq == rotation_seq)
        {
            return Ok(slot.current.clone());
        }
        Ok(slot.pending.as_ref().and_then(|pending| {
            if pending.rotation_seq == rotation_seq {
                Some(pending.clone())
            } else {
                None
            }
        }))
    }

    fn current_copy(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError> {
        Ok(self
            .by_principal
            .get(principal.as_ref())
            .and_then(|slot| slot.current.clone()))
    }

    fn pending_copy(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<RecoveryEnvelope>, EncDiscError> {
        Ok(self
            .by_principal
            .get(principal.as_ref())
            .and_then(|slot| slot.pending.clone()))
    }

    fn commit(&mut self, principal: &PrincipalId, signature: &str) -> Result<(), EncDiscError> {
        let key = principal.as_ref().to_string();
        let (account, head, _floor, generation) = self.account(principal)?;
        let next_generation = crate::store_write::next_store_generation(generation)?;
        let pending = self
            .by_principal
            .get(&key)
            .and_then(|slot| slot.pending.clone())
            .ok_or(EncDiscError::StoreRejected)?;
        let replaced = predecessor(
            self.by_principal
                .get(&key)
                .and_then(|slot| slot.current.as_ref()),
        )?;
        let hash = recovery_envelope_hash(&pending)?;
        verify_store_write(
            principal,
            "commit",
            &crate::store_write::decimal(head)?,
            &hash,
            &crate::store_write::decimal(head)?,
            &replaced,
            crate::store_write::STORE_CLASS_NONE,
            &crate::store_write::decimal(generation)?,
            signature,
            &account,
        )?;
        let pubs_match = pending.rotation_seq == head
            && account.current_epub.as_ref().is_some_and(|epub| {
                epub.as_ref() == pending.epub.as_ref()
                    && account.current_key.as_ref() == pending.signing_pub.as_ref()
            });
        if !pubs_match {
            return Err(EncDiscError::StoreRejected);
        }
        let Some(slot) = self.by_principal.get_mut(&key) else {
            return Err(EncDiscError::StoreRejected);
        };
        slot.current = Some(pending);
        slot.pending = None;
        self.bump(&key, next_generation, head);
        Ok(())
    }

    fn delete_copy(
        &mut self,
        principal: &PrincipalId,
        rotation_seq: u64,
        signature: &str,
    ) -> Result<(), EncDiscError> {
        let key = principal.as_ref().to_string();
        let (account, head, _floor, generation) = self.account(principal)?;
        let next_generation = crate::store_write::next_store_generation(generation)?;
        let stored = self
            .by_principal
            .get(&key)
            .and_then(|slot| {
                slot.current
                    .as_ref()
                    .filter(|envelope| envelope.rotation_seq == rotation_seq)
                    .or(slot
                        .pending
                        .as_ref()
                        .filter(|envelope| envelope.rotation_seq == rotation_seq))
            })
            .cloned()
            .ok_or(EncDiscError::StoreRejected)?;
        let hash = recovery_envelope_hash(&stored)?;
        let target = crate::store_write::decimal(rotation_seq)?;
        verify_store_write(
            principal,
            "delete",
            &target,
            &hash,
            &crate::store_write::decimal(head)?,
            &hash,
            crate::store_write::STORE_CLASS_NONE,
            &crate::store_write::decimal(generation)?,
            signature,
            &account,
        )?;
        let Some(slot) = self.by_principal.get_mut(&key) else {
            return Err(EncDiscError::StoreRejected);
        };
        if slot
            .current
            .as_ref()
            .is_some_and(|envelope| envelope.rotation_seq == rotation_seq)
        {
            slot.current = None;
        }
        if slot
            .pending
            .as_ref()
            .is_some_and(|envelope| envelope.rotation_seq == rotation_seq)
        {
            slot.pending = None;
        }
        if slot.current.is_none() && slot.pending.is_none() {
            self.by_principal.remove(&key);
        }
        self.bump(&key, next_generation, head);
        Ok(())
    }
}

fn predecessor(row: Option<&RecoveryEnvelope>) -> Result<String, EncDiscError> {
    match row {
        Some(envelope) => recovery_envelope_hash(envelope),
        None => Ok(crate::store_write::REPLACED_NONE.to_string()),
    }
}

/// NFC then UTF-8, in the style of an RFC 8265 OpaqueString, against Unicode 16.0.0.
///
/// A code point unassigned in Unicode 16.0.0 is [`EncDiscError::RecoveryParams`]
/// before NFC, so a later Unicode mark cannot reorder. Whitespace is the
/// Unicode 16 `White_Space` set, including U+0085. U+FEFF is not whitespace.
/// An empty string and a whitespace-only string are
/// [`EncDiscError::RecoveryParams`]. Leading and trailing whitespace on a
/// passphrase that also has a non-whitespace character is preserved.
///
/// The NFC buffer is [`Zeroizing`]. The caller's `&str` and any scratch
/// inside `unicode-normalization` are not wiped. TypeScript strings cannot
/// be wiped either. The byte API does not normalize; it receives these bytes
/// and applies the same Unicode 16 checks.
pub fn encode_passphrase(passphrase: &str) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    debug_assert_eq!(crate::unicode16::UNICODE_VERSION, "16.0.0");
    if passphrase.is_empty()
        || passphrase
            .chars()
            .any(|ch| !crate::unicode16::assigned(ch as u32))
    {
        return Err(EncDiscError::RecoveryParams);
    }
    let mut nfc = Zeroizing::new(String::new());
    for ch in passphrase.nfc() {
        nfc.push(ch);
    }
    if nfc
        .chars()
        .all(|ch| crate::unicode16::passphrase_whitespace(ch as u32))
    {
        return Err(EncDiscError::RecoveryParams);
    }
    let owned = std::mem::take(&mut *nfc);
    Ok(Zeroizing::new(owned.into_bytes()))
}

/// Seal with a passphrase string. The string is normalized by [`encode_passphrase`].
pub fn seal_recovery_copy_str(
    keyring: &AccountKeyring,
    passphrase: &str,
    store: &mut impl RecoveryCopyStore,
    handle: Option<&str>,
) -> Result<RecoveryEnvelope, EncDiscError> {
    let bytes = encode_passphrase(passphrase)?;
    seal_recovery_copy(keyring, &bytes, store, handle)
}

/// Open with a passphrase string. The string is normalized by [`encode_passphrase`].
pub fn open_recovery_copy_str(
    passphrase: &str,
    envelope: &RecoveryEnvelope,
    expected: &PrincipalId,
    expected_rotation_seq: u64,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<AccountKeyring, EncDiscError> {
    let bytes = encode_passphrase(passphrase)?;
    open_recovery_copy(
        &bytes,
        envelope,
        expected,
        expected_rotation_seq,
        rotations,
        context,
    )
}

/// Seal `keyring` under `passphrase` and store the ciphertext.
///
/// Salt and nonce are drawn here. The passphrase is not written to `store`.
/// The store write is signed by this keyring's current private key, which
/// must be the published chain-head key. A pending copy of the next keyring
/// is signed by [`rotate_and_reseal`] with the key that is still the head.
pub fn seal_recovery_copy(
    keyring: &AccountKeyring,
    passphrase: &[u8],
    store: &mut impl RecoveryCopyStore,
    handle: Option<&str>,
) -> Result<RecoveryEnvelope, EncDiscError> {
    seal_recovery_signed(keyring, passphrase, keyring.current_priv(), store, handle)
}

fn seal_recovery_signed(
    keyring: &AccountKeyring,
    passphrase: &[u8],
    signer_priv: &str,
    store: &mut impl RecoveryCopyStore,
    handle: Option<&str>,
) -> Result<RecoveryEnvelope, EncDiscError> {
    let mut salt = vec![0u8; ARGON2ID_LIMITS.salt_length.floor as usize];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; RECOVERY_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let envelope = seal_recovery_copy_with(
        keyring,
        passphrase,
        &salt,
        &nonce,
        signer_priv,
        store,
        handle,
    );
    salt.zeroize();
    nonce.zeroize();
    envelope
}

/// Caller-chosen salt and nonce. Tests only. Not a public export.
pub(crate) fn seal_recovery_copy_with(
    keyring: &AccountKeyring,
    passphrase: &[u8],
    salt: &[u8],
    nonce: &[u8],
    signer_priv: &str,
    store: &mut impl RecoveryCopyStore,
    handle: Option<&str>,
) -> Result<RecoveryEnvelope, EncDiscError> {
    if keyring.prior_lanes().len() as u64 != keyring.rotation_seq() {
        return Err(EncDiscError::BadLane);
    }
    if passphrase_rejected(passphrase) {
        return Err(EncDiscError::RecoveryParams);
    }
    crate::passphrase::check_recovery_passphrase(passphrase, keyring.principal(), handle)?;
    if salt.len() < ARGON2ID_LIMITS.salt_length.floor as usize
        || salt.len() > ARGON2ID_LIMITS.salt_length.ceiling as usize
        || nonce.len() != RECOVERY_NONCE_LEN
    {
        return Err(EncDiscError::RecoveryParams);
    }
    let mut plain = encode_keyring(keyring)?;
    let mut key = derive_key(
        passphrase,
        salt,
        ARGON2ID_LIMITS.memory_kib.floor,
        ARGON2ID_LIMITS.iterations.floor,
        ARGON2ID_LIMITS.parallelism.floor,
        ARGON2ID_LIMITS.hash_length.floor,
    )?;
    let aad = recovery_aad(
        keyring.principal().as_ref(),
        keyring.rotation_seq(),
        keyring.current_pub().as_ref(),
        keyring.current_epub().as_ref(),
        ARGON2ID_LIMITS.memory_kib.floor,
        ARGON2ID_LIMITS.iterations.floor,
        ARGON2ID_LIMITS.parallelism.floor,
        ARGON2ID_LIMITS.hash_length.floor,
        ARGON2ID_LIMITS.version.floor,
        salt,
    )?;
    let ciphertext = aes_encrypt(&key, nonce, &aad, &plain)?;
    plain.zeroize();
    key.zeroize();
    let mut bytes =
        Vec::with_capacity(RECOVERY_HEADER_LEN + salt.len() + nonce.len() + ciphertext.len());
    write_header(
        &mut bytes,
        ARGON2ID_LIMITS.version.floor,
        ARGON2ID_LIMITS.memory_kib.floor,
        ARGON2ID_LIMITS.iterations.floor,
        ARGON2ID_LIMITS.parallelism.floor,
        ARGON2ID_LIMITS.hash_length.floor,
        salt,
        keyring.rotation_seq(),
    );
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&ciphertext);
    if bytes.len() > RECOVERY_ABSOLUTE_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let envelope = RecoveryEnvelope {
        principal: keyring.principal().clone(),
        rotation_seq: keyring.rotation_seq(),
        signing_pub: keyring.current_pub().clone(),
        epub: keyring.current_epub().clone(),
        bytes,
    };
    let signature = sign_recovery_put(store, signer_priv, &envelope)?;
    store.put_copy(&envelope, &signature)?;
    Ok(envelope)
}

/// Open a recovery copy.
///
/// A wrong passphrase and a tampered envelope both return
/// [`EncDiscError::RecoveryRejected`]. A parameter outside
/// [`ARGON2ID_LIMITS`] returns [`EncDiscError::RecoveryParams`] before the
/// KDF runs. An authentic copy whose version is not `expected_rotation_seq`
/// returns [`EncDiscError::RecoveryStale`].
pub fn open_recovery_copy(
    passphrase: &[u8],
    envelope: &RecoveryEnvelope,
    expected: &PrincipalId,
    expected_rotation_seq: u64,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<AccountKeyring, EncDiscError> {
    if envelope.bytes.len() > RECOVERY_ABSOLUTE_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let header = parse_header(&envelope.bytes)?;
    if passphrase_rejected(passphrase) {
        return Err(EncDiscError::RecoveryParams);
    }
    if envelope.principal.as_ref() != expected.as_ref()
        || header.rotation_seq != envelope.rotation_seq
    {
        return Err(EncDiscError::RecoveryRejected);
    }
    if header.rotation_seq > JS_SAFE_INTEGER_MAX {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut key = derive_key(
        passphrase,
        &header.salt,
        header.memory_kib,
        header.iterations,
        header.parallelism,
        header.hash_length,
    )?;
    let aad = recovery_aad(
        expected.as_ref(),
        header.rotation_seq,
        envelope.signing_pub.as_ref(),
        envelope.epub.as_ref(),
        header.memory_kib,
        header.iterations,
        header.parallelism,
        header.hash_length,
        header.version,
        &header.salt,
    )?;
    let mut plain = match aes_decrypt(&key, &header.nonce, &aad, &header.ciphertext) {
        Ok(plain) => plain,
        Err(error) => {
            key.zeroize();
            return Err(error);
        }
    };
    key.zeroize();
    if plain.len() > KEYRING_SERIAL_MAX {
        plain.zeroize();
        return Err(EncDiscError::KeyringTooLarge);
    }
    let fields = match decode_keyring(&plain) {
        Ok(fields) => fields,
        Err(error) => {
            plain.zeroize();
            return Err(error);
        }
    };
    plain.zeroize();
    let parsed = parse_principal_id(fields.principal.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if parsed.as_ref() != fields.principal.as_str() || parsed.as_ref() != expected.as_ref() {
        return Err(EncDiscError::RecoveryRejected);
    }
    if fields.rotation_seq != header.rotation_seq
        || fields.current_pub.as_str() != envelope.signing_pub.as_ref()
        || fields.current_epub.as_str() != envelope.epub.as_ref()
    {
        return Err(EncDiscError::RecoveryRejected);
    }
    if fields.rotation_seq != expected_rotation_seq {
        return Err(EncDiscError::RecoveryStale);
    }
    let retired: Vec<(&str, &str)> = fields
        .retired
        .iter()
        .map(|(epub, epriv)| (epub.as_str(), epriv.as_str()))
        .collect();
    let prior: Vec<&str> = fields
        .prior_lanes
        .iter()
        .map(|lane| lane.as_str())
        .collect();
    let prior_contact: Vec<&str> = fields
        .prior_contact_secrets
        .iter()
        .map(|secret| secret.as_str())
        .collect();
    AccountKeyring::import_with_contact_secrets(
        fields.principal.as_str(),
        fields.genesis_epub.as_str(),
        fields.current_pub.as_str(),
        fields.current_priv.as_str(),
        fields.current_epub.as_str(),
        fields.current_epriv.as_str(),
        &retired,
        fields.lane_id.as_str(),
        fields.content_epoch,
        fields.rotation_seq,
        rotations,
        context,
        &prior,
        fields.contact_lane_secret.as_str(),
        &prior_contact,
    )
}

/// Rotate, then seal a pending recovery copy of the new keyring version.
///
/// The pending put is signed by the keyring that is still the published
/// chain head, not by the new key. The store reads that chain from its own
/// resolver. Commit promotes a pending copy only after that resolver reports
/// the published head and the pending public keys match it. An unsigned
/// draft fails to resolve. A signed rotation that is not on that chain is
/// not promoted, and the pending copy stays.
pub fn rotate_and_reseal<F>(
    keyring: &AccountKeyring,
    trusted: &[&str],
    lost: &str,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    mint: F,
    passphrase: &[u8],
    store: &mut impl RecoveryCopyStore,
    handle: Option<&str>,
) -> Result<(KeyringRotation, RecoveryEnvelope), EncDiscError>
where
    F: FnOnce() -> Result<RotationMint, EncDiscError>,
{
    let rotation = rotate_keyring(keyring, trusted, lost, rotations, context, mint)?;
    let envelope = seal_recovery_signed(
        &rotation.keyring,
        passphrase,
        keyring.current_priv(),
        store,
        handle,
    )?;
    Ok((rotation, envelope))
}

/// Promote the pending copy when its sequence and public keys equal the
/// published chain head the store resolved for itself.
///
/// `signer_priv` must be that head key. The signature covers the stored
/// pending envelope, the head, the current row it replaces, and the write
/// generation. A chain that does not resolve, a signature that does not
/// verify, a pending copy at head + 1, and a pending copy whose public keys
/// differ are [`EncDiscError::StoreRejected`]. None of those outcomes change
/// the stored copies.
pub fn commit_recovery_copy(
    principal: &PrincipalId,
    signer_priv: &str,
    store: &mut impl RecoveryCopyStore,
) -> Result<(), EncDiscError> {
    let pending = store
        .pending_copy(principal)?
        .ok_or(EncDiscError::StoreRejected)?;
    let account = store.published_account(principal)?;
    let head = account.rotations.len() as u64;
    let hash = recovery_envelope_hash(&pending)?;
    let replaced = predecessor(store.current_copy(principal)?.as_ref())?;
    let signature = sign_recovery_op(
        store,
        signer_priv,
        principal,
        "commit",
        head,
        &hash,
        &replaced,
    )?;
    store.commit(principal, &signature)
}

/// Delete the current or pending copy at `rotation_seq`.
///
/// The signature is the same store-write signature as put and commit.
/// Deleting the current copy does not promote a pending copy. A missing
/// target is [`EncDiscError::StoreRejected`].
pub fn delete_recovery_copy(
    principal: &PrincipalId,
    rotation_seq: u64,
    signer_priv: &str,
    store: &mut impl RecoveryCopyStore,
) -> Result<(), EncDiscError> {
    let envelope = store
        .get_copy(principal, rotation_seq)?
        .ok_or(EncDiscError::StoreRejected)?;
    let hash = recovery_envelope_hash(&envelope)?;
    let signature = sign_recovery_op(
        store,
        signer_priv,
        principal,
        "delete",
        rotation_seq,
        &hash,
        &hash,
    )?;
    store.delete_copy(principal, rotation_seq, &signature)
}

fn sign_recovery_put(
    store: &impl RecoveryCopyStore,
    signer_priv: &str,
    envelope: &RecoveryEnvelope,
) -> Result<String, EncDiscError> {
    let account = store.published_account(&envelope.principal)?;
    let head = account.rotations.len() as u64;
    let replaced = if envelope.rotation_seq == head {
        predecessor(store.current_copy(&envelope.principal)?.as_ref())?
    } else {
        predecessor(store.pending_copy(&envelope.principal)?.as_ref())?
    };
    let hash = recovery_envelope_hash(envelope)?;
    sign_recovery_op(
        store,
        signer_priv,
        &envelope.principal,
        "put",
        envelope.rotation_seq,
        &hash,
        &replaced,
    )
}

fn sign_recovery_op(
    store: &impl RecoveryCopyStore,
    signer_priv: &str,
    principal: &PrincipalId,
    operation: &str,
    target: u64,
    envelope_hash: &str,
    replaced: &str,
) -> Result<String, EncDiscError> {
    let account = store.published_account(principal)?;
    let generation = store.write_generation(principal);
    sign_store_write(
        signer_priv,
        principal,
        operation,
        &crate::store_write::decimal(target)?,
        envelope_hash,
        &crate::store_write::decimal(account.rotations.len() as u64)?,
        replaced,
        crate::store_write::STORE_CLASS_NONE,
        &crate::store_write::decimal(generation)?,
    )
}

pub(crate) struct KeyringFields {
    pub principal: Zeroizing<String>,
    pub genesis_epub: Zeroizing<String>,
    pub current_pub: Zeroizing<String>,
    pub current_priv: Zeroizing<String>,
    pub current_epub: Zeroizing<String>,
    pub current_epriv: Zeroizing<String>,
    pub retired: Vec<(Zeroizing<String>, Zeroizing<String>)>,
    pub lane_id: Zeroizing<String>,
    pub prior_lanes: Vec<Zeroizing<String>>,
    pub contact_lane_secret: Zeroizing<String>,
    pub prior_contact_secrets: Vec<Zeroizing<String>>,
    pub content_epoch: u64,
    pub rotation_seq: u64,
}

pub(crate) fn encode_keyring(keyring: &AccountKeyring) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    if keyring.prior_lanes().len() > KEYRING_HISTORY_MAX
        || keyring.prior_contact_secrets().len() > KEYRING_HISTORY_MAX
        || keyring.rotation_seq() > KEYRING_HISTORY_MAX as u64
    {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let retired_count = canonical::canonical_decimal(keyring.retired().len() as u64)?;
    let prior_count = canonical::canonical_decimal(keyring.prior_lanes().len() as u64)?;
    let contact_prior_count =
        canonical::canonical_decimal(keyring.prior_contact_secrets().len() as u64)?;
    let epoch = canonical::canonical_decimal(keyring.content_epoch())?;
    let seq = canonical::canonical_decimal(keyring.rotation_seq())?;
    let mut total = 0usize;
    let mut add = |len: usize| -> Result<(), EncDiscError> {
        total = total
            .checked_add(4 + len)
            .ok_or(EncDiscError::FieldTooLong)?;
        Ok(())
    };
    add(DOMAIN_KEYRING_PLAIN.len())?;
    add(keyring.principal().as_ref().len())?;
    add(keyring.genesis_epub().as_ref().len())?;
    add(keyring.current_pub().as_ref().len())?;
    add(keyring.current_priv().len())?;
    add(keyring.current_epub().as_ref().len())?;
    add(keyring.current_epriv().len())?;
    add(retired_count.len())?;
    for row in keyring.retired() {
        add(row.epub().as_ref().len())?;
        add(row.epriv().len())?;
    }
    add(keyring.lane_id().len())?;
    add(prior_count.len())?;
    for lane in keyring.prior_lanes() {
        add(lane.len())?;
    }
    add(keyring.contact_lane_secret().len())?;
    add(contact_prior_count.len())?;
    for secret in keyring.prior_contact_secrets() {
        add(secret.len())?;
    }
    add(epoch.len())?;
    add(seq.len())?;
    if total > KEYRING_SERIAL_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    // Both domains have the same length; existing small-copy bytes stay stable.
    let domain = if total > KEYRING_SERIAL_V2_MAX {
        DOMAIN_KEYRING_PLAIN_V3
    } else {
        DOMAIN_KEYRING_PLAIN
    };
    write_field(&mut out, domain);
    write_field(&mut out, keyring.principal().as_ref());
    write_field(&mut out, keyring.genesis_epub().as_ref());
    write_field(&mut out, keyring.current_pub().as_ref());
    write_field(&mut out, keyring.current_priv());
    write_field(&mut out, keyring.current_epub().as_ref());
    write_field(&mut out, keyring.current_epriv());
    write_field(&mut out, &retired_count);
    for row in keyring.retired() {
        write_field(&mut out, row.epub().as_ref());
        write_field(&mut out, row.epriv());
    }
    write_field(&mut out, keyring.lane_id());
    write_field(&mut out, &prior_count);
    for lane in keyring.prior_lanes() {
        write_field(&mut out, lane);
    }
    write_field(&mut out, keyring.contact_lane_secret());
    write_field(&mut out, &contact_prior_count);
    for secret in keyring.prior_contact_secrets() {
        write_field(&mut out, secret.as_str());
    }
    write_field(&mut out, &epoch);
    write_field(&mut out, &seq);
    if out.len() != total {
        return Err(EncDiscError::BadEncoding);
    }
    Ok(out)
}

pub(crate) fn decode_keyring(bytes: &[u8]) -> Result<KeyringFields, EncDiscError> {
    if bytes.len() > KEYRING_SERIAL_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let mut cursor = Cursor { bytes, offset: 0 };
    let domain = cursor.next_string()?;
    if domain.as_str() == DOMAIN_KEYRING_PLAIN_V1
        || (domain.as_str() != DOMAIN_KEYRING_PLAIN && domain.as_str() != DOMAIN_KEYRING_PLAIN_V3)
    {
        return Err(EncDiscError::RecoveryRejected);
    }
    if domain.as_str() == DOMAIN_KEYRING_PLAIN && bytes.len() > KEYRING_SERIAL_V2_MAX {
        return Err(EncDiscError::KeyringTooLarge);
    }
    let principal = cursor.next_string()?;
    let genesis_epub = cursor.next_string()?;
    let current_pub = cursor.next_string()?;
    let current_priv = cursor.next_string()?;
    let current_epub = cursor.next_string()?;
    let current_epriv = cursor.next_string()?;
    let retired_count = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if retired_count > 1024 {
        return Err(EncDiscError::IdentityRejected("too-many-keys".into()));
    }
    if retired_count.saturating_mul(8) > cursor.remaining() as u64 {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut retired = Vec::with_capacity(retired_count as usize);
    for _ in 0..retired_count {
        let epub = cursor.next_string()?;
        let epriv = cursor.next_string()?;
        retired.push((epub, epriv));
    }
    let lane_id = cursor.next_string()?;
    let prior_count = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if prior_count > KEYRING_HISTORY_MAX as u64 {
        return Err(EncDiscError::KeyringTooLarge);
    }
    if prior_count.saturating_mul(4) > cursor.remaining() as u64 {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut prior_lanes = Vec::with_capacity(prior_count as usize);
    for _ in 0..prior_count {
        prior_lanes.push(cursor.next_string()?);
    }
    let contact_lane_secret = cursor.next_string()?;
    let contact_prior_count = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if contact_prior_count > KEYRING_HISTORY_MAX as u64 {
        return Err(EncDiscError::KeyringTooLarge);
    }
    if contact_prior_count.saturating_mul(4) > cursor.remaining() as u64 {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut prior_contact_secrets = Vec::with_capacity(contact_prior_count as usize);
    for _ in 0..contact_prior_count {
        prior_contact_secrets.push(cursor.next_string()?);
    }
    let content_epoch = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    let rotation_seq = canonical::parse_canonical_decimal(cursor.next_string()?.as_str())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    if rotation_seq > KEYRING_HISTORY_MAX as u64 {
        return Err(EncDiscError::KeyringTooLarge);
    }
    if cursor.remaining() != 0 {
        return Err(EncDiscError::RecoveryRejected);
    }
    Ok(KeyringFields {
        principal,
        genesis_epub,
        current_pub,
        current_priv,
        current_epub,
        current_epriv,
        retired,
        lane_id,
        prior_lanes,
        contact_lane_secret,
        prior_contact_secrets,
        content_epoch,
        rotation_seq,
    })
}

struct Header {
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    rotation_seq: u64,
    salt: Vec<u8>,
    nonce: [u8; RECOVERY_NONCE_LEN],
    ciphertext: Vec<u8>,
}

fn parse_header(bytes: &[u8]) -> Result<Header, EncDiscError> {
    if bytes.len() < RECOVERY_HEADER_LEN || bytes[0] != 1 {
        return Err(EncDiscError::RecoveryRejected);
    }
    let version = read_u32(bytes, 1);
    let memory_kib = read_u32(bytes, 5);
    let iterations = read_u32(bytes, 9);
    let parallelism = read_u32(bytes, 13);
    let hash_length = read_u32(bytes, 17);
    let salt_len = read_u32(bytes, 21);
    let rotation_seq = read_u64(bytes, 25);
    if !params_allowed(
        version,
        memory_kib,
        iterations,
        parallelism,
        hash_length,
        salt_len,
    ) {
        return Err(EncDiscError::RecoveryParams);
    }
    let salt_len = salt_len as usize;
    let salt_end = RECOVERY_HEADER_LEN
        .checked_add(salt_len)
        .ok_or(EncDiscError::RecoveryRejected)?;
    let nonce_end = salt_end
        .checked_add(RECOVERY_NONCE_LEN)
        .ok_or(EncDiscError::RecoveryRejected)?;
    if bytes.len() < nonce_end {
        return Err(EncDiscError::RecoveryRejected);
    }
    let ciphertext = &bytes[nonce_end..];
    if ciphertext.len() > KEYRING_SERIAL_MAX + RECOVERY_TAG_LEN {
        return Err(EncDiscError::KeyringTooLarge);
    }
    if ciphertext.len() < RECOVERY_TAG_LEN {
        return Err(EncDiscError::RecoveryRejected);
    }
    let mut salt = Vec::with_capacity(salt_len);
    salt.extend_from_slice(&bytes[RECOVERY_HEADER_LEN..salt_end]);
    let mut nonce = [0u8; RECOVERY_NONCE_LEN];
    nonce.copy_from_slice(&bytes[salt_end..nonce_end]);
    Ok(Header {
        version,
        memory_kib,
        iterations,
        parallelism,
        hash_length,
        rotation_seq,
        salt,
        nonce,
        ciphertext: ciphertext.to_vec(),
    })
}

fn passphrase_rejected(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            text.chars()
                .any(|ch| !crate::unicode16::assigned(ch as u32))
                || text
                    .chars()
                    .all(|ch| crate::unicode16::passphrase_whitespace(ch as u32))
        }
        Err(_) => false,
    }
}

fn params_allowed(
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    salt_len: u32,
) -> bool {
    in_bound(version, ARGON2ID_LIMITS.version)
        && in_bound(memory_kib, ARGON2ID_LIMITS.memory_kib)
        && in_bound(iterations, ARGON2ID_LIMITS.iterations)
        && in_bound(parallelism, ARGON2ID_LIMITS.parallelism)
        && in_bound(hash_length, ARGON2ID_LIMITS.hash_length)
        && in_bound(salt_len, ARGON2ID_LIMITS.salt_length)
}

fn header_rotation_seq(bytes: &[u8]) -> Result<u64, EncDiscError> {
    if bytes.len() < RECOVERY_HEADER_LEN || bytes[0] != 1 {
        return Err(EncDiscError::StoreRejected);
    }
    Ok(read_u64(bytes, 25))
}

fn write_header(
    out: &mut Vec<u8>,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    salt: &[u8],
    rotation_seq: u64,
) {
    out.push(1);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&memory_kib.to_le_bytes());
    out.extend_from_slice(&iterations.to_le_bytes());
    out.extend_from_slice(&parallelism.to_le_bytes());
    out.extend_from_slice(&hash_length.to_le_bytes());
    out.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    out.extend_from_slice(&rotation_seq.to_le_bytes());
    out.extend_from_slice(salt);
}

fn recovery_aad(
    principal: &str,
    rotation_seq: u64,
    signing_pub: &str,
    epub: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    argon_version: u32,
    salt: &[u8],
) -> Result<Vec<u8>, EncDiscError> {
    let parsed = parse_principal_id(principal).map_err(|_| EncDiscError::RecoveryRejected)?;
    if parsed.as_ref() != principal {
        return Err(EncDiscError::RecoveryRejected);
    }
    let signing = parse_principal_id(signing_pub).map_err(|_| EncDiscError::RecoveryRejected)?;
    if signing.as_ref() != signing_pub {
        return Err(EncDiscError::RecoveryRejected);
    }
    let encryption = parse_principal_id(epub).map_err(|_| EncDiscError::RecoveryRejected)?;
    if encryption.as_ref() != epub {
        return Err(EncDiscError::RecoveryRejected);
    }
    let salt_hex = encode_hex(salt);
    canonical::length_prefixed(&[
        DOMAIN_RECOVERY,
        parsed.as_ref(),
        canonical::canonical_decimal(rotation_seq)?.as_str(),
        signing.as_ref(),
        encryption.as_ref(),
        canonical::canonical_decimal(u64::from(memory_kib))?.as_str(),
        canonical::canonical_decimal(u64::from(iterations))?.as_str(),
        canonical::canonical_decimal(u64::from(parallelism))?.as_str(),
        canonical::canonical_decimal(u64::from(hash_length))?.as_str(),
        canonical::canonical_decimal(u64::from(argon_version))?.as_str(),
        salt_hex.as_str(),
    ])
}

#[cfg(test)]
std::thread_local! {
    static KDF_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
) -> Result<Zeroizing<[u8; 32]>, EncDiscError> {
    #[cfg(test)]
    KDF_CALLS.with(|calls| calls.set(calls.get() + 1));
    if !params_allowed(
        ARGON2ID_LIMITS.version.floor,
        memory_kib,
        iterations,
        parallelism,
        hash_length,
        salt.len() as u32,
    ) || hash_length != 32
    {
        return Err(EncDiscError::RecoveryParams);
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|_| EncDiscError::RecoveryParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    Ok(key)
}

fn aes_encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, EncDiscError> {
    if nonce.len() != RECOVERY_NONCE_LEN {
        return Err(EncDiscError::RecoveryRejected);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::RecoveryRejected)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| EncDiscError::RecoveryRejected)
}

fn aes_decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::RecoveryRejected)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| EncDiscError::RecoveryRejected)?;
    Ok(Zeroizing::new(plain))
}

fn write_field(out: &mut Vec<u8>, field: &str) {
    let raw = field.as_bytes();
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(raw);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn next_string(&mut self) -> Result<Zeroizing<String>, EncDiscError> {
        if self.remaining() < 4 {
            return Err(EncDiscError::RecoveryRejected);
        }
        let len = read_u32(self.bytes, self.offset) as usize;
        self.offset += 4;
        if self.remaining() < len {
            return Err(EncDiscError::RecoveryRejected);
        }
        let field = std::str::from_utf8(&self.bytes[self.offset..self.offset + len])
            .map_err(|_| EncDiscError::RecoveryRejected)?;
        self.offset += len;
        Ok(Zeroizing::new(field.to_string()))
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(raw)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil;
    use crate::identity::KeyWrapStore;
    use crate::limits::RECOVERY_ENVELOPE_MAX;
    use crate::GenesisAccount;
    use serde_json::Value;
    use sociacl_ids::{
        history_state, resolve_current_key, HistoryResolver, Jwks, KeyState, Reason,
        ResolutionContext, Rotate, SiwePolicy,
    };
    use std::collections::{BTreeMap, BTreeSet};

    const RING: &str = include_str!("../../../vectors/encrypted-discovery/account-keyring.json");
    const RECOVERY: &str = include_str!("../../../vectors/encrypted-discovery/recovery-copy.json");
    const RECORDS: &str = include_str!("../../../vectors/ids/records.json");

    fn recovery() -> Value {
        serde_json::from_str(RECOVERY).unwrap()
    }

    fn ring() -> Value {
        serde_json::from_str(RING).unwrap()
    }

    #[test]
    fn argon2id_small_vector_matches_hash_wasm() {
        // m=32 is below the floor. This only checks the library against hash-wasm.
        let params = Params::new(32, 3, 4, Some(32)).unwrap();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(b"password", b"somesalt", &mut out)
            .unwrap();
        assert_eq!(
            encode_hex(&out),
            "bb0cc80a3e671149526915418c6eefe761bb19d5d2d567a017703e0cea6ab05c"
        );
    }

    #[test]
    fn limits_match_the_shared_vector() {
        let v = recovery();
        let limits = &v["limits"];
        assert_eq!(
            limits["version"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.version.floor)
        );
        assert_eq!(
            limits["version"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.version.ceiling)
        );
        assert_eq!(
            limits["memoryKiB"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.memory_kib.floor)
        );
        assert_eq!(
            limits["memoryKiB"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.memory_kib.ceiling)
        );
        assert_eq!(
            limits["iterations"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.iterations.floor)
        );
        assert_eq!(
            limits["iterations"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.iterations.ceiling)
        );
        assert_eq!(
            limits["parallelism"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.parallelism.floor)
        );
        assert_eq!(
            limits["parallelism"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.parallelism.ceiling)
        );
        assert_eq!(
            limits["hashLength"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.hash_length.floor)
        );
        assert_eq!(
            limits["hashLength"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.hash_length.ceiling)
        );
        assert_eq!(
            limits["saltLength"]["floor"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.salt_length.floor)
        );
        assert_eq!(
            limits["saltLength"]["ceiling"].as_u64().unwrap(),
            u64::from(ARGON2ID_LIMITS.salt_length.ceiling)
        );
        assert_eq!(
            limits["keyringSerialMax"].as_u64().unwrap() as usize,
            KEYRING_SERIAL_MAX
        );
        assert_eq!(
            limits["deliveryBlobMax"].as_u64().unwrap() as usize,
            crate::limits::DELIVERY_BLOB_MAX
        );
        assert_eq!(
            limits["recoveryEnvelopeMax"].as_u64().unwrap() as usize,
            RECOVERY_ENVELOPE_MAX
        );
        assert_eq!(
            limits["recoveryAbsoluteMax"].as_u64().unwrap() as usize,
            RECOVERY_ABSOLUTE_MAX
        );
        assert_eq!(
            limits["wrapsPerPrincipal"].as_u64().unwrap() as usize,
            crate::limits::MAX_WRAPS_PER_PRINCIPAL
        );
        assert_eq!(
            v["unicodeVersion"].as_str().unwrap(),
            crate::unicode16::UNICODE_VERSION
        );
        assert_eq!(
            RECOVERY_ABSOLUTE_MAX,
            RECOVERY_ENVELOPE_MAX + ARGON2ID_LIMITS.salt_length.ceiling as usize
        );
        assert_eq!(v["domain"].as_str().unwrap(), DOMAIN_RECOVERY);
        assert_eq!(v["keyringDomain"].as_str().unwrap(), DOMAIN_KEYRING_PLAIN);
        assert_eq!(DOMAIN_KEYRING_PLAIN, "sociacl-keyring-plain-v2");
        assert_eq!(
            v["bindDomain"].as_str().unwrap(),
            crate::delivery::DOMAIN_DELIVERY_BIND
        );
        assert_eq!(
            v["sigDomain"].as_str().unwrap(),
            crate::delivery::DOMAIN_DELIVERY_SIG
        );
    }

    #[test]
    fn keyring_plaintext_v1_is_refused() {
        let mut bytes = Vec::new();
        write_field(&mut bytes, DOMAIN_KEYRING_PLAIN_V1);
        assert!(matches!(
            decode_keyring(&bytes),
            Err(EncDiscError::RecoveryRejected)
        ));
    }

    #[test]
    fn passphrase_strength_matches_the_shared_vector() {
        let v = recovery();
        let gate = &v["passphraseStrength"];
        assert_eq!(gate["error"].as_str().unwrap(), "recovery-weak-passphrase");
        assert_eq!(gate["enforcedAt"].as_str().unwrap(), "seal");
        assert_eq!(gate["open"].as_str().unwrap(), "unchecked");
        assert_eq!(gate["parity"].as_str().unwrap(), "advisory");
        assert_eq!(gate["minVisibleCodePoints"].as_u64().unwrap(), 12);
        assert_eq!(gate["minScore"].as_u64().unwrap(), 3);
        let principal = principal_of();
        for row in gate["cases"].as_array().unwrap() {
            let name = row["name"].as_str().unwrap();
            let text = row["passphrase"].as_str().unwrap();
            let handle = row["handle"].as_str();
            let result = crate::check_recovery_passphrase(text.as_bytes(), &principal, handle);
            if row["result"].as_str().unwrap() == "pass" {
                assert!(result.is_ok(), "{name}");
                continue;
            }
            let err = result.expect_err(name);
            assert_eq!(token(&err), "recovery-weak-passphrase", "{name}");
            let EncDiscError::RecoveryWeakPassphrase {
                score,
                warning,
                suggestions,
            } = &err
            else {
                panic!("{name}");
            };
            assert!(*score < 3, "{name}");
            assert!(!warning.contains(text), "{name}");
            assert!(
                suggestions.iter().all(|item| !item.contains(text)),
                "{name}"
            );
            assert!(!err.to_string().contains(text), "{name}");
            if let Some(expected) = row["score"].as_u64() {
                assert_eq!(u64::from(*score), expected, "{name}");
            }
            if let Some(expected) = row["warning"].as_str() {
                assert_eq!(warning, expected, "{name}");
                assert!(suggestions.is_empty(), "{name}");
            }
        }
        let held = hold();
        let ctx = context_of(&held);
        let keyring = genesis_keyring();
        let mut store = MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new());
        let started = std::time::Instant::now();
        let sealed = seal_recovery_copy_with(
            &keyring,
            b"password",
            &[0x11; 16],
            &[0x22; 12],
            keyring.current_priv(),
            &mut store,
            None,
        )
        .unwrap_err();
        assert!(
            started.elapsed().as_millis() < 200,
            "a weak seal ran the KDF"
        );
        assert_eq!(token(&sealed), "recovery-weak-passphrase");
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_none());
        assert!(encode_passphrase("\u{feff}").is_ok());
        assert!(encode_passphrase("\u{200b}").is_ok());
    }

    #[test]
    fn emoji_presentation_is_retained_in_recovery_key_derivation() {
        let text = "flint-parcel-quantum-marble-92❤️";
        let passphrase = encode_passphrase(text).unwrap();
        assert_eq!(passphrase.as_slice(), text.as_bytes());
        let held = hold();
        let context = context_of(&held);
        let keyring = genesis_keyring();
        let mut store = MemoryRecoveryStore::new(watch(&[], &context), crate::HeadFloor::new());
        let sealed = seal_recovery_copy(&keyring, &passphrase, &mut store, None).unwrap();
        let restored = open_recovery_copy(
            &passphrase, &sealed, keyring.principal(), 0, &[], &context,
        ).unwrap();
        assert_eq!(restored.current_priv(), keyring.current_priv());
        let stripped = encode_passphrase(&text.replace('\u{fe0f}', "")).unwrap();
        assert!(open_recovery_copy(
            &stripped, &sealed, keyring.principal(), 0, &[], &context,
        ).is_err());
    }

    #[test]
    fn store_write_bytes_match_the_shared_vector() {
        let v = recovery();
        let write = &v["storeWrite"];
        assert_eq!(
            write["domain"].as_str().unwrap(),
            crate::store_write::DOMAIN_STORE_WRITE
        );
        assert_eq!(write["chain"].as_str().unwrap(), "store-resolver");
        assert_eq!(
            write["rejectedCommit"].as_str().unwrap(),
            "pending-unchanged"
        );
        assert_eq!(write["fork"].as_str().unwrap(), "store-rejected");
        assert_eq!(write["unpublished"].as_str().unwrap(), "store-rejected");
        let sample = &write["sample"];
        let principal = parse_principal_id(sample["principal"].as_str().unwrap()).unwrap();
        let signing = parse_principal_id(sample["signingPub"].as_str().unwrap()).unwrap();
        let epub = parse_principal_id(sample["epub"].as_str().unwrap()).unwrap();
        let envelope = RecoveryEnvelope {
            principal,
            rotation_seq: sample["seq"].as_u64().unwrap(),
            signing_pub: signing,
            epub,
            bytes: hexutil::decode_hex(sample["bytesHex"].as_str().unwrap()).unwrap(),
        };
        assert_eq!(
            recovery_envelope_hash(&envelope).unwrap(),
            sample["envelopeHash"].as_str().unwrap()
        );
        assert_eq!(
            crate::store_write::wrap_ciphertext_hash(sample["wrapCiphertextHex"].as_str().unwrap())
                .unwrap(),
            sample["wrapCiphertextHash"].as_str().unwrap()
        );
        let row = &sample["wrapRow"];
        let wrap = crate::EncryptedAccountWrap {
            principal: parse_principal_id(row["principal"].as_str().unwrap()).unwrap(),
            wrap_id: sociacl_ids::parse_object_id(row["wrapId"].as_str().unwrap()).unwrap(),
            epub: row["epub"].as_str().unwrap().to_string(),
            class: crate::WrapClass::Delivery,
            ciphertext_hex: row["ciphertextHex"].as_str().unwrap().to_string(),
            signature: row["signature"].as_str().unwrap().to_string(),
        };
        assert_eq!(
            crate::wrap_row_hash(&wrap).unwrap(),
            sample["wrapRowHash"].as_str().unwrap()
        );
        for field in 0..6 {
            let mut changed = wrap.clone();
            match field {
                0 => changed.principal = parse_principal_id(&wrap.epub).unwrap(),
                1 => {
                    changed.wrap_id = sociacl_ids::parse_object_id(&format!(
                        "{}00",
                        &wrap.wrap_id.as_ref()[..wrap.wrap_id.as_ref().len() - 2]
                    ))
                    .unwrap()
                }
                2 => changed.epub.push('a'),
                3 => changed.class = crate::WrapClass::Genesis,
                4 => changed.ciphertext_hex.push_str("00"),
                _ => changed.signature = "cd".repeat(64),
            }
            assert_ne!(
                crate::wrap_row_hash(&changed).unwrap(),
                sample["wrapRowHash"].as_str().unwrap()
            );
        }

        for (name, row) in sample["messages"].as_object().unwrap() {
            let message = crate::store_write::store_write_message(
                sample["principal"].as_str().unwrap(),
                row["operation"].as_str().unwrap(),
                row["target"].as_str().unwrap(),
                row["envelopeHash"].as_str().unwrap(),
                row["head"].as_str().unwrap(),
                row["replaced"].as_str().unwrap(),
                row["class"].as_str().unwrap(),
                row["generation"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(
                hexutil::encode_hex(&message),
                row["messageHex"].as_str().unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn parameter_and_size_rejects_happen_before_the_kdf() {
        let v = recovery();
        let principal = principal_of();
        let held = hold();
        let ctx = context_of(&held);
        for row in v["rejects"].as_array().unwrap() {
            if row["blobBytes"].is_u64() {
                continue;
            }
            let name = row["name"].as_str().unwrap();
            let kdf_calls = KDF_CALLS.with(std::cell::Cell::get);
            let (signing_pub, epub) = genesis_pubs();
            let envelope = if let Some(bytes) = row["envelopeBytes"].as_u64() {
                RecoveryEnvelope {
                    principal: principal.clone(),
                    rotation_seq: 0,
                    signing_pub: signing_pub.clone(),
                    epub: epub.clone(),
                    bytes: vec![0u8; bytes as usize],
                }
            } else if let Some(ciphertext_bytes) = row["ciphertextBytes"].as_u64() {
                crafted(row, ciphertext_bytes as usize, &principal)
            } else {
                crafted(row, 16, &principal)
            };
            let error = open_recovery_copy(b"x", &envelope, &principal, 0, &[], &ctx).unwrap_err();
            assert_eq!(
                KDF_CALLS.with(std::cell::Cell::get),
                kdf_calls,
                "{name} ran the KDF"
            );
            assert_eq!(token(&error), row["error"].as_str().unwrap(), "{name}");
        }
    }

    fn crafted(row: &Value, ciphertext_len: usize, principal: &PrincipalId) -> RecoveryEnvelope {
        let limits = &recovery()["limits"];
        let version = row["version"]
            .as_u64()
            .unwrap_or(limits["version"]["floor"].as_u64().unwrap()) as u32;
        let memory = row["memoryKiB"]
            .as_u64()
            .unwrap_or(limits["memoryKiB"]["floor"].as_u64().unwrap()) as u32;
        let iterations = row["iterations"]
            .as_u64()
            .unwrap_or(limits["iterations"]["floor"].as_u64().unwrap())
            as u32;
        let parallelism = row["parallelism"]
            .as_u64()
            .unwrap_or(limits["parallelism"]["floor"].as_u64().unwrap())
            as u32;
        let hash_length = row["hashLength"]
            .as_u64()
            .unwrap_or(limits["hashLength"]["floor"].as_u64().unwrap())
            as u32;
        let salt = if let Some(hex) = row["saltHex"].as_str() {
            hexutil::decode_hex(hex).unwrap()
        } else {
            vec![0x11; 16]
        };
        let mut bytes = Vec::new();
        write_header(
            &mut bytes,
            version,
            memory,
            iterations,
            parallelism,
            hash_length,
            &salt,
            0,
        );
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&vec![0u8; ciphertext_len]);
        let (signing_pub, epub) = genesis_pubs();
        RecoveryEnvelope {
            principal: principal.clone(),
            rotation_seq: 0,
            signing_pub,
            epub,
            bytes,
        }
    }

    fn token(err: &EncDiscError) -> String {
        match err {
            EncDiscError::RecoveryRejected => "recovery-rejected".into(),
            EncDiscError::RecoveryParams => "recovery-params".into(),
            EncDiscError::RecoveryWeakPassphrase { .. } => "recovery-weak-passphrase".into(),
            EncDiscError::RecoveryStale => "recovery-stale".into(),
            EncDiscError::KeyringTooLarge => "keyring-too-large".into(),
            EncDiscError::StoreRejected => "store-rejected".into(),
            EncDiscError::IdentityRejected(reason) => reason.clone(),
            other => panic!("unexpected {other}"),
        }
    }

    fn principal_of() -> PrincipalId {
        parse_principal_id(ring()["genesis"]["principal"].as_str().unwrap()).unwrap()
    }

    fn genesis_keyring() -> AccountKeyring {
        let g = &ring()["genesis"];
        let account = GenesisAccount::import(
            g["laneId"].as_str().unwrap(),
            g["signingPub"].as_str().unwrap(),
            g["signingPriv"].as_str().unwrap(),
            g["epub"].as_str().unwrap(),
            g["epriv"].as_str().unwrap(),
        )
        .unwrap();
        AccountKeyring::from_genesis_with_contact_secret(
            &account,
            g["contactLaneSecret"].as_str().unwrap(),
        )
        .unwrap()
    }

    struct Hold {
        jwks: Jwks,
        policy: SiwePolicy,
        pinned: BTreeSet<String>,
        links: BTreeMap<String, Value>,
        binding: Vec<Value>,
        revocations: Vec<Value>,
        now: u64,
    }

    fn hold() -> Hold {
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let ctx = &records["context"];
        let ring = ring();
        Hold {
            jwks: serde_json::from_value(ctx["jwks"].clone()).unwrap(),
            policy: serde_json::from_value(ctx["policy"].clone()).unwrap(),
            pinned: ctx["pinnedIss"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect(),
            links: ctx["links"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
                .collect(),
            binding: vec![ring["genesisBinding"].clone()],
            revocations: Vec::new(),
            now: ctx["now"].as_u64().unwrap(),
        }
    }

    fn missing_history(_: &PrincipalId, _: u64, _: u64) -> Result<KeyState, Reason> {
        Err(Reason::MissingHistory)
    }

    fn context_of(hold: &Hold) -> ResolutionContext<'_> {
        ResolutionContext {
            jwks: &hold.jwks,
            links: &hold.links,
            revocations: &hold.revocations,
            now: hold.now,
            policy: &hold.policy,
            pinned_iss: &hold.pinned,
            history: &missing_history,
            genesis_epub_bindings: &hold.binding,
        }
    }

    fn watch<'a>(
        rotations: &'a [Value],
        context: &'a ResolutionContext<'a>,
    ) -> impl Fn(&PrincipalId) -> Result<sociacl_ids::ResolvedAccount, EncDiscError> + 'a {
        move |principal: &PrincipalId| {
            crate::resolve_store_account(principal, rotations, context, &mut Vec::new())
        }
    }

    #[test]
    fn authenticated_store_resolver_skips_poison_and_rejects_forks() {
        let held = hold();
        let context = context_of(&held);
        let fixture: Value = serde_json::from_str(RECORDS).unwrap();
        let principal =
            &sociacl_ids::parse_principal_id(fixture["context"]["genesis"].as_str().unwrap())
                .unwrap();
        let rotations = std::cell::RefCell::new(vec![serde_json::json!({"seq": 1000000})]);
        let diagnostics = std::cell::RefCell::new(Vec::new());
        let store = MemoryRecoveryStore::new(
            |p: &PrincipalId| {
                crate::resolve_store_account(
                    p,
                    &rotations.borrow(),
                    &context,
                    &mut diagnostics.borrow_mut(),
                )
            },
            crate::HeadFloor::new(),
        );
        assert_eq!(
            store.published_account(principal).unwrap().rotations.len(),
            0
        );
        assert!(!diagnostics.borrow().is_empty());
        let fork = fixture["reject"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "forgery-does-not-hide-valid-fork")
            .unwrap();
        *rotations.borrow_mut() = fork["input"].as_array().unwrap().clone();
        let before = diagnostics.borrow().len();
        assert!(matches!(
            store.published_account(principal),
            Err(EncDiscError::StoreRejected)
        ));
        assert!(diagnostics.borrow().len() > before);
        rotations.borrow_mut().clear();
        assert_eq!(
            store.published_account(principal).unwrap().current_key,
            *principal
        );
    }

    #[test]
    fn store_generation_boundaries_preserve_recovery_rows() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../vectors/encrypted-discovery/store-generations.json"
        ))
        .unwrap();
        assert_eq!(
            crate::STORE_GENERATION_MAX,
            fixture["max"].as_u64().unwrap()
        );
        let keyring = genesis_keyring();
        let principal = keyring.principal();
        let held = hold();
        let context = context_of(&held);
        let envelope = dummy_envelope(principal, 0, keyring.current_pub(), keyring.current_epub());
        for row in fixture["cases"].as_array().unwrap() {
            let mut store = MemoryRecoveryStore::new(watch(&[], &context), crate::HeadFloor::new());
            put_as(&mut store, &envelope, keyring.current_priv()).unwrap();
            let generation = row["generation"].as_u64().unwrap();
            store
                .generation
                .insert(principal.as_ref().to_string(), generation);
            let mut changed = envelope.clone();
            *changed.bytes.last_mut().unwrap() ^= 1;
            let signature = crate::sign_store_write(
                keyring.current_priv(),
                principal,
                "put",
                "0",
                &recovery_envelope_hash(&changed).unwrap(),
                "0",
                &recovery_envelope_hash(&envelope).unwrap(),
                crate::STORE_CLASS_NONE,
                &generation.to_string(),
            )
            .unwrap();
            let result = store.put_copy(&changed, &signature);
            if row.get("error").is_some() {
                assert_eq!(result.unwrap_err(), EncDiscError::StoreRejected);
                assert_eq!(
                    store.current_copy(principal).unwrap().unwrap().bytes,
                    envelope.bytes
                );
                assert_eq!(store.write_generation(principal), generation);
            } else {
                result.unwrap();
                assert_eq!(
                    store.current_copy(principal).unwrap().unwrap().bytes,
                    changed.bytes
                );
                assert_eq!(
                    store.write_generation(principal),
                    row["next"].as_u64().unwrap()
                );
                assert_eq!(
                    store.put_copy(&changed, &signature).unwrap_err(),
                    EncDiscError::StoreRejected
                );
            }
        }
    }

    #[test]
    fn exhausted_generation_preserves_recovery_delete_and_commit_slots() {
        let keyring = genesis_keyring();
        let principal = keyring.principal();
        let held = hold();
        let context = context_of(&held);
        let mut store = MemoryRecoveryStore::new(watch(&[], &context), crate::HeadFloor::new());
        let current = dummy_envelope(principal, 0, keyring.current_pub(), keyring.current_epub());
        put_as(&mut store, &current, keyring.current_priv()).unwrap();
        // Model a pending copy at the now-published head. Only the generation
        // guard should prevent promotion; account and signature otherwise match.
        store
            .by_principal
            .get_mut(principal.as_ref())
            .unwrap()
            .pending = Some(current.clone());
        store
            .generation
            .insert(principal.as_ref().to_string(), crate::STORE_GENERATION_MAX);
        let hash = recovery_envelope_hash(&current).unwrap();
        for operation in ["delete", "commit"] {
            let signature = sign_recovery_op(
                &store,
                keyring.current_priv(),
                principal,
                operation,
                0,
                &hash,
                &hash,
            )
            .unwrap();
            let result = if operation == "delete" {
                store.delete_copy(principal, 0, &signature)
            } else {
                store.commit(principal, &signature)
            };
            assert_eq!(result.unwrap_err(), EncDiscError::StoreRejected);
            assert_eq!(
                store.current_copy(principal).unwrap().unwrap().bytes,
                current.bytes
            );
            assert_eq!(
                store.pending_copy(principal).unwrap().unwrap().bytes,
                current.bytes
            );
            assert_eq!(
                store.write_generation(principal),
                crate::STORE_GENERATION_MAX
            );
        }
    }

    #[test]
    fn legacy_backup_opens_after_strength_policy_changes_but_cannot_reseal_weakly() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../vectors/encrypted-discovery/recovery-legacy-strength.json"
        ))
        .unwrap();
        let keyring = genesis_keyring();
        let held = hold();
        let context = context_of(&held);
        let passphrase = fixture["passphraseUtf8"].as_str().unwrap();
        let weak =
            crate::check_recovery_passphrase(passphrase.as_bytes(), keyring.principal(), None)
                .unwrap_err();
        assert_eq!(token(&weak), fixture["sealError"].as_str().unwrap());
        let envelope = RecoveryEnvelope {
            principal: keyring.principal().clone(),
            rotation_seq: 0,
            signing_pub: keyring.current_pub().clone(),
            epub: keyring.current_epub().clone(),
            bytes: hexutil::decode_hex(fixture["envelopeHex"].as_str().unwrap()).unwrap(),
        };
        assert_eq!(fixture["openResult"], "pass");
        let opened =
            open_recovery_copy_str(passphrase, &envelope, keyring.principal(), 0, &[], &context)
                .unwrap();
        assert_eq!(opened.current_priv(), keyring.current_priv());
        assert_eq!(opened.current_epriv(), keyring.current_epriv());
        assert_eq!(opened.contact_lane_secret(), keyring.contact_lane_secret());
        assert_eq!(opened.lane_id(), keyring.lane_id());
        let mut store = MemoryRecoveryStore::new(watch(&[], &context), crate::HeadFloor::new());
        let err = seal_recovery_copy(&opened, passphrase.as_bytes(), &mut store, None).unwrap_err();
        assert_eq!(token(&err), fixture["sealError"].as_str().unwrap());
        assert!(store.current_copy(keyring.principal()).unwrap().is_none());
        let wrong = open_recovery_copy(b"wrong", &envelope, keyring.principal(), 0, &[], &context)
            .unwrap_err();
        assert_eq!(token(&wrong), "recovery-rejected");
    }

    #[test]
    fn recovery_copy_matches_the_shared_vector_and_stays_off_gun() {
        let v = recovery();
        let keyring = genesis_keyring();
        let held = hold();
        let ctx = context_of(&held);
        let mut store = MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new());
        let salt = hexutil::decode_hex(v["saltHex"].as_str().unwrap()).unwrap();
        let nonce = hexutil::decode_hex(v["nonceHex"].as_str().unwrap()).unwrap();
        let envelope = seal_recovery_copy_with(
            &keyring,
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &salt,
            &nonce,
            keyring.current_priv(),
            &mut store,
            None,
        )
        .unwrap();
        let hex = encode_hex(&envelope.bytes);
        let expected = v["envelopeHex"].as_str().unwrap();
        if expected.is_empty() {
            panic!("envelope {hex}");
        }
        assert_eq!(hex, expected);
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_some());
        assert!(!store.is_authority());
        assert!(!store.sees_plaintext());
        assert!(!store.sees_passphrase());
        let opened = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            0,
            &[],
            &ctx,
        )
        .unwrap();
        assert_eq!(opened.principal(), keyring.principal());
        assert_eq!(opened.current_priv(), keyring.current_priv());
        assert_eq!(opened.current_epriv(), keyring.current_epriv());
        assert_eq!(opened.lane_id(), keyring.lane_id());
        assert_eq!(opened.contact_lane_secret(), keyring.contact_lane_secret());
        let gun = opened.gun_document();
        assert!(!gun.contains(keyring.current_priv()));
        assert!(!gun.contains(keyring.current_epriv()));
        assert!(!gun.contains(keyring.lane_id()));
        assert!(!hex.contains(keyring.current_priv()));
        assert!(!hex.contains(keyring.lane_id()));
        assert!(!hex.contains(keyring.contact_lane_secret()));
        assert!(!gun.contains(keyring.contact_lane_secret()));
        let wrong = open_recovery_copy(
            v["wrongPassphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            0,
            &[],
            &ctx,
        )
        .unwrap_err();
        let mut tampered = envelope.clone();
        let last = tampered.bytes.len() - 1;
        tampered.bytes[last] ^= 0x01;
        let tamper = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &tampered,
            keyring.principal(),
            0,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(token(&wrong), token(&tamper));
        assert_eq!(token(&wrong), "recovery-rejected");
        let weak_open =
            open_recovery_copy(b"password", &envelope, keyring.principal(), 0, &[], &ctx)
                .unwrap_err();
        assert_eq!(token(&weak_open), "recovery-rejected");
        let stale = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            1,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(token(&stale), "recovery-stale");
    }

    #[test]
    fn rotation_reseals_a_new_version_and_writes_only_the_adapter() {
        let v = recovery();
        let ring = ring();
        let keyring = genesis_keyring();
        let held = hold();
        let ctx = context_of(&held);
        let mut store = MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new());
        let (signing_pub, epub) = genesis_pubs();
        let old = RecoveryEnvelope {
            principal: keyring.principal().clone(),
            rotation_seq: 0,
            signing_pub,
            epub,
            bytes: hexutil::decode_hex(v["envelopeHex"].as_str().unwrap()).unwrap(),
        };
        put_as(&mut store, &old, keyring.current_priv()).unwrap();
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_some());
        let trusted: Vec<&str> = ring["trusted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect();
        let (rotation, envelope) = rotate_and_reseal(
            &keyring,
            &trusted,
            ring["lost"].as_str().unwrap(),
            &[],
            &ctx,
            || {
                Ok(crate::keyring::RotationMint {
                    signing_pub: ring["mint"]["signingPub"].as_str().unwrap().to_string(),
                    signing_priv: Zeroizing::new(
                        ring["mint"]["signingPriv"].as_str().unwrap().to_string(),
                    ),
                    epub: ring["mint"]["epub"].as_str().unwrap().to_string(),
                    epriv: Zeroizing::new(ring["mint"]["epriv"].as_str().unwrap().to_string()),
                    lane_id: ring["mint"]["laneId"].as_str().unwrap().to_string(),
                    contact_lane_secret: ring["mint"]["contactLaneSecret"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                })
            },
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &mut store,
            None,
        )
        .unwrap();
        assert_eq!(rotation.keyring.rotation_seq(), 1);
        assert_eq!(envelope.rotation_seq, 1);
        assert!(store.get_copy(keyring.principal(), 1).unwrap().is_some());
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_some());
        let unpublished =
            commit_recovery_copy(keyring.principal(), keyring.current_priv(), &mut store)
                .unwrap_err();
        assert_eq!(
            token(&unpublished),
            v["retention"]["commitUnverified"].as_str().unwrap()
        );
        assert!(store.get_copy(keyring.principal(), 1).unwrap().is_some());
        assert!(store.get_copy(keyring.principal(), 0).unwrap().is_some());
        let hex = encode_hex(&envelope.bytes);
        assert!(!hex.contains(rotation.keyring.current_priv()));
        assert!(!hex.contains(rotation.keyring.current_epriv()));
        assert!(!hex.contains(rotation.keyring.lane_id()));
        assert!(!rotation
            .keyring
            .gun_document()
            .contains(rotation.keyring.current_priv()));
        let stale = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &old,
            keyring.principal(),
            1,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(token(&stale), "recovery-stale");
        let imported = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            1,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert!(matches!(imported, EncDiscError::PubMismatch));
    }

    #[test]
    fn the_store_copies_envelopes_and_keeps_only_the_latest() {
        let keyring = genesis_keyring();
        let principal = keyring.principal().clone();
        let held = hold();
        let ctx = context_of(&held);
        let mut store = MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new());
        let mut older =
            dummy_envelope(&principal, 0, keyring.current_pub(), keyring.current_epub());
        let original = older.bytes.clone();
        put_as(&mut store, &older, keyring.current_priv()).unwrap();
        older.bytes[40] ^= 0x01;
        let stored = store.get_copy(&principal, 0).unwrap().unwrap();
        assert_eq!(stored.bytes, original);
        let mut viewed = store.get_copy(&principal, 0).unwrap().unwrap();
        viewed.bytes[40] ^= 0xff;
        assert_eq!(
            store.get_copy(&principal, 0).unwrap().unwrap().bytes,
            original
        );
        let unsigned = store.put_copy(&older, "00");
        assert!(matches!(unsigned, Err(EncDiscError::StoreRejected)));
        assert_eq!(
            store.get_copy(&principal, 0).unwrap().unwrap().bytes,
            original
        );
        let mut resealed =
            dummy_envelope(&principal, 0, keyring.current_pub(), keyring.current_epub());
        resealed.bytes[40] ^= 0x11;
        put_as(&mut store, &resealed, keyring.current_priv()).unwrap();
        assert_eq!(
            store.get_copy(&principal, 0).unwrap().unwrap().bytes,
            resealed.bytes
        );
        assert!(store.get_copy(&principal, 1).unwrap().is_none());
        let pending_pub =
            parse_principal_id(ring()["mint"]["signingPub"].as_str().unwrap()).unwrap();
        let pending_epub = parse_principal_id(ring()["mint"]["epub"].as_str().unwrap()).unwrap();
        let newer = dummy_envelope(&principal, 1, &pending_pub, &pending_epub);
        put_as(&mut store, &newer, keyring.current_priv()).unwrap();
        assert!(store.get_copy(&principal, 0).unwrap().is_some());
        assert!(store.get_copy(&principal, 1).unwrap().is_some());
        assert_eq!(store.len(), 1);
        put_as(&mut store, &resealed, keyring.current_priv()).unwrap();
        assert_eq!(
            store.get_copy(&principal, 0).unwrap().unwrap().bytes,
            resealed.bytes
        );
        assert!(store.get_copy(&principal, 1).unwrap().is_none());
        let poisoned = dummy_envelope(
            &principal,
            99,
            keyring.current_pub(),
            keyring.current_epub(),
        );
        let pinned = put_as(&mut store, &poisoned, keyring.current_priv());
        assert_eq!(
            token(&pinned.unwrap_err()),
            recovery()["retention"]["downgrade"].as_str().unwrap()
        );
        assert!(store.get_copy(&principal, 99).unwrap().is_none());
        put_as(&mut store, &newer, keyring.current_priv()).unwrap();
        assert_eq!(
            store.get_copy(&principal, 1).unwrap().unwrap().bytes,
            newer.bytes
        );
        let mut high = MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new());
        let refused = put_as(
            &mut high,
            &dummy_envelope(&principal, 2, keyring.current_pub(), keyring.current_epub()),
            keyring.current_priv(),
        );
        assert_eq!(
            token(&refused.unwrap_err()),
            recovery()["retention"]["downgrade"].as_str().unwrap()
        );
        assert!(high.get_copy(&principal, 2).unwrap().is_none());
        let mut gap = MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new());
        put_as(
            &mut gap,
            &dummy_envelope(&principal, 0, keyring.current_pub(), keyring.current_epub()),
            keyring.current_priv(),
        )
        .unwrap();
        let skipped = put_as(
            &mut gap,
            &dummy_envelope(&principal, 2, keyring.current_pub(), keyring.current_epub()),
            keyring.current_priv(),
        );
        assert!(matches!(skipped, Err(EncDiscError::StoreRejected)));
        put_as(
            &mut gap,
            &dummy_envelope(&principal, 1, &pending_pub, &pending_epub),
            keyring.current_priv(),
        )
        .unwrap();
        assert!(gap.get_copy(&principal, 0).unwrap().is_some());
        assert!(gap.get_copy(&principal, 1).unwrap().is_some());
        assert!(gap.get_copy(&principal, 2).unwrap().is_none());
    }

    #[test]
    fn composed_and_decomposed_passphrases_derive_the_same_key() {
        let n = &recovery()["normalization"];
        let nfc = encode_passphrase(n["nfc"].as_str().unwrap()).unwrap();
        let nfd = encode_passphrase(n["nfd"].as_str().unwrap()).unwrap();
        assert_eq!(nfc.as_slice(), nfd.as_slice());
        assert_eq!(encode_hex(&nfc), "636166c3a9");
        let salt = hexutil::decode_hex(n["saltHex"].as_str().unwrap()).unwrap();
        let key = derive_key(&nfc, &salt, 65536, 3, 4, 32).unwrap();
        assert_eq!(
            encode_hex(key.as_ref()),
            n["derivedKeyHex"].as_str().unwrap()
        );
        assert!(matches!(
            encode_passphrase("").unwrap_err(),
            EncDiscError::RecoveryParams
        ));
        assert!(matches!(
            encode_passphrase(" \t\n").unwrap_err(),
            EncDiscError::RecoveryParams
        ));
        let vector = recovery();
        let held = hold();
        let ctx = context_of(&held);
        let keyring = genesis_keyring();
        let rejects = vector["passphraseRejects"].as_array().unwrap();
        for row in rejects {
            let text = row["passphrase"].as_str().unwrap();
            let rejected = encode_passphrase(text).unwrap_err();
            assert_eq!(token(&rejected), row["error"].as_str().unwrap(), "{text:?}");
            let bytes = text.as_bytes();
            let sealed = seal_recovery_copy_with(
                &keyring,
                bytes,
                &[0x11; 16],
                &[0x22; 12],
                keyring.current_priv(),
                &mut MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new()),
                None,
            )
            .unwrap_err();
            assert_eq!(token(&sealed), "recovery-params");
        }
        assert_eq!(
            encode_hex(encode_passphrase("\u{feff}").unwrap().as_ref()),
            "efbbbf"
        );
        let spaced = encode_passphrase(" café").unwrap();
        assert_eq!(spaced[0], b' ');
        let started = std::time::Instant::now();
        let rejected = seal_recovery_copy_with(
            &keyring,
            b"   ",
            &[0x11; 16],
            &[0x22; 12],
            keyring.current_priv(),
            &mut MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new()),
            None,
        )
        .unwrap_err();
        assert!(started.elapsed().as_millis() < 200);
        assert!(matches!(rejected, EncDiscError::RecoveryParams));
    }

    #[test]
    fn a_cross_principal_envelope_is_recovery_rejected_before_the_kdf() {
        let v = recovery();
        let principal = principal_of();
        let other = parse_principal_id(ring()["mint"]["signingPub"].as_str().unwrap()).unwrap();
        let held = hold();
        let ctx = context_of(&held);
        let (signing_pub, epub) = genesis_pubs();
        let envelope = RecoveryEnvelope {
            principal: principal.clone(),
            rotation_seq: 0,
            signing_pub,
            epub,
            bytes: hexutil::decode_hex(v["envelopeHex"].as_str().unwrap()).unwrap(),
        };
        let started = std::time::Instant::now();
        let swapped = open_recovery_copy(b"x", &envelope, &other, 0, &[], &ctx).unwrap_err();
        assert!(started.elapsed().as_millis() < 200);
        assert_eq!(token(&swapped), "recovery-rejected");
        let mut both = envelope.clone();
        both.principal = other.clone();
        let ad = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &both,
            &other,
            0,
            &[],
            &ctx,
        )
        .unwrap_err();
        assert_eq!(token(&ad), "recovery-rejected");
    }

    #[test]
    fn a_recovery_copy_opens_after_rotation_against_its_chain() {
        let v = recovery();
        let ring = ring();
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let rotation = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == ring["witnessed"]["rotationName"].as_str().unwrap())
            .unwrap()["input"]
            .clone();
        let (genesis_pub, genesis_priv) =
            scalar_sea(ring["witnessed"]["genesisScalar"].as_u64().unwrap() as u16);
        let (genesis_epub, genesis_epriv) =
            scalar_sea(ring["witnessed"]["genesisEpubScalar"].as_u64().unwrap() as u16);
        let (current_pub, current_priv) =
            scalar_sea(ring["witnessed"]["currentScalar"].as_u64().unwrap() as u16);
        let (current_epub, current_epriv) =
            scalar_sea(ring["witnessed"]["epubScalar"].as_u64().unwrap() as u16);
        let ctx = &records["context"];
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let pinned: BTreeSet<String> = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        let links: BTreeMap<String, Value> = ctx["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
            .collect();
        let authenticated = ctx["authenticatedAccounts"].clone();
        let history = |principal: &PrincipalId, at, until| {
            if !authenticated
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str() == Some(principal.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            let empty: Vec<Rotate> = Vec::new();
            Ok(history_state(principal, &empty, at, until))
        };
        let resolver: &HistoryResolver<'_> = &history;
        let revocations = Vec::new();
        let base = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &revocations,
            now: ctx["now"].as_u64().unwrap(),
            policy: &policy,
            pinned_iss: &pinned,
            history: resolver,
            genesis_epub_bindings: &[],
        };
        let retired = [(genesis_epub.as_str(), genesis_epriv.as_str())];
        let rotations = [rotation];
        let prior = ring["importPriorLanes"]["priorLane"].as_str().unwrap();
        let contact = ring["witnessContact"]["secret"].as_str().unwrap();
        let prior_contact = ring["witnessContact"]["prior"][0].as_str().unwrap();
        let keyring = AccountKeyring::import_with_contact_secrets(
            &genesis_pub,
            &genesis_epub,
            &current_pub,
            current_priv.as_str(),
            &current_epub,
            current_epriv.as_str(),
            &retired,
            ring["witnessed"]["laneId"].as_str().unwrap(),
            ring["witnessed"]["contentEpoch"].as_u64().unwrap(),
            ring["witnessed"]["rotationSeq"].as_u64().unwrap(),
            &rotations,
            &base,
            &[prior],
            contact,
            &[prior_contact],
        )
        .unwrap();
        let mut store = MemoryRecoveryStore::new(watch(&rotations, &base), crate::HeadFloor::new());
        let salt = hexutil::decode_hex(v["saltHex"].as_str().unwrap()).unwrap();
        let nonce = hexutil::decode_hex(v["nonceHex"].as_str().unwrap()).unwrap();
        let envelope = seal_recovery_copy_with(
            &keyring,
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &salt,
            &nonce,
            keyring.current_priv(),
            &mut store,
            None,
        )
        .unwrap();
        let opened = open_recovery_copy_str(
            v["passphraseUtf8"].as_str().unwrap(),
            &envelope,
            keyring.principal(),
            1,
            &rotations,
            &base,
        )
        .unwrap();
        assert_eq!(opened.rotation_seq(), 1);
        assert_eq!(opened.current_priv(), keyring.current_priv());
        let unsigned = open_recovery_copy(
            v["passphraseUtf8"].as_str().unwrap().as_bytes(),
            &envelope,
            keyring.principal(),
            1,
            &[],
            &base,
        )
        .unwrap_err();
        assert!(matches!(unsigned, EncDiscError::PubMismatch));
        let genesis_point = parse_principal_id(&genesis_pub).unwrap();
        let genesis_encryption = parse_principal_id(&genesis_epub).unwrap();
        let current_point = parse_principal_id(&current_pub).unwrap();
        let current_encryption = parse_principal_id(&current_epub).unwrap();
        let published = std::cell::RefCell::new(Vec::<Value>::new());
        let chain = |principal: &PrincipalId| {
            let held = published.borrow();
            resolve_current_key(principal, held.as_slice(), &base)
                .result
                .map_err(|_| EncDiscError::StoreRejected)
        };
        let mut forward = MemoryRecoveryStore::new(chain, crate::HeadFloor::new());
        put_as(
            &mut forward,
            &dummy_envelope(keyring.principal(), 0, &genesis_point, &genesis_encryption),
            genesis_priv.as_str(),
        )
        .unwrap();
        put_as(
            &mut forward,
            &dummy_envelope(keyring.principal(), 1, &current_point, &current_encryption),
            genesis_priv.as_str(),
        )
        .unwrap();
        published.replace(rotations.to_vec());
        commit_recovery_copy(keyring.principal(), keyring.current_priv(), &mut forward).unwrap();
        assert!(forward.get_copy(keyring.principal(), 0).unwrap().is_none());
        assert!(forward.get_copy(keyring.principal(), 1).unwrap().is_some());
        let again = commit_recovery_copy(keyring.principal(), keyring.current_priv(), &mut forward);
        assert!(matches!(again, Err(EncDiscError::StoreRejected)));
        assert!(forward.get_copy(keyring.principal(), 1).unwrap().is_some());
        let older = put_as(
            &mut forward,
            &dummy_envelope(keyring.principal(), 0, &genesis_point, &genesis_encryption),
            genesis_priv.as_str(),
        );
        assert!(matches!(older, Err(EncDiscError::StoreRejected)));
        let mut stuck = MemoryRecoveryStore::new(watch(&[], &base), crate::HeadFloor::new());
        put_as(
            &mut stuck,
            &dummy_envelope(keyring.principal(), 0, &genesis_point, &genesis_encryption),
            genesis_priv.as_str(),
        )
        .unwrap();
        put_as(
            &mut stuck,
            &dummy_envelope(keyring.principal(), 1, &current_point, &current_encryption),
            genesis_priv.as_str(),
        )
        .unwrap();
        let unverified =
            commit_recovery_copy(keyring.principal(), genesis_priv.as_str(), &mut stuck);
        assert!(matches!(unverified, Err(EncDiscError::StoreRejected)));
        assert!(stuck.get_copy(keyring.principal(), 0).unwrap().is_some());
        assert!(stuck.get_copy(keyring.principal(), 1).unwrap().is_some());
        delete_recovery_copy(keyring.principal(), 1, genesis_priv.as_str(), &mut stuck).unwrap();
        assert!(stuck.get_copy(keyring.principal(), 0).unwrap().is_some());
        assert!(stuck.get_copy(keyring.principal(), 1).unwrap().is_none());
        let fork_chain = std::cell::RefCell::new(Vec::<Value>::new());
        let chain = |principal: &PrincipalId| {
            let held = fork_chain.borrow();
            resolve_current_key(principal, held.as_slice(), &base)
                .result
                .map_err(|_| EncDiscError::StoreRejected)
        };
        let mut fork = MemoryRecoveryStore::new(chain, crate::HeadFloor::new());
        put_as(
            &mut fork,
            &dummy_envelope(keyring.principal(), 0, &genesis_point, &genesis_encryption),
            genesis_priv.as_str(),
        )
        .unwrap();
        let minted = parse_principal_id(ring["mint"]["signingPub"].as_str().unwrap()).unwrap();
        let minted_epub = parse_principal_id(ring["mint"]["epub"].as_str().unwrap()).unwrap();
        put_as(
            &mut fork,
            &dummy_envelope(keyring.principal(), 1, &minted, &minted_epub),
            genesis_priv.as_str(),
        )
        .unwrap();
        fork_chain.replace(rotations.to_vec());
        let forked = commit_recovery_copy(keyring.principal(), keyring.current_priv(), &mut fork);
        assert!(matches!(forked, Err(EncDiscError::StoreRejected)));
        assert!(fork.get_copy(keyring.principal(), 0).unwrap().is_some());
        assert!(fork.get_copy(keyring.principal(), 1).unwrap().is_some());
    }

    #[test]
    fn retired_keys_cannot_write_and_replays_do_not_restore() {
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let chain: Vec<Value> = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "probe-v3-then-v3")
            .unwrap()["input"]
            .as_array()
            .unwrap()
            .clone();
        let (k0_pub, k0_priv) = scalar_sea(1);
        let (k1_pub, k1_priv) = scalar_sea(2);
        let (k2_pub, k2_priv) = scalar_sea(3);
        let (e1_pub, _) = scalar_sea(6);
        let (e2_pub, _) = scalar_sea(7);
        assert_eq!(k0_pub, records["context"]["genesis"].as_str().unwrap());
        assert_eq!(k1_pub, chain[0]["nextKey"].as_str().unwrap());
        assert_eq!(e1_pub, chain[0]["nextEpub"].as_str().unwrap());
        assert_eq!(k2_pub, chain[1]["nextKey"].as_str().unwrap());
        assert_eq!(e2_pub, chain[1]["nextEpub"].as_str().unwrap());
        let ctx = &records["context"];
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let pinned: BTreeSet<String> = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        let links: BTreeMap<String, Value> = ctx["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
            .collect();
        let authenticated = ctx["authenticatedAccounts"].clone();
        let history = |principal: &PrincipalId, at, until| {
            if !authenticated
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str() == Some(principal.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            let empty: Vec<Rotate> = Vec::new();
            Ok(history_state(principal, &empty, at, until))
        };
        let resolver: &HistoryResolver<'_> = &history;
        let revocations = Vec::new();
        let base = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &revocations,
            now: ctx["now"].as_u64().unwrap(),
            policy: &policy,
            pinned_iss: &pinned,
            history: resolver,
            genesis_epub_bindings: &[],
        };
        let principal = parse_principal_id(&k0_pub).unwrap();
        let k0 = principal.clone();
        let k1 = parse_principal_id(&k1_pub).unwrap();
        let k2 = parse_principal_id(&k2_pub).unwrap();
        let e1 = parse_principal_id(&e1_pub).unwrap();
        let e2 = parse_principal_id(&e2_pub).unwrap();

        let mut honest = MemoryRecoveryStore::new(watch(&chain, &base), crate::HeadFloor::new());
        let current = dummy_envelope(&principal, 2, &k2, &e2);
        put_as(&mut honest, &current, k0_priv.as_str()).unwrap_err();
        put_as(&mut honest, &current, k2_priv.as_str()).unwrap();
        assert!(matches!(
            delete_recovery_copy(&principal, 2, k0_priv.as_str(), &mut honest).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert!(matches!(
            delete_recovery_copy(&principal, 2, k1_priv.as_str(), &mut honest).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(
            honest.get_copy(&principal, 2).unwrap().unwrap().bytes,
            current.bytes
        );
        assert!(matches!(
            put_as(
                &mut honest,
                &dummy_envelope(&principal, 0, &k0, &k0),
                k0_priv.as_str(),
            )
            .unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(
            honest.get_copy(&principal, 2).unwrap().unwrap().bytes,
            current.bytes
        );

        let published = std::cell::RefCell::new(chain.clone());
        let floor_chain = |principal: &PrincipalId| {
            let held = published.borrow();
            resolve_current_key(principal, held.as_slice(), &base)
                .result
                .map_err(|_| EncDiscError::StoreRejected)
        };
        let mut floored = MemoryRecoveryStore::new(floor_chain, crate::HeadFloor::new());
        put_as(&mut floored, &current, k2_priv.as_str()).unwrap();
        let generation = floored.write_generation(&principal);
        let hash = recovery_envelope_hash(&current).unwrap();
        published.replace(Vec::new());
        let short = resolve_current_key(&principal, &[], &base).result.unwrap();
        let signature = sign_store_write(
            k0_priv.as_str(),
            &principal,
            "delete",
            "2",
            &hash,
            "0",
            &hash,
            crate::store_write::STORE_CLASS_NONE,
            &crate::store_write::decimal(generation).unwrap(),
        )
        .unwrap();
        verify_store_write(
            &principal,
            "delete",
            "2",
            &hash,
            "0",
            &hash,
            crate::store_write::STORE_CLASS_NONE,
            &crate::store_write::decimal(generation).unwrap(),
            &signature,
            &short,
        )
        .unwrap();
        assert!(matches!(
            floored.delete_copy(&principal, 2, &signature).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert!(floored.get_copy(&principal, 2).unwrap().is_some());

        let mid = std::cell::RefCell::new(vec![chain[0].clone()]);
        let mid_chain = |principal: &PrincipalId| {
            let held = mid.borrow();
            resolve_current_key(principal, held.as_slice(), &base)
                .result
                .map_err(|_| EncDiscError::StoreRejected)
        };
        let mut between = MemoryRecoveryStore::new(mid_chain, crate::HeadFloor::new());
        let kept = dummy_envelope(&principal, 1, &k1, &e1);
        put_as(&mut between, &kept, k1_priv.as_str()).unwrap();
        let mut waiting = dummy_envelope(&principal, 2, &k2, &e2);
        waiting.bytes[40] = 0x21;
        put_as(&mut between, &waiting, k1_priv.as_str()).unwrap();
        mid.replace(chain.clone());
        let mut stolen = dummy_envelope(&principal, 1, &k1, &e1);
        stolen.bytes[40] = 0x99;
        assert!(matches!(
            put_as(&mut between, &stolen, k1_priv.as_str()).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(
            between.get_copy(&principal, 1).unwrap().unwrap().bytes,
            kept.bytes
        );
        assert_eq!(
            between.get_copy(&principal, 2).unwrap().unwrap().bytes,
            waiting.bytes
        );

        let mut early = MemoryRecoveryStore::new(watch(&chain[..1], &base), crate::HeadFloor::new());
        put_as(&mut early, &kept, k1_priv.as_str()).unwrap();
        put_as(&mut early, &waiting, k1_priv.as_str()).unwrap();
        let early_account = early.published_account(&principal).unwrap();
        let early_gen = early.write_generation(&principal);
        let replaced = recovery_envelope_hash(&kept).unwrap();
        let attack_hash = recovery_envelope_hash(&stolen).unwrap();
        let early_sig = sign_store_write(
            k1_priv.as_str(),
            &principal,
            "put",
            "1",
            &attack_hash,
            "1",
            &replaced,
            crate::store_write::STORE_CLASS_NONE,
            &crate::store_write::decimal(early_gen).unwrap(),
        )
        .unwrap();
        verify_store_write(
            &principal,
            "put",
            "1",
            &attack_hash,
            "1",
            &replaced,
            crate::store_write::STORE_CLASS_NONE,
            &crate::store_write::decimal(early_gen).unwrap(),
            &early_sig,
            &early_account,
        )
        .unwrap();
        early.put_copy(&stolen, &early_sig).unwrap();
        assert_eq!(
            early.get_copy(&principal, 1).unwrap().unwrap().bytes,
            stolen.bytes
        );
        assert!(early.get_copy(&principal, 2).unwrap().is_none());

        let mut live = MemoryRecoveryStore::new(watch(&chain, &base), crate::HeadFloor::new());
        let mut first = dummy_envelope(&principal, 2, &k2, &e2);
        first.bytes[40] = 0x11;
        let sig1 = sign_recovery_put(&live, k2_priv.as_str(), &first).unwrap();
        live.put_copy(&first, &sig1).unwrap();
        let mut second = first.clone();
        second.bytes[40] = 0x22;
        put_as(&mut live, &second, k2_priv.as_str()).unwrap();
        assert!(matches!(
            live.put_copy(&first, &sig1).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(
            live.get_copy(&principal, 2).unwrap().unwrap().bytes[40],
            0x22
        );
        delete_recovery_copy(&principal, 2, k2_priv.as_str(), &mut live).unwrap();
        assert!(live.get_copy(&principal, 2).unwrap().is_none());
        assert!(matches!(
            live.put_copy(&first, &sig1).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert!(live.get_copy(&principal, 2).unwrap().is_none());

        let stage = std::cell::RefCell::new(Vec::<Value>::new());
        let staged = |principal: &PrincipalId| {
            let held = stage.borrow();
            resolve_current_key(principal, held.as_slice(), &base)
                .result
                .map_err(|_| EncDiscError::StoreRejected)
        };
        let mut pending_store = MemoryRecoveryStore::new(staged, crate::HeadFloor::new());
        put_as(
            &mut pending_store,
            &dummy_envelope(&principal, 0, &k0, &k0),
            k0_priv.as_str(),
        )
        .unwrap();
        let mut captured_env = dummy_envelope(&principal, 1, &k1, &e1);
        captured_env.bytes[40] = 0x44;
        let captured = sign_recovery_put(&pending_store, k0_priv.as_str(), &captured_env).unwrap();
        pending_store.put_copy(&captured_env, &captured).unwrap();
        stage.replace(vec![chain[0].clone()]);
        let mut reseal = dummy_envelope(&principal, 1, &k1, &e1);
        reseal.bytes[40] = 0x55;
        put_as(&mut pending_store, &reseal, k1_priv.as_str()).unwrap();
        assert!(pending_store.get_copy(&principal, 0).unwrap().is_none());
        assert_eq!(
            pending_store
                .get_copy(&principal, 1)
                .unwrap()
                .unwrap()
                .bytes[40],
            0x55
        );
        assert!(matches!(
            pending_store
                .put_copy(&captured_env, &captured)
                .unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert!(matches!(
            commit_recovery_copy(&principal, k1_priv.as_str(), &mut pending_store).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(
            pending_store
                .get_copy(&principal, 1)
                .unwrap()
                .unwrap()
                .bytes[40],
            0x55
        );

        let lag = std::cell::RefCell::new(Vec::<Value>::new());
        let lagged = |principal: &PrincipalId| {
            let held = lag.borrow();
            resolve_current_key(principal, held.as_slice(), &base)
                .result
                .map_err(|_| EncDiscError::StoreRejected)
        };
        let mut rejected_commit = MemoryRecoveryStore::new(lagged, crate::HeadFloor::new());
        let genesis_row = dummy_envelope(&principal, 0, &k0, &k0);
        put_as(&mut rejected_commit, &genesis_row, k0_priv.as_str()).unwrap();
        let mut old_pending = dummy_envelope(&principal, 1, &k1, &e1);
        old_pending.bytes[40] = 0x66;
        put_as(&mut rejected_commit, &old_pending, k0_priv.as_str()).unwrap();
        lag.replace(chain.clone());
        assert!(matches!(
            commit_recovery_copy(&principal, k2_priv.as_str(), &mut rejected_commit).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(
            rejected_commit
                .get_copy(&principal, 0)
                .unwrap()
                .unwrap()
                .bytes,
            genesis_row.bytes
        );
        assert_eq!(
            rejected_commit
                .get_copy(&principal, 1)
                .unwrap()
                .unwrap()
                .bytes[40],
            0x66
        );
        let mut recovered = dummy_envelope(&principal, 2, &k2, &e2);
        recovered.bytes[40] = 0x77;
        put_as(&mut rejected_commit, &recovered, k2_priv.as_str()).unwrap();
        assert_eq!(
            rejected_commit
                .get_copy(&principal, 2)
                .unwrap()
                .unwrap()
                .bytes[40],
            0x77
        );
        assert!(rejected_commit.get_copy(&principal, 1).unwrap().is_none());
        assert!(rejected_commit.get_copy(&principal, 0).unwrap().is_none());
    }

    #[test]
    fn an_abandoned_pending_copy_does_not_freeze_recovery_writes() {
        let held = hold();
        let ctx = context_of(&held);
        let keyring = genesis_keyring();
        let (signing, encryption) = genesis_pubs();
        let mut store = MemoryRecoveryStore::new(watch(&[], &ctx), crate::HeadFloor::new());
        let current = dummy_envelope(keyring.principal(), 0, &signing, &encryption);
        put_as(&mut store, &current, keyring.current_priv()).unwrap();
        let mut pending = dummy_envelope(keyring.principal(), 1, &signing, &encryption);
        pending.bytes[40] = 0x21;
        put_as(&mut store, &pending, keyring.current_priv()).unwrap();
        delete_recovery_copy(keyring.principal(), 1, keyring.current_priv(), &mut store).unwrap();
        assert_eq!(
            store
                .get_copy(keyring.principal(), 0)
                .unwrap()
                .unwrap()
                .bytes,
            current.bytes
        );
        assert!(store.get_copy(keyring.principal(), 1).unwrap().is_none());
        let mut replaced = pending.clone();
        replaced.bytes[40] = 0x22;
        put_as(&mut store, &replaced, keyring.current_priv()).unwrap();
        assert_eq!(
            store
                .get_copy(keyring.principal(), 1)
                .unwrap()
                .unwrap()
                .bytes[40],
            0x22
        );
        let mut passphrase_change = current.clone();
        passphrase_change.bytes[40] = 0x33;
        put_as(&mut store, &passphrase_change, keyring.current_priv()).unwrap();
        assert_eq!(
            store
                .get_copy(keyring.principal(), 0)
                .unwrap()
                .unwrap()
                .bytes[40],
            0x33
        );
        assert!(store.get_copy(keyring.principal(), 1).unwrap().is_none());
    }

    #[test]
    fn a_resolved_head_raises_the_shared_floor() {
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let chain: Vec<Value> = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "probe-v3-then-v3")
            .unwrap()["input"]
            .as_array()
            .unwrap()
            .clone();
        let (k0_pub, k0_priv) = scalar_sea(1);
        let ctx = &records["context"];
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let pinned: BTreeSet<String> = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        let links: BTreeMap<String, Value> = ctx["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
            .collect();
        let authenticated = ctx["authenticatedAccounts"].clone();
        let history = |principal: &PrincipalId, at, until| {
            if !authenticated
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str() == Some(principal.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            let empty: Vec<Rotate> = Vec::new();
            Ok(history_state(principal, &empty, at, until))
        };
        let resolver: &HistoryResolver<'_> = &history;
        let revocations = Vec::new();
        let base = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &revocations,
            now: ctx["now"].as_u64().unwrap(),
            policy: &policy,
            pinned_iss: &pinned,
            history: resolver,
            genesis_epub_bindings: &[],
        };
        let principal = parse_principal_id(&k0_pub).unwrap();
        let published = std::cell::RefCell::new(chain.clone());
        let seen = |principal: &PrincipalId| {
            let held = published.borrow();
            resolve_current_key(principal, held.as_slice(), &base)
                .result
                .map_err(|_| EncDiscError::StoreRejected)
        };
        let floor = crate::HeadFloor::new();
        let mut recovery = MemoryRecoveryStore::new(seen, floor.clone());
        let envelope = dummy_envelope(
            &principal,
            2,
            &parse_principal_id(chain[1]["nextKey"].as_str().unwrap()).unwrap(),
            &parse_principal_id(chain[1]["nextEpub"].as_str().unwrap()).unwrap(),
        );
        let bogus = crate::store_write::sign_store_write(
            k0_priv.as_str(),
            &principal,
            "put",
            "2",
            &recovery_envelope_hash(&envelope).unwrap(),
            "2",
            crate::store_write::REPLACED_NONE,
            crate::store_write::STORE_CLASS_NONE,
            "0",
        )
        .unwrap();
        assert!(matches!(
            recovery.put_copy(&envelope, &bogus).unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(recovery.write_generation(&principal), 0);
        assert!(recovery.get_copy(&principal, 2).unwrap().is_none());
        published.replace(Vec::new());
        assert!(matches!(
            put_as(
                &mut recovery,
                &dummy_envelope(&principal, 0, &principal, &principal),
                k0_priv.as_str(),
            )
            .unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert_eq!(recovery.write_generation(&principal), 0);

        let mut wraps = crate::MemoryKeyWrapStore::new(watch(&[], &base), floor);
        let wrap_id =
            sociacl_ids::parse_object_id("wrap_p_60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299_00112233445566778899aabbccddee11").unwrap();
        let wrap = crate::EncryptedAccountWrap {
            principal: principal.clone(),
            wrap_id: wrap_id.clone(),
            epub: chain[0]["nextEpub"].as_str().unwrap().to_string(),
            ciphertext_hex: "aa".to_string(),
            signature: "ab".repeat(64),
            class: crate::WrapClass::Delivery,
        };
        let hash = crate::store_write::wrap_row_hash(&wrap).unwrap();
        let signature = crate::store_write::sign_store_write(
            k0_priv.as_str(),
            &principal,
            "put",
            wrap_id.as_ref(),
            &hash,
            "0",
            crate::store_write::REPLACED_NONE,
            crate::store_write::STORE_CLASS_DELIVERY,
            "0",
        )
        .unwrap();
        assert!(matches!(
            wraps
                .put_wrap(
                    &crate::WrapIndex {
                        principal: principal.clone(),
                        wrap_id: wrap_id.clone(),
                        epub: wrap.epub.clone(),
                    },
                    &wrap,
                    &signature,
                )
                .unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert!(wraps.list_wraps(&principal).unwrap().is_empty());
        assert_eq!(wraps.write_generation(&principal), 0);

        let shared = crate::HeadFloor::new();
        let long = watch(&chain, &base);
        let wrap_seen = crate::MemoryKeyWrapStore::new(long, shared.clone());
        wrap_seen.published_account(&principal).unwrap();
        assert_eq!(wrap_seen.write_generation(&principal), 0);
        let mut recovery_stale = MemoryRecoveryStore::new(watch(&[], &base), shared);
        assert!(matches!(
            put_as(
                &mut recovery_stale,
                &dummy_envelope(&principal, 0, &principal, &principal),
                k0_priv.as_str(),
            )
            .unwrap_err(),
            EncDiscError::StoreRejected
        ));
        assert!(recovery_stale.get_copy(&principal, 0).unwrap().is_none());
        assert_eq!(recovery_stale.write_generation(&principal), 0);
    }

    fn dummy_envelope(
        principal: &PrincipalId,
        seq: u64,
        signing_pub: &PrincipalId,
        epub: &PrincipalId,
    ) -> RecoveryEnvelope {
        let mut bytes = Vec::new();
        write_header(&mut bytes, 0x13, 65536, 3, 4, 32, &[0x11; 16], seq);
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&[0u8; 16]);
        RecoveryEnvelope {
            principal: principal.clone(),
            rotation_seq: seq,
            signing_pub: signing_pub.clone(),
            epub: epub.clone(),
            bytes,
        }
    }

    fn genesis_pubs() -> (PrincipalId, PrincipalId) {
        let keyring = genesis_keyring();
        (
            keyring.current_pub().clone(),
            keyring.current_epub().clone(),
        )
    }

    fn put_as<C: crate::store_write::PublishedChain>(
        store: &mut MemoryRecoveryStore<C>,
        envelope: &RecoveryEnvelope,
        signer: &str,
    ) -> Result<(), EncDiscError> {
        let signature = sign_recovery_put(store, signer, envelope)?;
        store.put_copy(envelope, &signature)
    }

    fn scalar_sea(n: u16) -> (String, Zeroizing<String>) {
        let mut bytes = [0u8; 32];
        bytes[30] = (n >> 8) as u8;
        bytes[31] = n as u8;
        let secret = p256::SecretKey::from_slice(&bytes).unwrap();
        bytes.zeroize();
        (
            crate::sea::sea_pub_from_secret(&secret).unwrap(),
            crate::sea::sea_priv_from_secret(&secret).unwrap(),
        )
    }

    #[test]
    fn shared_codec_history_bounds_reject_counts_before_payload() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../vectors/encrypted-discovery/keyring-history-import.json"
        )).unwrap();
        for row in fixture["codecCases"].as_array().unwrap() {
            let lanes = row["laneCount"].as_u64().unwrap();
            let contacts = row["contactCount"].as_u64().unwrap();
            let mut bytes = Vec::new();
            for field in [DOMAIN_KEYRING_PLAIN, "principal", "genesisEpub", "pub", "priv", "epub", "epriv", "0", "lane"] {
                write_field(&mut bytes, field);
            }
            write_field(&mut bytes, &lanes.to_string());
            if row["truncateAfter"] != "lanes" {
                for i in 1..=lanes {
                    write_field(&mut bytes, &format!("{i:064x}"));
                }
                write_field(&mut bytes, "contact");
                write_field(&mut bytes, &contacts.to_string());
                if row["truncateAfter"] != "contacts" {
                    for i in 1025..1025 + contacts {
                        write_field(&mut bytes, &format!("{i:064x}"));
                    }
                    write_field(&mut bytes, "0");
                    write_field(&mut bytes, &row["rotationSeq"].as_u64().unwrap().to_string());
                }
            }
            let result = decode_keyring(&bytes);
            if let Some(expected) = row["error"].as_str() {
                let Err(error) = result else { panic!("{} accepted", row["name"]); };
                assert_eq!(token(&error), expected, "{}", row["name"]);
            } else {
                // Structural decoding; import separately authenticates keys and history.
                let decoded = result.unwrap();
                assert_eq!(decoded.prior_lanes.len(), KEYRING_HISTORY_MAX);
                assert_eq!(decoded.prior_contact_secrets.len(), KEYRING_HISTORY_MAX);
                assert_eq!(decoded.rotation_seq, KEYRING_HISTORY_MAX as u64);
            }
        }
    }


    #[test]
    fn shared_versioned_plaintext_caps_precede_key_material_validation() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../vectors/encrypted-discovery/keyring-capacity.json"
        ))
        .unwrap();
        for row in fixture["boundaryCases"].as_array().unwrap() {
            let domain = row["domain"].as_str().unwrap();
            let size = row["bytes"].as_u64().unwrap() as usize;
            let mut fields: Vec<String> = [
                domain,
                "principal",
                "genesis",
                "pub",
                "",
                "epub",
                "epriv",
                "0",
                "lane",
                "0",
                "contact",
                "0",
                "0",
                "0",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            let base: usize = fields.iter().map(|s| 4 + s.len()).sum();
            fields[4] = "x".repeat(size - base);
            let mut bytes = Vec::new();
            for field in &fields {
                write_field(&mut bytes, field);
            }
            assert_eq!(bytes.len(), size);
            let result = decode_keyring(&bytes);
            if let Some(expected) = row["error"].as_str() {
                let Err(error) = result else {
                    panic!("accepted {domain} size {size}");
                };
                assert_eq!(token(&error), expected);
            } else {
                assert_eq!(result.unwrap().current_priv.len(), size - base);
            }
        }
    }

}
