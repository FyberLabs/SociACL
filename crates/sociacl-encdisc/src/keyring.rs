//! Account keyring.
//!
//! Holds the current signing key, the current encryption key, the retired
//! encryption keys, and the one lane id for this account. The account id
//! stays the genesis signing pub. Import checks that pair against
//! `resolve_current_key`. A null `current_epub` is not a match and is not
//! Gun's `user.epub`. New rotations are v3 and mint a fresh epub.

use sociacl_ids::{
    parse_eip55, parse_principal_id, principal_from_sec1, user_soul, PrincipalId, Reason,
};
use zeroize::{Zeroize, Zeroizing};

use crate::account::{self, require_lane, EnrolledSeaPub};
use crate::error::EncDiscError;
use crate::sea::{self, uncompressed_point};
use crate::wrap::{self, ItemDek, NamedSet, OpenedWrap, WrappedKey};

/// An encryption scalar kept so ciphertext wrapped to a retired epub still opens.
#[derive(Clone)]
pub struct RetiredEpriv {
    epub: PrincipalId,
    epriv: Zeroizing<String>,
}

impl RetiredEpriv {
    pub fn epub(&self) -> &PrincipalId {
        &self.epub
    }

    /// Device-local. Never write this to Gun.
    pub fn epriv(&self) -> &str {
        self.epriv.as_str()
    }
}

impl std::fmt::Debug for RetiredEpriv {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetiredEpriv")
            .field("epub", &self.epub)
            .field("epriv", &"<redacted>")
            .finish()
    }
}

/// Current keys, retired encryption keys, and the one lane this keyring holds.
#[derive(Clone)]
pub struct AccountKeyring {
    principal: PrincipalId,
    genesis_epub: PrincipalId,
    current_pub: PrincipalId,
    current_priv: Zeroizing<String>,
    current_epub: PrincipalId,
    current_epriv: Zeroizing<String>,
    retired: Vec<RetiredEpriv>,
    lane_id: String,
    content_epoch: u64,
    rotation_seq: u64,
}

/// Fresh material for one rotation. The builder rejects an epub it already holds.
pub struct RotationMint {
    pub signing_pub: String,
    pub signing_priv: Zeroizing<String>,
    pub epub: String,
    pub epriv: Zeroizing<String>,
    pub lane_id: String,
}

/// Unsigned v3 rotation fields. `next_epub` is always present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationDraft {
    pub principal: PrincipalId,
    pub seq: u64,
    pub prev_key: PrincipalId,
    pub next_key: PrincipalId,
    pub next_epub: PrincipalId,
}

impl RotationDraft {
    /// New rotations are v3. There is no v2 constructor.
    pub fn version(&self) -> u8 {
        3
    }

    /// Public fields only. No scalar.
    pub fn document(&self) -> String {
        format!(
            "{{\"v\":1,\"kind\":\"rotate\",\"principal\":{},\"seq\":{},\"prevKey\":{},\"nextKey\":{},\"nextEpub\":{}}}",
            account::json_string(self.principal.as_ref()),
            self.seq,
            account::json_string(self.prev_key.as_ref()),
            account::json_string(self.next_key.as_ref()),
            account::json_string(self.next_epub.as_ref()),
        )
    }
}

/// A device that received the rotated keyring. The lost device is not one of these.
#[derive(Clone)]
pub struct KeyringDevice {
    local_id: String,
    keyring: AccountKeyring,
}

impl KeyringDevice {
    pub fn local_id(&self) -> &str {
        &self.local_id
    }

    pub fn keyring(&self) -> &AccountKeyring {
        &self.keyring
    }

    /// Re-enrollment does not mint a grant.
    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn gun_document(&self) -> String {
        self.keyring.gun_document()
    }
}

impl std::fmt::Debug for KeyringDevice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyringDevice")
            .field("local_id", &self.local_id)
            .field("keyring", &self.keyring)
            .finish()
    }
}

/// The rotated keyring, the devices that still hold it, and the v3 draft.
#[derive(Debug)]
pub struct KeyringRotation {
    pub keyring: AccountKeyring,
    pub devices: Vec<KeyringDevice>,
    pub draft: RotationDraft,
    pub lost_local_id: String,
}

impl AccountKeyring {
    /// Local constructor for a new account. Does not ask the witness.
    /// Import is the path that checks `resolve_current_key`.
    pub fn from_genesis(account: &crate::GenesisAccount) -> Result<Self, EncDiscError> {
        Self::hold(
            account.principal().clone(),
            account.epub(),
            account.sea_pub(),
            account.local_priv(),
            account.epub(),
            account.local_epriv(),
            &[],
            account.lane_id(),
            0,
            0,
        )
    }

    /// Device import. The current pub and epub must equal the witnessed pair.
    /// A null `current_epub` is [`EncDiscError::EpubUnknown`], not the bound
    /// genesis epub and not a Gun `user.epub`.
    pub fn import(
        principal: &str,
        genesis_epub: &str,
        current_pub: &str,
        current_priv: &str,
        current_epub: &str,
        current_epriv: &str,
        retired: &[(&str, &str)],
        lane_id: &str,
        content_epoch: u64,
        rotation_seq: u64,
        rotations: &[serde_json::Value],
        context: &sociacl_ids::ResolutionContext<'_>,
    ) -> Result<Self, EncDiscError> {
        let principal = parse_principal_id(principal).map_err(reject)?;
        let keyring = Self::hold(
            principal,
            genesis_epub,
            current_pub,
            current_priv,
            current_epub,
            current_epriv,
            retired,
            lane_id,
            content_epoch,
            rotation_seq,
        )?;
        keyring.confirm(rotations, context)?;
        Ok(keyring)
    }

    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub fn genesis_epub(&self) -> &PrincipalId {
        &self.genesis_epub
    }

    pub fn current_pub(&self) -> &PrincipalId {
        &self.current_pub
    }

    /// Device-local signing scalar. Never write this to Gun.
    pub fn current_priv(&self) -> &str {
        self.current_priv.as_str()
    }

    pub fn current_epub(&self) -> &PrincipalId {
        &self.current_epub
    }

    /// Device-local encryption scalar. Never write this to Gun.
    pub fn current_epriv(&self) -> &str {
        self.current_epriv.as_str()
    }

    pub fn retired(&self) -> &[RetiredEpriv] {
        &self.retired
    }

    pub fn lane_id(&self) -> &str {
        &self.lane_id
    }

    pub fn content_epoch(&self) -> u64 {
        self.content_epoch
    }

    pub fn rotation_seq(&self) -> u64 {
        self.rotation_seq
    }

    /// Gun user node. Secrets, retired scalars, and the lane id are absent.
    /// The account id stays the genesis pub.
    pub fn gun_document(&self) -> String {
        let soul = user_soul(&self.principal);
        format!(
            "{{\"soul\":{},\"account\":{},\"pub\":{},\"epub\":{}}}",
            account::json_string(soul.as_ref()),
            account::json_string(self.principal.as_ref()),
            account::json_string(self.current_pub.as_ref()),
            account::json_string(self.current_epub.as_ref()),
        )
    }

    /// Check this keyring against the witnessed current pair.
    pub fn confirm(
        &self,
        rotations: &[serde_json::Value],
        context: &sociacl_ids::ResolutionContext<'_>,
    ) -> Result<sociacl_ids::ResolvedAccount, EncDiscError> {
        let resolved = sociacl_ids::resolve_current_key(&self.principal, rotations, context);
        let account = resolved.result.map_err(reject)?;
        if account.current_key.as_ref() != self.current_pub.as_ref() {
            return Err(EncDiscError::PubMismatch);
        }
        match &account.current_epub {
            Some(epub) if epub == &self.current_epub => {}
            Some(_) => return Err(EncDiscError::EpubMismatch),
            None => return Err(EncDiscError::EpubUnknown),
        }
        if account
            .binding_epub
            .as_ref()
            .is_some_and(|bound| bound != &self.genesis_epub)
        {
            return Err(EncDiscError::EpubMismatch);
        }
        if account.rotations.len() as u64 != self.rotation_seq {
            return Err(EncDiscError::RotationRejected);
        }
        if self.content_epoch < account.rotations.len() as u64 {
            return Err(EncDiscError::EpochRejected);
        }
        for row in &account.rotations {
            if let Some(epub) = &row.next_epub {
                if epub != &self.current_epub
                    && !self.retired.iter().any(|retired| &retired.epub == epub)
                {
                    return Err(EncDiscError::EpubMismatch);
                }
            }
        }
        if self.retired.len() > 1024 {
            return Err(EncDiscError::IdentityRejected("too-many-keys".into()));
        }
        Ok(account)
    }

    /// Seal a DEK to the witnessed epub at this keyring's content epoch.
    /// `gun_user_epub` is ignored. A null witness refuses the seal.
    pub fn seal_content(
        &self,
        dek: &ItemDek,
        object: &sociacl_ids::ObjectId,
        revision_id: &str,
        rotations: &[serde_json::Value],
        context: &sociacl_ids::ResolutionContext<'_>,
        gun_user_epub: Option<&str>,
    ) -> Result<WrappedKey, EncDiscError> {
        let account = self.confirm(rotations, context)?;
        let epub = epub_for_new_seal(account.current_epub.as_ref(), gun_user_epub)?;
        if epub != self.current_epub {
            return Err(EncDiscError::EpubMismatch);
        }
        let enrolled = EnrolledSeaPub {
            account: self.principal.as_ref().to_string(),
            sea_pub: self.current_pub.as_ref().to_string(),
            epub: self.current_epub.as_ref().to_string(),
            identity_pub: self.current_pub.as_ref().to_string(),
        };
        let named = NamedSet::try_from_accessors([self.principal.as_ref()])?;
        let mut wraps = wrap::wrap_item_dek_to_readers(
            dek,
            self.content_epoch,
            object.as_ref(),
            revision_id,
            &[enrolled],
            &named,
        )?;
        let wrap = wraps.pop().ok_or(EncDiscError::WrapRejected)?;
        if !wraps.is_empty() || wrap.target_id != self.current_epub.as_ref() {
            return Err(EncDiscError::WrapRejected);
        }
        if gun_user_epub.is_some_and(|gun| gun == wrap.target_id.as_str() && gun != epub.as_ref()) {
            return Err(EncDiscError::WrapRejected);
        }
        Ok(wrap)
    }

    /// Open a wrap with the current epriv, or a retired one when the target matches.
    /// Opening does not grant.
    pub fn open_content(&self, wrapped: &WrappedKey) -> Result<OpenedWrap, EncDiscError> {
        if wrapped.target_id == self.current_epub.as_ref() {
            return wrap::open_reader_wrap(
                wrapped,
                self.current_epriv.as_str(),
                self.current_epub.as_ref(),
            );
        }
        for retired in &self.retired {
            if wrapped.target_id == retired.epub.as_ref() {
                return wrap::open_reader_wrap(
                    wrapped,
                    retired.epriv.as_str(),
                    retired.epub.as_ref(),
                );
            }
        }
        Err(EncDiscError::WrapRejected)
    }

    fn hold(
        principal: PrincipalId,
        genesis_epub: &str,
        current_pub: &str,
        current_priv: &str,
        current_epub: &str,
        current_epriv: &str,
        retired: &[(&str, &str)],
        lane_id: &str,
        content_epoch: u64,
        rotation_seq: u64,
    ) -> Result<Self, EncDiscError> {
        require_lane(lane_id)?;
        if retired.len() > 1024 {
            return Err(EncDiscError::IdentityRejected("too-many-keys".into()));
        }
        let genesis_epub = encryption_point(genesis_epub, None)?.0;
        if genesis_epub == principal {
            return Err(EncDiscError::EpubMismatch);
        }
        let (current_pub, current_priv) = signing_point(current_pub, current_priv)?;
        let (current_epub, current_epriv) = {
            let (point, secret) = encryption_point(current_epub, Some(current_epriv))?;
            (point, secret.ok_or(EncDiscError::EpubMismatch)?)
        };
        if current_epub == current_pub || current_epub == principal {
            return Err(EncDiscError::EpubMismatch);
        }
        // The genesis epub is the current epub only while the signing key is still genesis.
        if current_pub != principal && current_epub == genesis_epub {
            return Err(EncDiscError::EpubMismatch);
        }
        let mut retired_keys = Vec::with_capacity(retired.len());
        let mut seen = vec![current_epub.clone()];
        for (epub, epriv) in retired {
            let (point, secret) = encryption_point(epub, Some(epriv))?;
            let secret = secret.ok_or(EncDiscError::EpubMismatch)?;
            // The genesis epub is retired once the signing key moves. It is
            // not a second current epub, and it is not repeated.
            if seen.iter().any(|held| held == &point) || point == current_pub || point == principal
            {
                return Err(EncDiscError::EpubReuse);
            }
            seen.push(point.clone());
            retired_keys.push(RetiredEpriv {
                epub: point,
                epriv: secret,
            });
        }
        if current_pub != principal && !retired_keys.iter().any(|row| row.epub == genesis_epub) {
            return Err(EncDiscError::EpubMismatch);
        }
        Ok(Self {
            principal,
            genesis_epub,
            current_pub,
            current_priv,
            current_epub,
            current_epriv,
            retired: retired_keys,
            lane_id: lane_id.to_string(),
            content_epoch,
            rotation_seq,
        })
    }
}

impl std::fmt::Debug for AccountKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountKeyring")
            .field("principal", &self.principal)
            .field("genesis_epub", &self.genesis_epub)
            .field("current_pub", &self.current_pub)
            .field("current_epub", &self.current_epub)
            .field("priv", &"<redacted>")
            .field("epriv", &"<redacted>")
            .field("retired", &self.retired.len())
            .field("lane_id", &"<redacted>")
            .field("content_epoch", &self.content_epoch)
            .field("rotation_seq", &self.rotation_seq)
            .finish()
    }
}

/// The witnessed epub, or an error. `gun_user_epub` is never the result.
pub fn epub_for_new_seal(
    current_epub: Option<&PrincipalId>,
    gun_user_epub: Option<&str>,
) -> Result<PrincipalId, EncDiscError> {
    match current_epub {
        Some(epub) => {
            let _ = gun_user_epub;
            Ok(epub.clone())
        }
        None => Err(EncDiscError::EpubUnknown),
    }
}

/// Mint a signing pair, an encryption pair, and a new lane id.
pub fn mint_rotation() -> Result<RotationMint, EncDiscError> {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut rng = OsRng;
    let signing = p256::ecdsa::SigningKey::random(&mut rng);
    let encryption = p256::SecretKey::random(&mut rng);
    let mut lane = [0u8; 32];
    rng.fill_bytes(&mut lane);
    let lane_id = crate::hexutil::encode_secret_hex(&lane).to_string();
    lane.zeroize();
    Ok(RotationMint {
        signing_pub: sea::sea_pub_from_signing(&signing)?,
        signing_priv: sea::sea_priv_from_signing(&signing)?,
        epub: sea::sea_pub_from_secret(&encryption)?,
        epriv: sea::sea_priv_from_secret(&encryption)?,
        lane_id,
    })
}

/// Mint the next v3 rotation. Name every trusted device except `lost`.
/// Delivery of the new keyring is part 3 and is not done here.
/// The account id does not change. The draft is checked with
/// `check_rotation_publish` before it is returned.
pub fn rotate_keyring<F>(
    keyring: &AccountKeyring,
    trusted: &[&str],
    lost: &str,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    mint: F,
) -> Result<KeyringRotation, EncDiscError>
where
    F: FnOnce() -> Result<RotationMint, EncDiscError>,
{
    if trusted.is_empty() || !trusted.contains(&lost) {
        return Err(EncDiscError::IdentityRejected("lost-device".into()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for local_id in trusted {
        if !seen.insert(*local_id) {
            return Err(EncDiscError::IdentityRejected("duplicate-device".into()));
        }
        require_device(local_id)?;
    }
    let minted = mint()?;
    let (next_key, next_priv) = signing_point(&minted.signing_pub, minted.signing_priv.as_str())?;
    let (next_epub, next_epriv) = {
        let (point, secret) = encryption_point(&minted.epub, Some(minted.epriv.as_str()))?;
        (point, secret.ok_or(EncDiscError::EpubMismatch)?)
    };
    require_lane(&minted.lane_id)?;
    if next_epub == next_key || holds_point(keyring, &next_epub) || holds_point(keyring, &next_key)
    {
        return Err(EncDiscError::EpubReuse);
    }
    let resolved = sociacl_ids::resolve_current_key(&keyring.principal, rotations, context);
    let account = resolved.result.map_err(reject)?;
    if account.current_key.as_ref() != keyring.current_pub.as_ref() {
        return Err(EncDiscError::PubMismatch);
    }
    if account.rotations.len() as u64 != keyring.rotation_seq {
        return Err(EncDiscError::RotationRejected);
    }
    if account
        .rotations
        .iter()
        .any(|row| row.prev_key == next_key || row.next_key == next_key)
        || account.binding_epub.as_ref() == Some(&next_key)
        || account.binding_epub.as_ref() == Some(&next_epub)
    {
        return Err(EncDiscError::EpubReuse);
    }
    if minted.lane_id == keyring.lane_id {
        return Err(EncDiscError::BadLane);
    }
    let mut retired = keyring.retired.clone();
    retired.push(RetiredEpriv {
        epub: keyring.current_epub.clone(),
        epriv: keyring.current_epriv.clone(),
    });
    let seq = keyring
        .rotation_seq
        .checked_add(1)
        .ok_or(EncDiscError::RotationRejected)?;
    let epoch = keyring
        .content_epoch
        .checked_add(1)
        .ok_or(EncDiscError::EpochRejected)?;
    let rotated = AccountKeyring {
        principal: keyring.principal.clone(),
        genesis_epub: keyring.genesis_epub.clone(),
        current_pub: next_key.clone(),
        current_priv: next_priv,
        current_epub: next_epub.clone(),
        current_epriv: next_epriv,
        retired,
        lane_id: minted.lane_id,
        content_epoch: epoch,
        rotation_seq: seq,
    };
    let mut devices = Vec::new();
    for local_id in trusted {
        if *local_id == lost {
            continue;
        }
        devices.push(KeyringDevice {
            local_id: (*local_id).to_string(),
            keyring: rotated.clone(),
        });
    }
    let draft = RotationDraft {
        principal: rotated.principal.clone(),
        seq,
        prev_key: keyring.current_pub.clone(),
        next_key,
        next_epub,
    };
    debug_assert_eq!(draft.version(), 3);
    let draft_record = serde_json::json!({
        "v": 1,
        "kind": "rotate",
        "principal": draft.principal.as_ref(),
        "seq": draft.seq,
        "prevKey": draft.prev_key.as_ref(),
        "nextKey": draft.next_key.as_ref(),
        "nextEpub": draft.next_epub.as_ref(),
        "retainedLinks": [],
    });
    sociacl_ids::check_rotation_publish(&draft_record, &[], &keyring.principal, rotations, context)
        .map_err(reject)?;
    Ok(KeyringRotation {
        keyring: rotated,
        devices,
        draft,
        lost_local_id: lost.to_string(),
    })
}

fn holds_point(keyring: &AccountKeyring, point: &PrincipalId) -> bool {
    point == &keyring.principal
        || point == &keyring.genesis_epub
        || point == &keyring.current_pub
        || point == &keyring.current_epub
        || keyring.retired.iter().any(|row| &row.epub == point)
}

fn require_device(local_id: &str) -> Result<(), EncDiscError> {
    if local_id.is_empty() {
        return Err(EncDiscError::EmptyDevice);
    }
    if parse_principal_id(local_id).is_ok() || parse_eip55(local_id).is_ok() {
        return Err(EncDiscError::IdentityRejected("device-id".into()));
    }
    Ok(())
}

fn signing_point(
    sea_pub: &str,
    sea_priv: &str,
) -> Result<(PrincipalId, Zeroizing<String>), EncDiscError> {
    let signing = sea::signing_key(sea_priv)?;
    let derived = sea::sea_pub_from_signing(&signing)?;
    if derived != sea_pub {
        return Err(EncDiscError::PubMismatch);
    }
    let public = p256::PublicKey::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .map_err(|_| EncDiscError::BadKey)?;
    let point = uncompressed_point(&public)?;
    let principal = principal_from_sec1(&point).map_err(reject)?;
    if principal.as_ref() != sea_pub {
        return Err(EncDiscError::PubMismatch);
    }
    let parsed = parse_principal_id(sea_pub).map_err(reject)?;
    if parsed != principal {
        return Err(EncDiscError::PubMismatch);
    }
    Ok((principal, Zeroizing::new(sea_priv.to_string())))
}

fn encryption_point(
    epub: &str,
    epriv: Option<&str>,
) -> Result<(PrincipalId, Option<Zeroizing<String>>), EncDiscError> {
    let parsed = parse_principal_id(epub).map_err(reject)?;
    if parsed.as_ref() != epub {
        return Err(EncDiscError::EpubMismatch);
    }
    let Some(epriv) = epriv else {
        return Ok((parsed, None));
    };
    let secret = sea::ecdh_secret(epriv)?;
    let derived = sea::sea_pub_from_secret(&secret)?;
    if derived != epub {
        return Err(EncDiscError::EpubMismatch);
    }
    Ok((parsed, Some(Zeroizing::new(epriv.to_string()))))
}

fn reject(reason: Reason) -> EncDiscError {
    EncDiscError::NotPrincipal(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::EnrolledSeaPub;
    use crate::hexutil;
    use crate::wrap::{
        open_reader_wrap, wrap_item_dek_to_readers_with, DetachedEphemeral, ItemDek, NamedSet,
        WrapScope, WrapTarget, WrappedKey,
    };
    use crate::{delivery_mints_grant, GenesisAccount};
    use serde_json::Value;
    use sociacl_ids::{
        format_principal_key, history_state, parse_object_id, HistoryResolver, Jwks, KeyState,
        PrincipalId, Reason, ResolutionContext, Rotate, SiwePolicy,
    };
    use std::collections::{BTreeMap, BTreeSet};

    const RING: &str = include_str!("../../../vectors/encrypted-discovery/account-keyring.json");
    const ACCOUNT: &str = include_str!("../../../vectors/encrypted-discovery/account-key.json");
    const RECORDS: &str = include_str!("../../../vectors/ids/records.json");

    fn ring() -> Value {
        serde_json::from_str(RING).unwrap()
    }

    fn account_key() -> Value {
        serde_json::from_str(ACCOUNT).unwrap()
    }

    fn records() -> Value {
        serde_json::from_str(RECORDS).unwrap()
    }

    fn token(err: &EncDiscError) -> String {
        match err {
            EncDiscError::EpubUnknown => "epub-unknown".into(),
            EncDiscError::EpubReuse => "epub-reuse".into(),
            EncDiscError::PubMismatch => "pub-mismatch".into(),
            EncDiscError::EpubMismatch => "epub-mismatch".into(),
            EncDiscError::RotationRejected => "rotation-rejected".into(),
            EncDiscError::BadLane => "bad-lane".into(),
            EncDiscError::EmptyDevice => "empty-device".into(),
            EncDiscError::IdentityRejected(reason) => reason.clone(),
            EncDiscError::EpochRejected => "content-epoch".into(),
            other => panic!("unexpected {other}"),
        }
    }

    fn expect_err(v: &Value, name: &str, err: EncDiscError) {
        assert_eq!(token(&err), v["errors"][name].as_str().unwrap(), "{name}");
    }

    fn scalar_sea(last: u8) -> (String, Zeroizing<String>) {
        let mut bytes = [0u8; 32];
        bytes[31] = last;
        let secret = p256::SecretKey::from_slice(&bytes).unwrap();
        bytes.zeroize();
        (
            crate::sea::sea_pub_from_secret(&secret).unwrap(),
            crate::sea::sea_priv_from_secret(&secret).unwrap(),
        )
    }

    fn vector_mint(v: &Value) -> RotationMint {
        let mint = &v["mint"];
        RotationMint {
            signing_pub: mint["signingPub"].as_str().unwrap().to_string(),
            signing_priv: Zeroizing::new(mint["signingPriv"].as_str().unwrap().to_string()),
            epub: mint["epub"].as_str().unwrap().to_string(),
            epriv: Zeroizing::new(mint["epriv"].as_str().unwrap().to_string()),
            lane_id: mint["laneId"].as_str().unwrap().to_string(),
        }
    }

    fn genesis_of(v: &Value) -> GenesisAccount {
        let g = &v["genesis"];
        GenesisAccount::import(
            g["laneId"].as_str().unwrap(),
            g["signingPub"].as_str().unwrap(),
            g["signingPriv"].as_str().unwrap(),
            g["epub"].as_str().unwrap(),
            g["epriv"].as_str().unwrap(),
        )
        .unwrap()
    }

    fn trusted<'a>(v: &'a Value) -> Vec<&'a str> {
        v["trusted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect()
    }

    fn secrets_absent(text: &str, v: &Value) {
        let genesis = &v["genesis"];
        let mint = &v["mint"];
        let scalar = genesis["signingScalarHex"].as_str().unwrap();
        let scalar_lower = scalar.to_ascii_lowercase();
        for secret in [
            genesis["signingPriv"].as_str().unwrap(),
            genesis["epriv"].as_str().unwrap(),
            scalar,
            scalar_lower.as_str(),
            genesis["laneId"].as_str().unwrap(),
            mint["signingPriv"].as_str().unwrap(),
            mint["epriv"].as_str().unwrap(),
            mint["laneId"].as_str().unwrap(),
        ] {
            assert!(!text.contains(secret), "leaked secret");
        }
        assert!(!text.contains("\"priv\""));
        assert!(!text.contains("\"epriv\""));
    }

    struct EmptyCtx {
        jwks: Jwks,
        policy: SiwePolicy,
        pinned: BTreeSet<String>,
        links: BTreeMap<String, Value>,
        revocations: Vec<Value>,
    }

    fn empty_ctx() -> EmptyCtx {
        EmptyCtx {
            jwks: Jwks { keys: Vec::new() },
            policy: SiwePolicy {
                allowed_domains: Vec::new(),
                allowed_uris: Vec::new(),
                allowed_chain_ids: Vec::new(),
                clock_skew_seconds: 0,
            },
            pinned: BTreeSet::new(),
            links: BTreeMap::new(),
            revocations: Vec::new(),
        }
    }

    fn missing_history(_: &PrincipalId, _: u64, _: u64) -> Result<KeyState, Reason> {
        Err(Reason::MissingHistory)
    }

    fn context_of(empty: &EmptyCtx) -> ResolutionContext<'_> {
        ResolutionContext {
            jwks: &empty.jwks,
            links: &empty.links,
            revocations: &empty.revocations,
            now: 1_700_000_060,
            policy: &empty.policy,
            pinned_iss: &empty.pinned,
            history: &missing_history,
            genesis_epub_bindings: &[],
        }
    }

    #[test]
    fn rotation_matches_the_shared_vector_and_keeps_secrets_off_gun() {
        let v = ring();
        let account = genesis_of(&v);
        let keyring = AccountKeyring::from_genesis(&account).unwrap();
        let empty = empty_ctx();
        let ctx = context_of(&empty);
        let names = trusted(&v);
        let lost = v["lost"].as_str().unwrap();
        let outcome =
            rotate_keyring(&keyring, &names, lost, &[], &ctx, || Ok(vector_mint(&v))).unwrap();
        let expected = &v["expected"];
        assert_eq!(
            outcome.keyring.principal().as_ref(),
            expected["principal"].as_str().unwrap()
        );
        assert_eq!(outcome.keyring.principal(), account.principal());
        assert_eq!(
            outcome.keyring.genesis_epub().as_ref(),
            v["genesis"]["epub"].as_str().unwrap()
        );
        assert_eq!(
            outcome.keyring.current_pub().as_ref(),
            expected["pub"].as_str().unwrap()
        );
        assert_eq!(
            outcome.keyring.current_epub().as_ref(),
            expected["epub"].as_str().unwrap()
        );
        assert_eq!(
            outcome.keyring.current_priv(),
            v["mint"]["signingPriv"].as_str().unwrap()
        );
        assert_eq!(
            outcome.keyring.current_epriv(),
            v["mint"]["epriv"].as_str().unwrap()
        );
        assert_eq!(
            outcome.keyring.lane_id(),
            expected["laneId"].as_str().unwrap()
        );
        assert_eq!(
            outcome.keyring.content_epoch(),
            expected["contentEpoch"].as_u64().unwrap()
        );
        assert_eq!(
            outcome.keyring.rotation_seq(),
            expected["rotationSeq"].as_u64().unwrap()
        );
        assert_eq!(
            outcome.draft.version(),
            expected["version"].as_u64().unwrap() as u8
        );
        assert_eq!(
            outcome.draft.prev_key.as_ref(),
            expected["prevKey"].as_str().unwrap()
        );
        assert_eq!(
            outcome.draft.next_key.as_ref(),
            expected["nextKey"].as_str().unwrap()
        );
        assert_eq!(
            outcome.draft.next_epub.as_ref(),
            expected["nextEpub"].as_str().unwrap()
        );
        assert_eq!(
            outcome.draft.document(),
            expected["draftDocument"].as_str().unwrap()
        );
        assert_eq!(outcome.lost_local_id, lost);
        let device_ids: Vec<&str> = outcome
            .devices
            .iter()
            .map(|device| device.local_id())
            .collect();
        let expected_devices: Vec<&str> = expected["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect();
        assert_eq!(device_ids, expected_devices);
        assert!(!device_ids.contains(&lost));
        for device in &outcome.devices {
            assert!(!device.grants_see());
            assert_eq!(
                device.keyring().current_epriv(),
                outcome.keyring.current_epriv()
            );
            assert_eq!(device.keyring().lane_id(), outcome.keyring.lane_id());
            assert_eq!(device.gun_document(), outcome.keyring.gun_document());
        }
        assert_eq!(outcome.keyring.retired().len(), 1);
        assert_eq!(
            outcome.keyring.retired()[0].epub().as_ref(),
            expected["retiredEpubs"][0].as_str().unwrap()
        );
        assert_eq!(
            outcome.keyring.retired()[0].epriv(),
            v["genesis"]["epriv"].as_str().unwrap()
        );
        let gun = outcome.keyring.gun_document();
        assert_eq!(gun, expected["gunDocument"].as_str().unwrap());
        let path_key = format_principal_key(outcome.keyring.principal());
        assert!(path_key.as_ref().starts_with("p_"));
        assert!(!gun.contains(path_key.as_ref()));
        assert!(!gun.contains("p_"));
        secrets_absent(&gun, &v);
        secrets_absent(&outcome.draft.document(), &v);
        for device in &outcome.devices {
            secrets_absent(&device.gun_document(), &v);
        }
        let debug = format!("{:?}", outcome.keyring);
        assert!(debug.contains("<redacted>"));
        secrets_absent(&debug, &v);
        secrets_absent(&format!("{:?}", outcome.keyring.retired()[0]), &v);
        let content = &account_key()["contentWrap"];
        let wrapped = WrappedKey {
            scope: WrapScope::ItemDek,
            epoch: content["epoch"].as_u64().unwrap(),
            target: WrapTarget::ReaderEpub,
            target_id: v["genesis"]["epub"].as_str().unwrap().to_string(),
            object: Some(content["objectId"].as_str().unwrap().to_string()),
            group: None,
            revision_id: content["revisionId"].as_str().unwrap().to_string(),
            wrapped_key: content["wrappedKey"].as_str().unwrap().to_string(),
        };
        assert_ne!(
            outcome.keyring.current_epub().as_ref(),
            wrapped.target_id.as_str()
        );
        let opened = outcome.keyring.open_content(&wrapped).unwrap();
        let dek: [u8; 32] = hexutil::decode_hex_array(content["dekHex"].as_str().unwrap()).unwrap();
        assert_eq!(opened.key_bytes(), &dek);
        assert!(!opened.grants_see());
        for kind in ["enrollment", "hop", "hint", "wrap", "request", "inbox"] {
            assert!(!delivery_mints_grant(kind).unwrap());
        }
    }

    #[test]
    fn builder_refuses_a_held_epub_and_a_bad_device() {
        let empty = empty_ctx();
        let ctx = context_of(&empty);
        let v = ring();
        let keyring = AccountKeyring::from_genesis(&genesis_of(&v)).unwrap();
        let names = trusted(&v);
        let lost = v["lost"].as_str().unwrap();
        let genesis_epub = || RotationMint {
            signing_pub: v["mint"]["signingPub"].as_str().unwrap().to_string(),
            signing_priv: Zeroizing::new(v["mint"]["signingPriv"].as_str().unwrap().to_string()),
            epub: v["genesis"]["epub"].as_str().unwrap().to_string(),
            epriv: Zeroizing::new(v["genesis"]["epriv"].as_str().unwrap().to_string()),
            lane_id: v["mint"]["laneId"].as_str().unwrap().to_string(),
        };
        expect_err(
            &v,
            "epubReuse",
            rotate_keyring(&keyring, &names, lost, &[], &ctx, || Ok(genesis_epub())).unwrap_err(),
        );
        let same_point = RotationMint {
            signing_pub: v["mint"]["signingPub"].as_str().unwrap().to_string(),
            signing_priv: Zeroizing::new(v["mint"]["signingPriv"].as_str().unwrap().to_string()),
            epub: v["mint"]["signingPub"].as_str().unwrap().to_string(),
            epriv: Zeroizing::new(v["mint"]["signingPriv"].as_str().unwrap().to_string()),
            lane_id: v["mint"]["laneId"].as_str().unwrap().to_string(),
        };
        expect_err(
            &v,
            "epubReuse",
            rotate_keyring(&keyring, &names, lost, &[], &ctx, || Ok(same_point)).unwrap_err(),
        );
        let held_signing = RotationMint {
            signing_pub: v["genesis"]["signingPub"].as_str().unwrap().to_string(),
            signing_priv: Zeroizing::new(v["genesis"]["signingPriv"].as_str().unwrap().to_string()),
            epub: v["mint"]["epub"].as_str().unwrap().to_string(),
            epriv: Zeroizing::new(v["mint"]["epriv"].as_str().unwrap().to_string()),
            lane_id: v["mint"]["laneId"].as_str().unwrap().to_string(),
        };
        expect_err(
            &v,
            "epubReuse",
            rotate_keyring(&keyring, &names, lost, &[], &ctx, || Ok(held_signing)).unwrap_err(),
        );
        let reused_lane = RotationMint {
            signing_pub: v["mint"]["signingPub"].as_str().unwrap().to_string(),
            signing_priv: Zeroizing::new(v["mint"]["signingPriv"].as_str().unwrap().to_string()),
            epub: v["mint"]["epub"].as_str().unwrap().to_string(),
            epriv: Zeroizing::new(v["mint"]["epriv"].as_str().unwrap().to_string()),
            lane_id: v["genesis"]["laneId"].as_str().unwrap().to_string(),
        };
        expect_err(
            &v,
            "badLane",
            rotate_keyring(&keyring, &names, lost, &[], &ctx, || Ok(reused_lane)).unwrap_err(),
        );
        expect_err(
            &v,
            "lostDevice",
            rotate_keyring(&keyring, &[], lost, &[], &ctx, || Ok(vector_mint(&v))).unwrap_err(),
        );
        expect_err(
            &v,
            "lostDevice",
            rotate_keyring(&keyring, &["phone"], lost, &[], &ctx, || {
                Ok(vector_mint(&v))
            })
            .unwrap_err(),
        );
        expect_err(
            &v,
            "duplicateDevice",
            rotate_keyring(&keyring, &["phone", "phone"], "phone", &[], &ctx, || {
                Ok(vector_mint(&v))
            })
            .unwrap_err(),
        );
        expect_err(
            &v,
            "emptyDevice",
            rotate_keyring(&keyring, &["", "phone"], "phone", &[], &ctx, || {
                Ok(vector_mint(&v))
            })
            .unwrap_err(),
        );
        let principal = v["genesis"]["principal"].as_str().unwrap();
        expect_err(
            &v,
            "deviceId",
            rotate_keyring(&keyring, &[principal, "phone"], "phone", &[], &ctx, || {
                Ok(vector_mint(&v))
            })
            .unwrap_err(),
        );
        let wallet = v["wallet"].as_str().unwrap();
        expect_err(
            &v,
            "deviceId",
            rotate_keyring(&keyring, &[wallet, "phone"], "phone", &[], &ctx, || {
                Ok(vector_mint(&v))
            })
            .unwrap_err(),
        );
        let outcome =
            rotate_keyring(&keyring, &names, lost, &[], &ctx, || Ok(vector_mint(&v))).unwrap();
        expect_err(
            &v,
            "epubReuse",
            rotate_keyring(&outcome.keyring, &names, lost, &[], &ctx, || {
                Ok(genesis_epub())
            })
            .unwrap_err(),
        );
        let again = vector_mint(&v);
        expect_err(
            &v,
            "epubReuse",
            rotate_keyring(&outcome.keyring, &names, lost, &[], &ctx, || Ok(again)).unwrap_err(),
        );
    }

    #[test]
    fn null_current_epub_refuses_the_seal_and_ignores_gun() {
        let v = ring();
        let account = genesis_of(&v);
        let keyring = AccountKeyring::from_genesis(&account).unwrap();
        let empty = empty_ctx();
        let context = context_of(&empty);
        let dek = ItemDek::from_bytes([1u8; 32]);
        let object = parse_object_id(v["witnessed"]["objectId"].as_str().unwrap()).unwrap();
        expect_err(
            &v,
            "epubUnknown",
            keyring
                .seal_content(
                    &dek,
                    &object,
                    v["witnessed"]["revisionId"].as_str().unwrap(),
                    &[],
                    &context,
                    Some(v["genesis"]["epub"].as_str().unwrap()),
                )
                .unwrap_err(),
        );
        expect_err(
            &v,
            "epubUnknown",
            epub_for_new_seal(None, Some(v["genesis"]["epub"].as_str().unwrap())).unwrap_err(),
        );
        let witnessed = keyring.current_epub().clone();
        let chosen = epub_for_new_seal(Some(&witnessed), Some("not-the-witness")).unwrap();
        assert_eq!(chosen.as_ref(), witnessed.as_ref());
        assert_ne!(chosen.as_ref(), "not-the-witness");
        expect_err(
            &v,
            "pubMismatch",
            GenesisAccount::import(
                v["genesis"]["laneId"].as_str().unwrap(),
                v["genesis"]["signingPub"].as_str().unwrap(),
                v["mint"]["signingPriv"].as_str().unwrap(),
                v["genesis"]["epub"].as_str().unwrap(),
                v["genesis"]["epriv"].as_str().unwrap(),
            )
            .unwrap_err(),
        );
        expect_err(
            &v,
            "pubMismatch",
            AccountKeyring::import(
                v["genesis"]["principal"].as_str().unwrap(),
                v["genesis"]["epub"].as_str().unwrap(),
                v["mint"]["signingPub"].as_str().unwrap(),
                v["mint"]["signingPriv"].as_str().unwrap(),
                v["mint"]["epub"].as_str().unwrap(),
                v["mint"]["epriv"].as_str().unwrap(),
                &[(
                    v["genesis"]["epub"].as_str().unwrap(),
                    v["genesis"]["epriv"].as_str().unwrap(),
                )],
                v["mint"]["laneId"].as_str().unwrap(),
                1,
                1,
                &[],
                &context,
            )
            .unwrap_err(),
        );
    }

    #[test]
    fn witnessed_import_seals_only_the_resolved_epub() {
        let v = ring();
        let records = records();
        let rotation = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == v["witnessed"]["rotationName"].as_str().unwrap())
            .unwrap()["input"]
            .clone();
        let (genesis_pub, _genesis_priv) =
            scalar_sea(v["witnessed"]["genesisScalar"].as_u64().unwrap() as u8);
        let (genesis_epub, genesis_epriv) =
            scalar_sea(v["witnessed"]["genesisEpubScalar"].as_u64().unwrap() as u8);
        let (current_pub, current_priv) =
            scalar_sea(v["witnessed"]["currentScalar"].as_u64().unwrap() as u8);
        let (current_epub, current_epriv) =
            scalar_sea(v["witnessed"]["epubScalar"].as_u64().unwrap() as u8);
        let (other_pub, other_priv) = scalar_sea(8);
        assert_eq!(genesis_pub, records["context"]["genesis"].as_str().unwrap());
        assert_eq!(genesis_pub, rotation["principal"].as_str().unwrap());
        assert_eq!(current_pub, rotation["nextKey"].as_str().unwrap());
        assert_eq!(current_epub, rotation["nextEpub"].as_str().unwrap());
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
        let lane = v["witnessed"]["laneId"].as_str().unwrap();
        let epoch = v["witnessed"]["contentEpoch"].as_u64().unwrap();
        let seq = v["witnessed"]["rotationSeq"].as_u64().unwrap();
        let rotations = [rotation.clone()];
        let imported = AccountKeyring::import(
            &genesis_pub,
            &genesis_epub,
            &current_pub,
            current_priv.as_str(),
            &current_epub,
            current_epriv.as_str(),
            &retired,
            lane,
            epoch,
            seq,
            &rotations,
            &base,
        )
        .unwrap();
        assert_eq!(imported.principal().as_ref(), genesis_pub);
        assert_eq!(imported.genesis_epub().as_ref(), genesis_epub);
        assert_eq!(imported.current_epub().as_ref(), current_epub);
        assert_eq!(imported.rotation_seq(), 1);
        let dek = ItemDek::from_bytes([7u8; 32]);
        let object = parse_object_id(v["witnessed"]["objectId"].as_str().unwrap()).unwrap();
        let sealed = imported
            .seal_content(
                &dek,
                &object,
                v["witnessed"]["revisionId"].as_str().unwrap(),
                &rotations,
                &base,
                Some(genesis_pub.as_str()),
            )
            .unwrap();
        assert_eq!(sealed.epoch, epoch);
        assert_eq!(sealed.target_id, current_epub);
        assert_ne!(sealed.target_id, genesis_pub);
        assert_ne!(sealed.target_id, genesis_epub);
        let sealed_gun = imported
            .seal_content(
                &dek,
                &object,
                v["witnessed"]["revisionId"].as_str().unwrap(),
                &rotations,
                &base,
                Some(genesis_epub.as_str()),
            )
            .unwrap();
        assert_eq!(sealed_gun.target_id, current_epub);
        secrets_absent(&imported.gun_document(), &v);
        assert!(!imported.gun_document().contains(current_priv.as_str()));
        assert!(!imported.gun_document().contains(current_epriv.as_str()));
        assert!(!imported.gun_document().contains(genesis_epriv.as_str()));
        assert!(!imported.gun_document().contains(lane));
        expect_err(
            &v,
            "pubMismatch",
            AccountKeyring::import(
                &genesis_pub,
                &genesis_epub,
                &current_pub,
                current_priv.as_str(),
                &current_epub,
                current_epriv.as_str(),
                &retired,
                lane,
                epoch,
                seq,
                &[],
                &base,
            )
            .unwrap_err(),
        );
        let wrong_epub = [(genesis_epub.as_str(), genesis_epriv.as_str())];
        expect_err(
            &v,
            "epubMismatch",
            AccountKeyring::import(
                &genesis_pub,
                &genesis_epub,
                &current_pub,
                current_priv.as_str(),
                &other_pub,
                other_priv.as_str(),
                &wrong_epub,
                lane,
                epoch,
                seq,
                &rotations,
                &base,
            )
            .unwrap_err(),
        );
        expect_err(
            &v,
            "rotationRejected",
            AccountKeyring::import(
                &genesis_pub,
                &genesis_epub,
                &current_pub,
                current_priv.as_str(),
                &current_epub,
                current_epriv.as_str(),
                &retired,
                lane,
                epoch,
                0,
                &rotations,
                &base,
            )
            .unwrap_err(),
        );
        let junk = vec![serde_json::json!({"kind": "nope"})];
        let ignored = ResolutionContext {
            jwks: base.jwks,
            links: base.links,
            revocations: base.revocations,
            now: base.now,
            policy: base.policy,
            pinned_iss: base.pinned_iss,
            history: base.history,
            genesis_epub_bindings: &junk,
        };
        let kept = AccountKeyring::import(
            &genesis_pub,
            &genesis_epub,
            &current_pub,
            current_priv.as_str(),
            &current_epub,
            current_epriv.as_str(),
            &retired,
            lane,
            epoch,
            seq,
            &rotations,
            &ignored,
        )
        .unwrap();
        assert_eq!(kept.current_epub().as_ref(), current_epub);
        expect_err(
            &v,
            "contentEpoch",
            AccountKeyring::import(
                &genesis_pub,
                &genesis_epub,
                &current_pub,
                current_priv.as_str(),
                &current_epub,
                current_epriv.as_str(),
                &retired,
                lane,
                0,
                seq,
                &rotations,
                &base,
            )
            .unwrap_err(),
        );
    }

    #[test]
    fn a_fresh_mint_is_v3_and_leaves_the_principal_in_place() {
        let v = ring();
        let account = genesis_of(&v);
        let keyring = AccountKeyring::from_genesis(&account).unwrap();
        let names = trusted(&v);
        let empty = empty_ctx();
        let ctx = context_of(&empty);
        let outcome = rotate_keyring(
            &keyring,
            &names,
            v["lost"].as_str().unwrap(),
            &[],
            &ctx,
            mint_rotation,
        )
        .unwrap();
        assert_eq!(outcome.keyring.principal(), account.principal());
        assert_eq!(outcome.draft.version(), 3);
        assert!(outcome.draft.document().contains("\"nextEpub\""));
        assert!(!outcome
            .devices
            .iter()
            .any(|device| device.local_id() == v["lost"].as_str().unwrap()));
        secrets_absent(&outcome.keyring.gun_document(), &v);
        assert!(!outcome
            .keyring
            .gun_document()
            .contains(outcome.keyring.current_priv()));
        assert!(!outcome
            .keyring
            .gun_document()
            .contains(outcome.keyring.current_epriv()));
        assert!(!outcome
            .keyring
            .gun_document()
            .contains(outcome.keyring.lane_id()));
        for retired in outcome.keyring.retired() {
            assert!(!outcome.keyring.gun_document().contains(retired.epriv()));
        }
        let empty = empty_ctx();
        let context = context_of(&empty);
        expect_err(
            &v,
            "pubMismatch",
            outcome.keyring.confirm(&[], &context).unwrap_err(),
        );
    }

    #[test]
    fn genesis_binding_import_and_cross_language_wrap() {
        let v = ring();
        let records = records();
        let binding = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "binding-valid-no-rotation")
            .unwrap()["genesisEpubBindings"]
            .as_array()
            .unwrap()
            .clone();
        let (signing_pub, signing_priv) = scalar_sea(1);
        let (epub, epriv) = scalar_sea(9);
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
            Ok(history_state(principal, &Vec::<Rotate>::new(), at, until))
        };
        let resolver: &HistoryResolver<'_> = &history;
        let revocations = Vec::new();
        let bound = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &revocations,
            now: ctx["now"].as_u64().unwrap(),
            policy: &policy,
            pinned_iss: &pinned,
            history: resolver,
            genesis_epub_bindings: &binding,
        };
        let imported = AccountKeyring::import(
            &signing_pub,
            &epub,
            &signing_pub,
            signing_priv.as_str(),
            &epub,
            epriv.as_str(),
            &[],
            v["genesis"]["laneId"].as_str().unwrap(),
            0,
            0,
            &[],
            &bound,
        )
        .unwrap();
        assert_eq!(imported.current_epub().as_ref(), epub);
        let (other_pub, other_priv) = scalar_sea(8);
        expect_err(
            &v,
            "epubMismatch",
            AccountKeyring::import(
                &signing_pub,
                &epub,
                &signing_pub,
                signing_priv.as_str(),
                &other_pub,
                other_priv.as_str(),
                &[],
                v["genesis"]["laneId"].as_str().unwrap(),
                0,
                0,
                &[],
                &bound,
            )
            .unwrap_err(),
        );
        let empty = empty_ctx();
        let bare = context_of(&empty);
        let retired = vec![("x", "y"); 1025];
        expect_err(
            &v,
            "tooManyKeys",
            AccountKeyring::import(
                v["genesis"]["principal"].as_str().unwrap(),
                v["genesis"]["epub"].as_str().unwrap(),
                v["genesis"]["signingPub"].as_str().unwrap(),
                v["genesis"]["signingPriv"].as_str().unwrap(),
                v["mint"]["epub"].as_str().unwrap(),
                v["mint"]["epriv"].as_str().unwrap(),
                &retired,
                v["genesis"]["laneId"].as_str().unwrap(),
                0,
                0,
                &[],
                &bare,
            )
            .unwrap_err(),
        );
        let (reader, reader_priv) =
            scalar_sea(v["witnessed"]["epubScalar"].as_u64().unwrap() as u8);
        let (_ephemeral_pub, ephemeral_priv) =
            scalar_sea(v["crossWrap"]["ephemeralScalar"].as_u64().unwrap() as u8);
        let dek_bytes =
            hexutil::decode_secret_array::<32>(v["witnessed"]["dekHex"].as_str().unwrap()).unwrap();
        let dek = ItemDek::from_bytes(*dek_bytes);
        let principal = records["context"]["genesis"].as_str().unwrap();
        let granted = NamedSet::try_from_accessors([principal]).unwrap();
        let wraps = wrap_item_dek_to_readers_with(
            &dek,
            v["crossWrap"]["epoch"].as_u64().unwrap(),
            v["witnessed"]["objectId"].as_str().unwrap(),
            v["witnessed"]["revisionId"].as_str().unwrap(),
            &[EnrolledSeaPub {
                account: principal.to_string(),
                sea_pub: principal.to_string(),
                epub: reader.clone(),
                identity_pub: principal.to_string(),
            }],
            &granted,
            &[DetachedEphemeral {
                epriv: ephemeral_priv.to_string(),
                nonce: [v["crossWrap"]["nonceByte"].as_u64().unwrap() as u8; 12],
            }],
        )
        .unwrap();
        assert_eq!(
            wraps[0].wrapped_key,
            v["crossWrap"]["wrappedKey"].as_str().unwrap()
        );
        let opened = open_reader_wrap(&wraps[0], reader_priv.as_str(), &reader).unwrap();
        assert_eq!(opened.key_bytes(), dek.as_bytes());
    }
}
