//! Genesis account key.
//!
//! The account is its genesis SEA signing pub: a `sociacl-ids`
//! `PrincipalId`. Devices inherit that one keypair. They do not mint
//! an identity. `priv` and `epriv` stay off Gun. The encrypted backup
//! is an index plus a wrap in a [`KeyWrapStore`]. The store is not an
//! authority. Wallets and OIDC records stay linked credentials.
//! Current-key resolution calls `sociacl_ids::resolve_current_key`.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sociacl_ids::{
    format_principal_key, grant_soul, parse_eip55, parse_object_id, parse_principal_id,
    principal_from_sec1, user_soul, ObjectId, PrincipalId, Reason,
};
use zeroize::{Zeroize, Zeroizing};

use crate::account::{self, require_lane, AccountSeaSecret, EnrolledSeaPub};
use crate::canonical;
use crate::error::EncDiscError;
use crate::hexutil::{self, encode_hex, encode_secret_hex};
use crate::sea::{self, ecdh_secret, ecdh_x, uncompressed_point};
use crate::wrap::{self, ItemDek, NamedSet, WrappedKey};

const DOMAIN_ACCOUNT_WRAP: &str = "sociacl-account-key-wrap-v1";
/// KDF info and AES-GCM associated data. Not the content-wrap domain.
const DOMAIN_ACCOUNT_BIND: &str = "sociacl-account-key-bind-v1";
const DOMAIN_ACCOUNT_SIG: &str = "sociacl-account-key-wrap-sig-v1";
const VER_BACKUP: u8 = 1;
/// Same bound as a content wrap. Reject before decoding.
const MAX_BACKUP_BYTES: usize = 8192;

/// One genesis SEA keypair. The account id is `principal`.
#[derive(Clone)]
pub struct GenesisAccount {
    principal: PrincipalId,
    secret: AccountSeaSecret,
}

/// Device-local copy of the genesis keypair. `local_id` is not an account.
#[derive(Clone)]
pub struct InheritedDevice {
    local_id: String,
    account: GenesisAccount,
}

/// Temporary ECDH key for one enrollment ciphertext. Not an account.
pub struct TransportKey {
    scalar: Zeroizing<[u8; 32]>,
    sea_pub: String,
}

/// Public index row. No private key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapIndex {
    pub principal: PrincipalId,
    pub wrap_id: ObjectId,
    pub epub: String,
}

/// Ciphertext of the genesis keypair. The store holds this, not Gun.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAccountWrap {
    pub principal: PrincipalId,
    pub wrap_id: ObjectId,
    pub epub: String,
    pub ciphertext_hex: String,
    /// Low-s P-1363 signature by the account's current signing key.
    pub signature: String,
}

/// Panopticon index and wrap store. Not an authority.
pub trait KeyWrapStore {
    fn put_wrap(
        &mut self,
        index: &WrapIndex,
        wrap: &EncryptedAccountWrap,
    ) -> Result<(), EncDiscError>;

    fn get_wrap(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<EncryptedAccountWrap>, EncDiscError>;

    fn is_authority(&self) -> bool {
        false
    }

    fn mints_grant(&self) -> bool {
        false
    }
}

/// In-memory adapter. One wrap per genesis principal.
#[derive(Clone, Debug, Default)]
pub struct MemoryKeyWrapStore {
    by_principal: BTreeMap<String, EncryptedAccountWrap>,
}

/// A verified wallet or OIDC link. The principal is the only account id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkedCredential {
    Wallet {
        principal: PrincipalId,
        address: String,
    },
    Oidc {
        principal: PrincipalId,
        issuer: String,
        tenant: String,
        subject: String,
    },
}

impl GenesisAccount {
    /// Mint one keypair. The account id is the genesis signing pub.
    pub fn generate() -> Result<Self, EncDiscError> {
        let mut rng = OsRng;
        let signing = p256::ecdsa::SigningKey::random(&mut rng);
        let encryption = p256::SecretKey::random(&mut rng);
        let mut lane = [0u8; 32];
        rng.fill_bytes(&mut lane);
        let lane_hex = encode_secret_hex(&lane);
        lane.zeroize();
        let sea_priv = sea::sea_priv_from_signing(&signing)?;
        let epriv = sea::sea_priv_from_secret(&encryption)?;
        let sea_pub = sea::sea_pub_from_signing(&signing)?;
        let epub = sea::sea_pub_from_secret(&encryption)?;
        Self::import(&lane_hex, &sea_pub, &sea_priv, &epub, &epriv)
    }

    /// Restore the genesis keypair. There is no separate account label.
    pub fn import(
        lane_id: &str,
        sea_pub: &str,
        sea_priv: &str,
        epub: &str,
        epriv: &str,
    ) -> Result<Self, EncDiscError> {
        require_lane(lane_id)?;
        let signing = sea::signing_key(sea_priv)?;
        let derived_pub = sea::sea_pub_from_signing(&signing)?;
        if derived_pub != sea_pub {
            return Err(EncDiscError::PubMismatch);
        }
        let point = uncompressed_point(
            &p256::PublicKey::from_sec1_bytes(
                signing.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .map_err(|_| EncDiscError::BadKey)?,
        )?;
        let principal = principal_from_sec1(&point).map_err(reject)?;
        if principal.as_ref() != sea_pub {
            return Err(EncDiscError::PubMismatch);
        }
        let parsed = parse_principal_id(sea_pub).map_err(reject)?;
        if parsed != principal {
            return Err(EncDiscError::PubMismatch);
        }
        let encryption = ecdh_secret(epriv)?;
        let derived_epub = sea::sea_pub_from_secret(&encryption)?;
        if derived_epub != epub {
            return Err(EncDiscError::EpubMismatch);
        }
        if epub == sea_pub {
            return Err(EncDiscError::EpubMismatch);
        }
        let secret = AccountSeaSecret::import_local(
            principal.as_ref(),
            lane_id,
            sea_pub,
            sea_priv,
            epub,
            epriv,
        )?;
        Ok(Self { principal, secret })
    }

    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub fn sea_pub(&self) -> &str {
        self.secret.sea_pub()
    }

    pub fn epub(&self) -> &str {
        self.secret.epub()
    }

    pub fn lane_id(&self) -> &str {
        self.secret.lane_id()
    }

    /// Device-local signing scalar. Never write this to Gun.
    pub fn local_priv(&self) -> &str {
        self.secret.local_priv()
    }

    /// Device-local ECDH scalar. Never write this to Gun.
    pub fn local_epriv(&self) -> &str {
        self.secret.local_epriv()
    }

    pub fn principal_key(&self) -> String {
        format_principal_key(&self.principal).to_string()
    }

    /// Gun user node. `priv` and `epriv` are absent.
    pub fn gun_document(&self) -> String {
        let soul = user_soul(&self.principal);
        format!(
            "{{\"soul\":{},\"account\":{},\"pub\":{},\"epub\":{}}}",
            account::json_string(soul.as_ref()),
            account::json_string(self.principal.as_ref()),
            account::json_string(self.sea_pub()),
            account::json_string(self.epub()),
        )
    }

    pub fn enrolled_pub(&self) -> EnrolledSeaPub {
        EnrolledSeaPub::from_account(&self.secret)
    }

    /// Copy this keypair onto a device. The device id is not an identity.
    pub fn enroll(&self, local_id: &str) -> Result<InheritedDevice, EncDiscError> {
        if local_id.is_empty() {
            return Err(EncDiscError::EmptyDevice);
        }
        if parse_principal_id(local_id).is_ok() || parse_eip55(local_id).is_ok() {
            return Err(EncDiscError::IdentityRejected("device-id".into()));
        }
        Ok(InheritedDevice {
            local_id: local_id.to_string(),
            account: self.clone(),
        })
    }

    /// Wrap a DEK to this account's one `epub`.
    pub fn wrap_dek(
        &self,
        dek: &ItemDek,
        epoch: u64,
        object: &ObjectId,
        revision_id: &str,
    ) -> Result<WrappedKey, EncDiscError> {
        let named = NamedSet::try_from_accessors([self.principal.as_ref()])?;
        let mut wraps = wrap::wrap_item_dek_to_readers(
            dek,
            epoch,
            object.as_ref(),
            revision_id,
            &[self.enrolled_pub()],
            &named,
        )?;
        let wrap = wraps.pop().ok_or(EncDiscError::WrapRejected)?;
        if wraps.len() != 0 || wrap.target_id != self.epub() {
            return Err(EncDiscError::WrapRejected);
        }
        Ok(wrap)
    }
}

impl std::fmt::Debug for GenesisAccount {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenesisAccount")
            .field("principal", &self.principal)
            .field("epub", &self.epub())
            .field("priv", &"<redacted>")
            .field("epriv", &"<redacted>")
            .field("lane_id", &"<redacted>")
            .finish()
    }
}

impl InheritedDevice {
    pub fn local_id(&self) -> &str {
        &self.local_id
    }

    pub fn account(&self) -> &GenesisAccount {
        &self.account
    }

    /// Enrollment does not mint a grant.
    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn gun_document(&self) -> String {
        self.account.gun_document()
    }
}

impl std::fmt::Debug for InheritedDevice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InheritedDevice")
            .field("local_id", &self.local_id)
            .field("account", &self.account)
            .finish()
    }
}

impl TransportKey {
    pub fn generate() -> Result<Self, EncDiscError> {
        let secret = p256::SecretKey::random(&mut OsRng);
        Self::from_secret(secret)
    }

    pub fn from_scalar_hex(hex: &str) -> Result<Self, EncDiscError> {
        let bytes = hexutil::decode_secret_array::<32>(hex).map_err(|_| EncDiscError::BadKey)?;
        let secret =
            p256::SecretKey::from_slice(bytes.as_slice()).map_err(|_| EncDiscError::BadKey)?;
        Self::from_secret(secret)
    }

    pub fn sea_pub(&self) -> &str {
        &self.sea_pub
    }

    /// A transport key is never adopted as an account.
    pub fn is_account(&self) -> bool {
        false
    }

    fn from_secret(secret: p256::SecretKey) -> Result<Self, EncDiscError> {
        let mut scalar = Zeroizing::new([0u8; 32]);
        scalar.copy_from_slice(secret.to_bytes().as_slice());
        let sea_pub = sea::sea_pub_from_secret(&secret)?;
        Ok(Self { scalar, sea_pub })
    }

    fn secret_key(&self) -> Result<p256::SecretKey, EncDiscError> {
        p256::SecretKey::from_slice(self.scalar.as_slice()).map_err(|_| EncDiscError::BadKey)
    }
}

impl std::fmt::Debug for TransportKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransportKey")
            .field("sea_pub", &self.sea_pub)
            .field("scalar", &"<redacted>")
            .field("is_account", &false)
            .finish()
    }
}

impl MemoryKeyWrapStore {
    pub fn len(&self) -> usize {
        self.by_principal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_principal.is_empty()
    }
}

impl KeyWrapStore for MemoryKeyWrapStore {
    fn put_wrap(
        &mut self,
        index: &WrapIndex,
        wrap: &EncryptedAccountWrap,
    ) -> Result<(), EncDiscError> {
        if index.principal != wrap.principal
            || index.wrap_id != wrap.wrap_id
            || index.epub != wrap.epub
            || wrap.epub.is_empty()
            || wrap.signature.len() != 128
            || wrap.ciphertext_hex.len() > MAX_BACKUP_BYTES * 2
            || wrap.ciphertext_hex.is_empty()
            || hexutil::decode_hex(&wrap.signature).is_err()
            || hexutil::decode_hex(&wrap.ciphertext_hex).is_err()
        {
            return Err(EncDiscError::StoreRejected);
        }
        if let Some(existing) = self.by_principal.get(wrap.principal.as_ref()) {
            if existing.wrap_id != wrap.wrap_id {
                return Err(EncDiscError::StoreRejected);
            }
        }
        self.by_principal
            .insert(wrap.principal.as_ref().to_string(), wrap.clone());
        Ok(())
    }

    fn get_wrap(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<EncryptedAccountWrap>, EncDiscError> {
        Ok(self.by_principal.get(principal.as_ref()).cloned())
    }
}

impl LinkedCredential {
    pub fn principal(&self) -> &PrincipalId {
        match self {
            Self::Wallet { principal, .. } | Self::Oidc { principal, .. } => principal,
        }
    }

    pub fn same_account(&self, account: &PrincipalId) -> bool {
        self.principal() == account
    }

    /// `link` is a `verify_wallet_link` result. A bare principal is not a credential.
    pub fn from_wallet(link: &sociacl_ids::WalletLink) -> Self {
        Self::Wallet {
            principal: link.principal.clone(),
            address: link.address.to_string(),
        }
    }

    /// `link` is a `verify_oidc_link` result. The subject is not an account.
    pub fn from_oidc(link: &sociacl_ids::OidcLink) -> Self {
        Self::Oidc {
            principal: link.principal.clone(),
            issuer: link.cred.issuer().to_string(),
            tenant: link.cred.tenant().to_string(),
            subject: link.cred.subject().to_string(),
        }
    }
}

/// Parse an account id. Only a `PrincipalId` matches. Labels do not.
pub fn account_id_from_label(label: &str) -> Result<PrincipalId, EncDiscError> {
    parse_principal_id(label).map_err(reject)
}

/// Enrollment, hop, hint, wrap, request, and inbox delivery never grant.
pub fn delivery_mints_grant(kind: &str) -> Result<bool, EncDiscError> {
    match kind {
        "enrollment" | "hop" | "hint" | "wrap" | "request" | "inbox" => Ok(false),
        _ => Err(EncDiscError::IdentityRejected("unknown-delivery".into())),
    }
}

/// Soul for a grant between two principals. Uses `sociacl-ids` only.
pub fn account_grant_soul(
    owner: &PrincipalId,
    object: &ObjectId,
    accessor: &PrincipalId,
) -> String {
    grant_soul(owner, object, accessor).to_string()
}

pub fn parse_wrap_object(text: &str) -> Result<ObjectId, EncDiscError> {
    parse_object_id(text).map_err(reject)
}

/// Current signing key under the package's witnessed rotation rules.
/// The genesis id is not replaced here.
pub fn current_signing_key(
    genesis: &PrincipalId,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<PrincipalId, EncDiscError> {
    let resolved = sociacl_ids::resolve_current_key(genesis, rotations, context);
    resolved
        .result
        .map(|account| account.current_key)
        .map_err(reject)
}

/// Encrypt the genesis keypair to a transport **public** key and store the wrap.
///
/// The ephemeral key and nonce are generated here. The transport public key
/// must reach this device out of band (a QR code, or a short-code comparison).
/// Panopticon stores the wrap. It is not a channel that delivers that public key.
/// The signature is from the current signing key (`resolve_current_key`).
/// This device can sign only while that key is the genesis key it holds.
pub fn seal_account_backup(
    account: &GenesisAccount,
    transport_pub: &str,
    wrap_id: &ObjectId,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    store: &mut impl KeyWrapStore,
) -> Result<EncryptedAccountWrap, EncDiscError> {
    let ephemeral = p256::SecretKey::random(&mut OsRng);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    seal_account_backup_with(
        account,
        transport_pub,
        &ephemeral,
        &nonce,
        wrap_id,
        rotations,
        context,
        store,
    )
}

/// Caller-chosen ephemeral key and nonce. Tests only. Not exported.
fn seal_account_backup_with(
    account: &GenesisAccount,
    transport_pub: &str,
    ephemeral: &p256::SecretKey,
    nonce: &[u8; 12],
    wrap_id: &ObjectId,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
    store: &mut impl KeyWrapStore,
) -> Result<EncryptedAccountWrap, EncDiscError> {
    let _current = require_held_current_key(account, rotations, context)?;
    let wrap = encrypt_backup(account, transport_pub, ephemeral, nonce, wrap_id)?;
    let index = WrapIndex {
        principal: wrap.principal.clone(),
        wrap_id: wrap.wrap_id.clone(),
        epub: wrap.epub.clone(),
    };
    store.put_wrap(&index, &wrap)?;
    Ok(wrap)
}

/// Open a wrap for `expected`. A store row that names some other account is rejected.
///
/// The signature is checked against `resolve_current_key(expected)` before import.
pub fn open_account_backup(
    transport: &TransportKey,
    wrap: &EncryptedAccountWrap,
    expected: &PrincipalId,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<GenesisAccount, EncDiscError> {
    if transport.is_account() {
        return Err(EncDiscError::IdentityRejected("transport".into()));
    }
    let blob = decode_backup(&wrap.ciphertext_hex)?;
    if blob.first().copied() != Some(VER_BACKUP) || blob.len() < 1 + 65 + 12 + 16 {
        return Err(EncDiscError::WrapRejected);
    }
    let ephemeral =
        p256::PublicKey::from_sec1_bytes(&blob[1..66]).map_err(|_| EncDiscError::WrapRejected)?;
    let nonce: [u8; 12] = blob[66..78]
        .try_into()
        .map_err(|_| EncDiscError::WrapRejected)?;
    let current = current_signing_key(expected, rotations, context)?;
    let message = signature_message(&blob, transport.sea_pub(), wrap.wrap_id.as_ref())?;
    sea::verify_sea(current.as_ref(), &message, &wrap.signature)?;
    let ephemeral_sea = sea::sea_pub_from_point(&ephemeral)?;
    let secret = transport.secret_key()?;
    let shared = ecdh_x(&secret, &ephemeral)?;
    let aes_key = kdf_backup(
        &shared,
        expected.as_ref(),
        wrap.wrap_id.as_ref(),
        transport.sea_pub(),
        &ephemeral_sea,
    )?;
    let aad = aad_backup(
        expected.as_ref(),
        wrap.wrap_id.as_ref(),
        transport.sea_pub(),
        &ephemeral_sea,
    )?;
    let plain = decrypt(&aes_key, &nonce, &aad, &blob[78..])?;
    let mut fields = decode_secret_fields(&plain)?;
    if fields.len() != 6 || fields[0].as_str() != DOMAIN_ACCOUNT_WRAP {
        for field in &mut fields {
            field.zeroize();
        }
        return Err(EncDiscError::WrapRejected);
    }
    let account = match GenesisAccount::import(
        fields[5].as_str(),
        fields[1].as_str(),
        fields[2].as_str(),
        fields[3].as_str(),
        fields[4].as_str(),
    ) {
        Ok(account) => account,
        Err(error) => {
            for field in &mut fields {
                field.zeroize();
            }
            return Err(error);
        }
    };
    for field in &mut fields {
        field.zeroize();
    }
    if account.principal() != expected
        || account.principal() != &wrap.principal
        || account.epub() != wrap.epub
    {
        return Err(EncDiscError::WrapRejected);
    }
    Ok(account)
}

fn encrypt_backup(
    account: &GenesisAccount,
    transport_pub: &str,
    ephemeral: &p256::SecretKey,
    nonce: &[u8; 12],
    wrap_id: &ObjectId,
) -> Result<EncryptedAccountWrap, EncDiscError> {
    let peer = require_transport_pub(account, transport_pub)?;
    let ephemeral_pub = sea::sea_pub_from_secret(ephemeral)?;
    let shared = ecdh_x(ephemeral, &peer)?;
    let aes_key = kdf_backup(
        &shared,
        account.principal().as_ref(),
        wrap_id.as_ref(),
        transport_pub,
        &ephemeral_pub,
    )?;
    let aad = aad_backup(
        account.principal().as_ref(),
        wrap_id.as_ref(),
        transport_pub,
        &ephemeral_pub,
    )?;
    let mut plain = Zeroizing::new(canonical::length_prefixed(&[
        DOMAIN_ACCOUNT_WRAP,
        account.principal().as_ref(),
        account.local_priv(),
        account.epub(),
        account.local_epriv(),
        account.lane_id(),
    ])?);
    let ciphertext = encrypt(&aes_key, nonce, &aad, &plain)?;
    plain.zeroize();
    let point = uncompressed_point(&ephemeral.public_key())?;
    let mut blob = Vec::with_capacity(1 + 65 + 12 + ciphertext.len());
    blob.push(VER_BACKUP);
    blob.extend_from_slice(&point);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext);
    if blob.len() > MAX_BACKUP_BYTES {
        return Err(EncDiscError::WrapRejected);
    }
    backup_hides_scalars(&blob, account)?;
    let message = signature_message(&blob, transport_pub, wrap_id.as_ref())?;
    let signature = sea::sign_sea(account.local_priv(), &message)?;
    Ok(EncryptedAccountWrap {
        principal: account.principal().clone(),
        wrap_id: wrap_id.clone(),
        epub: account.epub().to_string(),
        ciphertext_hex: encode_hex(&blob),
        signature,
    })
}

fn require_transport_pub(
    account: &GenesisAccount,
    transport_pub: &str,
) -> Result<p256::PublicKey, EncDiscError> {
    if transport_pub == account.sea_pub() || transport_pub == account.epub() {
        return Err(EncDiscError::IdentityRejected("transport".into()));
    }
    sea::parse_sea_point(transport_pub)
        .map_err(|_| EncDiscError::IdentityRejected("transport".into()))
}

fn require_held_current_key(
    account: &GenesisAccount,
    rotations: &[serde_json::Value],
    context: &sociacl_ids::ResolutionContext<'_>,
) -> Result<PrincipalId, EncDiscError> {
    let current = current_signing_key(account.principal(), rotations, context)?;
    if current.as_ref() != account.sea_pub() {
        return Err(EncDiscError::IdentityRejected("current-key".into()));
    }
    Ok(current)
}

fn kdf_backup(
    shared_x: &[u8; 32],
    principal: &str,
    wrap_id: &str,
    transport_pub: &str,
    ephemeral_pub: &str,
) -> Result<Zeroizing<[u8; 32]>, EncDiscError> {
    let hex = encode_secret_hex(shared_x);
    let bytes = Zeroizing::new(canonical::length_prefixed(&[
        DOMAIN_ACCOUNT_BIND,
        hex.as_str(),
        principal,
        wrap_id,
        transport_pub,
        ephemeral_pub,
    ])?);
    Ok(Zeroizing::new(canonical::sha256(&bytes)))
}

fn aad_backup(
    principal: &str,
    wrap_id: &str,
    transport_pub: &str,
    ephemeral_pub: &str,
) -> Result<Vec<u8>, EncDiscError> {
    canonical::length_prefixed(&[
        DOMAIN_ACCOUNT_BIND,
        principal,
        wrap_id,
        transport_pub,
        ephemeral_pub,
    ])
}

fn signature_message(
    blob: &[u8],
    transport_pub: &str,
    wrap_id: &str,
) -> Result<Vec<u8>, EncDiscError> {
    let digest = canonical::sha256_hex(blob);
    canonical::length_prefixed(&[DOMAIN_ACCOUNT_SIG, digest.as_str(), transport_pub, wrap_id])
}

fn backup_hides_scalars(blob: &[u8], account: &GenesisAccount) -> Result<(), EncDiscError> {
    let signing = sea::signing_key(account.local_priv())?;
    let encryption = sea::ecdh_secret(account.local_epriv())?;
    let mut sign_bytes = Zeroizing::new([0u8; 32]);
    let mut enc_bytes = Zeroizing::new([0u8; 32]);
    sign_bytes.copy_from_slice(signing.to_bytes().as_slice());
    enc_bytes.copy_from_slice(encryption.to_bytes().as_slice());
    if contains_bytes(blob, sign_bytes.as_slice()) || contains_bytes(blob, enc_bytes.as_slice()) {
        return Err(EncDiscError::WrapRejected);
    }
    let hex = encode_hex(blob);
    let sign_hex = encode_secret_hex(sign_bytes.as_slice());
    let enc_hex = encode_secret_hex(enc_bytes.as_slice());
    if hex.contains(sign_hex.as_str()) || hex.contains(enc_hex.as_str()) {
        return Err(EncDiscError::WrapRejected);
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn decode_backup(hex_text: &str) -> Result<Vec<u8>, EncDiscError> {
    if hex_text.len() > MAX_BACKUP_BYTES * 2 {
        return Err(EncDiscError::WrapRejected);
    }
    hexutil::decode_hex(hex_text).map_err(|_| EncDiscError::WrapRejected)
}

fn decode_secret_fields(bytes: &[u8]) -> Result<Vec<Zeroizing<String>>, EncDiscError> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(EncDiscError::BadEncoding);
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let len = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;
        if bytes.len() - offset < len {
            return Err(EncDiscError::BadEncoding);
        }
        let field = std::str::from_utf8(&bytes[offset..offset + len])
            .map_err(|_| EncDiscError::BadEncoding)?;
        out.push(Zeroizing::new(field.to_string()));
        offset += len;
    }
    Ok(out)
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::WrapRejected)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| EncDiscError::WrapRejected)
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::WrapRejected)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| EncDiscError::WrapRejected)?;
    Ok(Zeroizing::new(plain))
}

fn reject(reason: Reason) -> EncDiscError {
    EncDiscError::NotPrincipal(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wrap::{open_reader_wrap, DetachedEphemeral};
    use serde_json::Value;
    use sociacl_ids::{
        history_state, verify_oidc_link, verify_wallet_link, HistoryResolver, Jwks, KeyState,
        PrincipalId, Reason, ResolutionContext, Rotate, SiwePolicy,
    };
    use std::collections::{BTreeMap, BTreeSet};

    const VECTOR: &str = include_str!("../../../vectors/encrypted-discovery/account-key.json");
    const RECORDS: &str = include_str!("../../../vectors/ids/records.json");

    fn vector() -> Value {
        serde_json::from_str(VECTOR).unwrap()
    }

    fn fixture_account(v: &Value) -> GenesisAccount {
        GenesisAccount::import(
            v["laneId"].as_str().unwrap(),
            v["signingPub"].as_str().unwrap(),
            v["signingPriv"].as_str().unwrap(),
            v["epub"].as_str().unwrap(),
            v["epriv"].as_str().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn enrollment_inherits_one_keypair_and_secrets_stay_off_gun() {
        let v = vector();
        let account = fixture_account(&v);
        assert_eq!(
            account.principal().as_ref(),
            v["principal"].as_str().unwrap()
        );
        assert_eq!(account.sea_pub(), account.principal().as_ref());
        assert_eq!(account.principal_key(), v["principalKey"].as_str().unwrap());
        assert_ne!(account.epub(), account.principal().as_ref());
        let phone = account.enroll("phone").unwrap();
        let laptop = account.enroll("laptop").unwrap();
        assert_eq!(phone.account().principal(), laptop.account().principal());
        assert_eq!(phone.account().epub(), laptop.account().epub());
        assert_eq!(phone.account().local_priv(), laptop.account().local_priv());
        assert_eq!(
            phone.account().local_epriv(),
            laptop.account().local_epriv()
        );
        assert_eq!(phone.account().lane_id(), laptop.account().lane_id());
        assert!(!phone.grants_see());
        assert!(!laptop.grants_see());
        assert!(account.enroll("").is_err());
        assert!(account.enroll(account.principal().as_ref()).is_err());
        assert!(account.enroll(v["wallet"].as_str().unwrap()).is_err());

        let gun = phone.gun_document();
        assert_eq!(gun, v["gunDocument"].as_str().unwrap());
        assert!(!gun.contains(account.local_priv()));
        assert!(!gun.contains(account.local_epriv()));
        assert!(!gun.contains(v["signingScalarHex"].as_str().unwrap()));
        assert!(!gun.contains(&v["signingScalarHex"].as_str().unwrap().to_ascii_lowercase()));
        assert!(!gun.contains("\"priv\""));
        assert!(!gun.contains("\"epriv\""));
        assert!(!gun.contains("phone"));
        assert!(!gun.contains("laptop"));
        assert!(!gun.contains(account.lane_id()));
        let rendered = format!("{phone:?}{account:?}");
        assert!(!rendered.contains(account.local_priv()));
        assert!(!rendered.contains(account.local_epriv()));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn labels_are_not_accounts_and_credentials_are_not_identities() {
        let v = vector();
        let account = fixture_account(&v);
        for row in v["nonIdentities"].as_array().unwrap() {
            let err = account_id_from_label(row["input"].as_str().unwrap()).unwrap_err();
            assert_eq!(
                err,
                EncDiscError::NotPrincipal(row["reason"].as_str().unwrap().to_string()),
                "{}",
                row["name"].as_str().unwrap()
            );
        }
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let wallet = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "wallet")
            .unwrap();
        let oidc = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "oidc")
            .unwrap();
        let (jwks, policy, pinned, now, genesis) = record_parts(&records);
        let key_state = KeyState {
            key: genesis.clone(),
            current_key: genesis.clone(),
            retained_links: None,
        };
        let verified =
            verify_wallet_link(&wallet["input"], &jwks, &policy, now, &key_state).unwrap();
        let linked = LinkedCredential::from_wallet(&verified);
        assert!(linked.same_account(&genesis));
        assert!(!linked.same_account(account.principal()));
        assert_ne!(linked.principal().as_ref(), verified.address.as_ref());
        assert!(account_id_from_label(verified.address.as_ref()).is_err());

        let verified_oidc =
            verify_oidc_link(&oidc["input"], &jwks, &pinned, now, &key_state).unwrap();
        let oidc_link = LinkedCredential::from_oidc(&verified_oidc);
        assert!(oidc_link.same_account(&genesis));
        assert_ne!(oidc_link.principal().as_ref(), verified_oidc.cred.subject());
        assert!(account_id_from_label(verified_oidc.cred.subject()).is_err());
        assert!(account_id_from_label(verified_oidc.cred.issuer()).is_err());
    }

    #[test]
    fn rotation_uses_the_package_current_key() {
        let v = vector();
        let account = fixture_account(&v);
        let epub = account.epub().to_string();
        let records: Value = serde_json::from_str(RECORDS).unwrap();
        let rotate = records["accept"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "wallet-rotate")
            .unwrap();
        let current = resolve_fixture(&records, &rotate["input"]);
        assert_eq!(
            current.as_ref(),
            rotate["input"]["nextKey"].as_str().unwrap()
        );
        assert_ne!(
            current.as_ref(),
            records["context"]["genesis"].as_str().unwrap()
        );
        assert_ne!(current.as_ref(), v["wallet"].as_str().unwrap());
        assert_eq!(
            account.principal().as_ref(),
            v["principal"].as_str().unwrap()
        );
        assert_eq!(account.epub(), epub);
        assert_ne!(account.epub(), current.as_ref());
    }

    #[test]
    fn backup_wrap_is_stored_not_authoritative_and_devices_share_one_epub() {
        let v = vector();
        let account = fixture_account(&v);
        let transport =
            TransportKey::from_scalar_hex(v["backupWrap"]["transportScalarHex"].as_str().unwrap())
                .unwrap();
        assert!(!transport.is_account());
        assert_ne!(transport.sea_pub(), account.principal().as_ref());
        assert_ne!(transport.sea_pub(), account.epub());
        assert_eq!(
            transport.sea_pub(),
            v["backupWrap"]["transportPub"].as_str().unwrap()
        );
        let ephemeral = secret_from_hex(v["backupWrap"]["ephemeralScalarHex"].as_str().unwrap());
        let nonce = nonce_from_hex(v["backupWrap"]["nonceHex"].as_str().unwrap());
        let wrap_id = parse_wrap_object(v["backupWrap"]["wrapId"].as_str().unwrap()).unwrap();
        let mut store = MemoryKeyWrapStore::default();
        assert!(!store.is_authority());
        assert!(!store.mints_grant());
        let parts = empty_resolution();
        let context = parts.context();
        let wrap = seal_account_backup_with(
            &account,
            transport.sea_pub(),
            &ephemeral,
            &nonce,
            &wrap_id,
            &[],
            &context,
            &mut store,
        )
        .unwrap();
        assert_eq!(
            wrap.ciphertext_hex,
            v["backupWrap"]["ciphertextHex"].as_str().unwrap()
        );
        assert_eq!(
            wrap.signature,
            v["backupWrap"]["signature"].as_str().unwrap()
        );
        assert_eq!(wrap.epub, account.epub());
        let signing = sea::signing_key(account.local_priv()).unwrap();
        let encryption = sea::ecdh_secret(account.local_epriv()).unwrap();
        let sign_hex = crate::hexutil::encode_secret_hex(signing.to_bytes().as_slice());
        let enc_hex = crate::hexutil::encode_secret_hex(encryption.to_bytes().as_slice());
        assert!(!wrap.ciphertext_hex.contains(sign_hex.as_str()));
        assert!(!wrap.ciphertext_hex.contains(enc_hex.as_str()));
        assert!(seal_account_backup(
            &account,
            account.epub(),
            &wrap_id,
            &[],
            &context,
            &mut MemoryKeyWrapStore::default(),
        )
        .is_err());
        assert!(seal_account_backup(
            &account,
            account.sea_pub(),
            &wrap_id,
            &[],
            &context,
            &mut MemoryKeyWrapStore::default(),
        )
        .is_err());
        let gun = account.gun_document();
        assert!(!gun.contains(&wrap.ciphertext_hex));
        assert!(!gun.contains(account.local_priv()));
        let stored = store.get_wrap(account.principal()).unwrap().unwrap();
        let opened =
            open_account_backup(&transport, &stored, account.principal(), &[], &context).unwrap();
        assert_eq!(opened.principal(), account.principal());
        assert_eq!(opened.local_priv(), account.local_priv());
        assert_eq!(opened.local_epriv(), account.local_epriv());
        assert_eq!(opened.epub(), account.epub());
        let inherited = opened.enroll("tablet").unwrap();
        assert!(!inherited.grants_see());
        assert_eq!(inherited.account().epub(), account.epub());

        let dek = ItemDek::from_bytes(dek_bytes(v["contentWrap"]["dekHex"].as_str().unwrap()));
        let object = parse_wrap_object(v["contentWrap"]["objectId"].as_str().unwrap()).unwrap();
        let seal = DetachedEphemeral {
            epriv: sea::sea_priv_from_secret(&secret_from_hex(
                v["contentWrap"]["ephemeralScalarHex"].as_str().unwrap(),
            ))
            .unwrap()
            .to_string(),
            nonce: nonce_from_hex(v["contentWrap"]["nonceHex"].as_str().unwrap()),
        };
        let named = NamedSet::try_from_accessors([account.principal().as_ref()]).unwrap();
        let wraps = wrap::wrap_item_dek_to_readers_with(
            &dek,
            v["contentWrap"]["epoch"].as_u64().unwrap(),
            object.as_ref(),
            v["contentWrap"]["revisionId"].as_str().unwrap(),
            &[account.enrolled_pub()],
            &named,
            &[seal],
        )
        .unwrap();
        assert_eq!(wraps.len(), 1);
        assert_eq!(wraps[0].target_id, account.epub());
        assert_eq!(
            wraps[0].wrapped_key,
            v["contentWrap"]["wrappedKey"].as_str().unwrap()
        );
        let phone = account.enroll("phone").unwrap();
        let laptop = account.enroll("laptop").unwrap();
        let opened_phone = open_reader_wrap(
            &wraps[0],
            phone.account().local_epriv(),
            phone.account().epub(),
        )
        .unwrap();
        let opened_laptop = open_reader_wrap(
            &wraps[0],
            laptop.account().local_epriv(),
            laptop.account().epub(),
        )
        .unwrap();
        assert_eq!(opened_phone.key_bytes(), opened_laptop.key_bytes());
        assert!(!opened_phone.grants_see());
        assert!(!opened_laptop.grants_see());
        let soul = account_grant_soul(account.principal(), &object, account.principal());
        assert_eq!(soul.split('/').count(), 5);
        assert!(soul.contains(&account.principal_key()));
        assert!(!soul.contains(account.principal().as_ref()));
        assert!(!crate::inbox::lanes_per_device());
    }

    #[test]
    fn substituted_wrap_sealed_to_the_victim_transport_pub_does_not_open() {
        let v = vector();
        let victim = fixture_account(&v);
        let attacker = GenesisAccount::import(
            v["substitution"]["laneId"].as_str().unwrap(),
            v["substitution"]["signingPub"].as_str().unwrap(),
            v["substitution"]["signingPriv"].as_str().unwrap(),
            v["substitution"]["epub"].as_str().unwrap(),
            v["substitution"]["epriv"].as_str().unwrap(),
        )
        .unwrap();
        assert_ne!(attacker.principal(), victim.principal());
        let transport =
            TransportKey::from_scalar_hex(v["backupWrap"]["transportScalarHex"].as_str().unwrap())
                .unwrap();
        let ephemeral = secret_from_hex(v["substitution"]["ephemeralScalarHex"].as_str().unwrap());
        let nonce = nonce_from_hex(v["substitution"]["nonceHex"].as_str().unwrap());
        let wrap_id = parse_wrap_object(v["substitution"]["wrapId"].as_str().unwrap()).unwrap();
        let parts = empty_resolution();
        let context = parts.context();
        let mut store = MemoryKeyWrapStore::default();
        let wrap = seal_account_backup_with(
            &attacker,
            transport.sea_pub(),
            &ephemeral,
            &nonce,
            &wrap_id,
            &[],
            &context,
            &mut store,
        )
        .unwrap();
        assert_eq!(
            wrap.ciphertext_hex,
            v["substitution"]["ciphertextHex"].as_str().unwrap()
        );
        assert_eq!(
            wrap.signature,
            v["substitution"]["signature"].as_str().unwrap()
        );
        assert!(
            open_account_backup(&transport, &wrap, victim.principal(), &[], &context,).is_err()
        );
        let mut relabeled = wrap.clone();
        relabeled.principal = victim.principal().clone();
        relabeled.epub = victim.epub().to_string();
        assert!(
            open_account_backup(&transport, &relabeled, victim.principal(), &[], &context,)
                .is_err()
        );
        let mut huge = wrap.clone();
        huge.ciphertext_hex = "ab".repeat(MAX_BACKUP_BYTES + 1);
        assert!(
            open_account_backup(&transport, &huge, attacker.principal(), &[], &context).is_err()
        );
        assert!(store
            .put_wrap(
                &WrapIndex {
                    principal: huge.principal.clone(),
                    wrap_id: huge.wrap_id.clone(),
                    epub: huge.epub.clone(),
                },
                &huge,
            )
            .is_err());
    }

    #[test]
    fn random_public_seal_opens_only_for_the_expected_principal() {
        let v = vector();
        let account = fixture_account(&v);
        let transport =
            TransportKey::from_scalar_hex(v["backupWrap"]["transportScalarHex"].as_str().unwrap())
                .unwrap();
        let wrap_id = parse_wrap_object(v["backupWrap"]["wrapId"].as_str().unwrap()).unwrap();
        let parts = empty_resolution();
        let context = parts.context();
        let mut store = MemoryKeyWrapStore::default();
        let first = seal_account_backup(
            &account,
            transport.sea_pub(),
            &wrap_id,
            &[],
            &context,
            &mut store,
        )
        .unwrap();
        let mut other = MemoryKeyWrapStore::default();
        let second = seal_account_backup(
            &account,
            transport.sea_pub(),
            &parse_wrap_object("wrap_ffeeddccbbaa99887766554433221100").unwrap(),
            &[],
            &context,
            &mut other,
        )
        .unwrap();
        assert_ne!(first.ciphertext_hex, second.ciphertext_hex);
        let opened =
            open_account_backup(&transport, &first, account.principal(), &[], &context).unwrap();
        assert_eq!(opened.principal(), account.principal());
        assert_eq!(opened.local_priv(), account.local_priv());
    }

    #[test]
    fn enrollment_hop_hint_wrap_request_and_inbox_do_not_grant() {
        let v = vector();
        for kind in v["deliveries"].as_array().unwrap() {
            assert_eq!(delivery_mints_grant(kind.as_str().unwrap()).unwrap(), false);
        }
        assert!(delivery_mints_grant("grant").is_err());
        let account = fixture_account(&v);
        assert!(!account.enroll("phone").unwrap().grants_see());
        let hop = sociacl_gun::HopFactor::Slhp(b"not-a-grant".to_vec());
        assert!(!hop.is_grant());
        let hint = sociacl_gun::accept_hint(
            sociacl_gun::HandoffHint::new(
                account.principal().as_ref(),
                "item",
                None::<&str>,
                None::<&str>,
            )
            .unwrap(),
        );
        let checked = sociacl_gun::MeshCheckResult {
            allowed: false,
            reason: "missing".into(),
            hint: Some(hint),
            hop: Some(hop),
        };
        assert!(!checked.hint_is_grant());
        assert!(!checked.hop_is_grant());
        assert!(!checked.wrap_is_grant());
        assert!(!checked.request_is_grant());
        assert!(!checked.inbox_is_grant());
        assert!(!sociacl_gun::factor_grants("enrollment"));
        assert!(!sociacl_gun::factor_grants("request"));
        let intro = crate::accept_first_contact(
            &crate::FirstContactIntro {
                account: account.principal().as_ref().to_string(),
                sea_pub: account.sea_pub().to_string(),
                epub: account.epub().to_string(),
                binding: crate::AccountKeyBinding::Enrollment,
            },
            &account.enrolled_pub(),
        )
        .unwrap();
        assert!(!intro.grants_see());
        assert!(!intro.opens_lane());
    }

    struct EmptyResolution {
        jwks: Jwks,
        policy: SiwePolicy,
        pinned: BTreeSet<String>,
        links: BTreeMap<String, Value>,
        revocations: Vec<Value>,
    }

    impl EmptyResolution {
        fn context(&self) -> ResolutionContext<'_> {
            ResolutionContext {
                jwks: &self.jwks,
                links: &self.links,
                revocations: &self.revocations,
                now: 1_700_000_060,
                policy: &self.policy,
                pinned_iss: &self.pinned,
                history: &missing_history,
            }
        }
    }

    fn missing_history(
        _principal: &PrincipalId,
        _at: u64,
        _until: u64,
    ) -> Result<KeyState, Reason> {
        Err(Reason::MissingHistory)
    }

    fn empty_resolution() -> EmptyResolution {
        EmptyResolution {
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

    fn secret_from_hex(hex: &str) -> p256::SecretKey {
        let bytes = hexutil::decode_hex(hex).unwrap();
        p256::SecretKey::from_slice(&bytes).unwrap()
    }

    fn nonce_from_hex(hex: &str) -> [u8; 12] {
        let bytes = hexutil::decode_hex(hex).unwrap();
        bytes.try_into().unwrap()
    }

    fn dek_bytes(hex: &str) -> [u8; 32] {
        hexutil::decode_hex(hex).unwrap().try_into().unwrap()
    }

    fn record_parts(records: &Value) -> (Jwks, SiwePolicy, BTreeSet<String>, u64, PrincipalId) {
        let ctx = &records["context"];
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let pinned = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let genesis = parse_principal_id(ctx["genesis"].as_str().unwrap()).unwrap();
        (jwks, policy, pinned, ctx["now"].as_u64().unwrap(), genesis)
    }

    fn resolve_fixture(records: &Value, rotation: &Value) -> PrincipalId {
        let ctx = &records["context"];
        let (jwks, policy, pinned, now, genesis) = record_parts(records);
        let links = links_of(ctx);
        let history = |p: &PrincipalId, at, until| {
            if !ctx["authenticatedAccounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a.as_str() == Some(p.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            let empty: Vec<Rotate> = Vec::new();
            Ok(history_state(p, &empty, at, until))
        };
        let resolver: &HistoryResolver<'_> = &history;
        let revocations = Vec::new();
        let context = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &revocations,
            now,
            policy: &policy,
            pinned_iss: &pinned,
            history: resolver,
        };
        current_signing_key(&genesis, std::slice::from_ref(rotation), &context).unwrap()
    }

    fn links_of(ctx: &Value) -> BTreeMap<String, Value> {
        ctx["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
            .collect()
    }
}
