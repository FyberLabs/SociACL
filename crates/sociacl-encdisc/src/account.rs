//! One SEA keypair per account.
//!
//! Devices inherit that keypair through enrollment. Enrollment copies
//! it onto the device. It does not write `priv` or `epriv` to Gun, it
//! does not mint a second keypair, and it does not mint a grant. The
//! inbox lane stays one per account. Wraps for that account use the
//! one `epub`.
//!
//! `identityPub` is that same SEA `pub`, not a second keypair.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::canonical::{self, ItemAuthFields};
use crate::error::EncDiscError;
use crate::hexutil::encode_secret_hex;
use crate::sea::{self, ecdh_secret, signing_key};

/// Device-local account key. `priv` and `epriv` are not on the Gun view.
#[derive(Clone)]
pub struct AccountSeaSecret {
    account: String,
    lane_id: String,
    sea_pub: String,
    sea_priv: Zeroizing<String>,
    epub: String,
    epriv: Zeroizing<String>,
}

/// What may sit on the user node. No `priv`, no `epriv`, no lane id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSeaKey {
    pub account: String,
    /// SEA signing `pub`. JSON name is `pub`.
    pub sea_pub: String,
    pub epub: String,
}

/// One private lane for the account. Not one lane per device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientInbox {
    pub accessor: String,
    pub lane_id: String,
}

/// A device that inherited the account keypair.
///
/// `device_id` is local to this enrollment. It is not a Gun device
/// record, not a second SEA keypair, and not a grant.
#[derive(Clone)]
pub struct DeviceEnrollment {
    device_id: String,
    secret: AccountSeaSecret,
}

/// Verifier-held enrollment. The introduction does not supply this.
///
/// An empty `identity_pub` is missing and fails an account-signature
/// check. An empty `epub` fails every introduction. `identity_pub`
/// must equal `sea_pub` when it is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledSeaPub {
    pub account: String,
    pub sea_pub: String,
    pub epub: String,
    pub identity_pub: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountKeyBinding {
    Enrollment,
    AccountSignature { signature: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstContactIntro {
    pub account: String,
    pub sea_pub: String,
    pub epub: String,
    pub binding: AccountKeyBinding,
}

/// A checked introduction. Not a grant and not a second lane.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct AcceptedIntro {
    pub account: String,
    pub sea_pub: String,
    pub epub: String,
}

impl AccountSeaSecret {
    /// Mint the one keypair for a new account, and one lane id.
    pub fn generate(account: &str) -> Result<Self, EncDiscError> {
        if account.is_empty() {
            return Err(EncDiscError::EmptyAccount);
        }
        let mut rng = OsRng;
        let signing = p256::ecdsa::SigningKey::random(&mut rng);
        let encryption = p256::SecretKey::random(&mut rng);
        let mut lane = [0u8; 32];
        rng.fill_bytes(&mut lane);
        let lane_hex = encode_secret_hex(&lane);
        lane.zeroize();
        Self::from_generated(account, lane_hex.as_str(), &signing, &encryption)
    }

    /// Restore a device-local copy. Rejects a `pub` that does not match
    /// `priv`, or an `epub` that does not match `epriv`.
    pub fn import_local(
        account: &str,
        lane_id: &str,
        sea_pub: &str,
        sea_priv: &str,
        epub: &str,
        epriv: &str,
    ) -> Result<Self, EncDiscError> {
        if account.is_empty() {
            return Err(EncDiscError::EmptyAccount);
        }
        require_lane(lane_id)?;
        let signing = signing_key(sea_priv)?;
        let derived_pub = sea::sea_pub_from_signing(&signing)?;
        if derived_pub != sea_pub {
            return Err(EncDiscError::PubMismatch);
        }
        let encryption = ecdh_secret(epriv)?;
        let derived_epub = sea::sea_pub_from_secret(&encryption)?;
        if derived_epub != epub {
            return Err(EncDiscError::EpubMismatch);
        }
        // Parsing also rejects a scalar that is not on the curve order.
        let _ = sea::parse_sea_point(sea_pub)?;
        let _ = sea::parse_sea_point(epub)?;
        Ok(Self {
            account: account.to_string(),
            lane_id: lane_id.to_string(),
            sea_pub: sea_pub.to_string(),
            sea_priv: Zeroizing::new(sea_priv.to_string()),
            epub: epub.to_string(),
            epriv: Zeroizing::new(epriv.to_string()),
        })
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn lane_id(&self) -> &str {
        &self.lane_id
    }

    pub fn sea_pub(&self) -> &str {
        &self.sea_pub
    }

    pub fn epub(&self) -> &str {
        &self.epub
    }

    /// Device-local signing scalar (SEA `priv`). Never write this to Gun.
    pub fn local_priv(&self) -> &str {
        &self.sea_priv
    }

    /// Device-local ECDH scalar (SEA `epriv`). Never write this to Gun.
    pub fn local_epriv(&self) -> &str {
        &self.epriv
    }

    pub fn public_key(&self) -> AccountSeaKey {
        AccountSeaKey {
            account: self.account.clone(),
            sea_pub: self.sea_pub.clone(),
            epub: self.epub.clone(),
        }
    }

    pub fn inbox(&self) -> RecipientInbox {
        RecipientInbox {
            accessor: self.account.clone(),
            lane_id: self.lane_id.clone(),
        }
    }

    /// JSON object with `account`, `pub`, and `epub` only.
    pub fn gun_public_json(&self) -> String {
        self.public_key().gun_public_json()
    }

    /// Copy the same keypair and the same lane onto a device.
    pub fn enroll(&self, device_id: &str) -> Result<DeviceEnrollment, EncDiscError> {
        if device_id.is_empty() {
            return Err(EncDiscError::EmptyDevice);
        }
        Ok(DeviceEnrollment {
            device_id: device_id.to_string(),
            secret: self.clone(),
        })
    }

    pub fn sign_account_binding(&self) -> Result<String, EncDiscError> {
        let message = canonical::account_binding_bytes(&self.account, &self.sea_pub, &self.epub)?;
        sea::sign_sea(&self.sea_priv, &message)
    }

    /// Owner signature over `revisionId`. A signature over `keyCommitment` is not this.
    pub fn sign_epoch_manifest(&self, revision_id: &str) -> Result<String, EncDiscError> {
        canonical::require_revision_id(revision_id)?;
        let message = canonical::epoch_manifest_sig_bytes(revision_id)?;
        sea::sign_sea(&self.sea_priv, &message)
    }

    /// Owner signature over `finalizationId`. A signature over `revisionId` is not this.
    pub fn sign_epoch_finalization(&self, finalization_id: &str) -> Result<String, EncDiscError> {
        canonical::require_revision_id(finalization_id)?;
        let message = canonical::epoch_finalization_sig_bytes(finalization_id)?;
        sea::sign_sea(&self.sea_priv, &message)
    }

    /// Owner signature over the group-epoch config bytes. `owner` is this account.
    pub fn sign_group_epoch_config(
        &self,
        set_id: &str,
        predicate: &str,
        settle_window_ms: u64,
        config_revision: u64,
    ) -> Result<String, EncDiscError> {
        let message = canonical::group_epoch_config_bytes(
            &self.account,
            set_id,
            predicate,
            settle_window_ms,
            config_revision,
        )?;
        sea::sign_sea(&self.sea_priv, &message)
    }

    pub fn sign_item_auth(&self, fields: &ItemAuthFields) -> Result<String, EncDiscError> {
        canonical::require_digest_hex(&fields.plaintext_digest)?;
        canonical::require_revision_id(&fields.revision_id)?;
        let message = canonical::item_auth_bytes(fields)?;
        sea::sign_sea(&self.sea_priv, &message)
    }

    fn from_generated(
        account: &str,
        lane_id: &str,
        signing: &p256::ecdsa::SigningKey,
        encryption: &p256::SecretKey,
    ) -> Result<Self, EncDiscError> {
        let sea_pub = sea::sea_pub_from_signing(signing)?;
        let sea_priv = sea::sea_priv_from_signing(signing)?;
        let epub = sea::sea_pub_from_secret(encryption)?;
        let epriv = sea::sea_priv_from_secret(encryption)?;
        Self::import_local(account, lane_id, &sea_pub, &sea_priv, &epub, &epriv)
    }
}

impl std::fmt::Debug for AccountSeaSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountSeaSecret")
            .field("account", &self.account)
            .field("lane_id", &"<redacted>")
            .field("pub", &self.sea_pub)
            .field("epub", &self.epub)
            .field("priv", &"<redacted>")
            .field("epriv", &"<redacted>")
            .finish()
    }
}

impl AccountSeaKey {
    pub fn gun_public_json(&self) -> String {
        format!(
            "{{\"account\":{},\"pub\":{},\"epub\":{}}}",
            json_string(&self.account),
            json_string(&self.sea_pub),
            json_string(&self.epub),
        )
    }
}

impl DeviceEnrollment {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn secret(&self) -> &AccountSeaSecret {
        &self.secret
    }

    pub fn public_key(&self) -> AccountSeaKey {
        self.secret.public_key()
    }

    pub fn inbox(&self) -> RecipientInbox {
        self.secret.inbox()
    }

    pub fn gun_public_json(&self) -> String {
        self.secret.gun_public_json()
    }

    /// Enrollment does not mint a grant.
    pub fn grants_see(&self) -> bool {
        false
    }
}

impl std::fmt::Debug for DeviceEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceEnrollment")
            .field("device_id", &self.device_id)
            .field("secret", &self.secret)
            .finish()
    }
}

impl EnrolledSeaPub {
    /// A record this verifier already holds. `identity_pub` is the one SEA pub.
    pub fn from_account(secret: &AccountSeaSecret) -> Self {
        Self {
            account: secret.account.clone(),
            sea_pub: secret.sea_pub.clone(),
            epub: secret.epub.clone(),
            identity_pub: secret.sea_pub.clone(),
        }
    }
}

impl AcceptedIntro {
    /// An introduction does not set `allowed`.
    pub fn grants_see(&self) -> bool {
        false
    }

    /// An introduction does not open a second lane.
    pub fn opens_lane(&self) -> bool {
        false
    }
}

/// Accept a first introduction. The verification key is `identity_pub`
/// on the enrolled record. The introduced `pub` is never that key.
pub fn accept_first_contact(
    intro: &FirstContactIntro,
    enrolled: &EnrolledSeaPub,
) -> Result<AcceptedIntro, EncDiscError> {
    if intro.account.is_empty() || enrolled.account.is_empty() {
        return Err(EncDiscError::EmptyAccount);
    }
    if intro.account != enrolled.account {
        return Err(EncDiscError::BindingRejected);
    }
    if intro.epub.is_empty() || enrolled.epub.is_empty() {
        return Err(EncDiscError::EpubRequired);
    }
    if sea::parse_sea_point(&intro.epub).is_err() || sea::parse_sea_point(&enrolled.epub).is_err() {
        return Err(EncDiscError::BadKey);
    }
    if intro.sea_pub.is_empty() || enrolled.sea_pub.is_empty() {
        return Err(EncDiscError::PubMismatch);
    }
    if sea::parse_sea_point(&intro.sea_pub).is_err()
        || sea::parse_sea_point(&enrolled.sea_pub).is_err()
    {
        return Err(EncDiscError::BadKey);
    }
    if intro.epub != enrolled.epub {
        return Err(EncDiscError::EpubMismatch);
    }
    if !enrolled.identity_pub.is_empty() && enrolled.identity_pub != enrolled.sea_pub {
        return Err(EncDiscError::PubMismatch);
    }

    match &intro.binding {
        AccountKeyBinding::Enrollment => {
            if intro.sea_pub != enrolled.sea_pub {
                return Err(EncDiscError::PubMismatch);
            }
        }
        AccountKeyBinding::AccountSignature { signature } => {
            // The only verification key. There is no fallback to intro.sea_pub.
            let verify_key = enrolled.identity_pub.as_str();
            if verify_key.is_empty() {
                return Err(EncDiscError::IdentityPubMissing);
            }
            if intro.sea_pub != verify_key {
                return Err(EncDiscError::PubMismatch);
            }
            let message =
                canonical::account_binding_bytes(&intro.account, &intro.sea_pub, &intro.epub)?;
            sea::verify_sea(verify_key, &message, signature)?;
        }
    }

    Ok(AcceptedIntro {
        account: intro.account.clone(),
        sea_pub: intro.sea_pub.clone(),
        epub: intro.epub.clone(),
    })
}

pub fn verify_item_auth(
    owner_pub: &str,
    fields: &ItemAuthFields,
    signature: &str,
) -> Result<(), EncDiscError> {
    canonical::require_digest_hex(&fields.plaintext_digest)?;
    canonical::require_revision_id(&fields.revision_id)?;
    let message = canonical::item_auth_bytes(fields)?;
    sea::verify_sea(owner_pub, &message, signature)
}

/// 32 bytes of lowercase hex. The same check account mint uses.
pub(crate) fn lane_id_well_formed(lane_id: &str) -> bool {
    lane_id.len() == 64 && crate::hexutil::decode_hex(lane_id).is_ok()
}

pub(crate) fn require_lane(lane_id: &str) -> Result<(), EncDiscError> {
    if !lane_id_well_formed(lane_id) {
        return Err(EncDiscError::BadLane);
    }
    Ok(())
}

pub(crate) fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other.is_control() => {
                out.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}
