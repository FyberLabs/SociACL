//! Presenter binding.
//!
//! The destination issues a nonce and an audience. The presenter signs
//! the length-prefixed fields `s3rch-presenter-binding-v1`, the nonce,
//! the commitment hash, and that audience. A signature for a different
//! audience does not verify, and the nonce stays outstanding.
//!
//! `AuthenticatedPresenterChannel` is the transport capability. Its
//! brand is the private field set by [`AuthenticatedPresenterChannel::open`].
//! External code cannot construct the value. The TypeScript contract
//! uses an ECMAScript private field and a module `WeakSet` for the same
//! check. A channel is not a grant.

use crate::account::AccountSeaSecret;
use crate::canonical::{self, presenter_binding_bytes};
use crate::error::EncDiscError;
use crate::sea;

/// Nonce signature. `reader_pub` is the claimed key, not the enrollment record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenterBinding {
    pub nonce: String,
    pub signature: String,
    pub reader_pub: String,
}

/// One outstanding nonce. The presenter does not supply this object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenterChallenge {
    pub nonce: String,
    pub expires_at: u64,
    pub audience: String,
}

/// Verifier-held challenges. Spending one nonce leaves the others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierChallengeState {
    pub outstanding: Vec<PresenterChallenge>,
    pub spent: Vec<String>,
}

/// Private brand. Not a reflectable property and not `Copy` for callers.
struct ChannelBrand {
    _private: (),
}

/// Transport-minted capability. `open` is the only constructor.
pub struct AuthenticatedPresenterChannel {
    accessor: String,
    reader_pub: String,
    brand: ChannelBrand,
}

impl AuthenticatedPresenterChannel {
    /// Mint a channel for one accessor and that accessor's SEA pub.
    pub fn open(accessor: &str, reader_pub: &str) -> Result<Self, EncDiscError> {
        if accessor.is_empty() {
            return Err(EncDiscError::EmptyAccount);
        }
        sea::parse_sea_point(reader_pub)?;
        Ok(Self {
            accessor: accessor.to_string(),
            reader_pub: reader_pub.to_string(),
            brand: ChannelBrand { _private: () },
        })
    }

    pub fn accessor(&self) -> &str {
        &self.accessor
    }

    pub fn reader_pub(&self) -> &str {
        &self.reader_pub
    }

    /// True only for a value `open` minted. The brand is not a public field.
    pub fn has_transport_brand(&self) -> bool {
        let _ = &self.brand;
        true
    }
}

impl std::fmt::Debug for AuthenticatedPresenterChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedPresenterChannel")
            .field("accessor", &self.accessor)
            .field("reader_pub", &self.reader_pub)
            .field("brand", &"transport")
            .finish()
    }
}

impl AccountSeaSecret {
    pub fn sign_presenter_binding(
        &self,
        nonce: &str,
        commitment_hash: &str,
        audience: &str,
    ) -> Result<String, EncDiscError> {
        let message = presenter_binding_bytes(nonce, commitment_hash, audience)?;
        sea::sign_sea(self.local_priv(), &message)
    }
}

pub fn binding_for(
    secret: &AccountSeaSecret,
    nonce: &str,
    commitment_hash: &str,
    audience: &str,
) -> Result<PresenterBinding, EncDiscError> {
    Ok(PresenterBinding {
        nonce: nonce.to_string(),
        signature: secret.sign_presenter_binding(nonce, commitment_hash, audience)?,
        reader_pub: secret.sea_pub().to_string(),
    })
}

/// Verify one binding against one challenge. Does not spend the nonce.
pub fn verify_presenter_binding(
    binding: &PresenterBinding,
    challenge: &PresenterChallenge,
    commitment_hash: &str,
    enrolled_reader_pub: &str,
    now: u64,
) -> Result<(), EncDiscError> {
    if binding.nonce.is_empty() || challenge.nonce.is_empty() {
        return Err(EncDiscError::PresenterRejected);
    }
    if binding.nonce != challenge.nonce {
        return Err(EncDiscError::PresenterRejected);
    }
    if now >= challenge.expires_at {
        return Err(EncDiscError::PresenterRejected);
    }
    if binding.reader_pub != enrolled_reader_pub {
        return Err(EncDiscError::PubMismatch);
    }
    canonical::require_digest_hex(commitment_hash).map_err(|_| EncDiscError::CommitmentRejected)?;
    let message = presenter_binding_bytes(&challenge.nonce, commitment_hash, &challenge.audience)?;
    // The only audience is the one on the challenge. A different audience
    // does not verify, and the caller leaves the nonce outstanding.
    sea::verify_sea(enrolled_reader_pub, &message, &binding.signature)
}

pub fn challenge_for<'a>(
    state: &'a VerifierChallengeState,
    nonce: &str,
) -> Result<&'a PresenterChallenge, EncDiscError> {
    if state.spent.iter().any(|spent| spent == nonce) {
        return Err(EncDiscError::PresenterRejected);
    }
    state
        .outstanding
        .iter()
        .find(|challenge| challenge.nonce == nonce)
        .ok_or(EncDiscError::PresenterRejected)
}

pub fn spend_nonce(state: &mut VerifierChallengeState, nonce: &str) {
    state
        .outstanding
        .retain(|challenge| challenge.nonce != nonce);
    if !state.spent.iter().any(|spent| spent == nonce) {
        state.spent.push(nonce.to_string());
    }
}
