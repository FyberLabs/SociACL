//! Hidden authorship.
//!
//! A visible row stores ciphertext, a commitment hash, and an optional
//! wrap. It has no owner id and no owner SEA pub. The blinding stays in
//! the ciphertext and in the presentation. An unsalted hash of the grant
//! bytes is not the commitment.
//!
//! Opening recomputes the commitment and checks the owner signature.
//! That opening is not a grant. Author fast unwrap is a local DEK bound
//! to one `revisionId`. It does not scan a lane and it does not present
//! a commitment.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::account::AccountSeaSecret;
use crate::canonical::{
    self, grant_commitment_hash, grant_payload_bytes, grant_payload_digest, inbox_entry_id,
    EpochStatusBody, GrantPayloadBody, InboxEntryBody, InboxWrapFields,
};
use crate::error::EncDiscError;
use crate::hexutil::{decode_hex, encode_hex};
use crate::sea;
use crate::wrap::WrappedKey;

/// `stated` on a signed grant. `0` cancels. `1` is live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStated {
    Cancelled,
    Live,
}

impl GrantStated {
    pub fn from_u64(value: u64) -> Result<Self, EncDiscError> {
        match value {
            0 => Ok(Self::Cancelled),
            1 => Ok(Self::Live),
            _ => Err(EncDiscError::PayloadRejected),
        }
    }

    pub fn as_u64(self) -> u64 {
        match self {
            Self::Cancelled => 0,
            Self::Live => 1,
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Live)
    }
}

/// Opened canonical grant. The signature covers these fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGrantPayload {
    pub object: String,
    pub accessor: String,
    pub from: u64,
    pub until: u64,
    pub stated: GrantStated,
    pub epoch: u64,
    pub owner: String,
    pub grant_revision: u64,
    pub item_ciphertext_digest: String,
}

/// In-graph shape carried in a presentation. It must match the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshSeeGrant {
    pub object: String,
    pub accessor: String,
    pub from: u64,
    pub until: u64,
    pub stated: GrantStated,
}

/// SHA-256 of a fresh blinding plus the canonical grant. Hash only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantCommitment {
    pub hash: String,
}

/// Visible lane entry. No owner field and no `hamState`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindedGrantRow {
    pub lane_id: String,
    pub entry_id: String,
    pub grant_ciphertext: String,
    pub commitment: GrantCommitment,
    pub wrap: Option<WrappedKey>,
}

/// What the holder shows the destination. Not written to Gun.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantPresentation {
    pub owner: String,
    pub grant: MeshSeeGrant,
    pub grant_revision: u64,
    pub grant_bytes: String,
    pub blinding: String,
    pub signature: String,
    pub sea_pub: String,
}

/// Local author DEK. Not a Gun row and not a grant.
#[derive(Clone)]
pub struct AuthorFastUnwrap {
    object: String,
    epoch: u64,
    revision_id: String,
    dek: Zeroizing<String>,
}

impl SignedGrantPayload {
    pub fn validate(&self) -> Result<(), EncDiscError> {
        if self.object.is_empty() {
            return Err(EncDiscError::EmptyObject);
        }
        if self.accessor.is_empty() || self.owner.is_empty() {
            return Err(EncDiscError::EmptyAccount);
        }
        if !self.item_ciphertext_digest.is_empty() {
            canonical::require_digest_hex(&self.item_ciphertext_digest)
                .map_err(|_| EncDiscError::DigestRejected)?;
        }
        Ok(())
    }

    pub fn body(&self) -> GrantPayloadBody {
        GrantPayloadBody {
            object: self.object.clone(),
            accessor: self.accessor.clone(),
            from: self.from,
            until: self.until,
            stated: self.stated.as_u64(),
            epoch: self.epoch,
            owner: self.owner.clone(),
            grant_revision: self.grant_revision,
            item_ciphertext_digest: self.item_ciphertext_digest.clone(),
        }
    }

    pub fn names_item(&self) -> bool {
        !self.item_ciphertext_digest.is_empty()
    }
}

/// 32 fresh random bytes, lowercase hex. Not a field of the visible row.
pub fn fresh_blinding() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

pub fn require_blinding(blinding: &str) -> Result<(), EncDiscError> {
    if blinding.len() != 64 || decode_hex(blinding).is_err() {
        return Err(EncDiscError::CommitmentRejected);
    }
    Ok(())
}

pub fn commit_grant(
    blinding: &str,
    payload: &SignedGrantPayload,
) -> Result<GrantCommitment, EncDiscError> {
    payload.validate()?;
    require_blinding(blinding)?;
    let hash = grant_commitment_hash(blinding, &payload.body())?;
    Ok(GrantCommitment { hash })
}

/// Lowercase hex of the signed payload bytes.
pub fn encode_grant_bytes(payload: &SignedGrantPayload) -> Result<String, EncDiscError> {
    payload.validate()?;
    Ok(encode_hex(&grant_payload_bytes(&payload.body())?))
}

pub fn grant_digest(payload: &SignedGrantPayload) -> Result<String, EncDiscError> {
    payload.validate()?;
    grant_payload_digest(&payload.body())
}

pub fn decode_grant_bytes(grant_bytes: &str) -> Result<SignedGrantPayload, EncDiscError> {
    let raw = decode_hex(grant_bytes).map_err(|_| EncDiscError::PayloadRejected)?;
    let fields = canonical::decode_length_prefixed(&raw)?;
    if fields.len() != 10 || fields[0] != canonical::DOMAIN_GRANT_PAYLOAD {
        return Err(EncDiscError::PayloadRejected);
    }
    let payload = SignedGrantPayload {
        object: fields[1].clone(),
        accessor: fields[2].clone(),
        from: canonical::parse_canonical_decimal(&fields[3])?,
        until: canonical::parse_canonical_decimal(&fields[4])?,
        stated: GrantStated::from_u64(canonical::parse_canonical_decimal(&fields[5])?)?,
        epoch: canonical::parse_canonical_decimal(&fields[6])?,
        owner: fields[7].clone(),
        grant_revision: canonical::parse_canonical_decimal(&fields[8])?,
        item_ciphertext_digest: fields[9].clone(),
    };
    payload.validate()?;
    Ok(payload)
}

pub fn seal_blinded_row(
    lane_id: &str,
    grant_ciphertext: &str,
    commitment: GrantCommitment,
    wrap: Option<WrappedKey>,
) -> Result<BlindedGrantRow, EncDiscError> {
    if lane_id.is_empty() || grant_ciphertext.is_empty() {
        return Err(EncDiscError::RowRejected);
    }
    canonical::require_digest_hex(&commitment.hash)
        .map_err(|_| EncDiscError::CommitmentRejected)?;
    let entry_id = inbox_entry_id(&inbox_body(
        lane_id,
        grant_ciphertext,
        &commitment,
        wrap.as_ref(),
    ))?;
    Ok(BlindedGrantRow {
        lane_id: lane_id.to_string(),
        entry_id,
        grant_ciphertext: grant_ciphertext.to_string(),
        commitment,
        wrap,
    })
}

pub fn row_entry_matches(row: &BlindedGrantRow) -> Result<bool, EncDiscError> {
    let id = inbox_entry_id(&inbox_body(
        &row.lane_id,
        &row.grant_ciphertext,
        &row.commitment,
        row.wrap.as_ref(),
    ))?;
    Ok(id == row.entry_id)
}

/// True when a visible field contains the owner pub or the blinding.
///
/// The row has no owner field and no blinding field. Ciphertext that
/// was built to hide them does not contain those strings.
pub fn row_exposes_opening(row: &BlindedGrantRow, owner_pub: &str, blinding: &str) -> bool {
    let mut fields = vec![
        row.lane_id.as_str(),
        row.entry_id.as_str(),
        row.grant_ciphertext.as_str(),
        row.commitment.hash.as_str(),
    ];
    if let Some(wrap) = &row.wrap {
        fields.push(wrap.target_id.as_str());
        fields.push(wrap.revision_id.as_str());
        fields.push(wrap.wrapped_key.as_str());
        if let Some(object) = wrap.object.as_deref() {
            fields.push(object);
        }
        if let Some(group) = wrap.group.as_deref() {
            fields.push(group);
        }
    }
    let needles = [owner_pub, blinding];
    fields.iter().any(|field| {
        needles
            .iter()
            .any(|needle| !needle.is_empty() && field.contains(needle))
    })
}

/// Recompute the commitment and check the presented signature.
///
/// Does not read enrollment, does not spend a nonce, and does not grant.
pub fn open_commitment(
    row: &BlindedGrantRow,
    presentation: &GrantPresentation,
) -> Result<SignedGrantPayload, EncDiscError> {
    if !row_entry_matches(row)? {
        return Err(EncDiscError::RowRejected);
    }
    let payload = decode_grant_bytes(&presentation.grant_bytes)?;
    if !presentation_matches(presentation, &payload) {
        return Err(EncDiscError::PayloadRejected);
    }
    require_blinding(&presentation.blinding)?;
    let hash = grant_commitment_hash(&presentation.blinding, &payload.body())?;
    if hash != row.commitment.hash {
        return Err(EncDiscError::CommitmentRejected);
    }
    let message = grant_payload_bytes(&payload.body())?;
    sea::verify_sea(&presentation.sea_pub, &message, &presentation.signature)?;
    Ok(payload)
}

pub fn presentation_matches(
    presentation: &GrantPresentation,
    payload: &SignedGrantPayload,
) -> bool {
    presentation.owner == payload.owner
        && presentation.grant_revision == payload.grant_revision
        && presentation.grant.object == payload.object
        && presentation.grant.accessor == payload.accessor
        && presentation.grant.from == payload.from
        && presentation.grant.until == payload.until
        && presentation.grant.stated == payload.stated
}

impl AuthorFastUnwrap {
    /// Store a local DEK for one manifest revision.
    pub fn store(
        object: &str,
        epoch: u64,
        revision_id: &str,
        dek_hex: &str,
    ) -> Result<Self, EncDiscError> {
        if object.is_empty() {
            return Err(EncDiscError::EmptyObject);
        }
        canonical::require_revision_id(revision_id)?;
        let bytes = crate::hexutil::decode_hex_array::<32>(dek_hex)
            .map_err(|_| EncDiscError::DigestRejected)?;
        Ok(Self {
            object: object.to_string(),
            epoch,
            revision_id: revision_id.to_string(),
            dek: Zeroizing::new(encode_hex(&bytes)),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    /// Return the local DEK only when the object and revision match.
    ///
    /// The epoch number is not enough. A displaced manifest of the same
    /// epoch does not open.
    pub fn open(&self, object: &str, revision_id: &str) -> Result<String, EncDiscError> {
        if object != self.object || revision_id != self.revision_id {
            return Err(EncDiscError::AuthorUnwrapRejected);
        }
        Ok((*self.dek).clone())
    }

    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn scans_lane(&self) -> bool {
        false
    }

    pub fn presents_commitment(&self) -> bool {
        false
    }
}

impl std::fmt::Debug for AuthorFastUnwrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorFastUnwrap")
            .field("object", &self.object)
            .field("epoch", &self.epoch)
            .field("revision_id", &self.revision_id)
            .field("dek", &"<redacted>")
            .finish()
    }
}

impl AccountSeaSecret {
    pub fn sign_grant(&self, payload: &SignedGrantPayload) -> Result<String, EncDiscError> {
        if payload.owner != self.account() {
            return Err(EncDiscError::PayloadRejected);
        }
        let message = grant_payload_bytes(&payload.body())?;
        sea::sign_sea(self.local_priv(), &message)
    }

    pub fn sign_epoch_status(&self, body: &EpochStatusBody) -> Result<String, EncDiscError> {
        let message = canonical::epoch_status_bytes(body)?;
        sea::sign_sea(self.local_priv(), &message)
    }

    /// Sign a presentation that matches `payload`. Not a grant.
    pub fn present_grant(
        &self,
        payload: &SignedGrantPayload,
        blinding: &str,
    ) -> Result<GrantPresentation, EncDiscError> {
        let signature = self.sign_grant(payload)?;
        Ok(GrantPresentation {
            owner: payload.owner.clone(),
            grant: MeshSeeGrant {
                object: payload.object.clone(),
                accessor: payload.accessor.clone(),
                from: payload.from,
                until: payload.until,
                stated: payload.stated,
            },
            grant_revision: payload.grant_revision,
            grant_bytes: encode_grant_bytes(payload)?,
            blinding: blinding.to_string(),
            signature,
            sea_pub: self.sea_pub().to_string(),
        })
    }
}

pub fn inbox_body_of(row: &BlindedGrantRow) -> InboxEntryBody {
    inbox_body(
        &row.lane_id,
        &row.grant_ciphertext,
        &row.commitment,
        row.wrap.as_ref(),
    )
}

fn inbox_body(
    lane_id: &str,
    grant_ciphertext: &str,
    commitment: &GrantCommitment,
    wrap: Option<&WrappedKey>,
) -> InboxEntryBody {
    InboxEntryBody {
        lane_id: lane_id.to_string(),
        grant_ciphertext: grant_ciphertext.to_string(),
        commitment_hash: commitment.hash.clone(),
        wrap: wrap.map(|wrap| InboxWrapFields {
            scope: wrap.scope.as_str().to_string(),
            epoch: wrap.epoch,
            target: wrap.target.as_str().to_string(),
            target_id: wrap.target_id.clone(),
            object: wrap.object.clone(),
            group: wrap.group.clone(),
            revision_id: wrap.revision_id.clone(),
            wrapped_key: wrap.wrapped_key.clone(),
        }),
    }
}
