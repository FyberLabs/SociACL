//! Rotation on revoke.
//!
//! Privilege-down is immediate. The settle window is not an input, so
//! it cannot delay `stated: 0`. The owner then wraps the winning next
//! epoch to the remaining readers and chooses `forward-only` or
//! `re-encrypt` for ciphertext that already exists. A wrap produced
//! here is not a grant. Bytes a revoked reader already unwrapped stay
//! readable to them.

use crate::account::EnrolledSeaPub;
use crate::canonical;
use crate::epoch::{
    self, snapshot_can_settle, AclSnapshotBody, EpochManifest, EpochStatusProof, GroupEpochConfig,
};
use crate::error::EncDiscError;
use crate::grant::{GrantStated, MeshSeeGrant, SignedGrantPayload};
use crate::sea;
use crate::see::MeshMembership;
use crate::wrap::{WrapScope, WrapTarget, WrappedKey};

/// Owner's choice for ciphertext that already exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeCipherMode {
    ForwardOnly,
    ReEncrypt,
}

impl RevokeCipherMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForwardOnly => "forward-only",
            Self::ReEncrypt => "re-encrypt",
        }
    }
}

/// Where the grant lives. A plaintext edge does not cancel a private row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStorage {
    PublicPlain,
    PrivateRow,
}

/// Plaintext see edge or a direct membership, after privilege-down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlainGrant {
    See(MeshSeeGrant),
    Membership(MeshMembership),
}

/// `stated: 0` plus the bumped `hamState`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelledGrant {
    pub grant: PlainGrant,
    pub ham_state: u64,
}

/// One cancel. Plain and private-row do not mix on one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotationCancel {
    Plain {
        grant: CancelledGrant,
    },
    PrivateRow {
        payload: SignedGrantPayload,
        signature: String,
        status: EpochStatusProof,
    },
}

/// Revoke record. Privilege-down, then wraps of the next epoch, then cipher mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRotation {
    pub object: String,
    pub revoked_epoch: u64,
    pub next_epoch: u64,
    pub revision_id: String,
    pub cancelled: Vec<RotationCancel>,
    pub rewrapped: Vec<WrappedKey>,
    pub cipher: RevokeCipherMode,
}

/// Verifier-held prior row for one accessor. The presenter does not supply it.
///
/// `grant_revision` is the private-row high water. `ham_state` is the
/// merged live plaintext edge. A cancel must be strictly newer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorRevision {
    pub accessor: String,
    pub grant_revision: u64,
    pub ham_state: u64,
}

/// Owner state the rotation is checked against. Not a presenter argument.
pub struct RotationContext<'a> {
    pub owner: &'a str,
    pub owner_pub: &'a str,
    pub storage: GrantStorage,
    pub manifest: &'a EpochManifest,
    pub snapshot: &'a AclSnapshotBody,
    pub readers: &'a [EnrolledSeaPub],
    pub prior_revision: &'a [PriorRevision],
    pub now: u64,
    pub skew_allowance_ms: u64,
    pub policy_max_age_ms: u64,
    pub group_config: Option<&'a GroupEpochConfig>,
    pub owner_of_set: Option<&'a str>,
}

/// What the check accepted. `grants_see` stays false.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationOutcome {
    pub revoked_accessors: Vec<String>,
    pub wrapped_accessors: Vec<String>,
    pub cipher: RevokeCipherMode,
    /// `forward-only` leaves the old soul. `re-encrypt` replaces it.
    pub old_ciphertext_stays: bool,
    /// Honest limit, both modes. A local copy is not erased.
    pub unwrapped_bytes_remain_readable: bool,
}

impl RotationOutcome {
    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn privilege_down_immediate(&self) -> bool {
        true
    }

    pub fn delays_privilege_down(&self) -> bool {
        false
    }

    /// New writes stay buffered until the winner settles.
    pub fn encrypts_new_writes_under_settled_key(&self) -> bool {
        false
    }
}

/// Privilege-down first, then wraps of the winning next revision.
///
/// The settle window is not consulted. A revoked reader is absent from
/// `rewrapped`. An opened wrap still does not grant.
pub fn rotate_on_revoke(
    rotation: &EpochRotation,
    context: &RotationContext<'_>,
) -> Result<RotationOutcome, EncDiscError> {
    if rotation.object.is_empty() || context.owner.is_empty() {
        return Err(EncDiscError::RotationRejected);
    }
    let Some(next) = rotation.revoked_epoch.checked_add(1) else {
        return Err(EncDiscError::RotationRejected);
    };
    if rotation.next_epoch != next {
        return Err(EncDiscError::RotationRejected);
    }
    let _ = canonical::canonical_decimal(rotation.revoked_epoch)?;
    let _ = canonical::canonical_decimal(rotation.next_epoch)?;
    canonical::require_revision_id(&rotation.revision_id)?;
    if rotation.revision_id != context.manifest.revision_id
        || context.manifest.object != rotation.object
        || context.manifest.epoch != rotation.next_epoch
        || context.manifest.previous_epoch != rotation.revoked_epoch
    {
        return Err(EncDiscError::RotationRejected);
    }
    context
        .manifest
        .verify(context.snapshot, context.owner_pub)?;
    if !snapshot_can_settle(context.snapshot, context.now) {
        return Err(EncDiscError::RotationRejected);
    }
    require_group_window(context)?;
    if rotation.cancelled.is_empty() || readers_conflict(context.readers) {
        return Err(EncDiscError::RotationRejected);
    }

    let mut revoked = Vec::new();
    for cancel in &rotation.cancelled {
        let accessor = require_cancel(rotation, context, cancel)?;
        if revoked.iter().any(|held: &String| held == &accessor) {
            return Err(EncDiscError::RotationRejected);
        }
        revoked.push(accessor);
    }
    require_snapshot_lists_cancels(context.snapshot, &rotation.cancelled, &revoked)?;
    let wrapped = require_wraps(rotation, context, &revoked)?;
    revoked.sort();
    Ok(RotationOutcome {
        revoked_accessors: revoked,
        wrapped_accessors: wrapped,
        cipher: rotation.cipher,
        old_ciphertext_stays: rotation.cipher == RevokeCipherMode::ForwardOnly,
        unwrapped_bytes_remain_readable: true,
    })
}

fn require_group_window(context: &RotationContext<'_>) -> Result<(), EncDiscError> {
    match (&context.snapshot.object_set, context.group_config) {
        (None, None) => Ok(()),
        (Some(set), Some(config)) => {
            config
                .verify(context.owner_pub, context.owner_of_set)
                .map_err(|_| EncDiscError::RotationRejected)?;
            if config.predicate != set.predicate
                || config.set_id != set.set_id
                || config.settle_window_ms != context.manifest.settle_window_ms
                || set.stated != GrantStated::Live
            {
                return Err(EncDiscError::RotationRejected);
            }
            Ok(())
        }
        _ => Err(EncDiscError::RotationRejected),
    }
}

fn readers_conflict(readers: &[EnrolledSeaPub]) -> bool {
    for (index, reader) in readers.iter().enumerate() {
        if reader.account.is_empty() || reader.epub.is_empty() {
            return true;
        }
        if readers
            .iter()
            .skip(index + 1)
            .any(|other| other.account == reader.account || other.epub == reader.epub)
        {
            return true;
        }
    }
    false
}

fn require_cancel(
    rotation: &EpochRotation,
    context: &RotationContext<'_>,
    cancel: &RotationCancel,
) -> Result<String, EncDiscError> {
    match (context.storage, cancel) {
        (GrantStorage::PublicPlain, RotationCancel::Plain { grant }) => {
            plain_accessor(rotation, context, grant)
        }
        (
            GrantStorage::PrivateRow,
            RotationCancel::PrivateRow {
                payload,
                signature,
                status,
            },
        ) => private_accessor(rotation, context, payload, signature, status),
        _ => Err(EncDiscError::RotationRejected),
    }
}

fn plain_accessor(
    rotation: &EpochRotation,
    context: &RotationContext<'_>,
    grant: &CancelledGrant,
) -> Result<String, EncDiscError> {
    if grant.ham_state == 0 {
        return Err(EncDiscError::RotationRejected);
    }
    let _ = canonical::canonical_decimal(grant.ham_state)?;
    let accessor = match &grant.grant {
        PlainGrant::See(see) => {
            if see.object != rotation.object
                || see.accessor.is_empty()
                || see.stated != GrantStated::Cancelled
            {
                return Err(EncDiscError::RotationRejected);
            }
            see.accessor.clone()
        }
        PlainGrant::Membership(edge) => {
            if edge.accessor.is_empty()
                || edge.stated != GrantStated::Cancelled
                || edge.ham_state != grant.ham_state
                || edge.set_id.is_empty()
            {
                return Err(EncDiscError::RotationRejected);
            }
            edge.accessor.clone()
        }
    };
    let Some(prior) = context
        .prior_revision
        .iter()
        .find(|row| row.accessor == accessor)
    else {
        return Err(EncDiscError::RotationRejected);
    };
    let _ = canonical::canonical_decimal(prior.ham_state)?;
    if grant.ham_state <= prior.ham_state {
        return Err(EncDiscError::RotationRejected);
    }
    Ok(accessor)
}

fn private_accessor(
    rotation: &EpochRotation,
    context: &RotationContext<'_>,
    payload: &SignedGrantPayload,
    signature: &str,
    status: &EpochStatusProof,
) -> Result<String, EncDiscError> {
    payload
        .validate()
        .map_err(|_| EncDiscError::RotationRejected)?;
    if payload.object != rotation.object
        || payload.owner != context.owner
        || payload.stated != GrantStated::Cancelled
        || payload.epoch != rotation.revoked_epoch
        || payload.accessor.is_empty()
    {
        return Err(EncDiscError::RotationRejected);
    }
    let Some(prior) = context
        .prior_revision
        .iter()
        .find(|row| row.accessor == payload.accessor)
    else {
        return Err(EncDiscError::RotationRejected);
    };
    if payload.grant_revision <= prior.grant_revision {
        return Err(EncDiscError::RotationRejected);
    }
    let message = canonical::grant_payload_bytes(&payload.body())?;
    sea::verify_sea(context.owner_pub, &message, signature)?;
    if status.object != payload.object
        || status.zookie.object != payload.object
        || status.accessor != payload.accessor
        || status.grant_revision != payload.grant_revision
        || status.stated != GrantStated::Cancelled
        || status.epoch != payload.epoch
    {
        return Err(EncDiscError::RotationRejected);
    }
    canonical::require_revision_id(&status.revision_id)
        .map_err(|_| EncDiscError::RotationRejected)?;
    let status_bytes = canonical::epoch_status_bytes(&status.body())?;
    sea::verify_sea(context.owner_pub, &status_bytes, &status.signature)?;
    if !epoch::status_is_fresh(
        status,
        context.now,
        context.skew_allowance_ms,
        context.policy_max_age_ms,
    ) {
        return Err(EncDiscError::RotationRejected);
    }
    Ok(payload.accessor.clone())
}

fn require_snapshot_lists_cancels(
    snapshot: &AclSnapshotBody,
    cancels: &[RotationCancel],
    revoked: &[String],
) -> Result<(), EncDiscError> {
    for accessor in revoked {
        let Some(entry) = snapshot
            .entries
            .iter()
            .find(|row| row.accessor == *accessor)
        else {
            return Err(EncDiscError::RotationRejected);
        };
        if entry.stated != GrantStated::Cancelled {
            return Err(EncDiscError::RotationRejected);
        }
        if let Some(RotationCancel::PrivateRow { payload, .. }) = cancels
            .iter()
            .find(|cancel| cancel_accessor(cancel).as_deref() == Some(accessor.as_str()))
        {
            if entry.grant_revision < payload.grant_revision {
                return Err(EncDiscError::RotationRejected);
            }
        }
        if let Some(RotationCancel::Plain { grant }) = cancels
            .iter()
            .find(|cancel| cancel_accessor(cancel).as_deref() == Some(accessor.as_str()))
        {
            if let PlainGrant::Membership(edge) = &grant.grant {
                if entry.scope.as_str() != edge.predicate.as_str()
                    || entry.set_id != edge.set_id
                    || entry.ham_state != edge.ham_state
                {
                    return Err(EncDiscError::RotationRejected);
                }
            }
        }
    }
    Ok(())
}

fn cancel_accessor(cancel: &RotationCancel) -> Option<&str> {
    match cancel {
        RotationCancel::Plain { grant } => match &grant.grant {
            PlainGrant::See(see) => Some(see.accessor.as_str()),
            PlainGrant::Membership(edge) => Some(edge.accessor.as_str()),
        },
        RotationCancel::PrivateRow { payload, .. } => Some(payload.accessor.as_str()),
    }
}

fn require_wraps(
    rotation: &EpochRotation,
    context: &RotationContext<'_>,
    revoked: &[String],
) -> Result<Vec<String>, EncDiscError> {
    let mut needed = Vec::new();
    for entry in &context.snapshot.entries {
        let live = entry.stated == GrantStated::Live
            && entry.from <= context.now
            && context.now < entry.until;
        if entry.stated == GrantStated::Live && !live {
            return Err(EncDiscError::RotationRejected);
        }
        if live {
            if revoked.iter().any(|accessor| accessor == &entry.accessor) {
                return Err(EncDiscError::RotationRejected);
            }
            needed.push(entry.accessor.clone());
        }
    }
    let mut seen_group = false;
    let mut wrapped = Vec::new();
    for wrap in &rotation.rewrapped {
        if wrap.epoch != rotation.next_epoch
            || wrap.revision_id != rotation.revision_id
            || wrap.wrapped_key.is_empty()
        {
            return Err(EncDiscError::RotationRejected);
        }
        match (wrap.scope, wrap.target) {
            (WrapScope::ItemDek, WrapTarget::ReaderEpub) => {
                if wrap.object.as_deref() != Some(rotation.object.as_str())
                    || !wrap.group.as_deref().unwrap_or("").is_empty()
                {
                    return Err(EncDiscError::RotationRejected);
                }
                let Some(accessor) = reader_account(context.readers, &wrap.target_id) else {
                    return Err(EncDiscError::RotationRejected);
                };
                if revoked.iter().any(|revoked| revoked == accessor)
                    || !needed.iter().any(|needed| needed == accessor)
                    || wrapped.iter().any(|held: &String| held == accessor)
                {
                    return Err(EncDiscError::RotationRejected);
                }
                wrapped.push(accessor.to_string());
            }
            (WrapScope::ItemDek, WrapTarget::GroupEpoch) => {
                let Some(set) = &context.snapshot.object_set else {
                    return Err(EncDiscError::RotationRejected);
                };
                if seen_group
                    || wrap.target_id != set.set_id
                    || wrap.group.as_deref() != Some(set.set_id.as_str())
                    || wrap.object.as_deref() != Some(rotation.object.as_str())
                    || set.stated != GrantStated::Live
                {
                    return Err(EncDiscError::RotationRejected);
                }
                seen_group = true;
            }
            (WrapScope::GroupKey, WrapTarget::ReaderEpub)
            | (WrapScope::GroupKey, WrapTarget::GroupEpoch) => {
                return Err(EncDiscError::RotationRejected);
            }
        }
    }
    if wrapped.len() != needed.len() {
        return Err(EncDiscError::RotationRejected);
    }
    wrapped.sort();
    Ok(wrapped)
}

fn reader_account<'a>(readers: &'a [EnrolledSeaPub], epub: &str) -> Option<&'a str> {
    readers
        .iter()
        .find(|reader| reader.epub == epub)
        .map(|reader| reader.account.as_str())
}
