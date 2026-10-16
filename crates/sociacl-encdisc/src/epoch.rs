//! Read-key half of an epoch step.
//!
//! `checkPresentedGrant` asks whether the signed window has elapsed and
//! the winning snapshot still matches the replica ACL. While that is
//! false, the read key is `settledRevisionId` and the grant epoch is
//! `settledEpoch`. This module does not publish a manifest, does not
//! rebuild a chain, and does not rotate ciphertext.

use crate::canonical::{self, epoch_finalization_id};
use crate::error::EncDiscError;
use crate::grant::GrantStated;

pub const SETTLE_WINDOW_MIN_MS: u64 = 3_600_000;
pub const SETTLE_WINDOW_MAX_MS: u64 = 259_200_000;
pub const SETTLE_WINDOW_DEFAULT_MS: u64 = 86_400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AclScope {
    Direct,
    SameGroup,
    NamedCircle,
}

impl AclScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::SameGroup => "same-group",
            Self::NamedCircle => "named-circle",
        }
    }

    pub fn parse(text: &str) -> Result<Self, EncDiscError> {
        match text {
            "direct" => Ok(Self::Direct),
            "same-group" => Ok(Self::SameGroup),
            "named-circle" => Ok(Self::NamedCircle),
            _ => Err(EncDiscError::StatusRejected),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclSnapshotEntry {
    pub accessor: String,
    pub grant_revision: u64,
    pub stated: GrantStated,
    pub from: u64,
    pub until: u64,
    pub scope: AclScope,
    pub set_id: String,
    pub ham_state: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclObjectSet {
    pub predicate: crate::see::GroupPredicate,
    pub set_id: String,
    pub stated: GrantStated,
    pub ham_state: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclSnapshotBody {
    pub object_set: Option<AclObjectSet>,
    pub entries: Vec<AclSnapshotEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochFinalization {
    pub object: String,
    pub previous_epoch: u64,
    pub epoch: u64,
    pub revision_id: String,
    pub candidate_revision_ids: Vec<String>,
    pub previous_finalization_id: String,
    pub finalization_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochReplicaView {
    pub object: String,
    pub epoch: u64,
    pub previous_finalization_id: String,
    pub seen: Vec<EpochFinalization>,
    pub winner_seen_at: u64,
    pub settle_window_ms: u64,
    pub settled_revision_id: String,
    pub settled_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightZookie {
    pub object: String,
    pub object_version: u64,
    pub snapshot_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStatusProof {
    pub object: String,
    pub epoch: u64,
    pub revision_id: String,
    pub accessor: String,
    pub grant_revision: u64,
    pub stated: GrantStated,
    pub signed_at: u64,
    pub max_age_ms: u64,
    pub signature: String,
    pub zookie: LightZookie,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochReadKey {
    pub revision_id: String,
    pub epoch: u64,
}

impl EpochFinalization {
    /// Build a finalization whose id is the hash of the canonical body.
    ///
    /// `revision_id` must be the lexicographically smallest candidate.
    /// The signature is stored. This constructor does not check it.
    /// The verifier that fills `EpochReplicaView.seen` already did.
    pub fn seal(
        object: &str,
        previous_epoch: u64,
        epoch: u64,
        revision_id: &str,
        mut candidates: Vec<String>,
        previous_finalization_id: &str,
        signature: &str,
    ) -> Result<Self, EncDiscError> {
        if object.is_empty() {
            return Err(EncDiscError::EmptyObject);
        }
        canonical::require_revision_id(revision_id)?;
        if candidates.is_empty() {
            return Err(EncDiscError::StatusRejected);
        }
        for candidate in &candidates {
            canonical::require_revision_id(candidate)?;
        }
        candidates.sort();
        candidates.dedup();
        if candidates.first().map(String::as_str) != Some(revision_id) {
            return Err(EncDiscError::StatusRejected);
        }
        let finalization_id = epoch_finalization_id(
            object,
            epoch,
            previous_epoch,
            revision_id,
            previous_finalization_id,
            &candidates,
        )?;
        Ok(Self {
            object: object.to_string(),
            previous_epoch,
            epoch,
            revision_id: revision_id.to_string(),
            candidate_revision_ids: candidates,
            previous_finalization_id: previous_finalization_id.to_string(),
            finalization_id,
            signature: signature.to_string(),
        })
    }
}

impl EpochStatusProof {
    pub fn body(&self) -> canonical::EpochStatusBody {
        canonical::EpochStatusBody {
            object: self.object.clone(),
            epoch: self.epoch,
            revision_id: self.revision_id.clone(),
            accessor: self.accessor.clone(),
            grant_revision: self.grant_revision,
            stated: self.stated.as_u64(),
            signed_at: self.signed_at,
            max_age_ms: self.max_age_ms,
            zookie_object: self.zookie.object.clone(),
            zookie_version: self.zookie.object_version,
            zookie_snapshot: self.zookie.snapshot_hash.clone(),
        }
    }
}

/// True only when a verified winner has been stable for the signed window
/// and the snapshot still matches the ACL this replica has merged.
pub fn epoch_step_current(
    view: &EpochReplicaView,
    snapshot: &AclSnapshotBody,
    current: &AclSnapshotBody,
    now: u64,
) -> bool {
    if !(SETTLE_WINDOW_MIN_MS..=SETTLE_WINDOW_MAX_MS).contains(&view.settle_window_ms) {
        return false;
    }
    if !snapshot_matches(snapshot, current, now) {
        return false;
    }
    if consistent_winner(view).is_none() {
        return false;
    }
    let elapsed = view.winner_seen_at.saturating_add(view.settle_window_ms);
    now >= elapsed
}

/// Revision a presentation must name, and the epoch that goes with it.
pub fn epoch_read_key(
    view: &EpochReplicaView,
    snapshot: &AclSnapshotBody,
    current: &AclSnapshotBody,
    now: u64,
) -> Option<EpochReadKey> {
    if epoch_step_current(view, snapshot, current, now) {
        let winner = consistent_winner(view)?;
        return Some(EpochReadKey {
            revision_id: winner.revision_id.clone(),
            epoch: view.epoch,
        });
    }
    if view.settled_revision_id.is_empty() {
        return None;
    }
    if canonical::require_revision_id(&view.settled_revision_id).is_err() {
        return None;
    }
    Some(EpochReadKey {
        revision_id: view.settled_revision_id.clone(),
        epoch: view.settled_epoch,
    })
}

pub fn status_is_fresh(
    proof: &EpochStatusProof,
    now: u64,
    skew_allowance_ms: u64,
    policy_max_age_ms: u64,
) -> bool {
    let bound = proof.max_age_ms.min(policy_max_age_ms);
    let latest = now.saturating_add(skew_allowance_ms);
    if proof.signed_at > latest {
        return false;
    }
    if now >= proof.signed_at {
        now - proof.signed_at <= bound
    } else {
        true
    }
}

fn consistent_winner(view: &EpochReplicaView) -> Option<&EpochFinalization> {
    view.seen
        .iter()
        .filter(|fin| finalization_counts(view, fin))
        .min_by(|left, right| left.finalization_id.cmp(&right.finalization_id))
}

fn finalization_counts(view: &EpochReplicaView, fin: &EpochFinalization) -> bool {
    if fin.object != view.object
        || fin.epoch != view.epoch
        || fin.previous_finalization_id != view.previous_finalization_id
    {
        return false;
    }
    if fin.candidate_revision_ids.first().map(String::as_str) != Some(fin.revision_id.as_str()) {
        return false;
    }
    let mut sorted = fin.candidate_revision_ids.clone();
    sorted.sort();
    if sorted != fin.candidate_revision_ids {
        return false;
    }
    match epoch_finalization_id(
        &fin.object,
        fin.epoch,
        fin.previous_epoch,
        &fin.revision_id,
        &fin.previous_finalization_id,
        &fin.candidate_revision_ids,
    ) {
        Ok(id) => id == fin.finalization_id,
        Err(_) => false,
    }
}

fn snapshot_matches(snapshot: &AclSnapshotBody, current: &AclSnapshotBody, now: u64) -> bool {
    let Ok(snapshot_entries) = normalize(&snapshot.entries) else {
        return false;
    };
    let Ok(current_entries) = normalize(&current.entries) else {
        return false;
    };
    match (&snapshot.object_set, &current.object_set) {
        (None, None) => {}
        (Some(left), Some(right)) => {
            if left.predicate != right.predicate
                || left.set_id != right.set_id
                || left.stated != right.stated
                || left.ham_state < right.ham_state
            {
                return false;
            }
        }
        _ => return false,
    }
    for entry in &snapshot_entries {
        if entry.stated == GrantStated::Live && (entry.until <= now || entry.from > now) {
            return false;
        }
        if let Some(held) = current_entries
            .iter()
            .find(|row| row.accessor == entry.accessor)
        {
            if held.grant_revision > entry.grant_revision {
                return false;
            }
            if held.stated == GrantStated::Cancelled && entry.stated == GrantStated::Live {
                return false;
            }
            if held.until < entry.until || held.from > entry.from {
                return false;
            }
            if held.stated == GrantStated::Cancelled
                && held.scope != AclScope::Direct
                && held.ham_state > entry.ham_state
                && held.scope == entry.scope
                && held.set_id == entry.set_id
            {
                return false;
            }
        }
    }
    for held in &current_entries {
        if held.stated != GrantStated::Cancelled {
            continue;
        }
        let Some(entry) = snapshot_entries
            .iter()
            .find(|row| row.accessor == held.accessor)
        else {
            return false;
        };
        if entry.stated == GrantStated::Live || entry.grant_revision < held.grant_revision {
            return false;
        }
        if held.scope != AclScope::Direct
            && (entry.scope != held.scope
                || entry.set_id != held.set_id
                || entry.ham_state < held.ham_state)
        {
            return false;
        }
    }
    true
}

fn normalize(entries: &[AclSnapshotEntry]) -> Result<Vec<AclSnapshotEntry>, ()> {
    let mut rows = entries.to_vec();
    rows.sort_by(|left, right| left.accessor.cmp(&right.accessor));
    if rows
        .windows(2)
        .any(|pair| pair[0].accessor == pair[1].accessor)
    {
        return Err(());
    }
    Ok(rows)
}
