//! Epoch admission, convergent finalization, and the read/write key.
//!
//! `checkPresentedGrant` asks whether the signed window has elapsed and
//! the winning snapshot still matches the replica ACL. While that is
//! false, the read key is `settledRevisionId` and the grant epoch is
//! `settledEpoch`. `settledKeyOpen` is the same ACL check for new
//! writes. A pending successor, an expiry, or a cancel closes that key.
//! The settle window does not delay privilege-down. A manifest, a
//! finalization, and a status proof are not grants.

use crate::canonical::{self, epoch_finalization_id};
use crate::error::EncDiscError;
use crate::grant::GrantStated;
use crate::sea;
use crate::see::GroupPredicate;

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

    /// A finalization is not a grant.
    pub fn grants_see(&self) -> bool {
        false
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

    /// A status proof is not a grant.
    pub fn grants_see(&self) -> bool {
        false
    }
}

pub fn settle_window_in_range(window: u64) -> bool {
    (SETTLE_WINDOW_MIN_MS..=SETTLE_WINDOW_MAX_MS).contains(&window)
}

/// The owner signs [`SETTLE_WINDOW_DEFAULT_MS`] by omitting the number.
pub fn settle_window_or_default(signed: Option<u64>) -> u64 {
    signed.unwrap_or(SETTLE_WINDOW_DEFAULT_MS)
}

/// True only when a verified winner has been stable for the signed window
/// and the snapshot still matches the ACL this replica has merged.
pub fn epoch_step_current(
    view: &EpochReplicaView,
    snapshot: &AclSnapshotBody,
    current: &AclSnapshotBody,
    now: u64,
) -> bool {
    if !settle_window_in_range(view.settle_window_ms) {
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

/// Whether new ciphertext may use the settled key.
///
/// False while a successor is pending, when the settled snapshot
/// disagrees with the merged ACL, and when a stated-1 window has
/// closed. Ciphertext already written under the settled key stays.
pub fn settled_key_open(
    view: &EpochReplicaView,
    settled: &AclSnapshotBody,
    current: &AclSnapshotBody,
    now: u64,
) -> bool {
    if !settle_window_in_range(view.settle_window_ms) {
        return false;
    }
    if view.settled_revision_id.is_empty()
        || canonical::require_revision_id(&view.settled_revision_id).is_err()
    {
        return false;
    }
    if !snapshot_matches(settled, current, now) {
        return false;
    }
    if let Some(winner) = consistent_winner(view) {
        if winner.revision_id != view.settled_revision_id {
            return false;
        }
        let elapsed = view.winner_seen_at.saturating_add(view.settle_window_ms);
        if now < elapsed {
            return false;
        }
    }
    true
}

/// Where a new write goes. A pending or cancelled key stays buffered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteDisposition {
    Buffer,
    Settled { revision_id: String, epoch: u64 },
    Winner { revision_id: String, epoch: u64 },
}

pub fn write_disposition(
    view: &EpochReplicaView,
    winning_snapshot: &AclSnapshotBody,
    settled_snapshot: &AclSnapshotBody,
    current: &AclSnapshotBody,
    now: u64,
) -> WriteDisposition {
    if epoch_step_current(view, winning_snapshot, current, now) {
        if let Some(winner) = epoch_winner(view) {
            return WriteDisposition::Winner {
                revision_id: winner.revision_id.clone(),
                epoch: view.epoch,
            };
        }
    }
    if settled_key_open(view, settled_snapshot, current, now) {
        return WriteDisposition::Settled {
            revision_id: view.settled_revision_id.clone(),
            epoch: view.settled_epoch,
        };
    }
    WriteDisposition::Buffer
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

/// Smallest `finalizationId` among the finalizations that count for this step.
pub fn epoch_winner(view: &EpochReplicaView) -> Option<&EpochFinalization> {
    consistent_winner(view)
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
    rows.sort_by(|left, right| accessor_cmp(&left.accessor, &right.accessor));
    if rows
        .windows(2)
        .any(|pair| pair[0].accessor == pair[1].accessor)
    {
        return Err(());
    }
    Ok(rows)
}

pub(crate) fn snapshot_can_settle(snapshot: &AclSnapshotBody, now: u64) -> bool {
    snapshot_matches(snapshot, snapshot, now)
}

/// A higher `grantRevision` is required when displaced ciphertext is rewritten.
pub fn rebuild_grant_revision(previous: u64, next: u64) -> Result<u64, EncDiscError> {
    if next > previous {
        Ok(next)
    } else {
        Err(EncDiscError::EpochRejected)
    }
}

/// SHA-256 of the length-prefixed ACL snapshot. Entries must already be
/// sorted by accessor. This hash does not mint.
pub fn acl_snapshot_id(body: &AclSnapshotBody) -> Result<String, EncDiscError> {
    Ok(canonical::sha256_hex(&acl_snapshot_bytes(body)?))
}

pub fn acl_snapshot_bytes(body: &AclSnapshotBody) -> Result<Vec<u8>, EncDiscError> {
    validate_snapshot_shape(body)?;
    let mut fields = Vec::new();
    fields.push(canonical::DOMAIN_ACL_SNAPSHOT.to_string());
    match &body.object_set {
        Some(set) => {
            fields.push("1".to_string());
            fields.push(set.predicate.as_str().to_string());
            fields.push(set.set_id.clone());
            fields.push(canonical::canonical_decimal(set.stated.as_u64())?);
            fields.push(canonical::canonical_decimal(set.ham_state)?);
        }
        None => {
            fields.push("0".to_string());
            fields.extend(["", "", "", ""].into_iter().map(str::to_string));
        }
    }
    for entry in &body.entries {
        fields.push(entry.accessor.clone());
        fields.push(canonical::canonical_decimal(entry.grant_revision)?);
        fields.push(canonical::canonical_decimal(entry.stated.as_u64())?);
        fields.push(canonical::canonical_decimal(entry.from)?);
        fields.push(canonical::canonical_decimal(entry.until)?);
        fields.push(entry.scope.as_str().to_string());
        fields.push(entry.set_id.clone());
        fields.push(canonical::canonical_decimal(entry.ham_state)?);
    }
    let borrowed: Vec<&str> = fields.iter().map(String::as_str).collect();
    canonical::length_prefixed(&borrowed)
}

/// Bytewise UTF-8 order. JavaScript `<` is UTF-16 and disagrees past U+FFFF.
fn accessor_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

fn validate_snapshot_shape(body: &AclSnapshotBody) -> Result<(), EncDiscError> {
    if let Some(set) = &body.object_set {
        if set.set_id.is_empty() {
            return Err(EncDiscError::EpochRejected);
        }
    }
    let mut previous = None;
    for entry in &body.entries {
        if entry.accessor.is_empty() {
            return Err(EncDiscError::EpochRejected);
        }
        if let Some(prior) = previous {
            if accessor_cmp(&entry.accessor, prior) != std::cmp::Ordering::Greater {
                return Err(EncDiscError::EpochRejected);
            }
        }
        previous = Some(entry.accessor.as_str());
        match entry.scope {
            AclScope::Direct => {
                if !entry.set_id.is_empty() || entry.ham_state != 0 {
                    return Err(EncDiscError::EpochRejected);
                }
            }
            AclScope::SameGroup | AclScope::NamedCircle => {
                let Some(set) = &body.object_set else {
                    return Err(EncDiscError::EpochRejected);
                };
                if entry.set_id.is_empty()
                    || entry.scope.as_str() != set.predicate.as_str()
                    || entry.set_id != set.set_id
                {
                    return Err(EncDiscError::EpochRejected);
                }
            }
        }
    }
    Ok(())
}

/// Owner-signed epoch revision. `revisionId` is the hash of the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochManifest {
    pub object: String,
    pub previous_epoch: u64,
    pub epoch: u64,
    pub device_id: String,
    pub revision_id: String,
    pub key_commitment: String,
    pub settle_window_ms: u64,
    pub acl_snapshot: String,
    pub signature: String,
}

impl EpochManifest {
    pub fn body(&self) -> canonical::EpochManifestBody {
        canonical::EpochManifestBody {
            object: self.object.clone(),
            epoch: self.epoch,
            previous_epoch: self.previous_epoch,
            device_id: self.device_id.clone(),
            key_commitment: self.key_commitment.clone(),
            settle_window_ms: self.settle_window_ms,
            acl_snapshot: self.acl_snapshot.clone(),
        }
    }

    /// A manifest is not a grant.
    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn verify(&self, snapshot: &AclSnapshotBody, owner_pub: &str) -> Result<(), EncDiscError> {
        if self.object.is_empty() {
            return Err(EncDiscError::EmptyObject);
        }
        if self.device_id.is_empty() {
            return Err(EncDiscError::EmptyDevice);
        }
        if self.key_commitment.is_empty() || !settle_window_in_range(self.settle_window_ms) {
            return Err(EncDiscError::EpochRejected);
        }
        canonical::require_revision_id(&self.revision_id)?;
        if canonical::epoch_revision_id(&self.body())? != self.revision_id {
            return Err(EncDiscError::EpochRejected);
        }
        if acl_snapshot_id(snapshot)? != self.acl_snapshot {
            return Err(EncDiscError::EpochRejected);
        }
        let message = canonical::epoch_manifest_sig_bytes(&self.revision_id)?;
        sea::verify_sea(owner_pub, &message, &self.signature)?;
        Ok(())
    }
}

/// Owner-signed settle window for one group or circle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEpochConfig {
    pub owner: String,
    pub set_id: String,
    pub predicate: GroupPredicate,
    pub settle_window_ms: u64,
    pub config_revision: u64,
    pub signature: String,
}

impl GroupEpochConfig {
    /// A group config is not a grant.
    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn signed_bytes(&self) -> Result<Vec<u8>, EncDiscError> {
        canonical::group_epoch_config_bytes(
            &self.owner,
            &self.set_id,
            self.predicate.as_str(),
            self.settle_window_ms,
            self.config_revision,
        )
    }

    pub fn digest(&self) -> Result<String, EncDiscError> {
        Ok(canonical::sha256_hex(&self.signed_bytes()?))
    }

    pub fn verify(&self, owner_pub: &str, owner_of_set: Option<&str>) -> Result<(), EncDiscError> {
        let Some(owner) = owner_of_set else {
            return Err(EncDiscError::EpochRejected);
        };
        if self.owner.is_empty() || self.owner != owner || self.set_id.is_empty() {
            return Err(EncDiscError::EpochRejected);
        }
        if !settle_window_in_range(self.settle_window_ms) {
            return Err(EncDiscError::EpochRejected);
        }
        let message = self.signed_bytes()?;
        sea::verify_sea(owner_pub, &message, &self.signature)?;
        Ok(())
    }
}

/// Greatest `configRevision` for this predicate and set wins.
///
/// At a tie, the smaller signed digest wins. A higher revision for
/// another predicate or set is ignored. A missing set owner, a different
/// owner, an out-of-range window, or a signature under some other key
/// is ignored.
pub fn select_group_epoch_config<'a>(
    configs: &'a [GroupEpochConfig],
    predicate: GroupPredicate,
    set_id: &str,
    owner_pub: &str,
    owner_of_set: Option<&str>,
) -> Option<&'a GroupEpochConfig> {
    if set_id.is_empty() {
        return None;
    }
    let mut best: Option<(&GroupEpochConfig, String)> = None;
    for config in configs {
        if config.predicate != predicate || config.set_id != set_id {
            continue;
        }
        if config.verify(owner_pub, owner_of_set).is_err() {
            continue;
        }
        let Ok(digest) = config.digest() else {
            continue;
        };
        let replace = match &best {
            None => true,
            Some((held, held_digest)) => {
                config.config_revision > held.config_revision
                    || (config.config_revision == held.config_revision
                        && digest.as_str() < held_digest.as_str())
            }
        };
        if replace {
            best = Some((config, digest));
        }
    }
    best.map(|(config, _)| config)
}

#[derive(Clone, Debug)]
struct StoredManifest {
    manifest: EpochManifest,
    snapshot: AclSnapshotBody,
}

#[derive(Clone, Debug)]
struct StoredFinalization {
    finalization: EpochFinalization,
    seen_at: u64,
}

/// One replica's append-only epoch log for one object.
///
/// The winner is the smallest `finalizationId` on the current chain.
/// Insert order does not change that winner. A displaced parent takes
/// its descendants off the chain. Those finalizations stay in the log.
#[derive(Clone, Debug)]
pub struct EpochChain {
    object: String,
    manifests: Vec<StoredManifest>,
    finalizations: Vec<StoredFinalization>,
}

impl EpochChain {
    pub fn new(object: &str) -> Result<Self, EncDiscError> {
        if object.is_empty() {
            return Err(EncDiscError::EmptyObject);
        }
        Ok(Self {
            object: object.to_string(),
            manifests: Vec::new(),
            finalizations: Vec::new(),
        })
    }

    pub fn insert_manifest(
        &mut self,
        manifest: EpochManifest,
        snapshot: AclSnapshotBody,
        owner_pub: &str,
    ) -> Result<(), EncDiscError> {
        if manifest.object != self.object {
            return Err(EncDiscError::EpochRejected);
        }
        manifest.verify(&snapshot, owner_pub)?;
        if let Some(existing) = self
            .manifests
            .iter()
            .find(|row| row.manifest.revision_id == manifest.revision_id)
        {
            if existing.manifest.acl_snapshot != manifest.acl_snapshot
                || existing.snapshot != snapshot
            {
                return Err(EncDiscError::EpochRejected);
            }
            return Ok(());
        }
        self.manifests.push(StoredManifest { manifest, snapshot });
        Ok(())
    }

    pub fn insert_finalization(
        &mut self,
        fin: EpochFinalization,
        seen_at: u64,
        owner_pub: &str,
    ) -> Result<(), EncDiscError> {
        if fin.object != self.object {
            return Err(EncDiscError::EpochRejected);
        }
        let _ = canonical::canonical_decimal(seen_at)?;
        self.require_finalization(&fin, owner_pub)?;
        if self
            .finalizations
            .iter()
            .any(|row| row.finalization.finalization_id == fin.finalization_id)
        {
            return Ok(());
        }
        self.finalizations.push(StoredFinalization {
            finalization: fin,
            seen_at,
        });
        Ok(())
    }

    pub fn on_chain_winners(
        &self,
        current: &AclSnapshotBody,
        now: u64,
        group_window: Option<u64>,
    ) -> Vec<&EpochFinalization> {
        let effective = self.effective(current, now, group_window);
        let mut parent = String::new();
        let mut parent_epoch: Option<u64> = None;
        let mut winners = Vec::new();
        loop {
            let mut step: Vec<&StoredFinalization> = effective
                .iter()
                .copied()
                .filter(|row| row.finalization.previous_finalization_id == parent)
                .filter(|row| child_follows(parent_epoch, &row.finalization))
                .collect();
            if step.is_empty() {
                break;
            }
            let next_epoch = step
                .iter()
                .map(|row| row.finalization.epoch)
                .min()
                .unwrap_or(0);
            step.retain(|row| row.finalization.epoch == next_epoch);
            let Some(winner) = step.iter().copied().min_by(|left, right| {
                left.finalization
                    .finalization_id
                    .cmp(&right.finalization.finalization_id)
            }) else {
                break;
            };
            winners.push(&winner.finalization);
            parent = winner.finalization.finalization_id.clone();
            parent_epoch = Some(winner.finalization.epoch);
        }
        winners
    }

    pub fn revision_on_chain(
        &self,
        revision_id: &str,
        current: &AclSnapshotBody,
        now: u64,
        group_window: Option<u64>,
    ) -> bool {
        self.on_chain_winners(current, now, group_window)
            .iter()
            .any(|fin| fin.revision_id == revision_id)
    }

    /// Descendants whose parent finalization is no longer the winner.
    ///
    /// Parent epochs come before child epochs.
    pub fn displaced_finalizations(
        &self,
        current: &AclSnapshotBody,
        now: u64,
        group_window: Option<u64>,
    ) -> Vec<&EpochFinalization> {
        let winner_ids: Vec<String> = self
            .on_chain_winners(current, now, group_window)
            .iter()
            .map(|fin| fin.finalization_id.clone())
            .collect();
        let mut off: Vec<&EpochFinalization> = self
            .finalizations
            .iter()
            .filter(|row| {
                let previous = row.finalization.previous_finalization_id.as_str();
                !previous.is_empty()
                    && self
                        .finalizations
                        .iter()
                        .any(|known| known.finalization.finalization_id == previous)
                    && !winner_ids.iter().any(|id| id == previous)
            })
            .map(|row| &row.finalization)
            .collect();
        off.sort_by(|left, right| {
            left.epoch
                .cmp(&right.epoch)
                .then(left.finalization_id.cmp(&right.finalization_id))
        });
        off
    }

    pub fn replica_view(
        &self,
        epoch: u64,
        current: &AclSnapshotBody,
        now: u64,
        group_window: Option<u64>,
        settled_revision_id: &str,
    ) -> EpochReplicaView {
        let winners: Vec<(u64, String, String, String)> = self
            .on_chain_winners(current, now, group_window)
            .iter()
            .map(|fin| {
                (
                    fin.epoch,
                    fin.finalization_id.clone(),
                    fin.revision_id.clone(),
                    fin.previous_finalization_id.clone(),
                )
            })
            .collect();
        let step = winners.iter().find(|row| row.0 == epoch);
        let previous = step.map(|row| row.3.clone()).unwrap_or_default();
        let winner_id = step.map(|row| row.1.clone());
        let winner_revision = step.map(|row| row.2.clone());
        let seen = if step.is_some() {
            self.effective(current, now, group_window)
                .into_iter()
                .filter(|row| {
                    row.finalization.epoch == epoch
                        && row.finalization.previous_finalization_id == previous
                })
                .map(|row| row.finalization.clone())
                .collect()
        } else {
            Vec::new()
        };
        let settle_window_ms = winner_revision
            .as_ref()
            .and_then(|revision| {
                self.manifests
                    .iter()
                    .find(|row| row.manifest.revision_id == *revision)
                    .map(|row| row.manifest.settle_window_ms)
            })
            .unwrap_or(SETTLE_WINDOW_DEFAULT_MS);
        let winner_seen_at = winner_id
            .as_ref()
            .and_then(|id| {
                self.finalizations
                    .iter()
                    .find(|row| row.finalization.finalization_id == *id)
                    .map(|row| row.seen_at)
            })
            .unwrap_or(0);
        let settled = if settled_revision_id.is_empty() {
            None
        } else {
            winners
                .iter()
                .find(|row| row.2.as_str() == settled_revision_id)
        };
        EpochReplicaView {
            object: self.object.clone(),
            epoch,
            previous_finalization_id: previous,
            seen,
            winner_seen_at,
            settle_window_ms,
            settled_revision_id: settled.map(|row| row.2.clone()).unwrap_or_default(),
            settled_epoch: settled.map(|row| row.0).unwrap_or(0),
        }
    }

    fn effective(
        &self,
        current: &AclSnapshotBody,
        now: u64,
        group_window: Option<u64>,
    ) -> Vec<&StoredFinalization> {
        self.finalizations
            .iter()
            .filter(|row| {
                self.manifests.iter().any(|stored| {
                    stored.manifest.revision_id == row.finalization.revision_id
                        && self.manifest_admissible(stored, current, now, group_window)
                })
            })
            .collect()
    }

    fn manifest_admissible(
        &self,
        stored: &StoredManifest,
        current: &AclSnapshotBody,
        now: u64,
        group_window: Option<u64>,
    ) -> bool {
        let grouped = stored.snapshot.object_set.is_some();
        if grouped {
            let Some(window) = group_window else {
                return false;
            };
            if stored.manifest.settle_window_ms != window {
                return false;
            }
        } else if group_window.is_some() {
            return false;
        }
        snapshot_matches(&stored.snapshot, current, now)
    }

    fn require_finalization(
        &self,
        fin: &EpochFinalization,
        owner_pub: &str,
    ) -> Result<(), EncDiscError> {
        if fin.candidate_revision_ids.is_empty() {
            return Err(EncDiscError::EpochRejected);
        }
        let mut sorted = fin.candidate_revision_ids.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != fin.candidate_revision_ids
            || fin.candidate_revision_ids.first().map(String::as_str)
                != Some(fin.revision_id.as_str())
        {
            return Err(EncDiscError::EpochRejected);
        }
        if !fin.previous_finalization_id.is_empty() {
            canonical::require_revision_id(&fin.previous_finalization_id)?;
        }
        let id = epoch_finalization_id(
            &fin.object,
            fin.epoch,
            fin.previous_epoch,
            &fin.revision_id,
            &fin.previous_finalization_id,
            &fin.candidate_revision_ids,
        )?;
        if id != fin.finalization_id {
            return Err(EncDiscError::EpochRejected);
        }
        let message = canonical::epoch_finalization_sig_bytes(&fin.finalization_id)?;
        sea::verify_sea(owner_pub, &message, &fin.signature)?;
        if !fin.previous_finalization_id.is_empty() {
            if let Some(parent) = self
                .finalizations
                .iter()
                .find(|row| row.finalization.finalization_id == fin.previous_finalization_id)
            {
                if !child_follows(Some(parent.finalization.epoch), fin) {
                    return Err(EncDiscError::EpochRejected);
                }
            }
        }
        for revision in &fin.candidate_revision_ids {
            let Some(stored) = self
                .manifests
                .iter()
                .find(|row| row.manifest.revision_id == *revision)
            else {
                return Err(EncDiscError::EpochRejected);
            };
            if stored.manifest.object != fin.object
                || stored.manifest.epoch != fin.epoch
                || stored.manifest.previous_epoch != fin.previous_epoch
            {
                return Err(EncDiscError::EpochRejected);
            }
        }
        Ok(())
    }
}

/// A child names the parent epoch and is the next epoch number.
fn child_follows(parent_epoch: Option<u64>, fin: &EpochFinalization) -> bool {
    let Some(epoch) = parent_epoch else {
        return true;
    };
    let Some(next) = epoch.checked_add(1) else {
        return false;
    };
    fin.previous_epoch == epoch && fin.epoch == next
}
