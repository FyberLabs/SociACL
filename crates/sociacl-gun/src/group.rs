//! Direct `same-group` and `named-circle` rows on the plaintext mesh.
//!
//! Hopcap is 1. Both the object-to-set edge and the membership edge
//! must be stated 1. One-sided membership is stored and is not a grant.
//! Nested sets are not walked. A hop, a hint, or a wrap never mints.
//! Membership has no from/until window on this surface.
//!
//! A lower `hamState` does not replace a removal this peer has merged.
//! Member `hamState` does not stand in for the object-to-set edge.
//! Each party's assent has its own state. A higher state wins, and at
//! the same state a retraction wins. A membership row stays bound to
//! the set owner in its soul. An object-set row stays bound to the
//! object owner in its soul. At the same object-set state, stated 0 wins.
//! Clearing an object-set edge this replica has not seen writes a
//! stated-0 tombstone. A set id is `<principal>/<name>`. A cancel
//! epoch wins over party states that have not observed it.
//! Wrapped keys are not read here.

use std::collections::HashMap;

use sociacl_core::Timestamp;

use crate::mesh::{closed_reason, MeshCheckResult, MeshSeeGraph};
use crate::soul::{acl_key, acl_principal_key, S3RCH_ACL, S3RCH_ROOT};
use crate::{GunError, HandoffHint, HopFactor};

/// `same-group` or `named-circle`. The accessor does not pick a richer one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GroupPredicate {
    SameGroup,
    NamedCircle,
}

impl GroupPredicate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameGroup => "same-group",
            Self::NamedCircle => "named-circle",
        }
    }
}

/// Direct membership. Hopcap 1. `stated` 1 is live, 0 is not.
/// Cancel bumps `ham_state`. One-sided membership stays stated 0.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshMembership {
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub accessor: String,
    pub stated: u8,
    pub ham_state: u64,
}

impl MeshMembership {
    pub fn is_live(&self) -> bool {
        self.stated == 1
    }
}

/// The group or circle an object names. One predicate. Its `ham_state`
/// is not a member `ham_state`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectSetName {
    pub object: String,
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub stated: u8,
    pub ham_state: u64,
}

impl ObjectSetName {
    pub fn is_live(&self) -> bool {
        self.stated == 1
    }
}

/// Group or circle argument on a presentation. Not a grant by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentedGroup {
    pub predicate: GroupPredicate,
    pub set_id: String,
}

/// Opened payload window. `check_group_see` does not read this.
/// `from` is inclusive and `until` is exclusive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedGroupPayload {
    pub stated: u8,
    pub from: u64,
    pub until: u64,
}

impl DecodedGroupPayload {
    pub fn live_at(&self, now: u64) -> bool {
        self.stated == 1 && now >= self.from && now < self.until
    }
}

/// Member row inside an ACL snapshot. Direct grants are not this row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSnapshotMember {
    pub accessor: String,
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub stated: u8,
    pub ham_state: u64,
}

/// Object-to-set edge inside an ACL snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSnapshotObjectSet {
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub stated: u8,
    pub ham_state: u64,
}

/// Result of the group tail of a presentation.
/// Binding, signatures, and key unwrap stay outside this call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPresentation {
    pub allowed: bool,
    pub reason: String,
    pub hint: Option<HandoffHint>,
    pub hop: Option<HopFactor>,
    /// A stated-0 payload may be stored on the verifier record
    /// even when `allowed` is false.
    pub store_cancel: bool,
}

impl GroupPresentation {
    pub fn hint_is_grant(&self) -> bool {
        false
    }

    pub fn hop_is_grant(&self) -> bool {
        false
    }

    pub fn hop_factored(&self) -> bool {
        self.allowed && self.hop.is_some()
    }
}

/// One party's assent. A higher cancel epoch wins, including a
/// cancel written before this replica had seen the row. Inside one
/// epoch, higher `ham_state` wins. At the same state, a retraction
/// (`stated` false) wins over an assent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PartyStatement {
    stated: bool,
    ham_state: u64,
    epoch: u64,
}

impl PartyStatement {
    fn merged(self, incoming: Self) -> Self {
        if incoming.epoch > self.epoch {
            incoming
        } else if incoming.epoch < self.epoch {
            self
        } else if incoming.ham_state > self.ham_state {
            incoming
        } else if incoming.ham_state < self.ham_state {
            self
        } else if !incoming.stated && self.stated {
            incoming
        } else {
            self
        }
    }

    fn retracted(self) -> bool {
        !self.stated && self.ham_state > 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MembershipRecord {
    pub membership: MeshMembership,
    member: PartyStatement,
    set_party: PartyStatement,
    /// True after a removal. A one-sided first statement stays false.
    removed: bool,
    soul: String,
    /// Set owner encoded in `soul`. A merge drops the row when this
    /// does not match the owner this graph kept.
    set_owner: String,
}

impl MembershipRecord {
    pub(crate) fn merged(self, incoming: Self) -> Self {
        let mut out = self;
        out.member = out.member.merged(incoming.member);
        out.set_party = out.set_party.merged(incoming.set_party);
        out.membership.ham_state = out.membership.ham_state.max(incoming.membership.ham_state);
        out.sync_stated();
        out
    }

    fn sync_stated(&mut self) {
        if self.member.stated && self.set_party.stated {
            self.membership.stated = 1;
            self.removed = false;
        } else {
            self.membership.stated = 0;
            if self.member.retracted() || self.set_party.retracted() {
                self.removed = true;
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObjectSetRecord {
    name: ObjectSetName,
    soul: String,
    /// Object owner encoded in `soul`. A merge drops the row when this
    /// does not match the owner this graph kept.
    object_owner: String,
    /// A clear bumps this. It wins over a live edge that has not
    /// observed the clear, whatever that edge's `ham_state` is.
    epoch: u64,
}

impl ObjectSetRecord {
    fn merged(self, incoming: Self) -> Self {
        if incoming.epoch > self.epoch {
            return incoming;
        }
        if incoming.epoch < self.epoch {
            return self;
        }
        if incoming.name.ham_state > self.name.ham_state {
            return incoming;
        }
        if incoming.name.ham_state < self.name.ham_state {
            return self;
        }
        let incoming_down = incoming.name.stated == 0;
        let local_down = self.name.stated == 0;
        if incoming_down && !local_down {
            return incoming;
        }
        if local_down && !incoming_down {
            return self;
        }
        let incoming_key = (
            incoming.name.predicate.as_str(),
            incoming.name.set_id.as_str(),
        );
        let local_key = (self.name.predicate.as_str(), self.name.set_id.as_str());
        if incoming_key < local_key {
            incoming
        } else {
            self
        }
    }
}

type SetKey = (GroupPredicate, String);
type MembershipKey = (GroupPredicate, String, String);

#[derive(Clone, Debug, Default)]
pub(crate) struct GroupRows {
    memberships: HashMap<MembershipKey, MembershipRecord>,
    object_sets: HashMap<String, ObjectSetRecord>,
    set_owners: HashMap<SetKey, String>,
}

impl GroupRows {
    pub(crate) fn merge_from(&mut self, other: &Self, object_owners: &HashMap<String, String>) {
        for (key, owner) in &other.set_owners {
            if !set_id_binds_owner(&key.1, owner) {
                continue;
            }
            self.set_owners
                .entry(key.clone())
                .or_insert_with(|| owner.clone());
        }
        for record in other.memberships.values() {
            self.merge_membership(record.clone());
        }
        for record in other.object_sets.values() {
            self.merge_object_set(record.clone(), object_owners);
        }
    }

    fn merge_membership(&mut self, incoming: MembershipRecord) {
        if !set_id_binds_owner(&incoming.membership.set_id, &incoming.set_owner) {
            return;
        }
        let Some(owner) = self.set_owners.get(&(
            incoming.membership.predicate,
            incoming.membership.set_id.clone(),
        )) else {
            return;
        };
        if acl_principal_key(owner) != acl_principal_key(&incoming.set_owner) {
            return;
        }
        let key = membership_key(&incoming.membership);
        let merged = match self.memberships.remove(&key) {
            Some(local) => local.merged(incoming),
            None => incoming,
        };
        self.memberships.insert(key, merged);
    }

    fn merge_object_set(
        &mut self,
        incoming: ObjectSetRecord,
        object_owners: &HashMap<String, String>,
    ) {
        let Some(owner) = retained_object_owner(object_owners, &incoming.name.object) else {
            return;
        };
        if acl_principal_key(owner) != acl_principal_key(&incoming.object_owner) {
            return;
        }
        if incoming.name.stated == 1 && !set_id_has_bound_owner(&incoming.name.set_id) {
            return;
        }
        let key = object_set_key(&incoming.name.object);
        let merged = match self.object_sets.remove(&key) {
            Some(local) => local.merged(incoming),
            None => incoming,
        };
        self.object_sets.insert(key, merged);
    }
}

/// Membership soul under dest ACL. Not a five-segment grant soul
/// and not a Check object.
pub fn membership_soul(
    set_owner: &str,
    predicate: GroupPredicate,
    set_id: &str,
    accessor: &str,
) -> String {
    format!(
        "{S3RCH_ROOT}/{S3RCH_ACL}/{}/membership/{}/{}/{}",
        acl_principal_key(set_owner),
        predicate.as_str(),
        acl_key(set_id),
        acl_principal_key(accessor),
    )
}

/// Object-to-set soul under dest ACL. Six segments, so it is not a
/// five-segment grant soul and not a Check object. The path stays
/// on the object; the set id lives in the row, not in the soul.
pub fn object_set_soul(object_owner: &str, object: &str) -> String {
    format!(
        "{S3RCH_ROOT}/{S3RCH_ACL}/{}/object-set/edge/{}",
        acl_principal_key(object_owner),
        acl_key(object),
    )
}

impl MeshSeeGraph {
    /// Record the account that owns a set. A second account does not replace it.
    pub fn record_set_owner(
        &mut self,
        owner: impl AsRef<str>,
        predicate: GroupPredicate,
        set_id: impl AsRef<str>,
    ) -> Result<(), GunError> {
        let owner = owner.as_ref().trim();
        let set_id = set_id.as_ref().trim();
        if owner.is_empty() || set_id.is_empty() {
            return Err(GunError::EmptyGroupName);
        }
        let key = (predicate, set_id.to_string());
        if let Some(existing) = self.groups.set_owners.get(&key) {
            if acl_principal_key(existing) != acl_principal_key(owner) {
                return Err(GunError::SetOwnerConflict);
            }
            return Ok(());
        }
        if !set_id_binds_owner(set_id, owner) {
            return Err(GunError::UnboundSetOwner);
        }
        self.groups.set_owners.insert(key, owner.to_string());
        Ok(())
    }

    pub fn owner_of_set(&self, predicate: GroupPredicate, set_id: &str) -> Option<&str> {
        let set_id = set_id.trim();
        self.groups
            .set_owners
            .get(&(predicate, set_id.to_string()))
            .map(String::as_str)
    }

    /// One side of a direct membership. Live only when both the member
    /// and the set owner have stated it.
    pub fn state_membership(
        &mut self,
        speaker: impl AsRef<str>,
        predicate: GroupPredicate,
        set_id: impl AsRef<str>,
        accessor: impl AsRef<str>,
    ) -> Result<(), GunError> {
        let set_id = set_id.as_ref().trim();
        let accessor = accessor.as_ref().trim();
        if set_id.is_empty() || accessor.is_empty() {
            return Err(GunError::EmptyGroupName);
        }
        let (speaks_member, speaks_set) =
            self.membership_speaker(speaker.as_ref(), predicate, set_id, accessor)?;
        let key = (predicate, set_id.to_string(), acl_principal_key(accessor));
        let owner = self
            .owner_of_set(predicate, set_id)
            .ok_or(GunError::SetUnknown)?
            .to_string();
        let soul = membership_soul(&owner, predicate, set_id, accessor);
        let mut record = self
            .groups
            .memberships
            .remove(&key)
            .unwrap_or_else(|| MembershipRecord {
                membership: MeshMembership {
                    predicate,
                    set_id: set_id.to_string(),
                    accessor: accessor.to_string(),
                    stated: 0,
                    ham_state: 0,
                },
                member: PartyStatement {
                    stated: false,
                    ham_state: 0,
                    epoch: 0,
                },
                set_party: PartyStatement {
                    stated: false,
                    ham_state: 0,
                    epoch: 0,
                },
                removed: false,
                soul: soul.clone(),
                set_owner: owner.clone(),
            });
        record.soul = soul;
        record.set_owner = owner;
        record.membership.ham_state = record.membership.ham_state.saturating_add(1);
        let epoch = record.member.epoch.max(record.set_party.epoch);
        if speaks_member {
            record.member.stated = true;
            record.member.ham_state = record.member.ham_state.saturating_add(1);
            record.member.epoch = epoch;
        }
        if speaks_set {
            record.set_party.stated = true;
            record.set_party.ham_state = record.set_party.ham_state.saturating_add(1);
            record.set_party.epoch = epoch;
        }
        record.sync_stated();
        self.groups.memberships.insert(key, record);
        Ok(())
    }

    /// Privilege-down. Stated becomes 0 and `ham_state` bumps.
    /// The next Check after merge denies.
    pub fn cancel_membership(
        &mut self,
        speaker: impl AsRef<str>,
        predicate: GroupPredicate,
        set_id: impl AsRef<str>,
        accessor: impl AsRef<str>,
    ) -> Result<(), GunError> {
        let set_id = set_id.as_ref().trim();
        let accessor = accessor.as_ref().trim();
        if set_id.is_empty() || accessor.is_empty() {
            return Err(GunError::EmptyGroupName);
        }
        let _ = self.membership_speaker(speaker.as_ref(), predicate, set_id, accessor)?;
        let key = (predicate, set_id.to_string(), acl_principal_key(accessor));
        let owner = self
            .owner_of_set(predicate, set_id)
            .ok_or(GunError::SetUnknown)?
            .to_string();
        let soul = membership_soul(&owner, predicate, set_id, accessor);
        let mut record = self
            .groups
            .memberships
            .remove(&key)
            .unwrap_or_else(|| MembershipRecord {
                membership: MeshMembership {
                    predicate,
                    set_id: set_id.to_string(),
                    accessor: accessor.to_string(),
                    stated: 0,
                    ham_state: 0,
                },
                member: PartyStatement {
                    stated: false,
                    ham_state: 0,
                    epoch: 0,
                },
                set_party: PartyStatement {
                    stated: false,
                    ham_state: 0,
                    epoch: 0,
                },
                removed: false,
                soul: soul.clone(),
                set_owner: owner.clone(),
            });
        record.soul = soul;
        record.set_owner = owner;
        // A cancel epoch wins over party states that have not observed
        // it, including a row this replica had not seen yet.
        let epoch = record
            .member
            .epoch
            .max(record.set_party.epoch)
            .saturating_add(1);
        record.member.stated = false;
        record.member.ham_state = record.member.ham_state.saturating_add(1);
        record.member.epoch = epoch;
        record.set_party.stated = false;
        record.set_party.ham_state = record.set_party.ham_state.saturating_add(1);
        record.set_party.epoch = epoch;
        record.removed = true;
        record.membership.stated = 0;
        record.membership.ham_state = record.membership.ham_state.saturating_add(1);
        self.groups.memberships.insert(key, record);
        Ok(())
    }

    pub fn membership(
        &self,
        predicate: GroupPredicate,
        set_id: &str,
        accessor: &str,
    ) -> Option<&MeshMembership> {
        self.membership_record(predicate, set_id, accessor)
            .map(|r| &r.membership)
    }

    pub fn membership_row_soul(
        &self,
        predicate: GroupPredicate,
        set_id: &str,
        accessor: &str,
    ) -> Option<&str> {
        self.membership_record(predicate, set_id, accessor)
            .map(|r| r.soul.as_str())
    }

    /// Object owner names the one set this object uses.
    pub fn name_object_set(
        &mut self,
        owner: impl AsRef<str>,
        object: impl AsRef<str>,
        predicate: GroupPredicate,
        set_id: impl AsRef<str>,
    ) -> Result<(), GunError> {
        let set_id = set_id.as_ref().trim();
        if set_id.is_empty() {
            return Err(GunError::EmptyGroupName);
        }
        if !set_id_has_bound_owner(set_id) {
            return Err(GunError::UnboundSetOwner);
        }
        let (object_id, object_owner) =
            self.write_object_set_auth(owner.as_ref(), object.as_ref())?;
        if self
            .owner_of_set(predicate, set_id)
            .is_some_and(|set_owner| !set_id_binds_owner(set_id, set_owner))
        {
            return Err(GunError::UnboundSetOwner);
        }
        self.write_object_set(&object_id, &object_owner, predicate, set_id, 1);
        Ok(())
    }

    /// Object owner clears the set edge. `ham_state` bumps. Stated becomes 0.
    pub fn clear_object_set(
        &mut self,
        owner: impl AsRef<str>,
        object: impl AsRef<str>,
    ) -> Result<(), GunError> {
        let (object_id, object_owner) =
            self.write_object_set_auth(owner.as_ref(), object.as_ref())?;
        let existing = self.object_set_record(&object_id);
        let (predicate, set_id) = match existing {
            Some(record) => (record.name.predicate, record.name.set_id.clone()),
            // The live edge has not arrived. The clear still bumps the
            // cancel epoch, so a remote live revision that has not
            // observed it does not win on ham alone.
            None => (GroupPredicate::SameGroup, String::new()),
        };
        self.write_object_set(&object_id, &object_owner, predicate, &set_id, 0);
        Ok(())
    }

    pub fn object_set(&self, object: &str) -> Option<&ObjectSetName> {
        self.object_set_record(object).map(|r| &r.name)
    }

    pub fn object_set_row_soul(&self, object: &str) -> Option<&str> {
        self.object_set_record(object).map(|r| r.soul.as_str())
    }

    /// `CHECK(see)` when the object names `same-group` or `named-circle`.
    ///
    /// The owner sees their object. Otherwise both edges must be stated 1
    /// and the membership must be jointly stated. Hop missing does not
    /// fail. Hop alone never allows. `now` is the Check instant;
    /// membership has no window here.
    pub fn check_group_see(
        &self,
        predicate: GroupPredicate,
        object: impl AsRef<str>,
        accessor: impl AsRef<str>,
        now: Timestamp,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> MeshCheckResult {
        let object = object.as_ref().trim();
        let accessor = accessor.as_ref().trim();
        let hint = hint.cloned();
        let hop = hop.cloned();
        // Membership has no from/until. `now` does not widen an edge.
        let _ = now;

        let closed =
            |reason: &str, hint: Option<HandoffHint>, hop: Option<HopFactor>| MeshCheckResult {
                allowed: false,
                reason: reason.to_string(),
                hint,
                hop,
            };

        if let Some(reason) = closed_reason(object) {
            return closed(reason, hint, hop);
        }
        let Some((object_id, object_owner)) = self.object_record(object) else {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        };
        let object_id = object_id.to_string();
        let object_owner = object_owner.to_string();
        if acl_principal_key(&object_owner) == acl_principal_key(accessor) {
            return MeshCheckResult {
                allowed: true,
                reason: crate::MESH_REASON_OWNER.into(),
                hint,
                hop,
            };
        }
        let Some(edge) = self.object_set(&object_id) else {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        };
        let edge_predicate = edge.predicate;
        let edge_live = edge.is_live();
        let set_id = edge.set_id.clone();
        if edge_live && !set_id_has_bound_owner(&set_id) {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        }
        if edge_live
            && self
                .owner_of_set(predicate, &set_id)
                .is_some_and(|owner| !set_id_binds_owner(&set_id, owner))
        {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        }
        if edge_predicate != predicate || !edge_live {
            let reason = if edge_predicate == predicate && !edge_live {
                crate::MESH_REASON_CANCELLED
            } else {
                crate::MESH_REASON_MISSING
            };
            return closed(reason, hint, hop);
        }
        let Some(record) = self.membership_record(predicate, &set_id, accessor) else {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        };
        if record.membership.is_live() {
            return MeshCheckResult {
                allowed: true,
                reason: predicate.as_str().into(),
                hint,
                hop,
            };
        }
        let reason = if record.removed {
            crate::MESH_REASON_CANCELLED
        } else {
            crate::MESH_REASON_MISSING
        };
        closed(reason, hint, hop)
    }

    /// Group tail of a presentation, after binding and freshness.
    ///
    /// Allowed only when [`Self::check_group_see`] allows and the decoded
    /// payload is stated 1 with `now` in `[from, until)`. A live membership
    /// does not override a cancel or a closed window. A group object with
    /// no [`PresentedGroup`] fails closed. An ordinary object omits the
    /// argument and runs see.
    pub fn check_group_presentation(
        &self,
        group: Option<&PresentedGroup>,
        object: impl AsRef<str>,
        accessor: impl AsRef<str>,
        payload: &DecodedGroupPayload,
        now: Timestamp,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> GroupPresentation {
        let object = object.as_ref().trim();
        let accessor = accessor.as_ref().trim();
        let store_cancel = payload.stated == 0;
        let hinted = hint.cloned();
        let hopped = hop.cloned();
        let finish = |allowed: bool, reason: String| GroupPresentation {
            allowed,
            reason,
            hint: hinted.clone(),
            hop: hopped.clone(),
            store_cancel,
        };

        let named = self.object_set(object).is_some_and(|edge| edge.is_live());
        let Some(group) = group else {
            if named {
                return finish(false, crate::MESH_REASON_MISSING.into());
            }
            let dest = self.check_see(object, accessor, now, hint, hop);
            if dest.allowed && payload.live_at(now.0) {
                return finish(true, dest.reason);
            }
            let reason = if payload.live_at(now.0) {
                dest.reason
            } else {
                crate::MESH_REASON_CANCELLED.into()
            };
            return finish(false, reason);
        };

        let matched = self
            .object_set(object)
            .is_some_and(|edge| edge.predicate == group.predicate && edge.set_id == group.set_id);
        if !matched {
            return finish(false, crate::MESH_REASON_MISSING.into());
        }
        let see = self.check_group_see(group.predicate, object, accessor, now, hint, hop);
        if see.allowed && payload.live_at(now.0) {
            return finish(true, see.reason);
        }
        let reason = if payload.live_at(now.0) {
            see.reason
        } else {
            crate::MESH_REASON_CANCELLED.into()
        };
        finish(false, reason)
    }

    /// True when `members` and `object_set` would hide a removal or a
    /// newer object-to-set edge this graph has merged for `object`.
    ///
    /// A membership cancel at `ham_state` H is hidden by a snapshot that
    /// lists that accessor live for the set, omits the set, or names a
    /// lower `ham_state`. An object-set edge is hidden when the snapshot
    /// disagrees on predicate, set, or stated, names a lower `ham_state`,
    /// or drops the edge. Member `ham_state` is not the object-set edge.
    pub fn snapshot_understates_group(
        &self,
        object: &str,
        members: &[GroupSnapshotMember],
        object_set: Option<&GroupSnapshotObjectSet>,
    ) -> bool {
        let Some(current) = self.object_set_record(object) else {
            return object_set.is_some();
        };
        let current_ham = current.name.ham_state;
        let current_predicate = current.name.predicate;
        let current_set = current.name.set_id.clone();
        let current_stated = current.name.stated;
        let Some(snap) = object_set else {
            return true;
        };
        if snap.ham_state < current_ham
            || snap.predicate != current_predicate
            || snap.set_id != current_set
            || snap.stated != current_stated
        {
            return true;
        }
        self.groups.memberships.values().any(|record| {
            record.removed
                && record.membership.predicate == current_predicate
                && record.membership.set_id == current_set
                && membership_hidden(record, members)
        })
    }

    fn membership_speaker(
        &self,
        speaker: &str,
        predicate: GroupPredicate,
        set_id: &str,
        accessor: &str,
    ) -> Result<(bool, bool), GunError> {
        let owner = self
            .owner_of_set(predicate, set_id)
            .ok_or(GunError::SetUnknown)?;
        let speaker_key = acl_principal_key(speaker);
        let speaks_member = speaker_key == acl_principal_key(accessor);
        let speaks_set = speaker_key == acl_principal_key(owner);
        if !speaks_member && !speaks_set {
            return Err(GunError::MembershipSpeaker);
        }
        Ok((speaks_member, speaks_set))
    }

    fn write_object_set_auth(
        &self,
        owner: &str,
        object: &str,
    ) -> Result<(String, String), GunError> {
        let (object_id, object_owner) = self
            .object_record(object)
            .ok_or(GunError::ObjectNotInGraph)?;
        if acl_principal_key(object_owner) != acl_principal_key(owner) {
            return Err(GunError::AclOwnerOnly);
        }
        Ok((object_id.to_string(), object_owner.to_string()))
    }

    fn write_object_set(
        &mut self,
        object_id: &str,
        object_owner: &str,
        predicate: GroupPredicate,
        set_id: &str,
        stated: u8,
    ) {
        let key = object_set_key(object_id);
        let previous = self.groups.object_sets.get(&key);
        let ham_state = previous
            .map(|r| r.name.ham_state.saturating_add(1))
            .unwrap_or(1);
        let epoch = match previous {
            Some(record) if stated == 0 => record.epoch.saturating_add(1),
            Some(record) => record.epoch,
            None if stated == 0 => 1,
            None => 0,
        };
        let record = ObjectSetRecord {
            name: ObjectSetName {
                object: object_id.to_string(),
                predicate,
                set_id: set_id.to_string(),
                stated,
                ham_state,
            },
            soul: object_set_soul(object_owner, object_id),
            object_owner: object_owner.to_string(),
            epoch,
        };
        self.groups.object_sets.insert(key, record);
    }

    fn object_set_record(&self, object: &str) -> Option<&ObjectSetRecord> {
        let object = object.trim();
        if let Some((id, _)) = self.object_record(object) {
            if let Some(found) = self.groups.object_sets.get(&object_set_key(id)) {
                return Some(found);
            }
        }
        self.groups.object_sets.get(&object_set_key(object))
    }

    fn membership_record(
        &self,
        predicate: GroupPredicate,
        set_id: &str,
        accessor: &str,
    ) -> Option<&MembershipRecord> {
        let key = (
            predicate,
            set_id.trim().to_string(),
            acl_principal_key(accessor),
        );
        self.groups.memberships.get(&key)
    }
}

fn membership_key(membership: &MeshMembership) -> MembershipKey {
    (
        membership.predicate,
        membership.set_id.clone(),
        acl_principal_key(&membership.accessor),
    )
}

fn object_set_key(object: &str) -> String {
    acl_key(object.trim())
}

/// `<principal>/<name>`. The principal is the only account that can own the set.
fn set_id_binds_owner(set_id: &str, owner: &str) -> bool {
    let Some((head, tail)) = set_id.split_once('/') else {
        return false;
    };
    if head.is_empty() || tail.is_empty() {
        return false;
    }
    let owner_key = acl_principal_key(owner);
    !owner_key.is_empty() && acl_principal_key(head) == owner_key
}

fn set_id_has_bound_owner(set_id: &str) -> bool {
    set_id.split_once('/').is_some_and(|(head, tail)| {
        !head.is_empty() && !tail.is_empty() && !acl_principal_key(head).is_empty()
    })
}

fn retained_object_owner<'a>(owners: &'a HashMap<String, String>, object: &str) -> Option<&'a str> {
    if let Some(owner) = owners.get(object) {
        return Some(owner.as_str());
    }
    let want = object_set_key(object);
    owners
        .iter()
        .find(|(id, _)| object_set_key(id) == want)
        .map(|(_, owner)| owner.as_str())
}

fn membership_hidden(record: &MembershipRecord, members: &[GroupSnapshotMember]) -> bool {
    let ham = record.membership.ham_state;
    let accessor = acl_principal_key(&record.membership.accessor);
    let best = members
        .iter()
        .filter(|row| {
            row.predicate == record.membership.predicate
                && row.set_id == record.membership.set_id
                && acl_principal_key(&row.accessor) == accessor
        })
        .max_by_key(|row| (row.ham_state, u8::from(row.stated == 0)));
    match best {
        None => true,
        Some(row) if row.stated != 0 => true,
        Some(row) if row.ham_state < ham => true,
        Some(_) => false,
    }
}
