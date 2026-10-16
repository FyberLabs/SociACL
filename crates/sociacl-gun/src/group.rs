//! Direct `same-group` and `named-circle` rows on the plaintext mesh.
//!
//! Hopcap is 1. Both the object-to-set edge and the membership edge
//! must be stated 1. One-sided membership is stored and is not a grant.
//! Nested sets are not walked. A hop, a hint, or a wrap never mints.
//! Membership has no from/until window on this surface.
//!
//! A lower `hamState` does not replace a removal this peer has merged.
//! Member `hamState` does not stand in for the object-to-set edge.
//! Each party's assent is signed by that party. An object-set row is
//! signed by the object owner's enrolled key. Cancels are a grow-only
//! set of collision-free ids. A live assent or edge must list every
//! known cancel in its observed set. A set id is `<principal>/<name>`
//! with a name that does not collide under `acl_key`.
//! Wrapped keys are not read here.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rand::RngCore;
use sha2::{Digest, Sha256};
use sociacl_core::{AttestationSig, IssuerSecret, Timestamp, VerifyKey};

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

/// Collision-free cancel id. SHA-256 of this replica, a fresh nonce,
/// and the cancel ids already on the row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct CancelId(pub(crate) [u8; 32]);

/// A cancel signed by the party who issued it. The set only grows.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SignedCancel {
    id: CancelId,
    prior: BTreeSet<CancelId>,
    signer: String,
    signature: AttestationSig,
}

/// One party's assent. `observed` is the cancel ids this assent lists.
/// It is live only when `stated` is set and `observed` covers every
/// verified cancel on the row.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PartyStatement {
    stated: bool,
    ham_state: u64,
    observed: BTreeSet<CancelId>,
    signature: AttestationSig,
    spoken: bool,
}

impl PartyStatement {
    fn absent() -> Self {
        Self {
            stated: false,
            ham_state: 0,
            observed: BTreeSet::new(),
            signature: AttestationSig::empty(),
            spoken: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MembershipRecord {
    pub membership: MeshMembership,
    member: PartyStatement,
    set_party: PartyStatement,
    removed: bool,
    soul: String,
    set_owner: String,
    cancels: BTreeMap<CancelId, SignedCancel>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObjectSetRecord {
    name: ObjectSetName,
    signed_stated: u8,
    soul: String,
    object_owner: String,
    observed: BTreeSet<CancelId>,
    signature: AttestationSig,
    cancels: BTreeMap<CancelId, SignedCancel>,
}

type SetKey = (GroupPredicate, String);
type MembershipKey = (GroupPredicate, String, String);

#[derive(Clone, Debug)]
pub(crate) struct GroupRows {
    replica_id: [u8; 16],
    memberships: HashMap<MembershipKey, MembershipRecord>,
    object_sets: HashMap<String, ObjectSetRecord>,
    set_owners: HashMap<SetKey, String>,
    enrolled: HashMap<String, VerifyKey>,
}

impl Default for GroupRows {
    fn default() -> Self {
        let mut replica_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut replica_id);
        Self {
            replica_id,
            memberships: HashMap::new(),
            object_sets: HashMap::new(),
            set_owners: HashMap::new(),
            enrolled: HashMap::new(),
        }
    }
}

impl GroupRows {
    pub(crate) fn drop_object_set(&mut self, object: &str) {
        self.object_sets.remove(&object_set_key(object));
    }

    pub(crate) fn merge_from(&mut self, other: &Self, object_owners: &HashMap<String, String>) {
        for (key, owner) in &other.set_owners {
            let Some(set_id) = set_id_from_key(&key.1) else {
                continue;
            };
            if !set_id_binds_owner(&set_id, owner) {
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
        if canonical_set_id(&incoming.membership.set_id).is_err() {
            return;
        }
        if !set_id_binds_owner(&incoming.membership.set_id, &incoming.set_owner) {
            return;
        }
        let Some(owner) = self.set_owners.get(&(
            incoming.membership.predicate,
            set_map_key(&incoming.membership.set_id),
        )) else {
            return;
        };
        if acl_principal_key(owner) != acl_principal_key(&incoming.set_owner) {
            return;
        }
        let key = membership_key(&incoming.membership);
        let enrolled = self.enrolled.clone();
        let merged = match self.memberships.remove(&key) {
            Some(local) => merge_membership_records(local, incoming, &enrolled),
            None => {
                if !membership_signatures_ok(&incoming, &enrolled) {
                    return;
                }
                let mut incoming = incoming;
                incoming.publish(&enrolled);
                incoming
            }
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
        if incoming.signed_stated == 1 && canonical_set_id(&incoming.name.set_id).is_err() {
            return;
        }
        let enrolled = self.enrolled.clone();
        if !object_signature_ok(&incoming, &enrolled) {
            return;
        }
        let key = object_set_key(&incoming.name.object);
        let merged = match self.object_sets.remove(&key) {
            Some(local) => merge_object_records(local, incoming, &enrolled),
            None => {
                let mut incoming = incoming;
                refresh_object(&mut incoming, &enrolled);
                incoming
            }
        };
        self.object_sets.insert(key, merged);
    }
}

/// Membership soul under dest ACL. Not a five-segment grant soul
/// and not a Check object. The set segment is `acl_key` of the
/// canonical set id, the same key the in-memory map uses.
pub fn membership_soul(
    set_owner: &str,
    predicate: GroupPredicate,
    set_id: &str,
    accessor: &str,
) -> String {
    let set_key = canonical_set_id(set_id)
        .map(|id| acl_key(&id))
        .unwrap_or_else(|_| acl_key(set_id));
    format!(
        "{S3RCH_ROOT}/{S3RCH_ACL}/{}/membership/{}/{}/{}",
        acl_principal_key(set_owner),
        predicate.as_str(),
        set_key,
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
        let canonical = canonical_set_id(set_id)?;
        let key = (predicate, set_map_key(&canonical));
        if let Some(existing) = self.groups.set_owners.get(&key) {
            if acl_principal_key(existing) != acl_principal_key(owner) {
                return Err(GunError::SetOwnerConflict);
            }
            return Ok(());
        }
        if !set_id_binds_owner(&canonical, owner) {
            return Err(GunError::UnboundSetOwner);
        }
        self.groups.set_owners.insert(key, owner.to_string());
        Ok(())
    }

    pub fn owner_of_set(&self, predicate: GroupPredicate, set_id: &str) -> Option<&str> {
        let canonical = canonical_set_id(set_id.trim()).ok()?;
        self.groups
            .set_owners
            .get(&(predicate, set_map_key(&canonical)))
            .map(String::as_str)
    }

    /// Enroll the verify key that signs this principal's group rows.
    /// The signing key stays with the caller.
    pub fn enroll_signer(
        &mut self,
        principal: impl AsRef<str>,
        key: VerifyKey,
    ) -> Result<(), GunError> {
        let principal = principal.as_ref().trim();
        if principal.is_empty() || !key.is_valid() {
            return Err(GunError::SignerNotEnrolled);
        }
        let id = acl_principal_key(principal);
        if let Some(existing) = self.groups.enrolled.get(&id) {
            if existing != &key {
                return Err(GunError::SignerNotEnrolled);
            }
            return Ok(());
        }
        self.groups.enrolled.insert(id, key);
        Ok(())
    }

    /// One side of a direct membership. Live only when both the member
    /// and the set owner have stated it, and both assents have observed
    /// every cancel on the row.
    pub fn state_membership(
        &mut self,
        speaker: impl AsRef<str>,
        predicate: GroupPredicate,
        set_id: impl AsRef<str>,
        accessor: impl AsRef<str>,
        secret: &IssuerSecret,
    ) -> Result<(), GunError> {
        let set_id = set_id.as_ref().trim();
        let accessor = accessor.as_ref().trim();
        if set_id.is_empty() || accessor.is_empty() {
            return Err(GunError::EmptyGroupName);
        }
        let (speaks_member, speaks_set) =
            self.membership_speaker(speaker.as_ref(), predicate, set_id, accessor)?;
        let canonical = canonical_set_id(set_id)?;
        self.require_secret(speaker.as_ref(), secret)?;
        let key = membership_key_parts(predicate, &canonical, accessor);
        let owner = self
            .owner_of_set(predicate, &canonical)
            .ok_or(GunError::SetUnknown)?
            .to_string();
        let soul = membership_soul(&owner, predicate, &canonical, accessor);
        let mut record =
            self.groups.memberships.remove(&key).unwrap_or_else(|| {
                blank_membership(predicate, &canonical, accessor, &soul, &owner)
            });
        record.soul = soul;
        record.set_owner = owner;
        record.membership.ham_state = record.membership.ham_state.saturating_add(1);
        let observed = cancel_ids(&record.cancels);
        if speaks_member {
            let ham = record.member.ham_state.saturating_add(1);
            let message = party_message("member", &record, true, ham, &observed);
            sign_party(&mut record.member, true, observed.clone(), secret, &message);
        }
        if speaks_set {
            let ham = record.set_party.ham_state.saturating_add(1);
            let message = party_message("set", &record, true, ham, &observed);
            sign_party(
                &mut record.set_party,
                true,
                observed.clone(),
                secret,
                &message,
            );
        }
        let enrolled = self.groups.enrolled.clone();
        record.publish(&enrolled);
        self.groups.memberships.insert(key, record);
        Ok(())
    }

    /// Privilege-down. Adds a cancel id this replica has not used before.
    /// A later assent is live only after it lists that id.
    pub fn cancel_membership(
        &mut self,
        speaker: impl AsRef<str>,
        predicate: GroupPredicate,
        set_id: impl AsRef<str>,
        accessor: impl AsRef<str>,
        secret: &IssuerSecret,
    ) -> Result<(), GunError> {
        let set_id = set_id.as_ref().trim();
        let accessor = accessor.as_ref().trim();
        if set_id.is_empty() || accessor.is_empty() {
            return Err(GunError::EmptyGroupName);
        }
        let (speaks_member, speaks_set) =
            self.membership_speaker(speaker.as_ref(), predicate, set_id, accessor)?;
        let canonical = canonical_set_id(set_id)?;
        self.require_secret(speaker.as_ref(), secret)?;
        let key = membership_key_parts(predicate, &canonical, accessor);
        let owner = self
            .owner_of_set(predicate, &canonical)
            .ok_or(GunError::SetUnknown)?
            .to_string();
        let soul = membership_soul(&owner, predicate, &canonical, accessor);
        let mut record =
            self.groups.memberships.remove(&key).unwrap_or_else(|| {
                blank_membership(predicate, &canonical, accessor, &soul, &owner)
            });
        record.soul = soul;
        record.set_owner = owner;
        let row_key = membership_row_key(&record);
        self.groups.push_cancel(
            &mut record.cancels,
            "membership",
            &row_key,
            speaker.as_ref(),
            secret,
        );
        let observed = cancel_ids(&record.cancels);
        if speaks_member {
            let ham = record.member.ham_state.saturating_add(1);
            let message = party_message("member", &record, false, ham, &observed);
            sign_party(
                &mut record.member,
                false,
                observed.clone(),
                secret,
                &message,
            );
        }
        if speaks_set {
            let ham = record.set_party.ham_state.saturating_add(1);
            let message = party_message("set", &record, false, ham, &observed);
            sign_party(
                &mut record.set_party,
                false,
                observed.clone(),
                secret,
                &message,
            );
        }
        record.membership.ham_state = record.membership.ham_state.saturating_add(1);
        let enrolled = self.groups.enrolled.clone();
        record.publish(&enrolled);
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
        secret: &IssuerSecret,
    ) -> Result<(), GunError> {
        let set_id = set_id.as_ref().trim();
        if set_id.is_empty() {
            return Err(GunError::EmptyGroupName);
        }
        let canonical = canonical_set_id(set_id)?;
        let (object_id, object_owner) =
            self.write_object_set_auth(owner.as_ref(), object.as_ref())?;
        if self
            .owner_of_set(predicate, &canonical)
            .is_some_and(|set_owner| !set_id_binds_owner(&canonical, set_owner))
        {
            return Err(GunError::UnboundSetOwner);
        }
        self.require_secret(owner.as_ref(), secret)?;
        self.write_object_set(&object_id, &object_owner, predicate, &canonical, 1, secret);
        Ok(())
    }

    /// Object owner clears the set edge. The clear adds a cancel id,
    /// including when this replica has not seen the live edge.
    pub fn clear_object_set(
        &mut self,
        owner: impl AsRef<str>,
        object: impl AsRef<str>,
        secret: &IssuerSecret,
    ) -> Result<(), GunError> {
        let (object_id, object_owner) =
            self.write_object_set_auth(owner.as_ref(), object.as_ref())?;
        self.require_secret(owner.as_ref(), secret)?;
        let existing = self.object_set_record(&object_id);
        let (predicate, set_id) = match existing {
            Some(record) => (record.name.predicate, record.name.set_id.clone()),
            None => (GroupPredicate::SameGroup, String::new()),
        };
        self.write_object_set(&object_id, &object_owner, predicate, &set_id, 0, secret);
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
        let Some(edge) = self.object_set_record(&object_id) else {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        };
        if acl_principal_key(&edge.object_owner) != acl_principal_key(&object_owner) {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        }
        let edge_predicate = edge.name.predicate;
        if edge_predicate != predicate {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        }
        if !self.object_set_grantable(edge) {
            let reason = if edge.signed_stated == 0
                || !verified_cancel_ids(
                    &edge.cancels,
                    &self.groups.enrolled,
                    "object-set",
                    &object_set_key(&object_id),
                    |signer| acl_principal_key(signer) == acl_principal_key(&edge.object_owner),
                )
                .is_empty()
            {
                crate::MESH_REASON_CANCELLED
            } else {
                crate::MESH_REASON_MISSING
            };
            return closed(reason, hint, hop);
        }
        let set_id = edge.name.set_id.clone();
        if canonical_set_id(&set_id).ok().as_deref() != Some(set_id.as_str()) {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        }
        let Some(set_owner) = self.owner_of_set(predicate, &set_id) else {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        };
        if !set_id_binds_owner(&set_id, set_owner) {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        }
        let Some(record) = self.membership_record(predicate, &set_id, accessor) else {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        };
        if record.membership.set_id != set_id {
            return closed(crate::MESH_REASON_MISSING, hint, hop);
        }
        if self.membership_grantable(record) {
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

        let named = self
            .object_set_record(object)
            .is_some_and(|edge| self.object_set_grantable(edge));
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

        let matched = self.object_set_record(object).is_some_and(|edge| {
            edge.name.predicate == group.predicate && edge.name.set_id == group.set_id
        });
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

    fn require_secret(&self, principal: &str, secret: &IssuerSecret) -> Result<(), GunError> {
        let Some(key) = self.groups.enrolled.get(&acl_principal_key(principal)) else {
            return Err(GunError::SignerNotEnrolled);
        };
        if secret.verify_key() != *key {
            return Err(GunError::RowSignature);
        }
        Ok(())
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
        secret: &IssuerSecret,
    ) {
        let key = object_set_key(object_id);
        let previous = self.groups.object_sets.get(&key);
        let ham_state = previous
            .map(|r| r.name.ham_state.saturating_add(1))
            .unwrap_or(1);
        let mut cancels = previous.map(|r| r.cancels.clone()).unwrap_or_default();
        if stated == 0 {
            self.groups
                .push_cancel(&mut cancels, "object-set", &key, object_owner, secret);
        }
        let observed = cancel_ids(&cancels);
        let mut record = ObjectSetRecord {
            name: ObjectSetName {
                object: object_id.to_string(),
                predicate,
                set_id: set_id.to_string(),
                stated,
                ham_state,
            },
            signed_stated: stated,
            soul: object_set_soul(object_owner, object_id),
            object_owner: object_owner.to_string(),
            observed: observed.clone(),
            signature: AttestationSig::empty(),
            cancels,
        };
        record.signature = secret.sign(&object_message(&record));
        let enrolled = self.groups.enrolled.clone();
        refresh_object(&mut record, &enrolled);
        self.groups.object_sets.insert(key, record);
    }

    fn object_set_grantable(&self, record: &ObjectSetRecord) -> bool {
        object_live(record, &self.groups.enrolled)
    }

    fn membership_grantable(&self, record: &MembershipRecord) -> bool {
        record.is_grantable(&self.groups.enrolled)
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
        let Ok(canonical) = canonical_set_id(set_id.trim()) else {
            return None;
        };
        self.groups
            .memberships
            .get(&membership_key_parts(predicate, &canonical, accessor))
    }
}

impl GroupRows {
    fn push_cancel(
        &self,
        cancels: &mut BTreeMap<CancelId, SignedCancel>,
        kind: &str,
        row_key: &str,
        signer: &str,
        secret: &IssuerSecret,
    ) {
        let prior = cancel_ids(cancels);
        let id = new_cancel_id(&self.replica_id, &prior);
        let signature = secret.sign(&cancel_message(kind, row_key, &id, &prior));
        cancels.insert(
            id,
            SignedCancel {
                id,
                prior,
                signer: signer.trim().to_string(),
                signature,
            },
        );
    }
}

impl MembershipRecord {
    fn publish(&mut self, enrolled: &HashMap<String, VerifyKey>) {
        if self.is_grantable(enrolled) {
            self.membership.stated = 1;
            self.removed = false;
            return;
        }
        self.membership.stated = 0;
        let retracted =
            |party: &PartyStatement| party.spoken && !party.stated && party.ham_state > 0;
        let ids = verified_membership_ids(self, enrolled);
        self.removed = !ids.is_empty() || retracted(&self.member) || retracted(&self.set_party);
    }

    fn is_grantable(&self, enrolled: &HashMap<String, VerifyKey>) -> bool {
        if verified_membership_ids(self, enrolled).len() != self.cancels.len() {
            return false;
        }
        party_live(&self.member, "member", self, enrolled)
            && party_live(&self.set_party, "set", self, enrolled)
    }
}

fn blank_membership(
    predicate: GroupPredicate,
    set_id: &str,
    accessor: &str,
    soul: &str,
    owner: &str,
) -> MembershipRecord {
    MembershipRecord {
        membership: MeshMembership {
            predicate,
            set_id: set_id.to_string(),
            accessor: accessor.to_string(),
            stated: 0,
            ham_state: 0,
        },
        member: PartyStatement::absent(),
        set_party: PartyStatement::absent(),
        removed: false,
        soul: soul.to_string(),
        set_owner: owner.to_string(),
        cancels: BTreeMap::new(),
    }
}

fn sign_party(
    party: &mut PartyStatement,
    stated: bool,
    observed: BTreeSet<CancelId>,
    secret: &IssuerSecret,
    message: &[u8],
) {
    party.stated = stated;
    party.ham_state = party.ham_state.saturating_add(1);
    party.observed = observed;
    party.spoken = true;
    party.signature = secret.sign(message);
}

fn merge_membership_records(
    local: MembershipRecord,
    incoming: MembershipRecord,
    enrolled: &HashMap<String, VerifyKey>,
) -> MembershipRecord {
    let mut cancels = local.cancels.clone();
    if membership_signatures_ok(&incoming, enrolled) {
        for (id, cancel) in &incoming.cancels {
            if cancel_verifies(
                cancel,
                enrolled,
                "membership",
                &membership_row_key(&incoming),
                |signer| membership_cancel_signer(&incoming, signer),
            ) {
                cancels.entry(*id).or_insert_with(|| cancel.clone());
            }
        }
    }
    let ids = cancel_ids(&cancels);
    let member = pick_party(
        &local.member,
        &incoming.member,
        &ids,
        "member",
        &local,
        &incoming,
        enrolled,
    );
    let set_party = pick_party(
        &local.set_party,
        &incoming.set_party,
        &ids,
        "set",
        &local,
        &incoming,
        enrolled,
    );
    let mut out = local;
    out.member = member;
    out.set_party = set_party;
    out.cancels = cancels;
    out.membership.ham_state = out.membership.ham_state.max(incoming.membership.ham_state);
    out.publish(enrolled);
    out
}

fn pick_party(
    local: &PartyStatement,
    incoming: &PartyStatement,
    ids: &BTreeSet<CancelId>,
    role: &str,
    local_row: &MembershipRecord,
    incoming_row: &MembershipRecord,
    enrolled: &HashMap<String, VerifyKey>,
) -> PartyStatement {
    let local_ok = party_signature_ok(local, role, local_row, enrolled);
    let incoming_ok = party_signature_ok(incoming, role, incoming_row, enrolled);
    if local_ok && !incoming_ok {
        return local.clone();
    }
    if incoming_ok && !local_ok {
        return incoming.clone();
    }
    if !local_ok && !incoming_ok {
        return PartyStatement::absent();
    }
    let local_cov = local.observed.is_superset(ids);
    let incoming_cov = incoming.observed.is_superset(ids);
    if local_cov != incoming_cov {
        return if incoming_cov {
            incoming.clone()
        } else {
            local.clone()
        };
    }
    if incoming.ham_state > local.ham_state {
        return incoming.clone();
    }
    if incoming.ham_state < local.ham_state {
        return local.clone();
    }
    if !incoming.stated && local.stated {
        return incoming.clone();
    }
    local.clone()
}

fn merge_object_records(
    local: ObjectSetRecord,
    incoming: ObjectSetRecord,
    enrolled: &HashMap<String, VerifyKey>,
) -> ObjectSetRecord {
    let mut cancels = local.cancels.clone();
    let row_key = object_set_key(&incoming.name.object);
    for (id, cancel) in &incoming.cancels {
        if cancel_verifies(cancel, enrolled, "object-set", &row_key, |signer| {
            acl_principal_key(signer) == acl_principal_key(&incoming.object_owner)
        }) {
            cancels.entry(*id).or_insert_with(|| cancel.clone());
        }
    }
    let ids = cancel_ids(&cancels);
    let mut picked = pick_object(local, incoming, &ids);
    picked.cancels = cancels;
    refresh_object(&mut picked, enrolled);
    picked
}

fn pick_object(
    local: ObjectSetRecord,
    incoming: ObjectSetRecord,
    ids: &BTreeSet<CancelId>,
) -> ObjectSetRecord {
    let local_cov = local.observed.is_superset(ids);
    let incoming_cov = incoming.observed.is_superset(ids);
    if local_cov != incoming_cov {
        return if incoming_cov { incoming } else { local };
    }
    if incoming.name.ham_state > local.name.ham_state {
        return incoming;
    }
    if incoming.name.ham_state < local.name.ham_state {
        return local;
    }
    if incoming.signed_stated == 0 && local.signed_stated == 1 {
        return incoming;
    }
    if local.signed_stated == 0 && incoming.signed_stated == 1 {
        return local;
    }
    let incoming_key = (
        incoming.name.predicate.as_str(),
        incoming.name.set_id.as_str(),
    );
    let local_key = (local.name.predicate.as_str(), local.name.set_id.as_str());
    if incoming_key < local_key {
        incoming
    } else {
        local
    }
}

fn refresh_object(record: &mut ObjectSetRecord, enrolled: &HashMap<String, VerifyKey>) {
    record.name.stated = u8::from(object_live(record, enrolled));
}

fn object_live(record: &ObjectSetRecord, enrolled: &HashMap<String, VerifyKey>) -> bool {
    if record.signed_stated != 1 || !object_signature_ok(record, enrolled) {
        return false;
    }
    let ids = verified_cancel_ids(
        &record.cancels,
        enrolled,
        "object-set",
        &object_set_key(&record.name.object),
        |signer| acl_principal_key(signer) == acl_principal_key(&record.object_owner),
    );
    ids.len() == record.cancels.len() && record.observed.is_superset(&ids)
}

fn object_signature_ok(record: &ObjectSetRecord, enrolled: &HashMap<String, VerifyKey>) -> bool {
    let Some(key) = enrolled.get(&acl_principal_key(&record.object_owner)) else {
        return false;
    };
    key.verify(&object_message(record), &record.signature)
}

fn membership_signatures_ok(
    record: &MembershipRecord,
    enrolled: &HashMap<String, VerifyKey>,
) -> bool {
    party_signature_ok(&record.member, "member", record, enrolled)
        && party_signature_ok(&record.set_party, "set", record, enrolled)
        && verified_membership_ids(record, enrolled).len() == record.cancels.len()
}

fn party_live(
    party: &PartyStatement,
    role: &str,
    record: &MembershipRecord,
    enrolled: &HashMap<String, VerifyKey>,
) -> bool {
    let ids = verified_membership_ids(record, enrolled);
    party.spoken
        && party.stated
        && party.observed.is_superset(&ids)
        && party_signature_ok(party, role, record, enrolled)
}

fn party_signature_ok(
    party: &PartyStatement,
    role: &str,
    record: &MembershipRecord,
    enrolled: &HashMap<String, VerifyKey>,
) -> bool {
    if !party.spoken {
        return true;
    }
    let principal = if role == "member" {
        acl_principal_key(&record.membership.accessor)
    } else {
        acl_principal_key(&record.set_owner)
    };
    let Some(key) = enrolled.get(&principal) else {
        return false;
    };
    key.verify(
        &party_message(role, record, party.stated, party.ham_state, &party.observed),
        &party.signature,
    )
}

fn verified_membership_ids(
    record: &MembershipRecord,
    enrolled: &HashMap<String, VerifyKey>,
) -> BTreeSet<CancelId> {
    verified_cancel_ids(
        &record.cancels,
        enrolled,
        "membership",
        &membership_row_key(record),
        |signer| membership_cancel_signer(record, signer),
    )
}

fn membership_cancel_signer(record: &MembershipRecord, signer: &str) -> bool {
    let signer = acl_principal_key(signer);
    signer == acl_principal_key(&record.membership.accessor)
        || signer == acl_principal_key(&record.set_owner)
}

fn verified_cancel_ids(
    cancels: &BTreeMap<CancelId, SignedCancel>,
    enrolled: &HashMap<String, VerifyKey>,
    kind: &str,
    row_key: &str,
    allow: impl Fn(&str) -> bool,
) -> BTreeSet<CancelId> {
    cancels
        .iter()
        .filter(|(_, cancel)| cancel_verifies(cancel, enrolled, kind, row_key, &allow))
        .map(|(id, _)| *id)
        .collect()
}

fn cancel_verifies(
    cancel: &SignedCancel,
    enrolled: &HashMap<String, VerifyKey>,
    kind: &str,
    row_key: &str,
    allow: impl Fn(&str) -> bool,
) -> bool {
    if !allow(&cancel.signer) {
        return false;
    }
    let Some(key) = enrolled.get(&acl_principal_key(&cancel.signer)) else {
        return false;
    };
    key.verify(
        &cancel_message(kind, row_key, &cancel.id, &cancel.prior),
        &cancel.signature,
    )
}

fn new_cancel_id(replica_id: &[u8; 16], prior: &BTreeSet<CancelId>) -> CancelId {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut hasher = Sha256::new();
    hasher.update(b"sociacl-cancel-id-v1");
    hasher.update(replica_id);
    hasher.update(nonce);
    push_ids_hash(&mut hasher, prior);
    CancelId(hasher.finalize().into())
}

fn push_ids_hash(hasher: &mut Sha256, ids: &BTreeSet<CancelId>) {
    hasher.update((ids.len() as u64).to_be_bytes());
    for id in ids {
        hasher.update(id.0);
    }
}

fn cancel_ids(cancels: &BTreeMap<CancelId, SignedCancel>) -> BTreeSet<CancelId> {
    cancels.keys().copied().collect()
}

fn party_message(
    role: &str,
    record: &MembershipRecord,
    stated: bool,
    ham_state: u64,
    observed: &BTreeSet<CancelId>,
) -> Vec<u8> {
    let mut buf = b"sociacl-membership-assent-v1\0".to_vec();
    push_str(&mut buf, role);
    push_str(&mut buf, record.membership.predicate.as_str());
    push_str(&mut buf, &record.membership.set_id);
    push_str(&mut buf, &acl_principal_key(&record.membership.accessor));
    push_str(&mut buf, &acl_principal_key(&record.set_owner));
    buf.push(u8::from(stated));
    buf.extend_from_slice(&ham_state.to_be_bytes());
    push_ids(&mut buf, observed);
    buf
}

fn object_message(record: &ObjectSetRecord) -> Vec<u8> {
    let mut buf = b"sociacl-object-set-v1\0".to_vec();
    push_str(&mut buf, &acl_key(&record.name.object));
    push_str(&mut buf, &acl_principal_key(&record.object_owner));
    push_str(&mut buf, record.name.predicate.as_str());
    push_str(&mut buf, &record.name.set_id);
    buf.push(record.signed_stated);
    buf.extend_from_slice(&record.name.ham_state.to_be_bytes());
    push_ids(&mut buf, &record.observed);
    buf
}

fn cancel_message(kind: &str, row_key: &str, id: &CancelId, prior: &BTreeSet<CancelId>) -> Vec<u8> {
    let mut buf = b"sociacl-cancel-v1\0".to_vec();
    push_str(&mut buf, kind);
    push_str(&mut buf, row_key);
    buf.extend_from_slice(&id.0);
    push_ids(&mut buf, prior);
    buf
}

fn push_str(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&bytes[..usize::try_from(len).unwrap_or(bytes.len())]);
}

fn push_ids(buf: &mut Vec<u8>, ids: &BTreeSet<CancelId>) {
    let len = u32::try_from(ids.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    for id in ids.iter().take(usize::try_from(len).unwrap_or(ids.len())) {
        buf.extend_from_slice(&id.0);
    }
}

fn membership_row_key(record: &MembershipRecord) -> String {
    format!(
        "{}\0{}\0{}",
        record.membership.predicate.as_str(),
        record.membership.set_id,
        acl_principal_key(&record.membership.accessor)
    )
}

fn membership_key(membership: &MeshMembership) -> MembershipKey {
    membership_key_parts(
        membership.predicate,
        &membership.set_id,
        &membership.accessor,
    )
}

fn membership_key_parts(predicate: GroupPredicate, set_id: &str, accessor: &str) -> MembershipKey {
    (predicate, set_map_key(set_id), acl_principal_key(accessor))
}

fn object_set_key(object: &str) -> String {
    acl_key(object.trim())
}

fn set_map_key(set_id: &str) -> String {
    acl_key(set_id)
}

/// `<principal>/<name>`. The name has no `/` or `_`, so `acl_key`
/// is injective and the soul segment matches the map key.
fn canonical_set_id(set_id: &str) -> Result<String, GunError> {
    let set_id = set_id.trim();
    if set_id.is_empty() {
        return Err(GunError::EmptyGroupName);
    }
    let Some((head, name)) = set_id.split_once('/') else {
        return Err(GunError::UnboundSetOwner);
    };
    if head.is_empty()
        || name.is_empty()
        || head.contains('/')
        || name.contains('/')
        || name.contains('_')
        || name
            .chars()
            .any(|c| matches!(c, '.' | '#' | '$' | '[' | ']'))
        || head
            .chars()
            .any(|c| matches!(c, '.' | '#' | '$' | '[' | ']'))
    {
        return Err(GunError::UnboundSetOwner);
    }
    let principal = acl_principal_key(head);
    if principal.is_empty() || principal != head {
        return Err(GunError::UnboundSetOwner);
    }
    Ok(format!("{principal}/{name}"))
}

fn set_id_from_key(key: &str) -> Option<String> {
    let (head, name) = key.rsplit_once('_')?;
    if head.is_empty() || name.is_empty() || name.contains('_') {
        return None;
    }
    Some(format!("{head}/{name}"))
}

fn set_id_binds_owner(set_id: &str, owner: &str) -> bool {
    let Ok(canonical) = canonical_set_id(set_id) else {
        return false;
    };
    let Some((head, _)) = canonical.split_once('/') else {
        return false;
    };
    let owner_key = acl_principal_key(owner);
    !owner_key.is_empty() && acl_principal_key(head) == owner_key
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
