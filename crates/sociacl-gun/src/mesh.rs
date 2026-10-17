//! Mesh dest ACL: Gun-native see grants that HAM-merge across peers.
//!
//! Grants live under `s3rch/acl/…`, not under `items` or `users`.
//! Each peer evaluates [`MeshSeeGraph::check_see`] against its locally
//! HAM-merged graph at `now`. Cancel is owner-only and must be
//! visible as privilege-down on the next Check after merge. There is
//! no cached allow.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use sociacl_core::{NodeId, Timestamp};

use crate::soul::{
    acl_key, acl_principal_key, canonical_accessor_id, GunSoul, S3RCH_ACL, S3RCH_META, S3RCH_ROOT,
};
use crate::{GunError, HandoffHint, HopFactor, IdentitySeeGrant, UrlLeaf};

/// Predicate / deny reasons on the mesh consume surface.
pub const MESH_REASON_OWNER: &str = "owner";
pub const MESH_REASON_DELEGATE: &str = "delegate";
pub const MESH_REASON_MISSING: &str = "missing";
pub const MESH_REASON_META: &str = "meta";
pub const MESH_REASON_ACL: &str = "acl";
pub const MESH_REASON_URL_LEAF: &str = "url-leaf";
pub const MESH_REASON_CANCELLED: &str = "cancelled";

/// Jointly stated see grant stored as Gun-native data.
///
/// `stated` is 1 (live) or 0 (cancelled). HAM-merges across peers.
/// Privilege-down is `stated = 0` with a higher HAM state.
/// `from` inclusive, `until` exclusive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshSeeGrant {
    pub object: String,
    pub accessor: String,
    pub from: Timestamp,
    pub until: Timestamp,
    pub stated: u8,
}

impl MeshSeeGrant {
    pub fn live(
        object: impl Into<String>,
        accessor: impl Into<String>,
        from: u64,
        until: u64,
    ) -> Self {
        Self {
            object: object.into(),
            accessor: accessor.into(),
            from: Timestamp(from),
            until: Timestamp(until),
            stated: 1,
        }
    }

    pub fn is_stated(&self) -> bool {
        self.stated == 1
    }

    pub fn live_at(&self, now: Timestamp) -> bool {
        self.is_stated() && now.0 >= self.from.0 && now.0 < self.until.0
    }

    pub fn names_object(&self, object: &str) -> bool {
        object_names(&self.object, object)
    }

    pub fn names_accessor(&self, accessor: &str) -> bool {
        accessor_names(&self.accessor, accessor)
    }
}

pub(crate) fn object_names(stored: &str, query: &str) -> bool {
    let query = query.trim();
    stored == query || acl_key(stored) == acl_key(query) || item_soul_alias(stored, query)
}

pub(crate) fn accessor_names(stored: &str, query: &str) -> bool {
    canonical_accessor_id(stored) == canonical_accessor_id(query)
}

impl From<&IdentitySeeGrant> for MeshSeeGrant {
    fn from(grant: &IdentitySeeGrant) -> Self {
        Self {
            object: grant.claim_id.clone(),
            accessor: grant.accessor.as_str().to_string(),
            from: grant.from,
            until: grant.until,
            stated: 1,
        }
    }
}

/// One dest-ACL grant node. Soul does not fork items or users.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GunAclEdge {
    pub soul: GunSoul,
    pub owner: String,
    pub grant: MeshSeeGrant,
    /// Gun HAM state. Higher wins. Cancel must bump this.
    pub ham_state: u64,
}

impl GunAclEdge {
    pub fn new(owner: impl Into<String>, grant: MeshSeeGrant, ham_state: u64) -> Self {
        let owner = owner.into();
        let soul = GunSoul::s3rch_acl_grant(&owner, &grant.object, &grant.accessor);
        Self {
            soul,
            owner,
            grant,
            ham_state,
        }
    }

    pub fn soul_key(&self) -> String {
        self.soul.as_node_id().as_str().to_string()
    }

    /// Soul rebuilt from owner, object, and accessor. A peer map
    /// key or a copied soul does not choose where the grant lands.
    pub fn canonical(self) -> Self {
        Self::new(self.owner, self.grant, self.ham_state)
    }

    /// Higher HAM state wins. At the same state a cancellation wins,
    /// then the narrower window, then the smaller canonical bytes.
    pub fn ham_merge(self, incoming: Self) -> Self {
        let local = self.canonical();
        let incoming = incoming.canonical();
        if incoming.ham_state > local.ham_state {
            return incoming;
        }
        if incoming.ham_state < local.ham_state {
            return local;
        }
        match equal_ham_grant_order(&local, &incoming) {
            Ordering::Greater => incoming,
            Ordering::Less | Ordering::Equal => local,
        }
    }
}

/// `Less` means `left` is the privilege-down row.
fn equal_ham_grant_order(left: &GunAclEdge, right: &GunAclEdge) -> Ordering {
    let left_down = left.grant.stated != 1;
    let right_down = right.grant.stated != 1;
    match (left_down, right_down) {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    if let Some(order) = narrower_window(&left.grant, &right.grant) {
        return order;
    }
    canonical_grant_bytes(left).cmp(&canonical_grant_bytes(right))
}

fn narrower_window(left: &MeshSeeGrant, right: &MeshSeeGrant) -> Option<Ordering> {
    let left_inside = left.from.0 >= right.from.0
        && left.until.0 <= right.until.0
        && (left.from.0 > right.from.0 || left.until.0 < right.until.0);
    let right_inside = right.from.0 >= left.from.0
        && right.until.0 <= left.until.0
        && (right.from.0 > left.from.0 || right.until.0 < left.until.0);
    match (left_inside, right_inside) {
        (true, false) => Some(Ordering::Less),
        (false, true) => Some(Ordering::Greater),
        _ => None,
    }
}

fn canonical_grant_bytes(edge: &GunAclEdge) -> Vec<u8> {
    let mut buf = b"sociacl-see-grant-v1\0".to_vec();
    push_grant_str(&mut buf, &acl_principal_key(&edge.owner));
    push_grant_str(&mut buf, &acl_key(&edge.grant.object));
    push_grant_str(&mut buf, &acl_principal_key(&edge.grant.accessor));
    buf.extend_from_slice(&edge.grant.from.0.to_be_bytes());
    buf.extend_from_slice(&edge.grant.until.0.to_be_bytes());
    buf.push(edge.grant.stated);
    buf
}

fn push_grant_str(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&bytes[..usize::try_from(len).unwrap_or(bytes.len())]);
}

/// TS `CheckResult` on the mesh graph. A present hint or hop never
/// sets `allowed`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshCheckResult {
    pub allowed: bool,
    pub reason: String,
    pub hint: Option<HandoffHint>,
    pub hop: Option<HopFactor>,
}

impl MeshCheckResult {
    pub fn hint_is_grant(&self) -> bool {
        false
    }

    pub fn hop_is_grant(&self) -> bool {
        false
    }

    /// Hop was presented on an already-named live grant or owner path.
    /// Never true because of hop alone.
    pub fn hop_factored(&self) -> bool {
        self.allowed && self.hop.is_some()
    }

    /// A wrap is never an input that sets `allowed`.
    pub fn wrap_is_grant(&self) -> bool {
        false
    }

    /// An inbox delivery is never an input that sets `allowed`.
    pub fn inbox_is_grant(&self) -> bool {
        false
    }

    /// An access request is never an input that sets `allowed`.
    pub fn request_is_grant(&self) -> bool {
        false
    }
}

/// A hop, a hint, a wrap, a request, or an inbox delivery never grants.
/// Any other label is also not a grant.
pub fn factor_grants(_kind: &str) -> bool {
    false
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MeshObject {
    id: String,
    owner: String,
}

/// Locally HAM-merged dest ACL a peer Checks at `now`.
///
/// Friend edges may be recorded and are never walked (hopcap 1).
/// Mine overlay stays off this graph until an explicit share-into-mesh
/// [`MeshSeeGraph::put_object`].
///
/// Group and circle rows live on this same graph. They do not fork
/// items or users, and they are not see-grant souls.
#[derive(Clone, Debug, Default)]
pub struct MeshSeeGraph {
    objects: HashMap<String, MeshObject>,
    grants: HashMap<String, GunAclEdge>,
    pub(crate) posts: HashMap<String, crate::post::GunPostEdge>,
    friends: HashSet<(String, String)>,
    pub(crate) groups: crate::group::GroupRows,
}

impl MeshSeeGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_object(&mut self, object: impl AsRef<str>, owner: impl AsRef<str>) {
        let id = object.as_ref().trim().to_string();
        let owner = owner.as_ref().trim().to_string();
        let direct_key = object_store_key(&id);
        if self.objects.contains_key(&direct_key) {
            if self.objects.get(&direct_key).is_some_and(|existing| {
                canonical_accessor_id(&existing.owner) != canonical_accessor_id(&owner)
            }) {
                self.groups.drop_object_set(&id);
            }
            self.objects.insert(direct_key, MeshObject { id, owner });
            return;
        }
        if let Some(existing_id) = self.lookup_object(&id).map(|existing| existing.id.clone()) {
            let key = object_store_key(&existing_id);
            if self.objects.get(&key).is_some_and(|existing| {
                canonical_accessor_id(&existing.owner) != canonical_accessor_id(&owner)
            }) {
                self.groups.drop_object_set(&existing_id);
            }
            self.objects.insert(
                key,
                MeshObject {
                    id: existing_id,
                    owner,
                },
            );
            return;
        }
        self.objects.insert(direct_key, MeshObject { id, owner });
    }

    pub fn has_object(&self, object: &str) -> bool {
        self.lookup_object(object).is_some()
    }

    pub fn owner_of(&self, object: &str) -> Option<&str> {
        self.lookup_object(object).map(|o| o.owner.as_str())
    }

    pub fn see_grants(&self, object: &str) -> Vec<&MeshSeeGrant> {
        let canonical = self.canonical_object_id(object);
        self.grants
            .values()
            .filter(|e| e.grant.names_object(&canonical) && e.grant.is_stated())
            .map(|e| &e.grant)
            .collect()
    }

    pub fn grant_edge(&self, object: &str, accessor: &str) -> Option<&GunAclEdge> {
        let canonical = self.canonical_object_id(object);
        let owner = self.owner_of(&canonical).unwrap_or("");
        self.grants.values().find(|edge| {
            edge.grant.names_object(&canonical)
                && edge.grant.names_accessor(accessor)
                && canonical_accessor_id(&edge.owner) == canonical_accessor_id(owner)
        })
    }

    /// Record a person-to-person edge. Check never walks it.
    pub fn state_friend(&mut self, a: impl AsRef<str>, b: impl AsRef<str>) {
        self.friends
            .insert((acl_principal_key(a.as_ref()), acl_principal_key(b.as_ref())));
    }

    pub fn has_friend(&self, a: &str, b: &str) -> bool {
        self.friends
            .contains(&(acl_principal_key(a), acl_principal_key(b)))
    }

    /// Owner-only. Writes a live grant at the dest-ACL soul.
    /// The stored object id is the in-graph id, so a raw id and its
    /// item soul share one row.
    pub fn state_see_grant(
        &mut self,
        owner: impl AsRef<str>,
        grant: MeshSeeGrant,
    ) -> Result<(), GunError> {
        let owner = owner.as_ref().trim();
        let (stored_id, object_owner) = self
            .object_record(&grant.object)
            .map(|(id, object_owner)| (id.to_string(), object_owner.to_string()))
            .ok_or(GunError::ObjectNotInGraph)?;
        if canonical_accessor_id(&object_owner) != canonical_accessor_id(owner) {
            return Err(GunError::AclOwnerOnly);
        }
        let mut grant = grant;
        grant.object = stored_id;
        let ham_state = self
            .folded_see(&grant.object, &grant.accessor, owner)
            .map(|edge| edge.ham_state.saturating_add(1))
            .unwrap_or(1);
        self.merge_edge(GunAclEdge::new(owner, grant, ham_state));
        Ok(())
    }

    /// Owner-only privilege-down. Bumps HAM state. Next Check after
    /// merge denies. No cached allow.
    pub fn unstate_see_grant(
        &mut self,
        owner: impl AsRef<str>,
        accessor: impl AsRef<str>,
        object: impl AsRef<str>,
    ) -> Result<(), GunError> {
        let owner = owner.as_ref().trim();
        let object = object.as_ref().trim();
        let accessor = accessor.as_ref().trim();
        let (stored_id, object_owner) = self
            .object_record(object)
            .map(|(id, object_owner)| (id.to_string(), object_owner.to_string()))
            .ok_or(GunError::ObjectNotInGraph)?;
        if canonical_accessor_id(&object_owner) != canonical_accessor_id(owner) {
            return Err(GunError::AclOwnerOnly);
        }
        let existing = self.folded_see(&stored_id, accessor, owner);
        let mut grant = existing
            .as_ref()
            .map(|e| e.grant.clone())
            .unwrap_or_else(|| MeshSeeGrant {
                object: stored_id.clone(),
                accessor: accessor.to_string(),
                from: Timestamp(0),
                until: Timestamp(0),
                stated: 0,
            });
        grant.object = stored_id;
        grant.stated = 0;
        let ham_state = existing
            .map(|edge| edge.ham_state.saturating_add(1))
            .unwrap_or(1);
        self.merge_edge(GunAclEdge::new(owner, grant, ham_state));
        Ok(())
    }

    /// HAM-merge an incoming dest-ACL node from another peer.
    /// The stored key is rebuilt from the grant's owner, object,
    /// and accessor. When the object is already in the graph, a raw
    /// id and its item soul land on that in-graph id.
    pub fn merge_edge(&mut self, incoming: GunAclEdge) {
        let mut incoming = incoming.canonical();
        if let Some(stored_id) = self
            .object_record(&incoming.grant.object)
            .map(|(id, _)| id.to_string())
        {
            if incoming.grant.object != stored_id {
                incoming.grant.object = stored_id;
                incoming = incoming.canonical();
            }
            let object = incoming.grant.object.clone();
            let accessor = incoming.grant.accessor.clone();
            let owner = incoming.owner.clone();
            let keys: Vec<String> = self
                .grants
                .iter()
                .filter(|(_, edge)| {
                    edge.grant.names_object(&object)
                        && edge.grant.names_accessor(&accessor)
                        && canonical_accessor_id(&edge.owner) == canonical_accessor_id(&owner)
                })
                .map(|(key, _)| key.clone())
                .collect();
            let mut local: Option<GunAclEdge> = None;
            for key in keys {
                let Some(edge) = self.grants.remove(&key) else {
                    continue;
                };
                local = Some(match local {
                    Some(prev) => prev.ham_merge(edge),
                    None => edge,
                });
            }
            let merged = match local {
                Some(local) => local.ham_merge(incoming),
                None => incoming,
            };
            let mut merged = merged.canonical();
            if let Some(id) = self
                .object_record(&merged.grant.object)
                .map(|(id, _)| id.to_string())
            {
                if merged.grant.object != id {
                    merged.grant.object = id;
                    merged = merged.canonical();
                }
            }
            let key = merged.soul_key();
            self.grants.insert(key, merged);
            return;
        }
        let key = incoming.soul_key();
        let merged = match self.grants.remove(&key) {
            Some(local) => local.ham_merge(incoming),
            None => incoming,
        };
        let merged = merged.canonical();
        let key = merged.soul_key();
        self.grants.insert(key, merged);
    }

    /// Merge every dest-ACL node from `other` into this peer.
    /// Object rows are stored under the id on the row, not the
    /// peer's map key.
    pub fn merge_from(&mut self, other: &Self) {
        for object in other.objects.values() {
            let key = object_store_key(&object.id);
            if self.objects.contains_key(&key) || self.lookup_object(&object.id).is_some() {
                continue;
            }
            self.objects.insert(key, object.clone());
        }
        let grants: Vec<GunAclEdge> = other
            .grants
            .values()
            .filter(|edge| {
                self.lookup_object(&edge.grant.object)
                    .is_some_and(|object| {
                        canonical_accessor_id(&object.owner) == canonical_accessor_id(&edge.owner)
                    })
            })
            .cloned()
            .collect();
        for edge in grants {
            self.merge_edge(edge);
        }
        let posts: Vec<crate::post::GunPostEdge> = other
            .posts
            .values()
            .filter(|edge| {
                self.lookup_object(&edge.grant.object)
                    .is_some_and(|object| {
                        canonical_accessor_id(&object.owner) == canonical_accessor_id(&edge.owner)
                    })
            })
            .cloned()
            .collect();
        for edge in posts {
            self.merge_post_edge(edge);
        }
        let object_owners: HashMap<String, String> = self
            .objects
            .values()
            .map(|object| (object.id.clone(), object.owner.clone()))
            .collect();
        self.groups.merge_from(&other.groups, &object_owners);
    }

    /// `CHECK(see, object, accessor)` at `now` on the locally merged
    /// graph. `hint` and `hop` are ignored for `allowed`. Hop missing
    /// does not fail. Hop alone never allows.
    pub fn check_see(
        &self,
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

        if let Some(reason) = closed_reason(object) {
            return MeshCheckResult {
                allowed: false,
                reason: reason.into(),
                hint,
                hop,
            };
        }

        let Some(obj) = self.lookup_object(object) else {
            return MeshCheckResult {
                allowed: false,
                reason: MESH_REASON_MISSING.into(),
                hint,
                hop,
            };
        };

        if canonical_accessor_id(&obj.owner) == canonical_accessor_id(accessor) {
            return MeshCheckResult {
                allowed: true,
                reason: MESH_REASON_OWNER.into(),
                hint,
                hop,
            };
        }

        if let Some(edge) = self.grant_edge(object, accessor) {
            let names = edge.grant.names_object(object)
                && edge.grant.names_accessor(accessor)
                && canonical_accessor_id(&edge.owner) == canonical_accessor_id(&obj.owner);
            if names && edge.grant.live_at(now) {
                return MeshCheckResult {
                    allowed: true,
                    reason: MESH_REASON_DELEGATE.into(),
                    hint,
                    hop,
                };
            }
            if names && !edge.grant.is_stated() {
                return MeshCheckResult {
                    allowed: false,
                    reason: MESH_REASON_CANCELLED.into(),
                    hint,
                    hop,
                };
            }
        }

        let _ = self.has_friend(obj.owner.as_str(), accessor);
        MeshCheckResult {
            allowed: false,
            reason: MESH_REASON_MISSING.into(),
            hint,
            hop,
        }
    }

    /// Dest Check AND the presented grant window. Hop / hint do not
    /// mint and do not widen the window.
    pub fn check_see_grant(
        &self,
        grant: &MeshSeeGrant,
        object: impl AsRef<str>,
        accessor: impl AsRef<str>,
        now: Timestamp,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> MeshCheckResult {
        let dest = self.check_see(object.as_ref(), accessor.as_ref(), now, hint, hop);
        if !grant.names_object(object.as_ref())
            || !grant.names_accessor(accessor.as_ref())
            || !grant.live_at(now)
        {
            return MeshCheckResult {
                allowed: false,
                reason: dest.reason,
                hint: dest.hint,
                hop: dest.hop,
            };
        }
        dest
    }

    pub(crate) fn object_record(&self, object: &str) -> Option<(&str, &str)> {
        self.lookup_object(object)
            .map(|obj| (obj.id.as_str(), obj.owner.as_str()))
    }

    /// In-graph object id. See and post writes, cancels, and lookups
    /// use this spelling once the object is stored.
    pub(crate) fn canonical_object_id(&self, object: &str) -> String {
        self.object_record(object)
            .map(|(id, _)| id.to_string())
            .unwrap_or_else(|| object.trim().to_string())
    }

    /// In-range see rows that name this object, accessor, and owner.
    /// A raw id and its item soul count once.
    pub(crate) fn folded_see(
        &self,
        object: &str,
        accessor: &str,
        owner: &str,
    ) -> Option<GunAclEdge> {
        let canonical = self.canonical_object_id(object);
        self.grants
            .values()
            .filter(|edge| {
                edge.grant.names_object(&canonical)
                    && edge.grant.names_accessor(accessor)
                    && canonical_accessor_id(&edge.owner) == canonical_accessor_id(owner)
            })
            .cloned()
            .reduce(|left, right| left.ham_merge(right))
    }

    fn lookup_object(&self, object: &str) -> Option<&MeshObject> {
        let object = object.trim();
        if let Some(found) = self.objects.get(&object_store_key(object)) {
            return Some(found);
        }
        self.objects.values().find(|o| {
            o.id == object || acl_key(&o.id) == acl_key(object) || item_soul_alias(&o.id, object)
        })
    }
}

fn object_store_key(id: &str) -> String {
    acl_key(id)
}

pub(crate) fn is_item_shaped(id: &str) -> bool {
    GunSoul::parse(id)
        .map(|s| s.is_s3rch_item())
        .unwrap_or(false)
}

/// Alias a raw feed id to `s3rch/items/<encodeKey(id)>`. Held claim
/// ids (`ens:…` / `fc:…` / … without a `/`) stay the claim id itself
/// and must not rewrite into an item soul.
pub(crate) fn may_alias_to_item_soul(id: &str) -> bool {
    if is_item_shaped(id) {
        return true;
    }
    if crate::has_held_claim_prefix(id) && !id.contains('/') {
        return false;
    }
    true
}

fn item_soul_alias(a: &str, b: &str) -> bool {
    if !is_item_shaped(a) && !is_item_shaped(b) {
        return false;
    }
    if !may_alias_to_item_soul(a) || !may_alias_to_item_soul(b) {
        return false;
    }
    GunSoul::s3rch_item(a).as_node_id().as_str() == b
        || GunSoul::s3rch_item(b).as_node_id().as_str() == a
}

pub(crate) fn closed_reason(object: &str) -> Option<&'static str> {
    if is_url_leaf(object) {
        Some(MESH_REASON_URL_LEAF)
    } else if is_meta_object(object) {
        Some(MESH_REASON_META)
    } else if is_acl_object(object) {
        Some(MESH_REASON_ACL)
    } else {
        None
    }
}

fn is_url_leaf(object: &str) -> bool {
    let s = object.trim();
    let scheme = s
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    matches!(scheme.as_deref(), Some("http") | Some("https")) && UrlLeaf::parse(s).is_ok()
}

fn is_meta_object(object: &str) -> bool {
    let s = object.trim();
    s == S3RCH_META
        || s == format!("{S3RCH_ROOT}/{S3RCH_META}")
        || GunSoul::parse(s)
            .map(|soul| soul.is_s3rch_meta())
            .unwrap_or(false)
}

fn is_acl_object(object: &str) -> bool {
    let s = object.trim();
    s == S3RCH_ACL
        || s.starts_with(&format!("{S3RCH_ROOT}/{S3RCH_ACL}"))
        || GunSoul::parse(s)
            .map(|soul| soul.is_s3rch_acl())
            .unwrap_or(false)
}

/// Grant soul string the TS consume contract names.
pub fn grant_soul(
    owner: impl AsRef<str>,
    object: impl AsRef<str>,
    accessor: impl AsRef<str>,
) -> NodeId {
    GunSoul::s3rch_acl_grant(owner, object, accessor).as_node_id()
}

/// Owner dest-ACL root. Not a Check object.
pub fn acl_soul(owner: impl AsRef<str>) -> NodeId {
    GunSoul::s3rch_acl(owner).as_node_id()
}

#[cfg(test)]
mod tests {
    use sociacl_core::{IssuerSecret, Timestamp};

    use super::*;
    use crate::GroupPredicate;

    fn signer(name: &str) -> IssuerSecret {
        let mut bytes = [0u8; 32];
        for (i, b) in name.as_bytes().iter().enumerate() {
            bytes[i % 32] ^= b.wrapping_add((i as u8).wrapping_mul(17));
        }
        bytes[0] ^= name.len() as u8;
        bytes[31] |= 1;
        IssuerSecret::from_bytes(bytes)
    }

    #[test]
    fn check_rejects_an_edge_whose_owner_is_not_the_current_owner() {
        let mut graph = MeshSeeGraph::new();
        let alice = signer("0xalice");
        let bob = signer("0xbob");
        graph.enroll_signer("0xalice", alice.verify_key()).unwrap();
        graph.enroll_signer("0xbob", bob.verify_key()).unwrap();
        graph.put_object("doc", "0xalice");
        graph
            .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
            .unwrap();
        graph
            .name_object_set(
                "0xalice",
                "doc",
                GroupPredicate::SameGroup,
                "0xalice/ops",
                &alice,
            )
            .unwrap();
        graph
            .state_membership(
                "0xbob",
                GroupPredicate::SameGroup,
                "0xalice/ops",
                "0xbob",
                &bob,
            )
            .unwrap();
        graph
            .state_membership(
                "0xalice",
                GroupPredicate::SameGroup,
                "0xalice/ops",
                "0xbob",
                &alice,
            )
            .unwrap();
        graph
            .objects
            .get_mut(&object_store_key("doc"))
            .unwrap()
            .owner = "0xcarol".into();
        assert!(graph.object_set("doc").is_some());
        let denied = graph.check_group_see(
            GroupPredicate::SameGroup,
            "doc",
            "0xbob",
            Timestamp(1),
            None,
            None,
        );
        assert!(!denied.allowed);
        assert_eq!(denied.reason, MESH_REASON_MISSING);
    }

    #[test]
    fn a_grant_names_one_object_and_a_gun_chain_is_not_a_record() {
        let mut graph = MeshSeeGraph::new();
        for object in [
            "room.alpha",
            "room_alpha",
            "room/alpha",
            "alpha",
            "room/chat/alpha",
        ] {
            graph.put_object(object, "0xalice");
        }
        graph
            .state_see_grant("0xalice", MeshSeeGrant::live("room.alpha", "0xbob", 0, 80))
            .unwrap();
        graph
            .state_see_grant("0xalice", MeshSeeGrant::live("alpha", "0xbob", 0, 80))
            .unwrap();
        let now = Timestamp(10);
        assert!(
            graph
                .check_see("room.alpha", "0xbob", now, None, None)
                .allowed
        );
        assert!(graph.check_see("alpha", "0xbob", now, None, None).allowed);
        assert!(
            !graph
                .check_see("room_alpha", "0xbob", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see("room/alpha", "0xbob", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see("room/chat/alpha", "0xbob", now, None, None)
                .allowed
        );
        let chain = "0xattacker.get('s3rch').get('users').get('0xvictim')";
        assert!(graph.object_record(chain).is_none());
        assert_ne!(crate::soul::canonical_accessor_id(chain), "0xvictim");
        graph.put_object("doc", "0xvictim");
        assert!(!graph.check_see("doc", chain, now, None, None).allowed);
        assert!(graph.check_see("doc", "0xvictim", now, None, None).allowed);
    }
}
