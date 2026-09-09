//! Mesh dest ACL: Gun-native see grants that HAM-merge across peers.
//!
//! Grants live under `s3rch/acl/…`, not under `items` or `users`.
//! Each peer evaluates [`MeshSeeGraph::check_see`] against its locally
//! HAM-merged graph at `now`. Cancel is owner-only and must be
//! visible as privilege-down on the next Check after merge. There is
//! no cached allow.

use std::collections::{HashMap, HashSet};

use sociacl_core::{NodeId, Timestamp};

use crate::soul::{acl_key, acl_principal_key, GunSoul, S3RCH_ACL, S3RCH_META, S3RCH_ROOT};
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
        let object = object.trim();
        self.object == object
            || acl_key(&self.object) == acl_key(object)
            || GunSoul::s3rch_item(self.object.trim())
                .as_node_id()
                .as_str()
                == object
            || GunSoul::s3rch_item(object).as_node_id().as_str() == self.object
    }

    pub fn names_accessor(&self, accessor: &str) -> bool {
        acl_principal_key(&self.accessor) == acl_principal_key(accessor)
    }
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

    /// Last-write-wins on HAM state. Cancel bumps state so
    /// privilege-down wins the next merge.
    pub fn ham_merge(self, incoming: Self) -> Self {
        if incoming.ham_state > self.ham_state {
            incoming
        } else {
            self
        }
    }
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
#[derive(Clone, Debug, Default)]
pub struct MeshSeeGraph {
    objects: HashMap<String, MeshObject>,
    grants: HashMap<String, GunAclEdge>,
    friends: HashSet<(String, String)>,
}

impl MeshSeeGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_object(&mut self, object: impl AsRef<str>, owner: impl AsRef<str>) {
        let id = object.as_ref().trim().to_string();
        self.objects.insert(
            object_store_key(&id),
            MeshObject {
                id,
                owner: owner.as_ref().trim().to_string(),
            },
        );
    }

    pub fn has_object(&self, object: &str) -> bool {
        self.lookup_object(object).is_some()
    }

    pub fn owner_of(&self, object: &str) -> Option<&str> {
        self.lookup_object(object).map(|o| o.owner.as_str())
    }

    pub fn see_grants(&self, object: &str) -> Vec<&MeshSeeGrant> {
        self.grants
            .values()
            .filter(|e| e.grant.names_object(object) && e.grant.is_stated())
            .map(|e| &e.grant)
            .collect()
    }

    pub fn grant_edge(&self, object: &str, accessor: &str) -> Option<&GunAclEdge> {
        self.grants
            .values()
            .find(|e| e.grant.names_object(object) && e.grant.names_accessor(accessor))
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
    pub fn state_see_grant(
        &mut self,
        owner: impl AsRef<str>,
        grant: MeshSeeGrant,
    ) -> Result<(), GunError> {
        let owner = owner.as_ref().trim();
        let object = self
            .lookup_object(&grant.object)
            .ok_or(GunError::ObjectNotInGraph)?;
        if acl_principal_key(&object.owner) != acl_principal_key(owner) {
            return Err(GunError::AclOwnerOnly);
        }
        let key = GunSoul::s3rch_acl_grant(owner, &grant.object, &grant.accessor)
            .as_node_id()
            .as_str()
            .to_string();
        let ham_state = self
            .grants
            .get(&key)
            .map(|e| e.ham_state.saturating_add(1))
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
        let obj = self
            .lookup_object(object)
            .ok_or(GunError::ObjectNotInGraph)?;
        if acl_principal_key(&obj.owner) != acl_principal_key(owner) {
            return Err(GunError::AclOwnerOnly);
        }
        let existing = self.grant_edge(object, accessor).cloned();
        let mut grant = existing
            .as_ref()
            .map(|e| e.grant.clone())
            .unwrap_or_else(|| MeshSeeGrant {
                object: object.to_string(),
                accessor: accessor.to_string(),
                from: Timestamp(0),
                until: Timestamp(0),
                stated: 0,
            });
        grant.stated = 0;
        let ham_state = existing.map(|e| e.ham_state.saturating_add(1)).unwrap_or(1);
        self.merge_edge(GunAclEdge::new(owner, grant, ham_state));
        Ok(())
    }

    /// HAM-merge an incoming dest-ACL node from another peer.
    pub fn merge_edge(&mut self, incoming: GunAclEdge) {
        let key = incoming.soul_key();
        let merged = match self.grants.remove(&key) {
            Some(local) => local.ham_merge(incoming),
            None => incoming,
        };
        self.grants.insert(key, merged);
    }

    /// Merge every dest-ACL node from `other` into this peer.
    pub fn merge_from(&mut self, other: &Self) {
        for edge in other.grants.values() {
            self.merge_edge(edge.clone());
        }
        for (key, object) in &other.objects {
            self.objects
                .entry(key.clone())
                .or_insert_with(|| object.clone());
        }
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

        if is_url_leaf(object) {
            return MeshCheckResult {
                allowed: false,
                reason: MESH_REASON_URL_LEAF.into(),
                hint,
                hop,
            };
        }
        if is_meta_object(object) {
            return MeshCheckResult {
                allowed: false,
                reason: MESH_REASON_META.into(),
                hint,
                hop,
            };
        }
        if is_acl_object(object) {
            return MeshCheckResult {
                allowed: false,
                reason: MESH_REASON_ACL.into(),
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

        if acl_principal_key(&obj.owner) == acl_principal_key(accessor) {
            return MeshCheckResult {
                allowed: true,
                reason: MESH_REASON_OWNER.into(),
                hint,
                hop,
            };
        }

        if let Some(edge) = self.grant_edge(object, accessor) {
            if edge.grant.live_at(now) {
                return MeshCheckResult {
                    allowed: true,
                    reason: MESH_REASON_DELEGATE.into(),
                    hint,
                    hop,
                };
            }
            if !edge.grant.is_stated() {
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

    fn lookup_object(&self, object: &str) -> Option<&MeshObject> {
        let object = object.trim();
        if let Some(found) = self.objects.get(&object_store_key(object)) {
            return Some(found);
        }
        self.objects.values().find(|o| {
            o.id == object
                || acl_key(&o.id) == acl_key(object)
                || GunSoul::s3rch_item(&o.id).as_node_id().as_str() == object
                || GunSoul::s3rch_item(object).as_node_id().as_str() == o.id
        })
    }
}

fn object_store_key(id: &str) -> String {
    acl_key(id)
}

fn is_url_leaf(object: &str) -> bool {
    let s = object.trim();
    (s.starts_with("http://") || s.starts_with("https://")) && UrlLeaf::parse(s).is_ok()
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
