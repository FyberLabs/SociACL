//! Owner post grant on the plaintext mesh.
//!
//! The row is separate from [`crate::MeshSeeGrant`]. It uses the same
//! fields and the same cancel rule: `stated` 0 plus a higher `ham_state`,
//! and at an equal `ham_state` a cancellation wins, then the narrower
//! window, then the smaller canonical bytes. Privilege-down is the next
//! Check after that merge. This graph does not cache an allow.
//!
//! [`post_grant_signing_bytes`] is the length-prefixed encoding a later
//! owner signature can cover: canonical object id, canonical accessor id,
//! `stated`, `from`, `until`, scope `post`, and `ham_state`. Check does
//! not verify a signature.
//!
//! Allow-post requires see. The object owner passes see and may post.
//! Any other accessor needs a live post row as well. A hop, a hint, a
//! wrap, a request, or an inbox delivery never grants. Hopcap stays 1.

use std::cmp::Ordering;

use sociacl_core::{NodeId, Timestamp};

use crate::legacy::{
    accessor_names, acl_key, acl_principal_key, ascii_trim, object_id_rejected, object_names,
};
use crate::soul::{S3RCH_ACL, S3RCH_ROOT};
use crate::{
    GunError, MeshCheckResult, MeshSeeGraph, MESH_REASON_CANCELLED, MESH_REASON_MISSING,
    MESH_REASON_OWNER,
};

/// Reason when a non-owner's live post grant allows.
pub const MESH_REASON_POST: &str = "post";

/// Length-prefixed domain for the post-grant row encoding.
pub const POST_GRANT_DOMAIN: &str = "s3rch-post-grant-v1";

/// Scope covered by [`post_grant_signing_bytes`]. Not a see row.
pub const POST_GRANT_SCOPE: &str = "post";

/// Largest integer JavaScript `Number.isSafeInteger` accepts.
const JS_SAFE_INTEGER_MAX: u64 = (1 << 53) - 1;

/// Post grant. Same row shape as a see grant.
///
/// `stated` is 1 (live) or 0 (cancelled). `from` is inclusive.
/// `until` is exclusive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshPostGrant {
    pub object: String,
    pub accessor: String,
    pub from: Timestamp,
    pub until: Timestamp,
    pub stated: u8,
}

impl MeshPostGrant {
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

/// One post-grant node. Soul is [`post_soul`], not [`crate::grant_soul`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GunPostEdge {
    pub soul: String,
    pub owner: String,
    pub grant: MeshPostGrant,
    /// Gun HAM state. Higher wins. Cancel must bump this.
    pub ham_state: u64,
}

impl GunPostEdge {
    pub fn new(
        owner: impl Into<String>,
        grant: MeshPostGrant,
        ham_state: u64,
    ) -> Result<Self, GunError> {
        let owner = owner.into();
        let Some(soul) = post_soul(&owner, &grant.object, &grant.accessor) else {
            return Err(GunError::EmptyPrincipal);
        };
        Ok(Self {
            soul: soul.as_str().to_string(),
            owner,
            grant,
            ham_state,
        })
    }

    /// Soul rebuilt from owner, object, and accessor. A peer map key
    /// or a copied soul does not choose where the grant lands.
    pub fn canonical(self) -> Self {
        Self::new(self.owner.clone(), self.grant.clone(), self.ham_state).unwrap_or(self)
    }

    /// Higher HAM state wins. At the same state a cancellation wins,
    /// then the narrower window, then the smaller signing bytes.
    /// A row whose owner or accessor does not parse is dropped.
    pub fn ham_merge(self, incoming: Self) -> Self {
        let incoming_ok = post_edge_parsable(&incoming);
        let local_ok = post_edge_parsable(&self);
        if !incoming_ok {
            return self;
        }
        if !local_ok {
            return incoming.canonical();
        }
        let local = self.canonical();
        let incoming = incoming.canonical();
        if incoming.ham_state > local.ham_state {
            return incoming;
        }
        if incoming.ham_state < local.ham_state {
            return local;
        }
        match equal_ham_post_order(&local, &incoming) {
            Ordering::Greater => incoming,
            Ordering::Less | Ordering::Equal => local,
        }
    }
}

/// Six-segment post soul under the object owner's dest ACL.
/// Not a five-segment see-grant soul and not a Check object.
pub fn post_soul(
    owner: impl AsRef<str>,
    object: impl AsRef<str>,
    accessor: impl AsRef<str>,
) -> Option<NodeId> {
    let owner = acl_principal_key(owner.as_ref())?;
    let accessor = acl_principal_key(accessor.as_ref())?;
    Some(NodeId::new(format!(
        "{S3RCH_ROOT}/{S3RCH_ACL}/{owner}/{POST_GRANT_SCOPE}/{}/{}",
        acl_key(object.as_ref()),
        accessor,
    )))
}

/// Length-prefixed UTF-8 fields an owner signature can cover.
///
/// Order: domain, `aclKey(object)`, `aclPrincipalKey(accessor)`,
/// decimal `stated`, decimal `from`, decimal `until`, scope `post`,
/// decimal `hamState`. Lengths are uint32 little-endian. Integers
/// have no sign and no leading zeros. Check does not verify a signature.
pub fn post_grant_signing_bytes(
    grant: &MeshPostGrant,
    ham_state: u64,
) -> Result<Vec<u8>, GunError> {
    let fields = [
        POST_GRANT_DOMAIN.to_string(),
        acl_key(&grant.object),
        acl_principal_key(&grant.accessor).ok_or(GunError::PostGrantField)?,
        canonical_decimal(u64::from(grant.stated))?,
        canonical_decimal(grant.from.0)?,
        canonical_decimal(grant.until.0)?,
        POST_GRANT_SCOPE.to_string(),
        canonical_decimal(ham_state)?,
    ];
    length_prefixed(&fields)
}

fn canonical_decimal(value: u64) -> Result<String, GunError> {
    if value > JS_SAFE_INTEGER_MAX {
        return Err(GunError::PostGrantField);
    }
    Ok(value.to_string())
}

fn length_prefixed(fields: &[String]) -> Result<Vec<u8>, GunError> {
    let mut out = Vec::new();
    for field in fields {
        let raw = field.as_bytes();
        let len = u32::try_from(raw.len()).map_err(|_| GunError::PostGrantField)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(raw);
    }
    Ok(out)
}

/// `Less` means `left` is the privilege-down row.
fn equal_ham_post_order(left: &GunPostEdge, right: &GunPostEdge) -> Ordering {
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
    match (canonical_post_bytes(left), canonical_post_bytes(right)) {
        (Some(left_bytes), Some(right_bytes)) => left_bytes.cmp(&right_bytes),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn narrower_window(left: &MeshPostGrant, right: &MeshPostGrant) -> Option<Ordering> {
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

fn canonical_post_bytes(edge: &GunPostEdge) -> Option<Vec<u8>> {
    post_grant_signing_bytes(&edge.grant, edge.ham_state)
        .ok()
        .or_else(|| fallback_post_bytes(edge))
}

fn fallback_post_bytes(edge: &GunPostEdge) -> Option<Vec<u8>> {
    let owner = acl_principal_key(&edge.owner)?;
    let accessor = acl_principal_key(&edge.grant.accessor)?;
    let mut buf = b"sociacl-post-grant-fallback-v1\0".to_vec();
    push_str(&mut buf, &owner);
    push_str(&mut buf, &acl_key(&edge.grant.object));
    push_str(&mut buf, &accessor);
    buf.extend_from_slice(&edge.grant.from.0.to_be_bytes());
    buf.extend_from_slice(&edge.grant.until.0.to_be_bytes());
    buf.push(edge.grant.stated);
    buf.extend_from_slice(&edge.ham_state.to_be_bytes());
    Some(buf)
}

fn push_str(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&bytes[..usize::try_from(len).unwrap_or(bytes.len())]);
}

fn post_edge_parsable(edge: &GunPostEdge) -> bool {
    post_soul(&edge.owner, &edge.grant.object, &edge.grant.accessor).is_some()
}

fn post_row_in_range(edge: &GunPostEdge) -> bool {
    edge.grant.from.0 <= JS_SAFE_INTEGER_MAX
        && edge.grant.until.0 <= JS_SAFE_INTEGER_MAX
        && edge.ham_state <= JS_SAFE_INTEGER_MAX
}

fn same_post_row(edge: &GunPostEdge, object: &str, accessor: &str, owner: &str) -> bool {
    edge.grant.names_object(object)
        && edge.grant.names_accessor(accessor)
        && accessor_names(&edge.owner, owner)
}

impl MeshSeeGraph {
    pub fn post_grants(&self, object: &str) -> Vec<&MeshPostGrant> {
        let owner = self.owner_of(object).unwrap_or("");
        self.posts
            .values()
            .filter(|edge| {
                post_row_in_range(edge)
                    && edge.grant.names_object(object)
                    && edge.grant.is_stated()
                    && accessor_names(&edge.owner, owner)
            })
            .map(|edge| &edge.grant)
            .collect()
    }

    pub fn post_edge(&self, object: &str, accessor: &str) -> Option<&GunPostEdge> {
        let owner = self.owner_of(object).unwrap_or("");
        self.posts
            .values()
            .find(|edge| post_row_in_range(edge) && same_post_row(edge, object, accessor, owner))
    }

    fn canonical_post_object(&self, object: &str) -> String {
        self.canonical_object_id(object)
    }

    /// In-range rows that name this object, accessor, and owner, folded
    /// with the post HAM rule. A raw id and its item soul count once.
    pub(crate) fn folded_post(
        &self,
        object: &str,
        accessor: &str,
        owner: &str,
    ) -> Option<GunPostEdge> {
        self.posts
            .values()
            .filter(|edge| post_row_in_range(edge) && same_post_row(edge, object, accessor, owner))
            .cloned()
            .reduce(|left, right| left.ham_merge(right))
    }

    /// Owner-only. Writes a live post grant. Does not write a see grant.
    pub fn state_post_grant(
        &mut self,
        owner: impl AsRef<str>,
        grant: MeshPostGrant,
    ) -> Result<(), GunError> {
        let owner = ascii_trim(owner.as_ref());
        let (stored_id, object_owner) = self
            .object_record(&grant.object)
            .map(|(id, object_owner)| (id.to_string(), object_owner.to_string()))
            .ok_or(GunError::ObjectNotInGraph)?;
        if !accessor_names(&object_owner, owner) {
            return Err(GunError::AclOwnerOnly);
        }
        let mut grant = grant;
        grant.object = stored_id;
        grant.stated = 1;
        if grant.from.0 > JS_SAFE_INTEGER_MAX || grant.until.0 > JS_SAFE_INTEGER_MAX {
            return Err(GunError::PostGrantField);
        }
        let ham_state = self
            .folded_post(&grant.object, &grant.accessor, owner)
            .map(|edge| edge.ham_state.saturating_add(1))
            .unwrap_or(1);
        if ham_state > JS_SAFE_INTEGER_MAX {
            return Err(GunError::PostGrantField);
        }
        self.merge_post_edge(GunPostEdge::new(owner, grant, ham_state)?);
        Ok(())
    }

    /// Owner-only privilege-down. Sets `stated` to 0 and bumps HAM state.
    pub fn unstate_post_grant(
        &mut self,
        owner: impl AsRef<str>,
        accessor: impl AsRef<str>,
        object: impl AsRef<str>,
    ) -> Result<(), GunError> {
        let owner = ascii_trim(owner.as_ref());
        let object = object.as_ref();
        if object_id_rejected(object) {
            return Err(GunError::ObjectNotInGraph);
        }
        let accessor = ascii_trim(accessor.as_ref());
        let (stored_id, object_owner) = self
            .object_record(object)
            .map(|(id, object_owner)| (id.to_string(), object_owner.to_string()))
            .ok_or(GunError::ObjectNotInGraph)?;
        if !accessor_names(&object_owner, owner) {
            return Err(GunError::AclOwnerOnly);
        }
        let existing = self.folded_post(&stored_id, accessor, owner);
        let mut grant = existing
            .as_ref()
            .map(|edge| edge.grant.clone())
            .unwrap_or_else(|| MeshPostGrant {
                object: stored_id.clone(),
                accessor: accessor.to_string(),
                from: Timestamp(0),
                until: Timestamp(0),
                stated: 0,
            });
        grant.object = stored_id;
        grant.stated = 0;
        let ham_state = match existing.as_ref().map(|edge| edge.ham_state) {
            Some(ham) => {
                let next = ham.saturating_add(1);
                if next > JS_SAFE_INTEGER_MAX {
                    ham
                } else {
                    next
                }
            }
            None => 1,
        };
        self.merge_post_edge(GunPostEdge::new(owner, grant, ham_state)?);
        Ok(())
    }

    /// HAM-merge an incoming post node. The stored key is rebuilt
    /// from owner, object, and accessor. A raw id and the item soul
    /// `owner_of` already treats as that object land on one row.
    /// An integer above the JavaScript safe range is dropped.
    /// The object must already be in the graph, and `incoming.owner`
    /// must be that object's current owner. A row that arrives earlier
    /// is not retained.
    pub fn merge_post_edge(&mut self, incoming: GunPostEdge) {
        if !post_row_in_range(&incoming) || !post_edge_parsable(&incoming) {
            return;
        }
        let Some((stored_id, object_owner)) = self
            .object_record(&incoming.grant.object)
            .map(|(id, owner)| (id.to_string(), owner.to_string()))
        else {
            return;
        };
        if !accessor_names(&object_owner, &incoming.owner) {
            return;
        }
        let mut incoming = incoming.canonical();
        incoming.grant.object = stored_id;
        incoming = incoming.canonical();
        let object = incoming.grant.object.clone();
        let accessor = incoming.grant.accessor.clone();
        let owner = incoming.owner.clone();
        let keys: Vec<String> = self
            .posts
            .iter()
            .filter(|(_, edge)| same_post_row(edge, &object, &accessor, &owner))
            .map(|(key, _)| key.clone())
            .collect();
        let mut local: Option<GunPostEdge> = None;
        for key in keys {
            let Some(edge) = self.posts.remove(&key) else {
                continue;
            };
            if !post_row_in_range(&edge) {
                continue;
            }
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
        merged.grant.object = self.canonical_post_object(&merged.grant.object);
        merged = merged.canonical();
        if !post_row_in_range(&merged) {
            return;
        }
        let key = merged.soul.clone();
        self.posts.insert(key, merged);
    }

    /// Allow-post. See must pass. A post row alone does not allow.
    /// The object owner may post. Hop and hint are echoed and ignored
    /// for `allowed`.
    pub fn check_post(
        &self,
        object: impl AsRef<str>,
        accessor: impl AsRef<str>,
        now: Timestamp,
        hint: Option<&crate::HandoffHint>,
        hop: Option<&crate::HopFactor>,
    ) -> MeshCheckResult {
        let see = self.check_see_label(object.as_ref(), accessor.as_ref(), now, hint, hop);
        if !see.allowed {
            return see;
        }
        if see.reason == MESH_REASON_OWNER {
            return see;
        }
        let object = self.canonical_object_id(object.as_ref());
        let accessor = ascii_trim(accessor.as_ref());
        let owner = self.owner_of(&object).unwrap_or("");
        if let Some(edge) = self.post_edge(&object, accessor) {
            let names = edge.grant.names_object(&object)
                && edge.grant.names_accessor(accessor)
                && accessor_names(&edge.owner, owner);
            if names && edge.grant.live_at(now) {
                return MeshCheckResult {
                    allowed: true,
                    reason: MESH_REASON_POST.into(),
                    hint: see.hint,
                    hop: see.hop,
                };
            }
            if names && !edge.grant.is_stated() {
                return MeshCheckResult {
                    allowed: false,
                    reason: MESH_REASON_CANCELLED.into(),
                    hint: see.hint,
                    hop: see.hop,
                };
            }
        }
        MeshCheckResult {
            allowed: false,
            reason: MESH_REASON_MISSING.into(),
            hint: see.hint,
            hop: see.hop,
        }
    }
}
