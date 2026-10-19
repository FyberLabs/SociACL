//! Label-graph helpers still used by post, group, request, feed, and encdisc.
//!
//! The stored-id see path does not import this module. Each caller deletes
//! its copy when it migrates: post in PR 3, request in PR 4, group in PR 5,
//! and feed, encdisc, and the contract in PR 6.

use std::cmp::Ordering;
use std::collections::HashMap;

use sociacl_core::{NodeId, Timestamp};

use crate::mesh::{
    GunAclEdge, LabelGraph, MeshCheckResult, MeshObject, MeshSeeGrant, MESH_REASON_ACL,
    MESH_REASON_CANCELLED, MESH_REASON_DELEGATE, MESH_REASON_META, MESH_REASON_MISSING,
    MESH_REASON_OWNER, MESH_REASON_URL_LEAF,
};
use crate::soul::{
    GunNode, GunNodeKind, GunSoul, S3RCH_ACL, S3RCH_ITEMS, S3RCH_META, S3RCH_ROOT, S3RCH_USERS,
};
use crate::{GunError, HandoffHint, HopFactor, UrlLeaf};

/// Injective path escape. `~` is the escape character.
/// `. # $ [ ]` each get their own form. `/` stays here so an item
/// soul does not gain a new spelling of a slash-bearing id.
pub(crate) fn encode_key(id: &str) -> String {
    escape_key(id, false)
}

fn escape_key(id: &str, slash: bool) -> String {
    let mut out = String::with_capacity(id.len());
    for ch in id.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '.' => out.push_str("~1"),
            '#' => out.push_str("~2"),
            '$' => out.push_str("~3"),
            '[' => out.push_str("~4"),
            ']' => out.push_str("~5"),
            '/' if slash => out.push_str("~6"),
            _ => out.push(ch),
        }
    }
    out
}

/// Reverse of [`acl_key`]. A bad escape is not a set id.
pub(crate) fn unescape_acl_key(id: &str) -> Option<String> {
    let mut out = String::with_capacity(id.len());
    let mut chars = id.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            out.push(ch);
            continue;
        }
        let decoded = match chars.next()? {
            '0' => '~',
            '1' => '.',
            '2' => '#',
            '3' => '$',
            '4' => '[',
            '5' => ']',
            '6' => '/',
            _ => return None,
        };
        out.push(decoded);
    }
    Some(out)
}

impl GunSoul {
    pub fn new(segments: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            segments: segments
                .into_iter()
                .map(|s| ascii_trim(s.as_ref()).to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    /// `gun.get('s3rch').get('users').get(wallet)`.
    pub fn s3rch_user(wallet: impl AsRef<str>) -> Self {
        Self::new([S3RCH_ROOT, S3RCH_USERS, wallet.as_ref()])
    }

    /// `gun.get('s3rch').get('items').get(encodeKey(id))`.
    pub fn s3rch_item(id: impl AsRef<str>) -> Self {
        Self::new([S3RCH_ROOT, S3RCH_ITEMS, &encode_key(id.as_ref())])
    }

    /// `gun.get('s3rch').get('meta')`.
    pub fn s3rch_meta() -> Self {
        Self::new([S3RCH_ROOT, S3RCH_META])
    }

    /// Owner dest-ACL root.
    /// `gun.get('s3rch').get('acl').get(aclPrincipalKey(owner))`.
    pub fn s3rch_acl(owner: impl AsRef<str>) -> Self {
        let Some(owner) = acl_principal_key(owner.as_ref()) else {
            return Self {
                segments: Vec::new(),
            };
        };
        Self::new([S3RCH_ROOT, S3RCH_ACL, &owner])
    }

    /// Jointly stated see grant under the object owner's dest ACL.
    /// Does not fork `items` or `users`.
    ///
    /// `gun.get('s3rch').get('acl').get(aclPrincipalKey(owner))
    ///     .get(aclKey(object)).get(aclPrincipalKey(accessor))`
    pub fn s3rch_acl_grant(
        owner: impl AsRef<str>,
        object: impl AsRef<str>,
        accessor: impl AsRef<str>,
    ) -> Self {
        let Some(owner) = acl_principal_key(owner.as_ref()) else {
            return Self {
                segments: Vec::new(),
            };
        };
        let Some(accessor) = acl_principal_key(accessor.as_ref()) else {
            return Self {
                segments: Vec::new(),
            };
        };
        Self::new([
            S3RCH_ROOT,
            S3RCH_ACL,
            &owner,
            &acl_key(object.as_ref()),
            &accessor,
        ])
    }

    /// Slash form. A string containing `.get(` is rejected.
    /// Does not verify the graph.
    pub fn parse(s: &str) -> Result<Self, crate::GunError> {
        let s = ascii_trim(s);
        if s.is_empty() || s.contains(".get(") {
            return Err(crate::GunError::HintCorrupt);
        }
        let soul = Self::new(s.split('/'));
        if soul.segments.is_empty() {
            return Err(crate::GunError::HintCorrupt);
        }
        Ok(soul)
    }
}

/// Dest-ACL path key. The same escape as [`encode_key`], plus `/`,
/// so a grant soul stays five segments. `room.alpha`, `room_alpha`,
/// and `room/alpha` are three keys. Not a second spelling of an item.
pub(crate) fn acl_key(id: &str) -> String {
    escape_key(ascii_trim(id), true)
}

/// ASCII whitespace only. U+FEFF and U+0085 stay, so this trim matches
/// TypeScript. Unicode whitespace and format characters are rejected
/// later by [`bare_principal`].
pub(crate) fn ascii_trim(text: &str) -> &str {
    text.trim_matches(|ch: char| matches!(ch, '\t' | '\n' | '\u{000B}' | '\u{000C}' | '\r' | ' '))
}

/// Leading or trailing whitespace, including U+0085, U+00A0, and
/// U+FEFF. An object id with either is not stored and does not alias.
pub(crate) fn object_id_rejected(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    let last = chars.next_back().unwrap_or(first);
    edge_space(first) || edge_space(last)
}

fn edge_space(ch: char) -> bool {
    ch.is_whitespace() || is_format_char(ch)
}

fn is_format_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// A bare principal, or `None`. `.` may occur inside an id. The whole
/// id cannot be `.` or `..`. `/ # $ [ ] ~`, controls, Unicode
/// whitespace, format characters, and `.get(` are rejected. Longer
/// than 256 scalar values is rejected. Never `Some("")`.
fn bare_principal(id: &str) -> Option<String> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id == "..."
        || id.chars().count() > 256
        || id.contains(".get(")
        || id.contains(['/', '#', '$', '[', ']', '~', ' '])
        || id
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || is_format_char(ch))
    {
        return None;
    }
    Some(id.to_string())
}

/// Owner / accessor key on dest ACL. An exact `s3rch/users/<wallet>`
/// collapses to that wallet. Anything else must be a bare principal.
/// `None` is not a soul segment. [`encode_key`] is for object keys.
pub(crate) fn acl_principal_key(id: &str) -> Option<String> {
    let id = ascii_trim(id);
    if id.is_empty() || id.contains(".get(") {
        return None;
    }
    let parts: Vec<&str> = id
        .split('/')
        .map(ascii_trim)
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() == 3 && parts[0] == S3RCH_ROOT && parts[1] == S3RCH_USERS {
        return bare_principal(parts[2]);
    }
    if id.contains('/') {
        return None;
    }
    bare_principal(id)
}

/// One accessor id. A user soul `s3rch/users/<wallet>` and the wallet
/// are this key. See and post writes, cancels, and lookups use it.
pub(crate) fn canonical_accessor_id(id: &str) -> Option<String> {
    acl_principal_key(id)
}

impl GunNode {
    pub fn user(wallet: impl AsRef<str>) -> Self {
        Self {
            soul: GunSoul::s3rch_user(wallet),
            kind: GunNodeKind::User,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_keys_for_dot_underscore_and_slash_stay_distinct() {
        let dot = acl_key("room.alpha");
        let under = acl_key("room_alpha");
        let slash = acl_key("room/alpha");
        assert_ne!(dot, under);
        assert_ne!(dot, slash);
        assert_ne!(under, slash);
        assert_eq!(encode_key("a/b"), "a/b");
        assert_ne!(acl_key("a/b"), acl_key("a_b"));
        assert_eq!(acl_key("room~1alpha"), "room~01alpha");
        assert_ne!(acl_key("room.alpha"), acl_key("room~1alpha"));
    }

    #[test]
    fn a_principal_is_not_run_through_the_object_escape() {
        assert_eq!(acl_principal_key("bob.name").as_deref(), Some("bob.name"));
        assert_eq!(
            acl_principal_key(acl_principal_key("bob.name").unwrap().as_str()).as_deref(),
            Some("bob.name")
        );
        assert_ne!(acl_key(&acl_key("room.alpha")), acl_key("room.alpha"));
    }

    #[test]
    fn a_gun_chain_is_not_the_inner_wallet() {
        let spoof = "0xattacker.get('s3rch').get('users').get('0xvictim')";
        assert!(GunSoul::parse(spoof).is_err());
        assert_eq!(canonical_accessor_id(spoof), None);
    }

    #[test]
    fn a_rejected_principal_is_not_a_grant_path() {
        assert_eq!(crate::legacy::grant_soul("0xalice", "doc", "0xbob/x"), None);
        assert_eq!(crate::legacy::grant_soul("0xalice/doc", "0xbob", "x"), None);
        assert_eq!(
            crate::legacy::grant_soul("0xalice", "doc", "0xbob")
                .unwrap()
                .as_str(),
            "s3rch/acl/0xalice/doc/0xbob"
        );
        assert_eq!(crate::legacy::acl_soul("../meta"), None);
        assert_eq!(canonical_accessor_id("a\u{0}b"), None);
        assert_eq!(
            crate::post_label::post_soul("0xalice", "doc", "a\u{0}b"),
            None
        );
        assert_eq!(canonical_accessor_id("bob~name"), None);
        assert_eq!(canonical_accessor_id("x~1get('s3rch')"), None);
        assert_eq!(canonical_accessor_id("."), None);
        assert_eq!(canonical_accessor_id(".."), None);
        assert_eq!(canonical_accessor_id("0x bob"), None);
        assert_eq!(canonical_accessor_id(&"a".repeat(257)), None);
        let capped = "a".repeat(256);
        assert_eq!(
            canonical_accessor_id(&capped).as_deref(),
            Some(capped.as_str())
        );
        assert_eq!(canonical_accessor_id("\u{FEFF}0xvictim"), None);
        assert_eq!(canonical_accessor_id("0xvictim\u{FEFF}"), None);
        assert_eq!(canonical_accessor_id("\u{0085}0xvictim"), None);
        assert_eq!(
            canonical_accessor_id("bob.name").as_deref(),
            Some("bob.name")
        );
        assert_eq!(
            canonical_accessor_id("s3rch/users/0xbob").as_deref(),
            Some("0xbob")
        );
    }
}

impl MeshSeeGrant {
    pub(crate) fn names_object(&self, object: &str) -> bool {
        object_names(&self.object, object)
    }

    pub(crate) fn names_accessor(&self, accessor: &str) -> bool {
        accessor_names(&self.accessor, accessor)
    }
}

pub(crate) fn object_names(stored: &str, query: &str) -> bool {
    if object_id_rejected(stored) || object_id_rejected(query) {
        return false;
    }
    stored == query || acl_key(stored) == acl_key(query) || item_soul_alias(stored, query)
}

pub(crate) fn accessor_names(stored: &str, query: &str) -> bool {
    match (canonical_accessor_id(stored), canonical_accessor_id(query)) {
        (Some(stored), Some(query)) => stored == query,
        _ => false,
    }
}

impl GunAclEdge {
    pub(crate) fn new(
        owner: impl Into<String>,
        grant: MeshSeeGrant,
        ham_state: u64,
    ) -> Result<Self, crate::GunError> {
        let owner = owner.into();
        if acl_principal_key(&owner).is_none() || acl_principal_key(&grant.accessor).is_none() {
            return Err(crate::GunError::EmptyPrincipal);
        }
        let soul = GunSoul::s3rch_acl_grant(&owner, &grant.object, &grant.accessor);
        if !soul.is_s3rch_acl_grant() {
            return Err(crate::GunError::EmptyPrincipal);
        }
        Ok(Self {
            soul,
            owner,
            grant,
            ham_state,
        })
    }

    pub(crate) fn soul_key(&self) -> String {
        self.soul.as_node_id().as_str().to_string()
    }

    /// Soul rebuilt from owner, object, and accessor. A peer map
    /// key or a copied soul does not choose where the grant lands.
    pub(crate) fn canonical(self) -> Self {
        Self::new(self.owner.clone(), self.grant.clone(), self.ham_state).unwrap_or(self)
    }

    /// Higher HAM state wins. At the same state a cancellation wins,
    /// then the narrower window, then the smaller canonical bytes.
    /// A row whose owner or accessor does not parse is dropped.
    pub(crate) fn ham_merge(self, incoming: Self) -> Self {
        let incoming_ok = grant_edge_parsable(&incoming);
        let local_ok = grant_edge_parsable(&self);
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
    match (canonical_grant_bytes(left), canonical_grant_bytes(right)) {
        (Some(left_bytes), Some(right_bytes)) => left_bytes.cmp(&right_bytes),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn grant_edge_parsable(edge: &GunAclEdge) -> bool {
    acl_principal_key(&edge.owner).is_some() && acl_principal_key(&edge.grant.accessor).is_some()
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

fn canonical_grant_bytes(edge: &GunAclEdge) -> Option<Vec<u8>> {
    let owner = acl_principal_key(&edge.owner)?;
    let accessor = acl_principal_key(&edge.grant.accessor)?;
    let mut buf = b"sociacl-see-grant-v1\0".to_vec();
    push_grant_str(&mut buf, &owner);
    push_grant_str(&mut buf, &acl_key(&edge.grant.object));
    push_grant_str(&mut buf, &accessor);
    buf.extend_from_slice(&edge.grant.from.0.to_be_bytes());
    buf.extend_from_slice(&edge.grant.until.0.to_be_bytes());
    buf.push(edge.grant.stated);
    Some(buf)
}

fn push_grant_str(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&bytes[..usize::try_from(len).unwrap_or(bytes.len())]);
}

impl LabelGraph {
    pub(crate) fn put_object(&mut self, object: impl AsRef<str>, owner: impl AsRef<str>) {
        let raw = object.as_ref();
        if object_id_rejected(raw) {
            return;
        }
        let id = raw.to_string();
        let owner = ascii_trim(owner.as_ref()).to_string();
        let direct_key = object_store_key(&id);
        if let Some(existing) = self.objects.get(&direct_key) {
            if existing.id != id {
                return;
            }
            if !principals_are(existing.owner.as_str(), owner.as_str()) {
                self.groups.drop_object_set(&id);
            }
            self.objects.insert(direct_key, MeshObject { id, owner });
            return;
        }
        if self.lookup_object(&id).is_some() {
            return;
        }
        self.objects.insert(direct_key, MeshObject { id, owner });
    }

    pub(crate) fn remove_object(&mut self, object: &str) {
        let key = object_store_key(object);
        self.objects.remove(&key);
    }

    pub(crate) fn has_object(&self, object: &str) -> bool {
        self.lookup_object(object).is_some()
    }

    pub(crate) fn owner_of(&self, object: &str) -> Option<&str> {
        self.lookup_object(object).map(|o| o.owner.as_str())
    }

    pub(crate) fn see_grants(&self, object: &str) -> Vec<&MeshSeeGrant> {
        let canonical = self.canonical_object_id(object);
        self.grants
            .values()
            .filter(|e| e.grant.names_object(&canonical) && e.grant.is_stated())
            .map(|e| &e.grant)
            .collect()
    }

    pub(crate) fn grant_edge(&self, object: &str, accessor: &str) -> Option<&GunAclEdge> {
        let canonical = self.canonical_object_id(object);
        let owner = self.owner_of(&canonical).unwrap_or("");
        self.grants.values().find(|edge| {
            edge.grant.names_object(&canonical)
                && edge.grant.names_accessor(accessor)
                && accessor_names(&edge.owner, owner)
        })
    }

    /// Record a person-to-person edge. Check never walks it.
    pub(crate) fn state_friend(&mut self, a: impl AsRef<str>, b: impl AsRef<str>) {
        let (Some(a), Some(b)) = (acl_principal_key(a.as_ref()), acl_principal_key(b.as_ref()))
        else {
            return;
        };
        self.friends.insert((a, b));
    }

    pub(crate) fn has_friend(&self, a: &str, b: &str) -> bool {
        let (Some(a), Some(b)) = (acl_principal_key(a), acl_principal_key(b)) else {
            return false;
        };
        self.friends.contains(&(a, b))
    }

    /// Owner-only. Writes a live grant at the dest-ACL soul.
    /// The stored object id is the in-graph id, so a raw id and its
    /// item soul share one row.
    pub(crate) fn state_see_grant(
        &mut self,
        owner: impl AsRef<str>,
        grant: MeshSeeGrant,
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
        let ham_state = self
            .folded_see(&grant.object, &grant.accessor, owner)
            .map(|edge| edge.ham_state.saturating_add(1))
            .unwrap_or(1);
        self.merge_edge(GunAclEdge::new(owner, grant, ham_state)?);
        Ok(())
    }

    /// Owner-only privilege-down. Bumps HAM state. Next Check after
    /// merge denies. No cached allow.
    pub(crate) fn unstate_see_grant(
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
        self.merge_edge(GunAclEdge::new(owner, grant, ham_state)?);
        Ok(())
    }

    /// HAM-merge an incoming dest-ACL node from another peer.
    /// The stored key is rebuilt from the grant's owner, object,
    /// and accessor. When the object is already in the graph, a raw
    /// id and its item soul land on that in-graph id.
    pub(crate) fn merge_edge(&mut self, incoming: GunAclEdge) {
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
                        && accessor_names(&edge.owner, &owner)
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
    pub(crate) fn merge_from(&mut self, other: &Self) {
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
                    .is_some_and(|object| accessor_names(&object.owner, &edge.owner))
            })
            .cloned()
            .collect();
        for edge in grants {
            self.merge_edge(edge);
        }
        let posts: Vec<crate::post_label::GunPostEdge> = other
            .posts
            .values()
            .filter(|edge| {
                self.lookup_object(&edge.grant.object)
                    .is_some_and(|object| accessor_names(&object.owner, &edge.owner))
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
    pub(crate) fn check_see_label(
        &self,
        object: impl AsRef<str>,
        accessor: impl AsRef<str>,
        now: Timestamp,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> MeshCheckResult {
        let object = object.as_ref();
        let accessor = ascii_trim(accessor.as_ref());
        if object_id_rejected(object) {
            return MeshCheckResult {
                allowed: false,
                reason: MESH_REASON_MISSING.into(),
                hint: hint.cloned(),
                hop: hop.cloned(),
            };
        }
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

        if accessor_names(&obj.owner, accessor) {
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
                && accessor_names(&edge.owner, &obj.owner);
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
    pub(crate) fn check_see_grant(
        &self,
        grant: &MeshSeeGrant,
        object: impl AsRef<str>,
        accessor: impl AsRef<str>,
        now: Timestamp,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> MeshCheckResult {
        let dest = self.check_see_label(object.as_ref(), accessor.as_ref(), now, hint, hop);
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
            .unwrap_or_else(|| object.to_string())
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
                    && accessor_names(&edge.owner, owner)
            })
            .cloned()
            .reduce(|left, right| left.ham_merge(right))
    }

    fn lookup_object(&self, object: &str) -> Option<&MeshObject> {
        if object_id_rejected(object) {
            return None;
        }
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

fn principals_are(left: &str, right: &str) -> bool {
    match (canonical_accessor_id(left), canonical_accessor_id(right)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
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
pub(crate) fn grant_soul(
    owner: impl AsRef<str>,
    object: impl AsRef<str>,
    accessor: impl AsRef<str>,
) -> Option<NodeId> {
    let soul = GunSoul::s3rch_acl_grant(owner, object, accessor);
    if !soul.is_s3rch_acl_grant() {
        return None;
    }
    Some(soul.as_node_id())
}

/// Owner dest-ACL root. Not a Check object.
pub(crate) fn acl_soul(owner: impl AsRef<str>) -> Option<NodeId> {
    let soul = GunSoul::s3rch_acl(owner);
    if soul.segments().len() != 3 {
        return None;
    }
    Some(soul.as_node_id())
}

#[cfg(test)]
mod label_tests {
    use sociacl_core::{IssuerSecret, Timestamp};

    use super::*;
    use crate::mesh::MeshSeeGraph;
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
        graph.labels.put_object("doc", "0xalice");
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
            .labels
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
        let mut graph = LabelGraph::default();
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
                .check_see_label("room.alpha", "0xbob", now, None, None)
                .allowed
        );
        assert!(
            graph
                .check_see_label("alpha", "0xbob", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see_label("room_alpha", "0xbob", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see_label("room/alpha", "0xbob", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see_label("room/chat/alpha", "0xbob", now, None, None)
                .allowed
        );
        let chain = "0xattacker.get('s3rch').get('users').get('0xvictim')";
        assert!(graph.object_record(chain).is_none());
        assert_eq!(canonical_accessor_id(chain), None);
        graph.put_object("doc", "0xvictim");
        assert!(!graph.check_see_label("doc", chain, now, None, None).allowed);
        assert!(
            graph
                .check_see_label("doc", "0xvictim", now, None, None)
                .allowed
        );
    }

    #[test]
    fn encode_key_keeps_slash_and_acl_key_escapes_it() {
        assert_eq!(encode_key("rss3:act/1#x"), "rss3:act/1~2x");
        assert_eq!(encode_key("a.b#$[c]"), "a~1b~2~3~4c~5");
        assert_eq!(acl_key("rss3:act/1#x"), "rss3:act~61~2x");
        assert_ne!(acl_key("room.alpha"), acl_key("room_alpha"));
        assert_ne!(acl_key("room.alpha"), acl_key("room/alpha"));
        assert_eq!(
            acl_principal_key("gun.get('s3rch').get('users').get('0xalice')"),
            None
        );
        assert_eq!(
            grant_soul("0xalice", "item-1", "0xbob").unwrap().as_str(),
            "s3rch/acl/0xalice/item-1/0xbob"
        );
        assert_eq!(
            grant_soul("0xalice", "rss3:act/1_x", "s3rch/users/0xbob")
                .unwrap()
                .as_str(),
            "s3rch/acl/0xalice/rss3:act~61_x/0xbob"
        );
        assert_eq!(
            grant_soul("alice.name", "a.b", "carol").unwrap().as_str(),
            "s3rch/acl/alice.name/a~1b/carol"
        );
    }

    #[test]
    fn rejected_principals_do_not_match_as_the_owner() {
        let mut graph = LabelGraph::default();
        graph.put_object("doc", "../meta");
        let now = Timestamp(10);
        assert!(
            !graph
                .check_see_label("doc", "a\u{0}b", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see_label("doc", "../meta", now, None, None)
                .allowed
        );
        graph.put_object("owned", "0xalice");
        assert!(
            !graph
                .check_see_label("owned", "\u{FEFF}0xalice", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see_label("owned", "0xalice\u{FEFF}", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see_label("owned", "\u{0085}0xalice", now, None, None)
                .allowed
        );
        assert!(
            !graph
                .check_see_label("doc", "x~1get('s3rch')", now, None, None)
                .allowed
        );
    }
}
