use std::collections::HashMap;

use crate::cache::{HashCache, MemoryHashCache, Snapshot, SnapshotHash};
use crate::error::VerbError;
use crate::types::{
    AuthnState, Device, Edge, NodeId, NodeKind, Object, ObjectKind, ObjectProperties,
    ObjectVersion, Principal, Relation, Timestamp, Will,
};

/// Privilege-up delay used by tests unless a test sets another value.
/// Privilege-down does not use this number.
pub const DEFAULT_PRIVILEGE_UP_DELAY: Timestamp = Timestamp(1);

/// In-memory authority plane.
pub struct Plane {
    pub(crate) nodes: HashMap<NodeId, NodeKind>,
    pub(crate) objects: HashMap<NodeId, Object>,
    pub(crate) edges: Vec<Edge>,
    pub(crate) authn: HashMap<NodeId, AuthnState>,
    pub(crate) wills: HashMap<NodeId, Will>,
    pub(crate) cache: MemoryHashCache,
    /// Case C marker. Edges stated after this instant must not grant.
    /// Evaluation of the cut is not implemented (types + comments only).
    pub cut: Option<crate::types::CutBoundary>,
    now: Timestamp,
    privilege_up_delay: Timestamp,
}

impl Default for Plane {
    fn default() -> Self {
        Self::new()
    }
}

impl Plane {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            objects: HashMap::new(),
            edges: Vec::new(),
            authn: HashMap::new(),
            wills: HashMap::new(),
            cache: MemoryHashCache::default(),
            cut: None,
            now: Timestamp(0),
            privilege_up_delay: DEFAULT_PRIVILEGE_UP_DELAY,
        }
    }

    pub fn now(&self) -> Timestamp {
        self.now
    }

    pub fn set_now(&mut self, now: Timestamp) {
        self.now = now;
    }

    pub fn privilege_up_delay(&self) -> Timestamp {
        self.privilege_up_delay
    }

    pub fn set_privilege_up_delay(&mut self, delay: Timestamp) {
        self.privilege_up_delay = delay;
    }

    pub fn cache_hits(&self) -> u64 {
        self.cache.hits()
    }

    pub fn cache_misses(&self) -> u64 {
        self.cache.misses()
    }

    pub fn add_person(&mut self, id: impl Into<NodeId>) -> Principal {
        self.add_principal(id.into(), NodeKind::Person)
    }

    pub fn add_agent(&mut self, id: impl Into<NodeId>) -> Principal {
        self.add_principal(id.into(), NodeKind::Agent)
    }

    pub fn add_device(&mut self, id: impl Into<NodeId>) -> Device {
        let id = id.into();
        self.nodes.insert(id.clone(), NodeKind::Device);
        self.authn.entry(id.clone()).or_insert(AuthnState::Live);
        Device { id }
    }

    fn add_principal(&mut self, id: NodeId, kind: NodeKind) -> Principal {
        self.nodes.insert(id.clone(), kind);
        self.authn.entry(id.clone()).or_insert(AuthnState::Live);
        Principal { id, kind }
    }

    pub fn add_group(&mut self, id: impl Into<NodeId>) -> NodeId {
        let id = id.into();
        self.nodes.insert(id.clone(), NodeKind::Group);
        id
    }

    pub fn add_circle(&mut self, id: impl Into<NodeId>) -> NodeId {
        let id = id.into();
        self.nodes.insert(id.clone(), NodeKind::Circle);
        id
    }

    /// Creates a protected object owned by `owner`. The `owns` edge is jointly
    /// stated at creation (owner speaks for both endpoints) and is live
    /// immediately. Properties default to predicate `owner`.
    pub fn add_object(&mut self, id: impl Into<NodeId>, owner: impl Into<NodeId>) -> Object {
        let id = id.into();
        let owner = owner.into();
        let kind = match self.nodes.get(&id) {
            Some(NodeKind::Device) => ObjectKind::Device,
            _ => ObjectKind::Data,
        };
        let object = Object {
            id: id.clone(),
            kind,
            owner: owner.clone(),
            version: ObjectVersion(1),
            destroyed: false,
            content_key: Some([0u8; 32]),
            properties: ObjectProperties::owner(),
        };
        self.objects.insert(id.clone(), object.clone());
        self.edges.push(Edge {
            from: owner,
            to: id,
            relation: Relation::Owns,
            from_stated: true,
            to_stated: true,
            joint_at: Some(self.now),
            effective_at: Some(self.now),
        });
        object
    }

    /// Names the Check predicate and related fields (group, circle, mode).
    /// Bumps the object version. Fail closed later if `predicate` is missing
    /// or not on the named list.
    pub fn set_object_property(
        &mut self,
        object: impl Into<NodeId>,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), VerbError> {
        let object = object.into();
        {
            let obj = self
                .objects
                .get_mut(&object)
                .ok_or_else(|| VerbError::ObjectNotFound(object.clone()))?;
            if obj.destroyed {
                return Err(VerbError::ObjectDestroyed(object.clone()));
            }
            obj.properties.set(key, value);
        }
        self.bump_version(&object);
        Ok(())
    }

    pub fn object_properties(&self, object: &NodeId) -> Option<&ObjectProperties> {
        self.objects.get(object).map(|o| &o.properties)
    }

    pub fn set_authn(&mut self, id: impl Into<NodeId>, state: AuthnState) {
        self.authn.insert(id.into(), state);
    }

    pub fn authn(&self, id: &NodeId) -> AuthnState {
        self.authn.get(id).copied().unwrap_or(AuthnState::Gone)
    }

    pub fn object(&self, id: &NodeId) -> Option<&Object> {
        self.objects.get(id)
    }

    pub fn node_kind(&self, id: &NodeId) -> Option<NodeKind> {
        self.nodes.get(id).copied()
    }

    /// Privilege-up: `speaker` states one side. Grant only when both have stated.
    pub fn state_edge(
        &mut self,
        speaker: impl Into<NodeId>,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        relation: Relation,
    ) {
        let speaker = speaker.into();
        let from = from.into();
        let to = to.into();
        let speaks_from = self.may_speak(&speaker, &from);
        let speaks_to = self.may_speak(&speaker, &to);
        if !speaks_from && !speaks_to {
            return;
        }
        let now = self.now;
        let delay = self.privilege_up_delay;
        if let Some(edge) = self.find_edge_mut(&from, &to, relation) {
            if speaks_from {
                edge.from_stated = true;
            }
            if speaks_to {
                edge.to_stated = true;
            }
            if edge.is_jointly_stated() && edge.joint_at.is_none() {
                edge.joint_at = Some(now);
                edge.effective_at = Some(Timestamp(now.0.saturating_add(delay.0)));
            }
            return;
        }
        let joint = speaks_from && speaks_to;
        self.edges.push(Edge {
            from,
            to,
            relation,
            from_stated: speaks_from,
            to_stated: speaks_to,
            joint_at: if joint { Some(now) } else { None },
            effective_at: if joint {
                Some(Timestamp(now.0.saturating_add(delay.0)))
            } else {
                None
            },
        });
    }

    /// Both endpoints state. Convenience for tests and POSIX setup: advances
    /// `now` by the privilege-up delay so the edge is live for the next Check.
    pub fn jointly_state(
        &mut self,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        relation: Relation,
    ) {
        let from = from.into();
        let to = to.into();
        self.state_edge(&from, &from, &to, relation);
        self.state_edge(&to, &from, &to, relation);
        self.now.0 = self.now.0.saturating_add(self.privilege_up_delay.0);
    }

    /// Privilege-down: immediate. Bumps versions of objects the edge could grant.
    pub fn unstate_edge(
        &mut self,
        speaker: impl Into<NodeId>,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        relation: Relation,
    ) {
        let speaker = speaker.into();
        let from = from.into();
        let to = to.into();
        let speaks_from = self.may_speak(&speaker, &from);
        let speaks_to = self.may_speak(&speaker, &to);
        if !speaks_from && !speaks_to {
            return;
        }
        let mut affected: Vec<NodeId> = Vec::new();
        if let Some(edge) = self.find_edge_mut(&from, &to, relation) {
            if speaks_from {
                edge.from_stated = false;
            }
            if speaks_to {
                edge.to_stated = false;
            }
            if !edge.is_jointly_stated() {
                edge.joint_at = None;
                edge.effective_at = None;
            }
            affected.extend(self.objects_affected_by(&from, &to, relation));
        }
        self.edges.retain(|e| {
            e.from_stated || e.to_stated || e.from != from || e.to != to || e.relation != relation
        });
        for id in affected {
            self.bump_version(&id);
        }
    }

    pub fn write_object(&mut self, object: impl Into<NodeId>) {
        self.bump_version(&object.into());
    }

    pub fn write_will(&mut self, will: Will) -> Result<(), VerbError> {
        let object = self
            .objects
            .get(&will.object)
            .ok_or_else(|| VerbError::ObjectNotFound(will.object.clone()))?;
        if object.destroyed {
            return Err(VerbError::ObjectDestroyed(will.object.clone()));
        }
        if object.owner != will.testator {
            return Err(VerbError::CannotWriteWill(will.testator.clone()));
        }
        if self.authn(&will.testator) != AuthnState::Live {
            return Err(VerbError::TestatorNotAlive);
        }
        self.wills.insert(will.object.clone(), will);
        Ok(())
    }

    pub fn cancel_will(
        &mut self,
        object: impl Into<NodeId>,
        by: impl Into<NodeId>,
    ) -> Result<(), VerbError> {
        let object = object.into();
        let by = by.into();
        let will = self
            .wills
            .get_mut(&object)
            .ok_or_else(|| VerbError::NoWill(object.clone()))?;
        let may = will.cancelable_by.contains(&by) || will.testator == by;
        if !may {
            return Err(VerbError::CannotCancel(by));
        }
        will.canceled = true;
        Ok(())
    }

    pub fn will(&self, object: &NodeId) -> Option<&Will> {
        self.wills.get(object)
    }

    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    pub fn live_edges(&self) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(|e| e.is_jointly_stated())
    }

    /// Jointly stated and past the privilege-up delay. Privilege-down drops
    /// the edge before this filter runs.
    pub fn effective_edges(&self) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(|e| self.edge_effective(e))
    }

    fn edge_effective(&self, edge: &Edge) -> bool {
        if !edge.is_jointly_stated() {
            return false;
        }
        let Some(effective_at) = edge.effective_at else {
            return false;
        };
        self.now.0 >= effective_at.0
    }

    pub(crate) fn immediately_effective_at(&self) -> Timestamp {
        self.now
    }

    pub(crate) fn snapshot(&self, object: &NodeId) -> Option<Snapshot> {
        let obj = self.objects.get(object)?;
        let mut parts: Vec<Vec<u8>> = Vec::new();
        parts.push(object.as_bytes().to_vec());
        parts.push(obj.version.0.to_le_bytes().to_vec());
        let mut props: Vec<(&str, &str)> = obj.properties.iter().collect();
        props.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in props {
            parts.push(k.as_bytes().to_vec());
            parts.push(v.as_bytes().to_vec());
        }
        let mut live: Vec<&Edge> = self.effective_edges().collect();
        live.sort_by(|a, b| (&a.from, &a.to, a.relation).cmp(&(&b.from, &b.to, b.relation)));
        for e in live {
            let (from, to) = e.direction();
            parts.push(from.as_bytes().to_vec());
            parts.push(to.as_bytes().to_vec());
            parts.push(vec![e.relation as u8]);
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        Some(Snapshot {
            object: object.clone(),
            object_version: obj.version,
            hash: SnapshotHash::digest(&refs),
        })
    }

    pub(crate) fn bump_version(&mut self, object: &NodeId) {
        if let Some(obj) = self.objects.get_mut(object) {
            obj.version.0 = obj.version.0.saturating_add(1);
        }
    }

    fn may_speak(&self, speaker: &NodeId, endpoint: &NodeId) -> bool {
        if speaker == endpoint {
            return true;
        }
        if let Some(obj) = self.objects.get(endpoint) {
            return &obj.owner == speaker;
        }
        false
    }

    fn find_edge_mut(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        relation: Relation,
    ) -> Option<&mut Edge> {
        self.edges
            .iter_mut()
            .find(|e| e.from == *from && e.to == *to && e.relation == relation)
    }

    fn objects_affected_by(&self, from: &NodeId, to: &NodeId, relation: Relation) -> Vec<NodeId> {
        match relation {
            Relation::Owns | Relation::ObjectGroup | Relation::ObjectCircle | Relation::Trustee => {
                if self.objects.contains_key(to) {
                    vec![to.clone()]
                } else {
                    Vec::new()
                }
            }
            Relation::MemberOf => self
                .objects
                .keys()
                .filter(|oid| {
                    self.named_group(*oid).as_ref() == Some(to)
                        || self.effective_edges().any(|e| {
                            e.relation == Relation::ObjectGroup && e.from == **oid && e.to == *to
                        })
                })
                .cloned()
                .collect(),
            Relation::InCircle | Relation::Friend => self
                .objects
                .keys()
                .filter(|oid| {
                    self.named_circle(*oid).as_ref() == Some(to)
                        || self.effective_edges().any(|e| {
                            e.relation == Relation::ObjectCircle && e.from == **oid && e.to == *to
                        })
                })
                .cloned()
                .collect(),
        }
        .into_iter()
        .chain(if self.objects.contains_key(from) {
            vec![from.clone()]
        } else {
            Vec::new()
        })
        .collect()
    }

    pub(crate) fn has_live(&self, from: &NodeId, to: &NodeId, relation: Relation) -> bool {
        self.effective_edges()
            .any(|e| e.from == *from && e.to == *to && e.relation == relation)
    }

    pub(crate) fn named_group(&self, object: &NodeId) -> Option<NodeId> {
        if let Some(g) = self
            .objects
            .get(object)
            .and_then(|o| o.properties.get(ObjectProperties::GROUP))
        {
            return Some(NodeId::new(g));
        }
        self.effective_edges()
            .find(|e| e.relation == Relation::ObjectGroup && e.from == *object)
            .map(|e| e.to.clone())
    }

    pub(crate) fn named_circle(&self, object: &NodeId) -> Option<NodeId> {
        if let Some(c) = self
            .objects
            .get(object)
            .and_then(|o| o.properties.get(ObjectProperties::CIRCLE))
        {
            return Some(NodeId::new(c));
        }
        self.effective_edges()
            .find(|e| e.relation == Relation::ObjectCircle && e.from == *object)
            .map(|e| e.to.clone())
    }

    /// ACL names `principal` on `object` via owner, group, or one-hop circle.
    pub fn acl_names(&self, object: &NodeId, principal: &NodeId) -> bool {
        if self.has_live(principal, object, Relation::Owns) {
            return true;
        }
        if self.has_live(principal, object, Relation::Trustee) {
            return true;
        }
        if let Some(group) = self.named_group(object) {
            if self.has_live(principal, &group, Relation::MemberOf) {
                return true;
            }
        }
        if let Some(circle) = self.named_circle(object) {
            if self.has_live(principal, &circle, Relation::InCircle) {
                return true;
            }
        }
        false
    }
}
