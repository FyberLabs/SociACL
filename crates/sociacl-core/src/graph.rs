use std::collections::HashMap;

use crate::cache::{MemoryHashCache, Snapshot, SnapshotHash};
use crate::error::VerbError;
use crate::types::{
    AuthnState, Device, Edge, NodeId, NodeKind, Object, ObjectVersion, Principal, Relation,
    Timestamp, Will,
};

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
        }
    }

    pub fn now(&self) -> Timestamp {
        self.now
    }

    pub fn set_now(&mut self, now: Timestamp) {
        self.now = now;
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
    /// stated at creation (owner speaks for both endpoints).
    pub fn add_object(&mut self, id: impl Into<NodeId>, owner: impl Into<NodeId>) -> Object {
        let id = id.into();
        let owner = owner.into();
        let object = Object {
            id: id.clone(),
            owner: owner.clone(),
            version: ObjectVersion(1),
            destroyed: false,
            content_key: Some([0u8; 32]),
        };
        self.objects.insert(id.clone(), object.clone());
        self.edges.push(Edge {
            from: owner,
            to: id,
            relation: Relation::Owns,
            from_stated: true,
            to_stated: true,
        });
        object
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
        if let Some(edge) = self.find_edge_mut(&from, &to, relation) {
            if speaks_from {
                edge.from_stated = true;
            }
            if speaks_to {
                edge.to_stated = true;
            }
            return;
        }
        self.edges.push(Edge {
            from,
            to,
            relation,
            from_stated: speaks_from,
            to_stated: speaks_to,
        });
    }

    /// Both endpoints state. Convenience for tests and POSIX setup.
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

    pub fn live_edges(&self) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(|e| e.is_jointly_stated())
    }

    pub(crate) fn snapshot(&self, object: &NodeId) -> Option<Snapshot> {
        let obj = self.objects.get(object)?;
        let mut parts: Vec<Vec<u8>> = Vec::new();
        parts.push(object.as_bytes().to_vec());
        parts.push(obj.version.0.to_le_bytes().to_vec());
        let mut live: Vec<&Edge> = self.live_edges().collect();
        live.sort_by(|a, b| (&a.from, &a.to, a.relation).cmp(&(&b.from, &b.to, b.relation)));
        for e in live {
            parts.push(e.from.as_bytes().to_vec());
            parts.push(e.to.as_bytes().to_vec());
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
            Relation::Owns | Relation::ObjectGroup | Relation::ObjectCircle => {
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
                    self.live_edges().any(|e| {
                        e.relation == Relation::ObjectGroup && e.from == **oid && e.to == *to
                    })
                })
                .cloned()
                .collect(),
            Relation::InCircle => self
                .objects
                .keys()
                .filter(|oid| {
                    self.live_edges().any(|e| {
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
        self.live_edges()
            .any(|e| e.from == *from && e.to == *to && e.relation == relation)
    }

    /// ACL names `principal` on `object` via owner, group, or one-hop circle.
    pub fn acl_names(&self, object: &NodeId, principal: &NodeId) -> bool {
        if self.has_live(principal, object, Relation::Owns) {
            return true;
        }
        let groups: Vec<NodeId> = self
            .live_edges()
            .filter(|e| e.relation == Relation::ObjectGroup && e.from == *object)
            .map(|e| e.to.clone())
            .collect();
        if groups
            .iter()
            .any(|g| self.has_live(principal, g, Relation::MemberOf))
        {
            return true;
        }
        let circles: Vec<NodeId> = self
            .live_edges()
            .filter(|e| e.relation == Relation::ObjectCircle && e.from == *object)
            .map(|e| e.to.clone())
            .collect();
        circles
            .iter()
            .any(|c| self.has_live(principal, c, Relation::InCircle))
    }
}
