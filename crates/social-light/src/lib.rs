//! Local Social Light delivery lab.
//!
//! Nodes are SociACL people, agents, or devices holding a live
//! [`Plane`] or a Case C [`Client`]. A node may emit a signed hop
//! frame to neighbors it can already reach, in-process or over
//! localhost UDP. Hearing a flash does not mint a friend, heir, or
//! owner.
//!
//! FyberLabs/socialight is the product sibling that owns badge,
//! station, and later radio hops. This crate stays here so that
//! interface can move without merging names. SociACL verifies.
//! socialight delivers.
//!
//! Partition keeps the last bundle. Silence does not Elect. Rejoin
//! uses [`Client::rejoin`]. Not a hosted service.

use std::collections::{BTreeMap, BTreeSet};

use sociacl_core::{
    CheckRequest, CheckResult, Client, HolderSecret, NodeId, NodeKind, Plane, SocialLightStatement,
    VerbError,
};

pub use sociacl_core::{
    AttestationChannel, AttestationClaim, EnrollmentKind, IssuerSecret,
    SocialLightStatement as Statement, SocialLightView,
};

mod localhost;
pub use localhost::{HopIoError, LocalHop};

#[derive(Debug)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    plane: Option<Plane>,
    client: Option<Client>,
    neighbors: BTreeSet<NodeId>,
    inbox: Vec<SocialLightStatement>,
}

impl Node {
    pub fn live(&self) -> Option<&Plane> {
        self.plane.as_ref()
    }

    pub fn live_mut(&mut self) -> Option<&mut Plane> {
        self.plane.as_mut()
    }

    pub fn client(&self) -> Option<&Client> {
        self.client.as_ref()
    }

    pub fn client_mut(&mut self) -> Option<&mut Client> {
        self.client.as_mut()
    }

    pub fn inbox(&self) -> &[SocialLightStatement] {
        &self.inbox
    }

    pub fn neighbors(&self) -> impl Iterator<Item = &NodeId> {
        self.neighbors.iter()
    }
}

/// In-process lab. No cloud, no accounts, no billing.
#[derive(Debug, Default)]
pub struct Lab {
    nodes: BTreeMap<NodeId, Node>,
}

impl Lab {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_plane(&mut self, id: impl Into<NodeId>, kind: NodeKind, plane: Plane) -> NodeId {
        let id = id.into();
        self.nodes.insert(
            id.clone(),
            Node {
                id: id.clone(),
                kind,
                plane: Some(plane),
                client: None,
                neighbors: BTreeSet::new(),
                inbox: Vec::new(),
            },
        );
        id
    }

    /// Reachability for statement delivery. Not a friend edge.
    pub fn reach(&mut self, a: impl Into<NodeId>, b: impl Into<NodeId>) -> Result<(), VerbError> {
        let a = a.into();
        let b = b.into();
        if !self.nodes.contains_key(&a) {
            return Err(VerbError::PrincipalNotFound(a));
        }
        if !self.nodes.contains_key(&b) {
            return Err(VerbError::PrincipalNotFound(b));
        }
        if let Some(n) = self.nodes.get_mut(&a) {
            n.neighbors.insert(b.clone());
        }
        if let Some(n) = self.nodes.get_mut(&b) {
            n.neighbors.insert(a);
        }
        Ok(())
    }

    pub fn node(&self, id: &NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    pub fn node_mut(&mut self, id: &NodeId) -> Option<&mut Node> {
        self.nodes.get_mut(id)
    }

    /// Deliver a signed statement to neighbors this node already reaches.
    /// Reachability is not a friend edge.
    pub fn emit(
        &mut self,
        from: impl Into<NodeId>,
        statement: SocialLightStatement,
    ) -> Result<usize, VerbError> {
        let from = from.into();
        let neighbors = self
            .nodes
            .get(&from)
            .ok_or_else(|| VerbError::PrincipalNotFound(from.clone()))?
            .neighbors
            .clone();
        let mut n = 0;
        for id in neighbors {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.inbox.push(statement.clone());
                n += 1;
            }
        }
        Ok(n)
    }

    /// Decode hop-frame bytes, then deliver. Hearing still does not
    /// mint a friend.
    pub fn emit_bytes(
        &mut self,
        from: impl Into<NodeId>,
        bytes: &[u8],
    ) -> Result<usize, VerbError> {
        let statement =
            SocialLightStatement::decode(bytes).map_err(VerbError::AttestationRejected)?;
        self.emit(from, statement)
    }

    /// Decode and verify on this node's plane or client.
    pub fn accept_bytes(
        &self,
        id: impl Into<NodeId>,
        bytes: &[u8],
    ) -> Result<SocialLightStatement, VerbError> {
        let id = id.into();
        let node = self
            .nodes
            .get(&id)
            .ok_or_else(|| VerbError::PrincipalNotFound(id.clone()))?;
        match (&node.plane, &node.client) {
            (Some(plane), _) => plane
                .accept_social_light_bytes(bytes)
                .map_err(VerbError::AttestationRejected),
            (_, Some(client)) => client
                .accept_social_light_bytes(bytes)
                .map_err(VerbError::AttestationRejected),
            _ => Err(VerbError::PrincipalNotFound(id)),
        }
    }

    pub fn check_bytes(
        &self,
        id: impl Into<NodeId>,
        request: CheckRequest,
        bytes: &[u8],
    ) -> Result<CheckResult, sociacl_core::CheckError> {
        let statement = SocialLightStatement::decode(bytes)
            .map_err(sociacl_core::CheckError::AttestationRejected)?;
        self.check(id, request, Some(&statement))
    }

    pub fn remint_bytes(
        &self,
        id: impl Into<NodeId>,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
        bytes: &[u8],
    ) -> Result<sociacl_core::Capability, VerbError> {
        let statement =
            SocialLightStatement::decode(bytes).map_err(VerbError::AttestationRejected)?;
        self.remint(id, object, principal, &statement)
    }

    pub fn discover_bytes(
        &self,
        id: impl Into<NodeId>,
        bytes: &[u8],
    ) -> Result<SocialLightView, VerbError> {
        let statement =
            SocialLightStatement::decode(bytes).map_err(VerbError::AttestationRejected)?;
        self.discover(id, &statement)
    }

    pub fn take_inbox(
        &mut self,
        id: impl Into<NodeId>,
    ) -> Result<Vec<SocialLightStatement>, VerbError> {
        let id = id.into();
        let node = self
            .nodes
            .get_mut(&id)
            .ok_or_else(|| VerbError::PrincipalNotFound(id))?;
        Ok(std::mem::take(&mut node.inbox))
    }

    pub fn check(
        &self,
        id: impl Into<NodeId>,
        request: CheckRequest,
        statement: Option<&SocialLightStatement>,
    ) -> Result<CheckResult, sociacl_core::CheckError> {
        let id = id.into();
        let node = self
            .nodes
            .get(&id)
            .ok_or_else(|| sociacl_core::CheckError::AccessorNotFound(id.clone()))?;
        match (&node.plane, &node.client, statement) {
            (Some(plane), _, Some(s)) => plane.check_social_light(request, s),
            (Some(plane), _, None) => plane.check(request),
            (_, Some(client), Some(s)) => client.check_social_light(request, s),
            (_, Some(client), None) => client.check(request),
            _ => Err(sociacl_core::CheckError::AccessorNotFound(id)),
        }
    }

    pub fn remint(
        &self,
        id: impl Into<NodeId>,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
        statement: &SocialLightStatement,
    ) -> Result<sociacl_core::Capability, VerbError> {
        let id = id.into();
        let node = self
            .nodes
            .get(&id)
            .ok_or_else(|| VerbError::PrincipalNotFound(id.clone()))?;
        match (&node.plane, &node.client) {
            (Some(plane), _) => plane.remint_social_light(object, principal, statement),
            (_, Some(client)) => client.remint_social_light(object, principal, statement),
            _ => Err(VerbError::PrincipalNotFound(id)),
        }
    }

    pub fn discover(
        &self,
        id: impl Into<NodeId>,
        statement: &SocialLightStatement,
    ) -> Result<SocialLightView, VerbError> {
        let id = id.into();
        let node = self
            .nodes
            .get(&id)
            .ok_or_else(|| VerbError::PrincipalNotFound(id.clone()))?;
        match (&node.plane, &node.client) {
            (Some(plane), _) => plane.discover_social_light(statement),
            (_, Some(client)) => client.discover_social_light(statement),
            _ => Err(VerbError::PrincipalNotFound(id)),
        }
    }

    pub fn elect_from_flash(
        &mut self,
        id: impl Into<NodeId>,
        object: impl Into<NodeId>,
        statement: &SocialLightStatement,
    ) -> Result<sociacl_core::ElectResult, VerbError> {
        let id = id.into();
        let node = self
            .nodes
            .get_mut(&id)
            .ok_or_else(|| VerbError::PrincipalNotFound(id.clone()))?;
        match (&mut node.plane, &mut node.client) {
            (Some(plane), _) => plane.elect_from_social_light(object, statement),
            (_, Some(client)) => client.elect_from_social_light(object, statement),
            _ => Err(VerbError::PrincipalNotFound(id)),
        }
    }

    /// Freeze this node onto its last bundle. Silence does not Elect.
    pub fn cut(
        &mut self,
        id: impl Into<NodeId>,
        holder: impl Into<NodeId>,
        secret: &HolderSecret,
    ) -> Result<(), VerbError> {
        let id = id.into();
        let node = self
            .nodes
            .get_mut(&id)
            .ok_or_else(|| VerbError::PrincipalNotFound(id.clone()))?;
        let plane = node
            .plane
            .as_ref()
            .ok_or_else(|| VerbError::PrincipalNotFound(id.clone()))?;
        let bytes = plane.export_bundle_bytes(holder, secret)?;
        node.client = Some(Client::from_bytes(&bytes, secret)?);
        node.plane = None;
        Ok(())
    }

    /// SociACL rejoin. Does not union post-cut Elects.
    pub fn rejoin(
        &mut self,
        left: impl Into<NodeId>,
        right: impl Into<NodeId>,
    ) -> Result<(), VerbError> {
        let left = left.into();
        let right = right.into();
        let joined = {
            let l = self
                .nodes
                .get(&left)
                .and_then(|n| n.client.as_ref())
                .ok_or_else(|| VerbError::PrincipalNotFound(left.clone()))?;
            let r = self
                .nodes
                .get(&right)
                .and_then(|n| n.client.as_ref())
                .ok_or_else(|| VerbError::PrincipalNotFound(right.clone()))?;
            l.rejoin(r)?
        };
        if let Some(node) = self.nodes.get_mut(&left) {
            node.client = Some(joined);
        }
        Ok(())
    }
}
